require "./handle_capture"
require "../mutation"
{% if flag?(:windows) %}
  require "./writer_native"
{% end %}

module Filesystem::AccessControl::Windows
  enum InheritancePolicy
    PreserveObserved
  end

  enum PropagationPolicy
    TargetOnly
    NativePropagation
  end

  enum DescendantEffect
    NotApplicable
    NotAttempted
    Unverified
  end

  enum Normalization
    DaclAutoInherited
  end

  enum MutationStage
    Precondition
    PreCapture
    Validation
    Mutation
    PostCapture
    Verification
  end

  enum MutationState
    Rejected
    Applied
    AppliedUnverified
  end

  class MutationResult
    getter before : HandleSnapshot?
    getter after : HandleSnapshot?
    getter diagnostic : Diagnostic?
    getter execution : MutationExecution
    getter verification : MutationVerification
    getter stage : MutationStage
    getter descendants : DescendantEffect
    @normalizations : Array(Normalization)

    def initialize(@before : HandleSnapshot?, @after : HandleSnapshot?, @diagnostic : Diagnostic?,
                   @execution : MutationExecution, @verification : MutationVerification,
                   @stage : MutationStage, @descendants : DescendantEffect,
                   normalizations = [] of Normalization)
      if (@execution.succeeded? && @verification.not_run?) ||
         (!@execution.succeeded? && !@verification.not_run?)
        raise ArgumentError.new("Mutation execution and verification disagree")
      end
      @normalizations = normalizations.dup
    end

    def normalizations : Array(Normalization)
      @normalizations.dup
    end

    def state : MutationState
      return MutationState::Rejected unless @execution.succeeded?
      @verification.matched? ? MutationState::Applied : MutationState::AppliedUnverified
    end

    def applied? : Bool
      @execution.succeeded?
    end

    def verified? : Bool
      @verification.matched?
    end
  end

  module Writer
    {% if flag?(:windows) %}
      def self.replace_dacl_handle(handle : Void*, *, target : HandleSnapshot, dacl : ACL,
                                   inheritance : InheritancePolicy, propagation : PropagationPolicy) : MutationResult
        replace_dacl_handle(handle, target: target, dacl: dacl, inheritance: inheritance,
          propagation: propagation, provider: NativeWriterProvider.new)
      end
    {% end %}

    # The supplied target establishes identity, never an expected ACL revision.
    # There is no path reopening, no NULL installation, no no-op replacement,
    # no automatic mutation retry, and no descendant transaction claim.
    def self.replace_dacl_handle(handle : Void*, *, target : HandleSnapshot, dacl : ACL,
                                 inheritance : InheritancePolicy, propagation : PropagationPolicy, provider) : MutationResult
      unless inheritance.preserve_observed? && (propagation.target_only? || propagation.native_propagation?)
        raise ArgumentError.new("Unsupported inheritance or propagation policy")
      end
      descendant = target.kind.try(&.directory?) ? DescendantEffect::NotAttempted : DescendantEffect::NotApplicable
      unless target.complete? && target.security.information.owner? && target.security.information.group? &&
             target.security.information.dacl? && target.security.owner && target.security.group &&
             !handle.null? && handle.address != UInt64::MAX
        return refused(nil, MutationStage::Precondition, descendant, "A complete handle identity and owner/group/DACL capture is required")
      end
      if target.kind.try(&.directory?) && propagation.target_only?
        return refused(nil, MutationStage::Precondition, descendant, "TargetOnly directory edits require a separately qualified route")
      end
      before = provider.capture(handle)
      unless before.complete? && before.security.information.owner? && before.security.information.group? &&
             before.security.information.dacl? && before.security.owner && before.security.group
        return refused(before, MutationStage::PreCapture, descendant, "Fresh handle capture is incomplete", before.diagnostic || before.security.diagnostic)
      end
      unless before.identity == target.identity && before.kind == target.kind
        return refused(before, MutationStage::PreCapture, descendant, "The held object does not match the supplied target")
      end
      if diagnostic = provider.validate(dacl)
        return refused(before, MutationStage::Validation, descendant, "Native ACL validation failed", diagnostic)
      end
      protected_state = before.security.dacl_inheritance_control.not_nil!.protected?
      # Preserve the freshly observed protection setting explicitly. Unprotected
      # writes can merge parent inheritance; readback must still meet our exact
      # DACL postcondition or remain unverified.
      information = 4_u32 | (protected_state ? 0x80000000_u32 : 0x20000000_u32)
      code = provider.replace(handle, dacl, information)
      descendant = DescendantEffect::Unverified if before.kind.try(&.directory?)
      if code != 0
        diagnostic = Diagnostic.new("SetSecurityInfo", code, ErrorOrigin::ReturnValue, "SetSecurityInfo returned #{code}; side effects are not ruled out")
        return MutationResult.new(before, nil, diagnostic, MutationExecution::Failed,
          MutationVerification::NotRun, MutationStage::Mutation, descendant)
      end
      after = provider.capture(handle)
      unless after.complete? && after.security.information.owner? && after.security.information.group? && after.security.information.dacl?
        diagnostic = after.diagnostic || after.security.diagnostic || invalid("Writer.readback", "Mutation succeeded but readback is incomplete")
        return MutationResult.new(before, after, diagnostic, MutationExecution::Succeeded,
          MutationVerification::Unavailable, MutationStage::PostCapture, descendant)
      end
      mismatch = if before.identity != after.identity || before.kind != after.kind
                   "Post-write object identity or kind differs"
                 elsif after.security.owner != before.security.owner || after.security.group != before.security.group
                   "Owner or group changed during DACL replacement"
                 elsif !after.security.dacl_presence.present? || after.security.dacl != dacl
                   "Post-write DACL differs from the requested bytes"
                 elsif after.security.dacl_inheritance_control.not_nil!.protected? != protected_state
                   "Post-write DACL protection differs"
                 end
      # Installing a non-NULL DACL explicitly requests SE_DACL_PRESENT, even
      # when the captured descriptor had no DACL. This is a postcondition,
      # not an implicit normalization of the previous representation.
      expected_control = before.security.control.not_nil! | 0x0004_u16
      changes = expected_control ^ after.security.control.not_nil!
      # The lab observed adding SE_DACL_AUTO_INHERITED. No sorting, padding,
      # unknown-payload, removal or other control normalization is accepted.
      if !mismatch && changes != 0 && !(changes == 0x0400 && (after.security.control.not_nil! & 0x0400) != 0)
        mismatch = "Unqualified security-descriptor control change"
      end
      if mismatch
        return MutationResult.new(before, after, invalid("Writer.verify", mismatch), MutationExecution::Succeeded,
          MutationVerification::Mismatched, MutationStage::Verification, descendant)
      end
      normalizations = changes == 0x0400 ? [Normalization::DaclAutoInherited] : [] of Normalization
      MutationResult.new(before, after, nil, MutationExecution::Succeeded,
        MutationVerification::Matched, MutationStage::Verification, descendant, normalizations)
    end

    private def self.invalid(operation : String, message : String) : Diagnostic
      Diagnostic.new(operation, nil, ErrorOrigin::Validation, message)
    end

    private def self.refused(before : HandleSnapshot?, stage : MutationStage, descendant : DescendantEffect,
                             message : String, diagnostic : Diagnostic? = nil) : MutationResult
      MutationResult.new(before, nil, diagnostic || invalid("Writer.#{stage}", message),
        MutationExecution::NotAttempted, MutationVerification::NotRun, stage, descendant)
    end
  end
end
