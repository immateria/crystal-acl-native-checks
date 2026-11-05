{% skip_file unless flag?(:darwin) %}

require "errno"
require "c/fcntl"
require "c/sys/stat"
require "./model"
require "./external_acl"
require "./builder"
require "./writer_native"
require "./writer_provider"
require "../mutation"

module Filesystem::AccessControl::Darwin
  enum MutationOperation
    Replace
    Remove
  end

  enum MutationState
    Refused
    Rejected
    Applied
    AppliedWithNormalization
    ChangedButReadbackFailed
    ChangedButReadbackMismatched
  end

  class MutationResult
    getter operation : MutationOperation
    getter state : MutationState
    getter after : Snapshot?
    getter diagnostic : Diagnostic?
    getter execution : MutationExecution

    def initialize(@operation : MutationOperation, @state : MutationState,
                   @after : Snapshot? = nil, @diagnostic : Diagnostic? = nil, *,
                   @execution : MutationExecution)
    end

    # Native success, including writes whose verification failed. This does
    # not establish a semantic change or permission for another edit.
    def applied? : Bool
      @state.applied? || @state.applied_with_normalization? ||
        @state.changed_but_readback_failed? || @state.changed_but_readback_mismatched?
    end

    def verified? : Bool
      @state.applied? || @state.applied_with_normalization?
    end

    def verification : MutationVerification
      case @state
      when MutationState::Applied, MutationState::AppliedWithNormalization
        MutationVerification::Matched
      when MutationState::ChangedButReadbackMismatched
        MutationVerification::Mismatched
      when MutationState::ChangedButReadbackFailed
        MutationVerification::Unavailable
      else
        MutationVerification::NotRun
      end
    end
  end

  # The explicit Darwin mutator. It never repairs modes/ownership and does not
  # claim conflict detection against another writer.
  module Writer
    FILESEC_ACL        = 5
    FILESEC_REMOVE_ACL = Pointer(Void).new(1_u64)
    O_EVTONLY          = Constants::O_EVTONLY
    MAX_ENTRIES        = Constants::ACL_MAX_ENTRIES
    MAX_KERNEL_RIGHTS  = UInt32::MAX.to_u64

    # target is identity/provenance evidence, not an expected ACL version.
    # Another writer can change this inode's ACL before or after this call.

    def self.replace_fd(fd : Int32, *, target : Snapshot, acl : DesiredACL,
                        provider = NativeWriterProvider.new) : MutationResult
      perform(fd, target, MutationOperation::Replace, acl, provider)
    end

    def self.remove_fd(fd : Int32, *, target : Snapshot,
                       provider = NativeWriterProvider.new) : MutationResult
      perform(fd, target, MutationOperation::Remove, nil, provider)
    end

    private def self.perform(fd : Int32, target : Snapshot,
                             operation : MutationOperation,
                             desired : DesiredACL?, provider) : MutationResult
      target_kind = target.kind
      unless fd >= 0 && target.complete? &&
             target.device && target.inode && target.uid && target.gid &&
             target.mode && target.file_flags && target_kind
        return outcome(operation, MutationState::Refused,
          message: "A complete snapshot with native identity and metadata is required",
          reason: Reason::IncompleteEvidence, execution: MutationExecution::NotAttempted)
      end
      target_kind = target_kind.not_nil!
      unless target_kind.file? || target_kind.directory?
        return outcome(operation, MutationState::Refused,
          message: "Only regular files and directories can be edited", reason: Reason::Unsupported,
          execution: MutationExecution::NotAttempted)
      end
      unless LibC.fstat(fd, out status) == 0
        failure = Errno.value
        return outcome(operation, MutationState::Refused,
          message: "Unable to verify target descriptor: #{failure}", reason: native_reason(failure), errno: failure.value,
          execution: MutationExecution::NotAttempted)
      end
      descriptor_kind = (status.st_mode & LibC::S_IFMT) == LibC::S_IFREG ? Kind::File : (status.st_mode & LibC::S_IFMT) == LibC::S_IFDIR ? Kind::Directory : Kind::Other
      unless status.st_dev.to_u64 == target.device && status.st_ino.to_u64 == target.inode &&
             descriptor_kind == target_kind
        return outcome(operation, MutationState::Refused,
          message: "Target descriptor no longer identifies the captured inode and kind", reason: Reason::TargetMismatch,
          execution: MutationExecution::NotAttempted)
      end
      if desired
        validation = validate_desired(desired, target)
        return outcome(operation, MutationState::Refused, message: validation,
          execution: MutationExecution::NotAttempted) if validation
      end

      if operation.remove?
        apply_removal(fd, target, provider)
      else
        apply_replacement(fd, target, desired.not_nil!, provider)
      end
    end

    private def self.validate_desired(desired : DesiredACL, captured : Snapshot) : String?
      entries = desired.entries
      return "ACL entry count exceeds the native limit of 128" if entries.size > MAX_ENTRIES
      known_header = Constants::ACL_FLAG_NO_INHERIT | Constants::ACL_FLAG_DEFER_INHERIT | Constants::ACL_FLAG_DEFER_INHERIT_KERNEL
      if ((desired.acl_flags & ~known_header) & ~captured.acl_flags) != 0
        return "Fresh unknown ACL header flags cannot be introduced"
      end
      known_entry = Constants::ACL_ENTRY_FLAGS
      captured_entries = captured.entries
      entries.each_with_index do |ace, index|
        return "ACE ordinals must match sequence positions" unless ace.ordinal == index
        return "Unknown ACE tags cannot be encoded with the public ACL API" unless ace.raw_tag == Constants::ACL_EXTENDED_ALLOW || ace.raw_tag == Constants::ACL_EXTENDED_DENY
        return "ACE rights exceed the kernel's 32-bit rights field" if ace.rights > MAX_KERNEL_RIGHTS
        unknown = ace.raw_flags & ~known_entry
        if unknown != 0 && !captured_entries.any? { |old| old.principal == ace.principal &&
           old.raw_tag == ace.raw_tag && (old.raw_flags & unknown) == unknown }
          return "Fresh unknown ACE flags cannot be introduced"
        end
      end
      nil
    end

    private def self.apply_removal(fd : Int32, target : Snapshot, provider) : MutationResult
      filesec = provider.init_removal
      if filesec.null?
        failure = Errno.value
        return outcome(MutationOperation::Remove, MutationState::Rejected,
          message: "filesec_init failed before mutation: #{failure}", reason: native_reason(failure), errno: failure.value,
          execution: MutationExecution::NotAttempted)
      end
      apply_result, failure = begin
        # Matched libc acl_set_fd_np passes `&acl`, but the filesec API's public
        # removal sentinel is the direct value `(void *)1`. The independent
        # SDK helper verified this form with fchmodx_np on APFS.
        setter_result = provider.prepare_removal(filesec)
        if setter_result != 0
          failure = Errno.value
          return outcome(MutationOperation::Remove, MutationState::Rejected,
            message: "filesec_set_property rejected the removal sentinel before mutation: #{failure}", reason: native_reason(failure), errno: failure.value,
            execution: MutationExecution::NotAttempted)
        end
        result = provider.remove(fd, filesec)
        {result, Errno.value}
      ensure
        provider.free_removal(filesec)
      end
      if apply_result != 0
        outcome(MutationOperation::Remove, MutationState::Rejected,
          message: "fchmodx_np rejected ACL removal: #{failure}", reason: native_reason(failure), errno: failure.value,
          execution: MutationExecution::Failed)
      else
        readback(fd, MutationOperation::Remove, nil, target, provider)
      end
    end

    private def self.apply_replacement(fd : Int32, target : Snapshot, desired : DesiredACL, provider) : MutationResult
      acl = build_native_acl(desired)
      if acl.null?
        failure = Errno.value
        return outcome(MutationOperation::Replace, MutationState::Refused,
          message: "Could not construct a valid native ACL before mutation: #{failure}", reason: native_reason(failure), errno: failure.value,
          execution: MutationExecution::NotAttempted)
      end
      result, failure = begin
        applied = provider.replace(fd, acl)
        {applied, Errno.value}
      ensure
        Native::Darwin::ACL.acl_free(acl)
      end
      if result != 0
        outcome(MutationOperation::Replace, MutationState::Rejected,
          message: "acl_set_fd_np rejected the replacement: #{failure}", reason: native_reason(failure), errno: failure.value,
          execution: MutationExecution::Failed)
      else
        readback(fd, MutationOperation::Replace, desired, target, provider)
      end
    end

    private def self.build_native_acl(desired : DesiredACL) : Void*
      entries = desired.entries
      if entries.any? { |ace| (ace.rights & GENERIC_RIGHTS) != 0 }
        return build_generic_acl(desired, entries)
      end
      acl = Native::Darwin::ACL.acl_init(entries.size.to_i32)
      return acl if acl.null?
      begin
        entries.each do |ace|
          entry = Pointer(Void).null
          if Native::Darwin::ACL.acl_create_entry(pointerof(acl), pointerof(entry)) != 0 || entry.null?
            return discard_acl(acl)
          end
          unless Native::Darwin::ACL.acl_set_tag_type(entry, ace.raw_tag) == 0 &&
                 Native::Darwin::ACL.acl_set_qualifier(entry, ace.principal.uuid.to_unsafe) == 0 &&
                 Native::Darwin::ACL.acl_set_permset_mask_np(entry, ace.rights) == 0 &&
                 set_raw_flags(entry, ace.raw_flags)
            return discard_acl(acl)
          end
        end
        unless set_raw_flags(acl, desired.acl_flags) &&
               Native::Darwin::ACL.acl_valid(acl) == 0
          return discard_acl(acl)
        end
      rescue error
        Native::Darwin::ACL.acl_free(acl)
        raise error
      end
      acl
    end

    # The public permset-mask setter rejects KAUTH's four generic rights even
    # though acl_copy_int/ext preserve them and the kernel accepts them. Build
    # Apple's documented portable kauth_filesec encoding instead of dropping
    # or translating those raw bits. The offsets and sizes are pinned against
    # the installed SDK in darwin_generic_spec.cr.
    private def self.build_generic_acl(desired : DesiredACL, entries : Array(Ace)) : Void*
      external = ExternalACL.encode(entries, desired.acl_flags)
      acl = Native::Darwin::ACL.acl_copy_int(external.to_unsafe.as(Void*))
      return acl if acl.null?
      if Native::Darwin::ACL.acl_valid(acl) != 0
        return discard_acl(acl)
      end
      acl
    end

    # libc cleanup is allowed to change errno even on success. Construction
    # returns a null pointer to its caller, so preserve the original failure.
    private def self.discard_acl(acl : Void*) : Void*
      failure = Errno.value
      Native::Darwin::ACL.acl_free(acl)
      Errno.value = failure
      Pointer(Void).null
    end

    GENERIC_RIGHTS = Constants::ACL_GENERIC_MASK

    private def self.set_raw_flags(object : Void*, flags : UInt32) : Bool
      flagset = Pointer(Void).null
      return false unless Native::Darwin::ACL.acl_get_flagset_np(object, pointerof(flagset)) == 0 && !flagset.null?
      return false unless Native::Darwin::ACLWriter.acl_clear_flags_np(flagset) == 0
      32.times do |bit|
        next if (flags & (1_u32 << bit)) == 0
        return false unless Native::Darwin::ACL.acl_add_flag_np(flagset, (1 << bit).to_i32) == 0
      end
      Native::Darwin::ACLWriter.acl_set_flagset_np(object, flagset) == 0
    end

    private def self.readback(fd : Int32, operation : MutationOperation,
                              desired : DesiredACL?, target : Snapshot, provider) : MutationResult
      observed = provider.capture(fd)
      unless observed && observed.complete? && observed.device && observed.inode && observed.kind
        return outcome(operation, MutationState::ChangedButReadbackFailed,
          observed, "Mutation succeeded, but ACL or identity readback was incomplete", errno: observed.try(&.diagnostics).try(&.first?).try(&.errno),
          execution: MutationExecution::Succeeded)
      end
      unless observed.device == target.device && observed.inode == target.inode && observed.kind == target.kind
        return outcome(operation, MutationState::ChangedButReadbackMismatched,
          observed, "Mutation succeeded, but readback identifies a different inode or kind",
          reason: Reason::TargetMismatch, execution: MutationExecution::Succeeded)
      end
      if operation.remove?
        return outcome(operation,
          observed.status.absent? ? MutationState::Applied : MutationState::ChangedButReadbackMismatched,
          observed,
          observed.status.absent? ? nil : "ACL removal succeeded but readback still reports an ACL",
          execution: MutationExecution::Succeeded)
      end

      requested = desired.not_nil!
      if observed.status.absent? && requested.entries.empty? && requested.acl_flags == 0
        return outcome(operation, MutationState::AppliedWithNormalization,
          observed, "Filesystem normalized the requested empty ACL to absence", execution: MutationExecution::Succeeded)
      end
      if observed.acl_flags == requested.acl_flags && observed.entries == requested.entries
        outcome(operation, MutationState::Applied, observed, execution: MutationExecution::Succeeded)
      else
        outcome(operation, MutationState::ChangedButReadbackMismatched,
          observed, "ACL mutation succeeded, but readback differs from the requested native fields",
          execution: MutationExecution::Succeeded)
      end
    rescue error
      outcome(operation, MutationState::ChangedButReadbackFailed,
        message: "Mutation succeeded, but ACL readback failed: #{error.message}", execution: MutationExecution::Succeeded)
    end

    private def self.outcome(operation : MutationOperation, state : MutationState,
                             after : Snapshot? = nil, message : String? = nil,
                             reason : Reason? = nil, errno : Int32? = nil, *,
                             execution : MutationExecution) : MutationResult
      reason ||= case state
                 when MutationState::Refused                      then Reason::InvalidInput
                 when MutationState::Rejected                     then Reason::SystemError
                 when MutationState::AppliedWithNormalization     then Reason::Normalized
                 when MutationState::ChangedButReadbackFailed     then Reason::ReadbackFailed
                 when MutationState::ChangedButReadbackMismatched then Reason::ReadbackMismatched
                 end
      diagnostic = if message || reason || errno
                     Diagnostic.new("acl_#{operation.to_s.downcase}", errno, nil, nil,
                       message || "ACL mutation #{state}", reason || Reason::IncompleteEvidence)
                   end
      MutationResult.new(operation, state, after, diagnostic, execution: execution)
    end

    private def self.native_reason(error : Errno) : Reason
      case error
      when Errno::EACCES, Errno::EPERM then Reason::PermissionDenied
      when Errno::EOPNOTSUPP           then Reason::Unsupported
      else                                  Reason::SystemError
      end
    end
  end
end
