{% skip_file unless flag?(:linux) %}
require "./native"
require "../mutation"

module Filesystem::AccessControl
  @[Link("c")]
  lib Native::Linux::Xattr
    fun fsetxattr(fd : Int32, name : UInt8*, value : Void*, size : LibC::SizeT, flags : Int32) : Int32
    fun fremovexattr(fd : Int32, name : UInt8*) : Int32
  end
end

module Filesystem::AccessControl::Linux
  class NativeWriterProvider < NativeReaderProvider
    def set(fd : Int32, kind : ACLKind, bytes : Bytes) : Diagnostic?
      return nil if Native::Linux::Xattr.fsetxattr(fd, kind.key, bytes.to_unsafe.as(Void*), bytes.size, 0) == 0
      native_error("Cannot replace #{kind.key}", Errno.value, kind)
    end

    def remove(fd : Int32, kind : ACLKind) : Diagnostic?
      return nil if Native::Linux::Xattr.fremovexattr(fd, kind.key) == 0
      native_error("Cannot remove #{kind.key}", Errno.value, kind)
    end
  end

  enum MutationState
    Rejected
    Unchanged
    Applied
    AppliedUnverified
  end

  record MutationResult, state : MutationState, before : Snapshot?, after : Snapshot?, diagnostic : Diagnostic?,
    execution : MutationExecution, verification : MutationVerification do
    def applied? : Bool
      state.applied? || state.applied_unverified?
    end

    def verified? : Bool
      state.applied? || state.unchanged?
    end
  end

  module Writer
    # target checks identity only, not an ACL revision. A successful native
    # setter can update mode bits or collapse a base ACL to mode-only storage.
    def self.replace_fd(fd : Int32, *, target : Snapshot, acl : ACL, kind : ACLKind = ACLKind::Access,
                        provider = NativeWriterProvider.new) : MutationResult
      mutate(fd, target, acl, kind, provider)
    end

    # Access removal preserves the kernel's current mode bits. Default removal
    # changes future inheritance only; existing children are untouched.
    def self.remove_fd(fd : Int32, *, target : Snapshot, kind : ACLKind = ACLKind::Access,
                       provider = NativeWriterProvider.new) : MutationResult
      mutate(fd, target, nil, kind, provider)
    end

    private def self.mutate(fd : Int32, target : Snapshot, acl : ACL?, kind : ACLKind, provider) : MutationResult
      unless target.complete?
        return MutationResult.new(MutationState::Rejected, nil, nil,
          Diagnostic.new(Reason::IncompleteCapture, "The target must be a complete capture"),
          MutationExecution::NotAttempted, MutationVerification::NotRun)
      end
      before = Reader.capture(fd, provider: provider)
      unless before.complete?
        return MutationResult.new(MutationState::Rejected, before, nil,
          before.diagnostics.first? || Diagnostic.new(Reason::IncompleteCapture, "Cannot capture the write target"),
          MutationExecution::NotAttempted, MutationVerification::NotRun)
      end
      unless target.stat.not_nil!.same_inode?(before.stat.not_nil!)
        return MutationResult.new(MutationState::Rejected, before, nil,
          Diagnostic.new(Reason::IdentityMismatch, "Descriptor does not identify the captured inode"),
          MutationExecution::NotAttempted, MutationVerification::NotRun)
      end
      if kind.default? && before.stat.not_nil!.kind.file?
        return MutationResult.new(MutationState::Rejected, before, nil,
          Diagnostic.new(Reason::WrongKind, "Only a directory can have a default ACL", acl_kind: kind),
          MutationExecution::NotAttempted, MutationVerification::NotRun)
      end
      current = kind.access? ? before.access : before.default_acl
      if acl.nil? && current.nil?
        return MutationResult.new(MutationState::Unchanged, before, before, nil,
          MutationExecution::NotAttempted, MutationVerification::Matched)
      end
      problem = acl ? provider.set(fd, kind, Codec.encode(acl)) : provider.remove(fd, kind)
      if problem
        return MutationResult.new(MutationState::Rejected, before, nil, problem,
          MutationExecution::Failed, MutationVerification::NotRun)
      end
      after = Reader.capture(fd, provider: provider)
      unless after.complete?
        diagnostic = after.diagnostics.first?
        return MutationResult.new(MutationState::AppliedUnverified, before, after,
          Diagnostic.new(Reason::ReadbackFailed, diagnostic.try(&.message) || "Readback is incomplete", diagnostic.try(&.errno), kind),
          MutationExecution::Succeeded, MutationVerification::Unavailable)
      end
      actual = kind.access? ? after.access : after.default_acl
      matches = if acl && kind.access? && actual.nil? && !acl.named? && !acl.find(Tag::Mask)
                  acl.mode_bits == (after.stat.not_nil!.mode & 0o777)
                else
                  actual == acl
                end
      unless before.stat.not_nil!.same_inode?(after.stat.not_nil!) && matches
        return MutationResult.new(MutationState::AppliedUnverified, before, after,
          Diagnostic.new(Reason::ReadbackMismatch, "Write succeeded but the observed ACL differs", acl_kind: kind),
          MutationExecution::Succeeded, MutationVerification::Mismatched)
      end
      MutationResult.new(MutationState::Applied, before, after, nil,
        MutationExecution::Succeeded, MutationVerification::Matched)
    end
  end
end
