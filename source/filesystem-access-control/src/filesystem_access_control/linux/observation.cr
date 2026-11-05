require "./model"

module Filesystem::AccessControl::Linux
  record Stat, device : UInt64, inode : UInt64, uid : UInt32, gid : UInt32,
    mode : Int32, kind : Target, change_seconds : Int64, change_nanoseconds : Int64 do
    def same_inode?(other : Stat) : Bool
      device == other.device && inode == other.inode && kind == other.kind
    end
  end

  record StatResult, value : Stat?, diagnostic : Diagnostic?
  record ReadResult, bytes : Bytes?, diagnostic : Diagnostic?

  enum PrivacyReason
    IncompleteCapture
    OwnerMismatch
    UnsafeMode
    NamedAccessEntries
    DefaultACL
  end

  record PrivacyIssue, reason : PrivacyReason, message : String

  class Snapshot
    getter stat : Stat?
    getter access : ACL?
    getter default_acl : ACL?
    @diagnostics : Array(Diagnostic)

    def initialize(@stat : Stat?, @access : ACL?, @default_acl : ACL?, diagnostics : Array(Diagnostic) = [] of Diagnostic)
      @diagnostics = diagnostics.dup
      if stat = @stat
        if acl = @access
          if acl.mode_bits != stat.mode & 0o777
            @diagnostics << Diagnostic.new(Reason::ModeMismatch, "Access ACL disagrees with the captured mode")
          end
        end
        if stat.kind.file? && @default_acl
          @diagnostics << Diagnostic.new(Reason::WrongKind, "Only directories have default ACLs")
        end
      end
    end

    def diagnostics : Array(Diagnostic)
      @diagnostics.dup
    end

    def complete? : Bool
      !@stat.nil? && @diagnostics.empty?
    end

    def privacy_issues(owner_uid : UInt32) : Array(PrivacyIssue)
      issues = [] of PrivacyIssue
      issues << PrivacyIssue.new(PrivacyReason::IncompleteCapture, "ACL capture is incomplete") unless complete?
      if stat = @stat
        issues << PrivacyIssue.new(PrivacyReason::OwnerMismatch, "Owner UID #{stat.uid} differs from #{owner_uid}") unless stat.uid == owner_uid
        mode_ok = stat.kind.directory? ? stat.mode == 0o700 : stat.mode > 0 && (stat.mode & ~0o600) == 0
        issues << PrivacyIssue.new(PrivacyReason::UnsafeMode, "Mode #{stat.mode.to_s(8)} does not meet owner-only policy") unless mode_ok
      end
      issues << PrivacyIssue.new(PrivacyReason::NamedAccessEntries, "Named access entries remain, even if masked off") if @access.try(&.named?)
      issues << PrivacyIssue.new(PrivacyReason::DefaultACL, "A default ACL controls newly created children") if @default_acl
      issues
    end
  end
end
