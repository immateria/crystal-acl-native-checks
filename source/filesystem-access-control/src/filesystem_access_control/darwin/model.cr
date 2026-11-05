require "./principal"

module Filesystem::AccessControl::Darwin
  enum Status
    Absent
    Empty
    Present
    Unsupported
    Unavailable
    Incomplete
  end

  enum Kind
    File
    Directory
    Symlink
    Other
  end

  # Returned-attribute evidence is separate from libc's ACL interpretation.
  # NotReturned alone does not establish absence or filesystem ACL support.
  enum ExtendedSecurityPresence
    NotReturned
    Absent
    Present
  end

  module Constants
    O_EVTONLY          =     0x8000
    ACL_MAX_ENTRIES    =        128
    ACL_TYPE_EXTENDED  = 0x00000100
    ACL_EXTENDED_ALLOW =      1_u32
    ACL_EXTENDED_DENY  =      2_u32

    ACL_READ_DATA           = 1_u64 << 1
    ACL_WRITE_DATA          = 1_u64 << 2
    ACL_EXECUTE             = 1_u64 << 3
    ACL_DELETE              = 1_u64 << 4
    ACL_APPEND_DATA         = 1_u64 << 5
    ACL_DELETE_CHILD        = 1_u64 << 6
    ACL_READ_ATTRIBUTES     = 1_u64 << 7
    ACL_WRITE_ATTRIBUTES    = 1_u64 << 8
    ACL_READ_EXTATTRIBUTES  = 1_u64 << 9
    ACL_WRITE_EXTATTRIBUTES = 1_u64 << 10
    ACL_READ_SECURITY       = 1_u64 << 11
    ACL_WRITE_SECURITY      = 1_u64 << 12
    ACL_CHANGE_OWNER        = 1_u64 << 13
    ACL_SYNCHRONIZE         = 1_u64 << 20
    ACL_GENERIC_ALL         = 1_u64 << 21
    ACL_GENERIC_EXECUTE     = 1_u64 << 22
    ACL_GENERIC_WRITE       = 1_u64 << 23
    ACL_GENERIC_READ        = 1_u64 << 24

    ACL_GENERIC_MASK = ACL_GENERIC_ALL | ACL_GENERIC_EXECUTE | ACL_GENERIC_WRITE | ACL_GENERIC_READ

    ACL_LIST_DIRECTORY   = ACL_READ_DATA
    ACL_ADD_FILE         = ACL_WRITE_DATA
    ACL_SEARCH           = ACL_EXECUTE
    ACL_ADD_SUBDIRECTORY = ACL_APPEND_DATA

    ACL_ENTRY_INHERITED           = 1_u32 << 4
    ACL_ENTRY_FILE_INHERIT        = 1_u32 << 5
    ACL_ENTRY_DIRECTORY_INHERIT   = 1_u32 << 6
    ACL_ENTRY_LIMIT_INHERIT       = 1_u32 << 7
    ACL_ENTRY_ONLY_INHERIT        = 1_u32 << 8
    ACL_FLAG_DEFER_INHERIT        = 1_u32
    ACL_FLAG_NO_INHERIT           = 1_u32 << 17
    ACL_FLAG_DEFER_INHERIT_KERNEL = 1_u32 << 16
    ACL_ENTRY_FLAGS               = ACL_ENTRY_INHERITED | ACL_ENTRY_FILE_INHERIT |
                                    ACL_ENTRY_DIRECTORY_INHERIT | ACL_ENTRY_LIMIT_INHERIT |
                                    ACL_ENTRY_ONLY_INHERIT
  end

  # Raw ACE data is authoritative. Typed effect and known flags are views only.
  record Ace, ordinal : Int32, principal : Principal, raw_tag : UInt32,
    rights : UInt64, raw_flags : UInt32 do
    # Builders assign the final ordinal. Rights and flags retain their exact
    # native bits; the ordinary constructors choose only the entry's effect.
    def self.allow(principal : Principal, *, rights : UInt64, flags : UInt32 = 0_u32) : Ace
      new(0, principal, Constants::ACL_EXTENDED_ALLOW, rights, flags)
    end

    def self.deny(principal : Principal, *, rights : UInt64, flags : UInt32 = 0_u32) : Ace
      new(0, principal, Constants::ACL_EXTENDED_DENY, rights, flags)
    end

    # Positional ordinals belong to the ordered value, not an editor or a
    # native provider. Every returned record is detached from the input array.
    def self.reindex(entries : Array(Ace)) : Array(Ace)
      entries.map_with_index do |ace, index|
        new(index.to_i32, ace.principal, ace.raw_tag, ace.rights, ace.raw_flags)
      end
    end

    def effect : Symbol?
      case raw_tag
      when Constants::ACL_EXTENDED_ALLOW then :allow
      when Constants::ACL_EXTENDED_DENY  then :deny
      else                                    nil
      end
    end

    def inherited? : Bool
      (raw_flags & Constants::ACL_ENTRY_INHERITED) != 0
    end

    def file_inherit? : Bool
      (raw_flags & Constants::ACL_ENTRY_FILE_INHERIT) != 0
    end

    def directory_inherit? : Bool
      (raw_flags & Constants::ACL_ENTRY_DIRECTORY_INHERIT) != 0
    end

    def limit_inherit? : Bool
      (raw_flags & Constants::ACL_ENTRY_LIMIT_INHERIT) != 0
    end

    def only_inherit? : Bool
      (raw_flags & Constants::ACL_ENTRY_ONLY_INHERIT) != 0
    end
  end

  # Stable categories for callers. Messages explain a particular observation;
  # callers should branch on the category or result state, never on prose.
  enum Reason
    InvalidInput
    Unsupported
    IncompleteEvidence
    IdentityLookupFailed
    PermissionDenied
    SystemError
    TargetMismatch
    ReadbackFailed
    ReadbackMismatched
    Normalized
  end

  record Diagnostic, operation : String, errno : Int32?,
    entry : Int32?, field : String?, message : String,
    reason : Reason = Reason::IncompleteEvidence

  class MountObservation
    getter filesystem_id : StaticArray(Int32, 2)
    getter owner : UInt32
    getter filesystem_type : UInt32
    getter flags : UInt32
    getter subtype : UInt32
    getter type_name : String
    getter mount_point : String
    getter source : String
    getter extended_flags : UInt32

    def initialize(@filesystem_id : StaticArray(Int32, 2), @owner : UInt32,
                   @filesystem_type : UInt32, @flags : UInt32, @subtype : UInt32,
                   @type_name : String, @mount_point : String, @source : String,
                   @extended_flags : UInt32)
    end

    def ownership_ignored? : Bool
      (@flags & 0x00200000_u32) != 0 # MNT_IGNORE_OWNERSHIP
    end

    def server_authorized? : Bool
      @type_name.in?({"smbfs", "nfs", "webdav"})
    end
  end

  # One descriptor observation. Entry and mount arrays/strings are detached
  # from libc-owned storage before this value is constructed.
  class Snapshot
    getter status : Status
    getter acl_flags : UInt32
    getter uid : UInt32?
    getter gid : UInt32?
    getter mode : UInt32?
    getter file_flags : UInt32?
    getter device : UInt64?
    getter inode : UInt64?
    getter kind : Kind?
    getter mount : MountObservation?
    getter extended_security_presence : ExtendedSecurityPresence?
    @diagnostic : Diagnostic?
    @entries : Array(Ace)

    def initialize(@status : Status, entries : Array(Ace), @acl_flags : UInt32,
                   @uid : UInt32? = nil, @gid : UInt32? = nil,
                   @mode : UInt32? = nil, @file_flags : UInt32? = nil,
                   @device : UInt64? = nil, @inode : UInt64? = nil,
                   @kind : Kind? = nil, @mount : MountObservation? = nil,
                   @diagnostic : Diagnostic? = nil,
                   @extended_security_presence : ExtendedSecurityPresence? = nil)
      @entries = entries.dup
    end

    def diagnostics : Array(Diagnostic)
      diagnostic = @diagnostic
      diagnostic ? [diagnostic] : [] of Diagnostic
    end

    def entries : Array(Ace)
      @entries.dup
    end

    def complete? : Bool
      return false unless @diagnostic.nil? && @entries.size <= Constants::ACL_MAX_ENTRIES
      case @status
      when Status::Absent  then @entries.empty? && @acl_flags == 0
      when Status::Empty   then @entries.empty?
      when Status::Present then !@entries.empty?
      else                      false
      end
    end

    def nonempty? : Bool
      @status.present? && !@entries.empty?
    end
  end
end
