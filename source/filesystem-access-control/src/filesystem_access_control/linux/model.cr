require "set"

module Filesystem::AccessControl::Linux
  @[Flags]
  enum Permissions : UInt8
    Execute = 1
    Write   = 2
    Read    = 4
  end

  enum Tag : UInt16
    Owner       = 0x01
    User        = 0x02
    OwningGroup = 0x04
    Group       = 0x08
    Mask        = 0x10
    Other       = 0x20
  end

  enum ACLKind
    Access
    Default

    def key : String
      access? ? "system.posix_acl_access" : "system.posix_acl_default"
    end
  end

  enum Reason
    MalformedACL
    ModeMismatch
    Unsupported
    NativeError
    ObservationChanged
    WrongKind
    IdentityMismatch
    IncompleteCapture
    ReadbackFailed
    ReadbackMismatch
  end

  record Diagnostic, reason : Reason, message : String, errno : Int32? = nil,
    acl_kind : ACLKind? = nil

  struct Entry
    getter tag : Tag
    getter permissions : Permissions
    getter id : UInt32?

    def initialize(@tag : Tag, @permissions : Permissions, @id : UInt32? = nil)
      raise ArgumentError.new("Unknown ACL tag") unless Tag.values.includes?(@tag)
      raise ArgumentError.new("ACL permissions must be rwx bits") if @permissions.value > 7
      named = @tag.user? || @tag.group?
      raise ArgumentError.new("Only named users and groups require an ID") unless named == !@id.nil?
      raise ArgumentError.new("Invalid ACL qualifier") if @id == UInt32::MAX
    end

    def self.user(uid : UInt32, permissions : Permissions) : Entry
      new(Tag::User, permissions, uid)
    end

    def self.group(gid : UInt32, permissions : Permissions) : Entry
      new(Tag::Group, permissions, gid)
    end

    def_equals_and_hash @tag, @permissions, @id

    def to_s(io : IO) : Nil
      label = case @tag
              when .owner?, .user?         then "user"
              when .owning_group?, .group? then "group"
              when .mask?                  then "mask"
              else                              "other"
              end
      io << label << ':'
      io << @id if @id
      io << ':' << (@permissions.read? ? 'r' : '-') << (@permissions.write? ? 'w' : '-') << (@permissions.execute? ? 'x' : '-')
    end
  end

  # An immutable, structurally valid POSIX ACL. Entries retain their order.
  # Numeric qualifiers belong to the caller's current user namespace.
  class ACL
    @entries : Array(Entry)

    def initialize(entries : Array(Entry))
      @entries = entries.dup
      validate!
    end

    def entries : Array(Entry)
      @entries.dup
    end

    def find(tag : Tag, id : UInt32? = nil) : Entry?
      @entries.find { |entry| entry.tag == tag && entry.id == id }
    end

    def self.from_mode(mode : Int32) : ACL
      new([Entry.new(Tag::Owner, Permissions.new(((mode >> 6) & 7).to_u8)),
           Entry.new(Tag::OwningGroup, Permissions.new(((mode >> 3) & 7).to_u8)),
           Entry.new(Tag::Other, Permissions.new((mode & 7).to_u8))])
    end

    def mode_bits : Int32
      (find(Tag::Owner).not_nil!.permissions.value.to_i << 6) |
        ((find(Tag::Mask) || find(Tag::OwningGroup)).not_nil!.permissions.value.to_i << 3) |
        find(Tag::Other).not_nil!.permissions.value.to_i
    end

    def named? : Bool
      @entries.any? { |entry| entry.tag.user? || entry.tag.group? }
    end

    def masked_permissions(entry : Entry) : Permissions
      if entry.tag.user? || entry.tag.owning_group? || entry.tag.group?
        entry.permissions & (find(Tag::Mask).try(&.permissions) || Permissions::All)
      else
        entry.permissions
      end
    end

    def ==(other : ACL) : Bool
      @entries == other.entries
    end

    def to_s(io : IO) : Nil
      @entries.join(io, '\n')
    end

    private def validate! : Nil
      last = 0_u16
      seen = Set(Tuple(Tag, UInt32?)).new
      @entries.each do |entry|
        key = {entry.tag, entry.id}
        raise ArgumentError.new("Duplicate ACL entry") unless seen.add?(key)
        raise ArgumentError.new("ACL entries are out of order") if entry.tag.value < last
        last = entry.tag.value
      end
      [Tag::Owner, Tag::OwningGroup, Tag::Other].each do |tag|
        raise ArgumentError.new("ACL is missing #{tag}") unless find(tag)
      end
      raise ArgumentError.new("Named ACL entries require a mask") if named? && !find(Tag::Mask)
    end
  end

  record ParseResult, acl : ACL?, diagnostic : Diagnostic?
end
