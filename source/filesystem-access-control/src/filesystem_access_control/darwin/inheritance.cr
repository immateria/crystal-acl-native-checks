{% skip_file unless flag?(:darwin) %}

require "./model"

module Filesystem::AccessControl::Darwin
  module Inheritance
    enum Status
      Projected
      NoACL
      Indeterminate
    end

    # `present: false` means no explicit initial ACL was supplied. A present,
    # zero-entry ACL is distinct and remains an empty ACL after projection.
    class InitialACL
      getter present : Bool
      getter acl_flags : UInt32

      def initialize(@present : Bool, entries : Array(Ace), @acl_flags : UInt32 = 0_u32)
        raise ArgumentError.new("An ACL cannot contain more than 128 entries") if entries.size > Constants::ACL_MAX_ENTRIES
        raise ArgumentError.new("An absent initial ACL cannot contain entries or header flags") if !@present && (!entries.empty? || @acl_flags != 0)
        @entries = Ace.reindex(entries)
      end

      def self.absent : InitialACL
        new(false, [] of Ace)
      end

      def self.empty(acl_flags : UInt32 = 0_u32) : InitialACL
        new(true, [] of Ace, acl_flags)
      end

      def entries : Array(Ace)
        @entries.dup
      end
    end

    class Projection
      getter status : Status
      getter acl_flags : UInt32?
      getter detail : String?
      @entries : Array(Ace)

      def initialize(@status : Status, entries : Array(Ace), @acl_flags : UInt32?, @detail : String? = nil)
        @entries = Ace.reindex(entries)
      end

      def entries : Array(Ace)
        @entries.dup
      end

      def complete? : Bool
        @status.projected? || @status.no_acl?
      end
    end

    DEFER_INHERIT_PUBLIC = Constants::ACL_FLAG_DEFER_INHERIT
    DEFER_INHERIT_KERNEL = Constants::ACL_FLAG_DEFER_INHERIT_KERNEL

    # Project one generation using the matched XNU ordering and ACE flag
    # transformation. Native creation remains the authority for a filesystem.
    def self.project(parent : Snapshot, child_kind : Kind,
                     initial : InitialACL = InitialACL.absent) : Projection
      unless child_kind.file? || child_kind.directory?
        return Projection.new(Status::Indeterminate, [] of Ace, nil,
          "Inheritance is modeled only for regular files and directories")
      end
      if parent.mount.try(&.server_authorized?)
        return Projection.new(Status::Indeterminate, [] of Ace, nil,
          "Server inheritance is not established by a client ACL snapshot")
      end
      # XNU 11417.101.15 defines kernel bit 16 and libc exposes public bit 0.
      # Neither is read by kauth_acl_inherit. Keep both distinct in snapshots;
      # neither changes this reference composition. A remote server may differ.
      deferred = DEFER_INHERIT_PUBLIC | DEFER_INHERIT_KERNEL
      initial_entries = initial.entries
      parent_entries = parent.entries
      suppress_parent = initial.present &&
                        (initial.acl_flags & Constants::ACL_FLAG_NO_INHERIT) != 0
      if initial_entries.size > Constants::ACL_MAX_ENTRIES || (!suppress_parent && parent_entries.size > Constants::ACL_MAX_ENTRIES)
        return Projection.new(Status::Indeterminate, [] of Ace, nil,
          "Native ACL entry limit is 128")
      end
      relevant_header_flags = initial.acl_flags
      relevant_header_flags |= parent.acl_flags unless suppress_parent
      unless suppress_parent ||
             parent.complete?
        return Projection.new(Status::Indeterminate, [] of Ace, nil,
          "Parent ACL observation is incomplete or unsupported")
      end

      known_flags = Constants::ACL_ENTRY_FLAGS
      unknown_initial = initial_entries.any? { |ace| (ace.raw_flags & ~known_flags) != 0 || ace.effect.nil? }
      unknown_parent = !suppress_parent && parent_entries.any? { |ace| (ace.raw_flags & ~known_flags) != 0 || ace.effect.nil? }
      if (relevant_header_flags & ~(Constants::ACL_FLAG_NO_INHERIT | deferred)) != 0 ||
         unknown_initial || unknown_parent
        return Projection.new(Status::Indeterminate, [] of Ace, nil,
          "Unknown ACL flags or ACE kinds prevent a complete inheritance projection")
      end

      # The native allocator receives the initial count before inherited
      # initial ACEs are filtered. An oversized allocation cannot be modeled
      # as a successful smaller result.
      allocation_count = initial_entries.size
      unless suppress_parent
        allocation_count += parent_entries.count do |ace|
          child_kind.directory? ? ace.directory_inherit? : ace.file_inherit?
        end
      end
      if allocation_count > Constants::ACL_MAX_ENTRIES
        return Projection.new(Status::Indeterminate, [] of Ace, nil,
          "Native composition allocation exceeds the limit of 128 entries")
      end

      result = [] of Ace
      if initial.present
        initial_entries.each do |ace|
          # The kernel copies only direct initial entries; caller-supplied
          # entries already marked inherited are discarded.
          result << ace unless ace.inherited?
        end
      end

      unless suppress_parent
        parent_entries.each do |ace|
          inherits = child_kind.directory? ? ace.directory_inherit? : ace.file_inherit?
          next unless inherits

          flags = ace.raw_flags | Constants::ACL_ENTRY_INHERITED
          flags &= ~Constants::ACL_ENTRY_ONLY_INHERIT
          if ace.limit_inherit? || child_kind.file?
            flags &= ~(Constants::ACL_ENTRY_FILE_INHERIT |
                       Constants::ACL_ENTRY_DIRECTORY_INHERIT |
                       Constants::ACL_ENTRY_LIMIT_INHERIT |
                       Constants::ACL_ENTRY_ONLY_INHERIT)
          end
          result << Ace.new(result.size.to_i32, ace.principal, ace.raw_tag, ace.rights, flags)
        end
      end

      if result.empty? && !initial.present
        return Projection.new(Status::NoACL, result, nil)
      end
      if result.size > Constants::ACL_MAX_ENTRIES
        return Projection.new(Status::Indeterminate, [] of Ace, nil,
          "Inherited and explicit entries exceed the native limit of 128")
      end

      # kauth_acl_alloc uses Z_ZERO and composition copies only ACEs. Header
      # controls from either input are consumed, not copied to the product.
      Projection.new(Status::Projected, result, 0_u32)
    end
  end
end
