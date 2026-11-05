{% skip_file unless flag?(:darwin) %}

require "./model"

module Filesystem::AccessControl::Darwin
  # A replacement value is intentionally distinct from removal and from an
  # absent ACL. An empty replacement can carry header flags.
  class DesiredACL
    getter acl_flags : UInt32

    def initialize(entries : Array(Ace), @acl_flags : UInt32)
      raise ArgumentError.new("An ACL cannot contain more than 128 entries") if entries.size > Constants::ACL_MAX_ENTRIES
      @entries = Ace.reindex(entries)
    end

    def entries : Array(Ace)
      @entries.dup
    end
  end

  # Immutable ordered edit sequence. Every operation returns a fresh builder;
  # duplicates and the position of untouched entries are retained.
  class Builder
    getter acl_flags : UInt32
    @entries : Array(Ace)

    def self.from(snapshot : Snapshot) : Builder
      raise ArgumentError.new("Cannot build from an incomplete ACL observation") unless snapshot.complete?
      new(snapshot.entries, snapshot.acl_flags)
    end

    def self.empty(acl_flags : UInt32 = 0_u32) : Builder
      new([] of Ace, acl_flags)
    end

    def initialize(entries : Array(Ace), @acl_flags : UInt32)
      raise ArgumentError.new("An ACL cannot contain more than 128 entries") if entries.size > Constants::ACL_MAX_ENTRIES
      @entries = Ace.reindex(entries)
    end

    def entries : Array(Ace)
      @entries.dup
    end

    def with_inserted(at : Int32, ace : Ace) : Builder
      unless at >= 0 && at <= @entries.size
        raise IndexError.new("ACL insertion ordinal is outside the current sequence")
      end
      values = @entries.dup
      values.insert(at, ace)
      self.class.new(values, @acl_flags)
    end

    def without(at : Int32) : Builder
      check_index(at)
      values = @entries.dup
      values.delete_at(at)
      self.class.new(values, @acl_flags)
    end

    def with_replaced(at : Int32, ace : Ace) : Builder
      check_index(at)
      values = @entries.dup
      values[at] = ace
      self.class.new(values, @acl_flags)
    end

    # `order` is a full permutation of current sequence indexes. It does not
    # sort by principal, effect or rights.
    def with_order(order : Array(Int32)) : Builder
      unless order.size == @entries.size && order.sort == (0...@entries.size).to_a
        raise ArgumentError.new("ACL reorder must be a permutation of every current ordinal")
      end
      self.class.new(order.map { |index| @entries[index] }, @acl_flags)
    end

    def with_rights(at : Int32, rights : UInt64) : Builder
      current = entry_at(at)
      with_replaced(at, Ace.new(at, current.principal, current.raw_tag, rights, current.raw_flags))
    end

    def with_flags(at : Int32, flags : UInt32) : Builder
      current = entry_at(at)
      with_replaced(at, Ace.new(at, current.principal, current.raw_tag, current.rights, flags))
    end

    def with_tag(at : Int32, raw_tag : UInt32) : Builder
      current = entry_at(at)
      with_replaced(at, Ace.new(at, current.principal, raw_tag, current.rights, current.raw_flags))
    end

    def with_principal(at : Int32, principal : Principal) : Builder
      current = entry_at(at)
      with_replaced(at, Ace.new(at, principal, current.raw_tag, current.rights, current.raw_flags))
    end

    def with_acl_flags(flags : UInt32) : Builder
      self.class.new(@entries, flags)
    end

    def build : DesiredACL
      DesiredACL.new(@entries, @acl_flags)
    end

    private def entry_at(at : Int32) : Ace
      check_index(at)
      @entries[at]
    end

    private def check_index(at : Int32) : Nil
      unless at >= 0 && at < @entries.size
        raise IndexError.new("ACL ordinal is outside the current sequence")
      end
    end
  end
end
