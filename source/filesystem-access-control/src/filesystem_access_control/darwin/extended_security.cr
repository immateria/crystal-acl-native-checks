require "./external_acl"

module Filesystem::AccessControl::Darwin
  # Decoder for the bounded ATTR_CMN_RETURNED_ATTRS | EXTENDED_SECURITY
  # response on supported little-endian Darwin targets. Unlike acl_get_fd_np,
  # this representation retains an empty ACL's header flags.
  class ExtendedSecurity
    RETURNED = 0x8000_0000_u32
    SECURITY = 0x0040_0000_u32
    MAX_SIZE = 32 + ExternalACL::MAX_SIZE

    getter presence : ExtendedSecurityPresence
    getter acl_flags : UInt32
    @entries : Array(Ace)

    private def initialize(@presence, @acl_flags = 0_u32, @entries = [] of Ace)
    end

    def entries : Array(Ace)
      @entries.dup
    end

    def self.decode(bytes : Bytes) : ExtendedSecurity
      invalid! unless bytes.size >= 24
      length = word(bytes, 0).to_i64
      invalid! unless 24 <= length <= bytes.size && length <= MAX_SIZE
      common = word(bytes, 4)
      invalid! unless (common & RETURNED) != 0 && (common & ~(RETURNED | SECURITY)) == 0
      invalid! unless bytes[8, 16].all?(&.zero?)
      if (common & SECURITY) == 0
        # XNU may retain the unused fixed attrreference slot in the length.
        invalid! unless length == 24 || (length == 32 && bytes[24, 8].all?(&.zero?))
        return new(ExtendedSecurityPresence::NotReturned)
      end
      invalid! unless length >= 32
      relative = word(bytes, 24).to_i64
      size = word(bytes, 28).to_i64
      offset = 24_i64 + relative
      invalid! unless 8 <= relative <= Int32::MAX && relative % 4 == 0 &&
                      size >= ExternalACL::HEADER_SIZE && offset + size <= length
      payload = bytes[offset.to_i, size.to_i]
      invalid! unless word(payload, 0) == ExternalACL::MAGIC
      # Owner/group UUIDs are not requested by this query.
      invalid! unless payload[4, 32].all?(&.zero?)
      count = word(payload, ExternalACL::COUNT_OFFSET)
      flags = word(payload, ExternalACL::FLAGS_OFFSET)
      if count == UInt32::MAX
        invalid! unless size == ExternalACL::HEADER_SIZE
        return new(ExtendedSecurityPresence::Absent, flags)
      end
      invalid! unless count <= Constants::ACL_MAX_ENTRIES &&
                      size == ExternalACL::HEADER_SIZE + count.to_i64 * ExternalACL::ENTRY_SIZE
      entries = Array(Ace).new(count.to_i) do |ordinal|
        base = ExternalACL::HEADER_SIZE + ordinal * ExternalACL::ENTRY_SIZE
        uuid = StaticArray(UInt8, 16).new { |i| payload[base + i] }
        tag_flags = word(payload, base + 16)
        Ace.new(ordinal, Principal.new(uuid), tag_flags & 0xf_u32,
          word(payload, base + 20).to_u64, tag_flags & ~0xf_u32)
      end
      new(ExtendedSecurityPresence::Present, flags, entries)
    end

    private def self.word(bytes : Bytes, offset : Int32) : UInt32
      IO::ByteFormat::LittleEndian.decode(UInt32, bytes[offset, 4])
    end

    private def self.invalid! : NoReturn
      raise ArgumentError.new("Malformed or oversized extended-security attribute response")
    end
  end
end
