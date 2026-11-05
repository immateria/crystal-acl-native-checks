require "./model"

module Filesystem::AccessControl::Darwin
  # Apple's public acl_copy_int/ext representation (kauth_filesec). This is a
  # bounded value codec; native allocation and permission policy live elsewhere.
  module ExternalACL
    MAGIC        = 0x012cc16d_u32
    HEADER_SIZE  =             44
    ENTRY_SIZE   =             24
    COUNT_OFFSET =             36
    FLAGS_OFFSET =             40
    MAX_SIZE     = HEADER_SIZE + ENTRY_SIZE * Constants::ACL_MAX_ENTRIES

    def self.encode(entries : Array(Ace), flags : UInt32) : Bytes
      raise ArgumentError.new("ACL exceeds the native entry limit") if entries.size > Constants::ACL_MAX_ENTRIES
      external = Bytes.new(HEADER_SIZE + entries.size * ENTRY_SIZE, 0_u8)
      write_be32(external, 0, MAGIC)
      write_be32(external, COUNT_OFFSET, entries.size.to_u32)
      write_be32(external, FLAGS_OFFSET, flags)
      entries.each_with_index do |ace, index|
        base = HEADER_SIZE + index * ENTRY_SIZE
        ace.principal.uuid.each_with_index { |byte, i| external[base + i] = byte }
        write_be32(external, base + 16, ace.raw_tag | ace.raw_flags)
        write_be32(external, base + 20, ace.rights.to_u32)
      end
      external
    end

    def self.uuid_at(bytes : Bytes, ordinal : Int32) : StaticArray(UInt8, 16)
      unless bytes.size >= HEADER_SIZE && bytes.size <= MAX_SIZE
        raise ArgumentError.new("ACL external size is invalid or exceeds 128 entries")
      end
      unless read_be32(bytes, 0) == MAGIC
        raise ArgumentError.new("ACL external representation has an invalid KAUTH_FILESEC_MAGIC")
      end
      count = read_be32(bytes, COUNT_OFFSET)
      unless count <= Constants::ACL_MAX_ENTRIES && bytes.size == HEADER_SIZE + count.to_i64 * ENTRY_SIZE
        raise ArgumentError.new("ACL external entry count or size is inconsistent")
      end
      if ordinal < 0 || ordinal >= count
        raise ArgumentError.new("ACL external entry ordinal is out of range")
      end
      base = HEADER_SIZE + ordinal * ENTRY_SIZE
      StaticArray(UInt8, 16).new { |index| bytes[base + index] }
    end

    private def self.read_be32(bytes : Bytes, offset : Int32) : UInt32
      (bytes[offset].to_u32 << 24) | (bytes[offset + 1].to_u32 << 16) |
        (bytes[offset + 2].to_u32 << 8) | bytes[offset + 3].to_u32
    end

    private def self.write_be32(bytes : Bytes, offset : Int32, value : UInt32) : Nil
      bytes[offset] = (value >> 24).to_u8
      bytes[offset + 1] = ((value >> 16) & 0xff).to_u8
      bytes[offset + 2] = ((value >> 8) & 0xff).to_u8
      bytes[offset + 3] = (value & 0xff).to_u8
    end
  end
end
