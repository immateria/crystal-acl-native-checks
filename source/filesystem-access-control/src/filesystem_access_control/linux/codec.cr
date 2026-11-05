require "./model"

module Filesystem::AccessControl::Linux::Codec
  # Linux posix_acl_xattr version 2, independent of host byte order.
  def self.decode(bytes : Bytes, *, mode : Int32? = nil, kind : ACLKind = ACLKind::Access) : ParseResult
    unless bytes.size >= 4 && (bytes.size - 4) % 8 == 0 && u32(bytes, 0) == 2
      return malformed("Invalid ACL header or length", kind)
    end
    entries = [] of Entry
    offset = 4
    while offset < bytes.size
      raw_tag = u16(bytes, offset)
      tag = Tag.from_value?(raw_tag)
      return malformed("Unknown ACL tag #{raw_tag}", kind) unless tag
      rights = u16(bytes, offset + 2)
      return malformed("Invalid ACL permission bits", kind) if rights > 7
      id = tag.user? || tag.group? ? u32(bytes, offset + 4) : nil
      entries << Entry.new(tag, Permissions.new(rights.to_u8), id)
      offset += 8
    end
    acl = ACL.new(entries)
    if mode && acl.mode_bits != mode & 0o777
      return ParseResult.new(nil, Diagnostic.new(Reason::ModeMismatch, "ACL disagrees with mode #{mode.to_s(8)}", acl_kind: kind))
    end
    ParseResult.new(acl, nil)
  rescue error : ArgumentError
    malformed(error.message || "Invalid ACL", kind)
  end

  def self.encode(acl : ACL) : Bytes
    entries = acl.entries
    bytes = Bytes.new(4 + entries.size * 8, 0_u8)
    put32(bytes, 0, 2_u32)
    entries.each_with_index do |entry, index|
      offset = 4 + index * 8
      put16(bytes, offset, entry.tag.value)
      put16(bytes, offset + 2, entry.permissions.value.to_u16)
      put32(bytes, offset + 4, entry.id || UInt32::MAX)
    end
    bytes
  end

  private def self.malformed(message : String, kind : ACLKind) : ParseResult
    ParseResult.new(nil, Diagnostic.new(Reason::MalformedACL, message, acl_kind: kind))
  end

  private def self.u16(bytes : Bytes, at : Int32) : UInt16
    bytes[at].to_u16 | (bytes[at + 1].to_u16 << 8)
  end

  private def self.u32(bytes : Bytes, at : Int32) : UInt32
    u16(bytes, at).to_u32 | (u16(bytes, at + 2).to_u32 << 16)
  end

  private def self.put16(bytes : Bytes, at : Int32, value : UInt16) : Nil
    2.times { |index| bytes[at + index] = ((value >> (8 * index)) & 255).to_u8 }
  end

  private def self.put32(bytes : Bytes, at : Int32, value : UInt32) : Nil
    4.times { |index| bytes[at + index] = ((value >> (8 * index)) & 255).to_u8 }
  end
end
