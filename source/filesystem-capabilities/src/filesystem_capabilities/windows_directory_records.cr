# Platform-neutral decoder for the Windows FILE_NAMES_INFORMATION single-record
# output used by NtQueryDirectoryFile with ReturnSingleEntry. Native ABI/IO
# remains owned by the Windows Directory backend.
module Filesystem::Capabilities::WindowsDirectoryRecords
  HEADER_BYTES     = 12
  MAX_BUFFER_BYTES = 128 * 1024

  def self.read_u32_le(data : Bytes, offset : Int32) : UInt32
    (data[offset].to_u32 | (data[offset + 1].to_u32 << 8) |
      (data[offset + 2].to_u32 << 16) | (data[offset + 3].to_u32 << 24))
  end

  # Returns nil for '.' and '..'. Reject malformed, truncated, oversized,
  # chained, invalid UTF-16 or ill-formed names without attempting a lookup.
  def self.decode_single(data : Bytes, used : Int32) : String?
    unless used >= HEADER_BYTES && used <= data.size && used <= MAX_BUFFER_BYTES
      raise Filesystem::Capabilities::Error.new("Invalid Windows directory listing record size")
    end
    next_offset = read_u32_le(data, 0)
    length = read_u32_le(data, 8)
    unless next_offset == 0 && length > 0 && length.even? &&
           length <= used - HEADER_BYTES
      raise Filesystem::Capabilities::Error.new("Malformed Windows directory listing record")
    end
    units = Slice(UInt16).new((length // 2).to_i) do |index|
      offset = HEADER_BYTES + index * 2
      (data[offset].to_u16 | (data[offset + 1].to_u16 << 8))
    end
    name = String.from_utf16(units)
    unless name.to_utf16 == units
      raise Filesystem::Capabilities::Error.new("Windows directory entry has invalid UTF-16")
    end
    return nil if name == "." || name == ".."
    name
  end
end
