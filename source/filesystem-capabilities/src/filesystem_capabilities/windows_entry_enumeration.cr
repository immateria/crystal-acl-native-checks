# Independent HANDLE-based Windows listing. The scan needs a file object of
# its own: a duplicated root HANDLE would share the root's enumeration
# position. An NT open relative to the root with an empty name opens that
# same directory again, resolving no name. ReOpenFile, used before, refuses
# every directory HANDLE on build 17763 with ERROR_ACCESS_DENIED, while this
# open and a listing through it succeed (2026-11-02; the workspace's
# docs/design/windows-17763/results/2026-11-02/4-reopen_directory_probe.txt).
{% skip_file unless flag?(:windows) %}

module Filesystem::Capabilities::Directory::EntryEnumeration
  LIST_ACCESS          = 0x00100081_u32
  NAME_BUFFER_BYTES    = 128 * 1024
  STATUS_NO_MORE_FILES = -2147483642_i32

  def self.open(root : Pointer(Void), name : String) : Pointer(Void)
    Windows::EntryResolution.open_relative(root, "", name, :list_entries, :directory, LIST_ACCESS)
  end

  def self.each(scan : Pointer(Void), name : String, & : String ->) : Nil
    cursor = nil.as(Directory::EntryScan?)
    begin
      storage = Slice(UInt64).new(NAME_BUFFER_BYTES // 8, 0_u64)
      cursor = Directory::EntryScan.new(scan, name, storage)
      while part = cursor.next
        yield part
      end
    ensure
      if cursor
        cursor.close
      else
        LibC.CloseHandle(scan)
      end
    end
  end
end

# Owns a separately opened scan HANDLE; never shares the root's directory
# enumeration offset. Always close explicitly in `ensure` after use.
# A scanner owns its independent HANDLE. Advancing it and explicitly closing
# it are serialized, while GC finalization uses nonblocking atomic claiming.
class Filesystem::Capabilities::Directory
  class EntryScan
    @scan : RootLease(Pointer(Void))
    @storage : Slice(UInt64)

    protected def initialize(scan : Pointer(Void), @name : String,
                             @storage : Slice(UInt64))
      lease = begin
        RootLease.new(scan, Pointer(Void).null)
      rescue error
        LibC.CloseHandle(scan)
        raise error
      end
      @scan = lease
    end

    def next : String?
      @scan.lock do |scan|
        raise Filesystem::Capabilities::ClosedError.new("Directory entry scan is closed") if scan.null?
        payload = @storage.to_unsafe.as(Pointer(UInt8))
        loop do
          ios = LibC::IO_STATUS_BLOCK.new
          status = Filesystem::Capabilities::Native::Windows::Nt.NtQueryDirectoryFile(
            scan, Pointer(Void).null, Pointer(Void).null, Pointer(Void).null,
            pointerof(ios), payload.as(Void*), EntryEnumeration::NAME_BUFFER_BYTES.to_u32,
            12, 1_u8, Pointer(LibC::UNICODE_STRING).null, 0_u8)
          break nil if status == EntryEnumeration::STATUS_NO_MORE_FILES
          raise Directory::EntryError.new(:list_entries, @name, status) unless status == 0
          used = ios.information.address.to_u64
          if used > EntryEnumeration::NAME_BUFFER_BYTES
            raise Filesystem::Capabilities::Error.new("Invalid Windows directory listing record size")
          end
          record = Slice(UInt8).new(payload, used.to_i)
          if name = Filesystem::Capabilities::WindowsDirectoryRecords.decode_single(record, used.to_i)
            break name
          end
        end
      end
    end

    def close : Nil
      @scan.close { |scan| LibC.CloseHandle(scan) }
    end

    def closed? : Bool
      @scan.closed?
    end

    def finalize
      @scan.release_on_finalization { |scan| LibC.CloseHandle(scan) }
    end
  end
end
