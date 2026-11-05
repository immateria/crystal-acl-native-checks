# Compare retained directory handles by native filesystem identity without
# exposing raw descriptors/HANDLEs or importing the metadata provider.
{% skip_file unless flag?(:linux) || flag?(:darwin) || flag?(:windows) %}

{% if flag?(:windows) %}
  require "c/fileapi"
  require "c/handleapi"
{% end %}

class Filesystem::Capabilities::Directory
  # Native identity cannot change while this retained directory handle remains
  # open. Cache the first successful lookup under the existing descriptor lock
  # so repeated peer comparisons do not re-query the kernel. The cache is never
  # consulted before the closed-handle check.
  @native_identity_cache : Tuple(UInt64, UInt64)? = nil

  {% if flag?(:directories_identity_test_probe) %}
    @@native_identity_probe_count = ::Atomic(Int32).new(0)

    def self.reset_native_identity_probe_count : Nil
      @@native_identity_probe_count.set(0)
    end

    def self.native_identity_probe_count : Int32
      @@native_identity_probe_count.get
    end
  {% end %}

  # True when both independently owned handles refer to the same opened
  # directory object. This compares native device/volume + file identity;
  # it does not reopen either display path and does not imply ancestry.
  def same_directory?(other : Directory) : Bool
    identity == other.identity
  end

  # The opened folder's native identity: device and inode on Unix, volume
  # serial number and file index on Windows. An observation a caller may
  # record, to compare with later; it is no authority to open anything.
  def identity : Tuple(UInt64, UInt64)
    @descriptor.lock do |root|
      {% if flag?(:linux) || flag?(:darwin) %}
        raise Filesystem::Capabilities::ClosedError.new("Directory capability handle is closed") if root < 0
      {% else %}
        raise Filesystem::Capabilities::ClosedError.new("Directory capability handle is closed") if root.null?
      {% end %}

      if cached = @native_identity_cache
        cached
      else
        {% if flag?(:directories_identity_test_probe) %}
          @@native_identity_probe_count.add(1)
        {% end %}
        identity = {% if flag?(:linux) || flag?(:darwin) %}
                     info = uninitialized LibC::Stat
                     unless LibC.fstat(root, pointerof(info)) == 0
                       raise EntryError.new(:directory_identity, @path.to_s, Errno.value)
                     end
                     {info.st_dev.to_u64!, info.st_ino.to_u64!}
                   {% else %}
                     info = uninitialized LibC::BY_HANDLE_FILE_INFORMATION
                     if LibC.GetFileInformationByHandle(root, pointerof(info)) == 0
                       raise EntryError.new(:directory_identity, @path.to_s)
                     end
                     file_id = (info.nFileIndexHigh.to_u64 << 32) | info.nFileIndexLow.to_u64
                     {info.dwVolumeSerialNumber.to_u64, file_id}
                   {% end %}
        @native_identity_cache = identity
        identity
      end
    end
  end
end
