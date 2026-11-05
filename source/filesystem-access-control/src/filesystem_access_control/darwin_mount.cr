{% skip_file unless flag?(:darwin) %}

# Darwin's statfs64 layout from the public sys/mount.h. Keep this native
# representation behind the ACL owner; providers never inspect it directly.
@[Link("c")]
lib Filesystem::AccessControl::Native::Darwin::Mount
  struct Statfs
    block_size : UInt32
    io_size : Int32
    blocks : UInt64
    blocks_free : UInt64
    blocks_available : UInt64
    files : UInt64
    files_free : UInt64
    filesystem_id : StaticArray(Int32, 2)
    mount_owner : UInt32
    filesystem_type : UInt32
    flags : UInt32
    subtype : UInt32
    type_name : StaticArray(UInt8, 16)
    mount_point : StaticArray(UInt8, 1024)
    source : StaticArray(UInt8, 1024)
    extended_flags : UInt32
    reserved : StaticArray(UInt32, 7)
  end

  {% if flag?(:x86_64) %}
    fun fstatfs = "fstatfs$INODE64"(fd : Int32, info : Statfs*) : Int32
  {% else %}
    fun fstatfs(fd : Int32, info : Statfs*) : Int32
  {% end %}
end

module Filesystem::AccessControl
  private def self.darwin_mount_error(fd : Int32) : String?
    if Native::Darwin::Mount.fstatfs(fd, out filesystem) != 0
      "Unable to inspect filesystem ownership policy: #{Errno.value}"
    elsif (filesystem.flags & 0x00200000_u32) != 0 # MNT_IGNORE_OWNERSHIP
      "Filesystem ignores ownership; private access cannot be established"
    end
  end
end
