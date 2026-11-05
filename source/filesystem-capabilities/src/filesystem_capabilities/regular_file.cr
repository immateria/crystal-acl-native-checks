# Unix regular-file descriptor verification and ownership transfer. Linux
# and Darwin use the same fstat/type requirement: neither accepts directory,
# FIFO, device, socket or symlink handles as opened file contents. Ownership
# transfers to IO::FileDescriptor only after this check succeeds.
{% skip_file unless flag?(:linux) || flag?(:darwin) %}

module Filesystem::Capabilities::Directory::RegularFile
  def self.take(fd : Int32, name : String) : IO::FileDescriptor
    begin
      unless LibC.fstat(fd, out info) == 0 && (info.st_mode & LibC::S_IFMT) == LibC::S_IFREG
        raise Filesystem::Capabilities::Error.new("Confined entry is not a regular file: #{name.inspect}")
      end
      IO::FileDescriptor.new(fd)
    rescue error
      LibC.close(fd)
      raise error
    end
  end
end
