# Linux root-path admission. Produces an unowned descriptor; the Directory
# constructor adopts it only after successful initialization. The validator
# for path grammar remains RootPath (including exact / and terminal-component
# restrictions). Ordinary roots follow links, the last component's too, and
# hold the folder reached; strict roots may have no link anywhere.
{% skip_file unless flag?(:linux) %}

module Filesystem::Capabilities::Directory::Linux::RootAdmission
  def self.open_ordinary(path : Path) : Int32
    RootPath.validate_existing(path)
    readable_flags = LibC::O_RDONLY | LibC::O_CLOEXEC | Platform::DIRECTORY_ONLY
    fd = LibC.open(path.to_s, readable_flags)
    if fd < 0 && Errno.value == Errno::EACCES
      reference_flags = Platform::PATH_REFERENCE | LibC::O_CLOEXEC | Platform::DIRECTORY_ONLY
      fd = LibC.open(path.to_s, reference_flags)
    end
    raise Directory::EntryError.new(:open_root, path.to_s, Errno.value) if fd < 0
    fd
  end

  def self.open_no_symlinks(path : Path) : Int32
    names = RootPath.components(path)
    readable_flags = LibC::O_RDONLY | LibC::O_CLOEXEC |
                     LibC::O_NOFOLLOW | Platform::DIRECTORY_ONLY
    reference_flags = Platform::PATH_REFERENCE | LibC::O_CLOEXEC |
                      LibC::O_NOFOLLOW | Platform::DIRECTORY_ONLY
    fd = LibC.open("/", readable_flags)
    raise Directory::EntryError.new(:open_root, "/", Errno.value) if fd < 0
    begin
      names.each_with_index do |part, index|
        final_component = index == names.size - 1
        next_fd = Native::Linux::At.openat(fd, part,
          final_component ? readable_flags : reference_flags, 0)
        if next_fd < 0 && final_component && Errno.value == Errno::EACCES
          next_fd = Native::Linux::At.openat(fd, part, reference_flags, 0)
        end
        raise Directory::EntryError.new(:open_root_component, part, Errno.value) if next_fd < 0
        LibC.close(fd)
        fd = next_fd
      end
      fd
    rescue error
      LibC.close(fd)
      raise error
    end
  end
end
