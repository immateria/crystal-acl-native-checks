# Darwin root admission policy. Return an unowned fd to Directory, which
# adopts or closes it. Ordinary admission follows links, the last component's
# too, and holds the folder reached; the strict form opens every component
# through a no-follow parent fd. A folder that refuses a read open with
# EACCES is retried as an O_SEARCH reference, as Linux retries one as an
# O_PATH reference (macOS parity design §3.2), so a search-only folder can
# be a root.
{% skip_file unless flag?(:darwin) %}

module Filesystem::Capabilities::Directory::Darwin::RootAdmission
  def self.open_ordinary(path : Path) : Int32
    RootPath.validate_existing(path)
    fd = LibC.open(path.to_s, Directory::ROOT_FLAGS)
    fd = LibC.open(path.to_s, Directory::SEARCH_FLAGS) if fd < 0 && Errno.value == Errno::EACCES
    raise Directory::EntryError.new(:open_root, path.to_s, Errno.value) if fd < 0
    fd
  end

  def self.open_no_symlinks(path : Path) : Int32
    names = RootPath.components(path)
    fd = LibC.open("/", Directory::DIRECTORY_FLAGS)
    raise Directory::EntryError.new(:open_root, "/", Errno.value) if fd < 0
    begin
      names.each do |part|
        next_fd = Filesystem::Capabilities::Native::Darwin::At.openat(fd, part,
          Directory::DIRECTORY_FLAGS, 0)
        if next_fd < 0 && Errno.value == Errno::EACCES
          next_fd = Filesystem::Capabilities::Native::Darwin::At.openat(fd, part,
            Directory::SEARCH_FLAGS | LibC::O_NOFOLLOW, 0)
        end
        if next_fd < 0
          raise Directory::EntryError.new(:open_root_component, part, Errno.value)
        end
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
