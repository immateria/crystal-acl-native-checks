module Filesystem::AccessControl
  # Inspect an existing directory by opening it without following a final
  # symlink. On Linux use inspect_fd for a pre-opened retained capability.
  def self.inspect_directory(path : Path) : Report
    # No-follow applies to the last resolved component only. A trailing slash,
    # "." or ".." can turn a final symlink into an intermediate component.
    # Share the existing-root lexical contract with capability admission.
    Filesystem::Capabilities::RootPath.validate_existing(path)
    {% if flag?(:linux) %}
      fd = LibC.open(path.to_s, LibC::O_RDONLY | LibC::O_CLOEXEC | LibC::O_NOFOLLOW | Filesystem::Capabilities::Platform::DIRECTORY_ONLY)
      if fd < 0
        failure = Errno.value
        raise Filesystem::Capabilities::Error.new("Cannot inspect directory #{path}: #{failure}")
      end
      begin
        inspect_fd(fd, path)
      ensure
        LibC.close(fd)
      end
    {% elsif flag?(:darwin) %}
      # The capability's O_DIRECTORY policy also rules out FIFO/device opens
      # before ACL inspection; a plain read-only open could block on a FIFO.
      fd = LibC.open(path.to_s, Darwin::Constants::O_EVTONLY | LibC::O_CLOEXEC | LibC::O_NOFOLLOW | Filesystem::Capabilities::Directory::DIRECTORY_ONLY)
      if fd < 0
        failure = Errno.value
        raise Filesystem::Capabilities::Error.new("Cannot inspect directory #{path}: #{failure}")
      end
      begin
        inspect_fd(fd, path, expected: Target::Directory)
      ensure
        LibC.close(fd)
      end
    {% elsif flag?(:windows) %}
      inspect_windows_directory(path)
    {% else %}
      Report.new(path, :unsupported, nil, nil, ([] of Entry), ([] of Entry), State::Unsupported, false,
        "This platform has no verified descriptor-based ACL backend")
    {% end %}
  end
end
