# Linux entry-resolution mechanics, owned by Filesystem::Capabilities.
# This internal module borrows an already locked root FD. It never owns that
# root or resolves an ambient pathname. Intermediate handles are always closed,
# including on callback exceptions and failed final operations.
{% skip_file unless flag?(:linux) %}

module Filesystem::Capabilities::Directory::Linux::EntryResolution
  def self.with_parent(root : Int32, components : Array(String),
                       & : Int32, String, String -> T) : T forall T
    raise ArgumentError.new("At least one path component is required") if components.empty?
    full = components.join('/')
    current = root
    owned = -1
    begin
      components[0...-1].each do |component|
        flags = Platform::PATH_REFERENCE | LibC::O_CLOEXEC |
                LibC::O_NOFOLLOW | Platform::DIRECTORY_ONLY
        fd = Native::Linux::At.openat(current, component, flags, 0)
        raise Directory::EntryError.new(:traverse, full, Errno.value) if fd < 0
        LibC.close(owned) if owned >= 0
        owned = fd
        current = fd
      end
      yield current, components.last, full
    ensure
      LibC.close(owned) if owned >= 0
    end
  end

  def self.open_leaf(parent : Int32, leaf : String, full : String, operation : Symbol,
                     mode : Int32, *, directory_reference : Bool = false) : Int32
    flags = case operation
            when :inspect_reference
              Platform::PATH_REFERENCE | LibC::O_CLOEXEC | LibC::O_NOFOLLOW
            when :open_subdirectory
              (directory_reference ? Platform::PATH_REFERENCE : LibC::O_RDONLY) |
                LibC::O_CLOEXEC | LibC::O_NOFOLLOW | Platform::DIRECTORY_ONLY
            when :read
              LibC::O_RDONLY | LibC::O_CLOEXEC | LibC::O_NOFOLLOW | LibC::O_NONBLOCK
            when :create_exclusive
              LibC::O_WRONLY | LibC::O_CREAT | LibC::O_EXCL | LibC::O_CLOEXEC | LibC::O_NOFOLLOW
            else
              raise ArgumentError.new("Unsupported directory capability operation: #{operation}")
            end
    fd = Native::Linux::At.openat(parent, leaf, flags, mode)
    raise Directory::EntryError.new(operation, full, Errno.value) if fd < 0
    fd
  end

  # All four VFS restrictions remain together, including during retries.
  # Never downgrade ENOSYS/EINVAL/EPERM to openat. Retry transient EAGAIN/
  # EINTR at most three times beyond the initial attempt.
  def self.open_no_cross_mount(root : Int32, names : Array(String), operation : Symbol,
                               flags : Int32, mode : Int32) : Int32
    raise ArgumentError.new("At least one path component is required") if names.empty?
    how = Native::Linux::Openat2::OpenHow.new
    how.flags = flags.to_u64
    how.mode = mode.to_u64
    how.resolve = 0x0f_u64 # NO_XDEV | NO_MAGICLINKS | NO_SYMLINKS | BENEATH
    full = names.join('/')
    attempts = 0
    loop do
      result = -1_i64
      {% if flag?(:directories_openat2_test_probe) %}
        injected = ENV["DIRECTORIES_OPENAT2_TEST_ERRNO"]?
        if injected
          Errno.value = case injected
                        when "EAGAIN" then Errno::EAGAIN
                        when "EINTR"  then Errno::EINTR
                        when "ENOSYS" then Errno::ENOSYS
                        when "EINVAL" then Errno::EINVAL
                        when "EPERM"  then Errno::EPERM
                        else               raise ArgumentError.new("Unsupported fault code")
                        end
          result = -1_i64
        else
          result = Native::Linux::Openat2.syscall(437_i64, root.to_i64,
            full.to_unsafe, pointerof(how), sizeof(Native::Linux::Openat2::OpenHow).to_i64)
        end
      {% else %}
        result = Native::Linux::Openat2.syscall(437_i64, root.to_i64,
          full.to_unsafe, pointerof(how), sizeof(Native::Linux::Openat2::OpenHow).to_i64)
      {% end %}
      break result.to_i32 if result >= 0
      failure = Errno.value
      if {Errno::ENOSYS, Errno::EINVAL}.includes?(failure)
        raise Filesystem::Capabilities::UnsupportedOperationError.new("Linux openat2 no-cross-mount policy unavailable: #{failure}")
      end
      # EPERM is an authorization failure (for example seccomp), not proof
      # of a missing kernel API. Preserve errno for callers and diagnostics.
      raise Directory::EntryError.new(operation, full, failure) if failure == Errno::EPERM
      attempts += 1
      next if {Errno::EAGAIN, Errno::EINTR}.includes?(failure) && attempts < 4
      raise Directory::EntryError.new(operation, full, failure)
    end
  end

  # The no-cross-device policy walks the same way on both systems with fstat
  # and st_dev, so it needs no openat2 (macOS parity design §3.2). O_PATH
  # intermediates fail no permission check of their own; every opened step,
  # the final one included, is checked against the starting folder's st_dev,
  # read once when the walk begins, and refused with EXDEV.
  def self.open_no_cross_device(root : Int32, names : Array(String), operation : Symbol,
                                flags : Int32, mode : Int32) : Int32
    raise ArgumentError.new("At least one path component is required") if names.empty?
    full = names.join('/')
    if LibC.fstat(root, out base) != 0
      raise Directory::EntryError.new(operation, full, Errno.value)
    end
    current = root
    owned = -1
    begin
      names[0...-1].each do |component|
        step_flags = Platform::PATH_REFERENCE | LibC::O_CLOEXEC |
                     LibC::O_NOFOLLOW | Platform::DIRECTORY_ONLY
        fd = Native::Linux::At.openat(current, component, step_flags, 0)
        raise Directory::EntryError.new(operation, full, Errno.value) if fd < 0
        begin
          verify_same_device(fd, base.st_dev, operation, full)
        rescue error
          LibC.close(fd)
          raise error
        end
        LibC.close(owned) if owned >= 0
        owned = fd
        current = fd
      end
      leaf = Native::Linux::At.openat(current, names.last, flags, mode)
      raise Directory::EntryError.new(operation, full, Errno.value) if leaf < 0
      begin
        verify_same_device(leaf, base.st_dev, operation, full)
      rescue error
        LibC.close(leaf)
        raise error
      end
      LibC.close(owned) if owned >= 0
      leaf
    ensure
      LibC.close(owned) if owned >= 0
    end
  end

  private def self.verify_same_device(fd : Int32, device : LibC::DevT,
                                      operation : Symbol, full : String) : Nil
    if LibC.fstat(fd, out info) != 0
      raise Directory::EntryError.new(operation, full, Errno.value)
    end
    unless info.st_dev == device
      raise Directory::EntryError.new(operation, full, Errno::EXDEV)
    end
  end
end
