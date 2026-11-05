# Read-only, no-follow immediate-entry type and identity inspection against a
# retained root. This observes one instant, not a stable inode token for a
# later operation.
{% skip_file unless flag?(:linux) || flag?(:darwin) || flag?(:windows) %}

{% if flag?(:linux) %}
  @[Link("c")]
  lib Filesystem::Capabilities::Native::Linux::At
    fun fstatat(dirfd : Int32, pathname : UInt8*, statbuf : LibC::Stat*, flags : Int32) : Int32
  end
{% elsif flag?(:darwin) %}
  @[Link("c")]
  lib Filesystem::Capabilities::Native::Darwin::At
    fun fstatat(dirfd : Int32, pathname : UInt8*, statbuf : LibC::Stat*, flags : Int32) : Int32
  end
{% end %}

class Filesystem::Capabilities::Directory
  # Reparse points are not necessarily symbolic links; Windows deliberately
  # reports them separately. All kinds describe one point-in-time observation.
  enum EntryType
    Directory
    RegularFile
    Symlink
    Special
    ReparsePoint
  end

  # One no-follow observation of an immediate entry: its type and the native
  # identity it had then. It carries no authority, and by the time it is
  # used the name may name another object; `same_directory?` tells whether
  # an opened directory is the one observed.
  struct EntryStatus
    getter type : EntryType
    protected getter identity : Tuple(UInt64, UInt64)

    def initialize(@type : EntryType, @identity : Tuple(UInt64, UInt64))
    end

    def same_directory?(directory : Directory) : Bool
      @type.directory? && directory.identity == @identity
    end

    # True when both observations saw one object of one type: a name that
    # still names what it named before, for example.
    def same_entry?(other : EntryStatus) : Bool
      @type == other.type && @identity == other.identity
    end

    # True when this observation saw the regular file the descriptor holds:
    # whether a name still denotes a file one created, before removing it.
    def same_file?(file : IO::FileDescriptor) : Bool
      return false unless @type.regular_file?
      {% if flag?(:linux) || flag?(:darwin) %}
        info = uninitialized LibC::Stat
        return false unless LibC.fstat(file.fd, pointerof(info)) == 0
        return false unless (info.st_mode & LibC::S_IFMT) == LibC::S_IFREG
        {info.st_dev.to_u64!, info.st_ino.to_u64!} == @identity
      {% else %}
        info = uninitialized LibC::BY_HANDLE_FILE_INFORMATION
        return false if LibC.GetFileInformationByHandle(LibC::HANDLE.new(file.fd), pointerof(info)) == 0
        file_id = (info.nFileIndexHigh.to_u64 << 32) | info.nFileIndexLow.to_u64
        {info.dwVolumeSerialNumber.to_u64, file_id} == @identity
      {% end %}
    end
  end

  # Does not follow final symlinks/reparse points or reopen ambient paths.
  # Does not open a regular file, FIFO, socket, or device for I/O.
  def entry_type(name : String, mount : MountPolicy = MountPolicy::Allow) : EntryType
    observe(name, mount, :entry_type).type
  end

  # The type and identity of an entry, in one observation, without opening
  # it for I/O. A walker classifies with it before deciding to descend.
  # Under a mount policy other than Allow, an entry the policy would refuse
  # to enter, a mount point under StayOnRootMount for example, raises an
  # EntryError with EXDEV, as an open through it would.
  def entry_status(name : String, mount : MountPolicy = MountPolicy::Allow) : EntryStatus
    observe(name, mount, :entry_status)
  end

  private def observe(name : String, mount : MountPolicy, operation : Symbol) : EntryStatus
    case mount
    in .allow?
      observe_entry(name, operation)
    in .stay_on_root_mount?, .stay_on_root_device?
      observe_confined_entry(name, mount, confined_operation(operation, mount))
    end
  end

  {% if flag?(:linux) %}
    # One no-follow O_PATH open of the entry under the policy, which needs no
    # permission on it: openat2 opens a final link itself with O_PATH and
    # O_NOFOLLOW, even with NO_SYMLINKS, so a link is reported, not refused.
    private def observe_confined_entry(name : String, mount : MountPolicy, operation : Symbol) : EntryStatus
      leaf = Filesystem::Capabilities::Component.validate(name)
      flags = Platform::PATH_REFERENCE | LibC::O_CLOEXEC | LibC::O_NOFOLLOW
      @descriptor.lock do |root|
        raise Filesystem::Capabilities::ClosedError.new("Directory capability handle is closed") if root < 0
        fd = if mount.stay_on_root_mount?
               Linux::EntryResolution.open_no_cross_mount(root, [leaf], operation, flags, 0)
             else
               Linux::EntryResolution.open_no_cross_device(root, [leaf], operation, flags, 0)
             end
        begin
          info = uninitialized LibC::Stat
          raise EntryError.new(operation, leaf, Errno.value) unless LibC.fstat(fd, pointerof(info)) == 0
          EntryStatus.new(entry_type_of(info), {info.st_dev.to_u64!, info.st_ino.to_u64!})
        ensure
          LibC.close(fd)
        end
      end
    end
  {% elsif flag?(:darwin) %}
    # macOS has no O_PATH for a file, so the entry is observed with fstatat,
    # which needs no permission on it; a folder is then opened as one more
    # step of a confined walk and checked, as a walk through it would be.
    private def observe_confined_entry(name : String, mount : MountPolicy, operation : Symbol) : EntryStatus
      status = observe_entry(name, operation)
      if status.type.directory?
        leaf = Filesystem::Capabilities::Component.validate(name)
        @descriptor.lock do |root|
          raise Filesystem::Capabilities::ClosedError.new("Directory capability handle is closed") if root < 0
          Darwin::EntryResolution.verify_confined_child(root, leaf, operation, mount)
        end
      end
      status
    end
  {% else %}
    private def observe_confined_entry(name : String, mount : MountPolicy, operation : Symbol) : EntryStatus
      raise Filesystem::Capabilities::UnsupportedOperationError.new("Mount-policy observation requires Linux openat2 or the macOS confined walk")
    end
  {% end %}

  {% if flag?(:linux) || flag?(:darwin) %}
    private def entry_type_of(info : LibC::Stat) : EntryType
      case info.st_mode & LibC::S_IFMT
      when LibC::S_IFDIR then EntryType::Directory
      when LibC::S_IFREG then EntryType::RegularFile
      when LibC::S_IFLNK then EntryType::Symlink
      else                    EntryType::Special
      end
    end
  {% end %}

  private def observe_entry(name : String, operation : Symbol) : EntryStatus
    leaf = Filesystem::Capabilities::Component.validate(name)
    {% if flag?(:linux) || flag?(:darwin) %}
      @descriptor.lock do |root|
        raise Filesystem::Capabilities::ClosedError.new("Directory capability handle is closed") if root < 0
        info = uninitialized LibC::Stat
        {% if flag?(:linux) %}
          # Linux AT_SYMLINK_NOFOLLOW, from asm-generic/fcntl.h.
          result = Filesystem::Capabilities::Native::Linux::At.fstatat(root, leaf, pointerof(info), 0x100)
        {% else %}
          # Darwin AT_SYMLINK_NOFOLLOW, from sys/fcntl.h.
          result = Filesystem::Capabilities::Native::Darwin::At.fstatat(root, leaf, pointerof(info), 0x20)
        {% end %}
        raise EntryError.new(operation, leaf, Errno.value) unless result == 0
        EntryStatus.new(entry_type_of(info), {info.st_dev.to_u64!, info.st_ino.to_u64!})
      end
    {% else %}
      # FILE_READ_ATTRIBUTES | SYNCHRONIZE. The native relative opener pins
      # the parent and uses FILE_OPEN_REPARSE_POINT for the final entry.
      with_parent({leaf}) do |parent, child, full|
        handle = relative_open(parent, child, full, operation, :any,
          0x00100080_u32, allow_final_reparse: true)
        begin
          info = uninitialized LibC::BY_HANDLE_FILE_INFORMATION
          if LibC.GetFileInformationByHandle(handle, pointerof(info)) == 0
            raise EntryError.new(operation, full)
          end
          attrs = info.dwFileAttributes
          type = if (attrs & 0x400) != 0
                   EntryType::ReparsePoint
                 elsif (attrs & 0x10) != 0
                   EntryType::Directory
                 else
                   EntryType::RegularFile
                 end
          file_id = (info.nFileIndexHigh.to_u64 << 32) | info.nFileIndexLow.to_u64
          EntryStatus.new(type, {info.dwVolumeSerialNumber.to_u64, file_id})
        ensure
          LibC.CloseHandle(handle)
        end
      end
    {% end %}
  end
end
