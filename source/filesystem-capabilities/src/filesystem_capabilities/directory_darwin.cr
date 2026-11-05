# macOS counterpart to Linux's opt-in descriptor-pinned capability operations.
# Opening the *root* does not attest its ancestors; each later component is
# opened individually via openat(O_NOFOLLOW | O_DIRECTORY for parents).
# Under a mount policy the walk goes component by component and checks
# what was opened, per the macOS parity design §3.2.
{% skip_file unless flag?(:darwin) %}

require "io/file_descriptor"
require "errno"
require "sync/exclusive"
require "c/fcntl"
require "c/sys/stat"
require "c/unistd"
require "c/dirent"

@[Link("c")]
lib Filesystem::Capabilities::Native::Darwin::At
  fun openat(dirfd : Int32, pathname : UInt8*, flags : Int32, ...) : Int32
  fun mkdirat(dirfd : Int32, pathname : UInt8*, mode : LibC::ModeT) : Int32
  fun unlinkat(dirfd : Int32, pathname : UInt8*, flags : Int32) : Int32
  fun renameat(olddirfd : Int32, oldpath : UInt8*, newdirfd : Int32, newpath : UInt8*) : Int32
  fun renameatx_np(fromfd : Int32, from : UInt8*, tofd : Int32, to : UInt8*, flags : UInt32) : Int32
  fun fdopendir(fd : Int32) : LibC::DIR*
end

@[Link("c")]
lib Filesystem::Capabilities::Native::Darwin::Mounts
  # struct statfs from sys/mount.h under __DARWIN_64_BIT_INO_T (the default).
  # Layout pinned against the macOS 15.4.1 SDK: sizeof 2168, f_fsid at 48,
  # f_mntonname at 88 (2026-10-26).
  struct FsId
    val : Int32[2]
  end

  struct StatFs
    bsize : UInt32
    iosize : Int32
    blocks : UInt64
    bfree : UInt64
    bavail : UInt64
    files : UInt64
    ffree : UInt64
    fsid : FsId
    owner : UInt32
    type : UInt32
    flags : UInt32
    fssubtype : UInt32
    fstypename : UInt8[16]    # MFSTYPENAMELEN
    mntonname : UInt8[1024]   # MAXPATHLEN
    mntfromname : UInt8[1024] # MAXPATHLEN
    flags_ext : UInt32
    reserved : UInt32[7]
  end

  # The C symbol fstatfs64 is the same 64-bit-ino variant on both Darwin
  # CPUs, and binding it keeps this binding distinct from the access-control
  # library's fstatfs: Crystal rejects a second lib fun for a C symbol bound
  # elsewhere with another signature. File-Lock binds fstatfs64 too, so both
  # bind it as (Int32, Void*) : Int32 and cast their own struct: a program
  # that links both, as Corundum-Agent-Host does, then compiles (2026-11-02).
  fun mount_statfs = "fstatfs64"(fd : Int32, buf : Void*) : Int32
end

module Filesystem::Capabilities
  class Directory
    # Raw borrowed descriptors may never be resolved by consumers directly.
    private module Darwin
    end

    # Darwin O_DIRECTORY, source: Darwin sys/fcntl.h. Not exported by Crystal's
    # bundled lib_c/fcntl declarations; do not reuse Linux's CPU-dependent value.
    DIRECTORY_ONLY  = 0x00100000
    DIRECTORY_FLAGS = LibC::O_RDONLY | LibC::O_CLOEXEC | LibC::O_NOFOLLOW | DIRECTORY_ONLY
    # An ordinary root follows links; every operation after it is relative to
    # the descriptor, so a later change of a link cannot redirect them.
    ROOT_FLAGS = LibC::O_RDONLY | LibC::O_CLOEXEC | DIRECTORY_ONLY
    # Darwin sys/fcntl.h AT_REMOVEDIR (distinct from Linux).
    REMOVE_DIRECTORY_ENTRY = 0x80
    # Darwin sys/fcntl.h: O_SEARCH (O_EXEC | O_DIRECTORY) opens a folder for
    # search only — fstat and openat of known names work, listing does not.
    # It is what Linux's O_PATH retry gives a search-only folder (§3.2).
    SEARCH_ONLY  = 0x40100000
    SEARCH_FLAGS = LibC::O_CLOEXEC | SEARCH_ONLY
    # The EACCES retry of an open that was no-follow: the retry must itself
    # be no-follow, or a folder swapped for a link between the two opens is
    # followed out of the root (found by the search-retry race probe,
    # 2026-10-27).
    SEARCH_DIRECTORY_FLAGS = SEARCH_FLAGS | DIRECTORY_ONLY | LibC::O_NOFOLLOW
    # Darwin sys/fcntl.h O_RESOLVE_BENEATH: the kernel refuses to resolve
    # above the starting folder of each relative openat step.
    RESOLVE_BENEATH = 0x00001000
    # Each confined-walk step: no-follow, folders only, beneath the start.
    CONFINED_DIRECTORY_FLAGS = LibC::O_RDONLY | LibC::O_CLOEXEC | LibC::O_NOFOLLOW |
                               DIRECTORY_ONLY | RESOLVE_BENEATH
    # The EACCES retry of a confined step: a search-only folder reference.
    CONFINED_SEARCH_FLAGS = SEARCH_ONLY | LibC::O_CLOEXEC | LibC::O_NOFOLLOW |
                            DIRECTORY_ONLY | RESOLVE_BENEATH

    getter path : Path
    @descriptor : RootLease(Int32)

    # Native admission returns an unowned descriptor. Only this class takes
    # durable ownership; constructor failure must not leak the admitted fd.
    def self.open_existing(path : Path) : Directory
      adopt_root(path, Darwin::RootAdmission.open_ordinary(path))
    end

    # Explicit no-symlink ancestry traversal, not an ambient pathname reopen.
    def self.open_existing_no_symlinks(path : Path) : Directory
      adopt_root(path, Darwin::RootAdmission.open_no_symlinks(path))
    end

    private def self.adopt_root(path : Path, fd : Int32) : Directory
      begin
        new(path, fd)
      rescue error
        LibC.close(fd)
        raise error
      end
    end

    # Constructor also transfers ownership to child private-directory handles.
    protected def initialize(@path : Path, fd : Int32)
      @descriptor = RootLease.new(fd, -1)
    end

    def closed? : Bool
      @descriptor.closed?
    end

    def close : Nil
      @descriptor.close { |fd| LibC.close(fd) }
    end

    # No Sync::Mutex here: the GC finalizer thread has no Crystal Fiber.
    def finalize
      @descriptor.release_on_finalization { |fd| LibC.close(fd) }
    end

    # Under a mount policy other than Allow the walk opens each component
    # itself and checks what it opened, as the macOS parity design's §3.2
    # says: macOS has no RESOLVE_NO_XDEV, so StayOnRootMount compares each
    # step's f_fsid and mount point with the start's, counting APFS
    # firmlinks as crossings, and StayOnRootDevice compares st_dev. A step
    # that differs is closed at once and refused with EXDEV.
    def open_read(*components : String, mount : MountPolicy = MountPolicy::Allow) : IO::FileDescriptor
      case mount
      in .allow?
        with_parent(components, :read) do |parent, leaf, name|
          RegularFile.take(open_leaf(parent, leaf, name, :read, LibC::O_RDONLY | LibC::O_NONBLOCK, 0), name)
        end
      in .stay_on_root_mount?, .stay_on_root_device?
        names = components.map { |part| Component.validate(part) }.to_a
        fd = open_confined_relative(names, confined_operation(:open_read, mount),
          LibC::O_RDONLY | LibC::O_CLOEXEC | LibC::O_NONBLOCK, 0, mount)
        RegularFile.take(fd, names.join('/'))
      end
    end

    # This is an exclusive filesystem create, *not* a private ACL guarantee.
    # Use create_private_exclusive (opt-in access_control) for audited privacy.
    def create_exclusive(*components : String, mode : Int32 = 0o600,
                         mount : MountPolicy = MountPolicy::Allow) : IO::FileDescriptor
      validate_file_mode(mode)
      case mount
      in .allow?
        with_parent(components, :create_exclusive) do |parent, leaf, name|
          RegularFile.take(open_leaf(parent, leaf, name, :create_exclusive, LibC::O_WRONLY | LibC::O_CREAT | LibC::O_EXCL, mode), name)
        end
      in .stay_on_root_mount?, .stay_on_root_device?
        names = components.map { |part| Component.validate(part) }.to_a
        fd = open_confined_relative(names, confined_operation(:create_exclusive, mount),
          LibC::O_WRONLY | LibC::O_CREAT | LibC::O_EXCL | LibC::O_CLOEXEC, mode, mount)
        RegularFile.take(fd, names.join('/'))
      end
    end

    # A child owns its fd independently, even after the root closes or moves.
    # No ACL check is performed unless the opt-in strict API is selected.
    # A folder that refuses a read open with EACCES is retried as an O_SEARCH
    # reference, as Linux retries one as an O_PATH reference, so the
    # capability API holds a search-only folder on both systems.
    def open_subdirectory(*components : String, mount : MountPolicy = MountPolicy::Allow) : Directory
      case mount
      in .allow?
        with_parent(components, :open_subdirectory) do |parent, leaf, name|
          # A search-only folder is retried inside open_leaf, as a no-follow
          # O_SEARCH reference.
          fd = open_leaf(parent, leaf, name, :open_subdirectory, DIRECTORY_FLAGS, 0)
          begin
            Directory.new(@path / name, fd)
          rescue error
            LibC.close(fd)
            raise error
          end
        end
      in .stay_on_root_mount?, .stay_on_root_device?
        names = components.map { |part| Component.validate(part) }.to_a
        raise ArgumentError.new("At least one path component is required") if names.empty?
        fd = open_confined_relative(names, confined_operation(:open_subdirectory, mount),
          LibC::O_RDONLY | LibC::O_CLOEXEC | DIRECTORY_ONLY, 0, mount)
        begin
          Directory.new(names.reduce(@path) { |path, part| path / part }, fd)
        rescue error
          LibC.close(fd)
          raise error
        end
      end
    end

    # Borrow the opened root for the entire confined resolution. The resolver
    # owns only intermediate fds and releases them on every exit path.
    private def open_confined_relative(names : Array(String), operation : Symbol,
                                       flags : Int32, mode : Int32, mount : MountPolicy) : Int32
      @descriptor.lock do |root|
        raise Filesystem::Capabilities::ClosedError.new("Directory capability handle is closed") if root < 0
        Darwin::EntryResolution.open_confined(root, names, operation, flags, mode, mount)
      end
    end

    # Existing opt-in providers use this protected hook. The native openat
    # policy and errno capture belong to the private borrowed-FD resolver.
    protected def open_leaf(parent : Int32, leaf : String, name : String, op : Symbol, flags : Int32, mode : Int32) : Int32
      Darwin::EntryResolution.open_leaf(parent, leaf, name, op, flags, mode)
    end

    # Borrow the opened root for the entire resolution/callback. Validation
    # and retained-root synchronization stay with Directory; the resolver
    # owns *only* intermediate fds and releases them on every exit path.
    # The operation names a denied intermediate's error, as Linux's leaf
    # opens do: the walk belongs to the operation the caller asked for.
    protected def with_parent(components : Tuple, operation : Symbol, & : Int32, String, String -> T) : T forall T
      names = components.map { |part| Component.validate(part) }.to_a
      raise ArgumentError.new("At least one path component is required") if names.empty?
      @descriptor.lock do |root|
        raise Filesystem::Capabilities::ClosedError.new("Directory capability handle is closed") if root < 0
        Darwin::EntryResolution.with_parent(root, names, operation) { |parent, leaf, full| yield parent, leaf, full }
      end
    end
  end
end
