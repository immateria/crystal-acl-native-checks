# Windows handle-relative file capabilities. NtCreateFile's RootDirectory is
# an already-open directory HANDLE; each child is opened one component at a
# time with FILE_OPEN_REPARSE_POINT and checked for reparse attributes.
# Root path ancestors, network redirectors, token impersonation and hostile
# same-user reparse races are not a proven sandbox boundary.
{% skip_file unless flag?(:windows) %}

require "sync/exclusive"
require "io/file_descriptor"
require "c/fileapi"
require "c/handleapi"
require "c/ntdef"
require "c/wdm"

@[Link("ntdll")]
lib Filesystem::Capabilities::Native::Windows::Nt
  fun NtCreateFile(handle : Void**, access : UInt32,
                   attributes : LibC::OBJECT_ATTRIBUTES*, status : LibC::IO_STATUS_BLOCK*,
                   allocation_size : Int64*, file_attributes : UInt32, share_access : UInt32,
                   disposition : UInt32, options : UInt32, ea : Void*, ea_length : UInt32) : Int32
  fun NtQueryDirectoryFile(handle : Void*, event : Void*, apc_routine : Void*, apc_context : Void*,
                           status : LibC::IO_STATUS_BLOCK*, buffer : Void*, length : UInt32,
                           information_class : Int32, single_entry : UInt8,
                           file_name : LibC::UNICODE_STRING*, restart_scan : UInt8) : Int32
  fun NtSetInformationFile(handle : Void*, status : LibC::IO_STATUS_BLOCK*, buffer : Void*,
                           length : UInt32, information_class : Int32) : Int32
end

module Filesystem::Capabilities
  class Directory
    # Native RootDirectory relative open policy is owned privately; callers
    # can only use validated Directory APIs, not raw HANDLE operations.
    private module Windows
    end

    getter path : Path
    @descriptor : RootLease(Pointer(Void))

    # FILE_TRAVERSE(0x20), not FILE_LIST_DIRECTORY(0x01): callers with
    # traverse-only access may resolve a known child without listing siblings.
    # READ_CONTROL is also requested on the root for optional DACL inspection.
    ROOT_ACCESS            = 0x001200a0_u32
    CHILD_DIRECTORY_ACCESS = 0x001000a0_u32

    class EntryError < Filesystem::Capabilities::Error
      getter operation : Symbol
      getter entry : String
      getter ntstatus : Int32?

      def initialize(@operation : Symbol, @entry : String, @ntstatus : Int32? = nil)
        code = @ntstatus ? " (NTSTATUS=0x#{@ntstatus.not_nil!.to_u32!.to_s(16)})" : ""
        super("Cannot #{@operation} confined Windows entry #{@entry.inspect}#{code}")
      end

      # NtCreateFile reports several distinct not-found statuses. Keep this
      # classification at the native error owner instead of teaching callers
      # Windows status values or pretending they are POSIX errno.
      def missing? : Bool
        status = @ntstatus
        return false unless status
        {0xC000000F_u32, 0xC0000034_u32, 0xC000003A_u32}.includes?(status.to_u32!)
      end

      # STATUS_NAME_TOO_LONG, so that a caller asks as on Unix. The portable
      # rule refuses a name over 255 bytes before NtCreateFile sees it.
      def name_too_long? : Bool
        @ntstatus.try(&.to_u32!) == 0xC0000106_u32
      end
    end

    # Root ancestry is outside this ordinary capability's confinement policy.
    # The native admission helper checks the opened handle, but only this
    # resource owner can retain it or close it on constructor failure.
    def self.open_existing(path : Path) : Directory
      handle = Windows::RootAdmission.open_ordinary(path)
      begin
        new(path, handle)
      rescue error
        LibC.CloseHandle(handle)
        raise error
      end
    end

    # A pathname CreateFileW root cannot certify its intermediate ancestors.
    # Do not silently treat that weaker operation as strict no-reparse access.
    # A volume-root-relative native Windows walk needs dedicated host evidence.
    def self.open_existing_no_symlinks(path : Path) : Directory
      raise Filesystem::Capabilities::UnsupportedOperationError.new("No-symlink root-ancestor traversal is unavailable on Windows")
    end

    protected def initialize(@path : Path, handle : Pointer(Void))
      @descriptor = RootLease.new(handle, Pointer(Void).null)
    end

    def closed? : Bool
      @descriptor.closed?
    end

    def close : Nil
      @descriptor.close { |handle| LibC.CloseHandle(handle) }
    end

    # No Sync::Mutex here: the GC finalizer thread has no Crystal Fiber.
    def finalize
      @descriptor.release_on_finalization { |handle| LibC.CloseHandle(handle) }
    end

    def open_read(*components : String, mount : MountPolicy = MountPolicy::Allow) : IO::FileDescriptor
      refuse_mount_policy(mount)
      with_parent(components) do |parent, leaf, name|
        fd = relative_open(parent, leaf, name, :read, :file, 0x80100000_u32)
        begin
          take_file(fd)
        rescue error
          LibC.CloseHandle(fd)
          raise error
        end
      end
    end

    # NtCreateFile pins a child directory relative to the pinned parent.
    # This deliberately does not inspect DACL privacy; strict callers must
    # load access_control and choose open_private_subdirectory instead.
    def open_subdirectory(*components : String, mount : MountPolicy = MountPolicy::Allow) : Directory
      refuse_mount_policy(mount)
      with_parent(components) do |parent, leaf, name|
        child = relative_open(parent, leaf, name, :open_subdirectory, :directory, ROOT_ACCESS)
        begin
          Directory.new(@path / name, child)
        rescue error
          LibC.CloseHandle(child)
          raise error
        end
      end
    end

    # Windows creation without an explicit DACL may inherit permissive ACEs.
    # Fail closed rather than interpreting Unix's mode 0600 as a DACL.
    def create_exclusive(*components : String, mode : Int32 = 0o600,
                         mount : MountPolicy = MountPolicy::Allow) : IO::FileDescriptor
      refuse_mount_policy(mount)
      raise Filesystem::Capabilities::UnsupportedOperationError.new("Windows capability creation requires an explicit security descriptor backend")
    end

    # Windows has neither Linux's openat2 nor the Darwin component walk: both
    # policies refuse, never falling through to an ordinary open, which would
    # behave like Allow.
    private def refuse_mount_policy(mount : MountPolicy) : Nil
      case mount
      in .allow?
      in .stay_on_root_mount?
        raise Filesystem::Capabilities::UnsupportedOperationError.new("No-cross-mount resolution requires Linux openat2 or the macOS confined walk")
      in .stay_on_root_device?
        raise Filesystem::Capabilities::UnsupportedOperationError.new("No-cross-device resolution requires Linux or macOS checks")
      end
    end

    # Ordinary directory creation can inherit permissive ACLs. Creation remains
    # unsupported until an explicit SD and post-open identity/ACL policy exist.
    def create_directory(*components : String, mode : Int32 = 0o700) : Nil
      raise Filesystem::Capabilities::UnsupportedOperationError.new("Windows handle-relative directory creation is not implemented")
    end

    # Preserve the protected provider extension hook while moving the NT
    # protocol to the borrowed-HANDLE owner. No temporary handle escapes.
    protected def relative_open(parent : Pointer(Void), leaf : String, name : String,
                                operation : Symbol, kind : Symbol, access : UInt32,
                                allow_final_reparse : Bool = false) : Pointer(Void)
      Windows::EntryResolution.open_relative(parent, leaf, name, operation, kind, access,
        allow_final_reparse: allow_final_reparse)
    end

    protected def take_file(handle : Pointer(Void)) : IO::FileDescriptor
      # NtCreateFile FILE_SYNCHRONOUS_IO_NONALERT creates synchronous HANDLEs.
      # Crystal's Windows blocking IO path accepts such handles without IOCP.
      IO::FileDescriptor.new(handle: handle.address, blocking: true)
    end

    # Root lock stays held until the borrowed-parent operation completes.
    # Only the private resolver manages intermediate child HANDLE lifetimes.
    protected def with_parent(components : Tuple, & : Pointer(Void), String, String -> T) : T forall T
      names = components.map { |part| Component.validate(part) }.to_a
      raise ArgumentError.new("At least one path component is required") if names.empty?
      @descriptor.lock do |root|
        raise Filesystem::Capabilities::ClosedError.new("Directory capability handle is closed") if root.null?
        Windows::EntryResolution.with_parent(root, names) { |parent, leaf, full| yield parent, leaf, full }
      end
    end
  end
end
