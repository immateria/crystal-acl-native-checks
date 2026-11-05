# Linux directory-descriptor operations. The platform entrypoint selects the
# Darwin/Windows implementations on those targets. Not a filesystem sandbox.
# The caller provides an existing root, whose ancestors are outside the scope
# of this handle. Every subsequent relative component is validated and opened
# without following symbolic links. Concurrent directory moves or bind mounts
# can still invalidate any root-containment assumption.
require "../filesystem-capabilities"
require "./root_lease"

{% if flag?(:linux) %}
  module Filesystem::Capabilities
    class Directory
      # No raw descriptor admission or resolution API is public. The helpers
      # are reachable only through the owning Directory methods.
      private module Linux
      end

      getter path : Path
      @descriptor : RootLease(Int32)

      # Root admission and retained-FD ownership are deliberately separate.
      # The admission policy returns an unowned FD; only the Directory
      # constructor may take ownership, and construction failure closes it.
      def self.open_existing(path : Path) : Directory
        adopt_root(path, Linux::RootAdmission.open_ordinary(path))
      end

      def self.open_existing_no_symlinks(path : Path) : Directory
        adopt_root(path, Linux::RootAdmission.open_no_symlinks(path))
      end

      private def self.adopt_root(path : Path, fd : Int32) : Directory
        begin
          new(path, fd)
        rescue error
          LibC.close(fd)
          raise error
        end
      end

      private def initialize(@path : Path, descriptor : Int32)
        @descriptor = RootLease.new(descriptor, -1)
      end

      def closed? : Bool
        @descriptor.closed?
      end

      def close : Nil
        @descriptor.close { |fd| LibC.close(fd) }
      end

      # Boehm GC invokes finalizers on a thread without a Crystal Fiber.
      # Do not acquire Sync::Exclusive, yield, or call #close here.
      def finalize
        @descriptor.release_on_finalization { |fd| LibC.close(fd) }
      end

      # Each intermediate component must be a real directory (not a symlink).
      # The final entry must be a regular file, not a FIFO, socket or symlink.
      # Under StayOnRootMount one kernel resolution enforces NO_XDEV,
      # NO_SYMLINKS, NO_MAGICLINKS and BENEATH for the whole relative path,
      # with no fallback to component-by-component openat; under
      # StayOnRootDevice every opened step is checked against the root's
      # st_dev. Neither is an ACL privacy inspection.
      def open_read(*components : String, mount : MountPolicy = MountPolicy::Allow) : IO::FileDescriptor
        names = validate(components)
        fd = case mount
             in .allow?
               open_relative(names, :read, 0o600)
             in .stay_on_root_mount?, .stay_on_root_device?
               confined_open(names, confined_operation(:open_read, mount),
                 LibC::O_RDONLY | LibC::O_CLOEXEC | LibC::O_NOFOLLOW | LibC::O_NONBLOCK, 0, mount)
             end
        RegularFile.take(fd, names.join('/'))
      end

      # Atomic, non-replacing file creation, under an existing directory,
      # with the same resolution guarantees as open_read under the policy.
      # Kernel support is mandatory: no weaker openat fallback.
      def create_exclusive(*components : String, mode : Int32 = 0o600,
                           mount : MountPolicy = MountPolicy::Allow) : IO::FileDescriptor
        validate_file_mode(mode)
        names = validate(components)
        fd = case mount
             in .allow?
               open_relative(names, :create_exclusive, mode)
             in .stay_on_root_mount?, .stay_on_root_device?
               confined_open(names, confined_operation(:create_exclusive, mount),
                 LibC::O_WRONLY | LibC::O_CREAT | LibC::O_EXCL | LibC::O_CLOEXEC | LibC::O_NOFOLLOW, mode, mount)
             end
        RegularFile.take(fd, names.join('/'))
      end

      # Return an independently owned child directory under the pinned root.
      # This is a no-follow capability, NOT an ACL/privacy attestation. Its
      # display path is lexical; later filesystem renames do not change it.
      # A folder that refuses a read open with EACCES is retried as an O_PATH
      # reference, under the same policy, so a search-only folder can be held.
      def open_subdirectory(*components : String, mount : MountPolicy = MountPolicy::Allow) : Directory
        names = validate(components)
        raise ArgumentError.new("At least one path component is required") if names.empty?
        fd = case mount
             in .allow?
               begin
                 open_relative(names, :open_subdirectory, 0)
               rescue error : EntryError
                 raise error unless error.errno == Errno::EACCES
                 open_relative(names, :open_subdirectory, 0, directory_reference: true)
               end
             in .stay_on_root_mount?, .stay_on_root_device?
               operation = confined_operation(:open_subdirectory, mount)
               begin
                 confined_open(names, operation,
                   LibC::O_RDONLY | LibC::O_CLOEXEC | LibC::O_NOFOLLOW | Platform::DIRECTORY_ONLY, 0, mount)
               rescue error : EntryError
                 raise error unless error.errno == Errno::EACCES
                 confined_open(names, operation,
                   Platform::PATH_REFERENCE | LibC::O_CLOEXEC | LibC::O_NOFOLLOW | Platform::DIRECTORY_ONLY, 0, mount)
               end
             end
        begin
          self.class.from_verified_child(names.reduce(@path) { |path, part| path / part }, fd)
        rescue error
          LibC.close(fd)
          raise error
        end
      end

      # Borrow the handle for the complete resolution, but keep the policy's
      # resolution and retry protocol in their native resolver owner. The
      # device policy checks what was opened, not how the path resolved
      # (§3.2), so it walks with fstat and st_dev and needs no openat2.
      private def confined_open(names : Array(String), operation : Symbol,
                                flags : Int32, mode : Int32, mount : MountPolicy) : Int32
        @descriptor.lock do |root|
          raise Filesystem::Capabilities::ClosedError.new("Directory capability handle is closed") if root < 0
          if mount.stay_on_root_mount?
            Linux::EntryResolution.open_no_cross_mount(root, names, operation, flags, mode)
          else
            Linux::EntryResolution.open_no_cross_device(root, names, operation, flags, mode)
          end
        end
      end

      private def validate(components : Tuple) : Array(String)
        components.map { |part| Component.validate(part) }.to_a
      end

      # The root lock and each temporary parent fd live through the final
      # syscall; callers never re-resolve a concatenated ambient pathname.
      # One open root borrow encloses every intermediate FD and the caller's
      # final operation; a callback cannot observe a recycled root descriptor.
      private def with_parent(components : Array(String),
                              & : Int32, String, String -> T) : T forall T
        @descriptor.lock do |root|
          raise Filesystem::Capabilities::ClosedError.new("Directory capability handle is closed") if root < 0
          Linux::EntryResolution.with_parent(root, components) do |parent, leaf, full|
            yield parent, leaf, full
          end
        end
      end

      # :nodoc:
      # Provider extension point for validated components. The capability
      # owns resolution and root borrowing; the returned fd belongs to caller.
      protected def open_relative(components : Array(String), operation : Symbol, mode : Int32,
                                  *, directory_reference : Bool = false) : Int32
        with_parent(components) do |parent, leaf, full|
          Linux::EntryResolution.open_leaf(parent, leaf, full, operation, mode,
            directory_reference: directory_reference)
        end
      end
    end
  end
{% end %}

{% if flag?(:linux) %}
  require "./linux_root_admission"
  require "./linux_entry_resolution"
{% elsif flag?(:darwin) %}
  require "./directory_darwin"
  require "./darwin_root_admission"
  require "./darwin_entry_resolution"
{% elsif flag?(:windows) %}
  require "./directory_windows"
  require "./windows_root_admission"
  require "./windows_entry_resolution"
{% end %}

require "./provider_access"
require "./regular_file"
require "./scoped_directory"
require "./directory_provisioning"
require "./directory_dual_root"
require "./directory_listing"

# Ordinary enumeration and entry mutations have independent native owners.
{% if flag?(:linux) %}
  require "./unix_entry_enumeration"
  require "./linux_entry_mutations"
{% elsif flag?(:darwin) %}
  require "./unix_entry_enumeration"
  require "./darwin_entry_mutations"
{% elsif flag?(:windows) %}
  require "./windows_entry_enumeration"
  require "./windows_entry_mutations"
{% end %}
