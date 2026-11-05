# Borrowed handle-relative Darwin lookup. Directory validates components,
# holds its root lock, and retains root ownership throughout the callback.
# Only intermediate fds are owned/closed here; there is no ambient reopen.
# The confined walk (§3.2 of the macOS parity design) opens each component
# itself and checks what was opened: Linux refuses a mount crossing at
# lookup, macOS refuses it after the open, with the descriptor closed at once.
{% skip_file unless flag?(:darwin) %}

module Filesystem::Capabilities::Directory::Darwin::EntryResolution
  # One opened folder's mount identity: f_fsid (both words) and f_mntonname.
  # Both must match for two descriptors to name the same mount (§3.2): f_fsid
  # follows the volume, so one file system mounted at two points would share
  # it; a mount stacked over another would keep the mount point.
  private struct MountIdentity
    getter fsid_a : Int32
    getter fsid_b : Int32
    getter mount_point : String

    def initialize(@fsid_a : Int32, @fsid_b : Int32, @mount_point : String)
    end
  end

  def self.open_leaf(parent : Int32, leaf : String, name : String,
                     op : Symbol, flags : Int32, mode : Int32,
                     retry_flags : Int32? = nil) : Int32
    fd = Filesystem::Capabilities::Native::Darwin::At.openat(parent, leaf,
      flags | LibC::O_CLOEXEC | LibC::O_NOFOLLOW, mode)
    if fd < 0 && Errno.value == Errno::EACCES && (flags & Directory::DIRECTORY_ONLY) != 0
      # A search-only folder: the read open fails, the O_SEARCH reference
      # holds it and opens known names beneath it. File opens are not retried:
      # macOS has no O_PATH reference for a file.
      fd = Filesystem::Capabilities::Native::Darwin::At.openat(parent, leaf,
        retry_flags || Directory::SEARCH_DIRECTORY_FLAGS, 0)
    end
    raise Directory::EntryError.new(op, name, Errno.value) if fd < 0
    fd
  end

  def self.with_parent(root : Int32, names : Array(String), operation : Symbol,
                       & : Int32, String, String -> T) : T forall T
    full = names.join('/')
    current = root
    owned = -1
    begin
      names[0...-1].each do |component|
        fd = open_folder_step(current, component, Directory::DIRECTORY_FLAGS,
          Directory::SEARCH_DIRECTORY_FLAGS, operation, full)
        LibC.close(owned) if owned >= 0
        owned = fd
        current = fd
      end
      yield current, names.last, full
    ensure
      LibC.close(owned) if owned >= 0
    end
  end

  # The confined walk of §3.2. Each step is opened relative to the folder
  # before it, no-follow, beneath the start; a denied step is retried as an
  # O_SEARCH reference. Every opened descriptor is checked against the
  # starting folder's identity, read once from its own descriptor when the
  # walk begins, and refused with EXDEV as Linux reports a crossing.
  def self.open_confined(root : Int32, names : Array(String), operation : Symbol,
                         flags : Int32, mode : Int32, policy : MountPolicy) : Int32
    raise ArgumentError.new("At least one path component is required") if names.empty?
    raise ArgumentError.new("Allow is not a confinement policy") if policy.allow?
    full = names.join('/')
    baseline_mount = policy.stay_on_root_mount? ? mount_identity(root, operation, full) : nil
    baseline_device = policy.stay_on_root_device? ? file_device(root, operation, full) : nil
    current = root
    owned = -1
    begin
      names[0...-1].each do |component|
        fd = open_folder_step(current, component, Directory::CONFINED_DIRECTORY_FLAGS,
          Directory::CONFINED_SEARCH_FLAGS, operation, full)
        begin
          verify_confined(fd, baseline_mount, baseline_device, operation, full)
        rescue error
          LibC.close(fd)
          raise error
        end
        LibC.close(owned) if owned >= 0
        owned = fd
        current = fd
      end
      leaf = open_leaf(current, names.last, full, operation,
        flags | Directory::RESOLVE_BENEATH, mode, Directory::CONFINED_SEARCH_FLAGS)
      begin
        verify_confined(leaf, baseline_mount, baseline_device, operation, full)
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

  # A direct child folder, checked as one more step of a confined walk from
  # root: opened no-follow beneath root, retried as an O_SEARCH reference on
  # EACCES, compared with root's mount or device, and closed. An entry's
  # status uses it, so that a mount point named directly under a policy is
  # refused as a walk through it would be.
  def self.verify_confined_child(root : Int32, leaf : String, operation : Symbol,
                                 policy : MountPolicy) : Nil
    raise ArgumentError.new("Allow is not a confinement policy") if policy.allow?
    baseline_mount = policy.stay_on_root_mount? ? mount_identity(root, operation, leaf) : nil
    baseline_device = policy.stay_on_root_device? ? file_device(root, operation, leaf) : nil
    fd = open_folder_step(root, leaf, Directory::CONFINED_DIRECTORY_FLAGS,
      Directory::CONFINED_SEARCH_FLAGS, operation, leaf)
    begin
      verify_confined(fd, baseline_mount, baseline_device, operation, leaf)
    ensure
      LibC.close(fd)
    end
  end

  # Opens one folder step. A read open denied with EACCES is retried as a
  # search-only reference; a folder denied both ways fails with the caller's
  # operation, as the denied leaf of the same call would.
  private def self.open_folder_step(current : Int32, component : String,
                                    flags : Int32, retry_flags : Int32,
                                    operation : Symbol, full : String) : Int32
    fd = Filesystem::Capabilities::Native::Darwin::At.openat(current, component, flags, 0)
    if fd < 0 && Errno.value == Errno::EACCES
      fd = Filesystem::Capabilities::Native::Darwin::At.openat(current, component, retry_flags, 0)
    end
    raise Directory::EntryError.new(operation, full, Errno.value) if fd < 0
    fd
  end

  private def self.verify_confined(fd : Int32, baseline_mount : MountIdentity?,
                                   baseline_device : UInt64?, operation : Symbol, full : String) : Nil
    if baseline_mount
      opened = mount_identity(fd, operation, full)
      unless opened.fsid_a == baseline_mount.fsid_a && opened.fsid_b == baseline_mount.fsid_b &&
             opened.mount_point == baseline_mount.mount_point
        raise Directory::EntryError.new(operation, full, Errno::EXDEV)
      end
    else
      unless file_device(fd, operation, full) == baseline_device
        raise Directory::EntryError.new(operation, full, Errno::EXDEV)
      end
    end
  end

  private def self.mount_identity(fd : Int32, operation : Symbol, full : String) : MountIdentity
    info = uninitialized Filesystem::Capabilities::Native::Darwin::Mounts::StatFs
    if Filesystem::Capabilities::Native::Darwin::Mounts.mount_statfs(fd, pointerof(info).as(Void*)) != 0
      raise Directory::EntryError.new(operation, full, Errno.value)
    end
    MountIdentity.new(info.fsid.val[0], info.fsid.val[1],
      String.new(info.mntonname.to_unsafe))
  end

  private def self.file_device(fd : Int32, operation : Symbol, full : String) : UInt64
    if LibC.fstat(fd, out info) != 0
      raise Directory::EntryError.new(operation, full, Errno.value)
    end
    info.st_dev.to_u64!
  end
end
