# Owned handle block wrappers and validation shared by native backends.
# Common owned-handle block API, independent of the native backend.
# Opening returns an independent handle; ensure must close it on normal return,
# raised callbacks, and non-local exits without holding a parent descriptor lock.
{% skip_file unless flag?(:linux) || flag?(:darwin) || flag?(:windows) %}

class Filesystem::Capabilities::Directory
  # Descriptor-to-IO transfer is provider-internal on both Unix platforms.
  {% if flag?(:linux) || flag?(:darwin) %}
    private module RegularFile
    end
  {% end %}

  # Every block-form entry API transfers temporary ownership to this one
  # cleanup boundary. Protected providers may reuse the scope without owning
  # its cleanup implementation; ordinary consumers cannot call this helper.
  protected def with_owned_resource(resource : Resource, & : Resource -> T) : T forall Resource, T
    begin
      yield resource
    ensure
      resource.close
    end
  end

  private def validate_file_mode(mode : Int32) : Nil
    unless mode > 0 && (mode & ~0o600) == 0
      raise ArgumentError.new("Capability file mode must be a nonzero subset of 0600")
    end
  end

  def ensure_subdirectory : Directory
    raise ArgumentError.new("At least one path component is required")
  end

  def ensure_subdirectory(*components : String, mode : Int32 = 0o700, & : Directory -> T) : T forall T
    with_owned_resource(ensure_subdirectory(*components, mode: mode)) { |owned| yield owned }
  end

  # The operation an EntryError names for a confined open, so that a
  # failure says which policy refused it.
  private def confined_operation(base : Symbol, mount : MountPolicy) : Symbol
    mounts = mount.stay_on_root_mount?
    case base
    when :open_read         then mounts ? :open_read_no_cross_mount : :open_read_no_cross_device
    when :create_exclusive  then mounts ? :create_exclusive_no_cross_mount : :create_exclusive_no_cross_device
    when :open_subdirectory then mounts ? :open_subdirectory_no_cross_mount : :open_subdirectory_no_cross_device
    when :entry_status      then mounts ? :entry_status_no_cross_mount : :entry_status_no_cross_device
    when :entry_type        then mounts ? :entry_type_no_cross_mount : :entry_type_no_cross_device
    else                         raise ArgumentError.new("No confined operation for #{base}")
    end
  end

  def self.open_existing(path : Path, & : Directory -> T) : T forall T
    directory = open_existing(path)
    begin
      yield directory
    ensure
      directory.close
    end
  end

  def self.open_existing_no_symlinks(path : Path, & : Directory -> T) : T forall T
    directory = open_existing_no_symlinks(path)
    begin
      yield directory
    ensure
      directory.close
    end
  end

  def open_read(*components : String, mount : MountPolicy = MountPolicy::Allow,
                & : IO::FileDescriptor -> T) : T forall T
    with_owned_resource(open_read(*components, mount: mount)) { |owned| yield owned }
  end

  def create_exclusive(*components : String, mode : Int32 = 0o600, mount : MountPolicy = MountPolicy::Allow,
                       & : IO::FileDescriptor -> T) : T forall T
    with_owned_resource(create_exclusive(*components, mode: mode, mount: mount)) { |owned| yield owned }
  end

  def open_subdirectory(*components : String, mount : MountPolicy = MountPolicy::Allow,
                        & : Directory -> T) : T forall T
    with_owned_resource(open_subdirectory(*components, mount: mount)) { |owned| yield owned }
  end
end
