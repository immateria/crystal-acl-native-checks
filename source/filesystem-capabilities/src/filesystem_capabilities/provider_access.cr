# Internal extension contract for optional providers. The capability owner
# alone knows the root's storage, closed sentinel and synchronization protocol.
{% skip_file unless flag?(:linux) || flag?(:darwin) || flag?(:windows) %}

class Filesystem::Capabilities::Directory
  {% if flag?(:windows) %}
    private alias NativeDirectoryHandle = Pointer(Void)
  {% else %}
    private alias NativeDirectoryHandle = Int32
  {% end %}

  # :nodoc:
  # Borrow, never retain or close, the supplied root. Only native provider
  # operations belong in this callback; application callbacks run after it.
  protected def with_directory_handle(& : NativeDirectoryHandle -> T) : T forall T
    @descriptor.lock do |handle|
      {% if flag?(:windows) %}
        raise Filesystem::Capabilities::ClosedError.new("Directory capability handle is closed") if handle.null?
      {% else %}
        raise Filesystem::Capabilities::ClosedError.new("Directory capability handle is closed") if handle < 0
      {% end %}
      yield handle
    end
  end

  # :nodoc:
  # Adopt a provider-verified child on success. Until construction succeeds,
  # the caller owns the native handle and must close it on failure.
  protected def self.from_verified_child(path : Path, handle : NativeDirectoryHandle) : Directory
    new(path, handle)
  end
end
