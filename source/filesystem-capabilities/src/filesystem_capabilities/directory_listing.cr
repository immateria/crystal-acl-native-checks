# Opened-handle enumeration, independent scan resource and name materialization.
{% skip_file unless flag?(:linux) || flag?(:darwin) || flag?(:windows) %}

class Filesystem::Capabilities::Directory
  # Enumeration owns an independent OS scan handle; the root capability is
  # borrowed only long enough to acquire that handle, never during callbacks.
  # This intentionally does not attest privacy or a stable directory snapshot.
  private module EntryEnumeration
  end

  # Entry mutation owns native syscalls but borrows a parent from Directory.
  # It cannot acquire, close, or replace the retained root handle.
  private module EntryMutation
  end

  def each_entry(& : String ->) : Nil
    scan = @descriptor.lock do |root|
      {% if flag?(:windows) %}
        raise Filesystem::Capabilities::ClosedError.new("Directory capability handle is closed") if root.null?
      {% else %}
        raise Filesystem::Capabilities::ClosedError.new("Directory capability handle is closed") if root < 0
      {% end %}
      EntryEnumeration.open(root, @path.to_s)
    end
    EntryEnumeration.each(scan, @path.to_s) { |name| yield name }
  end

  # Open an independently owned, incremental directory listing. Unlike
  # #entry_names, this does not materialize the directory. The caller must
  # close the scan; the root capability can close independently afterwards.
  # Entries are names, not authority to reopen ambient paths.
  def open_entry_scan : EntryScan
    {% if flag?(:windows) %}
      # Allocate before acquiring the independently owned HANDLE so an
      # allocation failure cannot strand a native listing resource.
      storage = Slice(UInt64).new(EntryEnumeration::NAME_BUFFER_BYTES // 8, 0_u64)
    {% end %}
    scan = @descriptor.lock do |root|
      {% if flag?(:windows) %}
        raise Filesystem::Capabilities::ClosedError.new("Directory capability handle is closed") if root.null?
      {% else %}
        raise Filesystem::Capabilities::ClosedError.new("Directory capability handle is closed") if root < 0
      {% end %}
      EntryEnumeration.open(root, @path.to_s)
    end
    {% if flag?(:windows) %}
      EntryScan.new(scan, @path.to_s, storage)
    {% else %}
      EntryScan.new(scan, @path.to_s)
    {% end %}
  end

  # Block form guarantees release even if the caller raises or stops early.
  def open_entry_scan(& : EntryScan -> T) : T forall T
    scan = open_entry_scan
    begin
      yield scan
    ensure
      scan.close
    end
  end

  # The enumeration backend is platform-specific; materializing its returned
  # names has exactly one owner and never opens an ambient pathname.
  def entry_names : Array(String)
    names = [] of String
    each_entry { |name| names << name }
    names
  end
end
