# Independent Unix directory scanning, owned by the opened capability.
# The caller borrows its root fd only for open(); each() owns and closes the
# resulting descriptor through fdopendir/closedir even on callback exceptions.
{% skip_file unless flag?(:linux) || flag?(:darwin) %}

module Filesystem::Capabilities::Directory::EntryEnumeration
  def self.open(root : Int32, name : String) : Int32
    opened = -1
    {% if flag?(:linux) %}
      flags = LibC::O_RDONLY | LibC::O_CLOEXEC | LibC::O_NOFOLLOW | Platform::DIRECTORY_ONLY
      opened = Filesystem::Capabilities::Native::Linux::At.openat(root, ".", flags, 0)
    {% else %}
      opened = Filesystem::Capabilities::Native::Darwin::At.openat(root, ".", Directory::DIRECTORY_FLAGS, 0)
    {% end %}
    raise Directory::EntryError.new(:list_entries, name, Errno.value) if opened < 0
    opened
  end

  def self.each(fd : Int32, name : String, & : String ->) : Nil
    scan = Directory::EntryScan.new(fd, name)
    begin
      while part = scan.next
        yield part
      end
    ensure
      scan.close
    end
  end
end

# Pull-based scan, scoped by the consumer using `ensure`. The scan fd is
# separately opened from a retained directory, so it owns its own lifetime.
# A scan may be advanced and explicitly closed by different fibers. The
# borrowed DIR* must remain valid until each in-flight readdir finishes.
# RootLease also supports claim-only finalization without a Crystal Fiber.
class Filesystem::Capabilities::Directory
  class EntryScan
    @stream : RootLease(Pointer(LibC::DIR))

    protected def initialize(fd : Int32, @name : String)
      stream = {% if flag?(:linux) %}
                 Filesystem::Capabilities::Native::Linux::At.fdopendir(fd)
               {% else %}
                 Filesystem::Capabilities::Native::Darwin::At.fdopendir(fd)
               {% end %}
      if stream.null?
        failure = Errno.value
        LibC.close(fd)
        raise Directory::EntryError.new(:list_entries, @name, failure)
      end
      lease = begin
        RootLease.new(stream, Pointer(LibC::DIR).null)
      rescue error
        LibC.closedir(stream)
        raise error
      end
      @stream = lease
    end

    def next : String?
      @stream.lock do |stream|
        raise Filesystem::Capabilities::ClosedError.new("Directory entry scan is closed") if stream.null?
        loop do
          Errno.value = Errno::NONE
          entry = LibC.readdir(stream)
          if entry.null?
            failure = Errno.value
            raise Directory::EntryError.new(:list_entries, @name, failure) unless failure == Errno::NONE
            break nil
          end
          part = String.new(entry.value.d_name.to_unsafe)
          break part unless part == "." || part == ".."
        end
      end
    end

    # Test-only synchronization probe: hold the actual native scan lease while
    # an independent worker requests close. Not present in production builds.
    {% if flag?(:directories_scan_test_probe) %}
      def hold_native_borrow_for_test(entered : Channel(Nil), release : Channel(Nil)) : Nil
        @stream.lock do |stream|
          raise Filesystem::Capabilities::ClosedError.new("Directory entry scan is closed") if stream.null?
          entered.send(nil)
          release.receive
        end
      end
    {% end %}

    def close : Nil
      @stream.close { |stream| LibC.closedir(stream) }
    end

    def closed? : Bool
      @stream.closed?
    end

    # A GC finalizer has no Crystal Fiber and cannot acquire a blocking lock.
    def finalize
      @stream.release_on_finalization { |stream| LibC.closedir(stream) }
    end
  end
end
