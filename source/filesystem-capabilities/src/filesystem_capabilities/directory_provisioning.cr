# Portable no-follow directory provisioning policy; native creation stays in entry mutation.
{% skip_file unless flag?(:linux) || flag?(:darwin) || flag?(:windows) %}

class Filesystem::Capabilities::Directory
  # Directory modes are intentionally restricted to owner bits. This does
  # not establish effective privacy on ACL-capable filesystems.
  private def validate_directory_mode(mode : Int32) : Nil
    unless mode > 0 && (mode & ~0o700) == 0
      raise ArgumentError.new("Capability directory mode must be a nonzero subset of 0700")
    end
  end

  # Return an owned directory capability while creating only missing entries.
  # Validate every component and the creation mode before modifying anything.
  # Existing directories are not chmodded or ACL-certified; their names are
  # resolved without following symlinks, one pinned parent at a time.
  {% if flag?(:linux) || flag?(:darwin) %}
    def ensure_subdirectory(components : Array(String), *, mode : Int32 = 0o700) : Directory
      validate_directory_mode(mode)
      names = components.map { |part| Component.validate(part) }
      raise ArgumentError.new("At least one path component is required") if names.empty?

      current = self
      owned = nil.as(Directory?)
      begin
        names.each do |part|
          next_dir = begin
            current.open_subdirectory(part)
          rescue error : EntryError
            raise error unless error.errno == Errno::ENOENT
            begin
              current.create_directory(part, mode: mode)
            rescue collision : EntryError
              # A concurrent creator may have won. Reopen without following
              # symlinks and insist that the new entry is a directory.
              raise collision unless collision.errno == Errno::EEXIST
            end
            current.open_subdirectory(part)
          end
          owned.try(&.close)
          owned = next_dir
          current = next_dir
        end
        result = owned.not_nil!
        owned = nil
        result
      ensure
        owned.try(&.close)
      end
    end

    # Tuple/varargs callers and dynamic project-path callers share one owner.
    def ensure_subdirectory(*components : String, mode : Int32 = 0o700) : Directory
      ensure_subdirectory(components.to_a, mode: mode)
    end

    # Preserve the original no-return convenience API through the one
    # descriptor-owning provisioning implementation.
    def ensure_directories(*components : String, mode : Int32 = 0o700) : Nil
      ensure_subdirectory(components.to_a, mode: mode).close
    end
  {% elsif flag?(:windows) %}
    def ensure_subdirectory(components : Array(String), *, mode : Int32 = 0o700) : Directory
      raise Filesystem::Capabilities::UnsupportedOperationError.new("Windows handle-relative directory provisioning is not implemented")
    end

    def ensure_subdirectory(*components : String, mode : Int32 = 0o700) : Directory
      raise Filesystem::Capabilities::UnsupportedOperationError.new("Windows handle-relative directory provisioning is not implemented")
    end

    def ensure_directories(*components : String, mode : Int32 = 0o700) : Nil
      raise Filesystem::Capabilities::UnsupportedOperationError.new("Windows handle-relative directory provisioning is not implemented")
    end
  {% end %}
end
