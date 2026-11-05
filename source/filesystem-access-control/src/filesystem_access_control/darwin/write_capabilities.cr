{% skip_file unless flag?(:darwin) %}

require "./writer"

module Filesystem::Capabilities
  class Directory
    def replace_acl(*, target : Filesystem::AccessControl::Darwin::Snapshot,
                    acl : Filesystem::AccessControl::Darwin::DesiredACL) : Filesystem::AccessControl::Darwin::MutationResult
      with_directory_handle do |fd|
        Filesystem::AccessControl::Darwin::Writer.replace_fd(fd, target: target, acl: acl)
      end
    end

    def remove_acl(*, target : Filesystem::AccessControl::Darwin::Snapshot) : Filesystem::AccessControl::Darwin::MutationResult
      with_directory_handle do |fd|
        Filesystem::AccessControl::Darwin::Writer.remove_fd(fd, target: target)
      end
    end

    # Descriptor-based opt-in mutation. The final component is opened relative
    # to the held root without following symlinks or requesting data-read rights.
    def replace_acl(*components : String, target : Filesystem::AccessControl::Darwin::Snapshot,
                    acl : Filesystem::AccessControl::Darwin::DesiredACL) : Filesystem::AccessControl::Darwin::MutationResult
      with_acl_write_leaf(components) do |fd|
        Filesystem::AccessControl::Darwin::Writer.replace_fd(fd, target: target, acl: acl)
      end
    end

    def remove_acl(*components : String,
                   target : Filesystem::AccessControl::Darwin::Snapshot) : Filesystem::AccessControl::Darwin::MutationResult
      with_acl_write_leaf(components) do |fd|
        Filesystem::AccessControl::Darwin::Writer.remove_fd(fd, target: target)
      end
    end

    private def with_acl_write_leaf(components : Tuple, & : Int32 -> T) : T forall T
      if components.empty?
        return with_directory_handle { |fd| yield fd }
      end
      with_parent(components, :acl_write) do |parent, leaf, name|
        flags = Filesystem::AccessControl::Darwin::Writer::O_EVTONLY |
                LibC::O_CLOEXEC | LibC::O_NOFOLLOW | LibC::O_NONBLOCK
        fd = open_leaf(parent, leaf, name, :acl_write, flags, 0)
        begin
          yield fd
        ensure
          LibC.close(fd)
        end
      end
    end
  end
end
