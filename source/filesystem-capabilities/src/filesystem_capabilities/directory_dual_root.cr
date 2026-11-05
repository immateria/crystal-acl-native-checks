# Deadlock-free two-root descriptor borrow for handle-relative renames.
{% skip_file unless flag?(:linux) || flag?(:darwin) || flag?(:windows) %}

class Filesystem::Capabilities::Directory
  # Borrow two independent roots in a stable order. Calling a native rename
  # with one root already closed must never race a reused descriptor. Object
  # identity orders locks even for opposite-direction concurrent moves.
  # A move within the same handle must acquire its non-reentrant lease once.
  {% if flag?(:linux) || flag?(:darwin) %}
    private def with_two_roots(destination_directory : Directory,
                               & : Int32, Int32 -> T) : T forall T
      if same?(destination_directory)
        @descriptor.lock do |source_root|
          raise ClosedError.new("Directory capability handle is closed") if source_root < 0
          yield source_root, source_root
        end
      elsif object_id < destination_directory.object_id
        @descriptor.lock do |source_root|
          raise ClosedError.new("Source directory capability handle is closed") if source_root < 0
          destination_directory.@descriptor.lock do |target_root|
            raise ClosedError.new("Destination directory capability handle is closed") if target_root < 0
            yield source_root, target_root
          end
        end
      else
        destination_directory.@descriptor.lock do |target_root|
          raise ClosedError.new("Destination directory capability handle is closed") if target_root < 0
          @descriptor.lock do |source_root|
            raise ClosedError.new("Source directory capability handle is closed") if source_root < 0
            yield source_root, target_root
          end
        end
      end
    end

    # Replacing cross-parent rename has identical validated capability and
    # retained-root ownership policy on Linux and Darwin; the native syscall
    # and errno translation still belong to each platform's EntryMutation.
    def rename_entry_to(target_directory : Directory, source : String, destination : String) : Nil
      from = Component.validate(source)
      to = Component.validate(destination)
      with_two_roots(target_directory) do |source_root, target_root|
        EntryMutation.rename_between(source_root, from, target_root, to, from)
      end
    end
  {% end %}
end
