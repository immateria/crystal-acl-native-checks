# Ordinary Linux entry mutations beneath the borrowed opened parent.
{% skip_file unless flag?(:linux) %}

module Filesystem::Capabilities
  class Directory
    # Create exactly one directory entry under existing, no-follow parents.
    # The mode restricts Unix permission bits but is NOT a private ACL proof.
    # A leaf collision is an error; no implicit ancestor creation occurs.
    def create_directory(*components : String, mode : Int32 = 0o700) : Nil
      validate_directory_mode(mode)
      names = validate(components)
      with_parent(names) do |parent, leaf, full|
        EntryMutation.create_directory(parent, leaf, full, mode)
      end
    end

    # Remove a file *entry*, not the target of a final symlink. The parent
    # traversal never follows links. A concurrent rename may still change
    # which entry this name denotes; this is not identity-checked deletion.
    def remove_file(*components : String) : Nil
      names = validate(components)
      with_parent(names) do |parent, leaf, full|
        EntryMutation.remove_file(parent, leaf, full)
      end
    end

    # Remove only an empty directory; refuse symlinks in parent components.
    def remove_empty_directory(*components : String) : Nil
      names = validate(components)
      with_parent(names) do |parent, leaf, full|
        EntryMutation.remove_empty_directory(parent, leaf, full)
      end
    end

    # Rename two direct children of this opened directory. This can replace
    # an existing target, is not ACL/private checked, and does not fsync.
    # Open a child capability to rename within a deeper directory.
    def rename_entry(source : String, destination : String) : Nil
      from = Component.validate(source)
      to = Component.validate(destination)
      with_parent([from]) do |parent, _, full|
        EntryMutation.rename_entry(parent, from, to, full)
      end
    end

    # No separate existence check: Linux must enforce destination absence in
    # the same renameat2 syscall. An unavailable kernel/filesystem fails closed.
    def rename_entry_to_no_replace(target_directory : Directory, source : String, destination : String) : Nil
      from = Component.validate(source)
      to = Component.validate(destination)
      if same?(target_directory) && from == to
        raise ArgumentError.new("No-replace source and destination must differ")
      end
      with_two_roots(target_directory) do |source_root, target_root|
        EntryMutation.rename_between_no_replace(source_root, from, target_root, to, from)
      end
    end

    # Kernel-atomic, non-replacing rename of two direct entries beneath the
    # opened directory. An existing destination (even a dangling symlink)
    # is never overwritten. No check-then-rename race, ambient pathname
    # fallback, ACL privacy claim, or durable fsync is implied. The kernel
    # and filesystem must implement RENAME_NOREPLACE; errors propagate.
    def rename_entry_no_replace(source : String, destination : String) : Nil
      from = Component.validate(source)
      to = Component.validate(destination)
      raise ArgumentError.new("No-replace source and destination must differ") if from == to
      with_parent([from]) do |parent, _, full|
        EntryMutation.rename_entry_no_replace(parent, from, to, full)
      end
    end
  end
end

# Syscall authority only. This internal module neither owns nor closes the
# pinned root; the enclosing Directory holds its lock until each call returns.
module Filesystem::Capabilities::Directory::EntryMutation
  def self.create_directory(parent : Int32, leaf : String, full : String, mode : Int32) : Nil
    if Filesystem::Capabilities::Native::Linux::At.mkdirat(parent, leaf, mode) < 0
      raise Directory::EntryError.new(:create_directory, full, Errno.value)
    end
  end

  def self.remove_file(parent : Int32, leaf : String, full : String) : Nil
    if Filesystem::Capabilities::Native::Linux::At.unlinkat(parent, leaf, 0) < 0
      raise Directory::EntryError.new(:remove_file, full, Errno.value)
    end
  end

  def self.remove_empty_directory(parent : Int32, leaf : String, full : String) : Nil
    if Filesystem::Capabilities::Native::Linux::At.unlinkat(parent, leaf, Platform::REMOVE_DIRECTORY_ENTRY) < 0
      raise Directory::EntryError.new(:remove_empty_directory, full, Errno.value)
    end
  end

  def self.rename_entry(parent : Int32, from : String, to : String, full : String) : Nil
    rename_between(parent, from, parent, to, full, :rename_entry)
  end

  def self.rename_between(source_parent : Int32, from : String,
                          destination_parent : Int32, to : String, full : String,
                          operation : Symbol = :rename_entry_to) : Nil
    if Filesystem::Capabilities::Native::Linux::At.renameat(source_parent, from, destination_parent, to) < 0
      raise Directory::EntryError.new(operation, full, Errno.value)
    end
  end

  def self.rename_entry_no_replace(parent : Int32, from : String, to : String, full : String) : Nil
    rename_between_no_replace(parent, from, parent, to, full, :rename_entry_no_replace)
  end

  def self.rename_between_no_replace(source_parent : Int32, from : String,
                                     destination_parent : Int32, to : String, full : String,
                                     operation : Symbol = :rename_entry_to_no_replace) : Nil
    status = -1
    {% if flag?(:directories_rename_noreplace_test_probe) %}
      if failure = ENV["DIRECTORIES_RENAME_NOREPLACE_TEST_ERRNO"]?
        Errno.value = case failure
                      when "ENOSYS" then Errno::ENOSYS
                      when "EINVAL" then Errno::EINVAL
                      when "EPERM"  then Errno::EPERM
                      when "ENOSPC" then Errno::ENOSPC
                      when "EROFS"  then Errno::EROFS
                      when "EDQUOT" then Errno::EDQUOT
                      else               raise ArgumentError.new("Unsupported no-replace fault code")
                      end
        status = -1
      else
        status = Filesystem::Capabilities::Native::Linux::At.renameat2(source_parent, from, destination_parent, to,
          Platform::RENAME_NOREPLACE)
      end
    {% else %}
      status = Filesystem::Capabilities::Native::Linux::At.renameat2(source_parent, from, destination_parent, to,
        Platform::RENAME_NOREPLACE)
    {% end %}
    raise Directory::EntryError.new(operation, full, Errno.value) if status != 0
  end
end
