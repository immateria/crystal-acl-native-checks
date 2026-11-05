# Ordinary Darwin entry mutations beneath the borrowed opened parent.
{% skip_file unless flag?(:darwin) %}

module Filesystem::Capabilities
  class Directory
    # Exclusive, single-leaf directory creation; the caller must open a
    # separate private-policy provider to assert ACL privacy.
    def create_directory(*components : String, mode : Int32 = 0o700) : Nil
      validate_directory_mode(mode)
      with_parent(components, :create_directory) do |parent, leaf, full|
        EntryMutation.create_directory(parent, leaf, full, mode)
      end
    end

    # Entry unlink never dereferences the final symlink. Concurrent mutation
    # can change the last entry's identity before the syscall completes.
    def remove_file(*components : String) : Nil
      with_parent(components, :remove_file) do |parent, leaf, full|
        EntryMutation.remove_file(parent, leaf, full)
      end
    end

    # Delete only an empty directory, with all ancestors traversed no-follow.
    def remove_empty_directory(*components : String) : Nil
      with_parent(components, :remove_empty_directory) do |parent, leaf, full|
        EntryMutation.remove_empty_directory(parent, leaf, full)
      end
    end

    # Rename direct entries within the opened parent. A destination may be
    # replaced; this is neither an ACL audit nor a durable publication API.
    def rename_entry(source : String, destination : String) : Nil
      from = Component.validate(source)
      to = Component.validate(destination)
      with_parent({from}, :rename_entry) do |parent, _, full|
        EntryMutation.rename_entry(parent, from, to, full)
      end
    end

    # renameatx_np with RENAME_EXCL refuses an existing destination in the
    # same call, as Linux's renameat2 does. A file system that cannot, such
    # as ExFAT (ENOTSUP), fails closed with its errno; there is no fallback.
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
    # opened directory, as on Linux: an existing destination, even a dangling
    # symlink, is never overwritten, and no ambient path is resolved.
    def rename_entry_no_replace(source : String, destination : String) : Nil
      from = Component.validate(source)
      to = Component.validate(destination)
      raise ArgumentError.new("No-replace source and destination must differ") if from == to
      with_parent({from}, :rename_entry_no_replace) do |parent, _, full|
        EntryMutation.rename_entry_no_replace(parent, from, to, full)
      end
    end
  end
end

# Darwin syscalls are separate from Linux and cannot claim Linux renameat2.
module Filesystem::Capabilities::Directory::EntryMutation
  # renameatx_np's flag, from Darwin sys/stdio.h.
  RENAME_EXCL = 0x00000004_u32

  def self.create_directory(parent : Int32, leaf : String, full : String, mode : Int32) : Nil
    if Filesystem::Capabilities::Native::Darwin::At.mkdirat(parent, leaf, mode) < 0
      raise Directory::EntryError.new(:create_directory, full, Errno.value)
    end
  end

  def self.remove_file(parent : Int32, leaf : String, full : String) : Nil
    if Filesystem::Capabilities::Native::Darwin::At.unlinkat(parent, leaf, 0) < 0
      raise Directory::EntryError.new(:remove_file, full, Errno.value)
    end
  end

  def self.remove_empty_directory(parent : Int32, leaf : String, full : String) : Nil
    if Filesystem::Capabilities::Native::Darwin::At.unlinkat(parent, leaf, Directory::REMOVE_DIRECTORY_ENTRY) < 0
      raise Directory::EntryError.new(:remove_empty_directory, full, Errno.value)
    end
  end

  def self.rename_entry(parent : Int32, from : String, to : String, full : String) : Nil
    rename_between(parent, from, parent, to, full, :rename_entry)
  end

  def self.rename_between(source_parent : Int32, from : String,
                          destination_parent : Int32, to : String, full : String,
                          operation : Symbol = :rename_entry_to) : Nil
    if Filesystem::Capabilities::Native::Darwin::At.renameat(source_parent, from, destination_parent, to) < 0
      raise Directory::EntryError.new(operation, full, Errno.value)
    end
  end

  def self.rename_entry_no_replace(parent : Int32, from : String, to : String, full : String) : Nil
    rename_between_no_replace(parent, from, parent, to, full, :rename_entry_no_replace)
  end

  def self.rename_between_no_replace(source_parent : Int32, from : String,
                                     destination_parent : Int32, to : String, full : String,
                                     operation : Symbol = :rename_entry_to_no_replace) : Nil
    if Filesystem::Capabilities::Native::Darwin::At.renameatx_np(source_parent, from, destination_parent, to, RENAME_EXCL) != 0
      raise Directory::EntryError.new(operation, full, Errno.value)
    end
  end
end
