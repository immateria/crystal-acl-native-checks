# Ordinary Windows entry mutations via pinned NT HANDLEs.
{% skip_file unless flag?(:windows) %}

module Filesystem::Capabilities
  class Directory
    # Resolve parents through pinned, no-reparse handles; then delete the
    # opened final entry rather than reconstructing an ambient pathname.
    # File reparse points are opened as entries, never followed. The older
    # FileDispositionInformation class works without POSIX delete semantics:
    # successful deletion may not become visible until other handles close.
    def remove_file(*components : String) : Nil
      with_parent(components) do |parent, leaf, name|
        target = relative_open(parent, leaf, name, :remove_file, :file,
          EntryMutation::DELETE_ACCESS, allow_final_reparse: true)
        begin
          EntryMutation.delete_open_entry(target, name, :remove_file)
        ensure
          LibC.CloseHandle(target)
        end
      end
    end

    def remove_empty_directory(*components : String) : Nil
      with_parent(components) do |parent, leaf, name|
        # This deliberately rejects junctions and directory symlinks, as
        # Unix unlinkat(AT_REMOVEDIR) rejects final symlinks.
        target = relative_open(parent, leaf, name, :remove_empty_directory, :directory,
          EntryMutation::DELETE_ACCESS)
        begin
          EntryMutation.delete_open_entry(target, name, :remove_empty_directory)
        ensure
          LibC.CloseHandle(target)
        end
      end
    end

    # Cross-directory native HANDLE renaming requires verified Windows
    # FILE_RENAME_INFORMATION destination-root and DACL behavior. It must
    # never fall back to ambient Win32 pathnames or fake no-clobber checks.
    def rename_entry_to(target_directory : Directory, source : String, destination : String) : Nil
      Component.validate(source)
      Component.validate(destination)
      raise Filesystem::Capabilities::UnsupportedOperationError.new("Cross-directory HANDLE rename is not natively verified on Windows")
    end

    def rename_entry_to_no_replace(target_directory : Directory, source : String, destination : String) : Nil
      from = Component.validate(source)
      to = Component.validate(destination)
      raise ArgumentError.new("No-replace source and destination must differ") if same?(target_directory) && from == to
      raise Filesystem::Capabilities::UnsupportedOperationError.new("Atomic cross-directory no-replace rename is not verified on Windows")
    end

    # Legacy FILE_RENAME_INFORMATION (10): the destination is *one validated
    # component* resolved relative to our currently pinned parent HANDLE.
    # This may replace an existing entry and is not an atomic-private-write
    # or crash-durability contract. No Win32 absolute pathname is used.
    # Do not approximate FILE_RENAME_REPLACE_IF_EXISTS with a racy
    # destination preflight. Native no-clobber semantics need Windows proof.
    def rename_entry_no_replace(source : String, destination : String) : Nil
      from = Component.validate(source)
      to = Component.validate(destination)
      raise ArgumentError.new("No-replace source and destination must differ") if from == to
      raise Filesystem::Capabilities::UnsupportedOperationError.new("Atomic no-replace rename requires a verified native implementation on Windows")
    end

    def rename_entry(source : String, destination : String) : Nil
      from = Component.validate(source)
      to = Component.validate(destination)
      with_parent({from}) do |parent, leaf, name|
        target = relative_open(parent, leaf, name, :rename_entry, :any,
          EntryMutation::DELETE_ACCESS, allow_final_reparse: true)
        begin
          EntryMutation.rename_open_entry(target, parent, to, name)
        ensure
          LibC.CloseHandle(target)
        end
      end
    end
  end
end

# The native mutation protocol has no ownership of the root or opened target;
# the facade guarantees both borrow and temporary target cleanup.
module Filesystem::Capabilities::Directory::EntryMutation
  DELETE_ACCESS = 0x00110080_u32

  def self.delete_open_entry(target : Pointer(Void), name : String, operation : Symbol) : Nil
    # FILE_DISPOSITION_INFORMATION is a BOOLEAN, not a 32-bit BOOL.
    delete_flag = 1_u8
    status = LibC::IO_STATUS_BLOCK.new
    result = Native::Windows::Nt.NtSetInformationFile(target, pointerof(status),
      pointerof(delete_flag).as(Void*), 1_u32, 13)
    raise Directory::EntryError.new(operation, name, result) unless result == 0
  end

  def self.rename_open_entry(target : Pointer(Void), parent : Pointer(Void),
                             destination : String, name : String) : Nil
    units = destination.to_utf16
    # 64-bit FILE_RENAME_INFORMATION layout: ReplaceIfExists at 0,
    # RootDirectory at 8, FileNameLength at 16, UTF-16 FileName at 20.
    # Support only the already-compiled Windows x86-64 and AArch64 lanes.
    raise Filesystem::Capabilities::Error.new("Unsupported Windows HANDLE size") unless sizeof(Void*) == 8
    raise ArgumentError.new("Windows component exceeds UnicodeString limit") if units.size > 32766
    # sizeof(FILE_RENAME_INFORMATION) is 24 on Windows x64/ARM64,
    # including the one-unit trailing FileName field and tail padding.
    total = {24, 20 + units.size * 2}.max
    backing = Slice(UInt64).new((total + 7) // 8, 0_u64)
    data = backing.to_unsafe.as(Pointer(UInt8))
    data.value = 1_u8 # ReplaceIfExists = TRUE
    (data + 8).as(Pointer(Pointer(Void))).value = parent
    (data + 16).as(Pointer(UInt32)).value = (units.size * 2).to_u32
    units.copy_to(Slice(UInt16).new((data + 20).as(Pointer(UInt16)), units.size))
    status = LibC::IO_STATUS_BLOCK.new
    result = Native::Windows::Nt.NtSetInformationFile(target, pointerof(status),
      data.as(Void*), total.to_u32, 10)
    raise Directory::EntryError.new(:rename_entry, name, result) unless result == 0
  end
end
