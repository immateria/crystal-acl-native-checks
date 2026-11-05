# Windows existing-root HANDLE admission. The returned handle is unowned
# until Directory adopts it. All child operations remain RootDirectory-relative;
# no claim is made about symbolic links or reparse points in root ancestors.
{% skip_file unless flag?(:windows) %}

module Filesystem::Capabilities::Directory::Windows::RootAdmission
  def self.open_ordinary(path : Path) : Pointer(Void)
    RootPath.validate_existing(path)
    units = path.to_s.to_utf16
    name = Slice(UInt16).new(units.size + 1, 0_u16)
    units.copy_to(name)
    handle = LibC.CreateFileW(name.to_unsafe, Directory::ROOT_ACCESS,
      7_u32, Pointer(LibC::SECURITY_ATTRIBUTES).null, 3_u32,
      0x02200000_u32, Pointer(Void).null)
    raise Directory::EntryError.new(:open_root, path.to_s) if handle == LibC::INVALID_HANDLE_VALUE
    begin
      Windows::EntryResolution.check_kind(handle, :directory, path.to_s)
      handle
    rescue error
      LibC.CloseHandle(handle)
      raise error
    end
  end
end
