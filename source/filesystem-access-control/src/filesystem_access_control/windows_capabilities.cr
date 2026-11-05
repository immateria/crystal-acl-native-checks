# Read-only/native-handle Windows DACL checked access. Creation is unsupported
# until an explicit DACL construction/verification policy exists.
{% skip_file unless flag?(:windows) %}

module Filesystem::AccessControl
  # Unlike inspect_windows_directory(Path), this never reopens by pathname.
  # Validate kind and reparse status on the exact retained HANDLE used to read.
  def self.inspect_windows_handle(handle : Pointer(Void), path : Path, *, expected : Target = Target::Directory) : Report
    info = uninitialized LibC::BY_HANDLE_FILE_INFORMATION
    if LibC.GetFileInformationByHandle(handle, pointerof(info)) == 0 ||
       (info.dwFileAttributes & 0x400) != 0 ||
       ((info.dwFileAttributes & 0x10) != 0) != (expected == Target::Directory)
      raise Filesystem::Capabilities::Error.new("ACL inspection requires an opened non-reparse #{expected}: #{path}")
    end
    windows_report(handle, path)
  end
end

class Filesystem::Capabilities::Directory
  def access_report : Filesystem::AccessControl::Report
    with_directory_handle do |handle|
      Filesystem::AccessControl.inspect_windows_handle(handle, self.path)
    end
  end

  def require_private! : Filesystem::AccessControl::Report
    access_report.require_private!
  end
end
