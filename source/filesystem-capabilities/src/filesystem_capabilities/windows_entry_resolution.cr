# Borrowed Windows RootDirectory-relative name resolution. This module
# owns the NT open/reparse/type protocol and only intermediate child handles.
# The public Directory owns the retained root, its lock and validation.
{% skip_file unless flag?(:windows) %}

module Filesystem::Capabilities::Directory::Windows::EntryResolution
  def self.check_kind(handle : Pointer(Void), kind : Symbol, name : String,
                      allow_reparse : Bool = false) : Nil
    info = uninitialized LibC::BY_HANDLE_FILE_INFORMATION
    if LibC.GetFileInformationByHandle(handle, pointerof(info)) == 0
      raise Filesystem::Capabilities::Error.new("Cannot inspect opened Windows entry: #{name.inspect}")
    end
    attrs = info.dwFileAttributes
    if ((attrs & 0x400) != 0 && !allow_reparse) ||
       (kind != :any && ((attrs & 0x10) != 0) != (kind == :directory))
      raise Filesystem::Capabilities::Error.new("Confined Windows entry must be a non-reparse #{kind}: #{name.inspect}")
    end
  end

  def self.open_relative(parent : Pointer(Void), leaf : String, name : String,
                         operation : Symbol, kind : Symbol, access : UInt32,
                         allow_final_reparse : Bool = false) : Pointer(Void)
    units = leaf.to_utf16
    raise ArgumentError.new("Windows component exceeds UnicodeString limit") if units.size > 32766
    name_buf = Slice(UInt16).new(units.size + 1, 0_u16)
    units.copy_to(name_buf)
    unicode = LibC::UNICODE_STRING.new
    unicode.length = (units.size * 2).to_u16
    unicode.maximumLength = ((units.size + 1) * 2).to_u16
    unicode.buffer = name_buf.to_unsafe
    attrs = LibC::OBJECT_ATTRIBUTES.new
    attrs.length = sizeof(LibC::OBJECT_ATTRIBUTES).to_u32
    attrs.rootDirectory = parent
    attrs.objectName = pointerof(unicode)
    attrs.attributes = 0x40_u32 # OBJ_CASE_INSENSITIVE
    attrs.securityDescriptor = Pointer(Void).null
    attrs.securityQualityOfService = Pointer(Void).null
    options = 0x00200020_u32 | (kind == :directory ? 0x1_u32 : kind == :file ? 0x40_u32 : 0_u32)
    opened = Pointer(Void).null
    ios = LibC::IO_STATUS_BLOCK.new
    code = Filesystem::Capabilities::Native::Windows::Nt.NtCreateFile(pointerof(opened), access,
      pointerof(attrs), pointerof(ios), Pointer(Int64).null, 0_u32, 7_u32, 1_u32,
      options, Pointer(Void).null, 0_u32)
    raise Directory::EntryError.new(operation, name, code) if code < 0 || opened.null?
    begin
      check_kind(opened, kind, name, allow_reparse: allow_final_reparse)
      opened
    rescue error
      LibC.CloseHandle(opened)
      raise error
    end
  end

  def self.with_parent(root : Pointer(Void), names : Array(String),
                       & : Pointer(Void), String, String -> T) : T forall T
    full = names.join('/')
    current = root
    owned = Pointer(Void).null
    begin
      names[0...-1].each do |component|
        child = open_relative(current, component, full, :traverse, :directory,
          Directory::CHILD_DIRECTORY_ACCESS)
        LibC.CloseHandle(owned) unless owned.null?
        owned = child
        current = child
      end
      yield current, names.last, full
    ensure
      LibC.CloseHandle(owned) unless owned.null?
    end
  end
end
