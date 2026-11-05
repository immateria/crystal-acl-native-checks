module Filesystem::AccessControl::Windows
  # Native ACCESS_MASK bits. File/directory aliases share their Windows value;
  # retaining an unknown observation does not make it a supported request.
  @[Flags]
  enum Rights : UInt32
    ReadData             = 0x00000001
    ListDirectory        = 0x00000001
    WriteData            = 0x00000002
    AddFile              = 0x00000002
    AppendData           = 0x00000004
    AddSubdirectory      = 0x00000004
    ReadEA               = 0x00000008
    WriteEA              = 0x00000010
    Execute              = 0x00000020
    Traverse             = 0x00000020
    DeleteChild          = 0x00000040
    ReadAttributes       = 0x00000080
    WriteAttributes      = 0x00000100
    Delete               = 0x00010000
    ReadControl          = 0x00020000
    WriteDacl            = 0x00040000
    WriteOwner           = 0x00080000
    Synchronize          = 0x00100000
    FileAllAccess        = 0x001f01ff
    AccessSystemSecurity = 0x01000000
    MaximumAllowed       = 0x02000000
    GenericAll           = 0x10000000
    GenericExecute       = 0x20000000
    GenericWrite         = 0x40000000
    GenericRead          = 0x80000000

    # Initial fixed filesystem request profile. MAXIMUM_ALLOWED asks a
    # different question, and SACL access requires separate privilege evidence.
    # The empty request remains explicit rather than becoming F_OK/existence.
    def validate_file_request! : Nil
      if (value & ~0xf01f01ff_u32) != 0
        raise ArgumentError.new("Unsupported fixed filesystem access request")
      end
    end
  end

  # Portable value for the Win32 GENERIC_MAPPING fields, not a native pointer.
  struct GenericMapping
    getter read : UInt32
    getter write : UInt32
    getter execute : UInt32
    getter all : UInt32

    # File and directory generic mappings have the same native bit values.
    FILESYSTEM = new(0x00120089_u32, 0x00120116_u32, 0x001200a0_u32, 0x001f01ff_u32)

    def initialize(@read : UInt32, @write : UInt32, @execute : UInt32, @all : UInt32)
      if ((@read | @write | @execute | @all) & 0xf0000000_u32) != 0
        raise ArgumentError.new("Generic mapping must contain only nongeneric rights")
      end
    end

    def expand(permissions : Rights) : Rights
      raw = permissions.value
      expanded = raw & 0x0fffffff_u32
      expanded |= @read if (raw & 0x80000000_u32) != 0
      expanded |= @write if (raw & 0x40000000_u32) != 0
      expanded |= @execute if (raw & 0x20000000_u32) != 0
      expanded |= @all if (raw & 0x10000000_u32) != 0
      Rights.new(expanded)
    end

    def_equals_and_hash @read, @write, @execute, @all
  end
end
