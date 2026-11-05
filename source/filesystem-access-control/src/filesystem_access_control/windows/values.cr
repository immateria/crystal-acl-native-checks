module Filesystem::AccessControl::Windows
  enum ACLPresence
    NotQueried
    Unavailable
    Absent
    Null
    Present
  end

  # Header flags only: these do not interpret an ACE's body or predict the
  # result of a native inheritance operation.
  @[Flags]
  enum ACEInheritance : UInt8
    ObjectInherit    = 0x01
    ContainerInherit = 0x02
    NoPropagate      = 0x04
    InheritOnly      = 0x08
    Inherited        = 0x10
  end

  # Binary validity does not promise acceptance by Windows' text SID parser.
  class SID
    @bytes : Bytes

    def initialize(bytes : Bytes)
      unless bytes.size >= 8 && bytes[0] == 1 && bytes[1] <= 15 && bytes.size == 8 + 4 * bytes[1].to_i
        raise ArgumentError.new("Invalid binary SID length or revision")
      end
      @bytes = bytes.dup
    end

    def bytes : Bytes
      @bytes.dup
    end

    def_equals_and_hash @bytes
  end

  # The Windows GUID byte layout stores its first three integer fields in
  # little-endian order. Exact bytes remain the equality/ownership boundary.
  class GUID
    @bytes : Bytes

    def initialize(bytes : Bytes)
      raise ArgumentError.new("Invalid Windows GUID length") unless bytes.size == 16
      @bytes = bytes.dup
    end

    def bytes : Bytes
      @bytes.dup
    end

    def to_s(io : IO) : Nil
      io << IO::ByteFormat::LittleEndian.decode(UInt32, @bytes[0, 4]).to_s(16).rjust(8, '0') << '-'
      io << IO::ByteFormat::LittleEndian.decode(UInt16, @bytes[4, 2]).to_s(16).rjust(4, '0') << '-'
      io << IO::ByteFormat::LittleEndian.decode(UInt16, @bytes[6, 2]).to_s(16).rjust(4, '0') << '-'
      io << @bytes[8, 2].hexstring << '-' << @bytes[10, 6].hexstring
    end

    def_equals_and_hash @bytes
  end

  # Known layouts expose structural fields only. Callback payloads, object
  # GUIDs and audit masks do not become permission decisions. Other ACE kinds
  # remain owned opaque values, with no ordering or policy normalization.
  class ACE
    getter type : UInt8
    getter flags : UInt8
    getter rights : UInt32?
    getter trustee : SID?
    getter object_flags : UInt32?
    getter object_type : GUID?
    getter inherited_object_type : GUID?
    @bytes : Bytes
    @payload : Bytes?

    def initialize(bytes : Bytes)
      unless bytes.size >= 4 && bytes.size % 4 == 0 &&
             IO::ByteFormat::LittleEndian.decode(UInt16, bytes[2, 2]) == bytes.size
        raise ArgumentError.new("Invalid ACE size")
      end
      @bytes = bytes.dup
      @type, @flags = bytes[0], bytes[1]
      return unless known_layout?
      minimum = object_ace? ? 20 : 16
      raise ArgumentError.new("Truncated known ACE layout") unless @bytes.size >= minimum
      @rights = IO::ByteFormat::LittleEndian.decode(UInt32, @bytes[4, 4])
      offset = 8
      if object_ace?
        flags = IO::ByteFormat::LittleEndian.decode(UInt32, @bytes[8, 4])
        @object_flags = flags
        offset = 12
        if (flags & 1) != 0
          @object_type = guid_at(offset)
          offset += 16
        end
        if (flags & 2) != 0
          @inherited_object_type = guid_at(offset)
          offset += 16
        end
      end
      raise ArgumentError.new("Truncated ACE trustee") unless offset <= @bytes.size - 8
      size = 8 + 4 * @bytes[offset + 1].to_i
      raise ArgumentError.new("Truncated ACE trustee") unless size <= @bytes.size - offset
      @trustee = SID.new(@bytes[offset, size])
      @payload = @bytes[offset + size, @bytes.size - offset - size].dup
    end

    def inheritance : ACEInheritance
      ACEInheritance.new(@flags & 0x1f_u8)
    end

    def object_ace? : Bool
      @type.in?({5_u8, 6_u8, 7_u8, 8_u8, 11_u8, 12_u8, 15_u8, 16_u8})
    end

    def callback? : Bool
      9 <= @type <= 16
    end

    def payload : Bytes?
      @payload.try(&.dup)
    end

    def bytes : Bytes
      @bytes.dup
    end

    def_equals_and_hash @bytes

    private def known_layout? : Bool
      @type.in?({0_u8, 1_u8, 2_u8, 3_u8, 5_u8, 6_u8, 7_u8, 8_u8,
                 9_u8, 10_u8, 11_u8, 12_u8, 13_u8, 14_u8, 15_u8, 16_u8})
    end

    private def guid_at(offset : Int32) : GUID
      raise ArgumentError.new("Truncated ACE object GUID") unless offset <= @bytes.size - 16
      GUID.new(@bytes[offset, 16])
    end
  end

  class ACL
    @bytes : Bytes
    @entries : Array(ACE)
    getter revision : UInt8

    def initialize(bytes : Bytes)
      unless 8 <= bytes.size <= UInt16::MAX && bytes.size % 4 == 0 &&
             bytes[0].in?({2_u8, 4_u8}) &&
             IO::ByteFormat::LittleEndian.decode(UInt16, bytes[2, 2]) == bytes.size
        raise ArgumentError.new("Invalid ACL header or size")
      end
      count = IO::ByteFormat::LittleEndian.decode(UInt16, bytes[4, 2]).to_i
      raise ArgumentError.new("Excessive ACL ACE count") unless count <= 4096 && count * 4 <= bytes.size - 8
      @revision = bytes[0]
      @bytes = bytes.dup
      offset = 8
      @entries = Array(ACE).new(count) do
        raise ArgumentError.new("Truncated ACE header") unless offset <= bytes.size - 4
        size = IO::ByteFormat::LittleEndian.decode(UInt16, bytes[offset + 2, 2]).to_i
        raise ArgumentError.new("Truncated ACE") unless size >= 4 && size <= bytes.size - offset
        ace = ACE.new(bytes[offset, size])
        offset += size
        ace
      end
    end

    def entries : Array(ACE)
      @entries.dup
    end

    def bytes : Bytes
      @bytes.dup
    end

    def_equals_and_hash @bytes
  end
end
