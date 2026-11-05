require "./values"

module Filesystem::AccessControl::Windows
  @[Flags]
  enum SecurityInformation : UInt32
    Owner = 1
    Group = 2
    Dacl  = 4
    Sacl  = 8
  end

  DEFAULT_INFORMATION = SecurityInformation::Owner | SecurityInformation::Group | SecurityInformation::Dacl

  # Observed control bits for one queried ACL. These describe descriptor
  # state, not whether a future write will propagate to existing children.
  struct ACLInheritanceControl
    getter? protected : Bool
    getter? auto_inherit_requested : Bool
    getter? auto_inherited : Bool

    def initialize(@protected : Bool, @auto_inherit_requested : Bool, @auto_inherited : Bool)
    end

    def_equals_and_hash @protected, @auto_inherit_requested, @auto_inherited
  end

  # Owned self-relative SECURITY_DESCRIPTOR bytes. Query scope remains separate
  # from the control bits: an unrequested component is never called absent.
  # Structural decoding does not certify native setter or evaluator support.
  class SecurityDescriptor
    MAX_SIZE = 1_048_576

    getter information : SecurityInformation
    getter control : UInt16
    getter owner : SID?
    getter group : SID?
    getter dacl : ACL?
    getter sacl : ACL?
    getter dacl_presence : ACLPresence
    getter sacl_presence : ACLPresence
    @bytes : Bytes

    def initialize(bytes : Bytes, @information : SecurityInformation = DEFAULT_INFORMATION)
      self.class.validate_information!(@information)
      raise ArgumentError.new("Invalid relative security descriptor header") unless 20 <= bytes.size <= MAX_SIZE && bytes[0] == 1
      @control = IO::ByteFormat::LittleEndian.decode(UInt16, bytes[2, 2])
      raise ArgumentError.new("Security descriptor must be self-relative") if (@control & 0x8000) == 0
      @bytes = bytes.dup
      # Validate every nonzero pointer, including bytes outside the query scope.
      owner = sid_at(offset_at(4))
      group = sid_at(offset_at(8))
      sacl_presence, sacl = acl_at(offset_at(12), (@control & 0x10) != 0)
      dacl_presence, dacl = acl_at(offset_at(16), (@control & 0x04) != 0)
      @owner = owner if @information.owner?
      @group = group if @information.group?
      @sacl_presence = @information.sacl? ? sacl_presence : ACLPresence::NotQueried
      @dacl_presence = @information.dacl? ? dacl_presence : ACLPresence::NotQueried
      @sacl = sacl if @information.sacl?
      @dacl = dacl if @information.dacl?
    end

    def bytes : Bytes
      @bytes.dup
    end

    def dacl_inheritance_control : ACLInheritanceControl?
      return nil unless @information.dacl?
      ACLInheritanceControl.new((@control & 0x1000) != 0,
        (@control & 0x0100) != 0, (@control & 0x0400) != 0)
    end

    def sacl_inheritance_control : ACLInheritanceControl?
      return nil unless @information.sacl?
      ACLInheritanceControl.new((@control & 0x2000) != 0,
        (@control & 0x0200) != 0, (@control & 0x0800) != 0)
    end

    # No SID, ACE, padding or unknown-payload normalization.
    def_equals_and_hash @information, @bytes

    def self.validate_information!(information : SecurityInformation) : Nil
      if information.value == 0 || (information.value & ~15_u32) != 0
        raise ArgumentError.new("Query supports owner, group, DACL and full SACL information only")
      end
    end

    private def offset_at(position : Int32) : Int32
      offset = IO::ByteFormat::LittleEndian.decode(UInt32, @bytes[position, 4]).to_i64
      return 0 if offset == 0
      unless offset >= 20 && offset % 4 == 0 && offset <= @bytes.size - 8
        raise ArgumentError.new("Security descriptor component is outside its buffer or misaligned")
      end
      offset.to_i
    end

    private def sid_at(offset : Int32) : SID?
      return nil if offset == 0
      length = 8 + 4 * @bytes[offset + 1].to_i
      raise ArgumentError.new("Truncated descriptor SID") if length > @bytes.size - offset
      SID.new(@bytes[offset, length])
    end

    private def acl_at(offset : Int32, present : Bool) : Tuple(ACLPresence, ACL?)
      unless present
        raise ArgumentError.new("Absent ACL has a nonzero descriptor offset") unless offset == 0
        return {ACLPresence::Absent, nil}
      end
      return {ACLPresence::Null, nil} if offset == 0
      length = IO::ByteFormat::LittleEndian.decode(UInt16, @bytes[offset + 2, 2]).to_i
      raise ArgumentError.new("Truncated descriptor ACL") if length > @bytes.size - offset
      {ACLPresence::Present, ACL.new(@bytes[offset, length])}
    end
  end
end
