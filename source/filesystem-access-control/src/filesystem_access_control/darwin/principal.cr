module Filesystem::AccessControl::Darwin
  # Value identity copied from acl_get_qualifier. No native pointer escapes.
  class Principal
    getter uuid : StaticArray(UInt8, 16)

    def initialize(uuid : StaticArray(UInt8, 16))
      @uuid = uuid
    end

    def ==(other : Principal) : Bool
      @uuid == other.uuid
    end

    def hash(hasher)
      @uuid.each { |byte| hasher = hasher.hash(byte) }
      hasher
    end

    # UUID identity is useful even when a directory-service name is unavailable.
    def to_s(io : IO) : Nil
      @uuid.each_with_index do |byte, index|
        io << '-' if index.in?({4, 6, 8, 10})
        io << byte.to_s(16).rjust(2, '0')
      end
    end
  end

  enum WellKnown
    Owner
    Group
    Everybody
    Nobody
  end

  # Verified against kauth_wellknown_guid in the matched XNU source:
  # twelve-byte prefix followed by a network-order 32-bit discriminator.
  module WellKnownUUID
    PREFIX = StaticArray[0xab_u8, 0xcd_u8, 0xef_u8, 0xab_u8, 0xcd_u8, 0xef_u8,
      0xab_u8, 0xcd_u8, 0xef_u8, 0xab_u8, 0xcd_u8, 0xef_u8]

    OWNER = StaticArray[0xab_u8, 0xcd_u8, 0xef_u8, 0xab_u8, 0xcd_u8, 0xef_u8,
      0xab_u8, 0xcd_u8, 0xef_u8, 0xab_u8, 0xcd_u8, 0xef_u8, 0x00_u8, 0x00_u8, 0x00_u8, 0x0a_u8]
    GROUP = StaticArray[0xab_u8, 0xcd_u8, 0xef_u8, 0xab_u8, 0xcd_u8, 0xef_u8,
      0xab_u8, 0xcd_u8, 0xef_u8, 0xab_u8, 0xcd_u8, 0xef_u8, 0x00_u8, 0x00_u8, 0x00_u8, 0x10_u8]
    EVERYBODY = StaticArray[0xab_u8, 0xcd_u8, 0xef_u8, 0xab_u8, 0xcd_u8, 0xef_u8,
      0xab_u8, 0xcd_u8, 0xef_u8, 0xab_u8, 0xcd_u8, 0xef_u8, 0x00_u8, 0x00_u8, 0x00_u8, 0x0c_u8]
    NOBODY = StaticArray[0xab_u8, 0xcd_u8, 0xef_u8, 0xab_u8, 0xcd_u8, 0xef_u8,
      0xab_u8, 0xcd_u8, 0xef_u8, 0xab_u8, 0xcd_u8, 0xef_u8, 0xff_u8, 0xff_u8, 0xff_u8, 0xfe_u8]

    # Only exact UUID identities participate; names and numeric annotations
    # are resolver output, not evidence that a principal has a special role.
    def self.classify(uuid : StaticArray(UInt8, 16)) : WellKnown?
      return WellKnown::Owner if uuid == OWNER
      return WellKnown::Group if uuid == GROUP
      return WellKnown::Everybody if uuid == EVERYBODY
      return WellKnown::Nobody if uuid == NOBODY
      nil
    end
  end
end
