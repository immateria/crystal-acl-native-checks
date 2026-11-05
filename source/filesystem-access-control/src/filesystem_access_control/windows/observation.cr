require "./security_descriptor"

module Filesystem::AccessControl::Windows
  enum ErrorOrigin
    ReturnValue
    LastError
    Validation
  end

  record Diagnostic, operation : String, code : UInt32?, origin : ErrorOrigin,
    message : String

  # A scoped observation, not an access token or a writer precondition.
  class Snapshot
    getter descriptor : SecurityDescriptor?
    getter information : SecurityInformation
    getter diagnostic : Diagnostic?
    @raw_descriptor : Bytes?

    def initialize(@descriptor : SecurityDescriptor? = nil, *,
                   information : SecurityInformation? = nil,
                   @diagnostic : Diagnostic? = nil, raw_descriptor : Bytes? = nil)
      @information = information || @descriptor.try(&.information) || DEFAULT_INFORMATION
      SecurityDescriptor.validate_information!(@information)
      if @descriptor && @descriptor.not_nil!.information != @information
        raise ArgumentError.new("Descriptor and snapshot query scopes disagree")
      end
      @raw_descriptor = @descriptor.try(&.bytes) || raw_descriptor.try(&.dup)
    end

    def raw_descriptor : Bytes?
      @raw_descriptor.try(&.dup)
    end

    def owner : SID?
      @descriptor.try(&.owner)
    end

    def group : SID?
      @descriptor.try(&.group)
    end

    def control : UInt16?
      @descriptor.try(&.control)
    end

    def dacl : ACL?
      @descriptor.try(&.dacl)
    end

    def sacl : ACL?
      @descriptor.try(&.sacl)
    end

    def dacl_inheritance_control : ACLInheritanceControl?
      @descriptor.try(&.dacl_inheritance_control)
    end

    def sacl_inheritance_control : ACLInheritanceControl?
      @descriptor.try(&.sacl_inheritance_control)
    end

    def dacl_presence : ACLPresence
      @descriptor.try(&.dacl_presence) || (@information.dacl? ? ACLPresence::Unavailable : ACLPresence::NotQueried)
    end

    def sacl_presence : ACLPresence
      @descriptor.try(&.sacl_presence) || (@information.sacl? ? ACLPresence::Unavailable : ACLPresence::NotQueried)
    end

    def queried_information : UInt32
      @information.value
    end

    # Interpretation can fail independently of a complete native capture.
    def complete? : Bool
      !@descriptor.nil?
    end

    def diagnostics : Array(Diagnostic)
      diagnostic = @diagnostic
      diagnostic ? [diagnostic] : [] of Diagnostic
    end

    def with_diagnostic(diagnostic : Diagnostic) : Snapshot
      Snapshot.new(@descriptor, information: @information, diagnostic: diagnostic,
        raw_descriptor: @raw_descriptor)
    end
  end
end
