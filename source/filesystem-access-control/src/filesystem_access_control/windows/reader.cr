{% skip_file unless flag?(:windows) %}

require "./observation"
require "c/winbase"
require "c/errhandlingapi"

@[Link("advapi32")]
lib Filesystem::AccessControl::Native::Windows::ACL
  fun acl_descriptor_length = GetSecurityDescriptorLength(descriptor : Void*) : UInt32
  fun acl_valid_descriptor = IsValidSecurityDescriptor(descriptor : Void*) : Int32
end

module Filesystem::AccessControl::Windows
  module Reader
    # Borrow a file/directory HANDLE. This performs no pathname lookup, privilege
    # adjustment, token substitution or mutation. SACL reads are explicit.
    def self.capture(handle : Void*, *, information : SecurityInformation = DEFAULT_INFORMATION) : Snapshot
      SecurityDescriptor.validate_information!(information)
      security = Pointer(Void).null
      raw = nil.as(Bytes?)
      begin
        code = Native::Windows::ACL.acl_security_info(handle, 1_u32, information.value,
          Pointer(Void*).null, Pointer(Void*).null, Pointer(Void*).null, Pointer(Void*).null,
          pointerof(security))
        if code != 0
          return Snapshot.new(information: information, diagnostic: Diagnostic.new("GetSecurityInfo", code,
            ErrorOrigin::ReturnValue, "GetSecurityInfo returned #{code}"))
        end
        if security.null? || Native::Windows::ACL.acl_valid_descriptor(security) == 0
          return invalid(information, "IsValidSecurityDescriptor", "Native descriptor is unavailable or invalid")
        end
        control = 0_u16
        revision = 0_u32
        if Native::Windows::ACL.acl_descriptor_control(security, pointerof(control), pointerof(revision)) == 0
          code = LibC.GetLastError
          return Snapshot.new(information: information, diagnostic: Diagnostic.new("GetSecurityDescriptorControl", code,
            ErrorOrigin::LastError, "GetSecurityDescriptorControl failed: #{code}"))
        end
        # An absolute descriptor's components need not occupy one allocation.
        if (control & 0x8000) == 0
          return invalid(information, "GetSecurityDescriptorControl", "Native descriptor is not self-relative")
        end
        length = Native::Windows::ACL.acl_descriptor_length(security)
        unless 20 <= length <= SecurityDescriptor::MAX_SIZE
          return invalid(information, "GetSecurityDescriptorLength", "Native descriptor length is out of bounds")
        end
        raw = Bytes.new(security.as(UInt8*), length.to_i).dup
        Snapshot.new(SecurityDescriptor.new(raw, information))
      rescue error : ArgumentError
        Snapshot.new(information: information, raw_descriptor: raw, diagnostic: Diagnostic.new(
          "security_descriptor.decode", nil, ErrorOrigin::Validation, error.message || "Invalid descriptor"))
      ensure
        LibC.LocalFree(security) unless security.null?
      end
    end

    private def self.invalid(information : SecurityInformation, operation : String, message : String) : Snapshot
      Snapshot.new(information: information, diagnostic: Diagnostic.new(operation, nil, ErrorOrigin::Validation, message))
    end
  end
end
