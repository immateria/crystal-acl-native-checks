{% skip_file unless flag?(:windows) %}
require "./handle_native"

@[Link("advapi32")]
lib Filesystem::AccessControl::Native::Windows::ACL
  fun acl_set_security_info = SetSecurityInfo(handle : Void*, object_type : UInt32, info : UInt32,
                                              owner : Void*, group : Void*, dacl : Void*, sacl : Void*) : UInt32
  fun acl_valid_acl = IsValidAcl(acl : Void*) : Int32
end

module Filesystem::AccessControl::Windows
  # :nodoc:
  class NativeWriterProvider < NativeHandleProvider
    def validate(acl : ACL) : Diagnostic?
      bytes = acl.bytes
      return nil if Native::Windows::ACL.acl_valid_acl(bytes.to_unsafe.as(Void*)) != 0
      Diagnostic.new("IsValidAcl", nil, ErrorOrigin::Validation, "Native ACL validation failed before mutation")
    end

    def replace(handle : Void*, acl : ACL, information : UInt32) : UInt32
      bytes = acl.bytes
      Native::Windows::ACL.acl_set_security_info(handle, 1_u32, information,
        Pointer(Void).null, Pointer(Void).null, bytes.to_unsafe.as(Void*), Pointer(Void).null)
    end
  end
end
