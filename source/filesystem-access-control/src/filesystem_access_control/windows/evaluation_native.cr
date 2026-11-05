{% skip_file unless flag?(:windows) %}

require "c/errhandlingapi"

@[Link("advapi32")]
lib Filesystem::AccessControl::Native::Windows::AccessEvaluation
  struct GenericMapping
    read : UInt32
    write : UInt32
    execute : UInt32
    all : UInt32
  end

  fun access_check = AccessCheck(descriptor : Void*, subject : Void*, desired : UInt32,
                                 mapping : GenericMapping*, privileges : Void*,
                                 privilege_size : UInt32*, granted : UInt32*, status : Int32*) : Int32
end

module Filesystem::AccessControl::Windows
  # :nodoc:
  class NativeAccessCheckProvider
    def call(descriptor : Bytes, subject : Void*, permissions : UInt32,
             mapping : GenericMapping, privileges : Bytes) : AccessCheckCall
      native_mapping = Native::Windows::AccessEvaluation::GenericMapping.new
      native_mapping.read = mapping.read
      native_mapping.write = mapping.write
      native_mapping.execute = mapping.execute
      native_mapping.all = mapping.all
      length = privileges.size.to_u32
      granted = 0_u32
      status = 0
      ok = Native::Windows::AccessEvaluation.access_check(descriptor.to_unsafe.as(Void*),
        subject, permissions, pointerof(native_mapping), privileges.to_unsafe.as(Void*),
        pointerof(length), pointerof(granted), pointerof(status))
      if ok == 0
        code = LibC.GetLastError
        return AccessCheckCall.new(false, nil, nil, length, Diagnostic.new("AccessCheck", code,
          ErrorOrigin::LastError, "AccessCheck failed: #{code}"))
      end
      if status == 0
        code = LibC.GetLastError
        return AccessCheckCall.new(true, false, granted, length, Diagnostic.new("AccessCheck", code,
          ErrorOrigin::LastError, "AccessCheck denied the request: #{code}"))
      end
      AccessCheckCall.new(true, true, granted, length, nil)
    end
  end
end
