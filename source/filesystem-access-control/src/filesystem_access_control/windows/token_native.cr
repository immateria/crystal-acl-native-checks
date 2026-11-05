{% skip_file unless flag?(:windows) %}

module Filesystem::AccessControl::Windows
  # :nodoc:
  class NativeTokenProvider
    def open_process : Tuple(Void*, Diagnostic?)
      token = Pointer(Void).null
      if Native::Windows::ACL.acl_process_token(LibC.GetCurrentProcess, 8_u32, pointerof(token)) == 0
        return {Pointer(Void).null, last_error("OpenProcessToken")}
      end
      {token, nil}
    end

    def open_thread : Tuple(Void*, Diagnostic?)
      token = Pointer(Void).null
      # OpenAsSelf affects permission to open the token, not token selection.
      if Native::Windows::ACL.acl_thread_token(LibC.GetCurrentThread, 8_u32, 1, pointerof(token)) == 0
        return {Pointer(Void).null, last_error("OpenThreadToken")}
      end
      {token, nil}
    end

    def query(token : Void*, information : UInt32,
              maximum_size : Int32 = TokenReader::MAX_INFORMATION_SIZE) : Tuple(Bytes?, UInt32, Diagnostic?)
      operation = "GetTokenInformation(#{information})"
      required = 0_u32
      result = Native::Windows::ACL.acl_token_info(token, information,
        Pointer(Void).null, 0_u32, pointerof(required))
      if result != 0
        return invalid(operation, "Unexpected success from an empty token-information buffer")
      end
      code = LibC.GetLastError
      unless code == 122_u32
        return {nil, 0_u32, Diagnostic.new("#{operation}.size", code,
          ErrorOrigin::LastError, "#{operation} size query failed: #{code}")}
      end
      unless 0 < required <= maximum_size
        return invalid(operation, "Invalid token-information allocation length")
      end
      data = Bytes.new(required.to_i)
      if Native::Windows::ACL.acl_token_info(token, information, data.to_unsafe.as(Void*),
           required, pointerof(required)) == 0
        return {data, required, last_error(operation)}
      end
      {data, required, nil}
    end

    def close(token : Void*) : Nil
      LibC.CloseHandle(token)
    end

    private def last_error(operation : String) : Diagnostic
      code = LibC.GetLastError
      Diagnostic.new(operation, code, ErrorOrigin::LastError, "#{operation} failed: #{code}")
    end

    private def invalid(operation : String, message : String) : Tuple(Bytes?, UInt32, Diagnostic?)
      {nil, 0_u32, Diagnostic.new(operation, nil, ErrorOrigin::Validation, message)}
    end
  end
end
