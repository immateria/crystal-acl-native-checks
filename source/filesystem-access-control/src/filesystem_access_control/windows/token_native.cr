{% skip_file unless flag?(:windows) %}

module Filesystem::AccessControl::Windows
  # :nodoc:
  struct NativeTokenInformation
    def query(token : Void*, information : UInt32, buffer : Void*, capacity : UInt32)
      returned = 0_u32
      success = Native::Windows::ACL.acl_token_info(token, information, buffer,
        capacity, pointerof(returned)) != 0
      code = success ? nil : LibC.GetLastError
      {success, returned, code}
    end
  end

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
      TokenInformationReader.read(token, information, maximum_size, NativeTokenInformation.new)
    end

    def close(token : Void*) : Nil
      LibC.CloseHandle(token)
    end

    private def last_error(operation : String) : Diagnostic
      code = LibC.GetLastError
      Diagnostic.new(operation, code, ErrorOrigin::LastError, "#{operation} failed: #{code}")
    end
  end
end
