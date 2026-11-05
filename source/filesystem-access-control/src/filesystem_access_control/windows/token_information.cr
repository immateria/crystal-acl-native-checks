require "./observation"

module Filesystem::AccessControl::Windows
  # :nodoc:
  # The transport owns allocation and preserves native failures. Decoders consume
  # only the returned extent, which can differ from the allocated capacity.
  module TokenInformationReader
    def self.read(token : Void*, information : UInt32, maximum_size : Int32,
                  provider) : Tuple(Bytes?, UInt32, Diagnostic?)
      operation = "GetTokenInformation(#{information})"
      if information.in?({20_u32, 21_u32})
        # TOKEN_ELEVATION is one DWORD and its empty-buffer query can fail with
        # ERROR_BAD_LENGTH. TokenHasRestrictions instead returns one BOOLEAN,
        # at a DWORD-aligned address (Microsoft win32metadata discussion 2308,
        # clarified 2026-09-15). Capacity and initialized extent stay distinct.
        return invalid(operation, "Token scalar exceeds allocation limit") if maximum_size < 4
        storage = Slice(UInt32).new(1, 0_u32)
        data = Bytes.new(storage.to_unsafe.as(UInt8*), 4)
        return read_buffer(token, information, data, operation, provider)
      end
      success, required, code = provider.query(token, information, Pointer(Void).null, 0_u32)
      if success
        return invalid(operation, "Unexpected success from an empty token-information buffer")
      end
      unless code == 122_u32
        return {nil, 0_u32, Diagnostic.new("#{operation}.size", code,
          ErrorOrigin::LastError, "#{operation} size query failed: #{code}")}
      end
      unless 0 < required <= maximum_size
        return invalid(operation, "Invalid token-information allocation length")
      end
      data = Bytes.new(required.to_i)
      read_buffer(token, information, data, operation, provider)
    end

    private def self.read_buffer(token : Void*, information : UInt32, data : Bytes,
                                 operation : String, provider) : Tuple(Bytes?, UInt32, Diagnostic?)
      success, returned, code = provider.query(token, information, data.to_unsafe.as(Void*), data.size.to_u32)
      unless success
        return {data, returned, Diagnostic.new(operation, code,
          ErrorOrigin::LastError, "#{operation} failed: #{code}")}
      end
      {data, returned, nil}
    end

    private def self.invalid(operation : String, message : String) : Tuple(Bytes?, UInt32, Diagnostic?)
      {nil, 0_u32, Diagnostic.new(operation, nil, ErrorOrigin::Validation, message)}
    end
  end
end
