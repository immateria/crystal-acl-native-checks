{% skip_file unless flag?(:windows) %}
require "./handle_capture"

module Filesystem::AccessControl::Windows
  # :nodoc:
  class NativeHandleProvider
    def metadata(handle : Void*) : Tuple(FileMetadata?, Diagnostic?)
      LibC.SetLastError(0_u32)
      type = LibC.GetFileType(handle)
      if type == 0
        code = LibC.GetLastError
        if code != 0
          return {nil, Diagnostic.new("GetFileType", code, ErrorOrigin::LastError, "GetFileType failed: #{code}")}
        end
      end
      unless type == 1_u32
        return {nil, Diagnostic.new("GetFileType", nil, ErrorOrigin::Validation, "A disk file or directory handle is required")}
      end
      attributes = StaticArray(UInt32, 2).new(0_u32)
      if LibC.GetFileInformationByHandleEx(handle, LibC::FILE_INFO_BY_HANDLE_CLASS::FileAttributeTagInfo,
           attributes.to_unsafe.as(Void*), 8_u32) == 0
        return {nil, last_error("GetFileInformationByHandleEx(FileAttributeTagInfo)")}
      end
      # FILE_ID_INFO is a 64-bit volume serial followed by a 128-bit file ID.
      # The aligned buffer covers all 24 bytes, including on ReFS.
      identity = StaticArray(UInt64, 3).new(0_u64)
      if LibC.GetFileInformationByHandleEx(handle, LibC::FILE_INFO_BY_HANDLE_CLASS.new(18),
           identity.to_unsafe.as(Void*), 24_u32) == 0
        return {nil, last_error("GetFileInformationByHandleEx(FileIdInfo)")}
      end
      bytes = identity.to_unsafe.as(UInt8*)
      {FileMetadata.new(FileIdentity.new(identity[0], Bytes.new(bytes + 8, 16)), attributes[0]), nil}
    end

    def security(handle : Void*, information : SecurityInformation) : Snapshot
      Reader.capture(handle, information: information)
    end

    def capture(handle : Void*) : HandleSnapshot
      HandleReader.capture(handle, provider: self)
    end

    private def last_error(operation : String) : Diagnostic
      code = LibC.GetLastError
      Diagnostic.new(operation, code, ErrorOrigin::LastError, "#{operation} failed: #{code}")
    end
  end
end
