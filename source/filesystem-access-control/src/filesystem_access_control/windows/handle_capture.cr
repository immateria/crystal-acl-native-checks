require "./observation"

module Filesystem::AccessControl::Windows
  enum FileKind
    File
    Directory
  end

  # FILE_ID_INFO, kept separate from pathname and security descriptor bytes.
  class FileIdentity
    getter volume : UInt64
    @file_id : StaticArray(UInt8, 16)

    def initialize(@volume : UInt64, file_id : Bytes)
      raise ArgumentError.new("Windows file identity requires 16 bytes") unless file_id.size == 16
      @file_id = StaticArray(UInt8, 16).new { |index| file_id[index] }
    end

    def file_id : Bytes
      @file_id.to_slice.dup
    end

    def_equals_and_hash @volume, @file_id
  end

  record FileMetadata, identity : FileIdentity, attributes : UInt32 do
    def kind : FileKind
      (@attributes & 0x10) == 0 ? FileKind::File : FileKind::Directory
    end

    def reparse? : Bool
      (@attributes & 0x400) != 0
    end

    def same_object?(other : FileMetadata) : Bool
      @identity == other.identity && kind == other.kind
    end
  end

  class HandleSnapshot
    getter security : Snapshot
    getter metadata_before : FileMetadata?
    getter metadata_after : FileMetadata?
    getter diagnostic : Diagnostic?

    def initialize(@security : Snapshot, @metadata_before : FileMetadata? = nil,
                   @metadata_after : FileMetadata? = nil, @diagnostic : Diagnostic? = nil)
    end

    def complete? : Bool
      before, after = @metadata_before, @metadata_after
      !!(before && after && !before.reparse? && !after.reparse? &&
        before.same_object?(after) && @security.complete? && @diagnostic.nil?)
    end

    def identity : FileIdentity?
      @metadata_after.try(&.identity) || @metadata_before.try(&.identity)
    end

    def kind : FileKind?
      @metadata_after.try(&.kind) || @metadata_before.try(&.kind)
    end
  end

  module HandleReader
    {% if flag?(:windows) %}
      def self.capture(handle : Void*, *, information : SecurityInformation = DEFAULT_INFORMATION) : HandleSnapshot
        capture(handle, information: information, provider: NativeHandleProvider.new)
      end
    {% end %}

    # Bracketing consistency evidence, not an atomic metadata/ACL snapshot.
    def self.capture(handle : Void*, *, information : SecurityInformation = DEFAULT_INFORMATION, provider) : HandleSnapshot
      SecurityDescriptor.validate_information!(information)
      empty = Snapshot.new(information: information)
      before, diagnostic = provider.metadata(handle)
      return HandleSnapshot.new(empty, before, diagnostic: diagnostic) if diagnostic
      unless before && !before.reparse?
        return HandleSnapshot.new(empty, before, diagnostic: invalid("HandleReader.precondition", "A non-reparse disk file or directory is required"))
      end
      security = provider.security(handle, information)
      unless security.information == information
        return HandleSnapshot.new(security, before, diagnostic: invalid("HandleReader.scope", "Security capture differs from the requested query scope"))
      end
      unless security.complete?
        return HandleSnapshot.new(security, before, diagnostic: security.diagnostic || invalid("HandleReader.security", "Incomplete security capture"))
      end
      after, diagnostic = provider.metadata(handle)
      return HandleSnapshot.new(security, before, after, diagnostic) if diagnostic
      unless after && !after.reparse? && before.same_object?(after)
        diagnostic = invalid("HandleReader.identity", "Held object identity or kind changed during capture")
      end
      HandleSnapshot.new(security, before, after, diagnostic)
    end

    private def self.invalid(operation : String, message : String) : Diagnostic
      Diagnostic.new(operation, nil, ErrorOrigin::Validation, message)
    end
  end
end
