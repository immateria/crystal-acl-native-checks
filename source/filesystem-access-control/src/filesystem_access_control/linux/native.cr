{% skip_file unless flag?(:linux) %}
require "./reader"

module Filesystem::AccessControl
  @[Link("c")]
  lib Native::Linux::Xattr
    fun fgetxattr(fd : Int32, name : UInt8*, value : Void*, size : LibC::SizeT) : LibC::SSizeT
  end
end

module Filesystem::AccessControl::Linux
  class NativeReaderProvider < ReaderProvider
    def stat(fd : Int32) : StatResult
      if LibC.fstat(fd, out info) != 0
        return StatResult.new(nil, native_error("Cannot inspect descriptor", Errno.value))
      end
      kind = case info.st_mode & LibC::S_IFMT
             when LibC::S_IFREG then Target::File
             when LibC::S_IFDIR then Target::Directory
             else
               return StatResult.new(nil, Diagnostic.new(Reason::WrongKind, "ACL target must be a regular file or directory"))
             end
      StatResult.new(Stat.new(info.st_dev.to_u64, info.st_ino.to_u64, info.st_uid, info.st_gid,
        (info.st_mode & 0o7777).to_i, kind, info.st_ctim.tv_sec.to_i64, info.st_ctim.tv_nsec.to_i64), nil)
    end

    def read(fd : Int32, kind : ACLKind) : ReadResult
      length, failure = fetch_xattr(fd, kind, nil)
      if length < 0
        error = failure.not_nil!
        return ReadResult.new(nil, nil) if error == Errno::ENODATA
        return ReadResult.new(nil, native_error("Cannot read #{kind.key}", error, kind))
      end
      unless 4 <= length <= 65536
        return ReadResult.new(nil, Diagnostic.new(Reason::MalformedACL, "Invalid #{kind.key} length #{length}", acl_kind: kind))
      end
      bytes = Bytes.new(length.to_i)
      received, failure = fetch_xattr(fd, kind, bytes)
      if received < 0
        return ReadResult.new(nil, native_error("Cannot read #{kind.key}", failure.not_nil!, kind))
      end
      if received != bytes.size
        return ReadResult.new(nil, Diagnostic.new(Reason::ObservationChanged, "ACL size changed during inspection", acl_kind: kind))
      end
      ReadResult.new(bytes, nil)
    end

    protected def fetch_xattr(fd : Int32, kind : ACLKind, buffer : Bytes?) : Tuple(Int64, Errno?)
      pointer = buffer ? buffer.to_unsafe.as(Void*) : Pointer(Void).null
      length = Native::Linux::Xattr.fgetxattr(fd, kind.key, pointer, buffer.try(&.size) || 0)
      {length.to_i64, length < 0 ? Errno.value : nil}
    end

    protected def native_error(message : String, error : Errno, kind : ACLKind? = nil) : Diagnostic
      reason = error == Errno::EOPNOTSUPP ? Reason::Unsupported : Reason::NativeError
      Diagnostic.new(reason, "#{message}: #{error}", error.value, kind)
    end
  end

  module Reader
    def self.capture(fd : Int32, *, expected : Target? = nil) : Snapshot
      capture(fd, expected: expected, provider: NativeReaderProvider.new)
    end
  end
end
