{% skip_file unless flag?(:darwin) %}

require "./extended_security"

@[Link("c")]
lib Filesystem::AccessControl::Native::Darwin::Attributes
  struct List
    bitmapcount : UInt16
    reserved : UInt16
    common : UInt32
    volume : UInt32
    directory : UInt32
    file : UInt32
    fork : UInt32
  end

  fun fgetattrlist(fd : Int32, attributes : Void*, buffer : Void*, size : LibC::SizeT, options : UInt32) : Int32
end

module Filesystem::AccessControl::Darwin
  module ExtendedSecurityReader
    def self.capture(fd : Int32) : Tuple(ExtendedSecurity?, Diagnostic?)
      attributes = Native::Darwin::Attributes::List.new
      attributes.bitmapcount = 5_u16
      attributes.common = ExtendedSecurity::RETURNED | ExtendedSecurity::SECURITY
      bytes = Bytes.new(ExtendedSecurity::MAX_SIZE, 0_u8)
      if Native::Darwin::Attributes.fgetattrlist(fd, pointerof(attributes), bytes.to_unsafe,
           bytes.size, 4_u32) != 0 # FSOPT_REPORT_FULLSIZE
        failure = Errno.value
        return {nil, Diagnostic.new("fgetattrlist", failure.value, nil, "acl",
          "Unable to qualify libc's missing ACL result: #{failure}",
          failure == Errno::EACCES || failure == Errno::EPERM ? Reason::PermissionDenied : Reason::SystemError)}
      end
      {ExtendedSecurity.decode(bytes), nil}
    rescue error : ArgumentError
      {nil, Diagnostic.new("fgetattrlist", nil, nil, "acl", error.message.not_nil!)}
    end
  end
end
