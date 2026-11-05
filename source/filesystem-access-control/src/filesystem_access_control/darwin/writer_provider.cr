{% skip_file unless flag?(:darwin) %}

require "./writer_native"

module Filesystem::AccessControl::Darwin
  # Native boundaries are separate from validation and result classification.
  # The caller retains the descriptor throughout preparation, mutation and readback.
  class NativeWriterProvider
    def init_removal : Void*
      Native::Darwin::FileSecurityWriter.filesec_init
    end

    def prepare_removal(filesec : Void*) : Int32
      Native::Darwin::FileSecurityWriter.filesec_set_property(filesec,
        Writer::FILESEC_ACL, Writer::FILESEC_REMOVE_ACL)
    end

    def free_removal(filesec : Void*) : Nil
      Native::Darwin::FileSecurityWriter.filesec_free(filesec)
    end

    def remove(fd : Int32, filesec : Void*) : Int32
      Native::Darwin::FileSecurityWriter.fchmodx_np(fd, filesec)
    end

    def replace(fd : Int32, acl : Void*) : Int32
      Native::Darwin::ACL.acl_set_fd_np(fd, acl, Constants::ACL_TYPE_EXTENDED)
    end

    def capture(fd : Int32) : Snapshot?
      Filesystem::AccessControl.inspect_fd(fd).snapshot
    end
  end
end
