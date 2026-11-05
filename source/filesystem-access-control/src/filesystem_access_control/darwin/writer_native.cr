{% skip_file unless flag?(:darwin) %}

module Filesystem::AccessControl::Native::Darwin
  @[Link("c")]
  lib ACLWriter
    fun acl_set_flagset_np(object : Void*, flagset : Void*) : Int32
    fun acl_clear_flags_np(flagset : Void*) : Int32
  end

  @[Link("c")]
  lib FileSecurityWriter
    fun filesec_init : Void*
    fun filesec_set_property(filesec : Void*, property : Int32, value : Void*) : Int32
    fun filesec_free(filesec : Void*) : Void
    fun fchmodx_np(fd : Int32, filesec : Void*) : Int32
  end
end
