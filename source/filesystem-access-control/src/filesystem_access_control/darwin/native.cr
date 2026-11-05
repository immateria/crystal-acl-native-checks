{% skip_file unless flag?(:darwin) %}

module Filesystem::AccessControl::Native::Darwin
  lib Credentials
    fun geteuid : UInt32
  end

  @[Link("c")]
  lib ACL
    fun acl_init(count : Int32) : Void*
    fun acl_copy_int(external_acl : Void*) : Void*
    fun acl_create_entry(acl : Void**, entry : Void**) : Int32
    fun acl_set_tag_type(entry : Void*, tag : UInt32) : Int32
    fun acl_set_permset_mask_np(entry : Void*, mask : UInt64) : Int32
    fun acl_set_qualifier(entry : Void*, qualifier : UInt8*) : Int32
    fun acl_add_flag_np(flagset : Void*, flag : Int32) : Int32
    fun acl_set_fd_np(fd : Int32, acl : Void*, acl_type : Int32) : Int32
    fun acl_get_fd_np(fd : Int32, acl_type : Int32) : Void*
    fun acl_size(acl : Void*) : Int64
    fun acl_copy_ext(buffer : Void*, acl : Void*, size : Int64) : Int64
    fun acl_get_entry(acl : Void*, entry_id : Int32, entry : Void**) : Int32
    fun acl_valid(acl : Void*) : Int32
    fun acl_get_tag_type(entry : Void*, tag : UInt32*) : Int32
    fun acl_get_permset_mask_np(entry : Void*, mask : UInt64*) : Int32
    fun acl_get_flagset_np(object : Void*, flagset : Void**) : Int32
    fun acl_get_flag_np(flagset : Void*, flag : Int32) : Int32
    fun acl_get_qualifier(entry : Void*) : Void*
    fun acl_free(object : Void*) : Int32
  end

  @[Link("c")]
  lib Membership
    fun mbr_uid_to_uuid(uid : UInt32, uuid : UInt8*) : Int32
    fun mbr_gid_to_uuid(gid : UInt32, uuid : UInt8*) : Int32
    fun mbr_uuid_to_id(uuid : UInt8*, id : UInt32*, id_type : Int32*) : Int32
    fun mbr_check_membership(user : UInt8*, group : UInt8*, is_member : Int32*) : Int32
  end
end
