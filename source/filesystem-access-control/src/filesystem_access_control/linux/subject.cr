{% skip_file unless flag?(:linux) %}
require "./evaluation"

module Filesystem::AccessControl
  @[Link("c")]
  lib Native::Linux::Credentials
    fun geteuid : UInt32
    fun getegid : UInt32
    fun getgroups(size : Int32, groups : UInt32*) : Int32
  end
end

module Filesystem::AccessControl::Linux
  record SubjectResult, subject : Subject?, diagnostic : Diagnostic?

  class Subject
    # Effective IDs and supplementary groups, not Linux fsuid/fsgid or a
    # capability set. Callers that change filesystem IDs must supply those IDs
    # explicitly. This is a non-atomic observation: the ID/count comparisons
    # detect some concurrent changes, but not same-sized group replacement or ABA.
    def self.effective : SubjectResult
      uid = Native::Linux::Credentials.geteuid
      gid = Native::Linux::Credentials.getegid
      count = Native::Linux::Credentials.getgroups(0, Pointer(UInt32).null)
      return credential_error if count < 0
      groups = Array(UInt32).new(count, 0_u32)
      received = Native::Linux::Credentials.getgroups(count, groups.to_unsafe)
      return credential_error if received < 0
      if received != count || uid != Native::Linux::Credentials.geteuid || gid != Native::Linux::Credentials.getegid
        return SubjectResult.new(nil, Diagnostic.new(Reason::ObservationChanged, "Effective credentials changed during capture"))
      end
      groups << gid
      SubjectResult.new(new(uid, groups), nil)
    end

    private def self.credential_error : SubjectResult
      error = Errno.value
      SubjectResult.new(nil, Diagnostic.new(Reason::NativeError, "Cannot capture supplementary groups: #{error}", error.value))
    end
  end
end
