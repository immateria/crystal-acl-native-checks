{% skip_file unless flag?(:darwin) %}

require "./principal"

module Filesystem::AccessControl::Darwin
  enum Membership
    Member
    Nonmember
    Error
  end

  record MembershipResult, status : Membership, error : Int32? = nil do
    def reason : Reason?
      Reason::IdentityLookupFailed if status.error? || error
    end

    def evidence : Evaluation::Membership
      return Evaluation::Membership::Unknown if error
      case status
      when Membership::Member    then Evaluation::Membership::Member
      when Membership::Nonmember then Evaluation::Membership::NotMember
      else                            Evaluation::Membership::Unknown
      end
    end
  end

  # The provider seam retains native tuples. Public lookups have named fields,
  # including the direct Membership.framework error code (not errno).
  class Lookup(T)
    getter value : T?
    getter error : Int32?

    def initialize(value : T?, @error : Int32? = nil)
      @value = @error ? nil : value
    end

    def reason : Reason?
      return Reason::IdentityLookupFailed if @error
      Reason::IncompleteEvidence if @value.nil?
    end
  end

  enum IdentityKind
    User
    Group
  end

  record Identity, id : UInt32, raw_type : Int32 do
    def kind : IdentityKind?
      case raw_type
      when 0 then IdentityKind::User
      when 1 then IdentityKind::Group
      end
    end
  end

  # Thin seam around Membership.framework's direct error-code API. Consumers
  # may supply a deterministic provider in tests or when a caller already has
  # an identity-service backend; the default provider performs live lookups.
  abstract class MembershipProvider
    abstract def uid_to_uuid(uid : UInt32) : Tuple(Principal?, Int32?)
    abstract def gid_to_uuid(gid : UInt32) : Tuple(Principal?, Int32?)
    abstract def uuid_to_id(principal : Principal) : Tuple(UInt32?, Int32?, Int32?)
    abstract def membership(user : Principal, group : Principal) : MembershipResult
  end

  class NativeMembershipProvider < MembershipProvider
    def uid_to_uuid(uid : UInt32) : Tuple(Principal?, Int32?)
      uuid = StaticArray(UInt8, 16).new(0_u8)
      error = Native::Darwin::Membership.mbr_uid_to_uuid(uid, uuid.to_unsafe)
      error == 0 ? {Principal.new(uuid), nil} : {nil, error}
    end

    def gid_to_uuid(gid : UInt32) : Tuple(Principal?, Int32?)
      uuid = StaticArray(UInt8, 16).new(0_u8)
      error = Native::Darwin::Membership.mbr_gid_to_uuid(gid, uuid.to_unsafe)
      error == 0 ? {Principal.new(uuid), nil} : {nil, error}
    end

    def uuid_to_id(principal : Principal) : Tuple(UInt32?, Int32?, Int32?)
      id = 0_u32
      id_type = 0
      error = Native::Darwin::Membership.mbr_uuid_to_id(principal.uuid.to_unsafe, pointerof(id), pointerof(id_type))
      error == 0 ? {id, id_type, nil} : {nil, nil, error}
    end

    def membership(user : Principal, group : Principal) : MembershipResult
      member = 0
      error = Native::Darwin::Membership.mbr_check_membership(user.uuid.to_unsafe, group.uuid.to_unsafe, pointerof(member))
      return MembershipResult.new(Membership::Error, error) unless error == 0
      MembershipResult.new(member == 0 ? Membership::Nonmember : Membership::Member)
    end
  end

  # Public membership.h wrappers return their error code directly. They do not
  # consult errno, and they are intentionally separate from descriptor capture.
  module Principals
    extend self

    DEFAULT_PROVIDER = NativeMembershipProvider.new

    def effective_uid : UInt32
      Native::Darwin::Credentials.geteuid
    end

    def uid_to_uuid(uid : UInt32, provider : MembershipProvider = DEFAULT_PROVIDER) : Lookup(Principal)
      value, error = provider.uid_to_uuid(uid)
      Lookup(Principal).new(value, error)
    end

    def gid_to_uuid(gid : UInt32, provider : MembershipProvider = DEFAULT_PROVIDER) : Lookup(Principal)
      value, error = provider.gid_to_uuid(gid)
      Lookup(Principal).new(value, error)
    end

    def uuid_to_id(principal : Principal, provider : MembershipProvider = DEFAULT_PROVIDER) : Lookup(Identity)
      id, kind, error = provider.uuid_to_id(principal)
      value = id && kind ? Identity.new(id, kind) : nil
      Lookup(Identity).new(value, error)
    end

    def membership(user : Principal, group : Principal, provider : MembershipProvider = DEFAULT_PROVIDER) : MembershipResult
      provider.membership(user, group)
    end

    # Exact fixed UUID matching is used for the four XNU well-known principals.
    # Names and numeric annotations never participate in this classification.
    def classify(principal : Principal) : WellKnown?
      WellKnownUUID.classify(principal.uuid)
    end
  end
end
