{% skip_file unless flag?(:darwin) %}

require "./discretionary_access"
require "./principals"

module Filesystem::AccessControl::Darwin::DiscretionaryAccess
  class Subject
    # Resolve only the evidence these snapshots need. Calls happen outside
    # descriptor leases. Missing groups remain Unknown; no cache survives a
    # call. Supply every parent/replaced target for a composed operation and
    # extra_gids for a proposed ownership change.
    def self.resolve(snapshots : Enumerable(Snapshot), *, uid : UInt32 = Principals.effective_uid,
                     extra_gids : Array(UInt32) = [] of UInt32,
                     provider : MembershipProvider = Principals::DEFAULT_PROVIDER) : Subject
      diagnostics = [] of Diagnostic
      memberships = {} of StaticArray(UInt8, 16) => Membership
      errors = {} of StaticArray(UInt8, 16) => String
      groups = {} of UInt32 => Membership
      principals = {} of StaticArray(UInt8, 16) => Principal
      gids = extra_gids.dup
      snapshots.each do |snapshot|
        if gid = snapshot.gid
          gids << gid unless gids.includes?(gid)
        end
        snapshot.entries.each do |ace|
          principals[ace.principal.uuid] = ace.principal unless Principals.classify(ace.principal)
        end
      end

      lookup = Principals.uid_to_uuid(uid, provider)
      user = lookup.value
      unless user
        diagnostics << lookup_diagnostic("uid_to_uuid", lookup.error, "Cannot resolve UID #{uid}")
        return new(uid, nil, groups, memberships, diagnostics: diagnostics)
      end
      principals.each do |uuid, principal|
        if uuid == user.uuid
          memberships[uuid] = Membership::Member
          next
        end
        observed = Principals.membership(user, principal, provider)
        memberships[uuid] = observed.evidence
        if observed.evidence.unknown?
          diagnostic = lookup_diagnostic("membership", observed.error, "ACL principal membership is unknown")
          diagnostics << diagnostic
          errors[uuid] = diagnostic.message
        end
      end
      gids.uniq.each do |gid|
        lookup = Principals.gid_to_uuid(gid, provider)
        if group = lookup.value
          observed = Principals.membership(user, group, provider)
          groups[gid] = observed.evidence
          if observed.evidence.unknown?
            diagnostics << lookup_diagnostic("membership", observed.error, "Membership of GID #{gid} is unknown")
          end
        else
          groups[gid] = Membership::Unknown
          diagnostics << lookup_diagnostic("gid_to_uuid", lookup.error, "Cannot resolve GID #{gid}")
        end
      end
      new(uid, user.uuid, groups, memberships, membership_errors: errors, diagnostics: diagnostics)
    end

    private def self.lookup_diagnostic(operation : String, error : Int32?, message : String) : Diagnostic
      message += " (native error #{error})" if error
      Diagnostic.new(operation, error, nil, "principal", message, Reason::IdentityLookupFailed)
    end
  end
end
