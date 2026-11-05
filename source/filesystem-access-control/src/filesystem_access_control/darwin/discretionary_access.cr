{% skip_file unless flag?(:darwin) %}

require "./evaluation"

module Filesystem::AccessControl::Darwin::DiscretionaryAccess
  alias Membership = Evaluation::Membership
  alias Decision = Evaluation::Decision

  # Supplied advisory credential facts, not a kernel credential or permission
  # token. Membership queries happen before entering this pure composition.
  class Subject
    getter uid : UInt32
    getter uuid : StaticArray(UInt8, 16)?
    @groups : Hash(UInt32, Membership)
    @memberships : Hash(StaticArray(UInt8, 16), Membership)
    @well_known : Hash(StaticArray(UInt8, 16), Evaluation::PrincipalRole)
    @membership_errors : Hash(StaticArray(UInt8, 16), String)
    @diagnostics : Array(Diagnostic)

    def initialize(@uid : UInt32, @uuid : StaticArray(UInt8, 16)?,
                   groups = {} of UInt32 => Membership,
                   memberships = {} of StaticArray(UInt8, 16) => Membership,
                   well_known = {} of StaticArray(UInt8, 16) => Evaluation::PrincipalRole,
                   membership_errors = {} of StaticArray(UInt8, 16) => String,
                   diagnostics = [] of Diagnostic)
      @groups = groups.dup
      @memberships = memberships.dup
      @well_known = well_known.dup
      @membership_errors = membership_errors.dup
      @diagnostics = diagnostics.dup
    end

    def diagnostics : Array(Diagnostic)
      @diagnostics.dup
    end

    def group(gid : UInt32) : Membership
      @groups[gid]? || Membership::Unknown
    end

    def context(snapshot : Snapshot) : Evaluation::Context
      owner = snapshot.uid.try { |uid| uid == @uid ? Membership::Member : Membership::NotMember } || Membership::Unknown
      group = snapshot.gid.try { |gid| self.group(gid) } || Membership::Unknown
      Evaluation::Context.new(@uuid, owner, group, @memberships, @well_known,
        @membership_errors, Evaluation::GenericExpansion.vnode)
    end
  end

  # The full ACL decision and its target remain available even when mode
  # fallback or a later step determines the operation's final answer.
  record Check, stage : Symbol, decision : Decision, message : String,
    reason : Reason? = nil, acl : Evaluation::Result? = nil, target : Snapshot? = nil

  class Result
    getter decision : Decision
    getter operation : Symbol
    @checks : Array(Check)

    def initialize(@decision : Decision, @operation : Symbol, checks : Array(Check))
      @checks = checks.dup
    end

    def checks : Array(Check)
      @checks.dup
    end

    def allowed? : Bool
      @decision.allow?
    end

    def message : String
      @checks.map(&.message).join("; ")
    end

    def reason : Reason?
      @checks.reverse_each do |check|
        return check.reason if check.decision == @decision && check.reason
      end
      nil
    end

    def with_prefix(checks : Array(Check)) : Result
      Result.new(@decision, @operation, checks + @checks)
    end
  end

  WRITE_RIGHTS = Constants::ACL_WRITE_DATA | Constants::ACL_DELETE |
                 Constants::ACL_APPEND_DATA | Constants::ACL_DELETE_CHILD |
                 Constants::ACL_WRITE_ATTRIBUTES | Constants::ACL_WRITE_EXTATTRIBUTES |
                 Constants::ACL_WRITE_SECURITY | Constants::ACL_CHANGE_OWNER
  IMMUTABLE   = 0x00020002_u32 # UF_IMMUTABLE | SF_IMMUTABLE
  APPEND_ONLY = 0x00040004_u32 # UF_APPEND | SF_APPEND

  private def self.result(decision : Decision, operation : Symbol, stage : Symbol, detail : String, target : Snapshot? = nil) : Result
    reason = if decision.deny?
               Reason::PermissionDenied
             elsif decision.indeterminate?
               case stage
               when :server, :kind, :mount then Reason::Unsupported
               when :request               then Reason::InvalidInput
               when :membership            then Reason::IdentityLookupFailed
               else                             Reason::IncompleteEvidence
               end
             end
    Result.new(decision, operation, [Check.new(stage, decision, detail, reason, nil, target)])
  end

  private def self.acl_check(snapshot : Snapshot, acl : Evaluation::Result) : Check
    detail = case acl.decision
             when Decision::Allow then "Requested rights granted by the ordered ACL"
             when Decision::Deny
               entry = acl.trace.reverse.find { |step| step.action.in?({:deny, :deny_conservative_match}) }
               entry ? "ACL entry #{entry.ordinal} denies requested rights (mask #{acl.denied})" : "Requested rights denied by the ACL"
             when Decision::Defer then "ACL leaves rights for mode or parent evaluation"
             else                      "ACL evidence cannot determine the requested access"
             end
    detail += "; #{acl.errors.join("; ")}" unless acl.errors.empty?
    Check.new(:acl, acl.decision, detail, acl.reason, acl, snapshot)
  end

  # chown's target constraints precede vnode rights. CHANGE_OWNER permits
  # taking an inode, not giving it to an arbitrary third party. A group-only
  # change requires membership of the destination group and WRITE_SECURITY.
  # This models numeric UID/GID changes, not setattrlist's UUID attributes.
  # A read-only mount refuses every chown (vnode_setattr), but immutability
  # only one that asks for a right: XNU's vnode_authattr asks none when a
  # non-superuser's chown changes nothing, and always checks the superuser's.
  def self.change_ownership(snapshot : Snapshot, subject : Subject,
                            uid : UInt32? = nil, gid : UInt32? = nil) : Result
    validation = check(snapshot, subject: subject, permissions: 0_u64, operation: :change_ownership)
    return validation unless validation.decision.allow?
    if (snapshot.mount.not_nil!.flags & 1) != 0
      return result(Decision::Deny, :change_ownership, :mount, "Read-only filesystem", target: snapshot)
    end
    owner_changes = !uid.nil? && uid != snapshot.uid
    group_changes = !gid.nil? && gid != snapshot.gid
    if subject.uid == 0 || owner_changes || group_changes
      if denied = immutable(snapshot, Constants::ACL_CHANGE_OWNER, :change_ownership)
        return denied
      end
    end
    unless subject.uid == 0
      if owner_changes && uid != subject.uid
        return result(Decision::Deny, :change_ownership, :target_owner,
          "A non-superuser may change ownership only to their own UID", target: snapshot)
      end
      if group_changes
        membership = subject.group(gid.not_nil!)
        unless membership.member?
          return result(membership.unknown? ? Decision::Indeterminate : Decision::Deny,
            :change_ownership, :target_group, "Destination group membership is required", target: snapshot)
        end
      end
    end
    rights = owner_changes ? Constants::ACL_CHANGE_OWNER : group_changes ? Constants::ACL_WRITE_SECURITY : 0_u64
    check(snapshot, subject: subject, permissions: rights, operation: :change_ownership)
  end

  # One vnode's discretionary rights, including local mode fallback. This does
  # not grant a future syscall, model entitlements, or authorize a whole path.
  def self.check(snapshot : Snapshot, *, subject : Subject, permissions : UInt64,
                 operation : Symbol = :rights) : Result
    rights = permissions
    unless snapshot.complete? && snapshot.uid && snapshot.gid && snapshot.mode && snapshot.file_flags && snapshot.mount
      return result(Decision::Indeterminate, operation, :observation, "Complete inode and mount evidence is required", target: snapshot)
    end
    unless snapshot.kind == Kind::File || snapshot.kind == Kind::Directory
      return result(Decision::Indeterminate, operation, :kind, "Only regular files and directories are modeled", target: snapshot)
    end
    if (rights & ~Evaluation::KNOWN_PERMISSION_MASK) != 0
      return result(Decision::Indeterminate, operation, :request, "Unknown request rights", target: snapshot)
    end
    mount = snapshot.mount.not_nil!
    if mount.server_authorized?
      return result(Decision::Indeterminate, operation, :server,
        "Server authorization and credential mapping are not established by a client ACL snapshot", target: snapshot)
    end
    if mount.ownership_ignored?
      return result(Decision::Indeterminate, operation, :mount, "Ownership-disabled credential substitution is not modeled", target: snapshot)
    end
    if (rights & WRITE_RIGHTS) != 0 && (mount.flags & 1) != 0
      return result(Decision::Deny, operation, :mount, "Read-only filesystem", target: snapshot)
    end
    if snapshot.kind == Kind::File && (rights & Constants::ACL_EXECUTE) != 0 && (mount.flags & 4) != 0
      return result(Decision::Deny, operation, :mount, "No-execute filesystem", target: snapshot)
    end
    if (rights & Constants::ACL_WRITE_EXTATTRIBUTES) != 0 && (mount.flags & 0x01000000) != 0
      return result(Decision::Deny, operation, :mount, "User extended attributes disabled", target: snapshot)
    end
    if decision = immutable(snapshot, rights, operation)
      return decision
    end
    mode = snapshot.mode.not_nil!
    if subject.uid == 0
      if snapshot.kind == Kind::File && (rights & Constants::ACL_EXECUTE) != 0 && (mode & 0o111) == 0
        return result(Decision::Deny, operation, :superuser, "Root execute requires an executable mode bit", target: snapshot)
      end
      return result(Decision::Allow, operation, :superuser, "Supplied superuser credential; mounts and immutable flags checked", target: snapshot)
    end
    owner = snapshot.uid == subject.uid
    requested = rights
    requested &= ~Constants::ACL_WRITE_SECURITY if owner || (requested & Constants::ACL_CHANGE_OWNER) != 0
    return result(Decision::Allow, operation, :owner, "Write-security is implicit for the owner or requested takeover", target: snapshot) if requested == 0
    acl = Evaluation.evaluate(snapshot, Evaluation::Request.new(requested, snapshot.kind.not_nil!), subject.context(snapshot))
    evidence = [acl_check(snapshot, acl)]
    if acl.decision.deny? || acl.decision.indeterminate?
      return Result.new(acl.decision, operation, evidence)
    elsif acl.decision.allow?
      return Result.new(Decision::Allow, operation, evidence)
    end
    residual = acl.residual
    residual &= ~Constants::ACL_WRITE_ATTRIBUTES if owner
    if (residual & (Constants::ACL_CHANGE_OWNER | Constants::ACL_WRITE_SECURITY)) != 0
      return result(Decision::Deny, operation, :mode, "Ownership/security rights cannot be supplied by mode fallback", target: snapshot).with_prefix(evidence)
    end
    # DELETE requires both target and parent evidence; callers use delete.
    if (residual & Constants::ACL_DELETE) != 0
      return result(Decision::Indeterminate, operation, :parent, "Delete requires parent context", target: snapshot).with_prefix(evidence)
    end
    needed = 0_u32
    needed |= 4 if (residual & (Constants::ACL_READ_DATA | Constants::ACL_READ_EXTATTRIBUTES)) != 0
    needed |= 2 if (residual & (Constants::ACL_WRITE_DATA | Constants::ACL_APPEND_DATA |
                                Constants::ACL_DELETE_CHILD | Constants::ACL_WRITE_ATTRIBUTES | Constants::ACL_WRITE_EXTATTRIBUTES)) != 0
    needed |= 1 if (residual & Constants::ACL_EXECUTE) != 0
    if needed == 0
      return result(Decision::Allow, operation, :mode, "Residual metadata/interoperability rights need no mode mapping", target: snapshot).with_prefix(evidence)
    end
    mode_permission(snapshot, needed, subject, operation).with_prefix(evidence)
  end

  private def self.mode_permission(snapshot : Snapshot, needed : UInt32, subject : Subject, operation : Symbol) : Result
    mode = snapshot.mode
    uid = snapshot.uid
    gid = snapshot.gid
    unless mode && uid && gid
      return result(Decision::Indeterminate, operation, :mode, "Mode and numeric ownership required", target: snapshot)
    end
    owner = uid == subject.uid
    owner_ok = ((mode >> 6) & needed) == needed
    group_ok = ((mode >> 3) & needed) == needed
    world_ok = (mode & needed) == needed
    allowed = if owner
                owner_ok
              elsif group_ok == world_ok
                group_ok
              else
                case subject.group(snapshot.gid.not_nil!)
                when Membership::Member    then group_ok
                when Membership::NotMember then world_ok
                else
                  return result(Decision::Indeterminate, operation, :membership, "Owning-group membership is unknown and changes mode selection", target: snapshot)
                end
              end
    result(allowed ? Decision::Allow : Decision::Deny, operation, :mode, "Native owner/group/world mode selection", target: snapshot)
  end

  private def self.immutable(snapshot : Snapshot, rights : UInt64, operation : Symbol) : Result?
    flags = snapshot.file_flags
    return result(Decision::Indeterminate, operation, :flags, "File flags unavailable", target: snapshot) unless flags
    return nil if (rights & WRITE_RIGHTS) == 0
    if (flags & IMMUTABLE) != 0
      return result(Decision::Deny, operation, :flags, "Immutable inode", target: snapshot)
    end
    allowed = Constants::ACL_WRITE_EXTATTRIBUTES | Constants::ACL_APPEND_DATA
    allowed |= Constants::ACL_ADD_FILE if snapshot.kind == Kind::Directory
    if (flags & APPEND_ONLY) != 0 && ((rights & WRITE_RIGHTS) & ~allowed) != 0
      return result(Decision::Deny, operation, :flags, "Append-only inode", target: snapshot)
    end
    nil
  end

  def self.create(parent : Snapshot, kind : Kind, subject : Subject) : Result
    unless parent.kind == Kind::Directory && (kind == Kind::File || kind == Kind::Directory)
      return result(Decision::Indeterminate, :create, :kind, "Creation requires a directory parent and file/directory child kind", target: parent)
    end
    search = check(parent, subject: subject, permissions: Constants::ACL_SEARCH, operation: :create)
    return search unless search.decision.allow?
    right = kind == Kind::File ? Constants::ACL_ADD_FILE : Constants::ACL_ADD_SUBDIRECTORY
    decision = check(parent, subject: subject, permissions: right, operation: :create)
    Result.new(decision.decision, :create, search.checks + decision.checks)
  end

  def self.delete(target : Snapshot, parent : Snapshot, subject : Subject) : Result
    unless target.complete? && parent.complete? && parent.kind == Kind::Directory &&
           (target.kind == Kind::File || target.kind == Kind::Directory) && target.uid && parent.uid && parent.mode
      return result(Decision::Indeterminate, :delete, :observation, "Complete target and parent metadata required")
    end
    search = check(parent, subject: subject, permissions: Constants::ACL_SEARCH, operation: :delete)
    return search unless search.decision.allow?
    # Immutability of either inode overrides an ACL-specific delete grant.
    if denied = immutable(target, Constants::ACL_DELETE, :delete)
      return denied.with_prefix(search.checks)
    end
    if denied = immutable(parent, Constants::ACL_DELETE_CHILD, :delete)
      return denied.with_prefix(search.checks)
    end
    if mount = parent.mount
      return result(Decision::Deny, :delete, :mount, "Read-only parent filesystem", target: parent).with_prefix(search.checks) if (mount.flags & 1) != 0
    else
      return result(Decision::Indeterminate, :delete, :mount, "Parent mount unavailable", target: parent).with_prefix(search.checks)
    end
    return result(Decision::Allow, :delete, :superuser, "Supplied superuser credential", target: target).with_prefix(search.checks) if subject.uid == 0
    evidence = search.checks
    [{target, Constants::ACL_DELETE}, {parent, Constants::ACL_DELETE_CHILD}].each do |node, rights|
      acl = Evaluation.evaluate(node, Evaluation::Request.new(rights, node.kind.not_nil!), subject.context(node))
      evidence << acl_check(node, acl)
      unless acl.decision.defer?
        return Result.new(acl.decision, :delete, evidence)
      end
    end
    mode = mode_permission(parent, 2_u32, subject, :delete).with_prefix(evidence)
    return mode unless mode.decision.allow?
    if (parent.mode.not_nil! & 0o1000) != 0 && target.uid != subject.uid && parent.uid != subject.uid
      return result(Decision::Deny, :delete, :sticky, "Sticky parent requires target or parent ownership absent an ACL grant", target: parent).with_prefix(mode.checks)
    end
    result(Decision::Allow, :delete, :mode, "Parent write/search modes and sticky policy satisfied", target: parent).with_prefix(mode.checks)
  end

  # XNU's vn_authorize_renamex_with_paths (bsd/vfs/vfs_subr.c), without its
  # swap. The target's removal, and a folder target's ADD_SUBDIRECTORY on
  # itself, for its "..", wherever it goes. The right to add, asked of a
  # replaced folder rather than of the destination. DELETE of a replaced
  # entry only when it is not a folder: XNU asks none of a replaced folder.
  def self.rename(target : Snapshot, source_parent : Snapshot, destination_parent : Snapshot,
                  subject : Subject, replaced : Snapshot? = nil) : Result
    unless source_parent.device && destination_parent.device && target.kind
      return result(Decision::Indeterminate, :rename, :observation, "Parent devices and target kind required", target: target)
    end
    if source_parent.device != destination_parent.device
      return result(Decision::Deny, :rename, :filesystem, "Cross-filesystem rename is not supported", target: target)
    end
    folder = target.kind == Kind::Directory
    add = folder ? Constants::ACL_ADD_SUBDIRECTORY : Constants::ACL_ADD_FILE
    replaced_folder = replaced.try(&.kind) == Kind::Directory
    checks = [] of Check
    steps = [-> { delete(target, source_parent, subject) }]
    steps << -> { check(target, subject: subject, permissions: Constants::ACL_ADD_SUBDIRECTORY, operation: :rename) } if folder
    steps << -> { check(destination_parent, subject: subject, permissions: Constants::ACL_SEARCH, operation: :rename) }
    steps << -> { check(replaced_folder ? replaced.not_nil! : destination_parent, subject: subject, permissions: add, operation: :rename) }
    if (old = replaced) && !replaced_folder
      steps << -> { delete(old, destination_parent, subject) }
    end
    steps.each do |step|
      outcome = step.call
      checks.concat(outcome.checks)
      return Result.new(outcome.decision, :rename, checks) unless outcome.decision.allow?
    end
    Result.new(Decision::Allow, :rename, checks)
  end

  def self.hardlink(target : Snapshot, destination_parent : Snapshot, subject : Subject) : Result
    unless target.complete? && target.kind == Kind::File && target.device && destination_parent.device
      return result(Decision::Indeterminate, :hardlink, :observation, "Regular-file target and parent device evidence required", target: target)
    end
    if target.device != destination_parent.device
      return result(Decision::Deny, :hardlink, :filesystem, "Hard links cannot cross filesystems", target: target)
    end
    if denied = immutable(target, Constants::ACL_DELETE, :hardlink)
      return denied
    end
    parent = create(destination_parent, Kind::File, subject)
    Result.new(parent.decision, :hardlink, parent.checks)
  end
end
