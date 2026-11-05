{% skip_file unless flag?(:darwin) %}

require "./model"

module Filesystem::AccessControl::Darwin
  module Evaluation
    # XNU returns defer when an ACL does not explicitly satisfy the request.
    enum Decision
      Allow
      Deny
      Defer
      Indeterminate
    end

    enum Membership
      Member
      NotMember
      Unknown
    end

    # A role is only assigned after comparing the ACE UUID with a verified
    # well-known UUID. Names and labels never participate in evaluation.
    enum PrincipalRole
      Owner
      OwningGroup
      Everyone
      Nobody
    end

    # The vnode caller supplies these per-kind expansions to kauth_acl_evaluate.
    # Keeping them explicit avoids pretending that generic rights are stored
    # permissions or that a single expansion applies to every operation.
    class GenericExpansion
      getter read : UInt64
      getter write : UInt64
      getter execute : UInt64
      getter all : UInt64

      def initialize(@read : UInt64, @write : UInt64, @execute : UInt64, @all : UInt64)
      end

      # Exact KAUTH_VNODE_GENERIC_*_BITS sets from the matched public XNU
      # header. The ordinary file and directory names alias the same bit values.
      def self.vnode : GenericExpansion
        read = Constants::ACL_READ_DATA |
               Constants::ACL_READ_ATTRIBUTES |
               Constants::ACL_READ_EXTATTRIBUTES |
               Constants::ACL_READ_SECURITY
        write = Constants::ACL_WRITE_DATA |
                Constants::ACL_APPEND_DATA |
                Constants::ACL_DELETE |
                Constants::ACL_DELETE_CHILD |
                Constants::ACL_WRITE_ATTRIBUTES |
                Constants::ACL_WRITE_EXTATTRIBUTES |
                Constants::ACL_WRITE_SECURITY
        execute = Constants::ACL_EXECUTE
        new(read, write, execute, read | write | execute)
      end
    end

    struct Request
      getter rights : UInt64
      getter kind : Kind

      def initialize(@rights : UInt64, @kind : Kind)
      end
    end

    # Synthetic evidence corresponding to the credential facts that XNU's ACL
    # evaluator consumes. Missing membership entries are explicitly unknown.
    class Context
      getter subject_uuid : StaticArray(UInt8, 16)?
      getter owner : Membership
      getter owning_group : Membership
      getter generic_expansion : GenericExpansion
      @memberships : Hash(StaticArray(UInt8, 16), Membership)
      @well_known : Hash(StaticArray(UInt8, 16), PrincipalRole)
      @membership_errors : Hash(StaticArray(UInt8, 16), String)

      def initialize(@subject_uuid : StaticArray(UInt8, 16)? = nil,
                     @owner : Membership = Membership::Unknown,
                     @owning_group : Membership = Membership::Unknown,
                     memberships : Hash(StaticArray(UInt8, 16), Membership) = {} of StaticArray(UInt8, 16) => Membership,
                     well_known : Hash(StaticArray(UInt8, 16), PrincipalRole) = {} of StaticArray(UInt8, 16) => PrincipalRole,
                     membership_errors : Hash(StaticArray(UInt8, 16), String) = {} of StaticArray(UInt8, 16) => String,
                     @generic_expansion : GenericExpansion = GenericExpansion.vnode)
        @memberships = memberships.dup
        @well_known = well_known.dup
        @membership_errors = membership_errors.dup
      end

      def membership(uuid : StaticArray(UInt8, 16)) : Membership
        if role = role_for(uuid)
          case role
          when PrincipalRole::Owner       then @owner
          when PrincipalRole::OwningGroup then @owning_group
          when PrincipalRole::Everyone    then Membership::Member
          when PrincipalRole::Nobody      then Membership::NotMember
          else                                 Membership::Unknown
          end
        else
          return Membership::Member if @subject_uuid == uuid
          @memberships[uuid]? || Membership::Unknown
        end
      end

      def membership_error(uuid : StaticArray(UInt8, 16)) : String?
        @membership_errors[uuid]?
      end

      def memberships : Hash(StaticArray(UInt8, 16), Membership)
        @memberships.dup
      end

      def well_known : Hash(StaticArray(UInt8, 16), PrincipalRole)
        @well_known.dup
      end

      def membership_errors : Hash(StaticArray(UInt8, 16), String)
        @membership_errors.dup
      end

      def well_known_role?(uuid : StaticArray(UInt8, 16)) : Bool
        !role_for(uuid).nil?
      end

      def owning_group_role?(uuid : StaticArray(UInt8, 16)) : Bool
        role_for(uuid) == PrincipalRole::OwningGroup
      end

      private def role_for(uuid : StaticArray(UInt8, 16)) : PrincipalRole?
        if role = @well_known[uuid]?
          return role
        end
        case WellKnownUUID.classify(uuid)
        when WellKnown::Owner     then PrincipalRole::Owner
        when WellKnown::Group     then PrincipalRole::OwningGroup
        when WellKnown::Everybody then PrincipalRole::Everyone
        when WellKnown::Nobody    then PrincipalRole::Nobody
        else                           nil
        end
      end
    end

    record Trace, ordinal : Int32, raw_tag : UInt32, principal : StaticArray(UInt8, 16),
      membership : Membership, requested_overlap : UInt64, residual_before : UInt64,
      residual_after : UInt64, action : Symbol, detail : String? = nil

    class Result
      getter decision : Decision
      getter requested : UInt64
      getter residual : UInt64
      getter granted : UInt64
      getter denied : UInt64
      getter unresolved : UInt64
      getter reason : Reason?
      @trace : Array(Trace)
      @errors : Array(String)

      def initialize(@decision : Decision, @requested : UInt64, @residual : UInt64,
                     @granted : UInt64, @denied : UInt64, @unresolved : UInt64,
                     trace : Array(Trace), errors : Array(String), reason : Reason? = nil)
        @trace = trace.dup
        @errors = errors.dup
        @reason = reason || case @decision
        when Decision::Deny          then Reason::PermissionDenied
        when Decision::Indeterminate then Reason::IncompleteEvidence
        end
      end

      def trace : Array(Trace)
        @trace.dup
      end

      def errors : Array(String)
        @errors.dup
      end
    end

    GENERIC_ALL     = Constants::ACL_GENERIC_ALL
    GENERIC_EXECUTE = Constants::ACL_GENERIC_EXECUTE
    GENERIC_WRITE   = Constants::ACL_GENERIC_WRITE
    GENERIC_READ    = Constants::ACL_GENERIC_READ
    GENERIC_MASK    = Constants::ACL_GENERIC_MASK

    KNOWN_PERMISSION_MASK = Constants::ACL_READ_DATA |
                            Constants::ACL_WRITE_DATA |
                            Constants::ACL_EXECUTE |
                            Constants::ACL_DELETE |
                            Constants::ACL_APPEND_DATA |
                            Constants::ACL_DELETE_CHILD |
                            Constants::ACL_READ_ATTRIBUTES |
                            Constants::ACL_WRITE_ATTRIBUTES |
                            Constants::ACL_READ_EXTATTRIBUTES |
                            Constants::ACL_WRITE_EXTATTRIBUTES |
                            Constants::ACL_READ_SECURITY |
                            Constants::ACL_WRITE_SECURITY |
                            Constants::ACL_CHANGE_OWNER |
                            Constants::ACL_SYNCHRONIZE

    # Evaluate a complete request against one ordered ACL observation. This is
    # advisory; it does not compose mode bits, mounts, parents or later changes.
    def self.evaluate(snapshot : Snapshot, request : Request, context : Context) : Result
      requested = request.rights
      trace = [] of Trace
      errors = [] of String
      residual = requested
      granted = 0_u64
      denied = 0_u64
      unresolved = 0_u64

      # The kernel treats a no-op request as allowed without consulting ACLs.
      return Result.new(Decision::Allow, requested, 0_u64, 0_u64, 0_u64,
        0_u64, trace, errors) if requested == 0

      if request.kind != Kind::File && request.kind != Kind::Directory
        errors << "ACL request target kind is not a regular file or directory"
        return Result.new(Decision::Indeterminate, requested, residual, granted,
          denied, requested, trace, errors, Reason::Unsupported)
      end

      unless snapshot.complete?
        errors << "ACL observation is not complete (#{snapshot.status})"
        return Result.new(Decision::Indeterminate, requested, residual, granted,
          denied, requested, trace, errors, snapshot.diagnostics.first?.try(&.reason))
      end

      unknown_request = requested & ~KNOWN_PERMISSION_MASK
      if unknown_request != 0
        return Result.new(Decision::Indeterminate, requested, residual, granted,
          denied, requested, trace, ["Request contains unknown or generic request rights"], Reason::InvalidInput)
      end
      known_header_flags = Constants::ACL_FLAG_NO_INHERIT
      if (snapshot.acl_flags & ~known_header_flags) != 0
        return Result.new(Decision::Indeterminate, requested, residual, granted,
          denied, requested, trace, ["ACL header flags have unresolved evaluation semantics"], Reason::Unsupported)
      end

      entries = snapshot.entries
      if snapshot.status.absent? || snapshot.status.empty?
        unless entries.empty?
          errors << "ACL observation status conflicts with its entries"
          return Result.new(Decision::Indeterminate, requested, residual, granted,
            denied, requested, trace, errors)
        end
        return Result.new(Decision::Defer, requested, residual, granted, denied,
          0_u64, trace, errors)
      end
      unless snapshot.status.present? && !entries.empty?
        errors << "ACL observation status conflicts with its entries"
        return Result.new(Decision::Indeterminate, requested, residual, granted,
          denied, requested, trace, errors)
      end

      entries.each do |ace|
        before = residual
        known_entry_flags = Constants::ACL_ENTRY_FLAGS
        if (ace.raw_flags & ~known_entry_flags) != 0 ||
           (ace.rights & ~(KNOWN_PERMISSION_MASK | GENERIC_MASK)) != 0
          return Result.new(Decision::Indeterminate, requested, residual, granted,
            denied, requested, trace, ["ACE #{ace.ordinal} contains unknown rights or flags"], Reason::Unsupported)
        end
        if (ace.raw_flags & Constants::ACL_ENTRY_ONLY_INHERIT) != 0
          trace << Trace.new(ace.ordinal, ace.raw_tag, ace.principal.uuid,
            Membership::Unknown, 0_u64, before, residual, :only_inherit_skipped)
          next
        end

        rights = expand_rights(ace.rights, context.generic_expansion)
        overlap = requested & rights
        kind = ace.raw_tag
        is_allow = kind == Constants::ACL_EXTENDED_ALLOW
        is_deny = kind == Constants::ACL_EXTENDED_DENY

        # The kernel skips ACE kinds it does not recognize. A diagnostic
        # evaluator cannot silently assume future/unknown tags are harmless.
        unless is_allow || is_deny
          if overlap != 0
            unresolved |= overlap
            trace << Trace.new(ace.ordinal, kind, ace.principal.uuid,
              Membership::Unknown, overlap, before, residual,
              :unknown_tag_relevant, "Unknown ACE tag may affect requested rights")
            errors << "ACE #{ace.ordinal} has an unknown tag relevant to the request"
          else
            trace << Trace.new(ace.ordinal, kind, ace.principal.uuid,
              Membership::Unknown, 0_u64, before, residual, :unknown_tag_irrelevant)
          end
          next
        end

        # XNU ignores allow ACEs that cannot reduce the residual and deny ACEs
        # that do not overlap the ORIGINAL request. In particular, a deny is
        # never tested only against the residual mask.
        relevant = is_allow ? ((residual & rights) != 0) : (overlap != 0)
        unless relevant
          trace << Trace.new(ace.ordinal, kind, ace.principal.uuid,
            Membership::Unknown, overlap, before, residual, :no_right_overlap)
          next
        end

        membership = context.membership(ace.principal.uuid)
        detail = nil.as(String?)
        applies = case membership
                  when Membership::Member
                    true
                  when Membership::NotMember
                    false
                  when Membership::Unknown
                    detail = context.membership_error(ace.principal.uuid)
                    errors << "ACE #{ace.ordinal} membership is unknown#{detail ? ": #{detail}" : ""}"
                    if context.well_known_role?(ace.principal.uuid) &&
                       !context.owning_group_role?(ace.principal.uuid)
                      unresolved |= overlap
                      false
                    else
                      # Match XNU's conservative rule: an uncertain allow cannot
                      # grant; an uncertain deny is applied to avoid overgranting.
                      is_deny
                    end
                  end

        unless applies
          trace << Trace.new(ace.ordinal, kind, ace.principal.uuid, membership,
            overlap, before, residual,
            membership.unknown? ? (context.well_known_role?(ace.principal.uuid) ? :well_known_context_unknown : :unknown_allow_skipped) : :not_member,
            detail)
          next
        end

        if is_deny
          denied = overlap
          trace << Trace.new(ace.ordinal, kind, ace.principal.uuid, membership,
            overlap, before, residual, membership.unknown? ? :deny_conservative_match : :deny, detail)
          decision = unresolved == 0 ? Decision::Deny : Decision::Indeterminate
          return Result.new(decision, requested, residual, granted, denied,
            unresolved, trace, errors)
        end

        residual &= ~rights
        granted = requested & ~residual
        trace << Trace.new(ace.ordinal, kind, ace.principal.uuid, membership,
          overlap, before, residual, membership.unknown? ? :allow_match_known_membership : :allow)
        if residual == 0
          decision = unresolved == 0 ? Decision::Allow : Decision::Indeterminate
          return Result.new(decision, requested, residual, granted, denied,
            unresolved, trace, errors)
        end
      end

      decision = if unresolved != 0
                   Decision::Indeterminate
                 else
                   Decision::Defer
                 end
      Result.new(decision, requested, residual, granted, denied, unresolved,
        trace, errors)
    end

    private def self.expand_rights(rights : UInt64, expansion : GenericExpansion) : UInt64
      expanded = rights
      expanded |= expansion.all if (rights & GENERIC_ALL) != 0
      expanded |= expansion.execute if (rights & GENERIC_EXECUTE) != 0
      expanded |= expansion.write if (rights & GENERIC_WRITE) != 0
      expanded |= expansion.read if (rights & GENERIC_READ) != 0
      expanded
    end
  end
end
