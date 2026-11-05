require "./observation"

module Filesystem::AccessControl::Linux
  class Subject
    getter uid : UInt32
    getter? groups_complete : Bool
    @gids : Array(UInt32)

    # Include the primary/effective GID as well as supplementary groups.
    # IDs must be expressed in the same namespace as the captured ACL.
    def initialize(@uid : UInt32, gids : Array(UInt32), @groups_complete : Bool = true)
      raise ArgumentError.new("Invalid subject ID") if @uid == UInt32::MAX || gids.includes?(UInt32::MAX)
      @gids = gids.uniq
    end

    def gids : Array(UInt32)
      @gids.dup
    end

    def member?(gid : UInt32) : Bool
      @gids.includes?(gid)
    end
  end

  enum Decision
    Allowed
    Denied
    Indeterminate
  end

  enum DecisionReason
    Owner
    NamedUser
    Group
    Other
    IncompleteGroups
    IncompleteCapture
  end

  record Trace, entry : Entry, masked_permissions : Permissions

  class Evaluation
    getter decision : Decision
    getter reason : DecisionReason
    getter message : String
    getter target : Snapshot
    getter subject : Subject
    getter requested : Permissions
    @traces : Array(Trace)

    def initialize(@decision : Decision, @reason : DecisionReason, @message : String,
                   @target : Snapshot, @subject : Subject, @requested : Permissions, traces : Array(Trace))
      @traces = traces.dup
    end

    def traces : Array(Trace)
      @traces.dup
    end

    def allowed? : Bool
      @decision.allowed?
    end
  end

  # Pure POSIX ACL/mode evaluation, not a prediction of a complete syscall.
  # Does not emulate capability bypass, fsuid changes, LSMs or mount policy.
  module Evaluator
    def self.check(target : Snapshot, *, subject : Subject, permissions : Permissions) : Evaluation
      requested = permissions
      raise ArgumentError.new("Request must contain only rwx bits") if requested.value > 7
      unless target.complete?
        return Evaluation.new(Decision::Indeterminate, DecisionReason::IncompleteCapture,
          "ACL capture is incomplete", target, subject, requested, [] of Trace)
      end
      stat = target.stat.not_nil!
      acl = target.access || ACL.from_mode(stat.mode)
      if subject.uid == stat.uid
        return decide([acl.find(Tag::Owner).not_nil!], acl, DecisionReason::Owner, target, subject, requested)
      end
      if user = acl.find(Tag::User, subject.uid)
        return decide([user], acl, DecisionReason::NamedUser, target, subject, requested)
      end
      groups = acl.entries.select do |entry|
        (entry.tag.owning_group? && subject.member?(stat.gid)) ||
          (entry.tag.group? && subject.member?(entry.id.not_nil!))
      end
      if !groups.empty?
        result = decide(groups, acl, DecisionReason::Group, target, subject, requested)
        return result if result.allowed? || subject.groups_complete?
      end
      unless subject.groups_complete?
        return Evaluation.new(Decision::Indeterminate, DecisionReason::IncompleteGroups,
          "Group membership is incomplete; other permissions cannot decide this request", target, subject, requested,
          groups.map { |entry| Trace.new(entry, acl.masked_permissions(entry)) })
      end
      decide([acl.find(Tag::Other).not_nil!], acl, DecisionReason::Other, target, subject, requested)
    end

    private def self.decide(entries : Array(Entry), acl : ACL, reason : DecisionReason,
                            target : Snapshot, subject : Subject, requested : Permissions) : Evaluation
      traces = entries.map { |entry| Trace.new(entry, acl.masked_permissions(entry)) }
      allowed = traces.any? { |trace| (trace.masked_permissions & requested) == requested }
      explanation = allowed ? "#{reason} grants the requested permissions" : "#{reason} does not grant the whole request after masking"
      Evaluation.new(allowed ? Decision::Allowed : Decision::Denied, reason, explanation, target, subject, requested, traces)
    end
  end
end
