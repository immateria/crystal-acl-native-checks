require "../model"
require "./rights"
require "./observation"

module Filesystem::AccessControl::Windows
  enum AccessDecision
    Allowed
    Denied
    Indeterminate
  end

  enum EvaluationScope
    DiscretionaryDescriptor
  end

  # The raw BOOL result and its meaningful output fields are distinct. Output
  # fields from a failed call are deliberately unavailable, per AccessCheck.
  record AccessCheckCall, api_success : Bool, access_status : Bool?,
    granted_mask : UInt32?, privilege_size : UInt32, diagnostic : Diagnostic?

  class EvaluationResult
    getter decision : AccessDecision
    getter requested : Rights
    getter mapped : Rights
    getter kind : Filesystem::AccessControl::Target
    getter api_success : Bool?
    getter access_status : Bool?
    getter granted_mask : UInt32?
    getter native_error : Diagnostic?
    getter diagnostic : Diagnostic?
    @privileges : Bytes?

    def initialize(@decision : AccessDecision, @requested : Rights, @mapped : Rights,
                   @kind : Filesystem::AccessControl::Target, *, @api_success : Bool? = nil,
                   @access_status : Bool? = nil, @granted_mask : UInt32? = nil,
                   @native_error : Diagnostic? = nil, diagnostic : Diagnostic? = nil,
                   privileges : Bytes? = nil)
      @diagnostic = diagnostic || @native_error
      @privileges = privileges.try(&.dup)
      valid = case @decision
              when .allowed?
                @api_success == true && @access_status == true && @granted_mask == @mapped.value && @diagnostic.nil?
              when .denied?
                @api_success == true && @access_status == false && @granted_mask == 0_u32
              when .indeterminate?
                true
              else
                false
              end
      raise ArgumentError.new("Access-check decision disagrees with its evidence") unless valid
    end

    def allowed? : Bool
      @decision.allowed?
    end

    # This does not qualify mandatory integrity, a live filesystem acquisition,
    # sharing policy, remote-server policy or later changes to the token/object.
    def scope : EvaluationScope
      EvaluationScope::DiscretionaryDescriptor
    end

    def privileges : Bytes?
      @privileges.try(&.dup)
    end
  end

  module Evaluator
    INITIAL_PRIVILEGE_SIZE =     20
    MAX_PRIVILEGE_SIZE     = 65_536

    {% if flag?(:windows) %}
      # The caller retains an impersonation-token HANDLE with TOKEN_QUERY for
      # the entire check. No token substitution, impersonation or mutation.
      def self.check(snapshot : Snapshot, *, subject : Void*, permissions : Rights,
                     kind : Filesystem::AccessControl::Target) : EvaluationResult
        check(snapshot, subject: subject, permissions: permissions, kind: kind,
          provider: NativeAccessCheckProvider.new)
      end
    {% end %}

    def self.check(snapshot : Snapshot, *, subject : Void*, permissions : Rights,
                   kind : Filesystem::AccessControl::Target, provider) : EvaluationResult
      permissions.validate_file_request!
      raise ArgumentError.new("Empty access request is outside the initial Windows check profile") if permissions.none?
      unless kind.file? || kind.directory?
        raise ArgumentError.new("Unsupported filesystem access target")
      end
      mapping = GenericMapping::FILESYSTEM
      mapped = mapping.expand(permissions)
      if subject.null?
        return refused(permissions, mapped, kind, "AccessCheck.subject", "An explicit impersonation-token handle is required")
      end
      unless snapshot.complete? && snapshot.information.owner? && snapshot.information.group? &&
             snapshot.information.dacl? && snapshot.owner && snapshot.group
        return refused(permissions, mapped, kind, "AccessCheck.capture", "Complete owner, group and DACL observations are required")
      end
      if acl = snapshot.dacl
        if acl.entries.any? { |ace| ace.type != 0 && ace.type != 1 }
          return refused(permissions, mapped, kind, "AccessCheck.profile", "The initial check profile accepts only basic allow/deny DACL ACEs")
        end
      end
      descriptor = snapshot.descriptor.not_nil!.bytes
      privileges = Bytes.new(INITIAL_PRIVILEGE_SIZE, 0_u8)
      attempts = 0
      loop do
        attempts += 1
        call = provider.call(descriptor, subject, mapped.value, mapping, privileges)
        unless call.api_success
          if attempts < 2 && call.diagnostic.try(&.code) == 122_u32 &&
             privileges.size < call.privilege_size <= MAX_PRIVILEGE_SIZE
            privileges = Bytes.new(call.privilege_size.to_i, 0_u8)
            next
          end
          diagnostic = call.diagnostic || validation("AccessCheck", "Failed native check omitted its error diagnostic")
          return EvaluationResult.new(AccessDecision::Indeterminate, permissions, mapped, kind,
            api_success: false, native_error: call.diagnostic, diagnostic: diagnostic)
        end

        error = validate_outputs(call, privileges, mapped)
        raw = if 8 <= call.privilege_size <= privileges.size
                privileges[0, call.privilege_size.to_i]
              end
        decision = if error
                     AccessDecision::Indeterminate
                   elsif call.access_status
                     AccessDecision::Allowed
                   else
                     AccessDecision::Denied
                   end
        return EvaluationResult.new(decision, permissions, mapped, kind,
          api_success: true, access_status: call.access_status, granted_mask: call.granted_mask,
          native_error: call.diagnostic, diagnostic: error, privileges: raw)
      end
    end

    private def self.validate_outputs(call : AccessCheckCall, privileges : Bytes, mapped : Rights) : Diagnostic?
      unless call.access_status != nil && call.granted_mask != nil
        return validation("AccessCheck.result", "Successful check omitted its access status or granted mask")
      end
      if call.access_status
        unless call.granted_mask == mapped.value && call.diagnostic.nil?
          return validation("AccessCheck.result", "Granted access does not match the complete fixed request")
        end
      elsif call.granted_mask != 0_u32
        return validation("AccessCheck.result", "Denied check returned a nonzero granted mask")
      end
      unless 8 <= call.privilege_size <= privileges.size
        return validation("AccessCheck.privileges", "Returned privilege-set length is outside its buffer")
      end
      count = IO::ByteFormat::LittleEndian.decode(UInt32, privileges[0, 4])
      if count > (call.privilege_size - 8) // 12
        return validation("AccessCheck.privileges", "Returned privilege-set entries exceed its returned length")
      end
      nil
    end

    private def self.refused(requested : Rights, mapped : Rights, kind : Filesystem::AccessControl::Target,
                             operation : String, message : String) : EvaluationResult
      EvaluationResult.new(AccessDecision::Indeterminate, requested, mapped, kind,
        diagnostic: validation(operation, message))
    end

    private def self.validation(operation : String, message : String) : Diagnostic
      Diagnostic.new(operation, nil, ErrorOrigin::Validation, message)
    end
  end
end

{% if flag?(:windows) %}
  require "./evaluation_native"
{% end %}
