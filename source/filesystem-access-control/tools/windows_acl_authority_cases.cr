require "./windows_acl_propagation_cases"

module WindowsACLWorkflows
  # Qualify denied fresh child authority independently of the parent operation.
  # Propagation is not assumed to use the same authorization route as a new
  # WRITE_DAC handle. Failure and independently observed effects stay separate.
  def self.propagation_authority_violations(facts : JSON::Any) : Array(String)
    errors = [] of String
    unless facts["passed"].as_bool && facts["recovery_restored"].as_bool && facts["process_capture_complete"].as_bool &&
           facts["scope"].as_s == "child-write-dac-denial-under-privilege-free-thread-token" &&
           facts["privilege_control"].as_s == "delete-all-observed-privileges" && facts["deleted_privilege_count"].as_i64 >= 0
      errors << "Missing authority fixture or privilege-removal evidence"
    end
    token = facts["token"]
    unless token["capture_complete"].as_bool && token["source"].as_s == "Thread" &&
           token["type"].as_s == "Impersonation" && token["level"].as_s == "Impersonation" &&
           token["matches_process_user"].as_bool && token["privilege_count"].as_i64 == 0 &&
           token["enabled_privilege_count"].as_i64 == 0 && token["restored"].as_bool
      errors << "Unqualified selected token context"
    end
    principal = Filesystem::AccessControl::Windows::SID.new(facts["principal"].as_s.hexbytes)
    owner_names = Set(String).new
    facts["owner_proofs"].as_a.each do |row|
      name = row["name"].as_s
      unless owner_names.add?(name) && name.in?({"denied-file", "denied-dir"}) && row["setter_code"].as_i64 == 0 &&
             row["capture_complete"].as_bool && row["matches_process_user"].as_bool
        errors << "Invalid explicit child owner proof"
      end
    end
    errors << "Missing explicit child owner assignment" unless owner_names == Set{"denied-file", "denied-dir"}
    expected_oracles = {
      {"parent", 0x40000_i64} => true, {"allowed", 0x40000_i64} => true,
      {"denied-file", 0x20000_i64} => true, {"denied-file", 0x40000_i64} => false,
      {"denied-dir", 0x20000_i64} => true, {"denied-dir", 0x40000_i64} => false,
    }
    oracles = Set(Tuple(String, String, Int64)).new
    facts["oracles"].as_a.each do |row|
      phase, name, access = row["phase"].as_s, row["name"].as_s, row["requested_access"].as_i64
      wanted = expected_oracles[{name, access}]?
      if wanted.nil? || !phase.in?({"before", "after"}) || !oracles.add?({phase, name, access})
        errors << "Duplicate or unknown child authority oracle"
      elsif row["acquired"].as_bool != wanted || row["code"].as_i64 != (wanted ? 0 : 5)
        errors << "Fresh #{phase}/#{name}/#{access} disagrees with authority control"
      end
    end
    errors << "Missing before/after authority acquisition controls" unless oracles.size == 12

    before, after = facts["target_before"], facts["target_after"]
    errors.concat(held_witness_violations(before, after))
    prior, later = propagation_descriptor(before), propagation_descriptor(after)
    errors.concat(candidate_violations(prior, nil, "parent-before"))
    code = facts["native_code"].as_i64
    errors << "Unexpected native setter failure" unless code.in?({0_i64, 5_i64})
    result = facts["mutation"]
    errors.concat(propagation_result_violations(result, success: code == 0))
    unless facts["setter_calls"].as_i64 == 1 && facts["capture_calls"].as_i64 == (code == 0 ? 2 : 1) &&
           facts["public_after_nil"].as_bool == (code != 0)
      errors << "Parent mutation was replayed or readback evidence was misreported"
    end
    if code == 0
      errors << "Successful target has a diagnostic" unless result["diagnostic"].raw.nil?
      errors.concat(candidate_violations(later, 3, "parent-after"))
    else
      diagnostic = result["diagnostic"]
      unless diagnostic["operation"].as_s == "SetSecurityInfo" && diagnostic["code"].as_i64 == code && diagnostic["origin"].as_s == "ReturnValue"
        errors << "Failed setter lost diagnostic provenance"
      end
    end
    changed = security_observation_changed?(prior, later)
    seen = Set(String).new
    sampled = 0
    owner_rights = Filesystem::AccessControl::Windows::SID.new("010100000000000304000000".hexbytes)
    facts["nodes"].as_a.each do |row|
      name = row["name"].as_s
      errors << "Duplicate or unknown authority witness" unless seen.add?(name) && name.in?({"allowed", "denied-file", "denied-dir", "denied-grandchild", "protected"})
      errors.concat(held_witness_violations(row["before"], row["after"]))
      original, observed = propagation_descriptor(row["before"]), propagation_descriptor(row["after"])
      errors.concat(candidate_violations(original, nil, "before/#{name}"))
      errors << "Wrong authority witness kind" unless row["after"]["directory"].as_bool == (name == "denied-dir")
      errors << "Changed authority witness protection" unless observed.dacl_inheritance_control.not_nil!.protected? == (name == "protected")
      if name.in?({"denied-file", "denied-dir"})
        [original, observed].each do |descriptor|
          denies = descriptor.dacl.not_nil!.entries.select { |entry| entry.trustee == owner_rights }
          unless descriptor.owner == principal && denies.size == 1 && denies[0].type == 1 && denies[0].flags == 0 && denies[0].rights == 0x40000_u32
            errors << "Child owner or explicit OWNER_RIGHTS denial changed"
          end
        end
      end
      present = observed.dacl.not_nil!.entries.any? { |entry| entry.trustee.try(&.bytes.hexstring) == "010100000000000100000000" }
      expected_flags = present ? (name == "denied-dir" ? 19 : 16) : nil
      errors.concat(candidate_violations(observed, expected_flags, name))
      sampled += 1 if present && name != "protected"
      errors << "Protected control changed" if name == "protected" && security_observation_changed?(original, observed)
      errors << "Successful propagation skipped its ordinary allowed control" if code == 0 && name == "allowed" && !present
      changed ||= security_observation_changed?(original, observed)
    end
    errors << "Missing independent child observations" unless seen == Set{"allowed", "denied-file", "denied-dir", "denied-grandchild", "protected"}
    classification = if code == 0
                       sampled == 4 ? "SucceededAllSampled" : "SucceededWithSkippedSamples"
                     else
                       changed ? "FailedWithObservedEffects" : "FailedWithoutObservedEffects"
                     end
    errors << "Classification invents or erases observed effects" unless facts["classification"].as_s == classification
    errors
  rescue KeyError | IndexError | TypeCastError | ArgumentError | NilAssertionError
    ["Propagation authority evidence is missing or malformed"]
  end

  private def self.security_observation_changed?(before, after) : Bool
    before.control != after.control || before.owner != after.owner || before.group != after.group || before.dacl != after.dacl
  end

  {% if flag?(:windows) %}
    private def self.authority_open(path : Path, access : UInt32)
      units = path.to_s.to_utf16
      name = Slice(UInt16).new(units.size + 1, 0_u16)
      units.copy_to(name)
      # Directory opens require backup semantics, but no backup privilege is
      # present in the selected token. These are fresh security-right opens.
      handle = LibC.CreateFileW(name.to_unsafe, access, 7_u32,
        Pointer(LibC::SECURITY_ATTRIBUTES).null, 3_u32, 0x02200000_u32, Pointer(Void).null)
      if handle.address == UInt64::MAX
        {requested_access: access, acquired: false, code: LibC.GetLastError}
      else
        LibC.CloseHandle(handle)
        {requested_access: access, acquired: true, code: 0_u32}
      end
    end

    private def self.authority_oracles(paths, phase : String) : Array(JSON::Any)
      [{"parent", 0x40000_u32}, {"allowed", 0x40000_u32},
       {"denied-file", 0x20000_u32}, {"denied-file", 0x40000_u32},
       {"denied-dir", 0x20000_u32}, {"denied-dir", 0x40000_u32}].map do |name, access|
        json(authority_open(paths[name], access).merge({phase: phase, name: name}))
      end
    end

    private def self.propagation_authority(root : Path) : JSON::Any
      process = WinACL::TokenReader.capture_subject(WinACL::TokenContext::Process, information: WinACL::TokenSubjectInformation::Privileges)
      ensure!(process.complete?, "Process identity/privileges unavailable")
      principal = process.token.identity.not_nil!.user
      initial = WinACL::TokenReader.capture(WinACL::TokenContext::Effective)
      ensure!(initial.complete? && initial.source.try(&.process?) == true, "Authority helper requires an initially unimpersonated process")
      deleted = process.privileges.value.not_nil!.entries.map do |privilege|
        item = ProbeNative::OwnerPrivilegeAndAttributes.new
        item.low, item.high, item.attributes = privilege.luid_low, privilege.luid_high, 0_u32
        item
      end
      parent = root / "authority"
      Dir.mkdir(parent)
      paths = {"allowed" => parent / "allowed", "denied-file" => parent / "denied-file",
               "denied-dir" => parent / "denied-dir", "denied-grandchild" => parent / "denied-dir" / "child",
               "protected" => parent / "protected"}
      paths.each { |name, path| name == "denied-dir" ? Dir.mkdir(path) : File.write(path, "fixture") }
      paths["parent"] = parent
      everyone = WinACL::SID.new("010100000000000100000000".hexbytes)
      owner_rights = WinACL::SID.new("010100000000000304000000".hexbytes)
      recovery = acl([{0_u8, 0_u8, 0x1f01ff_u32, principal}])
      denied = acl([{1_u8, 0_u8, 0x40000_u32, owner_rights}, {0_u8, 0_u8, 0x1b01ff_u32, principal}])
      desired = acl([{0_u8, 3_u8, 0x1f01ff_u32, principal}, {0_u8, 3_u8, 1_u32, everyone}])
      handles = {} of String => Void*
      proofs, oracles, nodes = [] of JSON::Any, [] of JSON::Any, [] of JSON::Any
      recovery_restored = false
      begin
        paths.each { |name, path| handles[name] = open_handle(path, 0xe0080_u32) }
        held = handles["parent"]
        prepare(held, recovery)
        paths.each_key do |name|
          next if name == "parent"
          handle = handles[name]
          if name.in?({"denied-file", "denied-dir"})
            owner_bytes = principal.bytes
            code = Filesystem::AccessControl::Native::Windows::ACL.acl_set_security_info(handle, 1_u32, 1_u32,
              owner_bytes.to_unsafe.as(Void*), Pointer(Void).null, Pointer(Void).null, Pointer(Void).null)
            owned = WinACL::HandleReader.capture(handle)
            ensure!(code == 0 && owned.complete? && owned.security.owner == principal, "Explicit child owner installation failed")
            proofs << json({name: name, setter_code: code, capture_complete: owned.complete?, matches_process_user: owned.security.owner == principal})
          end
          if name == "protected"
            prepare(handle, recovery)
          else
            code = WinACL::NativeWriterProvider.new.replace(handle, name.starts_with?("denied-") && name != "denied-grandchild" ? denied : recovery, 0x20000004_u32)
            ensure!(code == 0, "Authority child policy setup failed: #{code}")
          end
        end
        before = handles.transform_values { |handle| propagation_capture(handle) }
        target = WinACL::HandleReader.capture(held)
        execution = with_process_token do |primary|
          restricted = Pointer(Void).null
          deleted_pointer = deleted.empty? ? Pointer(Void).null : deleted.to_unsafe.as(Void*)
          if ProbeNative.restricted_token(primary, 0_u32, 0_u32, Pointer(ProbeNative::SIDAndAttributes).null,
               deleted.size.to_u32, deleted_pointer, 0_u32, Pointer(ProbeNative::SIDAndAttributes).null, pointerof(restricted)) == 0
            raise "CreateRestrictedToken(delete privileges) failed: #{LibC.GetLastError}"
          end
          begin
            with_impersonation(restricted) do |subject|
              raise "SetThreadToken failed: #{LibC.GetLastError}" if ProbeNative.set_thread_token(Pointer(Void*).null, subject) == 0
              begin
                observed = WinACL::TokenReader.capture_subject(WinACL::TokenContext::Effective, information: WinACL::TokenSubjectInformation::Privileges)
                oracles.concat(authority_oracles(paths, "before"))
                provider = TrackedWriterProvider.new
                result = WinACL::Writer.replace_dacl_handle(held, target: target, dacl: desired,
                  inheritance: WinACL::InheritancePolicy::PreserveObserved,
                  propagation: WinACL::PropagationPolicy::NativePropagation, provider: provider)
                oracles.concat(authority_oracles(paths, "after"))
              ensure
                abort "RevertToSelf failed: #{LibC.GetLastError}" if ProbeNative.revert == 0
              end
              {observed, provider, result}
            end
          ensure
            LibC.CloseHandle(restricted)
          end
        end
        observed, provider, result = execution.not_nil!
        restored = WinACL::TokenReader.capture(WinACL::TokenContext::Effective)
        identity, privileges = observed.token.identity, observed.privileges.value
        token = {capture_complete: observed.complete?, source: observed.token.source.try(&.to_s), type: identity.try(&.type.to_s),
                 level: identity.try(&.impersonation_level.try(&.to_s)), matches_process_user: identity.try(&.user) == principal,
                 privilege_count: privileges.try(&.entries.size), enabled_privilege_count: privileges.try { |value| value.entries.count(&.enabled?) },
                 restored: restored.complete? && restored.source.try(&.process?) == true && restored.identity.try(&.user) == principal}
        after = handles.transform_values { |handle| propagation_capture(handle) }
        paths.each_key { |name| nodes << json({name: name, before: before[name], after: after[name]}) unless name == "parent" }
        changed = handles.keys.any? { |name| security_observation_changed?(propagation_descriptor(before[name]), propagation_descriptor(after[name])) }
        sampled = nodes.count { |row| propagation_descriptor(row["after"]).dacl.not_nil!.entries.any? { |entry| entry.trustee == everyone } }
        classification = result.execution.succeeded? ? (sampled == 4 ? "SucceededAllSampled" : "SucceededWithSkippedSamples") : (changed ? "FailedWithObservedEffects" : "FailedWithoutObservedEffects")
      ensure
        begin
          handles.each_value do |handle|
            prepare(handle, recovery)
            ensure!(WinACL::HandleReader.capture(handle).security.dacl == recovery, "Recovery policy was not observed")
          end
          recovery_restored = true
        ensure
          handles.each_value { |handle| LibC.CloseHandle(handle) }
        end
      end
      json({passed: true, scope: "child-write-dac-denial-under-privilege-free-thread-token", principal: principal.bytes.hexstring,
            recovery_restored: recovery_restored, process_capture_complete: process.complete?, privilege_control: "delete-all-observed-privileges",
            deleted_privilege_count: deleted.size, token: token, owner_proofs: proofs, oracles: oracles,
            native_code: provider.not_nil!.native_code, setter_calls: provider.not_nil!.setter_calls, capture_calls: provider.not_nil!.capture_calls,
            public_after_nil: result.not_nil!.after.nil?, mutation: mutation(result.not_nil!),
            target_before: before.not_nil!["parent"], target_after: after.not_nil!["parent"], nodes: nodes, classification: classification})
    end
  {% end %}
end
