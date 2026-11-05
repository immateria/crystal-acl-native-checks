require "json"
require "set"
require "./windows_acl_workflow_cases"

module WindowsACLWorkflows
  # OWNER_RIGHTS suppresses the owner's implicit READ_CONTROL and WRITE_DAC.
  # These are literal MS-DTYP expectations, independent of reported decisions.
  # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab
  def self.owner_rights_violations(facts : JSON::Any) : Array(String)
    errors = [] of String
    return ["Owner-rights evidence is missing or malformed"] unless facts.as_h?
    errors << "Owner-rights experiment did not complete" unless facts["passed"].as_bool
    errors << "Wrong OWNER_RIGHTS SID" unless facts["owner_rights_sid"].as_s == "S-1-3-4"
    errors << "Recovery handle lacks the required initial authority" unless facts["recovery_access"].as_i64 == 0xe0080
    errors << "Recovery policy was not restored" unless facts["recovery_restored"].as_bool
    errors << "Owner-rights oracle must not claim data I/O" if facts["data_io_performed"].as_bool
    errors << "Wrong owner-rights acquisition oracle" unless facts["oracle"].as_s == "fresh-CreateFileW-security-rights-under-explicit-thread-token"
    errors << "Token privileges were not explicitly removed" unless facts["privilege_control"].as_s == "CreateRestrictedToken-delete-all-observed-privileges-then-DuplicateToken"
    errors << "Invalid deleted privilege count" unless facts["deleted_privilege_count"].as_i64 >= 0
    errors << "Process token identity/privileges were not captured" unless facts["process_capture_complete"].as_bool
    owner = facts["owner_proof"].as_h
    unless owner["setter_code"].as_i64 == 0 && owner["capture_complete"].as_bool && owner["matches_process_user"].as_bool
      errors << "Explicit owner assignment and matching captured owner are required"
    end

    expectations = {
      "implicit-owner"     => {true, true, true},
      "owner-read-control" => {true, false, false},
      "owner-write-dac"    => {false, true, false},
      "owner-both"         => {true, true, true},
      "owner-deny-both"    => {false, false, false},
    }
    requests = {0x20000_i64, 0x40000_i64, 0x60000_i64}
    rows = facts["rows"].as_a
    errors << "All fifteen owner-rights policy/request controls are required" unless rows.size == 15
    seen = Set(Tuple(String, Int64)).new
    rows.each do |evidence|
      row = evidence.as_h
      policy, request = row["policy"].as_s, row["request"].as_i64
      key = {policy, request}
      errors << "Duplicate owner-rights control #{policy}/#{request}" unless seen.add?(key)
      grants, index = expectations[policy]?, requests.index(request)
      unless grants && index
        errors << "Unknown owner-rights policy/request #{policy}/#{request}"
        next
      end
      expected = grants[index]
      errors << "Incorrect expected grant for #{key}" unless row["expected"].as_bool == expected
      unless row["descriptor_complete"].as_bool && row["owner_matches_process_user"].as_bool && row["replacement_verified"].as_bool
        errors << "Unverified owner or policy for #{key}"
      end
      token = row["token"].as_h
      unless token["capture_complete"].as_bool && token["source"].as_s == "Thread" &&
             token["type"].as_s == "Impersonation" && token["level"].as_s == "Impersonation" &&
             token["matches_process_user"].as_bool && token["privilege_count"].as_i64 == 0 &&
             token["enabled_privilege_count"].as_i64 == 0 && token["restored"].as_bool
        errors << "Unqualified effective-token context for #{key}"
      end
      check = row["check"].as_h
      diagnostics_match = if expected
                            check["native_error"].raw.nil? && check["diagnostic"].raw.nil?
                          else
                            # A successful AccessCheck can deny AccessStatus.
                            # Preserve the provider's immediate denial error in
                            # both fields rather than requiring its erasure.
                            {"native_error", "diagnostic"}.all? do |field|
                              diagnostic = check[field].as_h
                              diagnostic["operation"].as_s == "AccessCheck" &&
                                diagnostic["code"].as_i64 == 5 && diagnostic["origin"].as_s == "LastError"
                            end
                          end
      unless check["api_success"].as_bool && check["decision"].as_s == (expected ? "Allowed" : "Denied") &&
             check["requested"].as_i64 == request && check["mapped"].as_i64 == request &&
             check["granted_mask"].as_i64 == (expected ? request : 0) && diagnostics_match
        errors << "AccessCheck result disagrees with owner-rights control #{key}"
      end
      actual = row["actual"].as_h
      unless actual["acquired"].as_bool == expected && actual["requested_access"].as_i64 == request &&
             actual["open_code"].as_i64 == (expected ? 0 : 5)
        errors << "Fresh security-right acquisition disagrees with #{key}"
      end
    end
    expectations.each_key do |policy|
      requests.each do |request|
        errors << "Missing owner-rights control #{policy}/#{request}" unless seen.includes?({policy, request})
      end
    end
    errors
  rescue KeyError | TypeCastError | IndexError
    ["Owner-rights evidence is missing or malformed"]
  end

  {% if flag?(:windows) %}
    lib ProbeNative
      # Native LUID_AND_ATTRIBUTES has DWORD alignment and a 12-byte stride.
      struct OwnerPrivilegeAndAttributes
        low : UInt32
        high : Int32
        attributes : UInt32
      end
    end

    private def self.owner_security_open(name : Slice(UInt16), requested : UInt32)
      # This acquires a NEW handle under the selected thread token. It requests
      # only security rights, performs no data I/O, and supplies no backup flag.
      handle = LibC.CreateFileW(name.to_unsafe, requested, 7_u32,
        Pointer(LibC::SECURITY_ATTRIBUTES).null, 3_u32, 0x40200000_u32, Pointer(Void).null)
      if handle.address == UInt64::MAX
        code = LibC.GetLastError
        {acquired: false, requested_access: requested, open_code: code}
      else
        LibC.CloseHandle(handle)
        {acquired: true, requested_access: requested, open_code: 0_u32}
      end
    end

    def self.owner_rights(root : Path) : JSON::Any
      process = WinACL::TokenReader.capture_subject(WinACL::TokenContext::Process,
        information: WinACL::TokenSubjectInformation::Privileges)
      ensure!(process.complete?, "Process identity/privileges unavailable for owner controls")
      principal = process.token.identity.not_nil!.user
      initial = WinACL::TokenReader.capture(WinACL::TokenContext::Effective)
      ensure!(initial.complete? && initial.source.try(&.process?) == true,
        "Owner-rights helper requires an initially unimpersonated disposable process")
      privileges = process.privileges.value.not_nil!.entries
      deleted = privileges.map do |privilege|
        item = ProbeNative::OwnerPrivilegeAndAttributes.new
        item.low, item.high, item.attributes = privilege.luid_low, privilege.luid_high, 0_u32
        item
      end
      path = root / "owner-rights"
      File.write(path, "fixture")
      units = path.to_s.to_utf16
      name = Slice(UInt16).new(units.size + 1, 0_u16)
      units.copy_to(name)
      owner_rights_sid = WinACL::SID.new("010100000000000304000000".hexbytes)
      recovery = acl([{0_u8, 0_u8, 0x1f01ff_u32, principal}])
      rows = [] of JSON::Any
      owner_proof = JSON.parse("null")
      recovery_restored = false
      # READ_CONTROL | WRITE_DAC | WRITE_OWNER | FILE_READ_ATTRIBUTES are held
      # before any restrictive policy. The owner's default SID is not assumed.
      with_handle(path, 0xe0080_u32) do |held|
        begin
          prepare(held, recovery)
          owner_bytes = principal.bytes
          owner_code = Filesystem::AccessControl::Native::Windows::ACL.acl_set_security_info(held,
            1_u32, 1_u32, owner_bytes.to_unsafe.as(Void*), Pointer(Void).null,
            Pointer(Void).null, Pointer(Void).null)
          ensure!(owner_code == 0, "Explicit fixture owner assignment failed: #{owner_code}")
          owned = WinACL::HandleReader.capture(held)
          ensure!(owned.complete? && owned.security.owner == principal, "Explicit fixture owner was not observed")
          owner_proof = json({setter_code: owner_code, capture_complete: owned.complete?,
                              matches_process_user: owned.security.owner == principal})
          with_process_token do |primary|
            restricted = Pointer(Void).null
            deleted_pointer = deleted.empty? ? Pointer(Void).null : deleted.to_unsafe.as(Void*)
            # Delete every observed privilege, including traversal bypass. No
            # privilege is enabled and neither user nor group SIDs are removed.
            if ProbeNative.restricted_token(primary, 0_u32, 0_u32,
                 Pointer(ProbeNative::SIDAndAttributes).null, deleted.size.to_u32, deleted_pointer,
                 0_u32, Pointer(ProbeNative::SIDAndAttributes).null, pointerof(restricted)) == 0
              raise "CreateRestrictedToken(delete privileges) failed: #{LibC.GetLastError}"
            end
            begin
              with_impersonation(restricted) do |subject|
                base = {0_u8, 0_u8, 0x100080_u32, principal}
                policies = [
                  {"implicit-owner", acl([base]), {true, true, true}},
                  {"owner-read-control", acl([{0_u8, 0_u8, 0x20000_u32, owner_rights_sid}, base]), {true, false, false}},
                  {"owner-write-dac", acl([{0_u8, 0_u8, 0x40000_u32, owner_rights_sid}, base]), {false, true, false}},
                  {"owner-both", acl([{0_u8, 0_u8, 0x60000_u32, owner_rights_sid}, base]), {true, true, true}},
                  {"owner-deny-both", acl([{1_u8, 0_u8, 0x60000_u32, owner_rights_sid}, base]), {false, false, false}},
                ]
                policies.each do |policy, value, expected|
                  result = replace(held, value)
                  ensure!(result.verified?, "Owner-rights fixture replacement failed: #{result.diagnostic}")
                  after = result.after.not_nil!
                  ensure!(after.complete? && after.security.owner == principal, "Policy capture lost verified owner")
                  {0x20000_u32, 0x40000_u32, 0x60000_u32}.each_with_index do |request, index|
                    check = WinACL::Evaluator.check(after.security, subject: subject,
                      permissions: WinACL::Rights.new(request), kind: Filesystem::AccessControl::Target::File)
                    if ProbeNative.set_thread_token(Pointer(Void*).null, subject) == 0
                      raise "SetThreadToken(owner controls) failed: #{LibC.GetLastError}"
                    end
                    begin
                      observed = WinACL::TokenReader.capture_subject(WinACL::TokenContext::Effective,
                        information: WinACL::TokenSubjectInformation::Privileges)
                      actual = owner_security_open(name, request)
                    ensure
                      abort "RevertToSelf failed: #{LibC.GetLastError}" if ProbeNative.revert == 0
                    end
                    # Assertions and serialization follow restoration. A failed
                    # helper must never leak its impersonation to later work.
                    restored = WinACL::TokenReader.capture(WinACL::TokenContext::Effective)
                    identity = observed.token.identity
                    selected_privileges = observed.privileges.value
                    token = {
                      capture_complete: observed.complete?, source: observed.token.source.try(&.to_s),
                      type: identity.try(&.type.to_s), level: identity.try(&.impersonation_level.try(&.to_s)),
                      matches_process_user: identity.try(&.user) == principal,
                      privilege_count: selected_privileges.try(&.entries.size),
                      enabled_privilege_count: selected_privileges.try { |items| items.entries.count(&.enabled?) },
                      restored: restored.complete? && restored.source.try(&.process?) == true && restored.identity.try(&.user) == principal,
                    }
                    row = json({policy: policy, request: request, expected: expected[index],
                                descriptor_complete: after.complete?, owner_matches_process_user: after.security.owner == principal,
                                replacement_verified: result.verified?, token: token,
                                check: {api_success: check.api_success, decision: check.decision.to_s,
                                        requested: check.requested.value, mapped: check.mapped.value,
                                        granted_mask: check.granted_mask,
                                        native_error: check.native_error.try { |d| {operation: d.operation, code: d.code, origin: d.origin.to_s} },
                                        diagnostic: check.diagnostic.try { |d| {operation: d.operation, code: d.code, origin: d.origin.to_s} }},
                                actual: actual})
                    rows << row
                    STDERR.puts("acl-owner-rights-observation #{row.to_json}")
                    STDERR.flush
                  end
                end
              end
            ensure
              LibC.CloseHandle(restricted)
            end
          end
        ensure
          prepare(held, recovery)
          restored_policy = WinACL::HandleReader.capture(held)
          recovery_restored = restored_policy.complete? && restored_policy.security.dacl == recovery && restored_policy.security.owner == principal
        end
      end
      facts = json({passed: true, owner_rights_sid: "S-1-3-4", recovery_access: 0xe0080_u32,
                    recovery_restored: recovery_restored, data_io_performed: false,
                    oracle: "fresh-CreateFileW-security-rights-under-explicit-thread-token",
                    privilege_control: "CreateRestrictedToken-delete-all-observed-privileges-then-DuplicateToken",
                    deleted_privilege_count: deleted.size, process_capture_complete: process.complete?,
                    owner_proof: owner_proof, rows: rows})
      errors = owner_rights_violations(facts)
      ensure!(errors.empty?, errors.join("; "))
      facts
    end
  {% end %}
end
