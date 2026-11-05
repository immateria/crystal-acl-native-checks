require "./spec_helper"
require "../tools/windows_acl_owner_cases"

private def owner_rights_facts
  # Literal expected grants follow MS-DTYP's OWNER_RIGHTS rule. The owner
  # receives implicit control rights only in the first fixture.
  policies = [
    {"implicit-owner", {true, true, true}},
    {"owner-read-control", {true, false, false}},
    {"owner-write-dac", {false, true, false}},
    {"owner-both", {true, true, true}},
    {"owner-deny-both", {false, false, false}},
  ]
  requests = {0x20000, 0x40000, 0x60000}
  rows = [] of JSON::Any
  policies.each do |policy, grants|
    requests.each_with_index do |request, index|
      allowed = grants[index]
      denial = allowed ? nil : {operation: "AccessCheck", code: 5, origin: "LastError"}
      rows << JSON.parse({policy: policy, request: request, expected: allowed,
                          descriptor_complete: true, owner_matches_process_user: true,
                          replacement_verified: true,
                          token: {capture_complete: true, source: "Thread", type: "Impersonation",
                                  level: "Impersonation", matches_process_user: true,
                                  privilege_count: 0, enabled_privilege_count: 0, restored: true},
                          check: {api_success: true, decision: allowed ? "Allowed" : "Denied",
                                  requested: request, mapped: request, granted_mask: allowed ? request : 0,
                                  native_error: denial, diagnostic: denial},
                          actual: {acquired: allowed, requested_access: request, open_code: allowed ? 0 : 5}}.to_json)
    end
  end
  JSON.parse({passed: true, owner_rights_sid: "S-1-3-4", recovery_access: 0xe0080,
              recovery_restored: true, data_io_performed: false,
              oracle: "fresh-CreateFileW-security-rights-under-explicit-thread-token",
              privilege_control: "CreateRestrictedToken-delete-all-observed-privileges-then-DuplicateToken",
              deleted_privilege_count: 3, process_capture_complete: true,
              owner_proof: {setter_code: 0, capture_complete: true, matches_process_user: true},
              rows: rows}.to_json)
end

describe "Windows OWNER_RIGHTS qualification evidence" do
  it "accepts native access-denied evidence without erasing diagnostic provenance" do
    # Literal row from Windows runner 41975341742. The API call succeeded;
    # AccessStatus denied the request and preserved ERROR_ACCESS_DENIED.
    denied = JSON.parse(%({"policy":"owner-read-control","request":262144,"expected":false,"descriptor_complete":true,"owner_matches_process_user":true,"replacement_verified":true,"token":{"capture_complete":true,"source":"Thread","type":"Impersonation","level":"Impersonation","matches_process_user":true,"privilege_count":0,"enabled_privilege_count":0,"restored":true},"check":{"api_success":true,"decision":"Denied","requested":262144,"mapped":262144,"granted_mask":0,"native_error":{"operation":"AccessCheck","code":5,"origin":"LastError"},"diagnostic":{"operation":"AccessCheck","code":5,"origin":"LastError"}},"actual":{"acquired":false,"requested_access":262144,"open_code":5}}))
    facts = owner_rights_facts
    facts["rows"].as_a[4] = denied
    WindowsACLWorkflows.owner_rights_violations(facts).should be_empty
  end

  it "requires AccessCheck access-denied provenance in both denied-result diagnostics" do
    ["native_error", "diagnostic"].each do |field|
      facts = owner_rights_facts
      facts["rows"].as_a[4]["check"].as_h[field] = JSON::Any.new(nil)
      WindowsACLWorkflows.owner_rights_violations(facts).should_not be_empty
      {"operation" => JSON::Any.new("CreateFileW"),
       "code"      => JSON::Any.new(1309_i64),
       "origin"    => JSON::Any.new("ReturnValue")}.each do |key, value|
        facts = owner_rights_facts
        facts["rows"].as_a[4]["check"][field].as_h[key] = value
        WindowsACLWorkflows.owner_rights_violations(facts).should_not be_empty
      end
    end
  end

  it "requires all fifteen owner controls instead of trusting a passed flag" do
    WindowsACLWorkflows.owner_rights_violations(owner_rights_facts).should be_empty
    WindowsACLWorkflows.owner_rights_violations(JSON.parse(%({"passed":true}))).should_not be_empty
    facts = owner_rights_facts
    facts.as_h["rows"] = JSON.parse("[]")
    WindowsACLWorkflows.owner_rights_violations(facts).should_not be_empty
  end

  it "rejects missing, duplicate and unrecognized policy/request rows" do
    facts = owner_rights_facts
    facts["rows"].as_a.pop
    WindowsACLWorkflows.owner_rights_violations(facts).should_not be_empty
    facts = owner_rights_facts
    facts["rows"].as_a[14] = facts["rows"].as_a[0]
    WindowsACLWorkflows.owner_rights_violations(facts).should_not be_empty
    facts = owner_rights_facts
    facts["rows"].as_a[0].as_h["request"] = JSON::Any.new(1_i64)
    WindowsACLWorkflows.owner_rights_violations(facts).should_not be_empty
    facts = owner_rights_facts
    facts["rows"].as_a[0].as_h["policy"] = JSON::Any.new("other")
    WindowsACLWorkflows.owner_rights_violations(facts).should_not be_empty
  end

  it "requires explicit owner verification rather than assuming a creator owns the file" do
    ["capture_complete", "matches_process_user"].each do |field|
      facts = owner_rights_facts
      facts["owner_proof"].as_h[field] = JSON::Any.new(false)
      WindowsACLWorkflows.owner_rights_violations(facts).should_not be_empty
    end
    facts = owner_rights_facts
    facts["owner_proof"].as_h["setter_code"] = JSON::Any.new(5_i64)
    WindowsACLWorkflows.owner_rights_violations(facts).should_not be_empty
    facts = owner_rights_facts
    facts["rows"].as_a[0].as_h["owner_matches_process_user"] = JSON::Any.new(false)
    WindowsACLWorkflows.owner_rights_violations(facts).should_not be_empty
  end

  it "requires the selected same-user impersonation token with privileges removed and context restored" do
    {"source" => "Process", "type" => "Primary", "level" => "Identification"}.each do |field, value|
      facts = owner_rights_facts
      facts["rows"].as_a[0]["token"].as_h[field] = JSON::Any.new(value)
      WindowsACLWorkflows.owner_rights_violations(facts).should_not be_empty
    end
    ["capture_complete", "matches_process_user", "restored"].each do |field|
      facts = owner_rights_facts
      facts["rows"].as_a[0]["token"].as_h[field] = JSON::Any.new(false)
      WindowsACLWorkflows.owner_rights_violations(facts).should_not be_empty
    end
    ["privilege_count", "enabled_privilege_count"].each do |field|
      facts = owner_rights_facts
      facts["rows"].as_a[0]["token"].as_h[field] = JSON::Any.new(1_i64)
      WindowsACLWorkflows.owner_rights_violations(facts).should_not be_empty
    end
  end

  it "checks expected grants independently of claimed decisions and acquisitions" do
    facts = owner_rights_facts
    row = facts["rows"].as_a[4] # READ_CONTROL-only policy denies WRITE_DAC.
    row.as_h["expected"] = JSON::Any.new(true)
    row["check"].as_h["decision"] = JSON::Any.new("Allowed")
    row["check"].as_h["granted_mask"] = JSON::Any.new(0x40000_i64)
    row["actual"].as_h["acquired"] = JSON::Any.new(true)
    row["actual"].as_h["open_code"] = JSON::Any.new(0_i64)
    WindowsACLWorkflows.owner_rights_violations(facts).should_not be_empty
  end

  it "requires successful AccessCheck with exact requested and granted masks" do
    ["requested", "mapped", "granted_mask"].each do |field|
      facts = owner_rights_facts
      facts["rows"].as_a[0]["check"].as_h[field] = JSON::Any.new(1_i64)
      WindowsACLWorkflows.owner_rights_violations(facts).should_not be_empty
    end
    facts = owner_rights_facts
    facts["rows"].as_a[0]["check"].as_h["api_success"] = JSON::Any.new(false)
    WindowsACLWorkflows.owner_rights_violations(facts).should_not be_empty
    facts = owner_rights_facts
    facts["rows"].as_a[0]["check"].as_h["decision"] = JSON::Any.new("Indeterminate")
    WindowsACLWorkflows.owner_rights_violations(facts).should_not be_empty
    ["native_error", "diagnostic"].each do |field|
      facts = owner_rights_facts
      facts["rows"].as_a[0]["check"].as_h[field] = JSON.parse(%({"code":1309}))
      WindowsACLWorkflows.owner_rights_violations(facts).should_not be_empty
    end
  end

  it "requires fresh security-right acquisition and access-denied provenance" do
    {"requested_access" => 1_i64, "open_code" => 87_i64}.each do |field, value|
      facts = owner_rights_facts
      facts["rows"].as_a[4]["actual"].as_h[field] = JSON::Any.new(value)
      WindowsACLWorkflows.owner_rights_violations(facts).should_not be_empty
    end
    facts = owner_rights_facts
    facts["rows"].as_a[0]["actual"].as_h["acquired"] = JSON::Any.new(false)
    WindowsACLWorkflows.owner_rights_violations(facts).should_not be_empty
    facts = owner_rights_facts
    facts.as_h["data_io_performed"] = JSON::Any.new(true)
    WindowsACLWorkflows.owner_rights_violations(facts).should_not be_empty
  end

  it "requires complete verified descriptors and a restored recovery policy" do
    ["descriptor_complete", "replacement_verified"].each do |field|
      facts = owner_rights_facts
      facts["rows"].as_a[0].as_h[field] = JSON::Any.new(false)
      WindowsACLWorkflows.owner_rights_violations(facts).should_not be_empty
    end
    facts = owner_rights_facts
    facts.as_h["recovery_access"] = JSON::Any.new(0x60080_i64)
    WindowsACLWorkflows.owner_rights_violations(facts).should_not be_empty
    facts = owner_rights_facts
    facts.as_h["recovery_restored"] = JSON::Any.new(false)
    WindowsACLWorkflows.owner_rights_violations(facts).should_not be_empty
  end

  it "reports malformed fields as evidence failures" do
    ["null", "[]", %({"rows":1}), %({"passed":true,"rows":[null]})].each do |source|
      WindowsACLWorkflows.owner_rights_violations(JSON.parse(source)).should_not be_empty
    end
  end
end
