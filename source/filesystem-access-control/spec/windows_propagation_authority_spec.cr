require "./spec_helper"
require "../tools/native_acl_cases"

private def authority_facts(*, code = 5, effects = true)
  # Literal native layouts, independent of the experiment's ACL constructor.
  sid = "010100000000000512000000"
  everyone = "010100000000000100000000"
  owner_rights = "010100000000000304000000"
  full = "00001400ff011f00#{sid}"
  inherited_full = "00101400ff011f00#{sid}"
  inherited_candidate = "0010140001000000#{everyone}"
  recovery = "02001c0001000000#{full}"
  desired = "020030000200000000031400ff011f00#{sid}0003140001000000#{everyone}"
  denied = "02003000020000000100140000000400#{owner_rights}00001400ff011b00#{sid}"
  inherited = "0200440003000000#{full}#{inherited_full}#{inherited_candidate}"
  denied_after = "0200580004000000" + denied[16..] + inherited_full + inherited_candidate
  directory_after = denied_after.sub("00101400ff011f00", "00131400ff011f00").sub("0010140001000000", "0013140001000000")
  snapshot = ->(id : Int32, directory : Bool, protected_acl : Bool, acl : String) do
    control = protected_acl ? "0494" : "0484"
    {complete: true, volume: "10", file_id: id.to_s.rjust(32, '0'), directory: directory,
     descriptor: "0100#{control}1400000020000000000000002c000000#{sid}#{sid}#{acl}"}
  end
  before = snapshot.call(0, true, true, recovery)
  after = snapshot.call(0, true, true, effects ? desired : recovery)
  rows = [{"allowed", false, false, recovery, inherited},
          {"denied-file", false, false, denied, denied_after},
          {"denied-dir", true, false, denied, directory_after},
          {"denied-grandchild", false, false, recovery, inherited},
          {"protected", false, true, recovery, recovery}].map_with_index do |(name, directory, protected_acl, prior, later), i|
    {name: name, before: snapshot.call(i + 1, directory, protected_acl, prior),
     after: snapshot.call(i + 1, directory, protected_acl, effects ? later : prior)}
  end
  oracles = [{"parent", 0x40000, true}, {"allowed", 0x40000, true},
             {"denied-file", 0x20000, true}, {"denied-file", 0x40000, false},
             {"denied-dir", 0x20000, true}, {"denied-dir", 0x40000, false}].map do |name, access, granted|
    {name: name, requested_access: access, acquired: granted, code: granted ? 0 : 5}
  end
  phased_oracles = ["before", "after"].flat_map { |phase| oracles.map { |row| row.merge({phase: phase}) } }
  success = code == 0
  JSON.parse({passed: true, scope: "child-write-dac-denial-under-privilege-free-thread-token",
              principal: sid, recovery_restored: true, process_capture_complete: true,
              privilege_control: "delete-all-observed-privileges", deleted_privilege_count: 3,
              token: {capture_complete: true, source: "Thread", type: "Impersonation", level: "Impersonation",
                      matches_process_user: true, privilege_count: 0, enabled_privilege_count: 0, restored: true},
              owner_proofs: ["denied-file", "denied-dir"].map { |name| {name: name, setter_code: 0, capture_complete: true, matches_process_user: true} },
              oracles: phased_oracles, native_code: code, setter_calls: 1, capture_calls: success ? 2 : 1,
              public_after_nil: !success,
              mutation: {state: success ? "Applied" : "Rejected", execution: success ? "Succeeded" : "Failed",
                         verification: success ? "Matched" : "NotRun", stage: success ? "Verification" : "Mutation",
                         descendants: "Unverified", diagnostic: success ? nil : {operation: "SetSecurityInfo", code: code, origin: "ReturnValue"}},
              target_before: before, target_after: after, nodes: rows,
              classification: success ? "SucceededAllSampled" : effects ? "FailedWithObservedEffects" : "FailedWithoutObservedEffects"}.to_json)
end

describe "Windows propagation under child ACL-authority denial" do
  it "retains native failure with observed target effects as distinct evidence" do
    NativeACLRunner.violations("windows.writer-authority", authority_facts).should be_empty
  end

  it "allows inheritance updates despite denied fresh child WRITE_DAC acquisition" do
    NativeACLRunner.violations("windows.writer-authority", authority_facts(code: 0)).should be_empty
  end

  it "does not manufacture effects from a failed call or trust a passed flag" do
    facts = authority_facts(effects: false)
    NativeACLRunner.violations("windows.writer-authority", facts).should be_empty
    facts.as_h["classification"] = JSON::Any.new("FailedWithObservedEffects")
    NativeACLRunner.violations("windows.writer-authority", facts).should_not be_empty
    NativeACLRunner.violations("windows.writer-authority", JSON.parse(%({"passed":true}))).should_not be_empty
  end

  it "requires privilege removal, explicit owners and the selected thread context" do
    facts = authority_facts
    facts["token"].as_h["privilege_count"] = JSON::Any.new(1_i64)
    NativeACLRunner.violations("windows.writer-authority", facts).should_not be_empty
    facts = authority_facts
    facts["owner_proofs"].as_a.pop
    NativeACLRunner.violations("windows.writer-authority", facts).should_not be_empty
  end

  it "requires all fresh authority oracles rather than inferring denial from readback" do
    facts = authority_facts
    facts["oracles"].as_a[3].as_h["acquired"] = JSON::Any.new(true)
    NativeACLRunner.violations("windows.writer-authority", facts).should_not be_empty
    facts = authority_facts
    facts["oracles"].as_a[2] = facts["oracles"][0]
    NativeACLRunner.violations("windows.writer-authority", facts).should_not be_empty
  end

  it "rejects replay, pre-mutation refusal and missing independent descendant samples" do
    facts = authority_facts
    facts.as_h["setter_calls"] = JSON::Any.new(2_i64)
    NativeACLRunner.violations("windows.writer-authority", facts).should_not be_empty
    facts = authority_facts
    facts["mutation"].as_h["execution"] = JSON::Any.new("NotAttempted")
    NativeACLRunner.violations("windows.writer-authority", facts).should_not be_empty
    facts = authority_facts
    facts["nodes"].as_a.pop
    NativeACLRunner.violations("windows.writer-authority", facts).should_not be_empty
  end
end
