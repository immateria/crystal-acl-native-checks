require "./spec_helper"
require "../tools/native_acl_cases"

private def propagation_facts
  # Independent fixture inventory and literal ACE flags: directories inherit
  # OI|CI|INHERITED (0x13); files inherit only INHERITED (0x10).
  layout = [{"open-dir", true, 19}, {"open-file", false, 16},
            {"grand-dir", true, 19}, {"deep-file", false, 16},
            {"protected-dir", true, nil}, {"barrier-file", false, nil},
            {"protected-file", false, nil}, {"direct-file", false, 16},
            {"future-direct", false, 16}, {"future-grand", false, 16},
            {"future-barrier", false, nil}]
  sid = "010100000000000512000000"
  empty = "0200080000000000"
  rows = layout.map_with_index do |(name, directory, flags), index|
    candidate = flags ? "02001c000100000000#{flags.to_s(16).rjust(2, '0')}140001000000010100000000000100000000" : empty
    protected_node = name.in?({"protected-dir", "protected-file"})
    control = protected_node ? "0490" : "0484"
    base = "0100#{control}1400000020000000000000002c000000#{sid}#{sid}"
    before = {complete: true, volume: "10", file_id: index.to_s.rjust(32, '0'),
              directory: directory, descriptor: base + empty}
    after = before.merge({descriptor: base + candidate})
    {name: name, before: name.starts_with?("future-") ? nil : before, after: after}
  end
  JSON.parse({passed: true, scope: "explicit-held-fixtures-not-tree-transaction",
              setter_calls: 1, recovery_restored: true,
              mutation: {state: "Applied", execution: "Succeeded", verification: "Matched",
                         stage: "Verification", descendants: "Unverified", diagnostic: nil},
              target_only_setter_calls: 0,
              target_only: {execution: "NotAttempted", verification: "NotRun"}, nodes: rows}.to_json)
end

private def partial_propagation_facts
  facts = propagation_facts
  nodes = facts["nodes"].as_a
  rows = [
    {name: "updated", before: nodes[7]["before"], after: nodes[7]["after"], after_failed: nodes[7]["after"]},
    {name: "exclusive", before: nodes[1]["before"], after: nodes[1]["before"], after_failed: nodes[1]["before"]},
    {name: "protected", before: nodes[6]["before"], after: nodes[6]["before"], after_failed: nodes[6]["before"]},
  ]
  JSON.parse({passed: true, scope: "share-conflict-mixed-propagation-not-acl-denial",
              recovery_restored: true, exclusive_share: 0, setter_calls: 1,
              mutation: facts["mutation"], nodes: rows,
              failed_setter_calls: 1, failed_capture_calls: 1, failed_public_after_nil: true,
              failed_mutation: {state: "Rejected", execution: "Failed", verification: "NotRun",
                                stage: "Mutation", descendants: "Unverified",
                                diagnostic: {operation: "SetSecurityInfo", code: 5, origin: "ReturnValue"}},
              parent_before_failed: nodes[0]["after"], parent_after_failed: nodes[0]["after"]}.to_json)
end

describe "Windows propagation qualification evidence" do
  it "accepts independently sampled mixed propagation and a failed readable-handle setter" do
    NativeACLRunner.violations("windows.writer-partial", partial_propagation_facts).should be_empty
  end

  it "does not turn a failed setter into proof of no effects or silently replay it" do
    ["failed_setter_calls", "failed_capture_calls"].each do |key|
      facts = partial_propagation_facts
      facts.as_h[key] = JSON::Any.new(2_i64)
      NativeACLRunner.violations("windows.writer-partial", facts).should_not be_empty
    end
    facts = partial_propagation_facts
    facts["failed_mutation"].as_h["execution"] = JSON::Any.new("NotAttempted")
    NativeACLRunner.violations("windows.writer-partial", facts).should_not be_empty
  end

  it "requires observations rather than trusting the workflow completion flag" do
    NativeACLRunner.violations("windows.writer-propagation", JSON.parse(%({"passed":true}))).should_not be_empty
  end

  it "accepts literal multilevel inheritance and protected barriers" do
    NativeACLRunner.violations("windows.writer-propagation", propagation_facts).should be_empty
  end

  it "rejects missing, duplicate and unexpected descendant witnesses" do
    facts = propagation_facts
    facts["nodes"].as_a.pop
    NativeACLRunner.violations("windows.writer-propagation", facts).should_not be_empty
    facts = propagation_facts
    facts["nodes"].as_a[1] = facts["nodes"][0]
    NativeACLRunner.violations("windows.writer-propagation", facts).should_not be_empty
  end

  it "rejects inherited flags lost on a grandchild and identity substitution" do
    facts = propagation_facts
    row = facts["nodes"][3]["after"]
    row.as_h["descriptor"] = JSON::Any.new(row["descriptor"].as_s.sub("00101400", "00001400"))
    NativeACLRunner.violations("windows.writer-propagation", facts).should_not be_empty
    facts = propagation_facts
    facts["nodes"][1]["after"].as_h["file_id"] = JSON::Any.new("ff" * 16)
    NativeACLRunner.violations("windows.writer-propagation", facts).should_not be_empty
  end

  it "rejects a tree-wide verification claim and a replayed setter" do
    facts = propagation_facts
    facts["mutation"].as_h["descendants"] = JSON::Any.new("Verified")
    NativeACLRunner.violations("windows.writer-propagation", facts).should_not be_empty
    facts = propagation_facts
    facts.as_h["setter_calls"] = JSON::Any.new(2_i64)
    NativeACLRunner.violations("windows.writer-propagation", facts).should_not be_empty
  end
end
