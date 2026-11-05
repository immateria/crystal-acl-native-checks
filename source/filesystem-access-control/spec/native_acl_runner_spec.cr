{% if flag?(:windows) %}
  # Crystal catches an actual access violation and exits 1. Terminate this
  # disposable child through the native API to qualify exception-status
  # transport separately from Crystal's exception reporting policy.
  if ENV["ACL_RUNNER_EXCEPTION_STATUS_CHILD"]? == "1"
    LibC.TerminateProcess(LibC.GetCurrentProcess, 0xc0000005_u32)
    exit 90
  end
{% end %}

require "./spec_helper"
require "../tools/native_acl_runner_support"
require "../tools/native_acl_cases"

private def writer_authority_facts
  JSON.parse({passed: true, authority: {
    requested_access: 0x40080_u32,
    public_result: {execution: "NotAttempted", verification: "NotRun", stage: "PreCapture",
                    diagnostic: {operation: "GetSecurityInfo", code: 5, origin: "ReturnValue"}},
    public_setter_calls: 0, before_unchanged: true,
    raw_setter_code: 0, raw_setter_calls: 1, raw_dacl_changed: true,
    raw_readback_matches: true, identity_retained: true,
    limited_readback_complete: false,
    limited_readback_diagnostic: {operation: "GetSecurityInfo", code: 5, origin: "ReturnValue"},
  }}.to_json)
end

describe "Native ACL writer authority evidence" do
  it "requires the complementary write-only authority control" do
    NativeACLRunner.violations("windows.writer-files", JSON.parse(%({"passed":true}))).should_not be_empty
    NativeACLRunner.violations("windows.writer-files", writer_authority_facts).should be_empty
  end

  it "rejects mutation attempts before the unreadable pre-capture boundary" do
    facts = writer_authority_facts
    facts["authority"].as_h["public_setter_calls"] = JSON::Any.new(1_i64)
    NativeACLRunner.violations("windows.writer-files", facts).should_not be_empty
    facts = writer_authority_facts
    facts["authority"]["public_result"].as_h["stage"] = JSON::Any.new("Precondition")
    NativeACLRunner.violations("windows.writer-files", facts).should_not be_empty
  end

  it "requires an actual successful native edit and independent matching readback" do
    ["raw_setter_code", "raw_setter_calls"].each do |field|
      facts = writer_authority_facts
      facts["authority"].as_h[field] = JSON::Any.new(2_i64)
      NativeACLRunner.violations("windows.writer-files", facts).should_not be_empty
    end
    ["before_unchanged", "raw_dacl_changed", "raw_readback_matches", "identity_retained"].each do |field|
      facts = writer_authority_facts
      facts["authority"].as_h[field] = JSON::Any.new(false)
      NativeACLRunner.violations("windows.writer-files", facts).should_not be_empty
    end
  end

  it "keeps unsupported verification and native error provenance explicit" do
    facts = writer_authority_facts
    facts["authority"].as_h["limited_readback_complete"] = JSON::Any.new(true)
    NativeACLRunner.violations("windows.writer-files", facts).should_not be_empty
    ["public_result", "limited_readback_diagnostic"].each do |field|
      facts = writer_authority_facts
      diagnostic = field == "public_result" ? facts["authority"][field]["diagnostic"] : facts["authority"][field]
      diagnostic.as_h["origin"] = JSON::Any.new("LastError")
      NativeACLRunner.violations("windows.writer-files", facts).should_not be_empty
    end
  end
end

describe "Native ACL runner completion evidence" do
  it "requires one matching complete observation and an agreeing exit status" do
    row = %({"schema":"filesystem-native-acl-observation","version":1,"case_id":"darwin.held-unlink","harness_status":"complete","expectations_met":true,"violations":[],"observation":{}})
    NativeACLRunner::Harness.classify("darwin.held-unlink", row + "\n", 0).should eq("matched")
    NativeACLRunner::Harness.classify("darwin.held-unlink", row + "\n", 1).should eq("exit-mismatch")
    NativeACLRunner::Harness.classify("darwin.hardlink-alias", row, 0).should eq("incomplete")
    NativeACLRunner::Harness.classify("darwin.held-unlink", row + "\n" + row, 0).should eq("malformed")
    NativeACLRunner::Harness.classify("darwin.held-unlink", "", 0).should eq("incomplete")
    NativeACLRunner::Harness.classify("darwin.held-unlink", "{", 0).should eq("malformed")
    NativeACLRunner::Harness.classify("darwin.held-unlink", row.sub("\"violations\":[]", "\"violations\":[\"different ACL\"]"), 0).should eq("malformed")
    NativeACLRunner::Harness.classify("darwin.held-unlink", row.sub("\"version\":1", "\"version\":2"), 0).should eq("incomplete")
  end

  it "retains timeout, crash and output-limit outcomes above ACL results" do
    NativeACLRunner::Harness.classify("darwin.held-unlink", "", nil, timed_out: true).should eq("timeout")
    NativeACLRunner::Harness.classify("darwin.held-unlink", "", nil, crashed: true).should eq("crash")
    NativeACLRunner::Harness.classify("darwin.held-unlink", "", nil, output_limited: true).should eq("output-limit")
    SpecEnvironment.with_temp_dir("acl-runner-deadline") do |folder|
      command = {% if flag?(:windows) %}
                  ["ping.exe", "-n", "6", "127.0.0.1"]
                {% else %}
                  ["/bin/sleep", "5"]
                {% end %}
      result = NativeACLRunner::Harness.execute(command, Path[folder] / "sleep", 50.milliseconds)
      result.timed_out.should be_true
      result.exit_code.should be_nil
      result.duration_ms.should be < 2000
    end
  end

  it "recognizes explicit Windows exception statuses without treating ordinary failed exits as crashes" do
    [0xc0000005_u32, 0xc000001d_u32, 0xc0000094_u32,
     0xc00000fd_u32, 0xc0000374_u32, 0xc0000409_u32].each do |status|
      NativeACLRunner::Harness.classify("fixture", "", status.to_i32!, windows: true).should eq("crash")
    end
    NativeACLRunner::Harness.classify("fixture", "", 7, windows: true).should eq("incomplete")
    NativeACLRunner::Harness.classify("fixture", "", 1, windows: true).should eq("incomplete")
    NativeACLRunner::Harness.classify("fixture", "", 0xc0000135_u32.to_i32!, windows: true).should eq("incomplete")
    NativeACLRunner::Harness.classify("fixture", "", 0xc0000005_u32.to_i32!, windows: false).should eq("incomplete")
  end

  it "preserves Windows status bits which optional normal-exit helpers discard" do
    [0_u32, 1_u32, 7_u32, 0x3fffffff_u32, 0x40000000_u32,
     0x80000000_u32, 0xc0000005_u32, 0xffffffff_u32].each do |raw|
      status = Process::Status.new(system_exit_status: {% if flag?(:windows) %}raw{% else %}raw.to_i32!{% end %})
      NativeACLRunner::Harness.reported_exit_code(status, windows: true).should eq(raw.to_i32!)
    end
    NativeACLRunner::Harness.reported_exit_code(Process::Status[7], windows: false).should eq(7)
    {% unless flag?(:windows) %}
      NativeACLRunner::Harness.reported_exit_code(Process::Status[Signal::KILL], windows: false).should be_nil
    {% end %}
  end

  {% if flag?(:windows) %}
    it "retains an explicit native exception-status termination from a disposable child" do
      SpecEnvironment.with_temp_dir("acl-runner-native-crash") do |folder|
        result = NativeACLRunner::Harness.execute([Process.executable_path.not_nil!], Path[folder] / "crash", 5.seconds,
          env: {"ACL_RUNNER_EXCEPTION_STATUS_CHILD" => "1"})
        result.timed_out.should be_false
        stderr = File.exists?(result.stderr_path) ? File.read(result.stderr_path)[0, 2048] : "<not captured>"
        result.exit_code.should eq(0xc0000005_u32.to_i32!),
          "Native status fixture returned #{result.exit_code}; harness error=#{result.error}; stderr=#{stderr}"
        result.system_exit_status.should eq(0xc0000005_u32)
        NativeACLRunner::Harness.classify("fixture", File.read(result.stdout_path), result.exit_code,
          windows: true).should eq("crash")
      end
    end
  {% end %}

  it "retains bounded stdout and stderr separately from a failed helper exit" do
    SpecEnvironment.with_temp_dir("acl-runner-output") do |folder|
      command = {% if flag?(:windows) %}
                  ["cmd.exe", "/d", "/c", "echo observation & echo diagnostic 1>&2 & exit /b 7"]
                {% else %}
                  ["/bin/sh", "-c", "printf observation; printf diagnostic >&2; exit 7"]
                {% end %}
      result = NativeACLRunner::Harness.execute(command, Path[folder] / "failed", 5.seconds)
      result.exit_code.should eq(7)
      result.error.should be_nil
      File.read(result.stdout_path).strip.should eq("observation")
      File.read(result.stderr_path).strip.should eq("diagnostic")
      result.timed_out.should be_false
      result.output_limited.should be_false
    end
  end

  it "stops an oversized helper without retaining more than its output budget" do
    SpecEnvironment.with_temp_dir("acl-runner-limit") do |folder|
      payload = Path[folder] / "payload"
      File.write(payload, "x" * 4096)
      command = {% if flag?(:windows) %}
                  ["cmd.exe", "/d", "/c", "type", payload.to_s]
                {% else %}
                  ["/bin/cat", payload.to_s]
                {% end %}
      result = NativeACLRunner::Harness.execute(command, Path[folder] / "limited", 5.seconds, maximum_output: 128)
      result.output_limited.should be_true
      result.exit_code.should be_nil
      File.size(result.stdout_path).should eq(128)
      result.duration_ms.should be < 2000
    end
  end

  {% unless flag?(:windows) %}
    it "records a signalled child as a harness crash" do
      SpecEnvironment.with_temp_dir("acl-runner-crash") do |folder|
        result = NativeACLRunner::Harness.execute(["/bin/sh", "-c", "kill -KILL $$"], Path[folder] / "crash", 5.seconds)
        result.signal.should_not be_nil
        result.exit_code.should be_nil
        NativeACLRunner::Harness.classify("fixture", File.read(result.stdout_path), result.exit_code,
          crashed: !result.signal.nil?).should eq("crash")
      end
    end
  {% end %}
end
