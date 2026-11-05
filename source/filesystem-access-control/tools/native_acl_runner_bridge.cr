# Build out of tree. Invoke --manifest to enumerate versioned cases, then
# execute each --case ID in a fresh process with the manifest's deadline.
# A killed helper, crash, malformed JSON or missing final line is a harness
# failure with uncertain side effects, never a fabricated ACL result.
require "./native_acl_cases"

if ARGV == ["--manifest"]
  puts({schema: "filesystem-native-acl-cases", version: NativeACLRunner::MANIFEST_VERSION,
        isolation: "fresh-exec-per-case", completion: "one-complete-jsonl-observation",
        timeout_or_crash: "harness-failure-with-unknown-side-effects",
        comparison: "NativeACLRunner.violations; public mutation results remain separate",
        cases: NativeACLRunner::CASES}.to_json)
elsif ARGV.size == 2 && ARGV[0] == "--case"
  id = ARGV[1]
  begin
    facts = NativeACLRunner.run_case(id)
    violations = NativeACLRunner.violations(id, facts)
    puts({schema: "filesystem-native-acl-observation", version: NativeACLRunner::MANIFEST_VERSION,
          case_id: id, harness_status: "complete", expectations_met: violations.empty?,
          violations: violations, environment: {platform: NativeACLRunner.platform,
                                                crystal: Crystal::VERSION, pid: Process.pid},
          observation: facts}.to_json)
    exit(violations.empty? ? 0 : 1)
  rescue error : NativeACLRunner::NativeCaseFailure
    puts({schema: "filesystem-native-acl-observation", version: NativeACLRunner::MANIFEST_VERSION,
          case_id: id, harness_status: "native-error", expectations_met: false,
          environment: {platform: NativeACLRunner.platform, crystal: Crystal::VERSION, pid: Process.pid},
          error: {operation: error.operation, code: error.code, origin: "native-operation"},
          partial_observation: error.facts}.to_json)
    exit 1
  rescue error
    puts({schema: "filesystem-native-acl-observation", version: NativeACLRunner::MANIFEST_VERSION,
          case_id: id, harness_status: "error", expectations_met: false,
          environment: {platform: NativeACLRunner.platform, crystal: Crystal::VERSION, pid: Process.pid},
          error: {type: error.class.name, message: error.message}}.to_json)
    exit 1
  end
else
  STDERR.puts "Usage: native_acl_runner_bridge --manifest | --case ID"
  exit 2
end
