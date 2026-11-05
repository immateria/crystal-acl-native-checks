# Native product comparison runner. Build and receipts stay outside source.
require "option_parser"
require "digest/sha256"
require "./native_acl_cases"
require "./native_acl_runner_support"

module NativeACLRunner
  module Runner
    SOURCE = Path[__DIR__].parent.expand

    def self.canonical_new_path(path : Path) : Path
      expanded = path.expand
      ancestor = expanded
      suffix = [] of String
      until File.exists?(ancestor) || File.symlink?(ancestor)
        suffix.unshift(ancestor.basename)
        parent = ancestor.parent
        raise ArgumentError.new("No existing output ancestor") if parent == ancestor
        ancestor = parent
      end
      suffix.reduce(Path[File.realpath(ancestor)]) { |parent, name| parent / name }
    end

    def self.output_path(value : String) : Path
      output = canonical_new_path(Path[value])
      current = Path[File.realpath(SOURCE)]
      loop do
        if File.exists?(current / ".git") || Dir.exists?(current / ".git")
          if output == current || output.to_s.starts_with?(current.to_s + File::SEPARATOR)
            raise ArgumentError.new("Output must be outside source repositories: #{output}")
          end
        end
        parent = current.parent
        break if parent == current
        current = parent
      end
      raise ArgumentError.new("Output directory must not exist") if File.exists?(output) || File.symlink?(output)
      output
    end

    def self.source_hashes : Hash(String, String)
      files = [] of String
      [SOURCE / "src", SOURCE / "tools", SOURCE / "spec",
       SOURCE.parent / "filesystem-capabilities" / "src"].each do |directory|
        Dir.glob((directory / "**" / "*").to_posix.to_s).each do |path|
          files << path if File.file?(path) && (path.ends_with?(".cr") || path.ends_with?(".c"))
        end
      end
      files.sort.to_h { |path| {File.realpath(path), Digest::SHA256.hexdigest(File.read(path))} }
    end

    def self.run(output : Path, selected : Array(String), compiler : String, binary : String?) : Bool
      Dir.mkdir_p(output.parent)
      Dir.mkdir(output)
      puts "native-acl-run receipts=#{output}"
      before = source_hashes
      File.write(output / "source-before.json", before.to_pretty_json)
      host_commands = {% if flag?(:windows) %}
                        {"os" => ["cmd.exe", "/d", "/c", "ver"], "identity" => ["whoami.exe", "/user"]}
                      {% elsif flag?(:darwin) %}
                        {"os" => ["/usr/bin/sw_vers"], "kernel" => ["/usr/bin/uname", "-a"], "identity" => ["/usr/bin/id"]}
                      {% else %}
                        {"kernel" => ["/usr/bin/uname", "-a"], "identity" => ["/usr/bin/id"]}
                      {% end %}
      host = host_commands.to_h do |label, command|
        {label, Harness.execute(command, output / "host-#{label}", 10.seconds)}
      end
      File.write(output / "host.json", host.to_pretty_json)
      version = Harness.execute([compiler, "--version"], output / "compiler-version", 10.seconds)
      unless version.exit_code == 0 && !version.timed_out && !version.output_limited
        raise "Compiler version query failed; see compiler-version logs"
      end
      stdlib = Harness.execute([compiler, "env", "CRYSTAL_PATH"], output / "compiler-stdlib", 10.seconds)
      raise "Compiler standard-library query failed" unless stdlib.exit_code == 0
      bridge = binary.try { |path| File.realpath(path) }
      unless bridge
        bridge = (output / {% if flag?(:windows) %} "native-acl-bridge.exe" {% else %} "native-acl-bridge" {% end %}).to_s
        env = {
          "CRYSTAL_CACHE_DIR" => (output / "compiler-cache").to_s,
          "CRYSTAL_PATH"      => (SOURCE.parent / "filesystem-capabilities" / "src").to_s +
                            Process::PATH_DELIMITER + File.read(stdlib.stdout_path).strip,
        }
        built = Harness.execute([compiler, "build", "--error-trace", (SOURCE / "tools" / "native_acl_runner_bridge.cr").to_s,
                                 "-o", bridge], output / "build", 180.seconds, env: env, chdir: SOURCE.to_s)
        File.write(output / "build.json", built.to_pretty_json)
        raise "Bridge build failed; see build logs" unless built.exit_code == 0 && !built.timed_out && !built.output_limited
      end
      bridge = bridge.not_nil!
      manifest_execution = Harness.execute([bridge, "--manifest"], output / "manifest", 10.seconds)
      raise "Manifest did not complete" unless manifest_execution.exit_code == 0 && !manifest_execution.timed_out && !manifest_execution.output_limited
      lines = File.read(manifest_execution.stdout_path).lines.reject(&.strip.empty?)
      raise "Manifest must have one JSONL record" unless lines.size == 1
      manifest = JSON.parse(lines[0])
      unless manifest["schema"].as_s == "filesystem-native-acl-cases" && manifest["version"].as_i == 1 &&
             manifest["isolation"].as_s == "fresh-exec-per-case"
        raise "Unexpected manifest schema/version/isolation"
      end
      definitions = manifest["cases"].as_a
      ids = definitions.map { |item| item["id"].as_s }
      raise "Manifest has duplicate IDs" unless ids.uniq.size == ids.size
      unknown = selected.reject { |id| ids.includes?(id) }
      raise ArgumentError.new("Unknown selected cases: #{unknown.join(", ")}") unless unknown.empty?
      cases = definitions.select do |item|
        selected.empty? ? item["platform"].as_s == NativeACLRunner.platform : selected.includes?(item["id"].as_s)
      end
      raise "No selected native cases for #{NativeACLRunner.platform}" if cases.empty?
      rows = [] of JSON::Any
      cases.each do |definition|
        id = definition["id"].as_s
        unless definition["platform"].as_s == NativeACLRunner.platform
          rows << NativeACLRunner.json({case_id: id, harness_outcome: "unavailable-platform", uncertain_side_effects: false})
          next
        end
        unless id.matches?(/\A[a-z0-9.-]+\z/)
          raise "Case ID cannot name a receipt file"
        end
        seconds = definition["timeout_seconds"].as_i
        raise "Invalid case deadline" unless 1 <= seconds <= 30
        execution = Harness.execute([bridge, "--case", id], output / id, seconds.seconds)
        stdout = File.exists?(execution.stdout_path) ? File.read(execution.stdout_path) : ""
        outcome = Harness.classify(id, stdout, execution.exit_code, timed_out: execution.timed_out,
          crashed: !execution.signal.nil?, output_limited: execution.output_limited,
          windows: NativeACLRunner.platform == "windows")
        outcome = "spawn-or-io-error" if execution.error && !execution.timed_out && !execution.output_limited
        rows << NativeACLRunner.json({case_id: id, harness_outcome: outcome,
                                      uncertain_side_effects: !outcome.in?({"matched", "mismatch"}), execution: execution})
        # Preserve completed case receipts even if the runner later crashes.
        File.write(output / "cases.json", rows.to_pretty_json)
      end
      after = source_hashes
      File.write(output / "source-after.json", after.to_pretty_json)
      matched = rows.count { |row| row["harness_outcome"].as_s == "matched" }
      stable = before == after
      receipt = {schema: "filesystem-native-acl-run", version: 1,
                 platform: NativeACLRunner.platform, runner_crystal: Crystal::VERSION, cwd: Dir.current,
                 source_root: SOURCE.to_s, source_stable: stable,
                 compiler: File.read(version.stdout_path).strip,
                 host: host,
                 bridge: bridge, bridge_sha256: Digest::SHA256.hexdigest(File.read(bridge)),
                 manifest_sha256: Digest::SHA256.hexdigest(File.read(manifest_execution.stdout_path)),
                 passed: matched, failed_or_unavailable: rows.size - matched, cases: rows,
                 timeout_or_crash_contract: "Harness failure; side effects unknown; no ACL result inferred"}
      File.write(output / "receipt.json", receipt.to_pretty_json)
      puts "native-acl-run cases=#{rows.size} matched=#{matched} source_stable=#{stable} receipt=#{output / "receipt.json"}"
      puts "native-acl-runner-ok" if matched == rows.size && stable
      matched == rows.size && stable
    end
  end
end

output_argument = nil.as(String?)
binary_argument = nil.as(String?)
compiler = "crystal"
selected = [] of String
temporary_output = false
OptionParser.parse do |options|
  options.banner = "Usage: native_acl_runner (--output-dir NEW_EXTERNAL_DIR | --temporary-output) [--case ID] [--compiler PATH] [--binary PATH]"
  options.on("--output-dir PATH", "New receipt/build directory outside source repositories") { |value| output_argument = value }
  options.on("--temporary-output", "Retain receipts in a new external temporary directory") { temporary_output = true }
  options.on("--case ID", "Select one case; repeat to select more") { |value| selected << value }
  options.on("--compiler PATH", "Compiler used for the bridge") { |value| compiler = value }
  options.on("--binary PATH", "Use an already built bridge") { |value| binary_argument = value }
end
abort "Choose --output-dir or --temporary-output" unless !!output_argument != temporary_output
output = nil.as(Path?)
begin
  proposed = output_argument || (Path[File.realpath(Dir.tempdir)] / "native-acl-run-#{Random::Secure.hex(16)}").to_s
  output = NativeACLRunner::Runner.output_path(proposed.not_nil!)
  exit(NativeACLRunner::Runner.run(output, selected, compiler, binary_argument) ? 0 : 1)
rescue error
  if output && Dir.exists?(output)
    File.write(output / "runner-error.json", {schema: "filesystem-native-acl-run", version: 1,
                                              harness_status: "error", uncertain_side_effects: true,
                                              error: error.message}.to_pretty_json)
  end
  STDERR.puts error.message
  exit 1
end
