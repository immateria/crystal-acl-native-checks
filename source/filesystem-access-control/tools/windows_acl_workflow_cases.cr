require "json"
require "file_utils"
require "random/secure"
require "../src/filesystem-access-control/write"

# Native Windows experiments. The bridge executes each case in a disposable
# process; only these probes change thread tokens, never library capture/checks.
module WindowsACLWorkflows
  {% if flag?(:windows) %}
    alias WinACL = Filesystem::AccessControl::Windows

    @[Link("advapi32")]
    lib ProbeNative
      struct SIDAndAttributes
        sid : Void*
        attributes : UInt32
      end

      fun duplicate_token = DuplicateToken(token : Void*, level : Int32, duplicate : Void**) : Int32
      fun restricted_token = CreateRestrictedToken(token : Void*, flags : UInt32,
                                                   disabled_count : UInt32, disabled : SIDAndAttributes*,
                                                   deleted_count : UInt32, deleted : Void*,
                                                   restricted_count : UInt32, restricted : SIDAndAttributes*,
                                                   result : Void**) : Int32
      fun set_thread_token = SetThreadToken(thread : Void**, token : Void*) : Int32
      fun revert = RevertToSelf : Int32
    end

    def self.run(id : String) : JSON::Any
      root = Path[Dir.tempdir] / "acl-workflow-#{Random::Secure.hex(8)}"
      Dir.mkdir(root)
      begin
        case id
        when "windows.writer-files"       then writer_files(root)
        when "windows.writer-propagation" then propagation(root)
        when "windows.access-check"       then access_check(root)
        when "windows.restricted-token"   then restricted_checks(root)
        else                                   raise ArgumentError.new("Unknown Windows workflow #{id}")
        end
      ensure
        FileUtils.rm_rf(root)
      end
    end

    private def self.ensure!(condition : Bool, message : String) : Nil
      raise message unless condition
    end

    private def self.json(value) : JSON::Any
      JSON.parse(value.to_json)
    end

    private def self.user : WinACL::SID
      capture = WinACL::TokenReader.capture
      ensure!(capture.complete?, "Process token identity unavailable: #{capture.diagnostic}")
      capture.identity.not_nil!.user
    end

    private def self.acl(entries : Array(Tuple(UInt8, UInt8, UInt32, WinACL::SID))) : WinACL::ACL
      size = 8 + entries.sum { |entry| 8 + entry[3].bytes.size }
      bytes = Bytes.new(size, 0_u8)
      bytes[0] = 2_u8
      IO::ByteFormat::LittleEndian.encode(size.to_u16, bytes[2, 2])
      IO::ByteFormat::LittleEndian.encode(entries.size.to_u16, bytes[4, 2])
      offset = 8
      entries.each do |type, flags, rights, sid|
        value = sid.bytes
        bytes[offset], bytes[offset + 1] = type, flags
        IO::ByteFormat::LittleEndian.encode((8 + value.size).to_u16, bytes[offset + 2, 2])
        IO::ByteFormat::LittleEndian.encode(rights, bytes[offset + 4, 4])
        value.copy_to(bytes[offset + 8, value.size])
        offset += 8 + value.size
      end
      WinACL::ACL.new(bytes)
    end

    private def self.open_handle(path : Path, access : UInt32) : Void*
      units = path.to_s.to_utf16
      name = Slice(UInt16).new(units.size + 1, 0_u16)
      units.copy_to(name)
      handle = LibC.CreateFileW(name.to_unsafe, access, 7_u32,
        Pointer(LibC::SECURITY_ATTRIBUTES).null, 3_u32, 0x02200000_u32, Pointer(Void).null)
      if handle.address == UInt64::MAX
        code = LibC.GetLastError
        raise "CreateFileW(#{access}) failed: #{code}"
      end
      handle
    end

    private def self.with_handle(path : Path, access : UInt32, &)
      handle = open_handle(path, access)
      begin
        yield handle
      ensure
        LibC.CloseHandle(handle)
      end
    end

    private def self.prepare(handle : Void*, value : WinACL::ACL) : Nil
      # Fixture recovery access was acquired before this protected DACL is
      # installed. Setter errors remain native failures, never fake denials.
      code = WinACL::NativeWriterProvider.new.replace(handle, value, 0x80000004_u32)
      ensure!(code == 0, "Fixture SetSecurityInfo failed: #{code}")
    end

    private def self.replace(handle : Void*, value : WinACL::ACL,
                             policy = WinACL::PropagationPolicy::TargetOnly) : WinACL::MutationResult
      target = WinACL::HandleReader.capture(handle)
      ensure!(target.complete?, "Handle capture unavailable: #{target.diagnostic || target.security.diagnostic}")
      WinACL::Writer.replace_dacl_handle(handle, target: target, dacl: value,
        inheritance: WinACL::InheritancePolicy::PreserveObserved, propagation: policy)
    end

    private def self.mutation(result : WinACL::MutationResult)
      {state: result.state.to_s, execution: result.execution.to_s,
       verification: result.verification.to_s, stage: result.stage.to_s,
       descendants: result.descendants.to_s, diagnostic: result.diagnostic.try { |d| {operation: d.operation, code: d.code, origin: d.origin.to_s} },
       normalizations: result.normalizations.map(&.to_s)}
    end

    private def self.writer_files(root : Path) : JSON::Any
      path = root / "file"
      File.write(path, "fixture")
      principal = user
      recovery = acl([{0_u8, 0_u8, 0x1f01ff_u32, principal}])
      observations = [] of JSON::Any
      with_handle(path, 0x60080_u32) do |held|
        prepare(held, recovery)
        original = WinACL::HandleReader.capture(held)
        ensure!(original.complete?, "Initial handle identity capture failed")
        identical = replace(held, recovery)
        ensure!(identical.applied? && identical.verified?, "Identical replacement did not execute and verify: #{identical.diagnostic}")
        observations << json({case: "identical", result: mutation(identical)})
        with_handle(path, 0x20080_u32) do |read_only|
          rejected = replace(read_only, recovery)
          ensure!(rejected.execution.failed? && rejected.verification.not_run?, "READ_CONTROL-only mutation did not retain setter failure")
          observations << json({case: "read-control-only", result: mutation(rejected)})
        end
        File.rename(path, root / "held-name")
        File.write(path, "replacement")
        target = WinACL::HandleReader.capture(held)
        ensure!(target.identity == original.identity, "Held identity changed after rename")
        empty = WinACL::ACL.new("0200080000000000".hexbytes)
        changed = replace(held, empty)
        ensure!(changed.verified?, "Held empty-DACL replacement failed: #{changed.diagnostic}")
        ensure!(File.read(path) == "replacement", "Held edit changed replacement path data")
        with_handle(path, 0x20080_u32) do |other|
          replacement = WinACL::HandleReader.capture(other)
          ensure!(replacement.complete? && replacement.identity != target.identity, "Replacement pathname identity was substituted")
          refused = WinACL::Writer.replace_dacl_handle(other, target: target, dacl: recovery,
            inheritance: WinACL::InheritancePolicy::PreserveObserved, propagation: WinACL::PropagationPolicy::TargetOnly)
          ensure!(refused.execution.not_attempted?, "Wrong-object target reached setter")
        end
        observations << json({case: "held-rename", result: mutation(changed), identity_retained: true})
      ensure
        prepare(held, recovery)
      end
      json({passed: true, observations: observations, scope: "held-regular-file-DACL", fixture_access: 0x60080_u32})
    end

    private def self.propagation(root : Path) : JSON::Any
      parent = root / "parent"
      Dir.mkdir(parent)
      child, protected_child = parent / "child", parent / "protected"
      File.write(child, "x")
      File.write(protected_child, "x")
      principal = user
      everyone = WinACL::SID.new("010100000000000100000000".hexbytes)
      recovery = acl([{0_u8, 0_u8, 0x1f01ff_u32, principal}])
      desired = acl([{0_u8, 3_u8, 0x1f01ff_u32, principal}, {0_u8, 3_u8, 1_u32, everyone}])
      with_handle(parent, 0x60080_u32) do |held|
        # Establish explicit recovery grants before replacing the parent's
        # inherited grants. The unprotected control must stay readable even
        # when that replacement removes all its inherited entries.
        with_handle(child, 0x60080_u32) do |handle|
          code = WinACL::NativeWriterProvider.new.replace(handle, recovery, 0x20000004_u32)
          ensure!(code == 0, "Unprotected child fixture SetSecurityInfo failed: #{code}")
        end
        with_handle(protected_child, 0x60080_u32) { |handle| prepare(handle, recovery) }
        prepare(held, recovery)
        refused = replace(held, desired)
        ensure!(refused.execution.not_attempted?, "TargetOnly directory mutation reached setter")
        result = replace(held, desired, WinACL::PropagationPolicy::NativePropagation)
        ensure!(result.verified? && result.descendants.unverified?, "Native propagation did not retain target/descendant scope")
        future = parent / "future-child"
        File.write(future, "future")
        child_has_candidate = false
        protected_has_candidate = false
        future_has_candidate = false
        [{child, false}, {protected_child, true}].each do |path, protected_case|
          with_handle(path, 0x20080_u32) do |handle|
            snapshot = WinACL::HandleReader.capture(handle)
            ensure!(snapshot.complete?, "Child readback failed")
            present = snapshot.security.dacl.not_nil!.entries.any? { |entry| entry.trustee == everyone && entry.inheritance.inherited? }
            protected_case ? (protected_has_candidate = present) : (child_has_candidate = present)
          end
        end
        with_handle(future, 0x20080_u32) do |handle|
          snapshot = WinACL::HandleReader.capture(handle)
          ensure!(snapshot.complete?, "Future child readback failed")
          future_has_candidate = snapshot.security.dacl.not_nil!.entries.any? { |entry| entry.trustee == everyone && entry.inheritance.inherited? }
        end
        ensure!(child_has_candidate && !protected_has_candidate && future_has_candidate, "Existing/protected/future child inheritance differed from fixture contract")
        json({passed: true, mutation: mutation(result), unprotected_inherited: child_has_candidate,
              protected_inherited: protected_has_candidate, future_inherited: future_has_candidate,
              descendant_check: "three-explicit-fixtures-only"})
      ensure
        prepare(held, recovery)
      end
    end

    private def self.with_process_token(&)
      token = Pointer(Void).null
      if Filesystem::AccessControl::Native::Windows::ACL.acl_process_token(LibC.GetCurrentProcess, 10_u32, pointerof(token)) == 0
        raise "OpenProcessToken(query/duplicate) failed: #{LibC.GetLastError}"
      end
      begin
        yield token
      ensure
        LibC.CloseHandle(token)
      end
    end

    private def self.with_impersonation(token : Void*, &)
      subject = Pointer(Void).null
      if ProbeNative.duplicate_token(token, 2, pointerof(subject)) == 0
        raise "DuplicateToken failed: #{LibC.GetLastError}"
      end
      begin
        yield subject
      ensure
        LibC.CloseHandle(subject)
      end
    end

    private def self.data_open(path : Path, requested : UInt32)
      units = path.to_s.to_utf16
      name = Slice(UInt16).new(units.size + 1, 0_u16)
      units.copy_to(name)
      # SYNCHRONIZE is explicitly granted as a fixture control. No create or
      # truncate occurs, and actual data I/O follows acquisition.
      desired = requested | 0x100000_u32
      handle = LibC.CreateFileW(name.to_unsafe, desired, 7_u32,
        Pointer(LibC::SECURITY_ATTRIBUTES).null, 3_u32, 0x00200080_u32, Pointer(Void).null)
      if handle.address == UInt64::MAX
        code = LibC.GetLastError
        return {acquired: false, open_code: code, desired_access: desired, io_ok: nil.as(Bool?), io_error: nil.as(UInt32?)}
      end
      begin
        io_ok = true
        io_error = nil.as(UInt32?)
        data = Bytes[0x78_u8]
        transferred = 0_u32
        if (requested & 1) != 0
          read_ok = LibC.ReadFile(handle, data.to_unsafe.as(Void*), 1_u32, pointerof(transferred), Pointer(LibC::OVERLAPPED).null)
          io_error = LibC.GetLastError if read_ok == 0
          io_ok &&= read_ok != 0 && transferred == 1_u32
        end
        if (requested & 2) != 0
          transferred = 0_u32
          write_ok = LibC.WriteFile(handle, data.to_unsafe.as(Void*), 1_u32, pointerof(transferred), Pointer(LibC::OVERLAPPED).null)
          io_error ||= LibC.GetLastError if write_ok == 0
          io_ok &&= write_ok != 0 && transferred == 1_u32
        end
        {acquired: true, open_code: 0_u32, desired_access: desired, io_ok: io_ok.as(Bool?), io_error: io_error}
      ensure
        LibC.CloseHandle(handle)
      end
    end

    private def self.access_check(root : Path) : JSON::Any
      path = root / "access"
      File.write(path, "fixture")
      principal = user
      recovery = acl([{0_u8, 0_u8, 0x1f01ff_u32, principal}])
      rows = [] of JSON::Any
      with_handle(path, 0x60080_u32) do |held|
        prepare(held, recovery)
        with_process_token do |primary|
          with_impersonation(primary) do |subject|
            policies = [
              {[{0_u8, 0_u8, 0x100000_u32, principal}], {false, false, false}},
              {[{0_u8, 0_u8, 0x100001_u32, principal}, {0_u8, 0_u8, 2_u32, principal}], {true, true, true}},
              {[{1_u8, 0_u8, 1_u32, principal}, {0_u8, 0_u8, 0x100003_u32, principal}], {false, true, false}},
              {[{0_u8, 0_u8, 0x100003_u32, principal}, {1_u8, 0_u8, 3_u32, principal}], {true, true, true}},
            ]
            policies.each_with_index do |(entries, expected), index|
              result = replace(held, acl(entries))
              ensure!(result.verified?, "Access fixture DACL replacement failed: #{result.diagnostic}")
              snapshot = result.after.not_nil!.security
              [1_u32, 2_u32, 3_u32].each_with_index do |request, ordinal|
                check = WinACL::Evaluator.check(snapshot, subject: subject,
                  permissions: WinACL::Rights.new(request), kind: Filesystem::AccessControl::Target::File)
                actual = data_open(path, request)
                ensure!(check.api_success == true && check.allowed? == expected[ordinal], "AccessCheck did not return expected complete decision")
                ensure!(actual[:acquired] == expected[ordinal], "Fresh native acquisition disagrees with controlled descriptor check")
                ensure!(actual[:open_code] == 5_u32, "Acquisition failed for a reason other than access denial") unless actual[:acquired]
                ensure!(actual[:io_ok] == true, "Acquired data I/O failed") if actual[:acquired]
                rows << json({policy: index, requested: request, decision: check.decision.to_s,
                              api_success: check.api_success, granted_mask: check.granted_mask, actual: actual})
              end
            end
            invalid = WinACL::Evaluator.check(WinACL::Reader.capture(held), subject: primary,
              permissions: WinACL::Rights::ReadData, kind: Filesystem::AccessControl::Target::File)
            ensure!(invalid.decision.indeterminate? && invalid.api_success == false && invalid.diagnostic.try(&.code) == 1309_u32,
              "Primary-token rejection was converted into an access decision")
          end
        end
      ensure
        prepare(held, recovery)
      end
      json({passed: true, rows: rows, oracle: "fresh-native-open-and-data-IO", primary_token: "API-error-1309"})
    end

    private def self.restricted_checks(root : Path) : JSON::Any
      # Diagnostic phases are bounded and contain only synthetic fixture IDs.
      # Keep stderr flushed so a native crash cannot erase the last boundary.
      stage = ->(phase : String) do
        STDERR.puts("acl-restricted-token phase=#{phase}")
        STDERR.flush
      end
      stage.call("setup")
      path = root / "restricted"
      File.write(path, "fixture")
      principal = user
      everyone = WinACL::SID.new("010100000000000100000000".hexbytes)
      recovery = acl([{0_u8, 0_u8, 0x1f01ff_u32, principal}])
      rows = [] of JSON::Any
      with_handle(path, 0x60080_u32) do |held|
        prepare(held, recovery)
        stage.call("recovery-installed")
        with_process_token do |primary|
          [false, true].each do |restricting|
            stage.call("create restricting=#{restricting}")
            sid = everyone.bytes
            entry = ProbeNative::SIDAndAttributes.new
            entry.sid, entry.attributes = sid.to_unsafe.as(Void*), 0_u32
            restricted = Pointer(Void).null
            disabled = restricting ? Pointer(ProbeNative::SIDAndAttributes).null : pointerof(entry)
            restrictions = restricting ? pointerof(entry) : Pointer(ProbeNative::SIDAndAttributes).null
            if ProbeNative.restricted_token(primary, 0_u32, restricting ? 0_u32 : 1_u32, disabled,
                 0_u32, Pointer(Void).null, restricting ? 1_u32 : 0_u32, restrictions, pointerof(restricted)) == 0
              raise "CreateRestrictedToken failed: #{LibC.GetLastError}"
            end
            stage.call("created")
            begin
              stage.call("duplicate")
              with_impersonation(restricted) do |subject|
                stage.call("duplicated")
                # Original user grants cannot satisfy a separate restricting
                # SID pass. A deny-only SID cannot satisfy an allow ACE.
                values = restricting ? [acl([{0_u8, 0_u8, 0x100001_u32, principal}]),
                                        acl([{0_u8, 0_u8, 0x100001_u32, principal}, {0_u8, 0_u8, 0x100001_u32, everyone}])] : [acl([{0_u8, 0_u8, 0x100001_u32, everyone}]),
                                                                                                                               acl([{0_u8, 0_u8, 0x100001_u32, principal}])]
                values.each_with_index do |value, index|
                  stage.call("replace restricting=#{restricting} fixture=#{index}")
                  result = replace(held, value)
                  stage.call("replace-returned")
                  ensure!(result.verified?, "Restricted fixture DACL replacement failed")
                  stage.call("access-check")
                  check = WinACL::Evaluator.check(result.after.not_nil!.security, subject: subject,
                    permissions: WinACL::Rights::ReadData, kind: Filesystem::AccessControl::Target::File)
                  stage.call("access-check-returned")
                  expected = index == 1
                  ensure!(check.api_success == true && check.allowed? == expected, "Restricted-token check was incomplete or unexpected")
                  stage.call("set-thread-token")
                  if ProbeNative.set_thread_token(Pointer(Void*).null, subject) == 0
                    raise "SetThreadToken failed: #{LibC.GetLastError}"
                  end
                  begin
                    # Keep assertions, formatting and serialization outside the
                    # impersonated interval. Native failures are returned as
                    # observations; they are assessed after restoring context.
                    observed = WinACL::TokenReader.capture_subject(WinACL::TokenContext::Effective)
                    actual = data_open(path, 1_u32)
                  ensure
                    abort "RevertToSelf failed: #{LibC.GetLastError}" if ProbeNative.revert == 0
                  end
                  stage.call("reverted")
                  row = json({restricting: restricting, positive_control: index == 1,
                              expected_acquisition: expected,
                              decision: check.decision.to_s, api_success: check.api_success,
                              granted_mask: check.granted_mask, actual: actual,
                              capture_complete: observed.complete?, token_source: observed.token.source.try(&.to_s),
                              capture_diagnostics: observed.diagnostics.map { |item|
                                {operation: item.operation, code: item.code, origin: item.origin.to_s}
                              },
                              restricted_sid_count: observed.restricted_sids.value.try(&.entries.size),
                              deny_only_count: observed.groups.value.try { |list| list.entries.count(&.deny_only?) }})
                  # Preserve each bounded fixture result even when a later
                  # assertion refuses completion. No raw token identity is logged.
                  STDERR.puts("acl-restricted-token-observation #{row.to_json}")
                  STDERR.flush
                  rows << row
                  ensure!(observed.complete? && observed.token.source.not_nil!.thread?, "Restricted effective-token capture incomplete")
                  if restricting
                    ensure!(observed.restricted_sids.value.not_nil!.entries.any? { |item| item.sid == everyone },
                      "Expected restricting SID was not observed")
                  else
                    ensure!(observed.groups.value.not_nil!.entries.any? { |item| item.sid == everyone && item.deny_only? && !item.enabled? },
                      "Expected deny-only Everyone group attributes were not observed")
                  end
                  ensure!(actual[:acquired] == expected, "Restricted fresh acquisition disagrees")
                  ensure!(actual[:open_code] == 5_u32, "Restricted acquisition failed for a reason other than access denial") unless actual[:acquired]
                  ensure!(actual[:io_ok] == true, "Restricted acquired data I/O failed") if actual[:acquired]
                  stage.call("row-validated")
                end
              end
              stage.call("duplicate-closed")
            ensure
              stage.call("close-restricted")
              LibC.CloseHandle(restricted)
            end
          end
        end
      ensure
        stage.call("restore-recovery")
        prepare(held, recovery)
      end
      stage.call("complete")
      json({passed: true, rows: rows, token_construction: "CreateRestrictedToken-then-DuplicateToken", oracle: "fresh-native-open-under-explicit-thread-token"})
    end
  {% else %}
    def self.run(id : String) : JSON::Any
      raise "Windows ACL workflows require a native Windows process"
    end
  {% end %}
end
