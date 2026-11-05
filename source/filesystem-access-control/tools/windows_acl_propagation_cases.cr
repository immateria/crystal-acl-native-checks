require "json"
require "set"
require "./windows_acl_owner_cases"

module WindowsACLWorkflows
  # Fixed witnesses, not enumeration of an arbitrary descendant tree. OI|CI
  # becomes INHERITED on files and OI|CI|INHERITED on directories.
  # https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-inheritance-rules
  def self.propagation_violations(facts : JSON::Any) : Array(String)
    errors = [] of String
    expectations = {
      "open-dir" => {true, 19}, "open-file" => {false, 16},
      "grand-dir" => {true, 19}, "deep-file" => {false, 16},
      "protected-dir" => {true, nil}, "barrier-file" => {false, nil},
      "protected-file" => {false, nil}, "direct-file" => {false, 16},
      "future-direct" => {false, 16}, "future-grand" => {false, 16},
      "future-barrier" => {false, nil},
    }
    errors << "Wrong propagation observation scope" unless facts["scope"].as_s == "explicit-held-fixtures-not-tree-transaction"
    errors << "Propagation experiment did not restore its fixtures" unless facts["passed"].as_bool && facts["recovery_restored"].as_bool
    errors << "Propagation must call the setter once" unless facts["setter_calls"].as_i64 == 1
    refused = facts["target_only"]
    unless facts["target_only_setter_calls"].as_i64 == 0 && refused["execution"].as_s == "NotAttempted" && refused["verification"].as_s == "NotRun"
      errors << "TargetOnly directory refusal reached the setter"
    end
    errors.concat(propagation_result_violations(facts["mutation"], success: true))
    seen = Set(String).new
    rows = facts["nodes"].as_a
    errors << "Missing multilevel descendant witnesses" unless rows.size == expectations.size
    rows.each do |row|
      name = row["name"].as_s
      errors << "Duplicate witness #{name}" unless seen.add?(name)
      expected = expectations[name]?
      unless expected
        errors << "Unexpected witness #{name}"
        next
      end
      directory, flags = expected
      after = propagation_descriptor(row["after"])
      errors << "Wrong fixture kind #{name}" unless row["after"]["directory"].as_bool == directory
      protected_node = name.in?({"protected-dir", "protected-file"})
      errors << "Protection changed for #{name}" unless after.dacl_inheritance_control.not_nil!.protected? == protected_node
      errors.concat(candidate_violations(after, flags, name))
      before = row["before"]
      if name.starts_with?("future-")
        errors << "Future witness claims a pre-creation capture" unless before.raw.nil?
      else
        prior = propagation_descriptor(before)
        errors.concat(candidate_violations(prior, nil, "before/#{name}"))
        errors.concat(held_witness_violations(before, row["after"]))
      end
    end
    expectations.each_key { |name| errors << "Missing witness #{name}" unless seen.includes?(name) }
    errors
  rescue KeyError | IndexError | TypeCastError | ArgumentError | NilAssertionError
    ["Propagation evidence is missing or malformed"]
  end

  private def self.propagation_descriptor(value : JSON::Any)
    raise ArgumentError.new("Incomplete held capture") unless value["complete"].as_bool
    raise ArgumentError.new("Invalid file identity") unless value["file_id"].as_s.hexbytes.size == 16 && value["volume"].as_s.to_u64 >= 0
    Filesystem::AccessControl::Windows::SecurityDescriptor.new(value["descriptor"].as_s.hexbytes)
  end

  private def self.held_witness_violations(before : JSON::Any, after : JSON::Any)
    errors = [] of String
    prior, later = propagation_descriptor(before), propagation_descriptor(after)
    unless {"volume", "file_id", "directory"}.all? { |key| before[key] == after[key] } && prior.owner == later.owner && prior.group == later.group
      errors << "Held fixture identity, kind, owner or group changed"
    end
    errors
  end

  private def self.candidate_violations(descriptor, flags : Int32?, name : String)
    everyone = Filesystem::AccessControl::Windows::SID.new("010100000000000100000000".hexbytes)
    entries = descriptor.dacl.not_nil!.entries.select { |entry| entry.trustee == everyone }
    correct = if flags
                entries.size == 1 && entries[0].type == 0 && entries[0].flags == flags && entries[0].rights == 1_u32
              else
                entries.empty?
              end
    correct ? [] of String : ["Candidate inheritance differs for #{name}"]
  end

  private def self.propagation_result_violations(result : JSON::Any, *, success : Bool)
    errors = [] of String
    unless result["descendants"].as_s == "Unverified" &&
           result["execution"].as_s == (success ? "Succeeded" : "Failed") &&
           result["verification"].as_s == (success ? "Matched" : "NotRun") &&
           result["stage"].as_s == (success ? "Verification" : "Mutation") &&
           result["state"].as_s == (success ? "Applied" : "Rejected")
      errors << "Public result overstates or loses propagation evidence"
    end
    errors
  end

  def self.partial_propagation_violations(facts : JSON::Any) : Array(String)
    errors = [] of String
    unless facts["passed"].as_bool && facts["recovery_restored"].as_bool &&
           facts["scope"].as_s == "share-conflict-subtree-observation-not-acl-denial" && facts["exclusive_share"].as_i64 == 0
      errors << "Unqualified sharing-conflict experiment"
    end
    errors.concat(propagation_result_violations(facts["mutation"], success: true))
    errors << "Parent setter was replayed" unless facts["setter_calls"].as_i64 == 1
    oracle = facts["directory_list_open"]
    unless oracle["requested_access"].as_i64 == 1 && !oracle["opened"].as_bool && oracle["code"].as_i64 == 32
      errors << "Exclusive directory did not deny fresh enumeration acquisition"
    end
    rows = facts["nodes"].as_a
    errors << "Missing mixed-result witnesses" unless rows.size == 5
    seen = Set(String).new
    rows.each do |row|
      name = row["name"].as_s
      errors << "Duplicate or unexpected mixed witness" unless seen.add?(name) && name.in?({"updated", "exclusive", "protected", "blocked-dir", "blocked-grandchild"})
      errors.concat(held_witness_violations(row["before"], row["after"]))
      prior, later = propagation_descriptor(row["before"]), propagation_descriptor(row["after"])
      errors.concat(candidate_violations(prior, nil, "before/#{name}"))
      expected_flags = if name == "blocked-dir"
                         # The blocked directory's own metadata can be updated
                         # independently of acquiring it for enumeration. Record
                         # both named outcomes; the grandchild must stay skipped.
                         case facts["blocked_directory_outcome"].as_s
                         when "updated" then 19
                         when "skipped" then nil
                         else
                           errors << "Unknown blocked-directory outcome"
                           nil
                         end
                       elsif name.in?({"updated", "exclusive"})
                         16
                       end
      errors.concat(candidate_violations(later, expected_flags, name))
      errors << "Wrong mixed fixture kind" unless row["after"]["directory"].as_bool == (name == "blocked-dir")
      errors << "Skipped fixture changed" if name.in?({"protected", "blocked-grandchild"}) && prior.bytes != later.bytes
      errors.concat(held_witness_violations(row["after"], row["after_failed"]))
      errors << "Failed parent setter changed sampled child" unless later.bytes == propagation_descriptor(row["after_failed"]).bytes
    end
    result = facts["failed_mutation"]
    diagnostic = result["diagnostic"]
    unless result["state"].as_s == "Rejected" && result["execution"].as_s == "Failed" &&
           result["verification"].as_s == "NotRun" && result["stage"].as_s == "Mutation" &&
           result["descendants"].as_s == "Unverified" &&
           diagnostic["operation"].as_s == "SetSecurityInfo" && diagnostic["code"].as_i64 == 5 && diagnostic["origin"].as_s == "ReturnValue" &&
           facts["failed_setter_calls"].as_i64 == 1 && facts["failed_capture_calls"].as_i64 == 1 && facts["failed_public_after_nil"].as_bool
      errors << "Failed setter lost execution/provenance or was replayed"
    end
    { {"parent_before_failed", "parent_after_failed"} }.each do |before_key, after_key|
      before, after = facts[before_key], facts[after_key]
      errors.concat(held_witness_violations(before, after))
      # Observed equality belongs to this fixture only. It is not an API
      # promise of rollback or absence of effects for arbitrary failed calls.
      errors << "Read-only-handle failure changed sampled security" unless propagation_descriptor(before).bytes == propagation_descriptor(after).bytes
    end
    errors
  rescue KeyError | IndexError | TypeCastError | ArgumentError | NilAssertionError
    ["Mixed propagation evidence is missing or malformed"]
  end

  {% if flag?(:windows) %}
    private def self.propagation_capture(handle : Void*) : JSON::Any
      snapshot = WinACL::HandleReader.capture(handle)
      ensure!(snapshot.complete?, "Independent held fixture readback failed: #{snapshot.diagnostic || snapshot.security.diagnostic}")
      identity = snapshot.identity.not_nil!
      json({complete: snapshot.complete?, volume: identity.volume.to_s, file_id: identity.file_id.hexstring,
            directory: snapshot.kind.not_nil!.directory?, descriptor: snapshot.security.descriptor.not_nil!.bytes.hexstring})
    end

    private def self.propagation_tree(root : Path) : JSON::Any
      parent = root / "parent"
      Dir.mkdir(parent)
      paths = {
        "open-dir" => parent / "open", "open-file" => parent / "open" / "file",
        "grand-dir" => parent / "open" / "grand", "deep-file" => parent / "open" / "grand" / "deep",
        "protected-dir" => parent / "barrier", "barrier-file" => parent / "barrier" / "file",
        "protected-file" => parent / "open" / "protected", "direct-file" => parent / "direct",
      }
      paths.each do |name, path|
        name.in?({"open-dir", "grand-dir", "protected-dir"}) ? Dir.mkdir(path) : File.write(path, "fixture")
      end
      principal = user
      everyone = WinACL::SID.new("010100000000000100000000".hexbytes)
      recovery = acl([{0_u8, 0_u8, 0x1f01ff_u32, principal}])
      barrier = acl([{0_u8, 3_u8, 0x1f01ff_u32, principal}])
      desired = acl([{0_u8, 3_u8, 0x1f01ff_u32, principal}, {0_u8, 3_u8, 1_u32, everyone}])
      handles = {} of String => Void*
      rows = [] of JSON::Any
      restored = false
      with_handle(parent, 0x60080_u32) do |held|
        begin
          # Acquire every recovery handle before changing an ancestor. A parent
          # replacement can remove inherited grants from existing descendants.
          paths.each { |name, path| handles[name] = open_handle(path, 0x60080_u32) }
          prepare(held, recovery)
          handles.each do |name, handle|
            if name.in?({"protected-dir", "protected-file"})
              prepare(handle, barrier)
            else
              code = WinACL::NativeWriterProvider.new.replace(handle, recovery, 0x20000004_u32)
              ensure!(code == 0, "Unprotected tree fixture failed: #{code}")
            end
          end
          before = handles.transform_values { |handle| propagation_capture(handle) }
          target = WinACL::HandleReader.capture(held)
          refused_provider = TrackedWriterProvider.new
          refused = WinACL::Writer.replace_dacl_handle(held, target: target, dacl: desired,
            inheritance: WinACL::InheritancePolicy::PreserveObserved,
            propagation: WinACL::PropagationPolicy::TargetOnly, provider: refused_provider)
          provider = TrackedWriterProvider.new
          result = WinACL::Writer.replace_dacl_handle(held, target: target, dacl: desired,
            inheritance: WinACL::InheritancePolicy::PreserveObserved,
            propagation: WinACL::PropagationPolicy::NativePropagation, provider: provider)
          handles.each { |name, handle| rows << json({name: name, before: before[name], after: propagation_capture(handle)}) }
          {"future-direct" => parent / "future", "future-grand" => paths["grand-dir"] / "future",
           "future-barrier" => paths["protected-dir"] / "future"}.each do |name, path|
            File.write(path, "future")
            with_handle(path, 0x20080_u32) do |handle|
              rows << json({name: name, before: nil, after: propagation_capture(handle)})
            end
          end
        ensure
          begin
            handles.each_value { |handle| prepare(handle, recovery) }
            prepare(held, recovery)
            restored = true
          ensure
            handles.each_value { |handle| LibC.CloseHandle(handle) }
          end
        end
        json({passed: true, scope: "explicit-held-fixtures-not-tree-transaction", recovery_restored: restored,
              setter_calls: provider.not_nil!.setter_calls, mutation: mutation(result.not_nil!),
              target_only_setter_calls: refused_provider.not_nil!.setter_calls,
              target_only: mutation(refused.not_nil!), nodes: rows})
      end
    end

    private def self.partial_propagation(root : Path) : JSON::Any
      parent = root / "partial"
      Dir.mkdir(parent)
      principal = user
      everyone = WinACL::SID.new("010100000000000100000000".hexbytes)
      recovery = acl([{0_u8, 0_u8, 0x1f01ff_u32, principal}])
      desired = acl([{0_u8, 3_u8, 0x1f01ff_u32, principal}, {0_u8, 3_u8, 1_u32, everyone}])
      paths = {"updated" => parent / "updated", "exclusive" => parent / "exclusive", "protected" => parent / "protected",
               "blocked-dir" => parent / "blocked", "blocked-grandchild" => parent / "blocked" / "child"}
      paths.each { |name, path| name == "blocked-dir" ? Dir.mkdir(path) : File.write(path, "fixture") }
      handles = {} of String => Void*
      rows = [] of JSON::Any
      with_handle(parent, 0x60080_u32) do |held|
        begin
          paths.each do |name, path|
            handle = if name.in?({"exclusive", "blocked-dir"})
                       units = path.to_s.to_utf16
                       native_name = Slice(UInt16).new(units.size + 1, 0_u16)
                       units.copy_to(native_name)
                       # The directory also holds LIST_DIRECTORY. The file
                       # control holds security rights only: share mode zero
                       # did not block its ACL update in run 41983308412.
                       access = name == "blocked-dir" ? 0x60081_u32 : 0x60080_u32
                       value = LibC.CreateFileW(native_name.to_unsafe, access, 0_u32,
                         Pointer(LibC::SECURITY_ATTRIBUTES).null, 3_u32, 0x02200000_u32, Pointer(Void).null)
                       raise "Exclusive fixture open failed: #{LibC.GetLastError}" if value.address == UInt64::MAX
                       value
                     else
                       open_handle(path, 0x60080_u32)
                     end
            handles[name] = handle
          end
          prepare(held, recovery)
          handles.each do |name, handle|
            if name == "protected"
              prepare(handle, recovery)
            else
              code = WinACL::NativeWriterProvider.new.replace(handle, recovery, 0x20000004_u32)
              ensure!(code == 0, "Mixed unprotected fixture failed: #{code}")
            end
          end
          before = handles.transform_values { |handle| propagation_capture(handle) }
          directory_list_open = propagation_list_open(paths["blocked-dir"])
          target = WinACL::HandleReader.capture(held)
          provider = TrackedWriterProvider.new
          result = WinACL::Writer.replace_dacl_handle(held, target: target, dacl: desired,
            inheritance: WinACL::InheritancePolicy::PreserveObserved,
            propagation: WinACL::PropagationPolicy::NativePropagation, provider: provider)
          handles.each { |name, handle| rows << json({name: name, before: before[name], after: propagation_capture(handle)}) }
          blocked = WinACL::HandleReader.capture(handles["blocked-dir"])
          ensure!(blocked.complete?, "Blocked directory independent readback failed")
          blocked_directory_outcome = blocked.security.dacl.not_nil!.entries.any? { |entry| entry.trustee == everyone } ? "updated" : "skipped"
          parent_before_failed = propagation_capture(held)
          # Complete capture is possible through this newly acquired handle;
          # the setter must execute and fail because WRITE_DAC was not granted.
          failed, failed_provider = with_handle(parent, 0x20080_u32) do |readable|
            limited_target = WinACL::HandleReader.capture(readable)
            limited_provider = TrackedWriterProvider.new
            limited_result = WinACL::Writer.replace_dacl_handle(readable, target: limited_target,
              dacl: desired, inheritance: WinACL::InheritancePolicy::PreserveObserved,
              propagation: WinACL::PropagationPolicy::NativePropagation, provider: limited_provider)
            {limited_result, limited_provider}
          end
          rows.each { |row| row.as_h["after_failed"] = propagation_capture(handles[row["name"].as_s]) }
          parent_after_failed = propagation_capture(held)
        ensure
          begin
            handles.each_value { |handle| prepare(handle, recovery) }
            prepare(held, recovery)
          ensure
            handles.each_value { |handle| LibC.CloseHandle(handle) }
          end
        end
        json({passed: true, scope: "share-conflict-subtree-observation-not-acl-denial", recovery_restored: true,
              directory_list_open: directory_list_open, blocked_directory_outcome: blocked_directory_outcome,
              exclusive_share: 0, setter_calls: provider.not_nil!.setter_calls, mutation: mutation(result.not_nil!), nodes: rows,
              failed_mutation: mutation(failed.not_nil!), failed_setter_calls: failed_provider.not_nil!.setter_calls,
              failed_capture_calls: failed_provider.not_nil!.capture_calls, failed_public_after_nil: failed.not_nil!.after.nil?,
              parent_before_failed: parent_before_failed, parent_after_failed: parent_after_failed})
      end
    end

    private def self.propagation_list_open(path : Path)
      units = path.to_s.to_utf16
      name = Slice(UInt16).new(units.size + 1, 0_u16)
      units.copy_to(name)
      handle = LibC.CreateFileW(name.to_unsafe, 1_u32, 7_u32,
        Pointer(LibC::SECURITY_ATTRIBUTES).null, 3_u32, 0x02200000_u32, Pointer(Void).null)
      if handle.address == UInt64::MAX
        {requested_access: 1_u32, opened: false, code: LibC.GetLastError}
      else
        LibC.CloseHandle(handle)
        {requested_access: 1_u32, opened: true, code: 0_u32}
      end
    end
  {% end %}
end
