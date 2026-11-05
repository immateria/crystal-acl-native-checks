require "json"
require "file_utils"
require "random/secure"
require "../src/filesystem-access-control"
require "../src/filesystem-access-control/write"
require "./windows_acl_owner_cases"

# Product API experiments. Each command runs one case in a disposable process;
# the calling harness owns deadlines, crashes and completion validation.
module NativeACLRunner
  MANIFEST_VERSION = 1

  record CaseDefinition, id : String, platform : String, contract : String,
    prerequisites : String, timeout_seconds : Int32 = 30 do
    include JSON::Serializable
  end

  class NativeCaseFailure < Exception
    getter operation : String
    getter code : Int64
    getter facts : JSON::Any?

    def initialize(@operation, @code, @facts = nil)
      super("#{@operation} failed with native code #{@code}")
    end
  end

  CASES = [
    CaseDefinition.new("darwin.held-unlink", "darwin", "Retained regular-file capture and edit after unlink", "Owned local ACL-capable filesystem"),
    CaseDefinition.new("darwin.held-replacement", "darwin", "Held-file edit does not edit its replacement pathname", "Owned local ACL-capable filesystem"),
    CaseDefinition.new("darwin.hardlink-alias", "darwin", "Both hard-link names observe one object's ACL edit", "Owned local ACL-capable filesystem"),
    CaseDefinition.new("darwin.move-inheritance", "darwin", "Same-volume move retains the source ACL; creation inherits", "Owned local ACL-capable filesystem"),
    CaseDefinition.new("darwin.copyfile-data", "darwin", "copyfile COPYFILE_DATA records destination ACL separately", "Owned local ACL-capable filesystem"),
    CaseDefinition.new("darwin.copyfile-acl", "darwin", "copyfile COPYFILE_DATA|COPYFILE_ACL records copied ACL", "Owned local ACL-capable filesystem"),
    CaseDefinition.new("darwin.clonefile-default", "darwin", "clonefile flags zero records destination ACL separately", "Owned local clone-capable filesystem"),
    CaseDefinition.new("darwin.clonefile-acl", "darwin", "clonefile CLONE_ACL records copied ACL", "Owned local clone-capable filesystem"),
    CaseDefinition.new("darwin.raw-storage-bits", "darwin", "Selected unnamed rights and captured flag combinations retain their fields", "Owned local ACL-capable filesystem"),
    CaseDefinition.new("windows.capture-rights", "windows", "Record handle-open and scoped descriptor-query outcomes separately", "Owned Windows local file fixture"),
    CaseDefinition.new("windows.token-context", "windows", "Explicit process/effective identity and self-impersonation retain token source", "Disposable Windows process; self-impersonation allowed"),
    CaseDefinition.new("windows.writer-files", "windows", "Held-file DACL replacement records verification and handle identity", "Owned Windows local ACL-capable file fixture"),
    CaseDefinition.new("windows.writer-propagation", "windows", "Explicit directory propagation policy records existing and future children", "Owned Windows local ACL-capable directory fixture"),
    CaseDefinition.new("windows.access-check", "windows", "Native access checks retain request and selected token context", "Disposable Windows process with queryable process token"),
    CaseDefinition.new("windows.restricted-token", "windows", "Restricted token observations and checks retain the selected context", "Disposable Windows process; restricted-token creation and impersonation allowed"),
    CaseDefinition.new("windows.owner-rights", "windows", "Explicit OWNER_RIGHTS entries control implicit owner security rights", "Disposable Windows process; owned NTFS file and privilege-free self-impersonation"),
  ]

  def self.platform : String
    {% if flag?(:darwin) %}
      "darwin"
    {% elsif flag?(:windows) %}
      "windows"
    {% elsif flag?(:linux) %}
      "linux"
    {% else %}
      "unsupported"
    {% end %}
  end

  def self.json(value) : JSON::Any
    JSON.parse(value.to_json)
  end

  def self.run_case(id : String) : JSON::Any
    definition = CASES.find { |item| item.id == id } || raise ArgumentError.new("Unknown case: #{id}")
    raise ArgumentError.new("#{id} requires #{definition.platform}") unless definition.platform == platform
    with_fixture do |root|
      {% if flag?(:darwin) %}
        run_darwin(id, root)
      {% elsif flag?(:windows) %}
        run_windows(id, root)
      {% else %}
        raise ArgumentError.new("No native cases for this platform")
      {% end %}
    end
  end

  # Failure here is a harness comparison result, never a public ACL result.
  # Missing/malformed completion evidence cannot become an ACL rejection.
  def self.violations(id : String, facts : JSON::Any) : Array(String)
    errors = [] of String
    case id
    when "darwin.held-unlink"
      errors << "Unlinked fixture still has a pathname" if facts["name_exists"].as_bool
      errors << "Held identity changed" unless same_identity?(facts["before"], facts["after"])
      errors << "Held ACL edit did not match" unless single_right?(facts["after"], 0x100000_i64)
      errors << "Mutation was not verified" unless verified_mutation?(facts["mutation"])
    when "darwin.held-replacement"
      errors << "Held identity changed" unless same_identity?(facts["before"], facts["held_after"])
      errors << "Path replacement did not create another inode" if same_identity?(facts["held_after"], facts["path_after"])
      errors << "Held ACL edit did not match" unless single_right?(facts["held_after"], 0x100000_i64)
      errors << "Replacement ACL was changed" unless single_right?(facts["path_after"], 0x80_i64)
      errors << "Replacement data was changed" unless facts["replacement_data"].as_s == "replacement"
      errors << "Mutation was not verified" unless verified_mutation?(facts["mutation"])
    when "darwin.hardlink-alias"
      errors << "Hard-link identity differs" unless same_identity?(facts["source"], facts["alias"])
      errors << "Hard-link ACL differs" unless facts["source"]["entries"] == facts["alias"]["entries"]
      errors << "Alias ACL edit did not match" unless single_right?(facts["alias"], 0x100000_i64)
      errors << "Mutation was not verified" unless verified_mutation?(facts["mutation"])
    when "darwin.move-inheritance"
      errors << "Same-volume move changed identity" unless same_identity?(facts["before"], facts["moved"])
      errors << "Move changed ACL" unless facts["before"]["entries"] == facts["moved"]["entries"]
      errors << "New child did not inherit the candidate" unless single_right?(facts["created"], 8_i64)
      errors << "New child did not retain inherited flag" unless facts["created"]["entries"][0]["flags"].as_i64 == 0x10
    when "darwin.copyfile-data", "darwin.copyfile-acl", "darwin.clonefile-default", "darwin.clonefile-acl"
      expected_flags = case id
                       when "darwin.copyfile-data" then 8_i64
                       when "darwin.copyfile-acl"  then 9_i64
                       when "darwin.clonefile-acl" then 4_i64
                       else                             0_i64
                       end
      errors << "Recipe used different native flags" unless facts["flags"].as_i64 == expected_flags
      errors << "Native transfer failed" unless facts["return_value"].as_i64 == 0
      if id.ends_with?("-acl")
        errors << "Explicit ACL transfer differs" unless facts["source"]["entries"] == facts["destination"]["entries"]
      else
        errors << "Recipe unexpectedly copied source ACL" unless facts["destination"]["entries"].as_a.empty?
      end
      errors << "Transfer changed data" unless facts["destination_data"].as_s == "fixture"
    when "darwin.raw-storage-bits"
      rows = facts["observations"].as_a
      errors << "Missing storage fixtures" unless rows.size == 4
      [0x4000_i64, 0x80000_i64, 0x2000000_i64, 0x80000000_i64].each_with_index do |rights, index|
        row = rows[index]
        errors << "Storage rights changed at #{index}" unless row["requested_rights"].as_i64 == rights && single_right?(row["captured"], rights)
        errors << "Storage flags changed at #{index}" unless row["captured"]["acl_flags"].as_i64 == 0x80020001 &&
                                                             row["captured"]["entries"][0]["flags"].as_i64 == 0x80000020
      end
      roundtrip = facts["flag_roundtrip"]
      errors << "Captured unknown flags changed" unless roundtrip["captured"]["entries"] == roundtrip["replaced"]["entries"] &&
                                                        roundtrip["captured"]["acl_flags"] == roundtrip["replaced"]["acl_flags"]
      errors << "Captured-flag replacement was not verified" unless verified_mutation?(roundtrip["mutation"])
    when "windows.capture-rights"
      rows = facts["attempts"].as_a
      errors << "Missing handle-access fixtures" unless rows.size == 4
      rows.each do |row|
        errors << "Fixture handle did not open" unless row["opened"].as_bool
        expected_complete = row["requested_access"].as_i64.in?({0x20000_i64, 0x60000_i64})
        errors << "Descriptor capture did not match handle profile" unless row["ordinary"]["complete"].as_bool == expected_complete
        errors << "Full SACL query unexpectedly completed" if row["full"]["complete"].as_bool
      end
    when "windows.token-context"
      errors << "Fresh effective selection did not fall back to process" unless facts["ordinary"]["source"].as_s == "Process"
      errors << "Self-impersonation did not select the thread" unless facts["impersonated"]["source"].as_s == "Thread"
      errors << "Explicit process selection changed under impersonation" unless facts["process"] == facts["explicit_process"]
      errors << "Reversion did not restore process fallback" unless facts["restored"] == facts["ordinary"]
      errors << "Process subject capture is incomplete" unless facts["process_subject"]["complete"].as_bool
      errors << "Effective subject capture is incomplete" unless facts["effective_subject"]["complete"].as_bool
    when "windows.owner-rights"
      errors.concat(WindowsACLWorkflows.owner_rights_violations(facts))
    when "windows.writer-files"
      errors << "Native workflow reported violations" unless facts["passed"].as_bool
      authority = facts["authority"]
      errors << "Wrong write-only handle profile" unless authority["requested_access"].as_i64 == 0x40080
      result = authority["public_result"]
      errors << "Unreadable handle reached mutation" unless result["execution"].as_s == "NotAttempted" &&
                                                            result["verification"].as_s == "NotRun" &&
                                                            result["stage"].as_s == "PreCapture" &&
                                                            authority["public_setter_calls"].as_i64 == 0
      [result["diagnostic"], authority["limited_readback_diagnostic"]].each do |diagnostic|
        errors << "Missing READ_CONTROL failure provenance" unless diagnostic["operation"].as_s == "GetSecurityInfo" &&
                                                                   diagnostic["code"].as_i64 == 5 &&
                                                                   diagnostic["origin"].as_s == "ReturnValue"
      end
      errors << "Public pre-capture refusal changed security" unless authority["before_unchanged"].as_bool
      errors << "Write-only handle unexpectedly supplied complete readback" if authority["limited_readback_complete"].as_bool
      errors.concat(writer_route_violations(authority["routes"]))
    when "windows.writer-propagation", "windows.access-check", "windows.restricted-token"
      errors << "Native workflow reported violations" unless facts["passed"].as_bool
    else
      errors << "No comparison contract for #{id}"
    end
    errors
  rescue error : KeyError | IndexError | TypeCastError
    ["Malformed or incomplete observation: #{error.message}"]
  end

  private def self.writer_route_violations(value : JSON::Any) : Array(String)
    errors = [] of String
    rows = value.as_a
    errors << "Missing setter route/handle controls" unless rows.size == 6
    expected = Set(Tuple(String, String, Int64)).new
    %w(write-only read-write).each do |profile|
      expected << {profile, "SetSecurityInfo", 4_i64}
      expected << {profile, "SetSecurityInfo", 0x80000004_i64}
      expected << {profile, "SetKernelObjectSecurity", 4_i64}
    end
    seen = Set(Tuple(String, String, Int64)).new
    rows.each do |row|
      profile, operation, information = row["profile"].as_s, row["operation"].as_s, row["information"].as_i64
      key = {profile, operation, information}
      unless expected.includes?(key) && seen.add?(key)
        errors << "Unexpected or duplicate setter route #{key}"
        next
      end
      access = profile == "write-only" ? 0x40080_i64 : 0x60080_i64
      errors << "Wrong setter handle rights for #{key}" unless row["requested_access"].as_i64 == access
      errors << "Setter did not execute exactly once for #{key}" unless row["setter_calls"].as_i64 == 1
      %w(readback_complete identity_retained owner_group_retained recovery_restored).each do |field|
        errors << "Missing setter witness #{field} for #{key}" unless row[field].as_bool
      end
      before, after = row["control_before"].as_i64, row["control_after"].as_i64
      errors << "Invalid control evidence for #{key}" unless before.in?(0..0xffff) && after.in?(0..0xffff) && before & 0x1000 != 0
      code, returned = row["code"].as_i64, row["return_value"].as_i64
      errors << "Unexpected setter error for #{key}" unless code.in?({0_i64, 5_i64})
      errors << "Readable positive setter control failed for #{key}" if profile == "read-write" && code != 0
      if operation == "SetSecurityInfo"
        errors << "SetSecurityInfo return provenance changed for #{key}" unless returned == code && row["origin"].as_s == "ReturnValue"
      else
        valid = code == 0 ? returned != 0 && row["origin"].raw.nil? : returned == 0 && row["origin"].as_s == "LastError"
        errors << "SetKernelObjectSecurity return provenance changed for #{key}" unless valid
      end
      changed, matches = row["dacl_changed"].as_bool, row["readback_matches"].as_bool
      errors << "Successful setter lacks changed matching readback for #{key}" if code == 0 && !(changed && matches)
      # A reported failure retains its independent readback, even when it
      # reveals effects. Neither failure nor a matched experiment proves rollback.
    end
    errors << "Missing distinct setter routes" unless seen == expected
    errors
  end

  private def self.same_identity?(left : JSON::Any, right : JSON::Any) : Bool
    !left["inode"].raw.nil? && !left["device"].raw.nil? &&
      left["inode"] == right["inode"] && left["device"] == right["device"]
  end

  private def self.single_right?(snapshot : JSON::Any, right : Int64) : Bool
    entries = snapshot["entries"].as_a
    entries.size == 1 && entries[0]["rights"].as_i64 == right
  end

  private def self.verified_mutation?(mutation : JSON::Any) : Bool
    mutation["execution"].as_s == "Succeeded" && mutation["verification"].as_s == "Matched"
  end

  private def self.with_fixture(& : Path -> JSON::Any) : JSON::Any
    root = Path[File.realpath(Dir.tempdir)] / "product-native-acl-#{Random::Secure.hex(16)}"
    Dir.mkdir(root, 0o700)
    begin
      yield root
    ensure
      # This random, exclusively created fixture is owned by this invocation.
      FileUtils.rm_rf(root)
    end
  end

  {% if flag?(:darwin) %}
    alias DACL = Filesystem::AccessControl::Darwin

    lib DarwinTransfer
      fun copyfile(from : UInt8*, to : UInt8*, state : Void*, flags : UInt32) : Int32
      fun clonefile(from : UInt8*, to : UInt8*, flags : UInt32) : Int32
    end

    private def self.capture(fd : Int32) : DACL::Snapshot
      snapshot = Filesystem::AccessControl.inspect_fd(fd).snapshot.not_nil!
      raise "Incomplete product ACL capture: #{snapshot.diagnostics}" unless snapshot.complete?
      snapshot
    end

    private def self.capture(path : Path) : DACL::Snapshot
      File.open(path) { |file| capture(file.fd) }
    end

    private def self.snapshot_value(snapshot : DACL::Snapshot) : JSON::Any
      json({status: snapshot.status.to_s, device: snapshot.device, inode: snapshot.inode,
            kind: snapshot.kind.try(&.to_s), mode: snapshot.mode, acl_flags: snapshot.acl_flags,
            extended_security_presence: snapshot.extended_security_presence.try(&.to_s),
            entries: snapshot.entries.map { |ace| {ordinal: ace.ordinal, principal: ace.principal.uuid.to_a,
                                                   tag: ace.raw_tag, rights: ace.rights, flags: ace.raw_flags} }})
    end

    private def self.mutation_value(result : DACL::MutationResult) : JSON::Any
      json({state: result.state.to_s, execution: result.execution.to_s,
            verification: result.verification.to_s, diagnostic: result.diagnostic.try { |item|
              {operation: item.operation, errno: item.errno, reason: item.reason.to_s}
            }})
    end

    private def self.replace(fd : Int32, rights : UInt64, flags : UInt32 = 0_u32,
                             header : UInt32 = 0_u32) : DACL::MutationResult
      entry = DACL::Ace.allow(DACL::Principal.new(DACL::WellKnownUUID::NOBODY), rights: rights, flags: flags)
      result = DACL::Writer.replace_fd(fd, target: capture(fd), acl: DACL::Builder.new([entry], header).build)
      raise "Fixture ACL write was not verified: #{result.state}, #{result.diagnostic}" unless result.verified?
      result
    end

    private def self.run_darwin(id : String, root : Path) : JSON::Any
      source = root / "source"
      File.write(source, "fixture")
      File.open(source, "r+") do |held|
        replace(held.fd, DACL::Constants::ACL_READ_ATTRIBUTES)
        before = capture(held.fd)
        facts = {"before" => snapshot_value(before)}
        case id
        when "darwin.held-unlink"
          File.delete(source)
          facts["unlinked"] = snapshot_value(capture(held.fd))
          facts["mutation"] = mutation_value(replace(held.fd, DACL::Constants::ACL_SYNCHRONIZE))
          facts["after"] = snapshot_value(capture(held.fd))
          facts["name_exists"] = json(File.exists?(source))
        when "darwin.held-replacement"
          replacement = root / "replacement"
          File.write(replacement, "replacement")
          File.open(replacement, "r+") { |file| replace(file.fd, DACL::Constants::ACL_READ_ATTRIBUTES) }
          File.rename(replacement, source)
          facts["mutation"] = mutation_value(replace(held.fd, DACL::Constants::ACL_SYNCHRONIZE))
          facts["held_after"] = snapshot_value(capture(held.fd))
          facts["path_after"] = snapshot_value(capture(source))
          facts["replacement_data"] = json(File.read(source))
        when "darwin.hardlink-alias"
          other = root / "alias"
          File.link(source, other)
          File.open(other, "r+") do |file|
            facts["mutation"] = mutation_value(replace(file.fd, DACL::Constants::ACL_SYNCHRONIZE))
          end
          facts["source"] = snapshot_value(capture(held.fd))
          facts["alias"] = snapshot_value(capture(other))
        when "darwin.move-inheritance"
          parent = root / "parent"
          Dir.mkdir(parent, 0o700)
          fd = LibC.open(parent.to_s, DACL::Constants::O_EVTONLY | LibC::O_CLOEXEC)
          raise "Parent fixture open failed: #{Errno.value}" if fd < 0
          begin
            replace(fd, DACL::Constants::ACL_EXECUTE,
              DACL::Constants::ACL_ENTRY_FILE_INHERIT | DACL::Constants::ACL_ENTRY_DIRECTORY_INHERIT)
            moved = parent / "moved"
            Filesystem::Capabilities::Directory.open_existing(root) do |origin|
              Filesystem::Capabilities::Directory.open_existing(parent) do |destination|
                origin.rename_entry_to(destination, "source", "moved")
              end
            end
            created = parent / "created"
            File.write(created, "created")
            facts["moved"] = snapshot_value(capture(moved))
            facts["created"] = snapshot_value(capture(created))
          ensure
            LibC.close(fd)
          end
        when "darwin.copyfile-data", "darwin.copyfile-acl", "darwin.clonefile-default", "darwin.clonefile-acl"
          destination = root / "destination"
          flags = case id
                  when "darwin.copyfile-data" then 8_u32
                  when "darwin.copyfile-acl"  then 9_u32
                  when "darwin.clonefile-acl" then 4_u32
                  else                             0_u32
                  end
          if id.starts_with?("darwin.copyfile")
            result = DarwinTransfer.copyfile(source.to_s, destination.to_s, Pointer(Void).null, flags)
            operation = "copyfile"
          else
            result = DarwinTransfer.clonefile(source.to_s, destination.to_s, flags)
            operation = "clonefile"
          end
          error = result < 0 ? Errno.value.value : nil
          facts["operation"] = json(operation)
          facts["flags"] = json(flags)
          facts["return_value"] = json(result)
          facts["errno"] = json(error)
          if error
            raise NativeCaseFailure.new(operation, error.to_i64, json(facts))
          end
          facts["source"] = snapshot_value(capture(held.fd))
          facts["destination"] = snapshot_value(capture(destination))
          facts["destination_data"] = json(File.read(destination))
        when "darwin.raw-storage-bits"
          rows = [] of JSON::Any
          [0x4000_u64, 0x80000_u64, 0x2000000_u64, 0x80000000_u64].each do |rights|
            # Native import accepts these storage bits independently of the
            # public writer's stricter native-constructor boundary.
            seed_unknown_storage(held.fd, rights)
            captured = capture(held.fd)
            rows << json({requested_rights: rights, captured: snapshot_value(captured)})
          end
          facts["observations"] = json(rows)
          seed_unknown_storage(held.fd, DACL::Constants::ACL_READ_ATTRIBUTES)
          captured = capture(held.fd)
          result = DACL::Writer.replace_fd(held.fd, target: captured, acl: DACL::Builder.from(captured).build)
          facts["flag_roundtrip"] = json({captured: snapshot_value(captured),
                                          mutation: mutation_value(result), replaced: snapshot_value(capture(held.fd))})
        else
          raise ArgumentError.new("Unknown Darwin case: #{id}")
        end
        json(facts)
      end
    end

    private def self.seed_unknown_storage(fd : Int32, rights : UInt64) : Nil
      entry = DACL::Ace.allow(DACL::Principal.new(DACL::WellKnownUUID::NOBODY),
        rights: rights, flags: 0x80000020_u32)
      exported = DACL::ExternalACL.encode([entry], 0x80020001_u32)
      acl = Filesystem::AccessControl::Native::Darwin::ACL.acl_copy_int(exported.to_unsafe.as(Void*))
      raise "Native storage fixture decode failed: #{Errno.value}" if acl.null?
      begin
        result = Filesystem::AccessControl::Native::Darwin::ACL.acl_set_fd_np(fd, acl, DACL::Constants::ACL_TYPE_EXTENDED)
        raise "Native storage fixture installation failed: #{Errno.value}" unless result == 0
      ensure
        Filesystem::AccessControl::Native::Darwin::ACL.acl_free(acl)
      end
    end
  {% end %}

  {% if flag?(:windows) %}
    alias WACL = Filesystem::AccessControl::Windows

    @[Link("advapi32")]
    lib WindowsExperiment
      fun impersonate_self = ImpersonateSelf(level : UInt32) : Int32
      fun revert_to_self = RevertToSelf : Int32
    end

    private def self.diagnostic_value(item : WACL::Diagnostic?) : JSON::Any
      json(item.try { |diagnostic| {operation: diagnostic.operation, code: diagnostic.code,
                                    origin: diagnostic.origin.to_s, message: diagnostic.message} })
    end

    private def self.windows_snapshot_value(snapshot : WACL::Snapshot) : JSON::Any
      json({complete: snapshot.complete?, information: snapshot.queried_information,
            control: snapshot.control, owner: snapshot.owner.try(&.bytes.hexstring),
            group: snapshot.group.try(&.bytes.hexstring), dacl_presence: snapshot.dacl_presence.to_s,
            sacl_presence: snapshot.sacl_presence.to_s, descriptor_hex: snapshot.raw_descriptor.try(&.hexstring),
            diagnostic: diagnostic_value(snapshot.diagnostic)})
    end

    private def self.token_value(snapshot : WACL::TokenSnapshot) : JSON::Any
      json({complete: snapshot.complete?, context: snapshot.context.to_s,
            source: snapshot.source.try(&.to_s), user: snapshot.identity.try(&.user.bytes.hexstring),
            type: snapshot.identity.try(&.type.to_s),
            impersonation_level: snapshot.identity.try(&.impersonation_level.try(&.to_s)),
            diagnostic: diagnostic_value(snapshot.diagnostic)})
    end

    private def self.field_value(observation : WACL::TokenObservation(T), &block : T -> JSON::Any) : JSON::Any forall T
      value = observation.value
      json({state: observation.state.to_s,
            value: value.nil? ? nil : yield(value), diagnostic: diagnostic_value(observation.diagnostic)})
    end

    private def self.subject_value(snapshot : WACL::TokenSubjectSnapshot) : JSON::Any
      json({complete: snapshot.complete?, information: snapshot.information.value,
            token: token_value(snapshot.token),
            groups: field_value(snapshot.groups) { |list| sid_list_value(list) },
            restricted_sids: field_value(snapshot.restricted_sids) { |list| sid_list_value(list) },
            privileges: field_value(snapshot.privileges) { |list|
              json(list.entries.map { |entry| {luid_low: entry.luid_low, luid_high: entry.luid_high,
                                               attributes: entry.attributes} })
            },
            integrity: field_value(snapshot.integrity) { |entry| json({sid: entry.sid.bytes.hexstring, attributes: entry.attributes}) },
            elevation_type: field_value(snapshot.elevation_type) { |value| json(value.to_s) },
            elevated: field_value(snapshot.elevated) { |value| json(value) },
            has_restrictions: field_value(snapshot.has_restrictions) { |value| json(value) }})
    end

    private def self.sid_list_value(list : WACL::TokenSIDList) : JSON::Any
      json(list.entries.map { |entry| {sid: entry.sid.bytes.hexstring, attributes: entry.attributes} })
    end

    private def self.run_windows(id : String, root : Path) : JSON::Any
      case id
      when "windows.writer-files", "windows.writer-propagation", "windows.access-check", "windows.restricted-token", "windows.owner-rights"
        WindowsACLWorkflows.run(id)
      when "windows.capture-rights"
        path = root / "file"
        File.write(path, "fixture")
        units = path.to_s.to_utf16
        name = Slice(UInt16).new(units.size + 1, 0_u16)
        units.copy_to(name)
        rows = [] of JSON::Any
        [0_u32, 0x20000_u32, 0x40000_u32, 0x60000_u32].each do |access|
          handle = LibC.CreateFileW(name.to_unsafe, access, 7_u32,
            Pointer(LibC::SECURITY_ATTRIBUTES).null, 3_u32, 0x02200000_u32, Pointer(Void).null)
          if handle == LibC::INVALID_HANDLE_VALUE
            code = LibC.GetLastError
            rows << json({requested_access: access, opened: false, open_error: code})
            next
          end
          begin
            ordinary = WACL::Reader.capture(handle)
            owner = WACL::Reader.capture(handle, information: WACL::SecurityInformation::Owner)
            full = WACL::Reader.capture(handle, information: WACL::SecurityInformation::All)
            rows << json({requested_access: access, opened: true, open_error: nil,
                          ordinary: windows_snapshot_value(ordinary), owner: windows_snapshot_value(owner),
                          full: windows_snapshot_value(full)})
          ensure
            LibC.CloseHandle(handle)
          end
        end
        json({attempts: rows})
      when "windows.token-context"
        process = WACL::TokenReader.capture(WACL::TokenContext::Process)
        ordinary = WACL::TokenReader.capture(WACL::TokenContext::Effective)
        subject = WACL::TokenReader.capture_subject(WACL::TokenContext::Process)
        if WindowsExperiment.impersonate_self(2_u32) == 0
          code = LibC.GetLastError
          raise NativeCaseFailure.new("ImpersonateSelf", code.to_i64)
        end
        begin
          impersonated = WACL::TokenReader.capture(WACL::TokenContext::Effective)
          explicit_process = WACL::TokenReader.capture(WACL::TokenContext::Process)
          effective_subject = WACL::TokenReader.capture_subject(WACL::TokenContext::Effective)
        ensure
          # The calling harness must discard this process if cleanup fails.
          if WindowsExperiment.revert_to_self == 0
            abort "RevertToSelf failed: #{LibC.GetLastError}"
          end
        end
        restored = WACL::TokenReader.capture(WACL::TokenContext::Effective)
        json({process: token_value(process), ordinary: token_value(ordinary),
              process_subject: subject_value(subject), impersonated: token_value(impersonated),
              explicit_process: token_value(explicit_process), effective_subject: subject_value(effective_subject),
              restored: token_value(restored)})
      else
        raise ArgumentError.new("Unknown Windows case: #{id}")
      end
    end
  {% end %}
end
