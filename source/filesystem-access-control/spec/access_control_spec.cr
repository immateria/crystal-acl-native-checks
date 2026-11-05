require "./spec_helper"
require "../src/filesystem-access-control"

describe "ACL report safety invariants" do
  it "never certifies unavailable or inconsistent ACL observations" do
    entries = [] of Filesystem::AccessControl::Entry
    [Filesystem::AccessControl::State::Unavailable, Filesystem::AccessControl::State::Unrestricted, Filesystem::AccessControl::State::Unsupported].each do |state|
      report = Filesystem::AccessControl::Report.new(nil, :fixture, true, 0o700,
        entries, entries, state, true)
      report.private?.should be_false
      report.private_result.should be_false
      expect_raises(Filesystem::AccessControl::InsecureAccessError) { report.require_private! }
    end
    missing_owner = Filesystem::AccessControl::Report.new(nil, :fixture, nil, 0o700,
      entries, entries, Filesystem::AccessControl::State::None, true)
    missing_owner.private?.should be_false
    reported_failure = Filesystem::AccessControl::Report.new(nil, :fixture, true, 0o700,
      entries, entries, Filesystem::AccessControl::State::Present, true, "inspection failed")
    reported_failure.private?.should be_false
    inconsistent_entries = Filesystem::AccessControl::Report.new(nil, :fixture, true, 0o700,
      [{% if flag?(:linux) %}Filesystem::AccessControl::Linux::Entry.user(123_u32, Filesystem::AccessControl::Linux::Permissions::Read){% else %}Filesystem::AccessControl::Entry.new("user:123", 4_u32){% end %}], entries,
      Filesystem::AccessControl::State::None, true)
    inconsistent_entries.private?.should be_false
    valid = Filesystem::AccessControl::Report.new(nil, :fixture, true, 0o700,
      entries, entries, Filesystem::AccessControl::State::None, true)
    valid.require_private!.private?.should be_true
  end
end

{% if flag?(:linux) %}
  @[Link("c")]
  lib LibACLFixture
    fun fsetxattr(fd : Int32, name : UInt8*, value : Void*, size : LibC::SizeT, flags : Int32) : Int32
  end

  module ACLFixture
    # Linux posix_acl_xattr ABI, version 2 and 8-byte entries.
    def self.bytes(entries : Array(Tuple(UInt16, UInt16, UInt32))) : Bytes
      result = Bytes.new(4 + entries.size * 8)
      result[0] = 2_u8
      entries.each_with_index do |(tag, rights, id), index|
        at = 4 + index * 8
        result[at] = (tag & 0xff).to_u8
        result[at + 1] = (tag >> 8).to_u8
        result[at + 2] = (rights & 0xff).to_u8
        result[at + 3] = (rights >> 8).to_u8
        4.times { |j| result[at + 4 + j] = ((id >> (8 * j)) & 0xff).to_u8 }
      end
      result
    end

    def self.put(path : Path, key : String, entries : Array(Tuple(UInt16, UInt16, UInt32)), *, directory : Bool = true)
      flags = LibC::O_RDONLY | LibC::O_CLOEXEC | LibC::O_NOFOLLOW
      flags |= Filesystem::Capabilities::Platform::DIRECTORY_ONLY if directory
      fd = LibC.open(path.to_s, flags)
      raise "test ACL fixture could not open" if fd < 0
      begin
        value = bytes(entries)
        if LibACLFixture.fsetxattr(fd, key, value.to_unsafe.as(Void*), value.size, 0) != 0
          raise "test ACL setup failed: #{Errno.value}"
        end
      ensure
        LibC.close(fd)
      end
    end
  end

  describe Filesystem::AccessControl do
    it "refuses raw ACLs the kernel would not store, and ones that disagree with the mode" do
      access = "system.posix_acl_access"
      owner = {0x01_u16, 7_u16, 0_u32}
      group = {0x04_u16, 0_u16, 0_u32}
      other = {0x20_u16, 0_u16, 0_u32}
      named = {0x02_u16, 7_u16, 1000_u32}
      mask = {0x10_u16, 0_u16, 0_u32}
      parsed = Filesystem::AccessControl::Linux::Codec.decode(ACLFixture.bytes([owner, group, other]), mode: 0o700)
      parsed.diagnostic.should be_nil
      parsed.acl.not_nil!.entries.map(&.tag).should eq([Filesystem::AccessControl::Linux::Tag::Owner, Filesystem::AccessControl::Linux::Tag::OwningGroup, Filesystem::AccessControl::Linux::Tag::Other])
      Filesystem::AccessControl::Linux::Codec.decode(ACLFixture.bytes([owner, named, group, mask, other]), mode: 0o700).diagnostic.should be_nil
      Filesystem::AccessControl::Linux::Codec.decode(ACLFixture.bytes([owner, group, mask, other]), mode: 0o700).diagnostic.should be_nil

      # As fs/posix_acl.c's posix_acl_valid refuses them.
      malformed = {
        "empty"             => [] of Tuple(UInt16, UInt16, UInt32),
        "no other"          => [owner, group],
        "no owning group"   => [owner, other],
        "two owners"        => [owner, owner, group, other],
        "group first"       => [group, owner, other],
        "two masks"         => [owner, group, mask, mask, other],
        "named, no mask"    => [owner, named, group, other],
        "named after group" => [owner, group, named, mask, other],
        "after other"       => [owner, group, other, other],
      }
      # The kernel keeps the base entries in step with the mode.
      disagreeing = {
        "group grants"     => [owner, {0x04_u16, 5_u16, 0_u32}, other],
        "other grants"     => [owner, group, {0x20_u16, 4_u16, 0_u32}],
        "owner differs"    => [{0x01_u16, 6_u16, 0_u32}, group, other],
        "mask grants"      => [owner, group, {0x10_u16, 5_u16, 0_u32}, other],
      }
      accepted = [] of String
      malformed.merge(disagreeing).each do |name, list|
        accepted << name unless Filesystem::AccessControl::Linux::Codec.decode(ACLFixture.bytes(list), mode: 0o700).diagnostic
      end
      accepted.should be_empty
      # A default ACL has no mode to agree with.
      Filesystem::AccessControl::Linux::Codec.decode(ACLFixture.bytes(disagreeing["group grants"]),
        kind: Filesystem::AccessControl::Linux::ACLKind::Default).diagnostic.should be_nil
    end

    it "retains ACL report entry snapshots across caller mutations" do
      entry = Filesystem::AccessControl::Linux::Entry.user(123_u32, Filesystem::AccessControl::Linux::Permissions::Read)
      default = Filesystem::AccessControl::Linux::Entry.group(456_u32, Filesystem::AccessControl::Linux::Permissions::Execute)
      original_access = [entry]
      original_defaults = [default]
      report = Filesystem::AccessControl::Report.new(nil, :fixture, true, 0o700,
        original_access, original_defaults, Filesystem::AccessControl::State::Present, false)

      # Incoming arrays and returned arrays must never be the report's buffers.
      original_access.clear
      original_defaults.clear
      report.access_entries.should eq([entry])
      report.default_entries.should eq([default])

      exposed_access = report.access_entries
      exposed_defaults = report.default_entries
      exposed_access.clear
      exposed_defaults.clear
      report.access_entries.should eq([entry])
      report.default_entries.should eq([default])
      report.private?.should be_false
      expect_raises(Filesystem::AccessControl::InsecureAccessError) { report.require_private! }
    end

    it "captures a regular file from its opened descriptor" do
      SpecEnvironment.with_temp_dir("acl-target") do |folder|
        path = Path[folder] / "private-file"
        File.write(path, "private")
        File.chmod(path, 0o600)
        fd = LibC.open(path.to_s, LibC::O_RDONLY | LibC::O_CLOEXEC | LibC::O_NOFOLLOW)
        raise "cannot open ACL target fixture: #{Errno.value}" if fd < 0
        begin
          report = Filesystem::AccessControl.inspect_fd(fd, expected: Filesystem::AccessControl::Target::File)
          report.require_private!
          report.mode.should eq(0o600)
          {% if flag?(:darwin) %}
            report.snapshot.not_nil!.kind.should eq(Filesystem::AccessControl::Darwin::Kind::File)
          {% end %}
        ensure
          LibC.close(fd)
        end
      end
    end

    it "reports private 0700, rejects world-readable paths and final symlinks" do
      SpecEnvironment.with_temp_dir("acl-basic") do |folder|
        private_path = Path[folder] / "private"
        Dir.mkdir(private_path, 0o700)
        report = Filesystem::AccessControl.inspect_directory(private_path)
        report.backend.should eq(:linux_posix_acl)
        report.owner_matches.should be_true
        report.mode.should eq(0o700)
        report.acl_state.should eq(Filesystem::AccessControl::State::None)
        report.require_private!.should eq(report)
        File.chmod(private_path, 0o755)
        exposed = Filesystem::AccessControl.inspect_directory(private_path)
        exposed.private?.should be_false
        expect_raises(Filesystem::AccessControl::InsecureAccessError) { exposed.require_private! }
        File.symlink(private_path, Path[folder] / "link")
        expect_raises(Filesystem::Capabilities::Error) { Filesystem::AccessControl.inspect_directory(Path[folder] / "link") }
      end
    end

    it "rejects terminal path ambiguity before opening a standalone ACL root" do
      SpecEnvironment.with_temp_dir("acl-root-grammar") do |folder|
        root = Path[folder] / "private"
        link = Path[folder] / "alias"
        Dir.mkdir(root, 0o700)
        File.symlink(root, link)
        Filesystem::AccessControl.inspect_directory(root).require_private!
        [Path["#{link}/"], Path["#{link}//"], Path["#{link}/."],
         Path["#{link}/.."], Path["#{root}/"], Path["#{root}/."],
         Path["#{root}/.."], Path["relative/path"]].each do |ambiguous|
          expect_raises(ArgumentError) { Filesystem::AccessControl.inspect_directory(ambiguous) }
        end
        # Ordinary final-component symlinks must still fail at the syscall.
        expect_raises(Filesystem::Capabilities::Error) do
          Filesystem::AccessControl.inspect_directory(link)
        end
      end
    end

    it "inspects named access entries and effective masks without trusting masked grants" do
      SpecEnvironment.with_temp_dir("acl-access") do |folder|
        path = Path[folder] / "private"
        Dir.mkdir(path, 0o700)
        ACLFixture.put(path, "system.posix_acl_access", [
          {0x01_u16, 7_u16, UInt32::MAX}, # owner rwx
          {0x02_u16, 4_u16, 12345_u32},   # additional user r--
          {0x04_u16, 0_u16, UInt32::MAX}, # group
          {0x10_u16, 0_u16, UInt32::MAX}, # mask (currently denies named user)
          {0x20_u16, 0_u16, UInt32::MAX}, # other
        ])
        report = Filesystem::AccessControl.inspect_directory(path)
        report.acl_state.should eq(Filesystem::AccessControl::State::Present)
        entry = report.access_entries.find { |e| e.tag.user? && e.id == 12345_u32 }.not_nil!
        entry.permissions.should eq(Filesystem::AccessControl::Linux::Permissions::Read)
        report.snapshot.not_nil!.access.not_nil!.masked_permissions(entry).should eq(Filesystem::AccessControl::Linux::Permissions::None)
        report.mode.should eq(0o700)
        report.private?.should be_false
        expect_raises(Filesystem::AccessControl::InsecureAccessError) { report.require_private! }
      end
    end

    it "inspects inheritable defaults and refuses to attest future-file privacy" do
      SpecEnvironment.with_temp_dir("acl-default") do |folder|
        path = Path[folder] / "private"
        Dir.mkdir(path, 0o700)
        ACLFixture.put(path, "system.posix_acl_default", [
          {0x01_u16, 7_u16, UInt32::MAX},
          {0x04_u16, 0_u16, UInt32::MAX},
          {0x20_u16, 0_u16, UInt32::MAX},
        ])
        report = Filesystem::AccessControl.inspect_directory(path)
        report.default_entries.size.should eq(3)
        report.snapshot.not_nil!.default_acl.should_not be_nil
        report.private?.should be_false
      end
    end

    it "preserves ACL attestation on a readable child opened as an ordinary capability" do
      SpecEnvironment.with_temp_dir("acl-child-read-access") do |folder|
        root = Path[folder] / "root"
        Dir.mkdir(root, 0o700)
        Dir.mkdir(root / "child", 0o700)
        Filesystem::Capabilities::Directory.open_existing(root) do |directory|
          directory.open_subdirectory("child") do |child|
            child.require_private!.private?.should be_true
            child.entry_names.should be_empty
          end
          directory.open_subdirectory("child", mount: :stay_on_root_mount) do |child|
            child.require_private!.private?.should be_true
          end
        end
      end
    end

    it "pins capability ACL inspection to the opened inode and synchronizes with closure" do
      SpecEnvironment.with_temp_dir("acl-pin") do |folder|
        root = Path[folder] / "root"
        renamed = Path[folder] / "original"
        replacement = Path[folder] / "replacement"
        Dir.mkdir(root, 0o700)
        Dir.mkdir(replacement, 0o755)
        cap = Filesystem::Capabilities::Directory.open_existing(root)
        begin
          File.rename(root, renamed)
          File.symlink(replacement, root)
          cap.access_report.mode.should eq(0o700)
          cap.require_private!.private?.should be_true
          cap.close
          expect_raises(Filesystem::Capabilities::Error, /closed/) { cap.access_report }
        ensure
          cap.close
        end
      end
    end
  end
{% end %}

{% if flag?(:darwin) || flag?(:windows) %}
  describe Filesystem::AccessControl do
    it "inspects the host-native ACL backend and refuses a final symlink" do
      SpecEnvironment.with_temp_dir("directories-native-acl") do |folder|
        root = Path[folder] / "native"
        Dir.mkdir(root)
        report = Filesystem::AccessControl.inspect_directory(root)
        report.backend.should eq({% if flag?(:windows) %}:windows_dacl{% else %}:darwin_extended_acl{% end %})
        report.acl_state.in?({% if flag?(:windows) %}[Filesystem::AccessControl::State::Present, Filesystem::AccessControl::State::Unrestricted]{% else %}[Filesystem::AccessControl::State::None, Filesystem::AccessControl::State::Present]{% end %}).should be_true
        report.owner_matches.should_not be_nil
        {% if flag?(:windows) %}
          # Windows normally has an explicit DACL on a newly created directory.
          report.acl_state.should eq(Filesystem::AccessControl::State::Present)
        {% else %}
          report.owner_matches.should be_true
        {% end %}
        {% if flag?(:darwin) %}
          File.symlink(root, Path[folder] / "link")
          expect_raises(Filesystem::Capabilities::Error) do
            Filesystem::AccessControl.inspect_directory(Path[folder] / "link")
          end
        {% else %}
          File.write(Path[folder] / "not-a-directory", "wrong kind")
          expect_raises(Filesystem::Capabilities::Error) do
            Filesystem::AccessControl.inspect_directory(Path[folder] / "not-a-directory")
          end
        {% end %}
      end
    end
  end
{% end %}
