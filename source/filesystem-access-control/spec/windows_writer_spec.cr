require "./spec_helper"
require "../src/filesystem_access_control/windows/writer"

alias WriteWindows = Filesystem::AccessControl::Windows

private module WindowsWriteFixtures
  def self.security(acl = WriteWindows::ACL.new("0200080000000000".hexbytes), control = 0x9004_u16)
    bytes = "010000001400000020000000000000002c000000".hexbytes
    IO::ByteFormat::LittleEndian.encode(control, bytes[2, 2])
    sid = "010100000000000512000000".hexbytes
    WriteWindows::Snapshot.new(WriteWindows::SecurityDescriptor.new(bytes + sid + sid + acl.bytes))
  end

  def self.target(acl = WriteWindows::ACL.new("0200080000000000".hexbytes), *, id = 7_u8, attributes = 0_u32, control = 0x9004_u16)
    metadata = WriteWindows::FileMetadata.new(WriteWindows::FileIdentity.new(10_u64, Bytes.new(16, id)), attributes)
    WriteWindows::HandleSnapshot.new(security(acl, control), metadata, metadata)
  end

  def self.acl
    WriteWindows::ACL.new("02001c00010000000000140001000000010100000000000512000000".hexbytes)
  end

  def self.absent_target
    bytes = "0100009014000000200000000000000000000000010100000000000512000000010100000000000512000000".hexbytes
    security = WriteWindows::Snapshot.new(WriteWindows::SecurityDescriptor.new(bytes))
    metadata = WriteWindows::FileMetadata.new(WriteWindows::FileIdentity.new(10_u64, Bytes.new(16, 7_u8)), 0_u32)
    WriteWindows::HandleSnapshot.new(security, metadata, metadata)
  end
end

# The native setter and captures are the unavailable Windows boundaries.
# The real writer validates, chooses flags and classifies all evidence.
private class WindowsWriteProvider
  getter writes = [] of Tuple(UInt32, String)
  getter captures = 0
  property code = 0_u32
  property invalid_acl = false
  property effect : Proc(Nil)?

  def initialize(@observations : Array(WriteWindows::HandleSnapshot))
  end

  def capture(handle : Void*)
    handle.address.should eq(123_u64)
    value = @observations[@captures]
    @captures += 1
    value
  end

  def validate(acl : WriteWindows::ACL)
    @invalid_acl ? WriteWindows::Diagnostic.new("IsValidAcl", nil,
      WriteWindows::ErrorOrigin::Validation, "Invalid native ACL") : nil
  end

  def replace(handle : Void*, acl : WriteWindows::ACL, information : UInt32)
    handle.address.should eq(123_u64)
    @writes << {information, acl.bytes.hexstring}
    @effect.try(&.call)
    @code
  end
end

describe WriteWindows::Writer do
  handle = Pointer(Void).new(123_u64)
  inheritance = WriteWindows::InheritancePolicy::PreserveObserved
  propagation = WriteWindows::PropagationPolicy::TargetOnly

  it "executes even identical replacements and verifies fresh observations" do
    initial = WindowsWriteFixtures.target
    provider = WindowsWriteProvider.new([initial, initial])
    result = WriteWindows::Writer.replace_dacl_handle(handle, target: initial,
      dacl: initial.security.dacl.not_nil!, inheritance: inheritance, propagation: propagation, provider: provider)
    result.execution.succeeded?.should be_true
    result.verification.matched?.should be_true
    result.applied?.should be_true
    result.verified?.should be_true
    result.before.should eq(initial)
    result.after.should eq(initial)
    provider.writes.should eq([{0x80000004_u32, "0200080000000000"}])
    provider.captures.should eq(2)
  end

  it "uses fresh protection rather than treating the supplied ACL as a revision" do
    old = WindowsWriteFixtures.target(control: 0x8004_u16)
    fresh = WindowsWriteFixtures.target
    provider = WindowsWriteProvider.new([fresh, fresh])
    result = WriteWindows::Writer.replace_dacl_handle(handle, target: old,
      dacl: fresh.security.dacl.not_nil!, inheritance: inheritance, propagation: propagation, provider: provider)
    result.verified?.should be_true
    provider.writes.first[0].should eq(0x80000004_u32)
  end

  it "treats absent-to-present DACL installation as a requested postcondition" do
    initial = WindowsWriteFixtures.absent_target
    initial.security.dacl_presence.absent?.should be_true
    after = WindowsWriteFixtures.target(WindowsWriteFixtures.acl)
    provider = WindowsWriteProvider.new([initial, after])
    result = WriteWindows::Writer.replace_dacl_handle(handle, target: initial,
      dacl: WindowsWriteFixtures.acl, inheritance: inheritance, propagation: propagation, provider: provider)
    result.execution.succeeded?.should be_true
    result.verification.matched?.should be_true
    result.normalizations.should be_empty
    provider.writes.size.should eq(1)
    provider.captures.should eq(2)
  end

  it "records auto-inheritance separately from absent-to-present DACL installation" do
    initial = WindowsWriteFixtures.absent_target
    after = WindowsWriteFixtures.target(WindowsWriteFixtures.acl, control: 0x9404_u16)
    provider = WindowsWriteProvider.new([initial, after])
    result = WriteWindows::Writer.replace_dacl_handle(handle, target: initial,
      dacl: WindowsWriteFixtures.acl, inheritance: inheritance, propagation: propagation, provider: provider)
    result.execution.succeeded?.should be_true
    result.verification.matched?.should be_true
    result.normalizations.should eq([WriteWindows::Normalization::DaclAutoInherited])
    provider.writes.size.should eq(1)
  end

  it "preserves a freshly unprotected DACL even when the supplied target was protected" do
    old = WindowsWriteFixtures.target
    fresh = WindowsWriteFixtures.target(control: 0x8004_u16)
    provider = WindowsWriteProvider.new([fresh, fresh])
    result = WriteWindows::Writer.replace_dacl_handle(handle, target: old,
      dacl: fresh.security.dacl.not_nil!, inheritance: inheritance, propagation: propagation, provider: provider)
    result.verified?.should be_true
    provider.writes.should eq([{0x20000004_u32, "0200080000000000"}])
    provider.captures.should eq(2)
  end

  it "refuses incomplete, substituted and reparse targets before the setter" do
    initial = WindowsWriteFixtures.target
    invalid = [WriteWindows::HandleSnapshot.new(WriteWindows::Snapshot.new),
               WindowsWriteFixtures.target(id: 8_u8), WindowsWriteFixtures.target(attributes: 0x400_u32)]
    invalid.each do |fresh|
      provider = WindowsWriteProvider.new([fresh])
      result = WriteWindows::Writer.replace_dacl_handle(handle, target: initial,
        dacl: WindowsWriteFixtures.acl, inheritance: inheritance, propagation: propagation, provider: provider)
      result.execution.not_attempted?.should be_true
      result.verification.not_run?.should be_true
      provider.writes.should be_empty
    end
  end

  it "does not claim target-only directory mutation through a propagating API" do
    directory = WindowsWriteFixtures.target(attributes: 0x10_u32)
    provider = WindowsWriteProvider.new([directory])
    refused = WriteWindows::Writer.replace_dacl_handle(handle, target: directory,
      dacl: WindowsWriteFixtures.acl, inheritance: inheritance, propagation: propagation, provider: provider)
    refused.execution.not_attempted?.should be_true
    provider.writes.should be_empty
    provider = WindowsWriteProvider.new([directory, directory])
    applied = WriteWindows::Writer.replace_dacl_handle(handle, target: directory,
      dacl: directory.security.dacl.not_nil!, inheritance: inheritance,
      propagation: WriteWindows::PropagationPolicy::NativePropagation, provider: provider)
    applied.verified?.should be_true
    applied.descendants.unverified?.should be_true
  end

  it "retains mutator failure without readback, retry or a rollback claim" do
    initial = WindowsWriteFixtures.target
    provider = WindowsWriteProvider.new([initial])
    provider.code = 5_u32
    result = WriteWindows::Writer.replace_dacl_handle(handle, target: initial,
      dacl: WindowsWriteFixtures.acl, inheritance: inheritance, propagation: propagation, provider: provider)
    result.execution.failed?.should be_true
    result.verification.not_run?.should be_true
    result.applied?.should be_false
    result.after.should be_nil
    result.diagnostic.not_nil!.code.should eq(5_u32)
    result.diagnostic.not_nil!.origin.return_value?.should be_true
    provider.writes.size.should eq(1)
    provider.captures.should eq(1)
  end

  it "keeps directory descendants unverified after a failed propagating setter" do
    directory = WindowsWriteFixtures.target(attributes: 0x10_u32)
    provider = WindowsWriteProvider.new([directory])
    provider.code = 5_u32
    result = WriteWindows::Writer.replace_dacl_handle(handle, target: directory,
      dacl: WindowsWriteFixtures.acl, inheritance: inheritance,
      propagation: WriteWindows::PropagationPolicy::NativePropagation, provider: provider)
    result.execution.failed?.should be_true
    result.verification.not_run?.should be_true
    result.stage.mutation?.should be_true
    result.descendants.unverified?.should be_true
    result.after.should be_nil
    result.diagnostic.not_nil!.code.should eq(5_u32)
    provider.writes.size.should eq(1)
    provider.captures.should eq(1)
  end

  it "retains provider failure after an observable side effect without replay or rollback" do
    SpecEnvironment.with_temp_dir("acl-windows-provider-side-effect") do |directory|
      path = File.join(directory, "effect.txt")
      File.write(path, "before")
      initial = WindowsWriteFixtures.target
      provider = WindowsWriteProvider.new([initial])
      provider.code = 5_u32
      provider.effect = -> do
        File.write(path, File.read(path) + ":effect")
        nil
      end
      result = WriteWindows::Writer.replace_dacl_handle(handle, target: initial,
        dacl: WindowsWriteFixtures.acl, inheritance: inheritance, propagation: propagation, provider: provider)
      result.execution.failed?.should be_true
      result.state.rejected?.should be_true
      result.verification.not_run?.should be_true
      result.applied?.should be_false
      result.after.should be_nil
      result.diagnostic.not_nil!.operation.should eq("SetSecurityInfo")
      result.diagnostic.not_nil!.code.should eq(5_u32)
      File.read(path).should eq("before:effect")
      provider.writes.size.should eq(1)
      provider.captures.should eq(1)
    end
  end

  it "retains failed directory mutation with mixed observable effects and unverified descendants" do
    # Provider/state-machine coverage: these ordinary files witness simulated
    # side effects. This does not reproduce a native ACL propagation failure.
    SpecEnvironment.with_temp_dir("acl-windows-provider-partial-tree") do |root|
      paths = ["target", "updated-child", "denied-child"].map { |name| File.join(root, name) }
      paths.each { |path| File.write(path, "before") }
      directory = WindowsWriteFixtures.target(attributes: 0x10_u32)
      provider = WindowsWriteProvider.new([directory])
      provider.code = 5_u32
      provider.effect = -> do
        paths[0, 2].each { |path| File.write(path, File.read(path) + ":effect") }
        nil
      end
      result = WriteWindows::Writer.replace_dacl_handle(handle, target: directory,
        dacl: WindowsWriteFixtures.acl, inheritance: inheritance,
        propagation: WriteWindows::PropagationPolicy::NativePropagation, provider: provider)
      result.state.rejected?.should be_true
      result.execution.failed?.should be_true
      result.verification.not_run?.should be_true
      result.stage.mutation?.should be_true
      result.descendants.unverified?.should be_true
      result.after.should be_nil
      result.diagnostic.not_nil!.code.should eq(5_u32)
      paths.map { |path| File.read(path) }.should eq(["before:effect", "before:effect", "before"])
      provider.writes.size.should eq(1)
      provider.captures.should eq(1)
    end
  end

  it "distinguishes valid mismatch, missing readback and post-write substitution" do
    initial = WindowsWriteFixtures.target
    afters = [initial, WriteWindows::HandleSnapshot.new(WriteWindows::Snapshot.new),
              WindowsWriteFixtures.target(WindowsWriteFixtures.acl, id: 8_u8)]
    afters.each_with_index do |after, index|
      provider = WindowsWriteProvider.new([initial, after])
      result = WriteWindows::Writer.replace_dacl_handle(handle, target: initial,
        dacl: WindowsWriteFixtures.acl, inheritance: inheritance, propagation: propagation, provider: provider)
      result.execution.succeeded?.should be_true
      result.applied?.should be_true
      result.verified?.should be_false
      result.verification.should eq(index == 1 ? Filesystem::AccessControl::MutationVerification::Unavailable : Filesystem::AccessControl::MutationVerification::Mismatched)
      result.after.should eq(after)
      provider.writes.size.should eq(1)
    end
  end

  it "keeps successful execution unverified when post-write capture fails or becomes a reparse point" do
    initial = WindowsWriteFixtures.target(WindowsWriteFixtures.acl)
    diagnostic = WriteWindows::Diagnostic.new("GetSecurityInfo", 5_u32,
      WriteWindows::ErrorOrigin::ReturnValue, "denied")
    failed = WriteWindows::HandleSnapshot.new(WriteWindows::Snapshot.new(diagnostic: diagnostic),
      initial.metadata_before, diagnostic: diagnostic)
    reparse = WindowsWriteFixtures.target(WindowsWriteFixtures.acl, attributes: 0x400_u32)
    [failed, reparse].each do |after|
      provider = WindowsWriteProvider.new([initial, after])
      result = WriteWindows::Writer.replace_dacl_handle(handle, target: initial,
        dacl: WindowsWriteFixtures.acl, inheritance: inheritance, propagation: propagation, provider: provider)
      result.execution.succeeded?.should be_true
      result.verification.unavailable?.should be_true
      result.state.applied_unverified?.should be_true
      result.stage.post_capture?.should be_true
      result.applied?.should be_true
      result.verified?.should be_false
      result.after.should eq(after)
      provider.writes.size.should eq(1)
      provider.captures.should eq(2)
    end
  end

  it "rejects owner or group changes even when the requested DACL readback matches" do
    initial = WindowsWriteFixtures.target(WindowsWriteFixtures.acl)
    # Owner SID's RID starts at byte 28; the group SID's RID starts at 40.
    [28, 40].each do |position|
      bytes = initial.security.raw_descriptor.not_nil!
      bytes[position] = 0x13_u8
      security = WriteWindows::Snapshot.new(WriteWindows::SecurityDescriptor.new(bytes))
      after = WriteWindows::HandleSnapshot.new(security, initial.metadata_before, initial.metadata_after)
      after.complete?.should be_true
      after.security.dacl.should eq(initial.security.dacl)
      provider = WindowsWriteProvider.new([initial, after])
      result = WriteWindows::Writer.replace_dacl_handle(handle, target: initial,
        dacl: WindowsWriteFixtures.acl, inheritance: inheritance, propagation: propagation, provider: provider)
      result.execution.succeeded?.should be_true
      result.verification.mismatched?.should be_true
      result.state.applied_unverified?.should be_true
      result.stage.verification?.should be_true
      result.applied?.should be_true
      result.after.should eq(after)
      provider.writes.size.should eq(1)
      provider.captures.should eq(2)
    end
  end

  it "accepts only the named auto-inherited control change" do
    initial = WindowsWriteFixtures.target(WindowsWriteFixtures.acl)
    [0x9404_u16, 0x8004_u16, 0x9104_u16].each do |control|
      after = WindowsWriteFixtures.target(WindowsWriteFixtures.acl, control: control)
      provider = WindowsWriteProvider.new([initial, after])
      result = WriteWindows::Writer.replace_dacl_handle(handle, target: initial,
        dacl: WindowsWriteFixtures.acl, inheritance: inheritance, propagation: propagation, provider: provider)
      result.verified?.should eq(control == 0x9404)
      if control == 0x9404
        result.normalizations.should eq([WriteWindows::Normalization::DaclAutoInherited])
      end
    end
  end

  it "rejects removal of the auto-inherited control bit instead of normalizing it" do
    initial = WindowsWriteFixtures.target(WindowsWriteFixtures.acl, control: 0x9404_u16)
    after = WindowsWriteFixtures.target(WindowsWriteFixtures.acl, control: 0x9004_u16)
    provider = WindowsWriteProvider.new([initial, after])
    result = WriteWindows::Writer.replace_dacl_handle(handle, target: initial,
      dacl: WindowsWriteFixtures.acl, inheritance: inheritance, propagation: propagation, provider: provider)
    result.execution.succeeded?.should be_true
    result.verification.mismatched?.should be_true
    result.state.applied_unverified?.should be_true
    result.normalizations.should be_empty
    provider.writes.size.should eq(1)
  end

  it "validates native ACLs before mutation and rejects unknown policies" do
    initial = WindowsWriteFixtures.target
    provider = WindowsWriteProvider.new([initial])
    provider.invalid_acl = true
    failed = WriteWindows::Writer.replace_dacl_handle(handle, target: initial,
      dacl: WindowsWriteFixtures.acl, inheritance: inheritance, propagation: propagation, provider: provider)
    failed.execution.not_attempted?.should be_true
    provider.writes.should be_empty
    expect_raises(ArgumentError) do
      WriteWindows::Writer.replace_dacl_handle(handle, target: initial,
        dacl: WindowsWriteFixtures.acl, inheritance: WriteWindows::InheritancePolicy.new(99),
        propagation: propagation, provider: provider)
    end
  end
end
