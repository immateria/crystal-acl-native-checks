require "./spec_helper"
require "../src/filesystem_access_control/windows/evaluation"

alias CheckedWindows = Filesystem::AccessControl::Windows

private module WindowsCheckFixtures
  def self.snapshot(acl : String = "02001c00010000000000140006000000010100000000000512000000",
                    information = CheckedWindows::DEFAULT_INFORMATION)
    CheckedWindows::Snapshot.new(CheckedWindows::SecurityDescriptor.new(
      ("010004801400000020000000000000002c000000" +
       "010100000000000512000000010100000000000512000000" + acl).hexbytes, information))
  end

  def self.call(snapshot = self.snapshot, *, permissions = CheckedWindows::Rights.new(6_u32),
                provider = WindowsCheckProvider.new)
    CheckedWindows::Evaluator.check(snapshot, subject: Pointer(Void).new(42_u64),
      permissions: permissions, kind: Filesystem::AccessControl::Target::File, provider: provider)
  end
end

# Only the native boundary is replaced. Request mapping, scoped preconditions,
# result classification, privilege-buffer validation and retry limits are real.
private class WindowsCheckProvider
  getter requests = [] of UInt32
  getter subjects = [] of UInt64
  getter descriptors = [] of Bytes
  getter capacities = [] of Int32
  getter last_privileges : Bytes?
  property fault : Symbol?
  property code = 1309_u32
  property growth = 32_u32

  def call(descriptor : Bytes, subject : Void*, permissions : UInt32,
           mapping : CheckedWindows::GenericMapping, privileges : Bytes)
    @requests << permissions
    @subjects << subject.address
    @descriptors << descriptor.dup
    @capacities << privileges.size
    @last_privileges = privileges
    if @fault == :api_failure
      return CheckedWindows::AccessCheckCall.new(false, nil, nil, 0_u32, diagnostic(@code))
    end
    if @fault == :growth || @fault == :repeat_growth || @fault == :bad_growth
      if @capacities.size == 1 || @fault != :growth
        required = @fault == :repeat_growth && @capacities.size > 1 ? @growth * 2 : @growth
        return CheckedWindows::AccessCheckCall.new(false, nil, nil, required, diagnostic(122_u32))
      end
    end
    bytes = if @fault == :growth
              "0200000000000000010000000000000000000080020000000000000000000080".hexbytes
            elsif @fault == :malformed_privileges
              "0200000000000000".hexbytes
            else
              "0000000000000000".hexbytes
            end
    bytes.copy_to(privileges)
    status = @fault != :denied && @fault != :denied_mask
    mask = case @fault
           when :denied       then 0_u32
           when :granted_mask then 1_u32
           else                    permissions
           end
    result_status = @fault == :missing_status ? nil : status
    returned_size = case @fault
                    when :short_privileges then 7_u32
                    when :long_privileges  then privileges.size.to_u32 + 1
                    else                        bytes.size.to_u32
                    end
    CheckedWindows::AccessCheckCall.new(true, result_status, mask, returned_size,
      status ? nil : diagnostic(5_u32))
  end

  private def diagnostic(code)
    CheckedWindows::Diagnostic.new("AccessCheck", code, CheckedWindows::ErrorOrigin::LastError,
      "AccessCheck native status #{code}")
  end
end

describe CheckedWindows::Evaluator do
  it "sends the whole mapped request and exact captured descriptor to the explicit token" do
    snapshot = WindowsCheckFixtures.snapshot
    provider = WindowsCheckProvider.new
    result = WindowsCheckFixtures.call(snapshot,
      permissions: CheckedWindows::Rights::GenericRead | CheckedWindows::Rights::GenericWrite,
      provider: provider)
    result.decision.allowed?.should be_true
    result.allowed?.should be_true
    result.api_success.should eq(true)
    result.access_status.should eq(true)
    result.granted_mask.should eq(0x0012019f_u32)
    result.requested.value.should eq(0xc0000000_u32)
    result.mapped.value.should eq(0x0012019f_u32)
    result.scope.discretionary_descriptor?.should be_true
    result.diagnostic.should be_nil
    result.native_error.should be_nil
    provider.requests.should eq([0x0012019f_u32])
    provider.subjects.should eq([42_u64])
    provider.descriptors.should eq([snapshot.raw_descriptor.not_nil!])
    result.privileges.not_nil!.hexstring.should eq("0000000000000000")
  end

  it "keeps successful denial distinct from a failed API check" do
    provider = WindowsCheckProvider.new
    provider.fault = :denied
    denied = WindowsCheckFixtures.call(provider: provider)
    denied.decision.denied?.should be_true
    denied.allowed?.should be_false
    denied.api_success.should eq(true)
    denied.access_status.should eq(false)
    denied.granted_mask.should eq(0_u32)
    denied.native_error.not_nil!.code.should eq(5_u32)
    [5_u32, 1309_u32, 1338_u32].each do |code|
      provider = WindowsCheckProvider.new
      provider.fault = :api_failure
      provider.code = code
      failed = WindowsCheckFixtures.call(provider: provider)
      failed.decision.indeterminate?.should be_true
      failed.allowed?.should be_false
      failed.api_success.should eq(false)
      failed.access_status.should be_nil
      failed.granted_mask.should be_nil
      failed.privileges.should be_nil
      failed.native_error.not_nil!.code.should eq(code)
      failed.diagnostic.not_nil!.operation.should eq("AccessCheck")
      provider.requests.size.should eq(1)
    end
  end

  it "requires complete owner, group and DACL evidence before a native check" do
    provider = WindowsCheckProvider.new
    snapshots = [
      CheckedWindows::Snapshot.new,
      WindowsCheckFixtures.snapshot(information: CheckedWindows::SecurityInformation::Owner),
      CheckedWindows::Snapshot.new(CheckedWindows::SecurityDescriptor.new(
        "0100048000000000000000000000000000000000".hexbytes)),
      CheckedWindows::Snapshot.new(CheckedWindows::SecurityDescriptor.new(
        "0100048014000000000000000000000000000000010100000000000512000000".hexbytes)),
    ]
    snapshots.each do |snapshot|
      result = WindowsCheckFixtures.call(snapshot, provider: provider)
      result.decision.indeterminate?.should be_true
      result.api_success.should be_nil
      result.diagnostic.not_nil!.origin.validation?.should be_true
    end
    provider.requests.should be_empty
  end

  it "leaves callback, object and unknown ACE policy to separately qualified profiles" do
    provider = WindowsCheckProvider.new
    ["0400200001000000050018000600000000000000010100000000000512000000",
     "02001c00010000000900140006000000010100000000000512000000",
     "0200100001000000fe0008004f504151"].each do |acl|
      result = WindowsCheckFixtures.call(WindowsCheckFixtures.snapshot(acl), provider: provider)
      result.decision.indeterminate?.should be_true
      result.api_success.should be_nil
      result.diagnostic.not_nil!.origin.validation?.should be_true
    end
    provider.requests.should be_empty
  end

  it "uses native checks for NULL, absent and empty DACLs instead of synthesizing decisions" do
    provider = WindowsCheckProvider.new
    ["01000480", "01000080"].each do |header|
      snapshot = CheckedWindows::Snapshot.new(CheckedWindows::SecurityDescriptor.new(
        (header + "14000000200000000000000000000000" +
         "010100000000000512000000010100000000000512000000").hexbytes))
      WindowsCheckFixtures.call(snapshot, provider: provider).api_success.should eq(true)
    end
    WindowsCheckFixtures.call(WindowsCheckFixtures.snapshot("0200080000000000"), provider: provider).api_success.should eq(true)
    provider.requests.size.should eq(3)
  end

  it "rejects unsupported requests and kinds before calling the provider" do
    provider = WindowsCheckProvider.new
    [0_u32, 0x200_u32, 0x01000000_u32, 0x02000000_u32, 0x08000000_u32].each do |raw|
      expect_raises(ArgumentError) do
        WindowsCheckFixtures.call(permissions: CheckedWindows::Rights.new(raw), provider: provider)
      end
    end
    expect_raises(ArgumentError) do
      CheckedWindows::Evaluator.check(WindowsCheckFixtures.snapshot, subject: Pointer(Void).new(42_u64),
        permissions: CheckedWindows::Rights::ReadData, kind: Filesystem::AccessControl::Target.new(99), provider: provider)
    end
    provider.requests.should be_empty
    null_subject = CheckedWindows::Evaluator.check(WindowsCheckFixtures.snapshot, subject: Pointer(Void).null,
      permissions: CheckedWindows::Rights::ReadData, kind: Filesystem::AccessControl::Target::File, provider: provider)
    null_subject.decision.indeterminate?.should be_true
    null_subject.api_success.should be_nil
    provider.requests.should be_empty
  end

  it "retries only a bounded read-only privilege-buffer growth and owns the returned evidence" do
    provider = WindowsCheckProvider.new
    provider.fault = :growth
    result = WindowsCheckFixtures.call(provider: provider)
    result.allowed?.should be_true
    result.native_error.should be_nil
    provider.capacities.should eq([20, 32])
    result.privileges.not_nil!.size.should eq(32)
    result.privileges.not_nil!.hexstring.should eq("0200000000000000010000000000000000000080020000000000000000000080")
    provider.last_privileges.not_nil!.fill(0_u8)
    result.privileges.not_nil!.hexstring.should eq("0200000000000000010000000000000000000080020000000000000000000080")
    result.privileges.not_nil!.fill(0_u8)
    result.privileges.not_nil!.hexstring.should eq("0200000000000000010000000000000000000080020000000000000000000080")
  end

  it "preserves the final native error when growth is invalid or still changing" do
    [0_u32, 20_u32, 65_537_u32].each do |growth|
      provider = WindowsCheckProvider.new
      provider.fault = :bad_growth
      provider.growth = growth
      result = WindowsCheckFixtures.call(provider: provider)
      result.decision.indeterminate?.should be_true
      result.native_error.not_nil!.code.should eq(122_u32)
      provider.capacities.should eq([20])
    end
    provider = WindowsCheckProvider.new
    provider.fault = :repeat_growth
    result = WindowsCheckFixtures.call(provider: provider)
    result.decision.indeterminate?.should be_true
    result.native_error.not_nil!.code.should eq(122_u32)
    provider.capacities.should eq([20, 32])
  end

  it "retains inconsistent native outputs as indeterminate rather than inventing a denial" do
    [:granted_mask, :denied_mask, :missing_status, :malformed_privileges, :short_privileges, :long_privileges].each do |fault|
      provider = WindowsCheckProvider.new
      provider.fault = fault
      result = WindowsCheckFixtures.call(provider: provider)
      result.decision.indeterminate?.should be_true
      result.allowed?.should be_false
      result.api_success.should eq(true)
      result.diagnostic.not_nil!.origin.validation?.should be_true
      result.native_error.not_nil!.code.should eq(5_u32) if fault == :denied_mask
    end
  end
end
