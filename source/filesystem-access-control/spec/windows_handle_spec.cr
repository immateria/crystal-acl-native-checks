require "./spec_helper"
require "../src/filesystem_access_control/windows/handle_capture"

alias HandleWindows = Filesystem::AccessControl::Windows

private module WindowsHandleFixtures
  def self.security(information = HandleWindows::DEFAULT_INFORMATION)
    bytes = "010004801400000020000000000000002c0000000101000000000005120000000101000000000005120000000200080000000000".hexbytes
    HandleWindows::Snapshot.new(HandleWindows::SecurityDescriptor.new(bytes, information))
  end

  def self.metadata(volume = 10_u64, id = 7_u8, attributes = 0_u32)
    HandleWindows::FileMetadata.new(HandleWindows::FileIdentity.new(volume, Bytes.new(16, id)), attributes)
  end

  def self.failure(operation = "GetFileInformationByHandleEx(FileIdInfo)")
    HandleWindows::Diagnostic.new(operation, 5_u32, HandleWindows::ErrorOrigin::LastError, "denied")
  end
end

# External Win32 metadata/security calls are the only replaced boundary.
# These fixtures leave the real capture brackets and completeness rules active.
private class WindowsHandleFixtureProvider
  getter metadata_calls = [] of UInt64
  getter security_calls = [] of Tuple(UInt64, HandleWindows::SecurityInformation)

  def initialize(@metadata : Array(HandleWindows::FileMetadata?),
                 @security = WindowsHandleFixtures.security,
                 @errors = [nil, nil] of HandleWindows::Diagnostic?)
  end

  def metadata(handle : Void*)
    index = @metadata_calls.size
    @metadata_calls << handle.address
    {@metadata[index], @errors[index]}
  end

  def security(handle : Void*, information : HandleWindows::SecurityInformation)
    @security_calls << {handle.address, information}
    @security
  end
end

describe HandleWindows::HandleReader do
  handle = Pointer(Void).new(123_u64)

  it "owns all 128 file identity bits and includes the volume in equality" do
    bytes = "000102030405060708090a0b0c0d0e0f".hexbytes
    identity = HandleWindows::FileIdentity.new(10_u64, bytes)
    bytes.fill(0_u8)
    identity.file_id.hexstring.should eq("000102030405060708090a0b0c0d0e0f")
    copy = identity.file_id
    copy.fill(0_u8)
    identity.should eq(HandleWindows::FileIdentity.new(10_u64, "000102030405060708090a0b0c0d0e0f".hexbytes))
    identity.should_not eq(HandleWindows::FileIdentity.new(11_u64, identity.file_id))
    changed = identity.file_id
    changed[15] = 0xff_u8
    identity.should_not eq(HandleWindows::FileIdentity.new(10_u64, changed))
    expect_raises(ArgumentError) { HandleWindows::FileIdentity.new(10_u64, Bytes.new(15)) }
  end

  it "brackets the same handle without treating unrelated attribute changes as substitution" do
    before = WindowsHandleFixtures.metadata(attributes: 0x01_u32)
    after = WindowsHandleFixtures.metadata(attributes: 0x20_u32)
    provider = WindowsHandleFixtureProvider.new([before, after] of HandleWindows::FileMetadata?)
    snapshot = HandleWindows::HandleReader.capture(handle, provider: provider)
    snapshot.complete?.should be_true
    snapshot.metadata_before.should eq(before)
    snapshot.metadata_after.should eq(after)
    snapshot.identity.should eq(before.identity)
    snapshot.kind.not_nil!.file?.should be_true
    provider.metadata_calls.should eq([123_u64, 123_u64])
    provider.security_calls.should eq([{123_u64, HandleWindows::DEFAULT_INFORMATION}])
  end

  it "rejects initial metadata failure, absence and reparse points before querying security" do
    metadata = WindowsHandleFixtures.metadata
    diagnostic = WindowsHandleFixtures.failure
    cases = [{metadata, diagnostic}, {nil, nil},
             {WindowsHandleFixtures.metadata(attributes: 0x400_u32), nil}]
    cases.each do |before, error|
      provider = WindowsHandleFixtureProvider.new([before] of HandleWindows::FileMetadata?,
        errors: [error] of HandleWindows::Diagnostic?)
      snapshot = HandleWindows::HandleReader.capture(handle, provider: provider)
      snapshot.complete?.should be_false
      snapshot.metadata_before.should eq(before)
      snapshot.metadata_after.should be_nil
      snapshot.security.complete?.should be_false
      if error
        snapshot.diagnostic.should eq(error)
      else
        snapshot.diagnostic.not_nil!.origin.validation?.should be_true
      end
      provider.metadata_calls.should eq([123_u64])
      provider.security_calls.should be_empty
    end
  end

  it "keeps failed security scope and provenance without a weaker query" do
    information = HandleWindows::SecurityInformation::All
    diagnostic = HandleWindows::Diagnostic.new("GetSecurityInfo", 1314_u32,
      HandleWindows::ErrorOrigin::ReturnValue, "privilege unavailable")
    security = HandleWindows::Snapshot.new(information: information, diagnostic: diagnostic)
    before = WindowsHandleFixtures.metadata
    provider = WindowsHandleFixtureProvider.new([before] of HandleWindows::FileMetadata?, security)
    snapshot = HandleWindows::HandleReader.capture(handle, information: information, provider: provider)
    snapshot.complete?.should be_false
    snapshot.security.information.should eq(information)
    snapshot.security.sacl_presence.unavailable?.should be_true
    snapshot.diagnostic.should eq(diagnostic)
    snapshot.metadata_after.should be_nil
    provider.security_calls.should eq([{123_u64, information}])
    provider.metadata_calls.should eq([123_u64])
  end

  it "rejects a provider returning a weaker security scope than requested" do
    before = WindowsHandleFixtures.metadata
    weaker = WindowsHandleFixtures.security(HandleWindows::SecurityInformation::Owner)
    provider = WindowsHandleFixtureProvider.new([before, before] of HandleWindows::FileMetadata?, weaker)
    snapshot = HandleWindows::HandleReader.capture(handle,
      information: HandleWindows::SecurityInformation::All, provider: provider)
    snapshot.complete?.should be_false
    snapshot.security.information.should eq(HandleWindows::SecurityInformation::Owner)
    snapshot.diagnostic.not_nil!.origin.validation?.should be_true
    provider.security_calls.size.should eq(1)
    provider.metadata_calls.should eq([123_u64])
  end

  it "retains security evidence when the final metadata query fails" do
    before = WindowsHandleFixtures.metadata
    diagnostic = WindowsHandleFixtures.failure
    provider = WindowsHandleFixtureProvider.new([before, nil] of HandleWindows::FileMetadata?,
      errors: [nil, diagnostic] of HandleWindows::Diagnostic?)
    snapshot = HandleWindows::HandleReader.capture(handle, provider: provider)
    snapshot.complete?.should be_false
    snapshot.security.complete?.should be_true
    snapshot.metadata_before.should eq(before)
    snapshot.metadata_after.should be_nil
    snapshot.diagnostic.should eq(diagnostic)
    provider.security_calls.size.should eq(1)
  end

  it "rejects changed volume, high file ID bytes, kind, disappearance and final reparse points" do
    before = WindowsHandleFixtures.metadata
    id = before.identity.file_id
    id[15] = 8_u8
    changed_high_id = HandleWindows::FileMetadata.new(HandleWindows::FileIdentity.new(10_u64, id), 0_u32)
    cases = [WindowsHandleFixtures.metadata(volume: 11_u64), changed_high_id,
             WindowsHandleFixtures.metadata(attributes: 0x10_u32),
             WindowsHandleFixtures.metadata(attributes: 0x400_u32), nil]
    cases.each do |after|
      provider = WindowsHandleFixtureProvider.new([before, after] of HandleWindows::FileMetadata?)
      snapshot = HandleWindows::HandleReader.capture(handle, provider: provider)
      snapshot.complete?.should be_false
      snapshot.security.complete?.should be_true
      snapshot.metadata_before.should eq(before)
      snapshot.metadata_after.should eq(after)
      snapshot.diagnostic.not_nil!.operation.should eq("HandleReader.identity")
      snapshot.diagnostic.not_nil!.origin.validation?.should be_true
      provider.metadata_calls.should eq([123_u64, 123_u64])
    end
  end

  it "rejects unsupported scopes before any metadata or security call" do
    provider = WindowsHandleFixtureProvider.new([] of HandleWindows::FileMetadata?)
    expect_raises(ArgumentError) do
      HandleWindows::HandleReader.capture(handle,
        information: HandleWindows::SecurityInformation.new(0x10_u32), provider: provider)
    end
    provider.metadata_calls.should be_empty
    provider.security_calls.should be_empty
  end

  {% if flag?(:windows) %}
    it "captures native FILE_ID_INFO and leaves the borrowed handle usable after a failed full query" do
      SpecEnvironment.with_temp_dir("acl-win-handle-reader") do |folder|
        units = folder.to_utf16
        name = Slice(UInt16).new(units.size + 1, 0_u16)
        units.copy_to(name)
        # READ_CONTROL | FILE_READ_ATTRIBUTES, all sharing, final no-follow.
        native = LibC.CreateFileW(name.to_unsafe, 0x20080_u32, 7_u32,
          Pointer(LibC::SECURITY_ATTRIBUTES).null, 3_u32, 0x02200000_u32, Pointer(Void).null)
        native.address.should_not eq(UInt64::MAX)
        begin
          first = HandleWindows::HandleReader.capture(native)
          first.complete?.should be_true
          first.kind.not_nil!.directory?.should be_true
          first.identity.not_nil!.file_id.size.should eq(16)
          first.metadata_before.not_nil!.identity.should eq(first.metadata_after.not_nil!.identity)
          failed = HandleWindows::HandleReader.capture(native, information: HandleWindows::SecurityInformation::All)
          failed.complete?.should be_false
          failed.metadata_before.should_not be_nil
          failed.security.information.should eq(HandleWindows::SecurityInformation::All)
          failed.security.diagnostic.not_nil!.operation.should eq("GetSecurityInfo")
          failed.security.diagnostic.not_nil!.origin.return_value?.should be_true
          again = HandleWindows::HandleReader.capture(native)
          again.complete?.should be_true
          again.identity.should eq(first.identity)
        ensure
          LibC.CloseHandle(native)
        end
      end
    end

    it "keeps the native invalid-handle failure at the metadata boundary" do
      snapshot = HandleWindows::HandleReader.capture(Pointer(Void).null)
      snapshot.complete?.should be_false
      snapshot.metadata_after.should be_nil
      snapshot.security.complete?.should be_false
      snapshot.diagnostic.not_nil!.operation.should eq("GetFileType")
      snapshot.diagnostic.not_nil!.origin.last_error?.should be_true
      snapshot.diagnostic.not_nil!.code.should eq(6_u32)
    end
  {% end %}
end
