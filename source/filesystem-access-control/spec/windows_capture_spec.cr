require "./spec_helper"

{% if flag?(:windows) %}
  alias CaptureWindows = Filesystem::AccessControl::Windows

  describe CaptureWindows::Reader do
    it "captures only the requested components through the same read-control handle" do
      SpecEnvironment.with_temp_dir("acl-win-scoped-reader") do |folder|
        units = folder.to_utf16
        name = Slice(UInt16).new(units.size + 1, 0_u16)
        units.copy_to(name)
        handle = LibC.CreateFileW(name.to_unsafe, 0x20000_u32, 7_u32,
          Pointer(LibC::SECURITY_ATTRIBUTES).null, 3_u32, 0x02200000_u32, Pointer(Void).null)
        handle.address.should_not eq(UInt64::MAX)
        begin
          ordinary = CaptureWindows::Reader.capture(handle)
          ordinary.complete?.should be_true
          ordinary.owner.should_not be_nil
          ordinary.group.should_not be_nil
          ordinary.sacl_presence.not_queried?.should be_true
          owner = CaptureWindows::Reader.capture(handle, information: CaptureWindows::SecurityInformation::Owner)
          owner.complete?.should be_true
          owner.owner.should eq(ordinary.owner)
          owner.group.should be_nil
          owner.dacl_presence.not_queried?.should be_true
          owner.sacl_presence.not_queried?.should be_true
          # The handle lacks ACCESS_SYSTEM_SECURITY even if the process has
          # an enabled privilege. Failure must not become a weaker retry.
          full = CaptureWindows::Reader.capture(handle, information: CaptureWindows::SecurityInformation::All)
          full.complete?.should be_false
          full.queried_information.should eq(15_u32)
          full.diagnostic.not_nil!.operation.should eq("GetSecurityInfo")
          full.diagnostic.not_nil!.origin.return_value?.should be_true
        ensure
          LibC.CloseHandle(handle)
        end
      end
    end

    it "keeps a failed SACL query unavailable without inventing a DACL observation" do
      snapshot = CaptureWindows::Reader.capture(Pointer(Void).null,
        information: CaptureWindows::SecurityInformation::Sacl)
      snapshot.complete?.should be_false
      snapshot.raw_descriptor.should be_nil
      snapshot.sacl_presence.unavailable?.should be_true
      snapshot.dacl_presence.not_queried?.should be_true
      diagnostic = snapshot.diagnostic.not_nil!
      diagnostic.operation.should eq("GetSecurityInfo")
      diagnostic.origin.return_value?.should be_true
      diagnostic.code.should_not eq(0_u32)
    end

    it "rejects unsupported query bits instead of silently weakening the query" do
      expect_raises(ArgumentError) do
        CaptureWindows::Reader.capture(Pointer(Void).null,
          information: CaptureWindows::SecurityInformation.new(0x10_u32))
      end
    end

    it "does not certify DACL privacy from a complete SACL-only capture" do
      descriptor = CaptureWindows::SecurityDescriptor.new(
        "0100008000000000000000000000000000000000".hexbytes,
        CaptureWindows::SecurityInformation::Sacl)
      snapshot = CaptureWindows::Snapshot.new(descriptor)
      snapshot.complete?.should be_true
      report = Filesystem::AccessControl::Report.new(nil, :windows_dacl, true, nil,
        ([] of Filesystem::AccessControl::Entry), ([] of Filesystem::AccessControl::Entry),
        Filesystem::AccessControl::State::None, true, snapshot: snapshot)
      report.private?.should be_false
    end
  end
{% end %}
