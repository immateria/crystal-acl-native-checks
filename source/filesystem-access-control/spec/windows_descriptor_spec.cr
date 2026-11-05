require "./spec_helper"

alias DescriptorWindows = Filesystem::AccessControl::Windows

describe DescriptorWindows::SecurityDescriptor do
  # Self-relative header, LocalSystem owner, builtin Administrators group,
  # NULL SACL, and a DACL containing the lab's opaque type-254 ACE.
  fixture = "0100148014000000200000000000000030000000" +
            "010100000000000512000000" +
            "01020000000000052000000020020000" +
            "0200100001000000fe0008004f504151"

  it "owns the descriptor and captures only the requested components" do
    bytes = fixture.hexbytes
    sd = DescriptorWindows::SecurityDescriptor.new(bytes)
    bytes.fill(0_u8)
    sd.bytes.hexstring.should eq(fixture)
    sd.bytes.fill(0_u8)
    sd.owner.not_nil!.bytes.hexstring.should eq("010100000000000512000000")
    sd.group.not_nil!.bytes.hexstring.should eq("01020000000000052000000020020000")
    sd.dacl_presence.present?.should be_true
    sd.dacl.not_nil!.entries.first.bytes.hexstring.should eq("fe0008004f504151")
    sd.sacl_presence.not_queried?.should be_true
    sd.sacl.should be_nil
    sd.control.should eq(0x8014_u16)
    all = DescriptorWindows::SecurityDescriptor.new(fixture.hexbytes,
      DescriptorWindows::SecurityInformation::All)
    all.sacl_presence.null?.should be_true
    all.should_not eq(sd) # Same bytes, different observation scope.
  end

  it "keeps absent, NULL, empty and unqueried ACLs distinct" do
    absent = DescriptorWindows::SecurityDescriptor.new("0100008000000000000000000000000000000000".hexbytes)
    null_acl = DescriptorWindows::SecurityDescriptor.new("0100048000000000000000000000000000000000".hexbytes)
    empty = DescriptorWindows::SecurityDescriptor.new("01000480000000000000000000000000140000000200080000000000".hexbytes)
    absent.dacl_presence.absent?.should be_true
    null_acl.dacl_presence.null?.should be_true
    empty.dacl_presence.present?.should be_true
    empty.dacl.not_nil!.entries.should be_empty
    owner_only = DescriptorWindows::SecurityDescriptor.new(fixture.hexbytes,
      DescriptorWindows::SecurityInformation::Owner)
    owner_only.group.should be_nil
    owner_only.dacl_presence.not_queried?.should be_true
    owner_only.dacl.should be_nil
    owner_only.bytes.hexstring.should eq(fixture)
  end

  it "reads independent DACL and SACL inheritance controls without changing raw bytes" do
    # DACL: protected + request + auto-inherited. SACL: request only.
    bytes = "0100009700000000000000000000000000000000".hexbytes
    sd = DescriptorWindows::SecurityDescriptor.new(bytes, DescriptorWindows::SecurityInformation::All)
    dacl = sd.dacl_inheritance_control.not_nil!
    dacl.protected?.should be_true
    dacl.auto_inherit_requested?.should be_true
    dacl.auto_inherited?.should be_true
    sacl = sd.sacl_inheritance_control.not_nil!
    sacl.protected?.should be_false
    sacl.auto_inherit_requested?.should be_true
    sacl.auto_inherited?.should be_false
    reverse = DescriptorWindows::SecurityDescriptor.new(
      "010000aa00000000000000000000000000000000".hexbytes,
      DescriptorWindows::SecurityInformation::All)
    reverse.dacl_inheritance_control.not_nil!.protected?.should be_false
    reverse.dacl_inheritance_control.not_nil!.auto_inherit_requested?.should be_false
    reverse.dacl_inheritance_control.not_nil!.auto_inherited?.should be_false
    reverse.sacl_inheritance_control.not_nil!.protected?.should be_true
    reverse.sacl_inheritance_control.not_nil!.auto_inherit_requested?.should be_true
    reverse.sacl_inheritance_control.not_nil!.auto_inherited?.should be_true
    bytes.fill(0_u8)
    sd.control.should eq(0x9700_u16)
    sd.bytes.hexstring.should eq("0100009700000000000000000000000000000000")
    sd.dacl_presence.absent?.should be_true
    sd.sacl_presence.absent?.should be_true
    snapshot = DescriptorWindows::Snapshot.new(sd)
    snapshot.dacl_inheritance_control.should eq(dacl)
    snapshot.sacl_inheritance_control.should eq(sacl)
  end

  it "does not report inheritance controls for unqueried or unavailable ACLs" do
    bytes = "010000bf00000000000000000000000000000000".hexbytes
    sd = DescriptorWindows::SecurityDescriptor.new(bytes, DescriptorWindows::SecurityInformation::Owner)
    sd.control.should eq(0xbf00_u16)
    sd.dacl_inheritance_control.should be_nil
    sd.sacl_inheritance_control.should be_nil
    snapshot = DescriptorWindows::Snapshot.new(sd)
    snapshot.dacl_inheritance_control.should be_nil
    snapshot.sacl_inheritance_control.should be_nil
    dacl_only = DescriptorWindows::SecurityDescriptor.new(bytes, DescriptorWindows::SecurityInformation::Dacl)
    dacl_only.dacl_inheritance_control.not_nil!.protected?.should be_true
    dacl_only.sacl_inheritance_control.should be_nil
    sacl_only = DescriptorWindows::SecurityDescriptor.new(bytes, DescriptorWindows::SecurityInformation::Sacl)
    sacl_only.dacl_inheritance_control.should be_nil
    sacl_only.sacl_inheritance_control.not_nil!.protected?.should be_true
    unavailable = DescriptorWindows::Snapshot.new(information: DescriptorWindows::SecurityInformation::All,
      raw_descriptor: bytes)
    unavailable.dacl_inheritance_control.should be_nil
    unavailable.sacl_inheritance_control.should be_nil
  end

  it "keeps protection, inheritance requests and completed auto-inheritance separate" do
    [
      {"0100008100000000000000000000000000000000", {false, true, false}, {false, false, false}},
      {"0100008400000000000000000000000000000000", {false, false, true}, {false, false, false}},
      {"0100009000000000000000000000000000000000", {true, false, false}, {false, false, false}},
      {"0100008200000000000000000000000000000000", {false, false, false}, {false, true, false}},
      {"0100008800000000000000000000000000000000", {false, false, false}, {false, false, true}},
      {"010000a000000000000000000000000000000000", {false, false, false}, {true, false, false}},
    ].each do |hex, expected_dacl, expected_sacl|
      sd = DescriptorWindows::SecurityDescriptor.new(hex.hexbytes, DescriptorWindows::SecurityInformation::All)
      dacl = sd.dacl_inheritance_control.not_nil!
      sacl = sd.sacl_inheritance_control.not_nil!
      {dacl.protected?, dacl.auto_inherit_requested?, dacl.auto_inherited?}.should eq(expected_dacl)
      {sacl.protected?, sacl.auto_inherit_requested?, sacl.auto_inherited?}.should eq(expected_sacl)
    end
  end

  it "captures a SACL without treating its audit ACE as a DACL grant" do
    bytes = "0100108000000000000000001400000000000000" +
            "02001c00010000000240140001000000010100000000000512000000"
    sd = DescriptorWindows::SecurityDescriptor.new(bytes.hexbytes,
      DescriptorWindows::SecurityInformation::Sacl)
    sd.sacl_presence.present?.should be_true
    sd.sacl.not_nil!.entries.first.type.should eq(2_u8)
    sd.sacl.not_nil!.bytes.hexstring.should eq(bytes[40..])
    sd.dacl_presence.not_queried?.should be_true
  end

  it "rejects truncated, absolute, misaligned and out-of-buffer descriptors" do
    ["", "01000000" + "00" * 16,
     "0100008013000000000000000000000000000000",
     "01000080ffffffff000000000000000000000000",
     "01000480000000000000000000000000140000000200100000000000",
     "01000080140000000000000000000000000000000101000000000005"].each do |hex|
      expect_raises(ArgumentError) { DescriptorWindows::SecurityDescriptor.new(hex.hexbytes) }
    end
    expect_raises(ArgumentError) do
      DescriptorWindows::SecurityDescriptor.new(fixture.hexbytes,
        DescriptorWindows::SecurityInformation.new(0x10_u32))
    end
  end

  it "allows owner and group to reference the same bounded SID" do
    sd = DescriptorWindows::SecurityDescriptor.new(
      "0100008014000000140000000000000000000000010100000000000512000000".hexbytes)
    sd.owner.should eq(sd.group)
  end

  it "preserves captured bytes and query scope when interpretation fails" do
    sd = DescriptorWindows::SecurityDescriptor.new(fixture.hexbytes)
    snapshot = DescriptorWindows::Snapshot.new(sd)
    snapshot.complete?.should be_true
    snapshot.queried_information.should eq(7_u32)
    diagnostic = DescriptorWindows::Diagnostic.new("DACL.privacy", nil,
      DescriptorWindows::ErrorOrigin::Validation, "opaque ACE")
    failed = snapshot.with_diagnostic(diagnostic)
    failed.complete?.should be_true
    failed.raw_descriptor.not_nil!.hexstring.should eq(fixture)
    failed.group.should eq(sd.group)
    failed.diagnostics.should eq([diagnostic])
    unavailable = DescriptorWindows::Snapshot.new(information: DescriptorWindows::SecurityInformation::Sacl,
      diagnostic: diagnostic, raw_descriptor: "0100".hexbytes)
    unavailable.complete?.should be_false
    unavailable.sacl_presence.unavailable?.should be_true
    unavailable.dacl_presence.not_queried?.should be_true
    unavailable.raw_descriptor.not_nil!.hexstring.should eq("0100")
  end
end
