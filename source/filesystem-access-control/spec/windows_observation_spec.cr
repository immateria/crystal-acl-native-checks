require "./spec_helper"
require "../src/filesystem_access_control/windows/observation"

alias ObservedWindowsACL = Filesystem::AccessControl::Windows

describe ObservedWindowsACL::ACE do
  it "reads every inheritance flag combination without interpreting an opaque ACE" do
    expected = [
      "01010101010101010101010101010101",
      "00110011001100110011001100110011",
      "00001111000011110000111100001111",
      "00000000111111110000000011111111",
      "00000000000000001111111111111111",
    ]
    32.times do |flags|
      bytes = "fe0008004f504151".hexbytes
      bytes[1] = 0xe0_u8 | flags.to_u8
      original = bytes.dup
      ace = ObservedWindowsACL::ACE.new(bytes)
      inheritance = ace.inheritance
      inheritance.value.should eq(flags)
      [inheritance.object_inherit?, inheritance.container_inherit?,
       inheritance.no_propagate?, inheritance.inherit_only?, inheritance.inherited?].each_with_index do |value, index|
        value.should eq(expected[index].byte_at(flags) == '1'.ord)
      end
      ace.flags.should eq(0xe0_u8 | flags.to_u8)
      ace.rights.should be_nil
      ace.trustee.should be_nil
      bytes.fill(0_u8)
      ace.bytes.should eq(original)
    end
  end

  it "distinguishes the lab's inherited directory ACE from an effective file ACE" do
    # native-acl-test 3eac770, inheritance-events:create:allow:01. The
    # directory inherits an inherit-only ACE; the file receives flags 0x10.
    directory = ObservedWindowsACL::ACE.new(
      "00192400ff011f00010500000000000515000000f75154eda5bca26f67d5efad32790600".hexbytes)
    file = ObservedWindowsACL::ACE.new(
      "00102400ff011f00010500000000000515000000f75154eda5bca26f67d5efad32790600".hexbytes)
    directory.inheritance.inherited?.should be_true
    directory.inheritance.inherit_only?.should be_true
    directory.inheritance.object_inherit?.should be_true
    directory.inheritance.container_inherit?.should be_false
    file.inheritance.inherited?.should be_true
    file.inheritance.inherit_only?.should be_false
    file.inheritance.object_inherit?.should be_false
    directory.rights.should eq(file.rights)
    directory.trustee.should eq(file.trustee)
    directory.flags.should eq(0x19_u8)
    file.flags.should eq(0x10_u8)
  end
end

describe ObservedWindowsACL::SID do
  it "owns binary SIDs including zero subauthorities and unsigned boundary values" do
    bytes = "0100000000000005".hexbytes
    sid = ObservedWindowsACL::SID.new(bytes)
    bytes.fill(0_u8)
    sid.bytes.hexstring.should eq("0100000000000005")
    sid.bytes.fill(0_u8)
    sid.bytes.hexstring.should eq("0100000000000005")
    ObservedWindowsACL::SID.new("0101000000000005ffffffff".hexbytes).bytes.size.should eq(12)
    expect_raises(ArgumentError) { ObservedWindowsACL::SID.new("0101000000000005".hexbytes) }
    expect_raises(ArgumentError) { ObservedWindowsACL::SID.new("0200000000000005".hexbytes) }
  end
end

describe ObservedWindowsACL::ACL do
  it "compares detached ACLs by all bytes, including equal-length opaque payload changes" do
    original = "0200100001000000fe0008004f504151".hexbytes
    first = ObservedWindowsACL::ACL.new(original)
    copy = ObservedWindowsACL::ACL.new(original.dup)
    first.should eq(copy)
    first.hash.should eq(copy.hash)
    first.entries.first.should eq(copy.entries.first)
    different = ObservedWindowsACL::ACL.new("0200100001000000fe0008004f504152".hexbytes)
    first.should_not eq(different)
    first.entries.first.should_not eq(different.entries.first)
  end

  it "preserves an empty DACL without treating it as absent or NULL" do
    acl = ObservedWindowsACL::ACL.new("0200080000000000".hexbytes)
    acl.entries.should be_empty
    snapshot = ObservedWindowsACL::Snapshot.new(ObservedWindowsACL::SecurityDescriptor.new(
      "01000480000000000000000000000000140000000200080000000000".hexbytes))
    snapshot.dacl_presence.present?.should be_true
    snapshot.queried_information.should eq(7_u32)
  end

  it "preserves unknown ACEs, order, padding and detached raw bytes" do
    bytes = "04002400020000007f100800deadbeef0000140080000000010100000000000512000000".hexbytes
    acl = ObservedWindowsACL::ACL.new(bytes)
    bytes.fill(0_u8)
    acl.entries.map(&.type).should eq([0x7f_u8, 0_u8])
    acl.entries.first.trustee.should be_nil
    acl.entries.first.bytes.hexstring.should eq("7f100800deadbeef")
    acl.entries.last.trustee.not_nil!.bytes.hexstring.should eq("010100000000000512000000")
    acl.entries.last.rights.should eq(0x80_u32)
    acl.entries.clear
    acl.entries.size.should eq(2)
    acl.bytes.fill(0_u8)
    acl.bytes[0].should eq(4_u8)
  end

  it "accepts a basic ACE with zero-subauthority SID and preserves trailing ACE bytes" do
    acl = ObservedWindowsACL::ACL.new("02001c000100000000001400010000000100000000000005aabbccdd".hexbytes)
    acl.entries.first.trustee.not_nil!.bytes.size.should eq(8)
    acl.entries.first.bytes[-4, 4].hexstring.should eq("aabbccdd")
  end

  it "rejects malformed ACL sizes, ACE sizes and trustee lengths" do
    ["0200080001000000", "02000c000100000000000000", "02000c000100000000000800",
     "020018000100000000001000010000000101000000000005"].each do |hex|
      expect_raises(ArgumentError) { ObservedWindowsACL::ACL.new(hex.hexbytes) }
    end
  end
end

describe ObservedWindowsACL::Diagnostic do
  it "keeps a returned Win32 error distinct from last-error and validation diagnostics" do
    returned = ObservedWindowsACL::Diagnostic.new("GetSecurityInfo", 5_u32,
      ObservedWindowsACL::ErrorOrigin::ReturnValue, "denied")
    returned.code.should eq(5_u32)
    returned.origin.return_value?.should be_true
    invalid = ObservedWindowsACL::Diagnostic.new("DACL.decode", nil,
      ObservedWindowsACL::ErrorOrigin::Validation, "truncated")
    invalid.code.should be_nil
  end
end

describe ObservedWindowsACL::Snapshot do
  it "keeps absent and NULL observations distinct and rejects contradictory scope" do
    absent = ObservedWindowsACL::SecurityDescriptor.new(
      "0100008014000000000000000000000000000000010100000000000512000000".hexbytes)
    null_acl = ObservedWindowsACL::SecurityDescriptor.new(
      "0100048014000000000000000000000000000000010100000000000512000000".hexbytes)
    ObservedWindowsACL::Snapshot.new(absent).complete?.should be_true
    ObservedWindowsACL::Snapshot.new(null_acl).complete?.should be_true
    absent.dacl_presence.should_not eq(null_acl.dacl_presence)
    absent.dacl.should be_nil
    null_acl.dacl.should be_nil
    expect_raises(ArgumentError) do
      ObservedWindowsACL::Snapshot.new(absent, information: ObservedWindowsACL::SecurityInformation::Sacl)
    end
  end

  it "retains a complete capture when privacy interpretation fails" do
    sd = ObservedWindowsACL::SecurityDescriptor.new(
      "0100048014000000000000000000000000000000010100000000000512000000".hexbytes)
    captured = ObservedWindowsACL::Snapshot.new(sd)
    diagnostic = ObservedWindowsACL::Diagnostic.new("DACL.privacy", nil,
      ObservedWindowsACL::ErrorOrigin::Validation, "unsupported ACE")
    explained = captured.with_diagnostic(diagnostic)
    explained.complete?.should be_true
    explained.owner.should eq(sd.owner)
    explained.raw_descriptor.should eq(sd.bytes)
    explained.diagnostics.should eq([diagnostic])
    captured.diagnostics.should be_empty
    ObservedWindowsACL::Snapshot.new(diagnostic: diagnostic).complete?.should be_false
  end
end
