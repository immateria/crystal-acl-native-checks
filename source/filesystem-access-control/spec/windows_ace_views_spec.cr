require "./spec_helper"

alias ViewsWindows = Filesystem::AccessControl::Windows

describe ViewsWindows::ACE do
  it "decodes audit and callback trustees while retaining uninterpreted payload bytes" do
    # SYSTEM_AUDIT_ACE and ACCESS_ALLOWED_CALLBACK_ACE use a DWORD mask then
    # the SID; the callback's trailing bytes are application data, not a SID.
    audit = ViewsWindows::ACE.new("0240140001000000010100000000000512000000".hexbytes)
    audit.rights.should eq(1_u32)
    audit.trustee.not_nil!.bytes.hexstring.should eq("010100000000000512000000")
    audit.callback?.should be_false
    audit.object_ace?.should be_false
    audit.payload.should eq(Bytes.empty)
    bytes = "09001c00020000000101000000000005120000006172747801020304".hexbytes
    callback = ViewsWindows::ACE.new(bytes)
    callback.callback?.should be_true
    callback.object_ace?.should be_false
    callback.rights.should eq(2_u32)
    callback.trustee.should eq(audit.trustee)
    callback.payload.not_nil!.hexstring.should eq("6172747801020304")
    bytes.fill(0_u8)
    callback.payload.not_nil!.fill(0_u8)
    callback.payload.not_nil!.hexstring.should eq("6172747801020304")
    callback.bytes.hexstring.should eq("09001c00020000000101000000000005120000006172747801020304")
    callback.object_flags.should be_nil
    callback.object_type.should be_nil
    callback.inherited_object_type.should be_nil
  end

  it "locates SIDs after either optional object GUID rather than fixed struct offsets" do
    guid1 = "33221100554477668899aabbccddeeff"
    guid2 = "efcdab89674523011032547698badcfe"
    [
      {"050018000100000000000000010100000000000512000000", 0_u32, nil, nil},
      {"050028000100000001000000" + guid1 + "010100000000000512000000", 1_u32, guid1, nil},
      {"050028000100000002000000" + guid2 + "010100000000000512000000", 2_u32, nil, guid2},
      {"050038000100000003000000" + guid1 + guid2 + "010100000000000512000000", 3_u32, guid1, guid2},
    ].each do |hex, flags, object_guid, inherited_guid|
      ace = ViewsWindows::ACE.new(hex.hexbytes)
      ace.object_ace?.should be_true
      ace.callback?.should be_false
      ace.object_flags.should eq(flags)
      ace.object_type.try(&.bytes.hexstring).should eq(object_guid)
      ace.inherited_object_type.try(&.bytes.hexstring).should eq(inherited_guid)
      ace.trustee.not_nil!.bytes.hexstring.should eq("010100000000000512000000")
      ace.payload.should eq(Bytes.empty)
      ace.bytes.hexstring.should eq(hex)
    end
    guid = ViewsWindows::GUID.new(guid1.hexbytes)
    guid.to_s.should eq("00112233-4455-6677-8899-aabbccddeeff")
    guid.bytes.fill(0_u8)
    guid.to_s.should eq("00112233-4455-6677-8899-aabbccddeeff")
  end

  it "shares known object and callback layouts without assigning permission semantics" do
    # All documented allow/deny/audit/alarm object/callback layout variants.
    basic = [0_u8, 1_u8, 2_u8, 3_u8, 9_u8, 10_u8, 13_u8, 14_u8]
    objects = [5_u8, 6_u8, 7_u8, 8_u8, 11_u8, 12_u8, 15_u8, 16_u8]
    (basic + objects).each do |type|
      hex = objects.includes?(type) ? "000018000100000000000000010100000000000512000000" : "0000140001000000010100000000000512000000"
      bytes = hex.hexbytes
      bytes[0] = type
      ace = ViewsWindows::ACE.new(bytes)
      ace.rights.should eq(1_u32)
      ace.trustee.not_nil!.bytes.hexstring.should eq("010100000000000512000000")
      ace.object_ace?.should eq(objects.includes?(type))
      ace.callback?.should eq(type.in?({9_u8, 10_u8, 11_u8, 12_u8, 13_u8, 14_u8, 15_u8, 16_u8}))
    end
    opaque = ViewsWindows::ACE.new("fe0008004f504151".hexbytes)
    opaque.rights.should be_nil
    opaque.trustee.should be_nil
    opaque.object_flags.should be_nil
    opaque.payload.should be_nil
    opaque.bytes.hexstring.should eq("fe0008004f504151")
  end

  it "retains callback-object payloads and unknown object flag bits exactly" do
    hex = "0b102c00000000800100008033221100554477668899aabbccddeeff010100000000000512000000aabbccdd"
    ace = ViewsWindows::ACE.new(hex.hexbytes)
    ace.callback?.should be_true
    ace.object_flags.should eq(0x80000001_u32)
    ace.object_type.not_nil!.to_s.should eq("00112233-4455-6677-8899-aabbccddeeff")
    ace.inherited_object_type.should be_nil
    ace.trustee.not_nil!.bytes.hexstring.should eq("010100000000000512000000")
    ace.payload.not_nil!.hexstring.should eq("aabbccdd")
    ace.bytes.hexstring.should eq(hex)
  end

  it "rejects known-layout truncation before reading GUIDs or a trustee" do
    [
      "0200080001000000",
      "09001000010000000101000000000005",
      "05001000010000000100000000000000",
      "05002000010000000300000033221100554477668899aabbccddeeff00000000",
      "0b0018000100000000000000010f00000000000512000000",
    ].each do |hex|
      expect_raises(ArgumentError) { ViewsWindows::ACE.new(hex.hexbytes) }
    end
    expect_raises(ArgumentError) { ViewsWindows::GUID.new(Bytes.new(15)) }
    expect_raises(ArgumentError) { ViewsWindows::GUID.new(Bytes.new(17)) }
  end
end
