require "./spec_helper"
require "../src/filesystem_access_control/windows/rights"

alias RightsWindows = Filesystem::AccessControl::Windows

describe RightsWindows::GenericMapping do
  it "expands filesystem generic requests without dropping explicit rights" do
    # Literal Windows FILE_GENERIC_* mappings. SYNCHRONIZE is part of each:
    # omitting it changes deny-ACE behavior for a combined request.
    mapping = RightsWindows::GenericMapping::FILESYSTEM
    [
      {0x80000000_u32, 0x00120089_u32},
      {0x40000000_u32, 0x00120116_u32},
      {0x20000000_u32, 0x001200a0_u32},
      {0x10000000_u32, 0x001f01ff_u32},
      {0xc0000000_u32, 0x0012019f_u32},
      {0xe0000000_u32, 0x001201bf_u32},
      {0x80040000_u32, 0x00160089_u32},
      {0x88000000_u32, 0x08120089_u32},
      {0x00000000_u32, 0x00000000_u32},
    ].each do |raw, expanded|
      mapping.expand(RightsWindows::Rights.new(raw)).value.should eq(expanded)
    end
  end

  it "uses the caller's mapping once and rejects mappings containing generic bits" do
    mapping = RightsWindows::GenericMapping.new(1_u32, 2_u32, 4_u32, 15_u32)
    mapping.expand(RightsWindows::Rights.new(0xe0000080_u32)).value.should eq(0x87_u32)
    [0x10000000_u32, 0x20000000_u32, 0x40000000_u32, 0x80000000_u32].each do |generic|
      expect_raises(ArgumentError) { RightsWindows::GenericMapping.new(generic, 0_u32, 0_u32, 0_u32) }
    end
  end
end

describe RightsWindows::Rights do
  it "keeps native aliases meaningful while accepting only fixed filesystem requests" do
    file = RightsWindows::Rights::ReadData | RightsWindows::Rights::AppendData
    directory = RightsWindows::Rights::ListDirectory | RightsWindows::Rights::AddSubdirectory
    file.should eq(directory)
    file.value.should eq(5_u32)
    [0_u32, 1_u32, 0x001f01ff_u32, 0xf0000000_u32].each do |raw|
      RightsWindows::Rights.new(raw).validate_file_request!
    end
    # Storage observations still retain these bits; a fixed-request checker
    # must not silently weaken them by masking them out.
    [0x200_u32, 0x01000000_u32, 0x02000000_u32, 0x08000000_u32].each do |raw|
      observed = RightsWindows::Rights.new(raw)
      observed.value.should eq(raw)
      expect_raises(ArgumentError) { observed.validate_file_request! }
    end
  end
end
