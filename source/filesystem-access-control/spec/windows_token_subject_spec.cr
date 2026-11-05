require "./spec_helper"
require "../src/filesystem_access_control/windows/token_reader"

alias SubjectWindows = Filesystem::AccessControl::Windows

# Native calls are the boundary: fixtures carry the complete documented
# pointer/count/alignment layouts, and production selection/decoding stays real.
private class TokenSubjectFixtureProvider
  getter opened = [] of Symbol
  getter queried = [] of UInt32
  getter closed = [] of UInt64
  getter buffers = [] of Bytes
  property thread_error : UInt32? = 1008_u32
  property process_error : UInt32?
  property query_error : UInt32?
  property malformed : Symbol?
  property fault_query = 2_u32
  property padded = false
  property empty_restricted = false
  property exceed_limit = false
  property failed_buffer = false

  def open_process
    @opened << :process
    {Pointer(Void).new(11_u64), diagnostic("OpenProcessToken", @process_error)}
  end

  def open_thread
    @opened << :thread
    {Pointer(Void).new(22_u64), diagnostic("OpenThreadToken", @thread_error)}
  end

  def close(token : Void*)
    @closed << token.address
  end

  def query(token : Void*, information : UInt32, maximum_size : Int32)
    @queried << information
    if information == @query_error
      if @failed_buffer
        data = Bytes.new(maximum_size, 0_u8)
        @buffers << data
        return {data, data.size.to_u32, diagnostic("GetTokenInformation(#{information})", 5_u32)}
      end
      return {nil, 0_u32, diagnostic("GetTokenInformation(#{information})", 5_u32)}
    end
    data = case information
           when 1, 25
             header = sizeof(Void*) == 8 ? 16 : 8
             bytes = Bytes.new(@padded && information == 25 ? maximum_size : header + 12, 0_u8)
             point(bytes, 0, header)
             if information == 1
               "010100000000000512000000".hexbytes.copy_to(bytes[header, 12])
             else
               "010100000000001000100000".hexbytes.copy_to(bytes[header, 12])
               put32(bytes, sizeof(Void*), 0x60_u32)
             end
             bytes
           when 2, 11
             offset = sizeof(Void*) == 8 ? 8 : 4
             stride = sizeof(Void*) == 8 ? 16 : 8
             count = information == 2 ? 2 : @empty_restricted ? 0 : 1
             bytes = Bytes.new(@padded ? maximum_size : offset + stride * count + 12 * count, 0_u8)
             unless @padded
               put32(bytes, 0, count.to_u32)
               count.times do |index|
                 sid_offset = offset + stride * count + 12 * index
                 point(bytes, offset + stride * index, sid_offset)
                 sid = index == 0 ? "010100000000000512000000" : "010100000000000100000000"
                 sid.hexbytes.copy_to(bytes[sid_offset, 12])
                 put32(bytes, offset + stride * index + sizeof(Void*),
                   index == 0 ? 0x80000004_u32 : 0x10_u32)
               end
             end
             bytes
           when 3
             bytes = Bytes.new(@padded ? maximum_size : 28, 0_u8)
             unless @padded
               "02000000efcdab89feffffff02000080785634120000000000010000".hexbytes.copy_to(bytes)
             end
             bytes
           else
             value = case information
                     when  8 then token.address == 22 ? 2_u32 : 1_u32
                     when  9 then 2_u32
                     when 18 then 3_u32
                     when 20 then 0_u32
                     when 21 then 9_u32
                     else         raise "Unexpected token information #{information}"
                     end
             bytes = Bytes.new(4)
             put32(bytes, 0, value)
             bytes
           end
    data = Bytes.new(maximum_size + 1, 0_u8) if @exceed_limit && information == 2
    length = data.size.to_u32
    if information == @fault_query
      case @malformed
      when :external_pointer
        position = information.in?({2_u32, 11_u32}) ? (sizeof(Void*) == 8 ? 8 : 4) : 0
        (data.to_unsafe + position).as(Void**).value = Pointer(Void).new(1_u64)
      when :inside_records
        point(data, sizeof(Void*) == 8 ? 8 : 4, 0)
      when :large_count
        put32(data, 0, UInt32::MAX)
      when :short
        length = 3_u32
      when :overreported
        length += 1
      when :invalid_elevation
        put32(data, 0, 4_u32)
      when :sid_cutoff
        length -= 1
      when :bad_sid_revision, :truncated_sid, :unaligned_sid
        position = information.in?({2_u32, 11_u32}) ? (sizeof(Void*) == 8 ? 8 : 4) : 0
        sid = (data.to_unsafe + position).as(Void**).value.as(UInt8*)
        case @malformed
        when :bad_sid_revision then sid[0] = 2_u8
        when :truncated_sid    then sid[1] = 15_u8
        when :unaligned_sid
          (data.to_unsafe + position).as(Void**).value = (sid + 1).as(Void*)
        end
      end
    end
    @buffers << data
    {data, length, nil.as(SubjectWindows::Diagnostic?)}
  end

  private def point(bytes, at, offset)
    (bytes.to_unsafe + at).as(Void**).value = (bytes.to_unsafe + offset).as(Void*)
  end

  private def put32(bytes, at, value : UInt32)
    IO::ByteFormat::SystemEndian.encode(value, bytes[at, 4])
  end

  private def diagnostic(operation, code : UInt32?)
    code.try { |value| SubjectWindows::Diagnostic.new(operation, value,
      SubjectWindows::ErrorOrigin::LastError, "#{operation} failed: #{value}") }
  end
end

describe "Windows token subject capture" do
  it "owns complete groups, restrictions, privileges, integrity and elevation observations" do
    provider = TokenSubjectFixtureProvider.new
    snapshot = SubjectWindows::TokenReader.capture_subject(provider: provider)
    snapshot.complete?.should be_true
    snapshot.token.identity.not_nil!.type.primary?.should be_true
    groups = snapshot.groups.value.not_nil!.entries
    groups.map(&.attributes).should eq([0x80000004_u32, 0x10_u32])
    groups[0].enabled?.should be_true
    groups[1].deny_only?.should be_true
    groups[1].enabled?.should be_false
    snapshot.restricted_sids.value.not_nil!.entries.size.should eq(1)
    privileges = snapshot.privileges.value.not_nil!.entries
    privileges.map(&.luid_low).should eq([0x89abcdef_u32, 0x12345678_u32])
    privileges.map(&.luid_high).should eq([-2, 0])
    privileges.map(&.attributes).should eq([0x80000002_u32, 0x100_u32])
    privileges[0].enabled?.should be_true
    privileges[0].used_for_access?.should be_true
    snapshot.integrity.value.not_nil!.attributes.should eq(0x60_u32)
    snapshot.elevation_type.value.not_nil!.limited?.should be_true
    snapshot.elevated.value.should eq(false)
    snapshot.has_restrictions.value.should eq(true)
    snapshot.diagnostics.should be_empty
    provider.opened.should eq([:process])
    provider.closed.should eq([11_u64])
    provider.queried.should eq([1_u32, 8_u32, 2_u32, 11_u32, 3_u32, 25_u32, 18_u32, 20_u32, 21_u32])
    provider.buffers.each(&.fill(0_u8))
    groups[1].sid.bytes.hexstring.should eq("010100000000000100000000")
    snapshot.integrity.value.not_nil!.sid.bytes.hexstring.should eq("010100000000001000100000")
    groups.clear
    snapshot.groups.value.not_nil!.entries.size.should eq(2)
    privileges.clear
    snapshot.privileges.value.not_nil!.entries.size.should eq(2)
  end

  it "queries only selected fields without inventing unrequested observations" do
    provider = TokenSubjectFixtureProvider.new
    information = SubjectWindows::TokenSubjectInformation::Groups | SubjectWindows::TokenSubjectInformation::Elevated
    snapshot = SubjectWindows::TokenReader.capture_subject(information: information, provider: provider)
    snapshot.complete?.should be_true
    snapshot.information.should eq(information)
    snapshot.groups.state.captured?.should be_true
    snapshot.elevated.value.should eq(false)
    snapshot.restricted_sids.state.not_queried?.should be_true
    snapshot.privileges.state.not_queried?.should be_true
    snapshot.integrity.state.not_queried?.should be_true
    snapshot.elevation_type.state.not_queried?.should be_true
    snapshot.has_restrictions.state.not_queried?.should be_true
    provider.queried.should eq([1_u32, 8_u32, 2_u32, 20_u32])
  end

  it "retains other fields and identity when an individual native query fails" do
    [2_u32, 11_u32, 3_u32, 25_u32, 18_u32, 20_u32, 21_u32].each do |kind|
      provider = TokenSubjectFixtureProvider.new
      provider.query_error = kind
      snapshot = SubjectWindows::TokenReader.capture_subject(provider: provider)
      snapshot.complete?.should be_false
      snapshot.token.complete?.should be_true
      fields = {snapshot.groups, snapshot.restricted_sids, snapshot.privileges,
                snapshot.integrity, snapshot.elevation_type, snapshot.elevated,
                snapshot.has_restrictions}
      fields.count(&.state.unavailable?).should eq(1)
      fields.count(&.state.captured?).should eq(6)
      snapshot.diagnostics.size.should eq(1)
      diagnostic = snapshot.diagnostics.first
      diagnostic.operation.should eq("GetTokenInformation(#{kind})")
      diagnostic.code.should eq(5_u32)
      diagnostic.origin.last_error?.should be_true
      provider.closed.should eq([11_u64])
      provider.opened.should eq([:process])
    end
  end

  it "keeps a failed token selection or identity distinct from empty subject fields" do
    provider = TokenSubjectFixtureProvider.new
    provider.thread_error = 5_u32
    failed = SubjectWindows::TokenReader.capture_subject(SubjectWindows::TokenContext::Effective,
      information: SubjectWindows::TokenSubjectInformation::Groups, provider: provider)
    failed.complete?.should be_false
    failed.token.source.should be_nil
    failed.groups.state.unavailable?.should be_true
    failed.privileges.state.not_queried?.should be_true
    failed.diagnostics.first.operation.should eq("OpenThreadToken")
    provider.opened.should eq([:thread])
    provider.queried.should be_empty
    provider.closed.should be_empty

    provider = TokenSubjectFixtureProvider.new
    provider.fault_query = 1_u32
    provider.malformed = :short
    failed = SubjectWindows::TokenReader.capture_subject(provider: provider)
    failed.token.complete?.should be_false
    failed.groups.state.unavailable?.should be_true
    failed.diagnostics.first.operation.should eq("TokenUser")
    provider.queried.should eq([1_u32])
    provider.closed.should eq([11_u64])
  end

  it "keeps effective subject queries on the opened thread token" do
    provider = TokenSubjectFixtureProvider.new
    provider.thread_error = nil
    snapshot = SubjectWindows::TokenReader.capture_subject(SubjectWindows::TokenContext::Effective, provider: provider)
    snapshot.complete?.should be_true
    snapshot.token.source.not_nil!.thread?.should be_true
    snapshot.token.identity.not_nil!.type.impersonation?.should be_true
    provider.opened.should eq([:thread])
    provider.closed.should eq([22_u64])
    provider.queried.first(3).should eq([1_u32, 8_u32, 9_u32])
  end

  it "rejects malformed SID arrays and integrity pointers before copying" do
    [2_u32, 11_u32, 25_u32].each do |kind|
      faults = [:external_pointer, :short, :overreported, :sid_cutoff,
                :bad_sid_revision, :truncated_sid, :unaligned_sid]
      faults += [:inside_records, :large_count] unless kind == 25
      faults.each do |fault|
        provider = TokenSubjectFixtureProvider.new
        provider.fault_query = kind
        provider.malformed = fault
        snapshot = SubjectWindows::TokenReader.capture_subject(provider: provider)
        snapshot.complete?.should be_false
        snapshot.token.complete?.should be_true
        observation = kind == 2 ? snapshot.groups : kind == 11 ? snapshot.restricted_sids : snapshot.integrity
        observation.state.unavailable?.should be_true
        observation.diagnostic.not_nil!.origin.validation?.should be_true
        snapshot.privileges.state.captured?.should be_true
        provider.closed.should eq([11_u64])
      end
    end
  end

  it "rejects malformed privilege counts and scalar fields without discarding other data" do
    [{3_u32, :large_count}, {3_u32, :short}, {3_u32, :overreported},
     {18_u32, :invalid_elevation}, {18_u32, :short}, {20_u32, :short},
     {21_u32, :overreported}].each do |kind, fault|
      provider = TokenSubjectFixtureProvider.new
      provider.fault_query = kind
      provider.malformed = fault
      snapshot = SubjectWindows::TokenReader.capture_subject(provider: provider)
      snapshot.complete?.should be_false
      snapshot.groups.state.captured?.should be_true
      snapshot.diagnostics.size.should eq(1)
      snapshot.diagnostics.first.origin.validation?.should be_true
      provider.closed.should eq([11_u64])
    end
  end

  it "bounds total native allocations and stops querying after the budget is spent" do
    provider = TokenSubjectFixtureProvider.new
    provider.padded = true
    snapshot = SubjectWindows::TokenReader.capture_subject(provider: provider)
    snapshot.complete?.should be_false
    snapshot.groups.value.not_nil!.entries.should be_empty
    snapshot.restricted_sids.value.not_nil!.entries.should be_empty
    snapshot.privileges.value.not_nil!.entries.should be_empty
    snapshot.integrity.state.captured?.should be_true
    snapshot.elevation_type.state.unavailable?.should be_true
    snapshot.elevation_type.diagnostic.not_nil!.operation.should eq("TokenSubject.budget")
    provider.buffers.sum(&.size).should eq(4_194_304)
    provider.queried.should eq([1_u32, 8_u32, 2_u32, 11_u32, 3_u32, 25_u32])
    provider.closed.should eq([11_u64])
  end

  it "counts allocated buffers from failed reads against the whole capture budget" do
    provider = TokenSubjectFixtureProvider.new
    provider.padded = true
    provider.query_error = 2_u32
    provider.failed_buffer = true
    snapshot = SubjectWindows::TokenReader.capture_subject(provider: provider)
    snapshot.groups.state.unavailable?.should be_true
    snapshot.groups.diagnostic.not_nil!.code.should eq(5_u32)
    snapshot.integrity.state.captured?.should be_true
    snapshot.elevation_type.state.unavailable?.should be_true
    provider.buffers.sum(&.size).should eq(4_194_304)
    provider.queried.should eq([1_u32, 8_u32, 2_u32, 11_u32, 3_u32, 25_u32])
    provider.closed.should eq([11_u64])
  end

  it "stops further reads if a provider violates the supplied allocation limit" do
    provider = TokenSubjectFixtureProvider.new
    provider.exceed_limit = true
    snapshot = SubjectWindows::TokenReader.capture_subject(provider: provider)
    snapshot.groups.state.unavailable?.should be_true
    snapshot.groups.diagnostic.not_nil!.operation.should eq("TokenSubject.budget")
    snapshot.privileges.state.unavailable?.should be_true
    provider.queried.should eq([1_u32, 8_u32, 2_u32])
    provider.closed.should eq([11_u64])
  end

  it "rejects empty and unknown scopes before token acquisition" do
    [0_u32, 0x80_u32, UInt32::MAX].each do |value|
      provider = TokenSubjectFixtureProvider.new
      expect_raises(ArgumentError) do
        SubjectWindows::TokenReader.capture_subject(
          information: SubjectWindows::TokenSubjectInformation.new(value), provider: provider)
      end
      provider.opened.should be_empty
    end
  end

  it "keeps a captured empty restricted list distinct from its filtering history" do
    provider = TokenSubjectFixtureProvider.new
    provider.empty_restricted = true
    snapshot = SubjectWindows::TokenReader.capture_subject(provider: provider)
    snapshot.complete?.should be_true
    snapshot.restricted_sids.state.captured?.should be_true
    snapshot.restricted_sids.value.not_nil!.entries.should be_empty
    snapshot.has_restrictions.value.should eq(true)
  end

  it "rejects contradictory field evidence and subject scope" do
    diagnostic = SubjectWindows::Diagnostic.new("TokenGroups", 5_u32,
      SubjectWindows::ErrorOrigin::LastError, "denied")
    expect_raises(ArgumentError) do
      SubjectWindows::TokenObservation(Bool).new(SubjectWindows::TokenObservationState::Captured)
    end
    expect_raises(ArgumentError) do
      SubjectWindows::TokenObservation(Bool).new(SubjectWindows::TokenObservationState::Unavailable)
    end
    expect_raises(ArgumentError) do
      SubjectWindows::TokenObservation(Bool).new(value: false)
    end
    expect_raises(ArgumentError) do
      SubjectWindows::TokenObservation(Bool).new(SubjectWindows::TokenObservationState::Captured,
        false, diagnostic)
    end
    provider = TokenSubjectFixtureProvider.new
    captured = SubjectWindows::TokenReader.capture_subject(provider: provider)
    expect_raises(ArgumentError) do
      SubjectWindows::TokenSubjectSnapshot.new(captured.token,
        SubjectWindows::TokenSubjectInformation::Groups, captured.groups,
        captured.restricted_sids, captured.privileges, captured.integrity,
        captured.elevation_type, captured.elevated, captured.has_restrictions)
    end
    failed = SubjectWindows::TokenSnapshot.new(SubjectWindows::TokenContext::Process, diagnostic: diagnostic)
    expect_raises(ArgumentError) do
      SubjectWindows::TokenSubjectSnapshot.new(failed, captured.information,
        captured.groups, captured.restricted_sids, captured.privileges,
        captured.integrity, captured.elevation_type, captured.elevated, captured.has_restrictions)
    end
  end
end
