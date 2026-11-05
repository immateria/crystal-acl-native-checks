require "./spec_helper"
require "../src/filesystem_access_control/windows/token_reader"

alias TokenWindows = Filesystem::AccessControl::Windows

# These are native-shaped buffers, including an in-buffer SID pointer. The
# provider controls only the syscall boundary; the real selection and decoder run.
private class TokenFixtureProvider
  getter opens = [] of Symbol
  getter queries = [] of UInt32
  getter closed = [] of UInt64
  property thread_error : UInt32? = 1008_u32
  property process_error : UInt32?
  property query_error : UInt32?
  property malformed : Symbol?
  property forced_type : UInt32?
  property level = 2_u32
  property short_query : UInt32?
  getter buffers = [] of Bytes

  def open_process
    @opens << :process
    {Pointer(Void).new(11_u64), diagnostic("OpenProcessToken", @process_error)}
  end

  def open_thread
    @opens << :thread
    {Pointer(Void).new(22_u64), diagnostic("OpenThreadToken", @thread_error)}
  end

  def query(token : Void*, information : UInt32)
    @queries << information
    if @query_error == information
      return {nil, 0_u32, diagnostic("GetTokenInformation(#{information})", 5_u32)}
    end
    data = if information == 1
             header = sizeof(Void*) == 8 ? 16 : 8
             bytes = Bytes.new(header + 12, 0_u8)
             bytes.to_unsafe.as(Void**).value = (bytes.to_unsafe + header).as(Void*)
             "010100000000000512000000".hexbytes.copy_to(bytes[header, 12])
             case @malformed
             when :external_pointer
               bytes.to_unsafe.as(Void**).value = Pointer(Void).new(1_u64)
             when :header_pointer
               bytes.to_unsafe.as(Void**).value = bytes.to_unsafe.as(Void*)
             when :truncated_sid
               bytes[header + 1] = 15_u8
             when :bad_revision
               bytes[header] = 2_u8
             when :unaligned_pointer
               bytes.to_unsafe.as(Void**).value = (bytes.to_unsafe + header + 1).as(Void*)
             end
             bytes
           else
             value = information == 8 ? (@forced_type || (token.address == 22 ? 2_u32 : 1_u32)) : @level
             bytes = Bytes.new(4)
             IO::ByteFormat::SystemEndian.encode(value, bytes)
             bytes
           end
    @buffers << data
    length = case @malformed
             when :overreported         then data.size.to_u32 + 1
             when :short_header         then 1_u32
             when :sid_outside_returned then sizeof(Void*).to_u32 * 2
             else                            data.size.to_u32
             end
    length = 3_u32 if @short_query == information
    {data, length, nil.as(TokenWindows::Diagnostic?)}
  end

  def close(token : Void*)
    @closed << token.address
  end

  private def diagnostic(operation, code : UInt32?)
    code.try { |value| TokenWindows::Diagnostic.new(operation, value,
      TokenWindows::ErrorOrigin::LastError, "#{operation} failed: #{value}") }
  end
end

describe TokenWindows::TokenReader do
  it "rejects contradictory public identity and observation states" do
    user = TokenWindows::SID.new("010100000000000512000000".hexbytes)
    primary = TokenWindows::TokenIdentity.new(user, TokenWindows::TokenType::Primary, nil)
    expect_raises(ArgumentError) do
      TokenWindows::TokenIdentity.new(user, TokenWindows::TokenType::Primary,
        TokenWindows::ImpersonationLevel::Delegation)
    end
    expect_raises(ArgumentError) do
      TokenWindows::TokenIdentity.new(user, TokenWindows::TokenType::Impersonation, nil)
    end
    expect_raises(ArgumentError) do
      TokenWindows::TokenIdentity.new(user, TokenWindows::TokenType.new(3_u32), nil)
    end
    expect_raises(ArgumentError) do
      TokenWindows::TokenIdentity.new(user, TokenWindows::TokenType::Impersonation,
        TokenWindows::ImpersonationLevel.new(4_u32))
    end
    expect_raises(ArgumentError) do
      TokenWindows::TokenSnapshot.new(TokenWindows::TokenContext::Effective, identity: primary)
    end
    expect_raises(ArgumentError) do
      TokenWindows::TokenSnapshot.new(TokenWindows::TokenContext::Effective,
        TokenWindows::TokenSource::Thread, primary)
    end
    expect_raises(ArgumentError) do
      TokenWindows::TokenSnapshot.new(TokenWindows::TokenContext::Process,
        TokenWindows::TokenSource::Thread)
    end
    expect_raises(ArgumentError) do
      TokenWindows::TokenSnapshot.new(TokenWindows::TokenContext.new(99))
    end
  end

  it "selects the process explicitly and owns its identity after token cleanup" do
    provider = TokenFixtureProvider.new
    snapshot = TokenWindows::TokenReader.capture(provider: provider)
    snapshot.complete?.should be_true
    snapshot.context.process?.should be_true
    snapshot.source.not_nil!.process?.should be_true
    identity = snapshot.identity.not_nil!
    identity.type.primary?.should be_true
    identity.impersonation_level.should be_nil
    provider.opens.should eq([:process])
    provider.queries.should eq([1_u32, 8_u32])
    provider.closed.should eq([11_u64])
    provider.buffers.each(&.fill(0_u8))
    identity.user.bytes.hexstring.should eq("010100000000000512000000")
  end

  it "observes the thread token when an effective context is requested" do
    (0_u32..3_u32).each do |level|
      provider = TokenFixtureProvider.new
      provider.thread_error = nil
      provider.level = level
      snapshot = TokenWindows::TokenReader.capture(TokenWindows::TokenContext::Effective, provider: provider)
      snapshot.complete?.should be_true
      snapshot.context.effective?.should be_true
      snapshot.source.not_nil!.thread?.should be_true
      snapshot.identity.not_nil!.type.impersonation?.should be_true
      snapshot.identity.not_nil!.impersonation_level.not_nil!.value.should eq(level)
      provider.opens.should eq([:thread])
      provider.queries.should eq([1_u32, 8_u32, 9_u32])
      provider.closed.should eq([22_u64])
    end
  end

  it "falls back only when the thread has no token" do
    [1008_u32, 5_u32, 1347_u32].each do |code|
      provider = TokenFixtureProvider.new
      provider.thread_error = code
      snapshot = TokenWindows::TokenReader.capture(TokenWindows::TokenContext::Effective, provider: provider)
      if code == 1008
        snapshot.complete?.should be_true
        snapshot.source.not_nil!.process?.should be_true
        provider.opens.should eq([:thread, :process])
        provider.closed.should eq([11_u64])
      else
        snapshot.complete?.should be_false
        snapshot.source.should be_nil
        snapshot.diagnostic.not_nil!.code.should eq(code)
        snapshot.diagnostic.not_nil!.operation.should eq("OpenThreadToken")
        provider.opens.should eq([:thread])
        provider.queries.should be_empty
        provider.closed.should be_empty
      end
    end
  end

  it "preserves process-open and information-query failures without a weaker retry" do
    provider = TokenFixtureProvider.new
    provider.process_error = 5_u32
    failed = TokenWindows::TokenReader.capture(provider: provider)
    failed.complete?.should be_false
    failed.diagnostic.not_nil!.operation.should eq("OpenProcessToken")
    provider.closed.should be_empty
    fallback = TokenWindows::TokenReader.capture(TokenWindows::TokenContext::Effective, provider: provider)
    fallback.complete?.should be_false
    fallback.diagnostic.not_nil!.operation.should eq("OpenProcessToken")
    provider.opens.should eq([:process, :thread, :process])
    provider.closed.should be_empty
    [1_u32, 8_u32, 9_u32].each do |information|
      provider = TokenFixtureProvider.new
      provider.thread_error = nil
      provider.query_error = information
      failed = TokenWindows::TokenReader.capture(TokenWindows::TokenContext::Effective, provider: provider)
      failed.complete?.should be_false
      failed.source.not_nil!.thread?.should be_true
      failed.diagnostic.not_nil!.code.should eq(5_u32)
      failed.diagnostic.not_nil!.operation.should eq("GetTokenInformation(#{information})")
      provider.opens.should eq([:thread])
      provider.closed.should eq([22_u64])
    end
  end

  it "bounds every pointer and SID against the successful returned length" do
    [:external_pointer, :header_pointer, :truncated_sid, :bad_revision, :unaligned_pointer,
     :overreported, :short_header, :sid_outside_returned].each do |fault|
      provider = TokenFixtureProvider.new
      provider.malformed = fault
      snapshot = TokenWindows::TokenReader.capture(provider: provider)
      snapshot.complete?.should be_false
      snapshot.identity.should be_nil
      snapshot.diagnostic.not_nil!.origin.validation?.should be_true
      snapshot.diagnostic.not_nil!.operation.should eq("TokenUser")
      provider.queries.should eq([1_u32])
      provider.closed.should eq([11_u64])
    end
  end

  it "rejects truncated type and level buffers and still closes the token" do
    [8_u32, 9_u32].each do |information|
      provider = TokenFixtureProvider.new
      provider.thread_error = nil
      provider.short_query = information
      failed = TokenWindows::TokenReader.capture(TokenWindows::TokenContext::Effective, provider: provider)
      failed.complete?.should be_false
      failed.diagnostic.not_nil!.origin.validation?.should be_true
      failed.diagnostic.not_nil!.operation.should eq(information == 8 ? "TokenType" : "TokenImpersonationLevel")
      provider.closed.should eq([22_u64])
    end
  end

  it "rejects invalid token types, source disagreements and impersonation levels" do
    [0_u32, 2_u32, 3_u32, UInt32::MAX].each do |type|
      provider = TokenFixtureProvider.new
      provider.forced_type = type
      failed = TokenWindows::TokenReader.capture(provider: provider)
      failed.complete?.should be_false
      failed.diagnostic.not_nil!.operation.should eq("TokenType")
      provider.closed.should eq([11_u64])
    end
    provider = TokenFixtureProvider.new
    provider.thread_error = nil
    provider.forced_type = 1_u32
    TokenWindows::TokenReader.capture(TokenWindows::TokenContext::Effective,
      provider: provider).complete?.should be_false
    provider = TokenFixtureProvider.new
    provider.thread_error = nil
    provider.level = 4_u32
    failed = TokenWindows::TokenReader.capture(TokenWindows::TokenContext::Effective, provider: provider)
    failed.complete?.should be_false
    failed.diagnostic.not_nil!.operation.should eq("TokenImpersonationLevel")
    provider.closed.should eq([22_u64])
  end

  it "rejects unknown context values before opening a token" do
    provider = TokenFixtureProvider.new
    expect_raises(ArgumentError) do
      TokenWindows::TokenReader.capture(TokenWindows::TokenContext.new(99), provider: provider)
    end
    provider.opens.should be_empty
  end
end
