require "./observation"

module Filesystem::AccessControl::Windows
  enum TokenContext
    Process
    Effective
  end

  enum TokenSource
    Process
    Thread
  end

  enum TokenType : UInt32
    Primary       = 1
    Impersonation = 2
  end

  enum ImpersonationLevel : UInt32
    Anonymous      = 0
    Identification = 1
    Impersonation  = 2
    Delegation     = 3
  end

  # Identity only: groups, restrictions, privileges and integrity are not captured.
  struct TokenIdentity
    getter user : SID
    getter type : TokenType
    getter impersonation_level : ImpersonationLevel?

    def initialize(@user : SID, @type : TokenType, @impersonation_level : ImpersonationLevel?)
      valid = case @type
              when .primary?       then @impersonation_level.nil?
              when .impersonation? then !!@impersonation_level.try { |level| level.value <= 3 }
              else                      false
              end
      raise ArgumentError.new("Invalid token type or impersonation level") unless valid
    end

    def_equals_and_hash @user, @type, @impersonation_level
  end

  class TokenSnapshot
    getter context : TokenContext
    getter source : TokenSource?
    getter identity : TokenIdentity?
    getter diagnostic : Diagnostic?

    def initialize(@context : TokenContext, @source : TokenSource? = nil,
                   @identity : TokenIdentity? = nil, @diagnostic : Diagnostic? = nil)
      unless @context.process? || @context.effective?
        raise ArgumentError.new("Unsupported token context")
      end
      if source = @source
        unless source.process? || (source.thread? && @context.effective?)
          raise ArgumentError.new("Token source disagrees with requested context")
        end
      end
      if identity = @identity
        expected = @source.try(&.process?) ? TokenType::Primary : TokenType::Impersonation
        unless @source && identity.type == expected && @diagnostic.nil?
          raise ArgumentError.new("Token identity disagrees with observation evidence")
        end
      elsif @diagnostic.nil?
        raise ArgumentError.new("Incomplete token observation requires a diagnostic")
      end
    end

    def complete? : Bool
      !@identity.nil?
    end
  end

  # Token handles are owned for this capture and closed before returning. A
  # provider separates syscall results from portable selection and validation.
  module TokenReader
    MAX_INFORMATION_SIZE = 4096

    {% if flag?(:windows) %}
      def self.capture(context : TokenContext = TokenContext::Process) : TokenSnapshot
        capture(context, provider: NativeTokenProvider.new)
      end
    {% end %}

    def self.capture(context : TokenContext = TokenContext::Process, *, provider) : TokenSnapshot
      token, source, diagnostic = select_token(context, provider)
      return TokenSnapshot.new(context, diagnostic: diagnostic) if diagnostic
      begin
        read_identity(context, source.not_nil!, token, provider)
      ensure
        provider.close(token)
      end
    end

    private def self.select_token(context : TokenContext, provider)
      unless context.process? || context.effective?
        raise ArgumentError.new("Unsupported token context")
      end
      source = TokenSource::Process
      if context.effective?
        token, diagnostic = provider.open_thread
        if diagnostic
          return {token, nil.as(TokenSource?), diagnostic} unless diagnostic.code == 1008_u32
          token, diagnostic = provider.open_process
        else
          source = TokenSource::Thread
        end
      else
        token, diagnostic = provider.open_process
      end
      {token, diagnostic ? nil.as(TokenSource?) : source, diagnostic}
    end

    private def self.read_identity(context : TokenContext, source : TokenSource, token : Void*, provider) : TokenSnapshot
      operation = "TokenUser"
      begin
        data, length, diagnostic = provider.query(token, 1_u32)
        return TokenSnapshot.new(context, source, diagnostic: diagnostic) if diagnostic
        user = decode_user(data, length)

        operation = "TokenType"
        data, length, diagnostic = provider.query(token, 8_u32)
        return TokenSnapshot.new(context, source, diagnostic: diagnostic) if diagnostic
        value = decode_enum(data, length)
        expected = source.process? ? TokenType::Primary : TokenType::Impersonation
        raise ArgumentError.new("Token type does not match its source") unless value == expected.value

        level = nil.as(ImpersonationLevel?)
        if expected.impersonation?
          operation = "TokenImpersonationLevel"
          data, length, diagnostic = provider.query(token, 9_u32)
          return TokenSnapshot.new(context, source, diagnostic: diagnostic) if diagnostic
          value = decode_enum(data, length)
          raise ArgumentError.new("Invalid impersonation level") unless value <= 3
          level = ImpersonationLevel.new(value)
        end
        TokenSnapshot.new(context, source, TokenIdentity.new(user, expected, level))
      rescue error : ArgumentError
        diagnostic = Diagnostic.new(operation, nil, ErrorOrigin::Validation,
          error.message || "Invalid token information")
        TokenSnapshot.new(context, source, diagnostic: diagnostic)
      end
    end

    private def self.decode_user(data : Bytes?, length : UInt32) : SID
      raise ArgumentError.new("Missing TokenUser buffer") unless data
      # SID_AND_ATTRIBUTES has a native pointer, a DWORD, and native padding.
      header = sizeof(Void*) == 8 ? 16 : 8
      unless header <= length <= data.size && data.size <= MAX_INFORMATION_SIZE
        raise ArgumentError.new("Invalid TokenUser returned length")
      end
      pointer = data.to_unsafe.as(Void**).value.address
      base = data.to_unsafe.address
      unless pointer >= base && pointer - base >= header &&
             pointer - base <= length - 8 && (pointer & 3) == 0
        raise ArgumentError.new("TokenUser SID is outside its returned buffer or unaligned")
      end
      offset = (pointer - base).to_i
      size = 8 + 4 * data[offset + 1].to_i
      raise ArgumentError.new("Truncated TokenUser SID") unless size <= length - offset
      SID.new(data[offset, size])
    end

    private def self.decode_enum(data : Bytes?, length : UInt32) : UInt32
      unless data && length == 4 && length <= data.size && data.size <= MAX_INFORMATION_SIZE
        raise ArgumentError.new("Invalid token enumeration length")
      end
      IO::ByteFormat::SystemEndian.decode(UInt32, data[0, 4])
    end
  end
end

require "./token_subject"
