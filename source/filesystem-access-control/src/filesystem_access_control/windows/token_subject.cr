module Filesystem::AccessControl::Windows
  @[Flags]
  enum TokenSubjectInformation : UInt32
    Groups          = 0x01
    RestrictedSids  = 0x02
    Privileges      = 0x04
    Integrity       = 0x08
    ElevationType   = 0x10
    Elevated        = 0x20
    HasRestrictions = 0x40
  end

  enum TokenObservationState
    NotQueried
    Captured
    Unavailable
  end

  # Capture status belongs to the field: unavailable data is never an empty
  # group list, an absent privilege, or an unelevated token.
  class TokenObservation(T)
    getter state : TokenObservationState
    getter value : T?
    getter diagnostic : Diagnostic?

    def initialize(@state : TokenObservationState = TokenObservationState::NotQueried,
                   @value : T? = nil, @diagnostic : Diagnostic? = nil)
      valid = case @state
              when .not_queried? then @value.nil? && @diagnostic.nil?
              when .captured?    then !@value.nil? && @diagnostic.nil?
              when .unavailable? then @value.nil? && !@diagnostic.nil?
              else                    false
              end
      raise ArgumentError.new("Contradictory token field observation") unless valid
    end
  end

  record TokenSIDAndAttributes, sid : SID, attributes : UInt32 do
    def enabled? : Bool
      (@attributes & 0x04) != 0
    end

    def deny_only? : Bool
      (@attributes & 0x10) != 0
    end
  end

  class TokenSIDList
    @entries : Array(TokenSIDAndAttributes)

    def initialize(entries : Array(TokenSIDAndAttributes))
      @entries = entries.dup
    end

    def entries : Array(TokenSIDAndAttributes)
      @entries.dup
    end

    def_equals_and_hash @entries
  end

  # Preserve the complete LUID and attributes. A name lookup is a separate
  # operation, and elevation is not a substitute for enabled privilege evidence.
  record TokenPrivilege, luid_low : UInt32, luid_high : Int32, attributes : UInt32 do
    def enabled? : Bool
      (@attributes & 0x02) != 0
    end

    def used_for_access? : Bool
      (@attributes & 0x80000000) != 0
    end
  end

  class TokenPrivileges
    @entries : Array(TokenPrivilege)

    def initialize(entries : Array(TokenPrivilege))
      @entries = entries.dup
    end

    def entries : Array(TokenPrivilege)
      @entries.dup
    end

    def_equals_and_hash @entries
  end

  enum TokenElevationType : UInt32
    Default = 1
    Full    = 2
    Limited = 3
  end

  # Separate queries through one opened token; this is not an atomic token
  # revision, an authorization result or a retained token for AccessCheck.
  class TokenSubjectSnapshot
    getter token : TokenSnapshot
    getter information : TokenSubjectInformation
    getter groups : TokenObservation(TokenSIDList)
    getter restricted_sids : TokenObservation(TokenSIDList)
    getter privileges : TokenObservation(TokenPrivileges)
    getter integrity : TokenObservation(TokenSIDAndAttributes)
    getter elevation_type : TokenObservation(TokenElevationType)
    getter elevated : TokenObservation(Bool)
    getter has_restrictions : TokenObservation(Bool)

    def initialize(@token : TokenSnapshot, @information : TokenSubjectInformation,
                   @groups : TokenObservation(TokenSIDList),
                   @restricted_sids : TokenObservation(TokenSIDList),
                   @privileges : TokenObservation(TokenPrivileges),
                   @integrity : TokenObservation(TokenSIDAndAttributes),
                   @elevation_type : TokenObservation(TokenElevationType),
                   @elevated : TokenObservation(Bool),
                   @has_restrictions : TokenObservation(Bool))
      self.class.validate_information!(@information)
      { {@information.groups?, @groups.state},
       {@information.restricted_sids?, @restricted_sids.state},
       {@information.privileges?, @privileges.state},
       {@information.integrity?, @integrity.state},
       {@information.elevation_type?, @elevation_type.state},
       {@information.elevated?, @elevated.state},
       {@information.has_restrictions?, @has_restrictions.state} }.each do |requested, state|
        if requested == state.not_queried?
          raise ArgumentError.new("Token field state disagrees with query scope")
        end
        if !@token.complete? && state.captured?
          raise ArgumentError.new("Token subject requires a captured identity")
        end
      end
    end

    def complete? : Bool
      @token.complete? && diagnostics.empty?
    end

    def diagnostics : Array(Diagnostic)
      {@token.diagnostic, @groups.diagnostic, @restricted_sids.diagnostic,
       @privileges.diagnostic, @integrity.diagnostic, @elevation_type.diagnostic,
       @elevated.diagnostic, @has_restrictions.diagnostic}.to_a.compact.uniq
    end

    def self.validate_information!(information : TokenSubjectInformation) : Nil
      if information.value == 0 || (information.value & ~127_u32) != 0
        raise ArgumentError.new("Unsupported or empty token subject query")
      end
    end
  end

  module TokenReader
    MAX_SUBJECT_INFORMATION_SIZE = 1_048_576
    MAX_SUBJECT_CAPTURE_BYTES    = 4_194_304
    MAX_SUBJECT_ENTRIES          =      4096

    # The native provider checks this limit before allocating. Count allocated
    # capacity, including buffers from failed reads, across the whole workflow.
    private class SubjectQueries(P)
      @remaining = MAX_SUBJECT_CAPTURE_BYTES

      def initialize(@provider : P)
      end

      def query(token : Void*, information : UInt32)
        if @remaining == 0
          return {nil, 0_u32, Diagnostic.new("TokenSubject.budget", nil,
            ErrorOrigin::Validation, "Token subject allocation budget exhausted")}
        end
        limit = information.in?({1_u32, 8_u32, 9_u32}) ? MAX_INFORMATION_SIZE : MAX_SUBJECT_INFORMATION_SIZE
        limit = Math.min(limit, @remaining)
        data, length, diagnostic = @provider.query(token, information, limit)
        if data
          if data.size > limit
            @remaining = 0
            return {nil, 0_u32, Diagnostic.new("TokenSubject.budget", nil,
              ErrorOrigin::Validation, "Token provider exceeded its allocation limit")}
          end
          @remaining -= data.size
        end
        {data, length, diagnostic}
      end
    end

    {% if flag?(:windows) %}
      def self.capture_subject(context : TokenContext = TokenContext::Process, *,
                               information : TokenSubjectInformation = TokenSubjectInformation::All) : TokenSubjectSnapshot
        capture_subject(context, information: information, provider: NativeTokenProvider.new)
      end
    {% end %}

    def self.capture_subject(context : TokenContext = TokenContext::Process, *,
                             information : TokenSubjectInformation = TokenSubjectInformation::All,
                             provider) : TokenSubjectSnapshot
      TokenSubjectSnapshot.validate_information!(information)
      handle, source, diagnostic = select_token(context, provider)
      if diagnostic
        identity = TokenSnapshot.new(context, diagnostic: diagnostic)
        return subject_unavailable(identity, information, diagnostic)
      end
      begin
        queries = SubjectQueries.new(provider)
        identity = read_identity(context, source.not_nil!, handle, queries)
        unless identity.complete?
          return subject_unavailable(identity, information, identity.diagnostic.not_nil!)
        end
        groups = observe(information.groups?, queries, handle, 2_u32, "TokenGroups") { |data, length| decode_sid_list(data, length) }
        restricted = observe(information.restricted_sids?, queries, handle, 11_u32, "TokenRestrictedSids") { |data, length| decode_sid_list(data, length) }
        privileges = observe(information.privileges?, queries, handle, 3_u32, "TokenPrivileges") { |data, length| decode_privileges(data, length) }
        integrity = observe(information.integrity?, queries, handle, 25_u32, "TokenIntegrityLevel") { |data, length| decode_integrity(data, length) }
        elevation_type = observe(information.elevation_type?, queries, handle, 18_u32, "TokenElevationType") do |data, length|
          value = decode_enum(data, length)
          raise ArgumentError.new("Invalid token elevation type") unless 1 <= value <= 3
          TokenElevationType.new(value)
        end
        elevated = observe(information.elevated?, queries, handle, 20_u32, "TokenElevation") { |data, length| decode_enum(data, length) != 0 }
        restrictions = observe(information.has_restrictions?, queries, handle, 21_u32, "TokenHasRestrictions") { |data, length| decode_boolean(data, length) }
        TokenSubjectSnapshot.new(identity, information, groups, restricted, privileges,
          integrity, elevation_type, elevated, restrictions)
      ensure
        provider.close(handle)
      end
    end

    private def self.decode_boolean(data : Bytes?, length : UInt32) : Bool
      unless data && length == 1 && length <= data.size && data.size <= MAX_INFORMATION_SIZE
        raise ArgumentError.new("Invalid token BOOLEAN length")
      end
      data[0] != 0
    end

    private def self.subject_unavailable(token, information, diagnostic) : TokenSubjectSnapshot
      TokenSubjectSnapshot.new(token, information,
        unavailable(TokenSIDList, information.groups?, diagnostic),
        unavailable(TokenSIDList, information.restricted_sids?, diagnostic),
        unavailable(TokenPrivileges, information.privileges?, diagnostic),
        unavailable(TokenSIDAndAttributes, information.integrity?, diagnostic),
        unavailable(TokenElevationType, information.elevation_type?, diagnostic),
        unavailable(Bool, information.elevated?, diagnostic),
        unavailable(Bool, information.has_restrictions?, diagnostic))
    end

    private def self.unavailable(type : T.class, requested, diagnostic) : TokenObservation(T) forall T
      requested ? TokenObservation(T).new(TokenObservationState::Unavailable, diagnostic: diagnostic) : TokenObservation(T).new
    end

    private def self.observe(requested, queries, token, kind, operation, &block : Bytes?, UInt32 -> T) : TokenObservation(T) forall T
      return TokenObservation(T).new unless requested
      data, length, diagnostic = queries.query(token, kind)
      return TokenObservation(T).new(TokenObservationState::Unavailable, diagnostic: diagnostic) if diagnostic
      begin
        TokenObservation(T).new(TokenObservationState::Captured, yield(data, length))
      rescue error : ArgumentError
        TokenObservation(T).new(TokenObservationState::Unavailable, diagnostic: Diagnostic.new(operation, nil, ErrorOrigin::Validation, error.message || "Invalid token information"))
      end
    end

    private def self.subject_buffer(data : Bytes?, length : UInt32, minimum : Int32) : Bytes
      unless data && minimum <= length <= data.size && data.size <= MAX_SUBJECT_INFORMATION_SIZE
        raise ArgumentError.new("Invalid token information returned length")
      end
      data
    end

    private def self.sid_and_attributes(data : Bytes, length : UInt32, position : Int32,
                                        sid_start : Int32) : TokenSIDAndAttributes
      pointer = (data.to_unsafe + position).as(Void**).value.address
      base = data.to_unsafe.address
      unless pointer >= base && pointer - base >= sid_start &&
             pointer - base <= length - 8 && (pointer & 3) == 0
        raise ArgumentError.new("Token SID is outside its returned buffer or unaligned")
      end
      offset = (pointer - base).to_i
      size = 8 + 4 * data[offset + 1].to_i
      raise ArgumentError.new("Truncated token SID") unless size <= length - offset
      attributes = IO::ByteFormat::SystemEndian.decode(UInt32, data[position + sizeof(Void*), 4])
      TokenSIDAndAttributes.new(SID.new(data[offset, size]), attributes)
    end

    private def self.decode_sid_list(data : Bytes?, length : UInt32) : TokenSIDList
      offset = sizeof(Void*) == 8 ? 8 : 4
      stride = sizeof(Void*) == 8 ? 16 : 8
      data = subject_buffer(data, length, offset)
      count = IO::ByteFormat::SystemEndian.decode(UInt32, data[0, 4])
      unless count <= MAX_SUBJECT_ENTRIES && count <= (length - offset) // stride
        raise ArgumentError.new("Invalid token SID array count or extent")
      end
      sid_start = offset + count.to_i * stride
      TokenSIDList.new(Array(TokenSIDAndAttributes).new(count.to_i) do |index|
        sid_and_attributes(data, length, offset + index * stride, sid_start)
      end)
    end

    private def self.decode_privileges(data : Bytes?, length : UInt32) : TokenPrivileges
      data = subject_buffer(data, length, 4)
      count = IO::ByteFormat::SystemEndian.decode(UInt32, data[0, 4])
      unless count <= MAX_SUBJECT_ENTRIES && count <= (length - 4) // 12
        raise ArgumentError.new("Invalid token privilege count or extent")
      end
      TokenPrivileges.new(Array(TokenPrivilege).new(count.to_i) do |index|
        position = 4 + index * 12
        TokenPrivilege.new(IO::ByteFormat::SystemEndian.decode(UInt32, data[position, 4]),
          IO::ByteFormat::SystemEndian.decode(Int32, data[position + 4, 4]),
          IO::ByteFormat::SystemEndian.decode(UInt32, data[position + 8, 4]))
      end)
    end

    private def self.decode_integrity(data : Bytes?, length : UInt32) : TokenSIDAndAttributes
      header = sizeof(Void*) == 8 ? 16 : 8
      data = subject_buffer(data, length, header)
      sid_and_attributes(data, length, 0, header)
    end
  end
end
