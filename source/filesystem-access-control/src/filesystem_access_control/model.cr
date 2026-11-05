require "./darwin/model"
require "./windows/observation"
require "./windows/token_reader"
require "./windows/rights"
require "./windows/handle_capture"

module Filesystem::AccessControl
  # :nodoc: Native ACL bindings owned by the security provider.
  module Native
    {% if flag?(:linux) %}
      module Linux
      end
    {% elsif flag?(:darwin) %}
      module Darwin
      end
    {% elsif flag?(:windows) %}
      module Windows
      end
    {% end %}
  end

  # The kind of opened inode/HANDLE inspected by ACL backends. A typed target
  # prevents unrecognized symbols from silently choosing file or directory
  # policies differently across operating systems.
  enum Target
    Directory
    File
  end

  # A closed vocabulary of ACL inspection outcomes. An unavailable or
  # unrestricted inspection cannot certify a private inode, regardless of
  # platform or the reported owner/mode.
  enum State
    None
    Present
    Unavailable
    Unrestricted
    Unsupported
  end
end

require "./linux/observation"

module Filesystem::AccessControl
  # Captured ACL entry; rights are platform native. Linux rights use rwx (4/2/1).
  # Portable presentation used only by the Linux POSIX ACL and Windows DACL
  # adapters. Darwin's ordered ACL is exposed as Report#snapshot instead.
  {% if flag?(:linux) %}
    alias Entry = Linux::Entry
  {% else %}
    record Entry, subject : String, rights : UInt32,
      inherited : Bool = false, effect : Symbol = :allow
  {% end %}

  # An observed inode security snapshot, not a capability or an access token.
  # `private?` is deliberately stricter than a POSIX 0700 check: ANY default
  # ACL and ANY named user/group entry disqualifies a directory.
  class Report
    getter path : Path?
    getter owner_matches : Bool?
    getter mode : Int32?
    @access_entries : Array(Entry)
    @default_entries : Array(Entry)
    getter acl_state : State
    getter detail : String?
    getter backend : Symbol
    getter private_result : Bool
    {% if flag?(:darwin) %}
      alias NativeSnapshot = Darwin::Snapshot
    {% elsif flag?(:linux) %}
      alias NativeSnapshot = Linux::Snapshot
    {% elsif flag?(:windows) %}
      alias NativeSnapshot = Windows::Snapshot
    {% else %}
      alias NativeSnapshot = Nil
    {% end %}
    getter snapshot : NativeSnapshot?
    @privacy_issues : Array(Linux::PrivacyIssue)

    def initialize(@path : Path?, @backend : Symbol, @owner_matches : Bool?,
                   @mode : Int32?, access_entries : Array(Entry),
                   default_entries : Array(Entry), @acl_state : State,
                   private_result : Bool, @detail : String? = nil,
                   @snapshot : NativeSnapshot? = nil,
                   privacy_issues : Array(Linux::PrivacyIssue) = [] of Linux::PrivacyIssue)
      # Reports are observed snapshots, not caller-owned mutable ACL buffers.
      @privacy_issues = privacy_issues.dup
      @access_entries = access_entries.dup
      @default_entries = default_entries.dup
      # Safety is never inferred solely from the backend's affirmative flag:
      # an unavailable/unknown inspection, missing owner or diagnostic error
      # cannot produce an affirmative privacy observation.
      snapshot_safe = {% if flag?(:darwin) %}
                        if native = @snapshot
                          native.complete? && !native.nonempty? &&
                            native.mount.try { |mount| !mount.ownership_ignored? && !mount.server_authorized? } == true &&
                            (native.acl_flags & ~Darwin::Constants::ACL_FLAG_NO_INHERIT) == 0
                        else
                          true
                        end
                      {% elsif flag?(:linux) %}
                        @snapshot.nil? || @snapshot.not_nil!.complete?
                      {% elsif flag?(:windows) %}
                        @snapshot.nil? || (@snapshot.not_nil!.complete? &&
                          @snapshot.not_nil!.information.owner? && @snapshot.not_nil!.information.dacl?)
                      {% else %}
                        true
                      {% end %}
      @private_result = private_result && @privacy_issues.empty? && snapshot_safe && @owner_matches == true && @detail.nil? &&
                        (@acl_state == State::Present ||
                         (@acl_state == State::None && @access_entries.empty? && @default_entries.empty?))
    end

    {% unless flag?(:darwin) %}
      def access_entries : Array(Entry)
        @access_entries.dup
      end

      def default_entries : Array(Entry)
        @default_entries.dup
      end
    {% end %}

    def privacy_issues : Array(Linux::PrivacyIssue)
      @privacy_issues.dup
    end

    def private? : Bool
      @private_result
    end

    def require_private! : Report
      unless private?
        raise InsecureAccessError.new("Filesystem privacy could not be established (#{@backend}, #{@acl_state}): #{@detail || @path}")
      end
      self
    end
  end

  class InsecureAccessError < Filesystem::Capabilities::Error
  end
end
