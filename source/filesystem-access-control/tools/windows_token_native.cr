# Run as a disposable Windows process. Only this probe impersonates; library
# capture never adjusts tokens, privileges or the caller's security context.
require "../src/filesystem-access-control"

{% if flag?(:windows) %}
  @[Link("advapi32")]
  lib TokenProbeNative
    fun impersonate_self = ImpersonateSelf(level : UInt32) : Int32
    fun revert_to_self = RevertToSelf : Int32
  end

  alias TokenProbe = Filesystem::AccessControl::Windows
  process = TokenProbe::TokenReader.capture
  raise "Process identity unavailable: #{process.diagnostic}" unless process.complete?
  raise "Process source/type incorrect" unless process.source.not_nil!.process? && process.identity.not_nil!.type.primary?
  ordinary = TokenProbe::TokenReader.capture(TokenProbe::TokenContext::Effective)
  raise "Effective process fallback unavailable: #{ordinary.diagnostic}" unless ordinary.complete?
  raise "Fresh helper unexpectedly has a thread token" unless ordinary.source.not_nil!.process?
  raise "Fallback changed user identity" unless ordinary.identity == process.identity
  subject = TokenProbe::TokenReader.capture_subject
  raise "Process subject incomplete: #{subject.diagnostics}" unless subject.complete?
  raise "Subject capture changed identity" unless subject.token.identity == process.identity
  raise "Token groups unavailable" unless subject.groups.state.captured?
  raise "Restricted SID observation unavailable" unless subject.restricted_sids.state.captured?
  raise "Privileges unavailable" unless subject.privileges.state.captured?
  raise "Integrity unavailable" unless subject.integrity.state.captured?
  raise "Elevation evidence unavailable" unless subject.elevation_type.state.captured? && subject.elevated.state.captured?
  raise "Restriction history unavailable" unless subject.has_restrictions.state.captured?
  selected = TokenProbe::TokenReader.capture_subject(
    information: TokenProbe::TokenSubjectInformation::Groups)
  raise "Scoped token groups unavailable" unless selected.complete? && selected.groups.state.captured?
  raise "Scoped query invented privileges" unless selected.privileges.state.not_queried?

  if TokenProbeNative.impersonate_self(2_u32) == 0
    raise "ImpersonateSelf failed: #{LibC.GetLastError}"
  end
  begin
    effective = TokenProbe::TokenReader.capture(TokenProbe::TokenContext::Effective)
    raise "Thread identity unavailable: #{effective.diagnostic}" unless effective.complete?
    raise "Thread source not retained" unless effective.source.not_nil!.thread?
    identity = effective.identity.not_nil!
    raise "Expected impersonation token" unless identity.type.impersonation?
    raise "Expected SecurityImpersonation" unless identity.impersonation_level == TokenProbe::ImpersonationLevel::Impersonation
    raise "Self-impersonation user changed" unless identity.user == process.identity.not_nil!.user
    explicit_process = TokenProbe::TokenReader.capture(TokenProbe::TokenContext::Process)
    raise "Explicit process selection changed under impersonation" unless explicit_process.source == process.source && explicit_process.identity == process.identity
    thread_subject = TokenProbe::TokenReader.capture_subject(TokenProbe::TokenContext::Effective)
    raise "Thread subject incomplete: #{thread_subject.diagnostics}" unless thread_subject.complete?
    raise "Subject capture lost thread source" unless thread_subject.token.source.not_nil!.thread?
    raise "Thread subject identity changed" unless thread_subject.token.identity == identity
  ensure
    if TokenProbeNative.revert_to_self == 0
      # Terminate this helper if cleanup fails; never resume an application
      # after failure to restore its security context.
      abort "RevertToSelf failed: #{LibC.GetLastError}"
    end
  end
  restored = TokenProbe::TokenReader.capture(TokenProbe::TokenContext::Effective)
  raise "Thread token remained after revert" unless restored.complete? && restored.source.not_nil!.process?
  puts "acl-windows-token-native-ok"
{% else %}
  abort "Windows token qualification requires a native Windows host"
{% end %}
