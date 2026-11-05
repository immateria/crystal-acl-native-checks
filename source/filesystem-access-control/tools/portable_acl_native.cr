# Native macOS/Windows ACL-observation test. No strict I/O import.
require "../src/filesystem-access-control"
{% if flag?(:darwin) || flag?(:windows) %}
  require "file_utils"
  require "random/secure"
  root = Path[Dir.tempdir] / "acl-observe-#{Random::Secure.hex(6)}"
  Dir.mkdir(root, 0o700)
  begin
    Filesystem::Capabilities::Directory.open_existing(root) do |handle|
      report = handle.access_report
      {% if flag?(:darwin) %}
        raise "wrong macOS ACL backend" unless report.backend == :darwin_extended_acl
      {% else %}
        raise "wrong Windows DACL backend" unless report.backend == :windows_dacl
        snapshot = report.snapshot.not_nil!
        raise "wrong query scope" unless snapshot.queried_information == 7_u32
        raise "incomplete owner/group/DACL capture: #{report.detail}" unless snapshot.complete?
        raise "owner SID not retained" unless snapshot.owner
        raise "group SID not retained" unless snapshot.group
        raise "unrequested SACL was interpreted" unless snapshot.sacl_presence.not_queried?
        raw = snapshot.raw_descriptor.not_nil!
        decoded = Filesystem::AccessControl::Windows::SecurityDescriptor.new(raw)
        raise "descriptor observation was changed" unless decoded == snapshot.descriptor
        raw.fill(0_u8)
        raise "descriptor bytes were borrowed" unless snapshot.raw_descriptor == decoded.bytes
        if snapshot.dacl_presence.present?
          acl = snapshot.dacl.not_nil!
          raise "DACL bytes not retained" unless Filesystem::AccessControl::Windows::ACL.new(acl.bytes).bytes == acl.bytes
        end
      {% end %}
      raise "native ACL inspection unsupported" if report.acl_state == Filesystem::AccessControl::State::Unsupported
    end
  ensure
    FileUtils.rm_rf(root)
  end
{% end %}
puts "acl-observation-native-ok"
