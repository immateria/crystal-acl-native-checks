{% skip_file unless flag?(:linux) %}
require "./linux/native"
require "./linux/builder"
require "./linux/evaluation"
require "./linux/inheritance"
require "./linux/subject"

module Filesystem::AccessControl
  # Strict privacy retains its real-UID default. General permission evaluation
  # uses an explicit Linux::Subject instead. The descriptor remains caller-owned.
  def self.inspect_fd(fd : Int32, path : Path? = nil, *, expected : Target? = nil,
                      owner_uid : UInt32 = LibC.getuid) : Report
    snapshot = Linux::Reader.capture(fd, expected: expected)
    issues = snapshot.privacy_issues(owner_uid)
    stat = snapshot.stat
    if snapshot.diagnostics.any? { |problem| problem.reason.wrong_kind? }
      raise Filesystem::Capabilities::Error.new("Access-control inspection requires an open #{expected}")
    end
    access = snapshot.access.try(&.entries) || [] of Entry
    defaults = snapshot.default_acl.try(&.entries) || [] of Entry
    state = !snapshot.complete? ? State::Unavailable : (snapshot.access || snapshot.default_acl ? State::Present : State::None)
    details = snapshot.diagnostics.map(&.message) + issues.map(&.message)
    Report.new(path, :linux_posix_acl, stat.try { |value| value.uid == owner_uid }, stat.try(&.mode),
      access, defaults, state, issues.empty?, details.empty? ? nil : details.join("; "),
      snapshot: snapshot, privacy_issues: issues)
  end
end
