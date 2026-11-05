# Opt-in native ACL mutation.
# Ordinary require "filesystem-access-control" stays read-only.
require "../filesystem-access-control"

{% if flag?(:linux) %}
  require "../filesystem_access_control/linux/writer"
  require "../filesystem_access_control/linux/write_capabilities"
{% elsif flag?(:darwin) %}
  require "../filesystem_access_control/darwin/model"
  require "../filesystem_access_control/darwin/builder"
  require "../filesystem_access_control/darwin/evaluation"
  require "../filesystem_access_control/darwin/inheritance"
  require "../filesystem_access_control/darwin/writer"
  require "../filesystem_access_control/darwin/write_capabilities"
{% elsif flag?(:windows) %}
  require "../filesystem_access_control/windows/writer"
{% end %}
