# Opt-in, read-only access-control inspection. No chmod, chown, ACL rewriting,
# implicit directory creation or assurance against external concurrent edits.
require "filesystem-capabilities"
require "./filesystem_access_control/model"

{% if flag?(:linux) %}
  require "./filesystem_access_control/linux"
{% elsif flag?(:darwin) %}
  require "./filesystem_access_control/darwin_inspection"
  require "./filesystem_access_control/darwin/evaluation"
  require "./filesystem_access_control/darwin/builder"
  require "./filesystem_access_control/darwin/inheritance"
  require "./filesystem_access_control/darwin/discretionary_access"
  require "./filesystem_access_control/darwin/subject_resolution"
{% elsif flag?(:windows) %}
  require "./filesystem_access_control/windows"
{% end %}

require "./filesystem_access_control/inspection"

{% if flag?(:linux) || flag?(:darwin) %}
  require "./filesystem_access_control/unix_capabilities"
{% elsif flag?(:windows) %}
  require "./filesystem_access_control/windows_capabilities"
{% end %}
