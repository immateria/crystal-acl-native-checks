{% skip_file unless flag?(:linux) %}
require "./writer"

class Filesystem::Capabilities::Directory
  # Keep the root's descriptor lease alive for capture, mutation and readback.
  def replace_acl(*, target : Filesystem::AccessControl::Linux::Snapshot,
                  acl : Filesystem::AccessControl::Linux::ACL,
                  kind : Filesystem::AccessControl::Linux::ACLKind = Filesystem::AccessControl::Linux::ACLKind::Access) : Filesystem::AccessControl::Linux::MutationResult
    with_directory_handle do |fd|
      Filesystem::AccessControl::Linux::Writer.replace_fd(fd, target: target, acl: acl, kind: kind)
    end
  end

  def remove_acl(*, target : Filesystem::AccessControl::Linux::Snapshot,
                 kind : Filesystem::AccessControl::Linux::ACLKind = Filesystem::AccessControl::Linux::ACLKind::Access) : Filesystem::AccessControl::Linux::MutationResult
    with_directory_handle do |fd|
      Filesystem::AccessControl::Linux::Writer.remove_fd(fd, target: target, kind: kind)
    end
  end
end
