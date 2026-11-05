# Common opened-directory ACL inspection extension on Unix capabilities.
# Native Linux and Darwin report backends retain separate platform syscall policy.
{% skip_file unless flag?(:linux) || flag?(:darwin) %}

class Filesystem::Capabilities::Directory
  def access_report : Filesystem::AccessControl::Report
    with_directory_handle do |fd|
      Filesystem::AccessControl.inspect_fd(fd, self.path)
    end
  end

  def require_private! : Filesystem::AccessControl::Report
    access_report.require_private!
  end
end
