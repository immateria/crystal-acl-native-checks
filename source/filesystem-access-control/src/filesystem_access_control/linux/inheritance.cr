require "./builder"

module Filesystem::AccessControl::Linux
  record Creation, access : ACL, default_acl : ACL?

  module Inheritance
    # Project only POSIX ACL and rwx mode inheritance. The caller supplies the
    # requested creation mode and, when defaults are absent, the process umask.
    # Ownership, setgid inheritance and filesystem policy remain the kernel's.
    def self.project(default_acl : ACL?, *, mode : Int32, directory : Bool, umask : Int32 = 0o022) : Creation
      raise ArgumentError.new("Creation mode and umask must be rwx bits") if mode < 0 || mode > 0o777 || umask < 0 || umask > 0o777
      unless acl = default_acl
        return Creation.new(ACL.from_mode(mode & ~umask), nil)
      end
      owner = acl.find(Tag::Owner).not_nil!
      other = acl.find(Tag::Other).not_nil!
      group = (acl.find(Tag::Mask) || acl.find(Tag::OwningGroup)).not_nil!
      access = acl.with_entry(Entry.new(Tag::Owner, owner.permissions & Permissions.new(((mode >> 6) & 7).to_u8)))
        .with_entry(Entry.new(group.tag, group.permissions & Permissions.new(((mode >> 3) & 7).to_u8)))
        .with_entry(Entry.new(Tag::Other, other.permissions & Permissions.new((mode & 7).to_u8)))
      Creation.new(access, directory ? acl : nil)
    end
  end
end
