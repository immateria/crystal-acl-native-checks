{% skip_file unless flag?(:darwin) %}

require "../darwin_mount"
require "./native"
require "./model"
require "./external_acl"
require "./extended_security_native"
require "./principals"

module Filesystem::AccessControl::Darwin
  # ACL ownership is explicit at this seam: every getter returning a native
  # object has a matching free operation. The native provider is used by
  # production callers; deterministic providers let specs inject libc faults.
  abstract class ACLReaderProvider
    def extended_security(fd : Int32) : Tuple(ExtendedSecurity?, Diagnostic?)
      {nil, Diagnostic.new("extended_security", nil, nil, "acl",
        "Provider cannot qualify a missing ACL result", Reason::IncompleteEvidence)}
    end

    abstract def get_fd(fd : Int32, acl_type : Int32) : Void*
    abstract def size(acl : Void*) : Int64
    abstract def copy_ext(buffer : Void*, acl : Void*, size : Int64) : Int64
    abstract def valid(acl : Void*) : Int32
    abstract def get_entry(acl : Void*, entry_id : Int32, entry : Void**) : Int32
    abstract def get_tag_type(entry : Void*, tag : UInt32*) : Int32
    abstract def get_permset_mask(entry : Void*, mask : UInt64*) : Int32
    abstract def get_flagset(object : Void*, flagset : Void**) : Int32
    abstract def get_flag(flagset : Void*, flag : Int32) : Int32
    abstract def get_qualifier(entry : Void*) : Void*
    abstract def free(object : Void*) : Int32
  end

  class NativeACLReaderProvider < ACLReaderProvider
    def extended_security(fd : Int32) : Tuple(ExtendedSecurity?, Diagnostic?)
      ExtendedSecurityReader.capture(fd)
    end

    def get_fd(fd : Int32, acl_type : Int32) : Void*
      Native::Darwin::ACL.acl_get_fd_np(fd, acl_type)
    end

    def size(acl : Void*) : Int64
      Native::Darwin::ACL.acl_size(acl)
    end

    def copy_ext(buffer : Void*, acl : Void*, size : Int64) : Int64
      Native::Darwin::ACL.acl_copy_ext(buffer, acl, size)
    end

    def valid(acl : Void*) : Int32
      Native::Darwin::ACL.acl_valid(acl)
    end

    def get_entry(acl : Void*, entry_id : Int32, entry : Void**) : Int32
      Native::Darwin::ACL.acl_get_entry(acl, entry_id, entry)
    end

    def get_tag_type(entry : Void*, tag : UInt32*) : Int32
      Native::Darwin::ACL.acl_get_tag_type(entry, tag)
    end

    def get_permset_mask(entry : Void*, mask : UInt64*) : Int32
      Native::Darwin::ACL.acl_get_permset_mask_np(entry, mask)
    end

    def get_flagset(object : Void*, flagset : Void**) : Int32
      Native::Darwin::ACL.acl_get_flagset_np(object, flagset)
    end

    def get_flag(flagset : Void*, flag : Int32) : Int32
      Native::Darwin::ACL.acl_get_flag_np(flagset, flag)
    end

    def get_qualifier(entry : Void*) : Void*
      Native::Darwin::ACL.acl_get_qualifier(entry)
    end

    def free(object : Void*) : Int32
      Native::Darwin::ACL.acl_free(object)
    end
  end
end

module Filesystem::AccessControl
  def self.inspect_fd(fd : Int32, path : Path? = nil, *, expected : Target? = nil,
                      owner_uid : UInt32 = LibC.getuid,
                      acl_provider : Darwin::ACLReaderProvider = Darwin::NativeACLReaderProvider.new) : Report
    raise ArgumentError.new("Invalid descriptor") if fd < 0
    unless LibC.fstat(fd, out status) == 0
      failure = Errno.value
      raise Filesystem::Capabilities::Error.new("Cannot inspect descriptor metadata: #{failure}")
    end

    mode = status.st_mode.to_u32
    file_type = mode & LibC::S_IFMT
    kind = if file_type == LibC::S_IFREG
             Darwin::Kind::File
           elsif file_type == LibC::S_IFDIR
             Darwin::Kind::Directory
           elsif file_type == LibC::S_IFLNK
             Darwin::Kind::Symlink
           else
             Darwin::Kind::Other
           end
    if expected == Target::Directory && kind != Darwin::Kind::Directory
      raise Filesystem::Capabilities::Error.new("Access-control inspection requires an open directory")
    elsif expected == Target::File && kind != Darwin::Kind::File
      raise Filesystem::Capabilities::Error.new("Access-control inspection requires an open regular file")
    end

    owner_matches = status.st_uid == owner_uid
    permissions = (mode & 0o7777).to_i
    mount, mount_diagnostic = darwin_mount_observation(fd)
    snapshot = darwin_capture_acl(fd, status, kind, mount, mount_diagnostic, acl_provider)
    state = case snapshot.status
            when Darwin::Status::Absent                         then State::None
            when Darwin::Status::Empty, Darwin::Status::Present then State::Present
            when Darwin::Status::Unsupported                    then State::Unsupported
            else                                                     State::Unavailable
            end
    detail = snapshot.diagnostics.first?.try(&.message) || mount_diagnostic.try(&.message)
    mode_ok = kind == Darwin::Kind::File ? permissions > 0 && (permissions & ~0o600) == 0 : kind == Darwin::Kind::Directory && permissions == 0o700
    mount_ok = !mount.nil? && !mount.ownership_ignored? && !mount.server_authorized?
    acl_ok = snapshot.complete? && !snapshot.nonempty? &&
             (snapshot.acl_flags & ~Darwin::Constants::ACL_FLAG_NO_INHERIT) == 0
    private_result = owner_matches && mode_ok && mount_ok && acl_ok && mount_diagnostic.nil?
    detail ||= mount_diagnostic.try(&.message)
    Report.new(path, :darwin_extended_acl, owner_matches, permissions, ([] of Entry), ([] of Entry),
      state, private_result, detail, snapshot)
  end

  private def self.darwin_capture_acl(fd : Int32, status : LibC::Stat,
                                      kind : Darwin::Kind,
                                      mount : Darwin::MountObservation?,
                                      mount_diagnostic : Darwin::Diagnostic?,
                                      provider : Darwin::ACLReaderProvider) : Darwin::Snapshot
    entries = [] of Darwin::Ace
    acl = provider.get_fd(fd, Darwin::Constants::ACL_TYPE_EXTENDED)
    unless acl
      failure = Errno.value
      if failure == Errno::ENOENT
        attribute, error = provider.extended_security(fd)
        if error
          return darwin_snapshot(status, kind, entries, 0_u32, Darwin::Status::Incomplete, mount, error)
        end
        if attribute
          entries = attribute.entries
          state = if attribute.presence.present?
                    entries.empty? ? Darwin::Status::Empty : Darwin::Status::Present
                  else
                    # Preserve the existing libc ENOENT interpretation, while
                    # recording whether the supplementary query returned an
                    # explicit no-ACL sentinel or omitted the attribute.
                    Darwin::Status::Absent
                  end
          return darwin_snapshot(status, kind, entries, attribute.acl_flags, state,
            mount, nil, attribute.presence)
        end
      end
      state = failure == Errno::ENOENT ? Darwin::Status::Absent : (failure == Errno::EOPNOTSUPP ? Darwin::Status::Unsupported : Darwin::Status::Unavailable)
      reason = state.unsupported? ? Darwin::Reason::Unsupported : (failure == Errno::EACCES || failure == Errno::EPERM ? Darwin::Reason::PermissionDenied : Darwin::Reason::SystemError)
      diagnostic = state.absent? ? nil : Darwin::Diagnostic.new("acl_get_fd_np", failure.value, nil, "acl", "Unable to read extended ACL: #{failure}", reason)
      return darwin_snapshot(status, kind, entries, 0_u32, state, mount, diagnostic)
    end

    status_value = Darwin::Status::Present
    acl_flags = 0_u32
    diagnostic = nil.as(Darwin::Diagnostic?)
    begin
      if provider.valid(acl) != 0
        failure = Errno.value
        status_value = Darwin::Status::Incomplete
        diagnostic = Darwin::Diagnostic.new("acl_valid", failure.value, nil, "acl", "ACL validation failed: #{failure}")
      else
        flags, flag_error = darwin_read_flag_bits(acl, provider)
        if flag_error
          status_value = Darwin::Status::Incomplete
          diagnostic = flag_error
        else
          acl_flags = flags
          index = 0
          entry_id = 0
          loop do
            item = Pointer(Void).null
            result = provider.get_entry(acl, entry_id, pointerof(item))
            failure = Errno.value
            break if result == -1 && failure == Errno::EINVAL
            if result != 0 || item.null?
              status_value = Darwin::Status::Incomplete
              diagnostic = Darwin::Diagnostic.new("acl_get_entry", failure.value, index, "entries", "Unexpected ACL iteration result #{result}: #{failure}")
              break
            end
            if index >= Darwin::Constants::ACL_MAX_ENTRIES
              status_value = Darwin::Status::Incomplete
              diagnostic = Darwin::Diagnostic.new("acl_get_entry", nil, index, "entries", "ACL exceeds ACL_MAX_ENTRIES (128)")
              break
            end
            ace, ace_error = darwin_read_ace(acl, item, index, provider)
            if ace_error
              status_value = Darwin::Status::Incomplete
              diagnostic = ace_error
              break
            end
            entries << ace.not_nil!
            index += 1
            entry_id = -1 # ACL_NEXT_ENTRY on Darwin.
          end
          if status_value.present? && entries.empty?
            status_value = Darwin::Status::Empty
          end
        end
      end
    ensure
      provider.free(acl)
    end
    darwin_snapshot(status, kind, entries, acl_flags, status_value, mount, diagnostic)
  end

  private def self.darwin_read_ace(acl : Void*, entry : Void*, ordinal : Int32,
                                   provider : Darwin::ACLReaderProvider) : Tuple(Darwin::Ace?, Darwin::Diagnostic?)
    tag = 0_u32
    rights = 0_u64
    unless provider.get_tag_type(entry, pointerof(tag)) == 0
      return {nil, darwin_diagnostic("acl_get_tag_type", ordinal, "tag")}
    end
    unless provider.get_permset_mask(entry, pointerof(rights)) == 0
      return {nil, darwin_diagnostic("acl_get_permset_mask_np", ordinal, "rights")}
    end
    flags, flag_error = darwin_read_flag_bits(entry, provider, ordinal)
    return {nil, flag_error} if flag_error

    qualifier = provider.get_qualifier(entry)
    if qualifier.null?
      # Audit, alarm and future ACE kinds have no public qualifier accessor,
      # even though Apple's portable ACL codec preserves their exact GUID.
      # Use that bounded public representation rather than fabricating a UUID.
      uuid, codec_error = darwin_external_uuid(acl, ordinal, provider)
      return {nil, codec_error || darwin_diagnostic("acl_get_qualifier", ordinal, "principal")} unless uuid
      return {Darwin::Ace.new(ordinal, Darwin::Principal.new(uuid.not_nil!), tag, rights, flags), nil}
    end
    begin
      bytes = qualifier.as(UInt8*)
      uuid = StaticArray(UInt8, 16).new { |i| bytes[i] }
      {Darwin::Ace.new(ordinal, Darwin::Principal.new(uuid), tag, rights, flags), nil}
    ensure
      provider.free(qualifier)
    end
  end

  private def self.darwin_external_uuid(acl : Void*, ordinal : Int32,
                                        provider : Darwin::ACLReaderProvider) : Tuple(StaticArray(UInt8, 16)?, Darwin::Diagnostic?)
    size = provider.size(acl)
    unless size >= Darwin::ExternalACL::HEADER_SIZE && size <= Darwin::ExternalACL::MAX_SIZE
      return {nil, Darwin::Diagnostic.new("acl_size", Errno.value.value, ordinal, "principal", "ACL external size is invalid or exceeds 128 entries")}
    end
    bytes = Bytes.new(size.to_i)
    copied = provider.copy_ext(bytes.to_unsafe.as(Void*), acl, size)
    unless copied == size
      failure = Errno.value
      return {nil, Darwin::Diagnostic.new("acl_copy_ext", failure.value, ordinal, "principal", "Unable to copy ACL external representation: #{failure}")}
    end
    {Darwin::ExternalACL.uuid_at(bytes, ordinal), nil}
  rescue error : ArgumentError
    {nil, Darwin::Diagnostic.new("acl_copy_ext", nil, ordinal, "principal", error.message || "Invalid ACL external representation")}
  rescue error
    {nil, Darwin::Diagnostic.new("acl_copy_ext", nil, ordinal, "principal", "Unable to parse ACL external representation: #{error.message}")}
  end

  private def self.darwin_read_flag_bits(object : Void*, provider : Darwin::ACLReaderProvider,
                                         ordinal : Int32? = nil) : Tuple(UInt32, Darwin::Diagnostic?)
    flagset = Pointer(Void).null
    unless provider.get_flagset(object, pointerof(flagset)) == 0 && !flagset.null?
      return {0_u32, darwin_diagnostic("acl_get_flagset_np", ordinal, "flags")}
    end
    raw = 0_u32
    32.times do |bit|
      value = provider.get_flag(flagset, 1 << bit)
      if value < 0
        return {raw, darwin_diagnostic("acl_get_flag_np(#{bit})", ordinal, "flags")}
      end
      raw |= 1_u32 << bit if value == 1
    end
    {raw, nil}
  end

  private def self.darwin_diagnostic(operation : String, entry : Int32?, field : String) : Darwin::Diagnostic
    failure = Errno.value
    Darwin::Diagnostic.new(operation, failure.value, entry, field, "#{operation} failed: #{failure}")
  end

  private def self.darwin_snapshot(status : LibC::Stat, kind : Darwin::Kind,
                                   entries : Array(Darwin::Ace), flags : UInt32,
                                   acl_status : Darwin::Status,
                                   mount : Darwin::MountObservation?,
                                   diagnostic : Darwin::Diagnostic?,
                                   presence : Darwin::ExtendedSecurityPresence? = nil) : Darwin::Snapshot
    Darwin::Snapshot.new(acl_status, entries, flags, status.st_uid.to_u32, status.st_gid.to_u32,
      (status.st_mode & 0o7777).to_u32, status.st_flags.to_u32, status.st_dev.to_u64,
      status.st_ino.to_u64, kind, mount, diagnostic, presence)
  end

  private def self.darwin_mount_observation(fd : Int32) : Tuple(Darwin::MountObservation?, Darwin::Diagnostic?)
    unless Native::Darwin::Mount.fstatfs(fd, out fs) == 0
      failure = Errno.value
      return {nil, Darwin::Diagnostic.new("fstatfs", failure.value, nil, "mount", "Unable to inspect filesystem mount: #{failure}")}
    end
    {Darwin::MountObservation.new(fs.filesystem_id, fs.mount_owner, fs.filesystem_type,
      fs.flags, fs.subtype, darwin_fixed_string(fs.type_name), darwin_fixed_string(fs.mount_point),
      darwin_fixed_string(fs.source), fs.extended_flags), nil}
  end

  private def self.darwin_fixed_string(bytes : StaticArray(UInt8, N)) : String forall N
    length = 0
    while length < N && bytes[length] != 0
      length += 1
    end
    String.new(Bytes.new(length) { |i| bytes[i] })
  end
end
