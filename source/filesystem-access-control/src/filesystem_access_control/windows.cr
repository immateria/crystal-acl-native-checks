{% skip_file unless flag?(:windows) %}

# Windows DACL inspection on an opened handle. No pathname security queries,
# ACL modification, impersonation or claims about mandatory-integrity policies.
require "c/fileapi"
require "c/winbase"
require "c/handleapi"
require "c/processthreadsapi"
require "c/errhandlingapi"

@[Link("advapi32")]
lib Filesystem::AccessControl::Native::Windows::ACL
  fun acl_security_info = GetSecurityInfo(handle : Void*, object_type : UInt32, info : UInt32,
                                          owner : Void**, group : Void**, dacl : Void**, sacl : Void**,
                                          descriptor : Void**) : UInt32
  fun acl_descriptor_control = GetSecurityDescriptorControl(descriptor : Void*, control : UInt16*, revision : UInt32*) : Int32
  fun acl_process_token = OpenProcessToken(process : Void*, rights : UInt32, token : Void**) : Int32
  fun acl_thread_token = OpenThreadToken(thread : Void*, rights : UInt32, open_as_self : Int32, token : Void**) : Int32
  fun acl_token_info = GetTokenInformation(token : Void*, info : UInt32, buffer : Void*, size : UInt32, required : UInt32*) : Int32
end

require "./windows/reader"
require "./windows/token_native"
require "./windows/handle_native"
require "./windows/evaluation"

module Filesystem::AccessControl
  # Conservative allow ACE analysis: any allow to principals besides current
  # process user or LocalSystem rejects strict privacy. Object/callback and
  # conditional allow ACEs are not decoded and invalidate certification.
  def self.inspect_windows_directory(path : Path) : Report
    units = path.to_s.to_utf16
    name = Slice(UInt16).new(units.size + 1, 0_u16)
    units.copy_to(name)
    # READ_CONTROL, FILE_SHARE_READ/WRITE/DELETE, OPEN_EXISTING, BACKUP_SEMANTICS
    # plus OPEN_REPARSE_POINT; reject final reparse points after opening.
    handle = LibC.CreateFileW(name.to_unsafe, 0x20000_u32, 7_u32,
      Pointer(LibC::SECURITY_ATTRIBUTES).null, 3_u32, 0x02200000_u32, Pointer(Void).null)
    if handle.address == UInt64::MAX
      raise Filesystem::Capabilities::Error.new("Cannot open directory for DACL inspection: #{path}")
    end
    begin
      info = StaticArray(UInt32, 2).new(0_u32)
      if LibC.GetFileInformationByHandleEx(handle, LibC::FILE_INFO_BY_HANDLE_CLASS::FileAttributeTagInfo,
           info.to_unsafe.as(Void*), 8_u32) == 0 ||
         (info[0] & 0x10) == 0 || (info[0] & 0x400) != 0
        raise Filesystem::Capabilities::Error.new("ACL inspection requires a real directory, not a reparse point: #{path}")
      end
      windows_report(handle, path)
    ensure
      LibC.CloseHandle(handle)
    end
  end

  private def self.windows_report(handle : Void*, path : Path) : Report
    snapshot = Windows::Reader.capture(handle)
    unless snapshot.complete?
      diagnostic = snapshot.diagnostic || windows_validation("GetSecurityInfo", "Incomplete security descriptor")
      return windows_unavailable(path, snapshot, diagnostic)
    end
    begin
      token = Windows::TokenReader.capture(Windows::TokenContext::Process)
      unless identity = token.identity
        diagnostic = token.diagnostic || windows_validation("TokenUser", "Process user SID unavailable")
        return windows_unavailable(path, snapshot, diagnostic)
      end
      current = identity.user
      matched = snapshot.owner == current
      if snapshot.dacl_presence.absent? || snapshot.dacl_presence.null?
        detail = snapshot.dacl_presence.absent? ? "DACL absent from queried descriptor" : "NULL DACL grants unrestricted access"
        return Report.new(path, :windows_dacl, matched, nil, ([] of Entry), ([] of Entry),
          State::Unrestricted, false, detail, snapshot)
      end
      # S-1-5-18, LocalSystem. Binary SID comparison retains exact identities;
      # the report summary still labels the current user and LocalSystem.
      system = Windows::SID.new("010100000000000512000000".hexbytes)
      entries = [] of Entry
      inherited = [] of Entry
      problem = nil.as(Windows::Diagnostic?)
      snapshot.dacl.not_nil!.entries.each_with_index do |ace, index|
        trustee, rights = ace.trustee, ace.rights
        unless (ace.type == 0 || ace.type == 1) && trustee && rights
          problem = windows_validation("DACL.privacy", "Unsupported DACL ACE type #{ace.type} at #{index}")
          break
        end
        subject = trustee == current ? "current-user" : trustee == system ? "local-system" : "other-principal"
        entry = Entry.new(subject, rights, (ace.flags & 0x10) != 0, ace.type == 0 ? :allow : :deny)
        entries << entry
        inherited << entry if (ace.flags & 0x13) != 0
      end
      unsafe_allow = entries.any? { |entry| entry.effect == :allow && entry.rights != 0 && entry.subject == "other-principal" }
      snapshot = snapshot.with_diagnostic(problem) if problem
      Report.new(path, :windows_dacl, matched, nil, entries, inherited,
        problem ? State::Unavailable : State::Present, !problem && matched && !unsafe_allow,
        problem.try(&.message), snapshot)
    rescue error : ArgumentError
      windows_unavailable(path, snapshot, windows_validation("security_descriptor.decode", error.message || "Invalid descriptor"))
    end
  end

  private def self.windows_unavailable(path : Path, snapshot : Windows::Snapshot,
                                       diagnostic : Windows::Diagnostic) : Report
    Report.new(path, :windows_dacl, nil, nil, ([] of Entry), ([] of Entry),
      State::Unavailable, false, diagnostic.message, snapshot.with_diagnostic(diagnostic))
  end

  private def self.windows_validation(operation : String, message : String) : Windows::Diagnostic
    Windows::Diagnostic.new(operation, nil, Windows::ErrorOrigin::Validation, message)
  end
end
