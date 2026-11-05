# Existing-root, descriptor-relative filesystem operations, independent of
# application path discovery. Loading this entrypoint never creates paths.
require "path"

# :nodoc: Native syscall bindings, independently owned by this provider.
module Filesystem
  module Capabilities
    module Native
      {% if flag?(:linux) %}
        module Linux
        end
      {% elsif flag?(:darwin) %}
        module Darwin
        end
      {% elsif flag?(:windows) %}
        module Windows
        end
      {% end %}
    end
  end
end

{% if flag?(:linux) %}
  require "io/file_descriptor"
  require "errno"
  require "sync/exclusive"
  require "c/fcntl"
  require "c/sys/stat"
  require "c/unistd"
  require "c/dirent"
  # openat2 allows the Linux VFS to enforce no mount crossing and no
  # symbolic or magic link traversal in one resolution operation.
  @[Link("c")]
  lib Filesystem::Capabilities::Native::Linux::Openat2
    struct OpenHow
      flags : UInt64
      mode : UInt64
      resolve : UInt64
    end

    fun syscall(number : LibC::Long, ...) : LibC::Long
  end

  @[Link("c")]
  lib Filesystem::Capabilities::Native::Linux::At
    fun openat(dirfd : Int32, pathname : UInt8*, flags : Int32, ...) : Int32
    fun mkdirat(dirfd : Int32, pathname : UInt8*, mode : LibC::ModeT) : Int32
    fun renameat(olddirfd : Int32, oldpath : UInt8*, newdirfd : Int32, newpath : UInt8*) : Int32
    # Kernel atomic destination absence check; unlike renameat, may never
    # overwrite an existing destination. Fail closed on unavailable kernels.
    fun renameat2(olddirfd : Int32, oldpath : UInt8*, newdirfd : Int32,
                  newpath : UInt8*, flags : UInt32) : Int32
    fun unlinkat(dirfd : Int32, pathname : UInt8*, flags : Int32) : Int32
    fun fdopendir(fd : Int32) : LibC::DIR*
  end
{% end %}

module Filesystem::Capabilities
  VERSION = "0.1.0"

  class Error < Exception
  end

  # A retained capability was explicitly closed. Never use message matching
  # to distinguish this from a failed native operation on an open handle.
  class ClosedError < Error
  end

  # An intentionally unavailable API or kernel-enforced policy. In contrast,
  # syscall permission failures and other native errors keep their native code.
  class UnsupportedOperationError < Error
  end

  # Native Linux syscall flag values vary by architecture.
  module Platform
    {% if flag?(:linux) %}
      {% if flag?(:arm) || flag?(:aarch64) %}
        DIRECTORY_ONLY = 0o40000
      {% else %}
        DIRECTORY_ONLY = 0o200000
      {% end %}
      # Linux O_PATH: an inode reference usable for fstat without read
      # permission or opening device contents. Linux asm-generic/fcntl.h.
      PATH_REFERENCE = 0o10000000
      # Linux unlinkat AT_REMOVEDIR; not Darwin's platform-specific value.
      REMOVE_DIRECTORY_ENTRY = 0x200
      RENAME_NOREPLACE = 0x1_u32
    {% end %}
  end
end

require "./filesystem_capabilities/windows_directory_records"
require "./filesystem_capabilities/component"
require "./filesystem_capabilities/root_path"
require "./filesystem_capabilities/mount_policy"
{% if flag?(:linux) || flag?(:darwin) %}
  require "./filesystem_capabilities/unix_entry_error"
{% end %}
require "./filesystem_capabilities/directory"
require "./filesystem_capabilities/entry_type"
require "./filesystem_capabilities/directory_identity"
