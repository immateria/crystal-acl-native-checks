# Linux and Darwin directory capabilities share an errno-bearing entry error.
# Windows intentionally has a different NTSTATUS-bearing contract.
{% skip_file unless flag?(:linux) || flag?(:darwin) %}

module Filesystem::Capabilities
  class Directory
    class EntryError < Filesystem::Capabilities::Error
      getter operation : Symbol
      getter entry : String
      getter errno : Errno

      def initialize(@operation : Symbol, @entry : String, @errno : Errno)
        super("Cannot #{@operation} confined entry #{@entry.inspect}: #{@errno} (#{@errno.message})")
      end

      def missing? : Bool
        @errno == Errno::ENOENT
      end

      # The file system's own limit on a name, in its own unit: the library
      # sets none on Unix (`Component.validate`).
      def name_too_long? : Bool
        @errno == Errno::ENAMETOOLONG
      end
    end
  end
end
