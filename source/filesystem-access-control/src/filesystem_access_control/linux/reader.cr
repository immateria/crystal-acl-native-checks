require "./observation"
require "./codec"

module Filesystem::AccessControl::Linux
  # I/O boundary for native providers. Missing xattrs have nil bytes and no
  # diagnostic; errors must never be reported as missing ACLs.
  abstract class ReaderProvider
    abstract def stat(fd : Int32) : StatResult
    abstract def read(fd : Int32, kind : ACLKind) : ReadResult
  end

  module Reader
    def self.capture(fd : Int32, *, expected : Target? = nil, provider : ReaderProvider) : Snapshot
      raise ArgumentError.new("Invalid file descriptor") if fd < 0
      first = provider.stat(fd)
      diagnostics = [] of Diagnostic
      diagnostics << first.diagnostic.not_nil! if first.diagnostic
      unless stat = first.value
        diagnostics << Diagnostic.new(Reason::IncompleteCapture, "Cannot inspect descriptor metadata") if diagnostics.empty?
        return Snapshot.new(nil, nil, nil, diagnostics)
      end
      if expected && stat.kind != expected
        diagnostics << Diagnostic.new(Reason::WrongKind, "Expected #{expected}, observed #{stat.kind}")
        return Snapshot.new(stat, nil, nil, diagnostics)
      end
      access = read(fd, ACLKind::Access, stat.mode, provider, diagnostics)
      defaults = stat.kind.directory? ? read(fd, ACLKind::Default, nil, provider, diagnostics) : nil
      final = provider.stat(fd)
      if problem = final.diagnostic
        diagnostics << problem
      elsif final.value != stat
        diagnostics << Diagnostic.new(Reason::ObservationChanged, "Descriptor metadata changed during ACL capture")
      end
      Snapshot.new(stat, access, defaults, diagnostics)
    end

    private def self.read(fd : Int32, kind : ACLKind, mode : Int32?, provider : ReaderProvider, diagnostics : Array(Diagnostic)) : ACL?
      result = provider.read(fd, kind)
      if problem = result.diagnostic
        diagnostics << problem
        return nil
      end
      return nil unless bytes = result.bytes
      parsed = Codec.decode(bytes, mode: mode, kind: kind)
      diagnostics << parsed.diagnostic.not_nil! if parsed.diagnostic
      parsed.acl
    end
  end
end
