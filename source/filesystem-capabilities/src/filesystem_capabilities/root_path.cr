# Root-path input policy for Unix and Windows opened handles.
# An accepted input path alone does not attest the filesystem.
module Filesystem::Capabilities
  # :nodoc:
  module RootPath
    # A root names a concrete folder: a terminal separator or a final . or ..
    # would make `path` name something other than the folder held. On
    # Windows FILE_FLAG_OPEN_REPARSE_POINT covers only the final entry, and
    # these spellings would change which entry is final. Unix roots follow
    # links; callers that need none anywhere use the no-symlink root opener.
    def self.validate_existing(path : Path) : Nil
      unless path.absolute?
        raise ArgumentError.new("Directory capability root must be absolute")
      end
      literal = path.to_s
      return if path.anchor.try(&.to_s) == literal
      separator_suffix = {% if flag?(:windows) %}
                           literal.ends_with?('/') || literal.ends_with?('\\')
                         {% else %}
                           literal.ends_with?('/')
                         {% end %}
      if separator_suffix || path.basename.in?(".", "..")
        raise ArgumentError.new("Directory capability root must end in a concrete directory name")
      end
    end

    {% if flag?(:linux) || flag?(:darwin) %}
      # Input for explicit no-symlink root traversal, not normal discovery paths.
      # Inspect original textual segments rather than Path#parts, which omits
      # repeated separators. Deliberately reject ambiguous or dot segments.
      def self.components(path : Path) : Array(String)
        literal = path.to_s
        unless path.absolute? && literal.starts_with?('/')
          raise ArgumentError.new("No-symlink capability root must be an absolute Unix path")
        end
        return [] of String if literal == "/"
        fragments = literal.split('/', remove_empty: false)
        fragments[1..].map { |part| Component.validate(part) }
      end
    {% end %}
  end
end
