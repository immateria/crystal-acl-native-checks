# Filename-component policy for owned filesystem operations: the host OS's
# own rule. Independent from application naming or XDG policies in
# directories, which keep the portable rule (`windows_valid?`).
module Filesystem::Capabilities
  # :nodoc:
  module Component
    # Win32's limit on a component, counted here in UTF-8 bytes. A name within
    # it also has at most 255 UTF-16 units (APFS's limit) and fits ext4's 255
    # bytes, so it is the portable limit. It is stricter than NTFS for
    # non-ASCII names.
    PORTABLE_MAX_BYTES = 255

    # The host's rule. On Windows it is Win32's (`windows_problem`): there
    # `aux.c` opens a device. On Unix only a path's grammar: not empty, not
    # `.` or `..`, no `/` and no NUL. Bytes that are not UTF-8 are allowed,
    # since `readdir` returns them and `openat` takes bytes. The file system
    # enforces its own length limit in its own unit (APFS counts UTF-16 units,
    # ext4 bytes); a name too long fails there with ENAMETOOLONG, which
    # `Directory::EntryError#name_too_long?` names.
    def self.validate(name : String) : String
      {% if flag?(:windows) %}
        if problem = windows_problem(name)
          raise ArgumentError.new(problem)
        end
      {% else %}
        bytes = name.to_slice
        if bytes.empty? || name.in?(".", "..") || bytes.includes?('/'.ord.to_u8) || bytes.includes?(0_u8)
          raise ArgumentError.new("Invalid directory path component: #{name.inspect}")
        end
      {% end %}
      name
    end

    # Whether NAME is a usable component on Windows, and so on every OS.
    def self.windows_valid?(name : String) : Bool
      windows_problem(name).nil?
    end

    # Why Windows refuses NAME as a component, or nil when it takes it.
    def self.windows_problem(name : String) : String?
      # Checked before split and stem strings are made from a huge name.
      if name.bytesize > PORTABLE_MAX_BYTES
        return "Directory path component exceeds #{PORTABLE_MAX_BYTES} UTF-8 bytes"
      end
      if !name.valid_encoding? || name.empty? || name.in?(".", "..") || name.includes?('/') ||
         name.includes?('\\') || name.includes?('\0') || name.includes?(':') ||
         (name.ends_with?(' ') || name.ends_with?('.'))
        return "Invalid directory path component: #{name.inspect}"
      end
      if name.each_char.any? { |char| char.ord < 32 || "<>\"|?*".includes?(char) }
        return "Invalid directory path component: #{name.inspect}"
      end
      stem = name.split('.', 2).first.rstrip(" ").upcase
      # Win32 also treats ISO-8859-1 superscript 1, 2 and 3 as device-number
      # suffixes. For example, COM¹.txt resolves as a reserved device name.
      device_suffix = stem[-1]?
      if stem.in?("CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$") ||
         (stem.size == 4 && (stem.starts_with?("COM") || stem.starts_with?("LPT")) &&
         device_suffix && (device_suffix.in?('1'..'9') || device_suffix.in?('¹', '²', '³')))
        return "Reserved directory path component: #{name.inspect}"
      end
    end
  end
end
