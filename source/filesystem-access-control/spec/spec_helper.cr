require "spec"
require "file_utils"
require "random/secure"
require "../src/filesystem-access-control"

# Temporarily replace environment variables without leaking global state to
# other examples. The test suite deliberately avoids parallel spec execution.
module SpecEnvironment
  def self.with_temp_dir(prefix : String, &)
    path = Path[Dir.tempdir] / "#{prefix}-#{Random::Secure.hex(8)}"
    Dir.mkdir_p(path)
    yield path.to_s
  ensure
    FileUtils.rm_rf(path) if path && Dir.exists?(path)
  end

  def self.with(values : Hash(String, String?), &)
    original = values.to_h { |key, _| {key, ENV[key]?} }
    values.each do |key, value|
      if value
        ENV[key] = value
      else
        ENV.delete(key)
      end
    end
    yield
  ensure
    if original
      original.each do |key, value|
        if value
          ENV[key] = value
        else
          ENV.delete(key)
        end
      end
    end
  end
end
