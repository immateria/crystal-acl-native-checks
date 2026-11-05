require "./spec_helper"

{% if flag?(:darwin) %}
  describe "native macOS extended ACL inspection" do
    it "observes an opened directory, then refuses a world-accessible mode" do
      SpecEnvironment.with_temp_dir("acl-darwin-native") do |folder|
        root = Path[folder] / "root"
        Dir.mkdir(root, 0o700)
        Filesystem::Capabilities::Directory.open_existing(root) do |cap|
          first = cap.access_report
          first.backend.should eq(:darwin_extended_acl)
          first.owner_matches.should be_true
          first.mode.should eq(0o700)
          File.chmod(root, 0o777)
          exposed = cap.access_report
          exposed.mode.should eq(0o777)
          exposed.private?.should be_false
          expect_raises(Filesystem::AccessControl::InsecureAccessError) { exposed.require_private! }
        end
      end
    end

    it "rejects symlinks when opening a pathname ACL inspector" do
      SpecEnvironment.with_temp_dir("acl-darwin-reparse") do |folder|
        root = Path[folder] / "root"
        Dir.mkdir(root, 0o700)
        File.symlink(root, Path[folder] / "link")
        expect_raises(Filesystem::Capabilities::Error) do
          Filesystem::AccessControl.inspect_directory(Path[folder] / "link")
        end
      end
    end
  end
{% elsif flag?(:windows) %}
  describe "native Windows opened-HANDLE DACL inspection" do
    it "inspects the same retained directory without reopening its display path" do
      SpecEnvironment.with_temp_dir("acl-win-native") do |folder|
        root = Path[folder] / "root"
        Dir.mkdir(root)
        Filesystem::Capabilities::Directory.open_existing(root) do |cap|
          first = cap.access_report
          first.backend.should eq(:windows_dacl)
          first.acl_state.should_not eq(Filesystem::AccessControl::State::Unsupported)
          # Observation remains available after the original pathname moves.
          renamed = Path[folder] / "moved"
          File.rename(root, renamed)
          second = cap.access_report
          second.backend.should eq(:windows_dacl)
          second.path.should eq(root)
        end
      end
    end

    it "rejects typed file-versus-directory mismatches on a retained handle" do
      SpecEnvironment.with_temp_dir("acl-win-kind") do |folder|
        root = Path[folder]
        Filesystem::Capabilities::Directory.open_existing(root) do |cap|
          report = cap.access_report
          report.backend.should eq(:windows_dacl)
          report.acl_state.should_not eq(Filesystem::AccessControl::State::Unsupported)
        end
      end
    end
  end
{% end %}
