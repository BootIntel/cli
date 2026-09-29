# Reference copy of the formula published at BootIntel/homebrew-tap.
#
# The tap is what users install from:
#
#   brew tap bootintel/tap
#   brew install bootintel
#
# THE TAP IS THE ONE THAT MATTERS. This file is a copy for review and for
# bootstrapping the tap if it ever has to be recreated; nothing installs from
# it. It sat at 0.5.0 while 0.6.0, 0.6.1 and 0.7.0 shipped, because the release
# checklist did not name the tap as a step; that is now fixed in
# docs/releasing.md. A stale copy of a formula is worse than no copy: it invites
# someone to trust the checksums in it.
#
# Keep this byte-identical to the tap's Formula/bootintel.rb apart from this
# header, so a diff between them is a real finding rather than noise.
class Bootintel < Formula
  desc "Interactive UART capture and streaming boot-log analysis"
  homepage "https://bootintel.com"
  version "0.13.0"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/BootIntel/cli/releases/download/cli-v#{version}/bootintel-v#{version}-aarch64-macos.tar.gz"
      sha256 "8f7f6b588a65ec683fa9cf3dfd7e397a750e08619f5af95a3f5d1b185aa79046"
    end
    on_intel do
      url "https://github.com/BootIntel/cli/releases/download/cli-v#{version}/bootintel-v#{version}-x86_64-macos.tar.gz"
      sha256 "de219222b70013ee2a3b28ae07479f438dcc297ee14f95c3a7f4e4064c222dd4"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/BootIntel/cli/releases/download/cli-v#{version}/bootintel-v#{version}-aarch64-linux.tar.gz"
      sha256 "7376741baa7c70de58659275d30193ab5af6b679a1455a7006d5bc78fcb88620"
    end
    on_intel do
      url "https://github.com/BootIntel/cli/releases/download/cli-v#{version}/bootintel-v#{version}-x86_64-linux.tar.gz"
      sha256 "a23f16104344d578c6c99b3e8ea6ab6f15dbfbe26163c48582ce00810aa5442c"
    end
  end

  def install
    bin.install "bootintel"
  end

  test do
    # `version` is a real subcommand and prints the detector count, so this
    # asserts the binary actually ran rather than just existing on disk.
    assert_match "bootintel #{version}", shell_output("#{bin}/bootintel version")
  end
end
