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
  version "0.8.0"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/BootIntel/cli/releases/download/cli-v#{version}/bootintel-v#{version}-aarch64-macos.tar.gz"
      sha256 "7952a953cf6ca61654375fd0077f1a2918db3f7cc058fbb770278a12476ea3b3"
    end
    on_intel do
      url "https://github.com/BootIntel/cli/releases/download/cli-v#{version}/bootintel-v#{version}-x86_64-macos.tar.gz"
      sha256 "6704ea35f8c6f1925784046c91dd3a11c6439600ab8fc71aa3665c7dbe6efe4a"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/BootIntel/cli/releases/download/cli-v#{version}/bootintel-v#{version}-aarch64-linux.tar.gz"
      sha256 "1126fc60c68e1bb80e8607c2ad81ec77926f8a343c3c4247959d593455138158"
    end
    on_intel do
      url "https://github.com/BootIntel/cli/releases/download/cli-v#{version}/bootintel-v#{version}-x86_64-linux.tar.gz"
      sha256 "8b225459d6e61be6523dc92a3882963dd464599bb09ea00c2de2976ffe7d74a8"
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
