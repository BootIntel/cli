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
  version "0.9.0"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/BootIntel/cli/releases/download/cli-v#{version}/bootintel-v#{version}-aarch64-macos.tar.gz"
      sha256 "91bfe71fe7e7e28a62bae6df0e0933dd416debcc21e234fbf0de2d8a3a1345ce"
    end
    on_intel do
      url "https://github.com/BootIntel/cli/releases/download/cli-v#{version}/bootintel-v#{version}-x86_64-macos.tar.gz"
      sha256 "332acfc3d0add6c0846994d8709139e630bed619ec29c16ff8e9bac437e588a1"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/BootIntel/cli/releases/download/cli-v#{version}/bootintel-v#{version}-aarch64-linux.tar.gz"
      sha256 "800eefc3889dc3ce0882ac8bc261b375ae5e9d765062d229742e442605bf9a9c"
    end
    on_intel do
      url "https://github.com/BootIntel/cli/releases/download/cli-v#{version}/bootintel-v#{version}-x86_64-linux.tar.gz"
      sha256 "f8c7d70d636b154bb9b3ee8d2a5b8b0a7c038bf0300d4fce7d80728fa1915cc9"
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
