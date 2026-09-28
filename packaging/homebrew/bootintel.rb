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
  version "0.11.0"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/BootIntel/cli/releases/download/cli-v#{version}/bootintel-v#{version}-aarch64-macos.tar.gz"
      sha256 "31d85dcb1e84fc328c6099eb98b803ca03e5c7bd79048af94f1f57e70f949b91"
    end
    on_intel do
      url "https://github.com/BootIntel/cli/releases/download/cli-v#{version}/bootintel-v#{version}-x86_64-macos.tar.gz"
      sha256 "87a6e2595b5375e84f1a7996987addfdc1101d81dcb6d1e837ff72cca59c54cc"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/BootIntel/cli/releases/download/cli-v#{version}/bootintel-v#{version}-aarch64-linux.tar.gz"
      sha256 "82199d44158ddb96b48637de49a9a36d0284cd222725e4d77b28b28277739b4f"
    end
    on_intel do
      url "https://github.com/BootIntel/cli/releases/download/cli-v#{version}/bootintel-v#{version}-x86_64-linux.tar.gz"
      sha256 "779c6e487b59dbccb3a6d3098cd46ce62609980b8de237b1cd1db4baeeab056e"
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
