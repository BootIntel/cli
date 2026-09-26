# Template for the formula published at BootIntel/homebrew-tap.
#
# The tap is what users install from:
#
#   brew tap bootintel/tap
#   brew install bootintel
#
# This file is the reference copy. When cutting a release, update the tap's
# Formula/bootintel.rb with the new version and all four sha256 values from
# that release's SHA256SUMS artifact. A stale formula is worse than a missing
# one: it installs an old binary while appearing to work.
#
# The version and checksums below track the latest release but are NOT what
# users get; the tap is. Verify the tap after every release.

class Bootintel < Formula
  desc "Interactive UART capture + streaming boot-log analysis"
  homepage "https://bootintel.com"
  version "0.5.0"
  license "Apache-2.0"

  # SHA256s pulled from the SHA256SUMS artifact of the v0.3.1
  # release cut on bootintel/cli. Regenerate on every version bump.
  on_macos do
    on_arm do
      url "https://github.com/bootintel/cli/releases/download/cli-v#{version}/bootintel-v#{version}-aarch64-macos.tar.gz"
      sha256 "3863ee56f86b43a1fd4f131d9e484713ebcb1550bece5ad7c2ee4de2c3ca77ce"
    end
    on_intel do
      url "https://github.com/bootintel/cli/releases/download/cli-v#{version}/bootintel-v#{version}-x86_64-macos.tar.gz"
      sha256 "55cfe10f276b47e8843a670ba349c0add1f091e842a190fdd07229b646425c44"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/bootintel/cli/releases/download/cli-v#{version}/bootintel-v#{version}-aarch64-linux.tar.gz"
      sha256 "0f91ffde24100bc8456aef39bda9493ba677d81b1589b2d59833be10d62ea4be"
    end
    on_intel do
      url "https://github.com/bootintel/cli/releases/download/cli-v#{version}/bootintel-v#{version}-x86_64-linux.tar.gz"
      sha256 "1a2dc10499c8db658a698d45e47789b964843d806a0b5f7f51e439c1e05586ed"
    end
  end

  def install
    bin.install "bootintel"
  end

  test do
    assert_match "bootintel", shell_output("#{bin}/bootintel version")
  end
end
