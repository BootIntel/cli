# Homebrew formula for bootintel-cli.
#
# In-repo only — not published to any tap yet. To use today,
# copy this file into your own tap:
#
#   brew tap-new <you>/bootintel
#   cp bootintel.rb $(brew --repo <you>/bootintel)/Formula/
#   brew install <you>/bootintel/bootintel
#
# Once the first public release is cut, a `bootintel/homebrew-tap`
# repo will provide `brew tap bootintel/tap; brew install bootintel`.
#
# Formula uses the release tarballs from GitHub Releases directly.
# Regenerate the sha256 values on every version bump: run the
# release workflow, then paste values from SHA256SUMS into this file.

class Bootintel < Formula
  desc "Interactive UART capture + streaming boot-log analysis"
  homepage "https://bootintel.com"
  version "0.3.1"
  license "Apache-2.0"

  # SHA256s pulled from the SHA256SUMS artifact of the v0.3.1
  # release cut on bootintel/cli. Regenerate on every version bump.
  on_macos do
    on_arm do
      url "https://github.com/bootintel/cli/releases/download/cli-v#{version}/bootintel-v#{version}-aarch64-macos.tar.gz"
      sha256 "469133f56a72a54fa865ad8b39e62a7b82c490244aa18e6a19f4fb0b58f23ba1"
    end
    on_intel do
      url "https://github.com/bootintel/cli/releases/download/cli-v#{version}/bootintel-v#{version}-x86_64-macos.tar.gz"
      sha256 "984134978e995003c672c2aa0d370e968ddb2855f697166fbc132805b2afb376"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/bootintel/cli/releases/download/cli-v#{version}/bootintel-v#{version}-aarch64-linux.tar.gz"
      sha256 "62ea0fd1b537c193fbc4f6874b960854e10e2f27f4f94c163ac8d19afdb2996c"
    end
    on_intel do
      url "https://github.com/bootintel/cli/releases/download/cli-v#{version}/bootintel-v#{version}-x86_64-linux.tar.gz"
      sha256 "6c7a7e401d6691afab53bee5522a604f02777d269cea85357275cd40ee4b54e9"
    end
  end

  def install
    bin.install "bootintel"
  end

  test do
    assert_match "bootintel", shell_output("#{bin}/bootintel version")
  end
end
