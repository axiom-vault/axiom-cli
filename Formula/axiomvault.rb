# Homebrew formula for AxiomVault CLI
#
# This formula is intended for the axiom-vault/homebrew-tap repository.
# Install via:
#   brew tap axiom-vault/tap
#   brew install axiomvault
#
# The sha256 values below are updated automatically by the release workflow.
# To update manually: set VERSION and run `brew audit --strict` to verify.

class Axiomvault < Formula
  desc "Command-line interface for AxiomVault encrypted vault"
  homepage "https://github.com/axiom-vault/axiom-cli"
  version "0.1.0"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/axiom-vault/axiom-cli/releases/download/v#{version}/axiomvault-aarch64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_AARCH64_APPLE_DARWIN"
    end

    on_intel do
      url "https://github.com/axiom-vault/axiom-cli/releases/download/v#{version}/axiomvault-x86_64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_X86_64_APPLE_DARWIN"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/axiom-vault/axiom-cli/releases/download/v#{version}/axiomvault-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "PLACEHOLDER_AARCH64_LINUX"
    end

    on_intel do
      url "https://github.com/axiom-vault/axiom-cli/releases/download/v#{version}/axiomvault-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "PLACEHOLDER_X86_64_LINUX"
    end
  end

  def install
    bin.install "axiomvault"
  end

  test do
    system "#{bin}/axiomvault", "--version"
  end
end
