# typed: false
# frozen_string_literal: true

class Vaultic < Formula
  desc "Local-first, hardware-secured password manager with AI-powered management"
  homepage "https://github.com/punitmishra/vaultic"
  version "2.0.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/punitmishra/vaultic/releases/download/v#{version}/vaultic-macos-aarch64.tar.gz"
      sha256 "PLACEHOLDER_SHA256_ARM64"
    end
    on_intel do
      url "https://github.com/punitmishra/vaultic/releases/download/v#{version}/vaultic-macos-x86_64.tar.gz"
      sha256 "PLACEHOLDER_SHA256_X86_64"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/punitmishra/vaultic/releases/download/v#{version}/vaultic-linux-aarch64.tar.gz"
      sha256 "PLACEHOLDER_SHA256_LINUX_ARM64"
    end
    on_intel do
      url "https://github.com/punitmishra/vaultic/releases/download/v#{version}/vaultic-linux-x86_64.tar.gz"
      sha256 "PLACEHOLDER_SHA256_LINUX_X86_64"
    end
  end

  def install
    bin.install "vaultic"

    # Generate shell completions
    generate_completions_from_executable(bin/"vaultic", "completions")
  end

  def caveats
    <<~EOS
      To get started with vaultic:
        vaultic init -n "My Vault"
        vaultic unlock
        vaultic add "GitHub" -u "user@example.com"

      For shell completions, add to your shell config:
        # Bash (~/.bashrc)
        eval "$(vaultic completions bash)"

        # Zsh (~/.zshrc)
        eval "$(vaultic completions zsh)"

        # Fish (~/.config/fish/config.fish)
        vaultic completions fish | source

      For Git credential helper:
        git config --global credential.helper vaultic
    EOS
  end

  test do
    # Test basic CLI
    assert_match "vaultic", shell_output("#{bin}/vaultic --version")

    # Test init in temp directory
    system bin/"vaultic", "--vault", testpath/"vault", "init", "-n", "Test", "--password", "test123!"

    # Verify vault was created
    assert_predicate testpath/"vault", :exist?
  end
end
