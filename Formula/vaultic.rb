# typed: false
# frozen_string_literal: true

class Vaultic < Formula
  desc "Local-first, hardware-backed password manager with CLI, TUI, and GUI"
  homepage "https://github.com/punitmishra/vaultic"
  version "2.2.0"
  license "MIT"

  # SHA256 placeholders are substituted by the update-homebrew job in
  # .github/workflows/release.yml when a new tag is pushed. Keep them
  # in this exact form so the sed substitution finds them.

  on_macos do
    on_arm do
      url "https://github.com/punitmishra/vaultic/releases/download/v#{version}/vaultic-macos-aarch64.tar.gz"
      sha256 "PLACEHOLDER_SHA256_ARM64"
    end
    on_intel do
      # Intel macOS uses ARM64 binary via Rosetta 2
      url "https://github.com/punitmishra/vaultic/releases/download/v#{version}/vaultic-macos-aarch64.tar.gz"
      sha256 "PLACEHOLDER_SHA256_ARM64"
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
    # The release tarballs ship the binaries available on each target.
    # macOS (Apple Silicon and Intel) and Linux x86_64 ship all three;
    # Cross builds (Linux ARM64 / musl) ship the CLI + agent + MCP
    # server but no GUI binary. Install whichever are present.
    bin.install "vaultic"
    bin.install "vaultic-agent" if File.exist?("vaultic-agent")
    bin.install "vaultic-gui" if File.exist?("vaultic-gui")
    bin.install "vaultic-mcp" if File.exist?("vaultic-mcp")

    # Generate shell completions for the CLI.
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

      The optional Unix-socket daemon (`vaultic-agent`), desktop GUI
      (`vaultic-gui`), and MCP server for AI clients (`vaultic-mcp`)
      are installed alongside `vaultic` (the GUI is macOS / Linux
      x86_64 only). See:
        vaultic-agent --help
        vaultic-gui --help
        vaultic-mcp --help
    EOS
  end

  test do
    assert_match "vaultic #{version}", shell_output("#{bin}/vaultic --version")
    assert_match "vaultic-agent", shell_output("#{bin}/vaultic-agent --version") if (bin/"vaultic-agent").exist?
  end
end
