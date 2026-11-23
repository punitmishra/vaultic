# typed: false
# frozen_string_literal: true

class Vaultic < Formula
  desc "Local-first, hardware-backed password manager with CLI, TUI, and GUI"
  homepage "https://github.com/punitmishra/vaultic"
  version "2.3.2"
  license "MIT"

  # The sha256 values below are kept current by the update-homebrew job in
  # .github/workflows/release.yml: on each tag it rewrites the sha256 line
  # following each release URL (idempotent — no one-shot placeholders).

  on_macos do
    on_arm do
      url "https://github.com/punitmishra/vaultic/releases/download/v#{version}/vaultic-macos-aarch64.tar.gz"
      sha256 "e118634b25f497f7c9e7caeec5cc49385d1486d4de4695215c5a9f8e8f1ea724"
    end
    on_intel do
      # Intel macOS uses the ARM64 binary via Rosetta 2.
      url "https://github.com/punitmishra/vaultic/releases/download/v#{version}/vaultic-macos-aarch64.tar.gz"
      sha256 "e118634b25f497f7c9e7caeec5cc49385d1486d4de4695215c5a9f8e8f1ea724"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/punitmishra/vaultic/releases/download/v#{version}/vaultic-linux-aarch64.tar.gz"
      sha256 "7d6a0a328a66d1a67ae71d6f23a4bc144074b8fb33a4917243546367c7d975ac"
    end
    on_intel do
      url "https://github.com/punitmishra/vaultic/releases/download/v#{version}/vaultic-linux-x86_64.tar.gz"
      sha256 "80ea0613ee4e187a841a93fa6a39fa714c0f1d4619fd4fc9bed323eeb57e31c5"
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
