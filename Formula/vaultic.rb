# typed: false
# frozen_string_literal: true

class Vaultic < Formula
  desc "Local-first, hardware-backed password manager with CLI, TUI, and GUI"
  homepage "https://github.com/punitmishra/vaultic"
  version "2.3.1"
  license "MIT"

  # The sha256 values below are kept current by the update-homebrew job in
  # .github/workflows/release.yml: on each tag it rewrites the sha256 line
  # following each release URL (idempotent — no one-shot placeholders).

  on_macos do
    on_arm do
      url "https://github.com/punitmishra/vaultic/releases/download/v#{version}/vaultic-macos-aarch64.tar.gz"
      sha256 "c081dcbea671de018bab70577e21d459805f013153e7737cc933c584680bdb2a"
    end
    on_intel do
      # Intel macOS uses the ARM64 binary via Rosetta 2.
      url "https://github.com/punitmishra/vaultic/releases/download/v#{version}/vaultic-macos-aarch64.tar.gz"
      sha256 "c081dcbea671de018bab70577e21d459805f013153e7737cc933c584680bdb2a"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/punitmishra/vaultic/releases/download/v#{version}/vaultic-linux-aarch64.tar.gz"
      sha256 "e93d301c590cf3eda11acb83d9f55c116951a018a1a31d65f566315fbdaa67ec"
    end
    on_intel do
      url "https://github.com/punitmishra/vaultic/releases/download/v#{version}/vaultic-linux-x86_64.tar.gz"
      sha256 "bdc49368c0517a32426fc5b4d266d5a641165f185cbc61a982216f5f13f3a36e"
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
