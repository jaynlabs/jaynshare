Jaynshare beta access for __CLIENT_ID__

This bundle contains the installer and the public Jaynshare CA. It does not
contain your client secret. The same bundle serves macOS and Windows; follow the
section for your machine.

Before starting, on either platform:

1. Install and connect Tailscale using the private invite from the operator.
2. Make sure `node --version` reports 26 or newer.
3. Make sure the existing `claude` command starts normally.
4. Obtain your one-time Jaynshare secret through the separate private channel.

-- macOS ---------------------------------------------------------------------

Open Terminal in this directory and run:

    bash ./install.sh

Use this exact form even on macOS. It also works when a messaging or
file-transfer service has stripped the script's Unix executable bit.

-- Windows 10/11 (Git Bash) --------------------------------------------------

Jaynshare runs on native Windows through Git for Windows. It does not use WSL,
and it never needs Administrator rights.

1. Install Git for Windows if you do not already have it, which provides the
   "Git Bash" terminal.
2. Make sure Node.js 26+ and Claude Code are the native Windows builds, and that
   `node --version` and `claude --version` both work inside Git Bash.
3. Right-click this folder and choose "Open Git Bash here", then run:

    bash ./install.sh

PowerShell and CMD are not supported for installation. Your enrollment is stored
under your Windows profile and locked to your account with an NTFS access rule.

-- Both platforms ------------------------------------------------------------

Paste the secret when prompted; it is not echoed. The installer verifies your
access to __PROXY_HOST__ before reporting success, and undoes everything if that
check fails.

Normal use:

    ~/.local/bin/jaynshare-claude
    ~/.local/bin/jaynshare status

The installer prints the full path to both commands. Use what it printed if it
differs from the two lines above: your enrollment is stored under your Windows
profile, and `~` inside Git Bash does not always mean that profile.

The launcher shows a terminal picker. Choose Automatic for normal fleet routing,
or choose an account to prefer it for this Claude process with automatic failover.
Arrow keys work in most terminals; where they do not, including some Git Bash
setups, the picker lists numbered accounts and waits for you to type one.

For non-interactive use:

    ~/.local/bin/jaynshare-claude --account ACCOUNT -- CLAUDE_ARGS...
    ~/.local/bin/jaynshare-claude --auto -- CLAUDE_ARGS...

If Jaynshare is unavailable and you explicitly want to use your own local
Claude account:

    ~/.local/bin/jaynshare-claude --direct

Do not share the secret or this bundle's CA publicly. Report a lost secret to
the operator so only your credential can be revoked and replaced.

To remove Jaynshare, ask the operator to revoke your credential, then follow
the client removal instructions at:

    https://github.com/jaynlabs/jaynshare/blob/main/docs/deployment.md#removal
