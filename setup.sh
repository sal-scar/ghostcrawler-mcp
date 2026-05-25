#!/usr/bin/env bash
set -e

# ============================================================
#  GhostCrawler - setup.sh
#  Supports: macOS, Linux (Kali / Ubuntu / Debian)
#  For Windows: use setup.ps1 instead
# ============================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info() { echo -e "${CYAN}[*]${RESET} $1"; }
ok()   { echo -e "${GREEN}[+]${RESET} $1"; }
warn() { echo -e "${YELLOW}[!]${RESET} $1"; }
die()  { echo -e "${RED}[x]${RESET} $1"; exit 1; }

echo ""
echo -e "${BOLD}========================================${RESET}"
echo -e "${BOLD}   GhostCrawler - Setup${RESET}"
echo -e "${BOLD}   Live MCP Pentest Agent${RESET}"
echo -e "${BOLD}========================================${RESET}"
echo ""

# -----------------------------------------------------------
# 1. Detect repo root
# -----------------------------------------------------------
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
info "Repo root: $REPO_DIR"

# -----------------------------------------------------------
# 2. Detect Node.js
# -----------------------------------------------------------
NODE_BIN=""
CANDIDATES=(
  "node"
  "/usr/bin/node"
  "/usr/local/bin/node"
  "/opt/homebrew/bin/node"
  "$HOME/.nvm/versions/node/$(ls "$HOME/.nvm/versions/node" 2>/dev/null | sort -V | tail -1)/bin/node"
  "$HOME/.local/bin/node"
  "/private/tmp/node-v20.19.1-darwin-x64/bin/node"
)

for candidate in "${CANDIDATES[@]}"; do
  if [ -x "$candidate" ] 2>/dev/null; then
    NODE_BIN="$candidate"; break
  elif command -v "$candidate" &>/dev/null 2>&1; then
    NODE_BIN="$(command -v "$candidate")"; break
  fi
done

if [ -z "$NODE_BIN" ]; then
  die "Node.js not found. Install Node.js v18+ from https://nodejs.org then re-run this script."
fi

NODE_VERSION=$("$NODE_BIN" --version 2>/dev/null)
MAJOR=$(echo "$NODE_VERSION" | sed 's/v//' | cut -d. -f1)
if [ "$MAJOR" -lt 18 ] 2>/dev/null; then
  die "Node.js v18+ required. Found: $NODE_VERSION. Upgrade at https://nodejs.org"
fi
ok "Node.js: $NODE_BIN ($NODE_VERSION)"

NODE_DIR="$(dirname "$NODE_BIN")"
export PATH="$NODE_DIR:$PATH"

# -----------------------------------------------------------
# 3. Build MCP server
# -----------------------------------------------------------
info "Installing MCP server dependencies..."
cd "$REPO_DIR/mcp-server"
npm install --silent 2>&1 | tail -3
ok "Dependencies installed"

info "Building MCP server..."
npm run build 2>&1 | tail -5

if [ ! -f "$REPO_DIR/mcp-server/dist/index.js" ]; then
  die "Build  dist/index.js not found. Check errors above."failed 
fi
ok "MCP server built: dist/index.js"
cd "$REPO_DIR"

# -----------------------------------------------------------
# 3b. Build burp-bridge daemon
# -----------------------------------------------------------
# The burp-bridge owns the SSE connection to Burp Suite MCP and survives
# MCP server restarts. Without it, every MCP server restart drops the SSE
# socket, which crashes Burp's MCP extension and takes down Burp Suite.
info "Installing burp-bridge dependencies..."
cd "$REPO_DIR/burp-bridge"
npm install --silent 2>&1 | tail -3
ok "Dependencies installed"

info "Building burp-bridge daemon..."
npm run build 2>&1 | tail -5

if [ ! -f "$REPO_DIR/burp-bridge/dist/index.js" ]; then
  die "Build failed - burp-bridge/dist/index.js not found. Check errors above."
fi
ok "burp-bridge built: dist/index.js"
cd "$REPO_DIR"

# -----------------------------------------------------------
# 4. Detect VS Code MCP config path
# -----------------------------------------------------------
OS="$(uname -s)"
if [ "$OS" = "Darwin" ]; then
  VSCODE_CONFIG_DIR="$HOME/Library/Application Support/Code/User"
elif [ "$OS" = "Linux" ]; then
  # Standard VS Code on Linux
  if [ -d "$HOME/.config/Code/User" ]; then
    VSCODE_CONFIG_DIR="$HOME/.config/Code/User"
  # VS Code Insiders
  elif [ -d "$HOME/.config/Code - Insiders/User" ]; then
    VSCODE_CONFIG_DIR="$HOME/.config/Code - Insiders/User"
  else
    VSCODE_CONFIG_DIR="$HOME/.config/Code/User"
    mkdir -p "$VSCODE_CONFIG_DIR"
    warn "VS Code config dir not found, creating: $VSCODE_CONFIG_DIR"
  fi
else
  warn "Unrecognised OS: $OS. Use setup.ps1 on Windows."
  VSCODE_CONFIG_DIR=""
fi

# -----------------------------------------------------------
# 5. Write VS Code mcp.json
# -----------------------------------------------------------
if [ -n "$VSCODE_CONFIG_DIR" ]; then
  MCP_JSON="$VSCODE_CONFIG_DIR/mcp.json"
  info "Writing VS Code MCP config: $MCP_JSON"

  if [ -f "$MCP_JSON" ]; then
    cp "$MCP_JSON" "${MCP_JSON}.bak"
    warn "Existing mcp.json backed up to ${MCP_JSON}.bak"
  fi

  "$NODE_BIN" -e "
const fs = require('fs');
const path = '$MCP_JSON';
let cfg = {};
try { cfg = JSON.parse(fs.readFileSync(path, 'utf8')); } catch {}
if (!cfg.servers) cfg.servers = {};
cfg.servers.ghostcrawler = {
  type: 'stdio',
  command: '$NODE_BIN',
  args: ['$REPO_DIR/mcp-server/dist/index.js']
};
fs.mkdirSync(require('path').dirname(path), { recursive: true });
fs.writeFileSync(path, JSON.stringify(cfg, null, 2));
console.log('Written: ' + path);
"
  ok "VS Code MCP config written"
else
  warn "Could not detect VS Code config path. Add manually (see README)."
fi

# -----------------------------------------------------------
# 6. Install SKILL.md for GitHub Copilot
# -----------------------------------------------------------
SKILL_DIR="$HOME/.copilot/skills/ghostcrawler"
info "Installing GhostCrawler skill: $SKILL_DIR"
mkdir -p "$SKILL_DIR"
cp "$REPO_DIR/SKILL.md" "$SKILL_DIR/SKILL.md"
ok "Skill installed: $SKILL_DIR/SKILL.md"

# -----------------------------------------------------------
# 7. Done
# -----------------------------------------------------------
echo ""
echo -e "${GREEN}${BOLD}========================================${RESET}"
echo -e "${GREEN}${BOLD}   Setup complete!${RESET}"
echo -e "${GREEN}${BOLD}========================================${RESET}"
echo ""
echo -e "  ${BOLD}Next steps:${RESET}"
echo ""
echo -e "  ${CYAN}1.${RESET} Load the Chrome extension:"
echo -e "     Open chrome://extensions -> Enable Developer Mode"
echo -e "     -> Load Unpacked -> select: ${BOLD}$REPO_DIR${RESET}"
echo ""
echo -e "  ${CYAN}2.${RESET} Install Burp Suite MCP extension:"
echo -e "     Extensions -> BApp Store -> search 'MCP' -> Install"
echo ""
echo -e "  ${CYAN}3.${RESET} Restart VS Code (picks up new MCP config)"
echo ""
echo -e "  ${CYAN}4.${RESET} Open GitHub Copilot Chat and activate the skill:"
echo -e "     Type: ${BOLD}ghostcrawler https://your-target.com${RESET}"
echo -e "     Then: ${BOLD}pentest_active_tab${RESET} or ${BOLD}auto_crawl${RESET}"
echo ""
