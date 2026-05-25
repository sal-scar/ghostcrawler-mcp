# GhostCrawler MCP

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-green.svg)](https://nodejs.org)
[![Browser](https://img.shields.io/badge/Browser-Chromium%20only-orange.svg)](https://www.chromium.org)
[![Burp Suite](https://img.shields.io/badge/Burp%20Suite-MCP%20required-darkred.svg)](https://portswigger.net/burp)
[![VS Code](https://img.shields.io/badge/VS%20Code-Copilot%20required-blueviolet.svg)](https://code.visualstudio.com)

*A live MCP pentest agent. Crawls attack surfaces, fires exploits through your browser, and logs every finding to Burp Suite.*

---

## What is GhostCrawler?

GhostCrawler is a Chrome extension + Node.js MCP server that turns **VS Code + GitHub Copilot** into a live web penetration testing agent, with Burp Suite capturing everything.

Invoke `ghostcrawler` to activate the skill, then `pentest_active_tab`. GhostCrawler goes to work:

- Scans page source for hidden vulnerabilities
- Navigates the browser live to fire real exploits
- Logs every request to **Burp Suite Proxy History + Repeater**
- Chains auth bypass, IDOR, stored XSS -- all visible in real time

No black boxes. Every move is live in your browser and recorded in Burp.

> **Browser support:** Chromium-based browsers only (Chrome, Edge, Brave). This matches Burp Suite's embedded browser and ensures full proxy compatibility.

---

## Architecture

```
+-------------------------------------------------------------+
|                      VS Code Copilot                        |
|                   (you type, AI hunts)                      |
+------------------------+------------------------------------+
                         | MCP (stdio)
                         v
+-------------------------------------------------------------+
|               MCP Server  :3200                             |
|          ghostcrawler/mcp-server/dist/index.js              |
+-----------+-----------------------------+-------------------+
            | HTTP commands              | via burp-bridge
            v                            v
+---------------------+    +------------------------------+
|  Chrome Extension   |    |  burp-bridge daemon  :3201   |
|  (real browser)     |    |  survives MCP restarts       |
|  JS executes        |    +---------------+--------------+
|  cookies are live   |                    | SSE :9876
|  DOM XSS fires      |                    v
+---------------------+    +------------------------------+
                           |      Burp Suite MCP          |
                           |  Proxy History + Repeater    |
                           +------------------------------+
```

---

## Quick Start

### Prerequisites

- [Node.js](https://nodejs.org) v18+
- [Google Chrome](https://www.google.com/chrome/) (or any Chromium-based browser)
- [Burp Suite Community/Pro](https://portswigger.net/burp)
- [VS Code](https://code.visualstudio.com) with [GitHub Copilot](https://github.com/features/copilot)

### 1. Clone and Setup

**macOS / Linux (Kali, Ubuntu, Debian):**
```bash
git clone https://github.com/sal-scar/ghostcrawler-mcp.git
cd ghostcrawler-mcp
./setup.sh
```

**Windows (PowerShell):**
```powershell
git clone https://github.com/sal-scar/ghostcrawler-mcp.git
cd ghostcrawler-mcp
powershell -ExecutionPolicy Bypass -File setup.ps1
```

> **Note:** Windows setup (`setup.ps1`) is untested. Contributions welcome.

Both scripts auto-detect Node.js, build the MCP server, and write the VS Code `mcp.json` config. No manual editing required.

### 2. Set up Burp Suite

1. Open Burp Suite
2. Go to **Extensions > BApp Store**, search `MCP`, install **Burp MCP**
3. Burp MCP listens on `127.0.0.1:9876` by default
4. Set your browser proxy to `127.0.0.1:8080`

### 3. Load Chrome Extension

1. Open `chrome://extensions`
2. Enable **Developer Mode** (top right toggle)
3. Click **Load Unpacked** and select the `ghostcrawler-mcp/` folder
4. Pin the GhostCrawler icon to your toolbar

### 4. Restart VS Code

Restart VS Code. GitHub Copilot will auto-connect to GhostCrawler.

### 5. Activate the skill

In VS Code Copilot Chat, invoke the GhostCrawler skill first:

```
ghostcrawler https://your-target.com
```

This loads the pentest methodology and makes all tools available for the session.

### 6. Hunt

```
pentest_active_tab
```

or

```
auto_crawl
```

---

## MCP Tools

| Tool | Description |
|------|-------------|
| `pentest_active_tab` | Full OWASP Top 10 scan + live exploit chain on active tab |
| `auto_crawl` | Crawl and attack all forms/buttons on the page |
| `get_attack_surface` | Extract forms, buttons, and endpoints from current page |
| `run_attack_command` | Fire a specific attack: XSS, SQLi, default-creds, or custom |
| `run_browser_plan` | Execute browser actions live: navigate, type, click |
| `observe_dom_changes` | Watch live DOM mutations during an attack |
| `gc_doctor` | Diagnose connection issues end-to-end |
| `check_burp_mcp` | Verify Burp Suite MCP connection |

---

## Troubleshooting

Run `gc_doctor` first. It checks the HTTP bridge, extension polling, roundtrip, and Burp MCP connection.

| Problem | Fix |
|---------|-----|
| `Failed to sync` | MCP server not running -- restart VS Code |
| Extension not polling | Reload at `chrome://extensions` |
| Burp not capturing | Check browser proxy is set to `127.0.0.1:8080` |
| `pentest_active_tab` timeout | Run `gc_doctor`, reload extension, retry |

### Burp stays alive across MCP server restarts

GhostCrawler ships with a tiny **burp-bridge** daemon (`burp-bridge/`) that owns the SSE connection to Burp Suite MCP. The bridge survives MCP server restarts, so Burp never sees a client disconnect -- which previously crashed Burp and lost unsaved project state.

The bridge starts automatically the first time the MCP server tries to talk to Burp. You don't need to run it manually. To check it:

```bash
curl http://127.0.0.1:3201/health
```

If the bridge ever stops, the MCP server will re-spawn it on the next Burp call.

---

## Security Notice

- Local only - no external data transmission
- All traffic routed through Burp for full audit trail
- **Use only on targets you have written authorization to test**

---

## Support Me?

If GhostCrawler saved you time or helped on an engagement, feel free to buy me a coffee!

- BTC: 1K8mUDMZ1Yqk5BEzenkUmsN93GFcmdx6oN
- DOGE: DFE7BF8G4KXgoUchhm1UQNTgAx3BHoJCzy

No pressure — stars and contributions are just as welcome. 🕷
