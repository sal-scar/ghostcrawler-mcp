# ============================================================
#  GhostCrawler - setup.ps1
#  Windows PowerShell setup script
#  Run: Right-click -> "Run with PowerShell"
#  Or:  powershell -ExecutionPolicy Bypass -File setup.ps1
# ============================================================

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   GhostCrawler - Setup (Windows)"       -ForegroundColor Cyan
Write-Host "   Live MCP Pentest Agent"                -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# -----------------------------------------------------------
# 1. Repo root
# -----------------------------------------------------------
$RepoDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Write-Host "[*] Repo root: $RepoDir" -ForegroundColor Cyan

# -----------------------------------------------------------
# 2. Detect Node.js
# -----------------------------------------------------------
$NodeBin = $null
$Candidates = @(
    "node",
    "$env:ProgramFiles\nodejs\node.exe",
    "$env:LOCALAPPDATA\Programs\nodejs\node.exe",
    "$env:LOCALAPPDATA\nvm\node.exe"
)

foreach ($c in $Candidates) {
    try {
        $resolved = (Get-Command $c -ErrorAction SilentlyContinue)?.Source
        if ($resolved) { $NodeBin = $resolved; break }
    } catch {}
    if (Test-Path $c) { $NodeBin = $c; break }
}

if (-not $NodeBin) {
    Write-Host "[x] Node.js not found. Install from https://nodejs.org (v18+) then re-run." -ForegroundColor Red
    exit 1
}

$NodeVersion = & $NodeBin --version 2>$null
$Major = [int]($NodeVersion -replace 'v','').Split('.')[0]
if ($Major -lt 18) {
    Write-Host "[x] Node.js v18+ required. Found: $NodeVersion" -ForegroundColor Red
    exit 1
}
Write-Host "[+] Node.js: $NodeBin ($NodeVersion)" -ForegroundColor Green

# -----------------------------------------------------------
# 3. Build MCP server
# -----------------------------------------------------------
Write-Host "[*] Installing dependencies..." -ForegroundColor Cyan
Set-Location "$RepoDir\mcp-server"
& npm install --silent
Write-Host "[+] Dependencies installed" -ForegroundColor Green

Write-Host "[*] Building MCP server..." -ForegroundColor Cyan
& npm run build

$DistFile = "$RepoDir\mcp-server\dist\index.js"
if (-not (Test-Path $DistFile)) {
    Write-Host "[x] Build failed - dist/index.js not found." -ForegroundColor Red
    exit 1
}
Write-Host "[+] MCP server built: dist\index.js" -ForegroundColor Green
Set-Location $RepoDir

# -----------------------------------------------------------
# 3b. Build burp-bridge daemon
# -----------------------------------------------------------
# The burp-bridge owns the SSE connection to Burp Suite MCP and survives
# MCP server restarts. Without it, every MCP server restart drops the SSE
# socket, which crashes Burp's MCP extension and closes Burp entirely.
Write-Host "[*] Installing burp-bridge dependencies..." -ForegroundColor Cyan
Set-Location "$RepoDir\burp-bridge"
& npm install --silent
Write-Host "[+] Dependencies installed" -ForegroundColor Green

Write-Host "[*] Building burp-bridge daemon..." -ForegroundColor Cyan
& npm run build

$BridgeDistFile = "$RepoDir\burp-bridge\dist\index.js"
if (-not (Test-Path $BridgeDistFile)) {
    Write-Host "[x] Build failed - burp-bridge\dist\index.js not found." -ForegroundColor Red
    exit 1
}
Write-Host "[+] burp-bridge built: dist\index.js" -ForegroundColor Green
Set-Location $RepoDir

# -----------------------------------------------------------
# 4. Write VS Code mcp.json
# -----------------------------------------------------------
$VsCodeConfigDir = "$env:APPDATA\Code\User"
# Also check VS Code Insiders
if (-not (Test-Path $VsCodeConfigDir)) {
    $Insiders = "$env:APPDATA\Code - Insiders\User"
    if (Test-Path $Insiders) { $VsCodeConfigDir = $Insiders }
    else {
        New-Item -ItemType Directory -Force -Path $VsCodeConfigDir | Out-Null
    }
}

$McpJson = "$VsCodeConfigDir\mcp.json"
Write-Host "[*] Writing VS Code MCP config: $McpJson" -ForegroundColor Cyan

if (Test-Path $McpJson) {
    Copy-Item $McpJson "$McpJson.bak" -Force
    Write-Host "[!] Existing mcp.json backed up to $McpJson.bak" -ForegroundColor Yellow
}

$DistPath = ($DistFile -replace '\\', '\\\\')
$NodePath  = ($NodeBin  -replace '\\', '\\\\')

& $NodeBin -e @"
const fs = require('fs');
const p = '$($McpJson -replace "\\", "\\\\")';
let cfg = {};
try { cfg = JSON.parse(fs.readFileSync(p, 'utf8')); } catch {}
if (!cfg.servers) cfg.servers = {};
cfg.servers.ghostcrawler = {
  type: 'stdio',
  command: '$($NodeBin -replace "\\", "\\\\")',
  args: ['$($DistFile -replace "\\", "\\\\")']
};
fs.mkdirSync(require('path').dirname(p), { recursive: true });
fs.writeFileSync(p, JSON.stringify(cfg, null, 2));
console.log('Written: ' + p);
"@

Write-Host "[+] VS Code MCP config written" -ForegroundColor Green

# -----------------------------------------------------------
# 5. Install SKILL.md for GitHub Copilot
# -----------------------------------------------------------
$SkillDir = "$env:USERPROFILE\.copilot\skills\ghostcrawler"
Write-Host "[*] Installing GhostCrawler skill: $SkillDir" -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $SkillDir | Out-Null
Copy-Item "$RepoDir\SKILL.md" "$SkillDir\SKILL.md" -Force
Write-Host "[+] Skill installed: $SkillDir\SKILL.md" -ForegroundColor Green

# -----------------------------------------------------------
# 6. Done
# -----------------------------------------------------------
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "   Setup complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Next steps:" -ForegroundColor White
Write-Host ""
Write-Host "  1. Load the Chrome extension:"
Write-Host "     chrome://extensions -> Developer Mode -> Load Unpacked -> $RepoDir"
Write-Host ""
Write-Host "  2. Install Burp Suite MCP extension:"
Write-Host "     Extensions -> BApp Store -> search 'MCP' -> Install"
Write-Host ""
Write-Host "  3. Restart VS Code (picks up new MCP config)"
Write-Host ""
Write-Host "  4. Open GitHub Copilot Chat and activate the skill:"
Write-Host "     Type: ghostcrawler https://your-target.com" -ForegroundColor Cyan
Write-Host "     Then: pentest_active_tab  or  auto_crawl" -ForegroundColor Cyan
Write-Host ""
