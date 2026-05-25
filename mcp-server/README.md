# Ghostcrawler MCP Server

AI-driven vulnerability scanner for web applications using the Model Context Protocol (MCP). Works in conjunction with the Ghostcrawler browser extension to provide intelligent, context-aware security testing.

## Architecture

```
┌─────────────────┐       ┌──────────────────┐       ┌─────────────────┐
│ Browser         │       │ MCP Server       │       │ Burp Suite      │
│ Extension       │◄─────►│ (AI Orchestrator)│◄─────►│ (HTTP Proxy)    │
│                 │ HTTP  │                  │ Proxy │                 │
│ - Detector      │       │ - Vuln Tests     │       │ - Traffic Log   │
│ - Network Hook  │       │ - Payloads       │       │ - Intercept     │
│ - Form Fill     │       │ - MCP Tools      │       │ - Scan Results  │
└─────────────────┘       └──────────────────┘       └─────────────────┘
```

## Features

- **Attack Surface Discovery**: Receives page structure, forms, buttons, and captured API endpoints from browser extension
- **AI-Driven Testing**: Exposes MCP tools for intelligent vulnerability testing orchestrated by Claude/GPT
- **Burp Suite Integration**: All test requests proxied through Burp for complete traffic logging and analysis
- **Bidirectional Communication**: HTTP bridge for extension→server (scans) and server→extension (commands)
- **Vulnerability Tests**:
  - SQL Injection (8 payloads)
  - XSS (5 payloads)
  - IDOR fuzzing
  - Command Injection (5 payloads)
  - Custom endpoint testing

## Installation

```bash
cd mcp-server
npm install
npm run build
```

## Usage

### 1. Start the HTTP bridge server:

```bash
npm start
```

The server will:
- Listen on `http://127.0.0.1:3100` for extension communication
- Start MCP server on stdio for AI model connection
- Proxy all vulnerability test requests through Burp Suite at `http://127.0.0.1:8080`

### 2. Configure in Claude Desktop (or other MCP client):

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ghostcrawler": {
      "command": "node",
      "args": ["/Users/sal/Documents/ghostcrawler/mcp-server/dist/index.js"],
      "env": {
        "HTTP_PROXY": "http://127.0.0.1:8080",
        "HTTP_PORT": "3100"
      }
    }
  }
}
```

### 3. Enable MCP in browser extension:

1. Open the Ghostcrawler extension popup
2. Scroll to "MCP Server" section
3. Check "Enable MCP"
4. Verify server URL: `http://127.0.0.1:3100`

### 4. Use from Claude/GPT:

```
Scan the current page for vulnerabilities
```

Claude will:
1. Call `get_attack_surface` to retrieve page info from extension
2. Analyze forms, buttons, and API endpoints
3. Select appropriate tests (SQLi, XSS, etc.)
4. Execute tests through Burp proxy
5. Correlate results and report findings

## MCP Tools

### `get_attack_surface`
Retrieve current page structure from browser extension.

**Returns**: Page title, URL, detected frameworks, forms, buttons, captured API endpoints

### `trigger_button`
Trigger a specific button in the browser to generate traffic.

**Parameters**:
- `index` (number): Button index to trigger
- `formValues` (object, optional): Form values to fill before triggering

### `test_sql_injection`
Test endpoint for SQL injection vulnerabilities.

**Parameters**:
- `url` (string): Target URL
- `method` (string): HTTP method (GET/POST)
- `params` (object): Parameters to inject payloads into

**Payloads**: `' OR '1'='1`, `' UNION SELECT NULL--`, etc.

### `test_xss`
Test endpoint for XSS vulnerabilities.

**Parameters**:
- `url` (string): Target URL
- `method` (string): HTTP method (GET/POST)
- `params` (object): Parameters to inject payloads into

**Payloads**: `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`, etc.

### `test_idor`
Test endpoint for IDOR by fuzzing ID parameters.

**Parameters**:
- `url` (string): Target URL with ID parameter
- `method` (string): HTTP method
- `idParam` (string): Name of ID parameter to fuzz

**Test Values**: `1`, `2`, `999`, `-1`, `admin`, etc.

### `test_command_injection`
Test endpoint for command injection vulnerabilities.

**Parameters**:
- `url` (string): Target URL
- `method` (string): HTTP method
- `params` (object): Parameters to inject payloads into

**Payloads**: `; ls`, `| whoami`, `` `id` ``, `$(cat /etc/passwd)`, etc.

## Environment Variables

- `HTTP_PORT`: Port for HTTP bridge server (default: 3100)
- `HTTP_PROXY`: Burp Suite proxy URL (default: http://127.0.0.1:8080)

## Security Notes

- All vulnerability test requests are proxied through Burp Suite for audit logging
- No test results are sent to external servers
- Attack surface data stays local (extension → MCP server → AI model)
- Designed for authorized penetration testing only

## Development

```bash
# Build TypeScript
npm run build

# Run in dev mode
npm run dev
```

## Workflow Example

1. User navigates to target site in browser
2. Extension scans page: detects React, finds login form with username/password fields, captures 3 API endpoints
3. Extension POSTs scan to MCP server at `/ghostcrawler/scan`
4. User asks Claude: "Test this page for vulnerabilities"
5. Claude calls `get_attack_surface`, receives full scan data
6. Claude analyzes: identifies `/api/login` POST endpoint with username/password params
7. Claude calls `test_sql_injection` with login endpoint
8. MCP server sends 8 SQL payloads through Burp proxy
9. Burp logs all requests in HTTP history
10. MCP server detects SQL error in one response
11. Claude reports: "SQL injection found in username parameter using payload: `' OR 1=1--`"
12. User reviews full request/response in Burp Suite

## License

MIT
