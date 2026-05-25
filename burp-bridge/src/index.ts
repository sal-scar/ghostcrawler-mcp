#!/usr/bin/env node
/**
 * GhostCrawler Burp Bridge
 *
 * Persistent daemon that owns the single SSE connection to Burp Suite MCP
 * (default :9876) and exposes a tiny local HTTP API for the MCP server
 * to call into. This daemon stays alive across MCP server restarts so
 * Burp never sees a client disconnect — which is what causes Burp's
 * MCP extension to crash the entire JVM.
 *
 * Endpoints (default :3201):
 *   GET  /health           - { ok, connected, burpUrl, pid }
 *   GET  /tools            - { ok, tools: string[], details: ToolDef[] }
 *   POST /call             - body: { name, arguments } -> { ok, result } | { ok:false, error }
 *   POST /reconnect        - force-drop the current client and reconnect
 *   POST /shutdown         - graceful exit (used by tests; not by MCP server)
 */
import express from "express";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";

const BURP_MCP_URL = process.env.BURP_MCP_URL || "http://127.0.0.1:9876";
const BRIDGE_PORT = Number(process.env.BRIDGE_PORT || 3201);
// Per-call timeout. If a Burp MCP tool call doesn't respond within this window
// we assume the SSE channel is half-dead (TCP open, stream stalled) and force
// a reconnect on the next request. 20s is well above any legitimate Burp tool
// latency but short enough that a wedged scan recovers quickly.
const CALL_TIMEOUT_MS = Number(process.env.BRIDGE_CALL_TIMEOUT_MS || 20000);
// Background heartbeat probes Burp with a cheap built-in tool to detect a
// silently-dead SSE stream (the failure mode where /health says "connected"
// but every real call hangs forever).
const HEARTBEAT_INTERVAL_MS = Number(process.env.BRIDGE_HEARTBEAT_MS || 30000);
const HEARTBEAT_TIMEOUT_MS = Number(process.env.BRIDGE_HEARTBEAT_TIMEOUT_MS || 5000);
// Cheap, side-effect-free Burp MCP tool used for the heartbeat. Falls back to
// listTools if this tool is not advertised.
const HEARTBEAT_TOOL = process.env.BRIDGE_HEARTBEAT_TOOL || "url_encode";

// Ensure EventSource is available globally for the SDK's SSE transport.
async function ensureEventSource(): Promise<void> {
  if (typeof (globalThis as any).EventSource === "undefined") {
    const mod: any = await import("eventsource");
    (globalThis as any).EventSource = mod.EventSource ?? mod.default;
  }
}

let client: any = null;
let connectPromise: Promise<any> | null = null;
let toolsCache: any[] = [];
let lastConnectAt: number = 0;
let lastError: string | null = null;
let lastHeartbeatAt: number = 0;
let lastHeartbeatOk: boolean = false;
let lastHeartbeatError: string | null = null;
let heartbeatInFlight: boolean = false;

/**
 * Race a promise against a timeout. On timeout we reject with a tagged error
 * AND invalidate the client so the next request reconnects. The original
 * promise is intentionally orphaned — we cannot cancel an in-flight MCP
 * request, and calling client.close() would crash Burp's JVM.
 */
function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      const err: any = new Error(`${label} timed out after ${ms}ms (SSE likely stalled)`);
      err.code = "BRIDGE_TIMEOUT";
      reject(err);
    }, ms);
    p.then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      (e) => {
        clearTimeout(timer);
        reject(e);
      }
    );
  });
}

async function connect(): Promise<any> {
  if (client) return client;
  if (connectPromise) return connectPromise;

  connectPromise = (async () => {
    await ensureEventSource();
    const c = new Client({ name: "ghostcrawler-burp-bridge", version: "0.1.0" }, { capabilities: {} });
    const transport = new SSEClientTransport(new URL(BURP_MCP_URL));
    await c.connect(transport);
    client = c;
    lastConnectAt = Date.now();
    lastError = null;
    console.error(`[BurpBridge] Connected to Burp MCP at ${BURP_MCP_URL}`);
    // Pre-cache tools list so /tools doesn't hit Burp on every call
    try {
      const res: any = await c.listTools();
      toolsCache = res?.tools ?? [];
      console.error(`[BurpBridge] Discovered ${toolsCache.length} tool(s)`);
    } catch (err: any) {
      console.error(`[BurpBridge] listTools failed: ${err?.message ?? err}`);
    }
    return c;
  })().catch((err: any) => {
    connectPromise = null;
    lastError = String(err?.message ?? err);
    throw err;
  });

  return connectPromise.then((c) => {
    connectPromise = null;
    return c;
  });
}

/**
 * Drop the in-process client reference WITHOUT calling .close().
 * Calling .close() sends a clean MCP disconnect to Burp, which is
 * what makes Burp shut itself down. We just orphan the reference;
 * the underlying SSE transport will eventually time out if Burp is
 * actually gone, but in the common case Burp stays up.
 */
function invalidate(): void {
  client = null;
  connectPromise = null;
}

const app = express();
app.use(express.json({ limit: "20mb" }));

app.get("/health", async (req, res) => {
  const base = {
    ok: true,
    connected: !!client,
    burpUrl: BURP_MCP_URL,
    pid: process.pid,
    uptimeSec: Math.floor(process.uptime()),
    lastConnectAt,
    lastError,
    toolsCached: toolsCache.length,
    lastHeartbeatAt,
    lastHeartbeatOk,
    lastHeartbeatError,
  };
  // ?deep=1 runs an inline heartbeat probe so callers can verify the SSE
  // channel is actually round-tripping, not just TCP-open. This is the real
  // healthcheck — the cheap default only reflects last cached state.
  if (req.query.deep === "1" || req.query.deep === "true") {
    const probe = await runHeartbeat();
    return res.json({ ...base, deep: probe });
  }
  res.json(base);
});

app.get("/tools", async (_req, res) => {
  try {
    const c = await connect();
    if (!toolsCache.length) {
      const r: any = await withTimeout(c.listTools(), CALL_TIMEOUT_MS, "listTools");
      toolsCache = r?.tools ?? [];
    }
    res.json({
      ok: true,
      tools: toolsCache.map((t: any) => t.name),
      details: toolsCache,
    });
  } catch (err: any) {
    invalidate();
    res.status(502).json({ ok: false, error: String(err?.message ?? err) });
  }
});

app.post("/call", async (req, res) => {
  const name = req.body?.name;
  const args = req.body?.arguments ?? {};
  if (!name || typeof name !== "string") {
    return res.status(400).json({ ok: false, error: "missing 'name'" });
  }
  try {
    const c = await connect();
    const result = await withTimeout(
      c.callTool({ name, arguments: args }),
      CALL_TIMEOUT_MS,
      `callTool(${name})`
    );
    return res.json({ ok: true, result });
  } catch (err: any) {
    const msg = String(err?.message ?? err);
    // On transport errors OR our own timeout, invalidate so the next call
    // reconnects. Do NOT call .close() — that crashes Burp.
    if (err?.code === "BRIDGE_TIMEOUT" || /failed to fetch|econnrefused|econnreset|network error|sse/i.test(msg)) {
      invalidate();
    }
    return res.status(502).json({ ok: false, error: msg });
  }
});

/**
 * Active heartbeat: round-trip a cheap, idempotent tool through the SSE
 * channel. Detects the silent-stall failure mode where TCP stays open but
 * the JSON-RPC stream is dead. On failure we invalidate the client so the
 * next request (or the next heartbeat) re-establishes a fresh SSE.
 */
async function runHeartbeat(): Promise<{ ok: boolean; ms: number; via: string; error: string | null }> {
  if (heartbeatInFlight) {
    return { ok: lastHeartbeatOk, ms: 0, via: "skipped-inflight", error: lastHeartbeatError };
  }
  heartbeatInFlight = true;
  const started = Date.now();
  let via = HEARTBEAT_TOOL;
  try {
    const c = await connect();
    const toolNames = toolsCache.map((t: any) => t.name);
    const useTool = toolNames.includes(HEARTBEAT_TOOL) ? HEARTBEAT_TOOL : null;
    if (useTool) {
      await withTimeout(
        c.callTool({ name: useTool, arguments: { text: "gc-heartbeat" } }),
        HEARTBEAT_TIMEOUT_MS,
        `heartbeat(${useTool})`
      );
    } else {
      // Fallback: listTools is always available and exercises the same channel.
      via = "listTools";
      await withTimeout(c.listTools(), HEARTBEAT_TIMEOUT_MS, "heartbeat(listTools)");
    }
    const ms = Date.now() - started;
    lastHeartbeatAt = Date.now();
    lastHeartbeatOk = true;
    lastHeartbeatError = null;
    return { ok: true, ms, via, error: null };
  } catch (err: any) {
    const ms = Date.now() - started;
    const msg = String(err?.message ?? err);
    lastHeartbeatAt = Date.now();
    lastHeartbeatOk = false;
    lastHeartbeatError = msg;
    // Stalled channel — drop the reference so next /call gets a fresh SSE.
    // Never .close() (would crash Burp).
    invalidate();
    console.error(`[BurpBridge] Heartbeat failed (${via}, ${ms}ms): ${msg} — invalidated client for reconnect.`);
    return { ok: false, ms, via, error: msg };
  } finally {
    heartbeatInFlight = false;
  }
}

function startHeartbeatLoop(): void {
  if (HEARTBEAT_INTERVAL_MS <= 0) {
    console.error(`[BurpBridge] Heartbeat disabled (BRIDGE_HEARTBEAT_MS=${HEARTBEAT_INTERVAL_MS}).`);
    return;
  }
  const tick = () => {
    runHeartbeat().catch(() => {/* errors already logged */});
  };
  // Fire once shortly after startup, then on interval.
  setTimeout(tick, Math.min(5000, HEARTBEAT_INTERVAL_MS));
  const handle = setInterval(tick, HEARTBEAT_INTERVAL_MS);
  // Don't let the heartbeat keep the event loop alive on its own.
  if (typeof handle.unref === "function") handle.unref();
  console.error(`[BurpBridge] Heartbeat scheduled every ${HEARTBEAT_INTERVAL_MS}ms (timeout ${HEARTBEAT_TIMEOUT_MS}ms, tool ${HEARTBEAT_TOOL}).`);
}

app.post("/reconnect", async (_req, res) => {
  invalidate();
  try {
    await connect();
    res.json({ ok: true, connected: !!client });
  } catch (err: any) {
    res.status(502).json({ ok: false, error: String(err?.message ?? err) });
  }
});

app.post("/shutdown", (_req, res) => {
  res.json({ ok: true });
  setTimeout(() => process.exit(0), 100);
});

/**
 * Self-healing port bind: if 3201 is held by an old bridge instance,
 * politely ask it to shut down via /shutdown, then bind. This keeps the
 * "one bridge process" invariant without resorting to kill -9.
 */
async function startBridge(): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const srv = app.listen(BRIDGE_PORT, "127.0.0.1", () => {
      console.error(`[BurpBridge] Listening on http://127.0.0.1:${BRIDGE_PORT}  (pid=${process.pid})`);
      resolve();
    });
    srv.on("error", (err: any) => {
      if (err?.code === "EADDRINUSE") {
        // An existing bridge process already owns this port AND the Burp SSE connection.
        // Exit this new instance silently — killing the existing bridge would drop the
        // SSE connection and crash Burp. The spawner will detect the healthy bridge.
        console.error(`[BurpBridge] Port ${BRIDGE_PORT} already bound — existing bridge is running. Exiting this instance.`);
        process.exit(0);
      } else {
        reject(err);
      }
    });
  });

  // Try an initial connect so /health reports `connected: true` quickly.
  // Failure here is non-fatal — Burp may not be up yet.
  connect().catch((err) => {
    console.error(`[BurpBridge] Initial connect failed (will retry on first /call): ${err?.message ?? err}`);
  });

  // Start the active heartbeat so silent SSE stalls are detected and recovered
  // even when no client is currently using the bridge.
  startHeartbeatLoop();
}

// Never crash on unexpected errors — bridge availability matters more than strictness.
process.on("uncaughtException", (err) =>
  console.error(`[BurpBridge] uncaughtException (continuing): ${err.message}`)
);
process.on("unhandledRejection", (reason) =>
  console.error(`[BurpBridge] unhandledRejection (continuing): ${reason}`)
);

// CRITICAL: The bridge's ONLY job is to keep the Burp SSE connection alive.
// It must NEVER exit due to OS signals — even SIGTERM from VS Code restarting
// the MCP server. process.exit() drops the SSE socket → Burp crashes.
// The only intentional shutdown path is the /shutdown HTTP endpoint.
process.on("SIGTERM", () =>
  console.error("[BurpBridge] SIGTERM received — ignoring to keep Burp SSE alive.")
);
process.on("SIGINT", () =>
  console.error("[BurpBridge] SIGINT received — ignoring to keep Burp SSE alive.")
);
// SIGHUP fires when the parent shell (bash -c wrapper) exits in non-interactive mode.
process.on("SIGHUP", () =>
  console.error("[BurpBridge] SIGHUP received — ignoring to keep Burp SSE alive.")
);
// Log exit cause so users can diagnose unexpected bridge deaths.
process.on("exit", (code) =>
  console.error(`[BurpBridge] Exiting with code ${code} — if unexpected, check for SIGKILL or fatal error above.`)
);

startBridge().catch((err) => {
  console.error(`[BurpBridge] Fatal: ${err?.message ?? err}`);
  process.exit(1);
});
