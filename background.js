// Background script for MCP command polling
(function () {
  const runtimeApi = globalThis.browser || globalThis.chrome;
  let pollLoopRunning = false;
  let commandPollInFlight = false;
  let pollEnabled = false;
  const SESSIONS_KEY = "ghostcrawlerSessions";

  const storageGet = (keys) => new Promise((resolve) => runtimeApi.storage.local.get(keys, resolve));

  const getRoleContextForTab = async (tab) => {
    try {
      const cookieStoreId = tab?.cookieStoreId || "firefox-default";
      const stored = await storageGet([SESSIONS_KEY]);
      const sessions = stored?.[SESSIONS_KEY] || {};
      const matched = sessions[cookieStoreId] || null;
      return {
        cookieStoreId,
        role: matched?.role ? String(matched.role) : "",
        containerName: matched?.containerName ? String(matched.containerName) : "",
      };
    } catch {
      return { cookieStoreId: tab?.cookieStoreId || "firefox-default", role: "", containerName: "" };
    }
  };

  const getTargetTabFromPayload = async (payload) => {
    if (payload?.tabId) {
      try {
        return await runtimeApi.tabs.get(Number(payload.tabId));
      } catch {}
    }

    const stored = await storageGet([SESSIONS_KEY]);
    const sessions = stored?.[SESSIONS_KEY] || {};
    let cookieStoreId = payload?.cookieStoreId ? String(payload.cookieStoreId) : "";

    if (!cookieStoreId && payload?.role) {
      const targetRole = String(payload.role).toLowerCase().trim();
      for (const [id, meta] of Object.entries(sessions)) {
        if (String(meta?.role || "").toLowerCase().trim() === targetRole) {
          cookieStoreId = id;
          break;
        }
      }
    }

    if (cookieStoreId) {
      try {
        const tabs = await runtimeApi.tabs.query({ currentWindow: true, cookieStoreId });
        const best = tabs.find((t) => t.active) || tabs[0];
        if (best?.id) return best;
      } catch {
        // cookieStoreId query unsupported on some browsers; fall back to active tab
      }
      return null;
    }

    const [activeTab] = await runtimeApi.tabs.query({ active: true, currentWindow: true });
    return activeTab;
  };

  // ── Wire-request capture (real browser traffic → MCP server) ──
  // Captures method, URL, headers (incl. Cookie), and body of every browser
  // request so the MCP server can build Burp Repeater tabs that exactly match
  // what the page actually sent (auth cookies, CSRF tokens, real Content-Type,
  // session headers, etc.).
  const wirePending = new Map(); // requestId -> { method, url, headers, body, ts }
  let wireServerUrl = "http://127.0.0.1:3200";
  const MAX_WIRE_BODY = 64 * 1024; // 64 KB cap to keep flush cheap

  const isControlChannel = (headers) => {
    if (!Array.isArray(headers)) return false;
    return headers.some(h => (h.name || "").toLowerCase() === "x-ghostcrawler-channel");
  };

  const isLocalMcpUrl = (url) => {
    try {
      const p = new URL(url);
      if (p.hostname === "127.0.0.1" || p.hostname === "localhost") {
        if (p.pathname.startsWith("/ghostcrawler/")) return true;
      }
    } catch {}
    return false;
  };

  const decodeRequestBody = (requestBody) => {
    if (!requestBody) return undefined;
    if (requestBody.raw && requestBody.raw.length) {
      try {
        const parts = requestBody.raw
          .filter(r => r && r.bytes)
          .map(r => new Uint8Array(r.bytes));
        const total = parts.reduce((n, p) => n + p.length, 0);
        const buf = new Uint8Array(Math.min(total, MAX_WIRE_BODY));
        let off = 0;
        for (const p of parts) {
          if (off >= buf.length) break;
          const slice = p.subarray(0, buf.length - off);
          buf.set(slice, off);
          off += slice.length;
        }
        return new TextDecoder("utf-8", { fatal: false }).decode(buf);
      } catch {
        return undefined;
      }
    }
    if (requestBody.formData) {
      try {
        const params = new URLSearchParams();
        for (const [k, arr] of Object.entries(requestBody.formData)) {
          (arr || []).forEach(v => params.append(k, String(v)));
        }
        return params.toString();
      } catch {
        return undefined;
      }
    }
    return undefined;
  };

  const flushWire = async (entry) => {
    if (!entry || !entry.url || isLocalMcpUrl(entry.url)) return;
    try {
      await fetch(`${wireServerUrl}/ghostcrawler/wire-request`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Ghostcrawler-Channel": "control",
        },
        body: JSON.stringify(entry),
        cache: "no-store",
      });
    } catch {
      // server may be down — best-effort capture
    }
  };

  const installWireCapture = () => {
    if (!runtimeApi.webRequest || installWireCapture._installed) return;
    try {
      runtimeApi.webRequest.onBeforeRequest.addListener(
        (details) => {
          if (isLocalMcpUrl(details.url)) return;
          wirePending.set(details.requestId, {
            method: details.method,
            url: details.url,
            headers: {},
            body: decodeRequestBody(details.requestBody),
            ts: Date.now(),
          });
        },
        { urls: ["<all_urls>"] },
        ["requestBody"]
      );
    } catch (e) {
      console.warn("[Ghostcrawler] onBeforeRequest wire capture disabled:", String(e?.message || e));
    }

    // Use extraHeaders on Chromium to include Cookie / Authorization.
    const extraOpts = ["requestHeaders"];
    try {
      if (runtimeApi.webRequest.OnSendHeadersOptions &&
          runtimeApi.webRequest.OnSendHeadersOptions.EXTRA_HEADERS) {
        extraOpts.push("extraHeaders");
      } else {
        // Chrome accepts the literal string too
        extraOpts.push("extraHeaders");
      }
    } catch {}

    const onSendHeadersHandler = (details) => {
      if (isLocalMcpUrl(details.url)) return;
      if (isControlChannel(details.requestHeaders)) return;
      const entry = wirePending.get(details.requestId) || {
        method: details.method,
        url: details.url,
        headers: {},
        ts: Date.now(),
      };
      for (const h of details.requestHeaders || []) {
        if (h.name && typeof h.value === "string") {
          entry.headers[h.name] = h.value;
        }
      }
      entry.method = details.method || entry.method;
      entry.url = details.url || entry.url;
      wirePending.set(details.requestId, entry);
      flushWire(entry);
    };

    try {
      runtimeApi.webRequest.onSendHeaders.addListener(
        onSendHeadersHandler,
        { urls: ["<all_urls>"] },
        extraOpts
      );
    } catch (e) {
      // Firefox may reject extraHeaders; fall back to requestHeaders only.
      try {
        runtimeApi.webRequest.onSendHeaders.addListener(
          onSendHeadersHandler,
          { urls: ["<all_urls>"] },
          ["requestHeaders"]
        );
      } catch (e2) {
        console.warn("[Ghostcrawler] onSendHeaders wire capture disabled:", String(e2?.message || e2));
      }
    }

    const cleanup = (details) => {
      wirePending.delete(details.requestId);
    };
    runtimeApi.webRequest.onCompleted.addListener(cleanup, { urls: ["<all_urls>"] });
    runtimeApi.webRequest.onErrorOccurred.addListener(cleanup, { urls: ["<all_urls>"] });
    installWireCapture._installed = true;
  };
  // ──────────────────────────────────────────────────────────────

  const isMcpEnabled = (value) => value !== false;

  const pollForCommands = async () => {
    const settings = await storageGet(["mcpEnabled", "mcpUrl"]);
    if (!isMcpEnabled(settings.mcpEnabled)) return;

    const configuredUrl = normalizeMcpBaseUrl(settings.mcpUrl || "");
    const candidates = buildFallbackUrls(configuredUrl || "http://127.0.0.1:3200");
    if (!candidates.length) return;

    try {
      if (commandPollInFlight) return;
      commandPollInFlight = true;
      let selectedUrl = "";
      let checkRes = null;
      const [activeTab] = await runtimeApi.tabs.query({ active: true, currentWindow: true });
      const roleCtx = await getRoleContextForTab(activeTab);
      const controlHeaders = {
        "X-Ghostcrawler-Channel": "control",
        ...(roleCtx.role ? { "X-Ghostcrawler-Role": roleCtx.role } : {}),
        ...(roleCtx.cookieStoreId ? { "X-Ghostcrawler-Cookie-Store": roleCtx.cookieStoreId } : {}),
        ...(roleCtx.containerName ? { "X-Ghostcrawler-Container": roleCtx.containerName } : {}),
      };
      for (const base of candidates) {
        try {
          const r = await fetchWithTimeout(`${base}/ghostcrawler/has-command`, {
            method: "GET",
            cache: "no-store",
            headers: controlHeaders,
          }, 5000);
          if (!r.ok && r.status !== 204) continue;
          selectedUrl = base;
          checkRes = r;
          break;
        } catch {
          // try the next fallback candidate
        }
      }
      if (!selectedUrl || !checkRes) return;
      wireServerUrl = selectedUrl;
      if (checkRes.status === 204) return; // nothing pending — stay quiet

      // Phase 2: command is ready — long-poll to get it immediately
      const response = await fetchWithTimeout(`${selectedUrl}/ghostcrawler/commands?waitMs=5000`, {
        method: "GET",
        headers: controlHeaders,
        cache: "no-store",
      }, 7000);

      if (!response.ok) return;

      const data = await response.json();
      if (!data.command) return;

      // Execute the command
      await executeCommand(data.command, selectedUrl);
    } catch (error) {
      console.warn("[Ghostcrawler] MCP polling error:", error.message);
    } finally {
      commandPollInFlight = false;
    }
  };

  const executeCommand = async (command, serverUrl) => {
    const { type, payload, commandId } = command;

    // Auto-start HUD push when the first scan command arrives so the in-page
    // overlay appears immediately without requiring a popup button click.
    // Also restarts the push interval if the service worker was previously killed
    // and revived by the keepalive alarm (hudPushInterval would be null).
    const hudTriggerTypes = new Set(["browser_action", "scan", "request", "trigger", "trigger_all", "trigger_button", "fill_form", "dom_observe_start", "hud-auth-choice", "hud-probe-pending", "hud-probe-result"]);
    if (hudTriggerTypes.has(type)) {
      if (!hudSessionActive || !hudPushInterval) {
        startHudPush(serverUrl);
      }
    }

    const sendMessageWithInject = async (tabId, msg) => {
      try {
        return await runtimeApi.tabs.sendMessage(tabId, msg);
      } catch (error) {
        const text = String(error?.message || error || "").toLowerCase();
        const needsInject =
          text.includes("receiving end does not exist") ||
          text.includes("could not establish connection") ||
          text.includes("message port closed");

        if (!needsInject) throw error;

        await runtimeApi.scripting.executeScript({
          target: { tabId },
          files: ["detector.js", "content.js"],
        });
        runtimeApi.scripting.executeScript({ target: { tabId }, world: "MAIN", files: ["net-observer.js"] }).catch(() => {});

        await new Promise((resolve) => setTimeout(resolve, 500));
        return runtimeApi.tabs.sendMessage(tabId, msg);
      }
    };

    try {
      // Get active tab
      const tab = await getTargetTabFromPayload(payload || {});
      if (!tab?.id) {
        throw new Error("No active tab");
      }

      let result;



      switch (type) {
        case "dom_observe_start":
          result = await sendMessageWithInject(tab.id, {
            type: "ghostcrawler:dom-observe-start",
            payload: payload || {}
          });
          break;

        case "dom_observe_get":
          result = await sendMessageWithInject(tab.id, {
            type: "ghostcrawler:dom-observe-get",
          });
          break;

        case "dom_observe_stop":
          result = await sendMessageWithInject(tab.id, {
            type: "ghostcrawler:dom-observe-stop",
          });
          break;

        case "browser_action":
          result = await sendMessageWithInject(tab.id, {
            type: "ghostcrawler:browser-action",
            payload: payload || {}
          });
          break;

        case "request":
          result = await sendMessageWithInject(tab.id, {
            type: "ghostcrawler:browser-action",
            payload: { ...(payload || {}), action: "request" }
          });
          break;

        case "trigger_button":
          result = await sendMessageWithInject(tab.id, {
            type: "ghostcrawler:trigger-one",
            index: payload.index,
            valuesMap: payload.formValues || {}
          });
          break;

        case "trigger":
        case "trigger_all":
          result = await sendMessageWithInject(tab.id, {
            type: "ghostcrawler:trigger",
            delayMs: payload.delayMs || 700,
            valuesMap: payload.formValues || {}
          });
          break;

        case "fill_form":
          result = await sendMessageWithInject(tab.id, {
            type: "ghostcrawler:fill",
            valuesMap: payload.valuesMap || {}
          });
          break;

        case "scan":
          result = await sendMessageWithInject(tab.id, {
            type: "ghostcrawler:scan"
          });
          break;

        case "get_url":
          result = { url: tab.url, title: tab.title };
          break;

        case "hud-auth-choice":
          result = await sendMessageWithInject(tab.id, {
            type: "ghostcrawler:hud-auth-choice",
            data: payload || {}
          });
          break;

        case "hud-probe-pending":
          result = await sendMessageWithInject(tab.id, {
            type: "ghostcrawler:hud-probe-pending",
            data: payload || {}
          });
          break;

        case "hud-probe-result":
          result = await sendMessageWithInject(tab.id, {
            type: "ghostcrawler:hud-probe-result",
            data: payload || {}
          });
          break;

        default:
          throw new Error(`Unknown command type: ${type}`);
      }

      // Send result back to MCP server
      await fetch(`${serverUrl}/ghostcrawler/result`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Ghostcrawler-Channel": "control",
        },
        body: JSON.stringify({
          commandId,
          success: true,
          result
        })
      });
    } catch (error) {
      // Send error back to MCP server
      await fetch(`${serverUrl}/ghostcrawler/result`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Ghostcrawler-Channel": "control",
        },
        body: JSON.stringify({
          commandId,
          success: false,
          error: error.message
        })
      }).catch(() => {});
    }
  };

  // ── HUD state push: background polls bridge, pushes to active tab ──
  let hudPushInterval = null;
  let lastHudPush = "";
  // Stays true from scan-start until extension reload or explicit HUD close,
  // so the HUD survives page navigations that happen after the scan completes.
  let hudSessionActive = false;

  const sendHudMessageWithInject = async (tabId, msg) => {
    try {
      return await runtimeApi.tabs.sendMessage(tabId, msg);
    } catch (error) {
      const text = String(error?.message || error || "").toLowerCase();
      const needsInject =
        text.includes("receiving end does not exist") ||
        text.includes("could not establish connection") ||
        text.includes("message port closed");

      if (!needsInject) throw error;

      await runtimeApi.scripting.executeScript({
        target: { tabId },
        files: ["detector.js", "content.js"],
      });
      runtimeApi.scripting.executeScript({ target: { tabId }, world: "MAIN", files: ["net-observer.js"] }).catch(() => {});

      await new Promise((resolve) => setTimeout(resolve, 500));
      return runtimeApi.tabs.sendMessage(tabId, msg);
    }
  };

  const pushHudToTab = async (serverUrl) => {
    try {
      const [tab] = await runtimeApi.tabs.query({ active: true, currentWindow: true });
      if (!tab?.id) return;
      const roleCtx = await getRoleContextForTab(tab);
      const resp = await fetch(`${serverUrl}/ghostcrawler/scan-progress`, {
        method: "GET",
        cache: "no-store",
        headers: {
          "X-Ghostcrawler-Channel": "control",
          ...(roleCtx.role ? { "X-Ghostcrawler-Role": roleCtx.role } : {}),
          ...(roleCtx.cookieStoreId ? { "X-Ghostcrawler-Cookie-Store": roleCtx.cookieStoreId } : {}),
          ...(roleCtx.containerName ? { "X-Ghostcrawler-Container": roleCtx.containerName } : {}),
        },
      });
      if (!resp.ok) return;
      const state = await resp.json();

      // Only push when state changed — EXCEPT during active scans/agent work where
      // the HUD may have been destroyed by a page navigation and needs reinjecting.
      const sig = `${state.status}|${state.progress}|${state.currentTest}|${(state.vulnerabilities||[]).length}|${(state.activityLog||[]).length}`;
      const alwaysPush = state.status === "scanning" || state.status === "captcha-waiting" || state.status === "agent-active";
      if (sig === lastHudPush && !alwaysPush) return;
      lastHudPush = sig;

      await sendHudMessageWithInject(tab.id, {
        type: "ghostcrawler:hud-push",
        state,
      });

      // Stop polling only when truly idle — not when the agent is still working.
      if (state.status === "idle") {
        if (hudPushInterval) {
          clearInterval(hudPushInterval);
          hudPushInterval = null;
        }
        stopHeartbeat();
      }
    } catch {
      // Keep quiet but ensure stale signatures don't prevent the next successful push.
      lastHudPush = "";
    }
  };

  const startHudPush = (serverUrl) => {
    if (hudPushInterval) clearInterval(hudPushInterval);
    lastHudPush = "";
    hudSessionActive = true;
    const url = (serverUrl || "http://127.0.0.1:3200").trim();
    hudPushInterval = setInterval(() => pushHudToTab(url), 2000);
    pushHudToTab(url);
    startHeartbeat(url);
  };

  // ── Heartbeat: prove the extension is alive every 2s so the server
  // can distinguish "scan command hung" from "extension disconnected".
  let heartbeatInterval = null;
  const startHeartbeat = (serverUrl) => {
    if (heartbeatInterval) clearInterval(heartbeatInterval);
    const send = async () => {
      try {
        await fetchWithTimeout(`${serverUrl}/ghostcrawler/heartbeat`, {
          method: "POST",
          cache: "no-store",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ts: Date.now(), ua: navigator.userAgent.slice(0, 80) }),
        }, 1500);
      } catch { /* server may be down — that's exactly what we want server-side to detect */ }
    };
    heartbeatInterval = setInterval(send, 2000);
    send();
  };
  const stopHeartbeat = () => {
    if (heartbeatInterval) { clearInterval(heartbeatInterval); heartbeatInterval = null; }
  };

  // Re-inject HUD on navigation so the live scan panel survives page changes
  // (SPA route changes, form submits, redirects after auth bypass, etc).
  if (runtimeApi.webNavigation && !globalThis.__ghostcrawlerNavHooked) {
    globalThis.__ghostcrawlerNavHooked = true;
    const reinjectHud = async (details) => {
      if (details.frameId !== 0) return; // only main frame
      if (!hudSessionActive) return;     // only while a HUD session is active (survives scan completion)
      try {
        await runtimeApi.scripting.executeScript({
          target: { tabId: details.tabId },
          files: ["detector.js", "content.js"],
        });
        runtimeApi.scripting.executeScript({ target: { tabId: details.tabId }, world: "MAIN", files: ["net-observer.js"] }).catch(() => {});
        lastHudPush = ""; // force re-push so HUD re-renders state
        // Push at 300ms, 700ms, and 1500ms — onCommitted fires before the DOM
        // is ready so a single short delay often races against the page parser.
        // The retries ensure the HUD survives slow pages and redirect chains.
        const url = wireServerUrl || "http://127.0.0.1:3200";
        setTimeout(() => pushHudToTab(url), 300);
        setTimeout(() => pushHudToTab(url), 700);
        setTimeout(() => pushHudToTab(url), 1500);
      } catch { /* tab may have been closed */ }
    };
    // onDOMContentLoaded fires once the DOM is parsed — safer for HUD injection
    // than onCommitted (which fires before document.body exists).
    try { runtimeApi.webNavigation.onDOMContentLoaded.addListener(reinjectHud); } catch {}
    try { runtimeApi.webNavigation.onHistoryStateUpdated.addListener(reinjectHud); } catch {}
  }
  // ────────────────────────────────────────────────────────────────────

  // Start command polling loop.
  // When idle: tiny /has-command check every 2s — completely silent in Burp.
  // When a command is pending: instantly fetches and executes it.
  const startPolling = () => {
    if (pollLoopRunning) return;
    pollEnabled = true;
    pollLoopRunning = true;
    try {
      installWireCapture();
    } catch (e) {
      console.warn("[Ghostcrawler] wire capture init failed; continuing polling:", String(e?.message || e));
    }

    // Keepalive alarm: wakes the service worker if Chrome kills it while MCP is on.
    // For unpacked extensions Chrome honours sub-minute periods; production is floored to 1 min.
    if (runtimeApi.alarms) {
      runtimeApi.alarms.create("ghostcrawler-keepalive", { periodInMinutes: 0.1 });
    }

    (async () => {
      while (pollEnabled) {
        try {
          await pollForCommands();
        } catch {}
        // 2 s gap keeps the extension responsive while generating no Burp noise at idle
        await new Promise((resolve) => setTimeout(resolve, 2000));
      }
      pollLoopRunning = false;
    })();
  };

  const stopPolling = () => {
    pollEnabled = false;
    if (runtimeApi.alarms) {
      runtimeApi.alarms.clear("ghostcrawler-keepalive");
    }
  };

  // Restart the polling loop whenever the alarm fires (service worker may have been killed).
  if (runtimeApi.alarms) {
    runtimeApi.alarms.onAlarm.addListener((alarm) => {
      if (alarm.name !== "ghostcrawler-keepalive") return;
      // If MCP was enabled but the loop stopped (service worker was killed), restart it.
      storageGet(["mcpEnabled"]).then((settings) => {
        if (isMcpEnabled(settings.mcpEnabled) && !pollLoopRunning) {
          pollLoopRunning = false; // reset so startPolling re-enters
          startPolling();
        }
      });
    });
  }

  const normalizeMcpBaseUrl = (value) => {
    const raw = String(value || "").trim();
    if (!raw) return "";
    const withScheme = /^https?:\/\//i.test(raw) ? raw : `http://${raw}`;
    return withScheme.replace(/\/+$/, "");
  };

  const buildFallbackUrls = (baseUrl) => {
    const urls = [baseUrl];
    try {
      const parsed = new URL(baseUrl);
      if (parsed.hostname === "127.0.0.1") {
        urls.push(baseUrl.replace("127.0.0.1", "localhost"));
      } else if (parsed.hostname === "localhost") {
        urls.push(baseUrl.replace("localhost", "127.0.0.1"));
      }
    } catch {}
    return [...new Set(urls)];
  };

  const fetchWithTimeout = async (url, options, timeoutMs = 6000) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      return await fetch(url, { ...options, signal: controller.signal });
    } finally {
      clearTimeout(timer);
    }
  };

  // Popup asks background to sync scan data to MCP bridge.
  runtimeApi.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message?.type === "ghostcrawler:get-role-context") {
      (async () => {
        try {
          const tab = sender?.tab?.id
            ? await runtimeApi.tabs.get(sender.tab.id)
            : (await runtimeApi.tabs.query({ active: true, currentWindow: true }))[0];
          const roleCtx = await getRoleContextForTab(tab);
          sendResponse({ ok: true, roleContext: roleCtx });
        } catch (error) {
          sendResponse({ ok: false, error: String(error?.message || error) });
        }
      })();
      return true;
    }

    // Content-script keepalive ping — wakes the service worker and restarts poll loop if needed.
    if (message?.type === "ghostcrawler:ping") {
      storageGet(["mcpEnabled"]).then((settings) => {
        if (isMcpEnabled(settings.mcpEnabled) && !pollLoopRunning) {
          startPolling();
        }
        // If a HUD session was active before the service worker was killed,
        // the push interval is gone. Restart it so the HUD stays live.
        if (hudSessionActive && !hudPushInterval) {
          startHudPush(wireServerUrl || "http://127.0.0.1:3200");
        }
      });
      sendResponse({ ok: true });
      return false;
    }

    // Panic STOP — relayed from in-page HUD button. Background can freely fetch localhost.
    if (message?.type === "ghostcrawler:stop-scan") {
      (async () => {
        try {
          const base = normalizeMcpBaseUrl(message.serverUrl) || wireServerUrl || "http://127.0.0.1:3200";
          const candidates = buildFallbackUrls(base);
          let stopped = false;
          for (const url of candidates) {
            try {
              const r = await fetchWithTimeout(`${url}/ghostcrawler/stop-scan`, {
                method: "POST",
                cache: "no-store",
                headers: { "Content-Type": "application/json", "X-Ghostcrawler-Channel": "control" },
                body: "{}",
              }, 4000);
              if (r.ok) { stopped = true; break; }
            } catch {}
          }
          sendResponse({ ok: stopped });
        } catch (error) {
          sendResponse({ ok: false, error: String(error?.message || error) });
        }
      })();
      return true;
    }

    // User clicked "Hide" in the HUD — stop re-injecting on navigation.
    if (message?.type === "ghostcrawler:hud-closed") {
      hudSessionActive = false;
      sendResponse({ ok: true });
      return false;
    }

    // Popup toggle button: show or hide the HUD on the active tab.
    if (message?.type === "ghostcrawler:toggle-hud") {
      (async () => {
        const [tab] = await runtimeApi.tabs.query({ active: true, currentWindow: true });
        if (!tab?.id) { sendResponse({ ok: false, hudActive: false }); return; }
        const url = message.serverUrl || "http://127.0.0.1:3200";
        if (hudSessionActive) {
          // Hide: clear session, stop push interval, tell content to close.
          hudSessionActive = false;
          if (hudPushInterval) { clearInterval(hudPushInterval); hudPushInterval = null; }
          runtimeApi.tabs.sendMessage(tab.id, { type: "ghostcrawler:hide-hud" }).catch(() => {});
          sendResponse({ ok: true, hudActive: false });
        } else {
          // Show: inject content script then start HUD push.
          try {
            await runtimeApi.scripting.executeScript({
              target: { tabId: tab.id },
              files: ["detector.js", "content.js"],
            });
            runtimeApi.scripting.executeScript({ target: { tabId: tab.id }, world: "MAIN", files: ["net-observer.js"] }).catch(() => {});
          } catch { /* already injected */ }
          startHudPush(url);
          await new Promise(r => setTimeout(r, 150));
          runtimeApi.tabs.sendMessage(tab.id, { type: "ghostcrawler:scan-live-start", serverUrl: url }).catch(() => {});
          sendResponse({ ok: true, hudActive: true });
        }
      })();
      return true; // async sendResponse
    }

    // Popup queries current HUD visibility state.
    if (message?.type === "ghostcrawler:hud-state") {
      sendResponse({ hudActive: hudSessionActive });
      return false;
    }


    if (message?.type === "ghostcrawler:send-to-burp") {
      (async () => {
        try {
          const base = normalizeMcpBaseUrl(message.serverUrl) || wireServerUrl || "http://127.0.0.1:3200";
          const candidates = buildFallbackUrls(base);
          let lastError = null;
          for (const url of candidates) {
            try {
              const r = await fetchWithTimeout(`${url}/ghostcrawler/send-to-burp`, {
                method: "POST",
                cache: "no-store",
                headers: { "Content-Type": "application/json", "X-Ghostcrawler-Channel": "control" },
                body: JSON.stringify({ finding: message.finding }),
              }, 6000);
              if (r.ok) { sendResponse({ ok: true }); return; }
              lastError = new Error(`HTTP ${r.status}`);
            } catch (e) { lastError = e; }
          }
          sendResponse({ ok: false, error: String(lastError?.message || lastError || "no MCP route") });
        } catch (e) {
          sendResponse({ ok: false, error: String(e?.message || e) });
        }
      })();
      return true;
    }

    if (message?.type !== "ghostcrawler:mcp-sync") return;

    (async () => {
      try {
        const serverUrl = normalizeMcpBaseUrl(message.serverUrl);
        if (!serverUrl) throw new Error("MCP URL is empty");

        const candidates = buildFallbackUrls(serverUrl);
        let lastError = null;

        for (const base of candidates) {
          try {
            const health = await fetchWithTimeout(`${base}/ghostcrawler/scan-progress`, {
              method: "GET",
              cache: "no-store",
              headers: { "X-Ghostcrawler-Channel": "control" },
            }, 4000);

            if (!health.ok) throw new Error(`health check returned ${health.status}`);

            const response = await fetchWithTimeout(`${base}/ghostcrawler/scan`, {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                "X-Ghostcrawler-Channel": "control",
              },
              body: JSON.stringify({
                timestamp: new Date().toISOString(),
                scan: message.scan,
              }),
            }, 8000);

            if (!response.ok) throw new Error(`sync returned ${response.status}`);

            sendResponse({ ok: true, serverUrl: base });
            return;
          } catch (error) {
            lastError = error;
          }
        }

        throw lastError || new Error("Failed to fetch");
      } catch (error) {
        sendResponse({ ok: false, error: String(error?.message || error) });
      }
    })();

    return true;
  });

  // Listen for settings changes
  runtimeApi.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes.mcpEnabled) {
      if (isMcpEnabled(changes.mcpEnabled.newValue)) {
        startPolling();
      } else {
        stopPolling();
        if (hudPushInterval) { clearInterval(hudPushInterval); hudPushInterval = null; }
        stopHeartbeat();
      }
    }
  });

  // Check initial state and start if enabled
  storageGet(["mcpEnabled", "mcpUrl"]).then((settings) => {
    if (settings.mcpUrl) wireServerUrl = settings.mcpUrl.trim();
    if (isMcpEnabled(settings.mcpEnabled)) {
      startPolling();
    }
  });

  // First-run auto-enable: when extension is installed, default mcpEnabled=true
  // and mcpUrl to localhost:3200 so user can run pentest_active_tab immediately.
  try {
    runtimeApi.runtime.onInstalled.addListener(async (details) => {
      try {
        const cur = await storageGet(["mcpEnabled", "mcpUrl"]);
        const patch = {};
        if (cur.mcpEnabled === undefined) patch.mcpEnabled = true;
        if (!cur.mcpUrl) patch.mcpUrl = "http://127.0.0.1:3200";
        if (Object.keys(patch).length) {
          await new Promise((r) => runtimeApi.storage.local.set(patch, r));
          console.log("[GhostCrawler] First-run defaults applied:", patch);
        }
        if (details.reason === "install" || details.reason === "update") {
          // Kick polling immediately
          if ((patch.mcpEnabled ?? cur.mcpEnabled) && !pollLoopRunning) {
            if (patch.mcpUrl) wireServerUrl = patch.mcpUrl;
            startPolling();
          }
        }
      } catch (e) {
        console.warn("[GhostCrawler] onInstalled handler failed:", e);
      }
    });
  } catch { /* not in extension context */ }
})();
