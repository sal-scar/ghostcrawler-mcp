(function () {
  const runtimeApi = globalThis.browser || globalThis.chrome;

  const storageGet = (keys) => new Promise((resolve) => runtimeApi.storage.local.get(keys, resolve));
  const storageSet = (value) => new Promise((resolve) => runtimeApi.storage.local.set(value, resolve));

  // Guard: skip expensive re-initialization (fetch/XHR hooks, timers) if already
  // injected into this page. Message listeners are always re-registered so the
  // extension can communicate with a freshly re-injected instance.
  const alreadyLoaded = !!window.__ghostcrawlerContentLoaded;
  window.__ghostcrawlerContentLoaded = true;

  // ── In-Page Live Scan HUD ─────────────────────────────────────────
  let hudRoot = null;
  let hudPollInterval = null;
  let hudServerUrl = "http://127.0.0.1:3200";
  let hudLog = [];
  let hudLastSignature = "";
  let hudPersistObserver = null;
  let hudLastState = null;
  let hudActive = false;

  let domObserver = null;
  let domObserverEvents = [];
  let domObserverStartedAt = null;

  const ensureHud = () => {
    if (hudRoot && document.body.contains(hudRoot)) {
      return hudRoot;
    }

    // Inject pulse animation keyframes once
    if (!document.getElementById("ghostcrawler-hud-style")) {
      const style = document.createElement("style");
      style.id = "ghostcrawler-hud-style";
      style.textContent = "@keyframes ghostcrawler-pulse{0%{box-shadow:0 0 0 0 rgba(239,68,68,0.55)}70%{box-shadow:0 0 0 8px rgba(239,68,68,0)}100%{box-shadow:0 0 0 0 rgba(239,68,68,0)}}";
      (document.head || document.documentElement).appendChild(style);
    }

    hudRoot = document.createElement("div");
    hudRoot.id = "ghostcrawler-live-hud";
    hudRoot.style.cssText = [
      "position:fixed",
      "top:16px",
      "right:16px",
      "z-index:2147483647",
      "width:360px",
      "max-height:70vh",
      "overflow:auto",
      "padding:12px",
      "border-radius:12px",
      "background:rgba(16,18,20,0.95)",
      "color:#e8eef2",
      "font:12px/1.4 -apple-system,BlinkMacSystemFont,Segoe UI,Helvetica,Arial,sans-serif",
      "box-shadow:0 10px 28px rgba(0,0,0,0.45)",
      "border:1px solid rgba(140,180,255,0.25)",
    ].join(";");

    hudRoot.innerHTML = [
      '<div style="display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:8px;">',
      '<strong style="font-size:13px;letter-spacing:0.2px;">🕷 Ghostcrawler</strong>',
      '<div style="display:flex;gap:6px;">',
      '<button id="ghostcrawler-hud-stop" title="STOP all scanning and attacks immediately" style="border:1px solid #ef4444;background:#dc2626;color:#fff;border-radius:8px;padding:3px 10px;cursor:pointer;font-weight:700;font-size:11px;letter-spacing:0.3px;box-shadow:0 0 0 0 rgba(239,68,68,0.4);animation:ghostcrawler-pulse 2s infinite;">⏹ STOP</button>',
      '<button id="ghostcrawler-hud-help" title="Quick Reference" style="border:1px solid rgba(255,255,255,0.15);background:rgba(255,255,255,0.06);color:#94a3b8;border-radius:8px;padding:2px 8px;cursor:pointer;font-size:12px;">?</button>',
      '<button id="ghostcrawler-hud-close" style="border:0;background:#2f3942;color:#e8eef2;border-radius:8px;padding:3px 8px;cursor:pointer;">Hide</button>',
      '</div>',
      "</div>",
      '<div id="ghostcrawler-hud-help-panel" style="display:none;margin-bottom:10px;padding:10px;background:rgba(0,0,0,0.3);border-radius:8px;border:1px solid rgba(255,255,255,0.08);font-size:11px;color:#94a3b8;line-height:1.7;">',
      '<div style="color:#e8eef2;font-weight:600;margin-bottom:4px;">Scan phases:</div>',
      '<div style="display:flex;flex-wrap:wrap;gap:4px;">',
      '<span style="padding:1px 6px;border-radius:10px;background:#a78bfa22;color:#a78bfa;border:1px solid #a78bfa33;font-size:10px;">source-review</span>',
      '<span style="padding:1px 6px;border-radius:10px;background:#60a5fa22;color:#60a5fa;border:1px solid #60a5fa33;font-size:10px;">fingerprint</span>',
      '<span style="padding:1px 6px;border-radius:10px;background:#34d39922;color:#34d399;border:1px solid #34d39933;font-size:10px;">crawl</span>',
      '<span style="padding:1px 6px;border-radius:10px;background:#fbbf2422;color:#fbbf24;border:1px solid #fbbf2433;font-size:10px;">auth-check</span>',
      '<span style="padding:1px 6px;border-radius:10px;background:#f8717122;color:#f87171;border:1px solid #f8717133;font-size:10px;">attack</span>',
      '<span style="padding:1px 6px;border-radius:10px;background:#94a3b822;color:#94a3b8;border:1px solid #94a3b833;font-size:10px;">passive-checks</span>',
      '<span style="padding:1px 6px;border-radius:10px;background:#4ade8022;color:#4ade80;border:1px solid #4ade8033;font-size:10px;">complete</span>',
      '</div>',
      '</div>',
      '<div id="ghostcrawler-hud-status">Initializing...</div>',
    ].join("");

    const closeButton = hudRoot.querySelector("#ghostcrawler-hud-close");
    if (closeButton) {
      closeButton.addEventListener("click", () => {
        hudActive = false;
        stopHudPolling();
        hudRoot?.remove();
        hudRoot = null;
        // Tell background to clear hudSessionActive so the HUD won't re-inject on navigation
        try { runtimeApi.runtime.sendMessage({ type: "ghostcrawler:hud-closed" }); } catch {}
      });
    }

    // Delegated click handler for "→ Burp" buttons (renderHud rewrites innerHTML
    // every push, so direct listeners on findings would be lost).
    hudRoot.addEventListener("click", (e) => {
      const btn = e.target && e.target.closest && e.target.closest(".ghostcrawler-send-burp");
      if (!btn) return;
      e.preventDefault();
      e.stopPropagation();
      const raw = btn.getAttribute("data-finding") || "";
      let finding = null;
      try { finding = JSON.parse(decodeURIComponent(raw)); } catch { return; }
      const prev = btn.textContent;
      btn.disabled = true;
      btn.textContent = "Sending…";
      try {
        runtimeApi.runtime.sendMessage(
          { type: "ghostcrawler:send-to-burp", serverUrl: hudServerUrl, finding },
          (response) => {
            btn.disabled = false;
            if (response && response.ok) {
              btn.textContent = "✓ Burp";
              btn.style.background = "#166534";
              btn.style.borderColor = "#4ade80";
              btn.style.color = "#bbf7d0";
            } else {
              btn.textContent = "✗ Failed";
              setTimeout(() => { btn.textContent = prev; }, 2000);
            }
          }
        );
      } catch {
        btn.disabled = false;
        btn.textContent = prev;
      }
    });

    const stopButton = hudRoot.querySelector("#ghostcrawler-hud-stop");
    if (stopButton) {
      let stopArmed = false;
      let stopArmTimer = null;
      stopButton.addEventListener("click", async () => {
        // Two-click confirmation: first click arms, second click within 3s sends.
        if (!stopArmed) {
          stopArmed = true;
          const prevText = stopButton.textContent;
          const prevBg = stopButton.style.background;
          stopButton.textContent = "⚠ Click again to STOP";
          stopButton.style.background = "#b45309";
          stopButton.style.animation = "none";
          if (stopArmTimer) clearTimeout(stopArmTimer);
          stopArmTimer = setTimeout(() => {
            stopArmed = false;
            stopButton.textContent = prevText;
            stopButton.style.background = prevBg || "#dc2626";
            stopButton.style.animation = "ghostcrawler-pulse 2s infinite";
          }, 3000);
          return;
        }
        if (stopArmTimer) { clearTimeout(stopArmTimer); stopArmTimer = null; }
        stopArmed = false;
        const prevText = stopButton.textContent;
        stopButton.disabled = true;
        stopButton.textContent = "Stopping…";
        stopButton.style.opacity = "0.7";
        try {
          // Send via runtime to background.js (content scripts cannot fetch localhost reliably under CORS)
          await new Promise((resolve) => {
            try {
              runtimeApi.runtime.sendMessage(
                { type: "ghostcrawler:stop-scan", serverUrl: hudServerUrl },
                (response) => resolve(response)
              );
            } catch { resolve(null); }
          });
          stopButton.textContent = "⏹ STOPPED";
          stopButton.style.background = "#7f1d1d";
          stopButton.style.animation = "none";
        } catch (e) {
          stopButton.textContent = "⚠ Failed";
        } finally {
          setTimeout(() => {
            stopButton.disabled = false;
            stopButton.textContent = prevText;
            stopButton.style.opacity = "1";
            stopButton.style.background = "#dc2626";
            stopButton.style.animation = "ghostcrawler-pulse 2s infinite";
          }, 4000);
        }
      });
    }

    const helpButton = hudRoot.querySelector("#ghostcrawler-hud-help");
    const helpPanel = hudRoot.querySelector("#ghostcrawler-hud-help-panel");
    if (helpButton && helpPanel) {
      helpButton.addEventListener("click", () => {
        const open = helpPanel.style.display !== "none";
        helpPanel.style.display = open ? "none" : "block";
        helpButton.style.color = open ? "#94a3b8" : "#06b6d4";
        helpButton.style.borderColor = open ? "rgba(255,255,255,0.15)" : "rgba(6,182,212,0.4)";
      });
    }

    document.body.appendChild(hudRoot);
    return hudRoot;
  };

  const renderHud = (state) => {
    const root = ensureHud();
    const statusEl = root.querySelector("#ghostcrawler-hud-status");
    if (!statusEl) return;
    hudLastState = state;

    const severityColor = (sev) => {
      if (sev === "Critical") return "#ff6b6b";
      if (sev === "High") return "#ff9f43";
      if (sev === "Medium") return "#feca57";
      return "#54a0ff";
    };

    const phaseLabel = (phase) => {
      const map = {
        "source-review": ["Source Review", "#a78bfa"],
        "fingerprint":   ["Fingerprinting", "#60a5fa"],
        "crawl":         ["Crawling", "#34d399"],
        "auth-check":    ["Auth Check", "#fbbf24"],
        "attack":        ["Attacking", "#f87171"],
        "passive-checks":["Passive Checks", "#94a3b8"],
        "complete":      ["Complete", "#4ade80"],
      };
      return map[phase] || [phase || "idle", "#94a3b8"];
    };

    const [phaseName, phaseColor] = phaseLabel(state?.phase);

    const vulnerabilities = Array.isArray(state?.vulnerabilities) ? state.vulnerabilities : [];
    const recent = vulnerabilities.slice(-5).reverse();

    // Use activityLog from server if available, otherwise fall back to local hudLog
    const serverLog = Array.isArray(state?.activityLog) ? state.activityLog : [];
    const events = serverLog.length ? serverLog.slice(-8).reverse() : hudLog.slice(-8).reverse();

    statusEl.innerHTML = [
      // Phase badge
      `<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">`,
      `  <span style="display:inline-block;padding:2px 10px;border-radius:20px;font-size:11px;font-weight:700;background:${phaseColor}22;color:${phaseColor};border:1px solid ${phaseColor}44;">${phaseName}</span>`,
      `  <span style="opacity:0.7;font-size:11px;">${state?.status || "unknown"}</span>`,
      `</div>`,
      // Current test
      `<div style="margin-bottom:6px;font-size:11px;opacity:0.85;">${state?.currentTest || "waiting"}</div>`,
      // Reasoning box (if set)
      state?.reasoning
        ? `<div style="margin-bottom:8px;padding:6px 8px;border-radius:6px;background:#1e2d20;border-left:3px solid #4ade80;font-size:11px;color:#86efac;">${state.reasoning}</div>`
        : "",
      // Progress bar
      `<div style="height:6px;background:#2a3138;border-radius:6px;overflow:hidden;margin-bottom:8px;">`,
      `  <div style="height:100%;width:${Math.max(0, Math.min(100, state?.progress ?? 0))}%;background:linear-gradient(90deg,#2dd4bf,#3b82f6);transition:width 0.4s;"></div>`,
      `</div>`,
      `<div style="font-size:11px;opacity:0.7;margin-bottom:10px;">${state?.progress ?? 0}% — ${state?.completedTests ?? 0}/${state?.totalTests ?? 0} tests — ${vulnerabilities.length} finding(s)</div>`,
      // Findings
      `<div style="font-weight:600;margin-bottom:6px;">Latest Findings</div>`,
      recent.length
        ? recent.map((v, idx) => {
            const payloadEnc = encodeURIComponent(JSON.stringify(v));
            return `<div style="margin-bottom:6px;padding:7px 8px;border-radius:8px;background:#1f252b;border:1px solid rgba(255,255,255,0.08);">` +
            `<div style="display:flex;justify-content:space-between;align-items:center;gap:6px;">` +
              `<div><span style="color:${severityColor(v.severity)};font-weight:700;">${v.severity}</span> — ${v.type}</div>` +
              `<button class="ghostcrawler-send-burp" data-finding="${payloadEnc}" title="Send to Burp Repeater" style="border:1px solid #fb923c;background:#9a3412;color:#fed7aa;border-radius:6px;padding:1px 6px;cursor:pointer;font-size:10px;font-weight:600;">→ Burp</button>` +
            `</div>` +
            `<div style="opacity:0.8;word-break:break-all;font-size:11px;">${v.endpoint}</div>` +
            `</div>`;
          }).join("")
        : '<div style="opacity:0.6;font-size:11px;">No findings yet</div>',
      // Activity log
      `<div style="font-weight:600;margin:10px 0 6px;">Live Activity</div>`,
      events.length
        ? events.map((entry) => {
            const msg = typeof entry === "object" ? entry.msg || JSON.stringify(entry) : String(entry);
            const ts  = typeof entry === "object" && entry.ts ? `<span style="opacity:0.45;margin-right:4px;">${new Date(entry.ts).toLocaleTimeString()}</span>` : "";
            return `<div style="opacity:0.9;margin-bottom:3px;font-size:11px;">${ts}${msg}</div>`;
          }).join("")
        : '<div style="opacity:0.6;font-size:11px;">Waiting for scan events</div>',
      // Export button (shown when scan is complete)
      (state?.status === "completed" || state?.progress >= 100)
        ? `<div style="margin-top:12px;"><a href="http://127.0.0.1:3200/ghostcrawler/export-findings?format=markdown" target="_blank" download="ghostcrawler-report.md" style="display:inline-block;padding:6px 14px;background:#1e3a2f;border:1px solid #4ade80;color:#4ade80;border-radius:6px;font-size:12px;font-weight:600;text-decoration:none;">📋 Export Report</a><a href="http://127.0.0.1:3200/ghostcrawler/export-findings?format=json" target="_blank" download="ghostcrawler-report.json" style="display:inline-block;margin-left:8px;padding:6px 14px;background:#1e2d3a;border:1px solid #60a5fa;color:#60a5fa;border-radius:6px;font-size:12px;font-weight:600;text-decoration:none;">📦 JSON</a></div>`
        : "",
    ].join("");
  };

  const stopHudPolling = () => {
    if (hudPollInterval) {
      clearInterval(hudPollInterval);
      hudPollInterval = null;
    }
  };

  // HUD state is now PUSHED by background.js (which can freely fetch localhost).
  // startHudPolling just shows the HUD and waits for ghostcrawler:hud-push messages.
  const startHudPolling = (serverUrl) => {
    hudServerUrl = (serverUrl || "http://127.0.0.1:3200").trim();
    hudLog = [];
    hudLastSignature = "";
    hudActive = true;
    ensureHud();
    ensureHudPersistence();
    renderHud({ status: "active", currentTest: "Waiting for agent...", progress: 0, vulnerabilities: [] });
  };

  // ── Persistent HUD: re-mount within ~100ms if removed by page scripts,
  // SPA route changes, or React re-renders that wipe document.body.
  const ensureHudPersistence = () => {
    if (hudPersistObserver) return;
    try {
      hudPersistObserver = new MutationObserver(() => {
        if (!hudActive) return;
        if (!hudRoot || !document.body || !document.body.contains(hudRoot)) {
          hudRoot = null;
          ensureHud();
          if (hudLastState) renderHud(hudLastState);
        }
      });
      const start = () => {
        if (!document.body) { setTimeout(start, 50); return; }
        try { hudPersistObserver.observe(document.body, { childList: true, subtree: false }); } catch {}
        try { hudPersistObserver.observe(document.documentElement, { childList: true, subtree: false }); } catch {}
      };
      start();
    } catch { /* MutationObserver unavailable */ }

    // Hook history API to detect SPA navigation; re-render so the HUD
    // doesn't show stale state during route transitions.
    if (!window.__ghostcrawlerHistoryHooked) {
      window.__ghostcrawlerHistoryHooked = true;
      const fire = () => {
        if (!hudActive) return;
        setTimeout(() => {
          ensureHud();
          if (hudLastState) renderHud(hudLastState);
        }, 50);
      };
      const wrap = (name) => {
        const orig = history[name];
        if (typeof orig !== "function") return;
        history[name] = function () {
          const r = orig.apply(this, arguments);
          fire();
          return r;
        };
      };
      try { wrap("pushState"); wrap("replaceState"); } catch {}
      try { window.addEventListener("popstate", fire); } catch {}
    }
  };

  // Render an auth-choice prompt inside the HUD overlay.
  const showAuthChoicePrompt = (data) => {
    const root = ensureHud();
    if (!root) return;
    // Remove any existing choice panel
    const existing = root.querySelector("#ghostcrawler-auth-choice");
    if (existing) existing.remove();

    const options = Array.isArray(data?.options)
      ? data.options
      : [
          { label: "✅ Run Authenticated Scan", value: "run" },
          { label: "⏭️ Skip (stay unauthenticated)", value: "skip" },
          { label: "👁️ Manual (I'll explore myself)", value: "manual" },
        ];

    const panel = document.createElement("div");
    panel.id = "ghostcrawler-auth-choice";
    panel.style.cssText = [
      "margin-top:10px",
      "padding:10px",
      "border-radius:8px",
      "background:#1a2230",
      "border:1px solid rgba(140,180,255,0.3)",
    ].join(";");

    panel.innerHTML = `<div style="font-weight:700;margin-bottom:8px;color:#7ecbff;">⚡ Auth Bypass Confirmed</div>` +
      `<div style="opacity:0.9;margin-bottom:8px;word-break:break-all;">${data?.postAuthUrl || ""}</div>`;

    for (const opt of options) {
      const btn = document.createElement("button");
      btn.textContent = opt.label;
      btn.style.cssText = [
        "display:block",
        "width:100%",
        "margin-bottom:6px",
        "padding:7px 10px",
        "border:0",
        "border-radius:6px",
        "background:#2f3942",
        "color:#e8eef2",
        "font-size:12px",
        "cursor:pointer",
        "text-align:left",
      ].join(";");
      btn.addEventListener("mouseenter", () => { btn.style.background = "#3b4a58"; });
      btn.addEventListener("mouseleave", () => { btn.style.background = "#2f3942"; });
      btn.addEventListener("click", () => {
        fetch(`${hudServerUrl}/ghostcrawler/auth-decision`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ decision: opt.value }),
        }).catch(() => {});
        panel.remove();
      });
      panel.appendChild(btn);
    }

    root.appendChild(panel);
  };

  // Probe pending card: shown while AI is analysing a probe response
  const showProbePending = (data) => {
    const root = ensureHud();
    if (!root) return;
    const existing = root.querySelector("#ghostcrawler-probe-card");
    if (existing) existing.remove();

    const attackLabel = { xss: "XSS", sqli: "SQLi", authinject: "Auth Bypass" }[data?.attackType] || data?.attackType || "Probe";
    const snippet = (data?.postText || "").slice(0, 120).replace(/</g, "&lt;");

    const card = document.createElement("div");
    card.id = "ghostcrawler-probe-card";
    card.style.cssText = "margin-top:10px;padding:10px;border-radius:8px;background:#1a2a1a;border:1px solid rgba(80,200,120,0.35);font-size:11px;";
    card.innerHTML = `
      <div style="font-weight:700;color:#7eff9a;margin-bottom:5px;">🔬 AI Probe Analysis — ${attackLabel}</div>
      <div style="opacity:0.8;margin-bottom:4px;"><b>Field:</b> ${data?.selector || "?"}</div>
      <div style="opacity:0.8;margin-bottom:4px;word-break:break-all;"><b>Payload:</b> ${(data?.payload || "").replace(/</g, "&lt;")}</div>
      <div style="opacity:0.7;font-family:monospace;background:#0d1a0d;padding:4px 6px;border-radius:4px;margin-top:4px;max-height:60px;overflow:hidden;">${snippet}…</div>
      <div style="margin-top:6px;color:#b3d9b3;">⏳ AI analysing response…</div>`;
    root.appendChild(card);
  };

  // Probe result card: replaces/updates the pending card with the AI verdict
  const showProbeResult = (data) => {
    const root = ensureHud();
    if (!root) return;
    const existing = root.querySelector("#ghostcrawler-probe-card");
    if (existing) existing.remove();

    const attackLabel = { xss: "XSS", sqli: "SQLi", authinject: "Auth Bypass" }[data?.attackType] || data?.attackType || "Probe";
    const icon = { skip: "⏭", continue: "🔍", vulnerable: "🚨" }[data?.decision] || "ℹ️";
    const color = { skip: "#aaa", continue: "#7ecbff", vulnerable: "#ff6b6b" }[data?.decision] || "#ccc";

    const card = document.createElement("div");
    card.id = "ghostcrawler-probe-card";
    card.style.cssText = `margin-top:10px;padding:10px;border-radius:8px;background:#1a1a2a;border:1px solid ${color}55;font-size:11px;`;
    card.innerHTML = `
      <div style="font-weight:700;color:${color};margin-bottom:5px;">${icon} ${attackLabel} verdict: ${data?.decision?.toUpperCase()}</div>
      <div style="opacity:0.8;"><b>Field:</b> ${data?.selector || "?"}</div>
      <div style="opacity:0.8;margin-top:4px;word-break:break-word;"><b>Reason:</b> ${data?.reason || ""}</div>`;
    root.appendChild(card);

    // Auto-dismiss non-critical verdicts after 8 seconds
    if (data?.decision !== "vulnerable") {
      setTimeout(() => { card.remove(); }, 8000);
    }
  };
  // ────────────────────────────────────────────────────────────────────

  // ── Network Interception for Attack Surface Discovery ──────────────
  const capturedEndpoints = new Map();

  const extractParams = (url, body, contentType) => {
    const params = {};
    try {
      const urlObj = new URL(url, window.location.origin);
      urlObj.searchParams.forEach((value, key) => {
        params[`query.${key}`] = value;
      });
      if (body) {
        if (contentType?.includes('application/json')) {
          const json = JSON.parse(body);
          Object.keys(json).forEach(key => {
            params[`body.${key}`] = json[key];
          });
        } else if (contentType?.includes('application/x-www-form-urlencoded')) {
          new URLSearchParams(body).forEach((value, key) => {
            params[`body.${key}`] = value;
          });
        }
      }
    } catch {}
    return params;
  };

  const captureRequest = (method, url, body, contentType) => {
    const normalizedUrl = String(url || "");
    if (
      normalizedUrl.includes("127.0.0.1:3200/ghostcrawler") ||
      normalizedUrl.includes("localhost:3200/ghostcrawler")
    ) {
      return;
    }

    const key = `${method} ${url.split('?')[0]}`;
    if (!capturedEndpoints.has(key)) {
      capturedEndpoints.set(key, {
        method,
        url: url.split('?')[0],
        params: extractParams(url, body, contentType),
        captured: new Date().toISOString()
      });
    }
  };

  // Hook fetch()
  if (!alreadyLoaded) {
  const originalFetch = window.fetch;
  window.fetch = function(...args) {
    const [url, options = {}] = args;
    const method = (options.method || 'GET').toUpperCase();
    const contentType = options.headers?.['Content-Type'] || options.headers?.['content-type'];
    captureRequest(method, url, options.body, contentType);
    return originalFetch.apply(this, args);
  };

  // Hook XMLHttpRequest
  const originalXHROpen = XMLHttpRequest.prototype.open;
  const originalXHRSetRequestHeader = XMLHttpRequest.prototype.setRequestHeader;
  const originalXHRSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function(method, url, ...rest) {
    this._ghostcrawler = { method, url, headers: {} };
    return originalXHROpen.call(this, method, url, ...rest);
  };
  XMLHttpRequest.prototype.setRequestHeader = function(name, value) {
    if (this._ghostcrawler) {
      this._ghostcrawler.headers[String(name || "").toLowerCase()] = String(value || "");
    }
    return originalXHRSetRequestHeader.call(this, name, value);
  };
  XMLHttpRequest.prototype.send = function(body) {
    if (this._ghostcrawler) {
      const contentType = this._ghostcrawler.headers["content-type"];
      captureRequest(this._ghostcrawler.method, this._ghostcrawler.url, body, contentType);
    }
    return originalXHRSend.call(this, body);
  };
  } // end !alreadyLoaded
  // ────────────────────────────────────────────────────────────────────

  const runScan = async () => {
    const detector = window.GhostcrawlerDetector;
    if (!detector?.detectFrameworks) {
      return { findings: [], error: "Detector unavailable" };
    }

    const result = detector.detectFrameworks();
    result.endpoints = Array.from(capturedEndpoints.values());
    
    const existing = await storageGet(["ghostcrawlerScans"]);
    const scans = existing.ghostcrawlerScans || {};

    scans[result.page.url] = result;
    await storageSet({ ghostcrawlerScans: scans });

    return result;
  };

  runtimeApi.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message?.type === "ghostcrawler:dom-observe-start") {
      try {
        if (domObserver) {
          domObserver.disconnect();
          domObserver = null;
        }

        domObserverEvents = [];
        domObserverStartedAt = Date.now();

        const payload = message.payload || {};
        const maxEvents = Number(payload.maxEvents || 200);
        const selector = payload.selector;
        const target = selector
          ? document.querySelector(selector)
          : document.body || document.documentElement;

        if (!target) {
          throw new Error("Could not resolve DOM observation target");
        }

        const summarizeMutation = (mutation) => {
          if (mutation.type === "attributes") {
            return {
              type: "attributes",
              attributeName: mutation.attributeName,
              target: mutation.target?.nodeName || "unknown",
            };
          }

          const added = mutation.addedNodes ? mutation.addedNodes.length : 0;
          const removed = mutation.removedNodes ? mutation.removedNodes.length : 0;
          let sampleText = "";
          if (added > 0) {
            const node = mutation.addedNodes[0];
            const text = (node?.textContent || "").trim();
            sampleText = text.slice(0, 140);
          }

          return {
            type: mutation.type,
            added,
            removed,
            sampleText,
          };
        };

        domObserver = new MutationObserver((mutations) => {
          for (const mutation of mutations) {
            domObserverEvents.push({
              ts: new Date().toISOString(),
              elapsedMs: Date.now() - domObserverStartedAt,
              ...summarizeMutation(mutation),
            });
            if (domObserverEvents.length > maxEvents) {
              domObserverEvents = domObserverEvents.slice(-maxEvents);
            }
          }
        });

        domObserver.observe(target, {
          childList: true,
          subtree: true,
          attributes: true,
          characterData: false,
        });

        sendResponse({
          ok: true,
          result: {
            started: true,
            selector: selector || "document",
            maxEvents,
          },
        });
        return false;
      } catch (error) {
        sendResponse({ ok: false, error: String(error) });
        return false;
      }
    }

    if (message?.type === "ghostcrawler:dom-observe-get") {
      sendResponse({
        ok: true,
        result: {
          active: Boolean(domObserver),
          events: domObserverEvents,
          total: domObserverEvents.length,
          startedAt: domObserverStartedAt,
        },
      });
      return false;
    }

    if (message?.type === "ghostcrawler:dom-observe-stop") {
      if (domObserver) {
        domObserver.disconnect();
        domObserver = null;
      }
      sendResponse({
        ok: true,
        result: {
          stopped: true,
          events: domObserverEvents,
          total: domObserverEvents.length,
          startedAt: domObserverStartedAt,
          stoppedAt: Date.now(),
        },
      });
      return false;
    }

    if (message?.type === "ghostcrawler:browser-action") {
      const payload = message.payload || {};
      const action = payload.action;

      const setValue = (element, value) => {
        const prototype = Object.getPrototypeOf(element);
        const descriptor = Object.getOwnPropertyDescriptor(prototype, "value");
        if (descriptor?.set) {
          descriptor.set.call(element, value);
        } else {
          element.value = value;
        }
        element.dispatchEvent(new Event("input", { bubbles: true }));
        element.dispatchEvent(new Event("change", { bubbles: true }));
      };

      try {
        if (action === "navigate") {
          if (!payload.url) throw new Error("Missing url");
          window.location.href = payload.url;
          sendResponse({ ok: true, result: { action, url: payload.url } });
          return false;
        }

        if (action === "get_page_state") {
          // Returns current URL + full body text so caller can detect navigation
          sendResponse({
            ok: true,
            result: {
              action,
              url: window.location.href,
              text: (document.body ? (document.body.innerText || document.body.textContent || "") : "").slice(0, 8000),
              title: document.title || "",
            },
          });
          return false;
        }

        if (action === "smart_fill_form") {
          // Fill all visible form fields with benign data, then inject payload into target field.
          // Ensures the form actually submits (passes required-field validation) so the server
          // processes the injection rather than rejecting early due to missing fields.
          const targetSelector = payload.targetSelector;
          const attackPayload = payload.payload || "";
          const formSelector = payload.formSelector || null; // optional: restrict to one form
          const includeHidden = !!payload.includeHidden; // when true, also mutate hidden inputs matching targetSelector

          const FILLABLE = 'input:not([type="hidden"]):not([type="submit"]):not([type="button"]):not([type="reset"]):not([type="checkbox"]):not([type="radio"]):not([type="file"]):not([type="image"]):not([disabled]):not([readonly]), textarea:not([disabled]):not([readonly]), select:not([disabled])';

          // Pick a benign value for a field based on its type/name/label/placeholder
          function benignValue(el) {
            const type = (el.getAttribute("type") || el.tagName).toLowerCase();
            const hint = (el.name + " " + el.id + " " + (el.placeholder || "") + " " + (el.getAttribute("aria-label") || "")).toLowerCase();
            if (type === "email" || hint.includes("email")) return "test@example.com";
            if (type === "tel" || hint.includes("phone") || hint.includes("mobile") || hint.includes("tel")) return "5551234567";
            if (type === "number" || type === "range") return "42";
            if (type === "url") return "https://example.com";
            if (type === "date") return "2024-01-15";
            if (type === "datetime-local") return "2024-01-15T10:00";
            if (type === "time") return "10:00";
            if (type === "month") return "2024-01";
            if (type === "week") return "2024-W03";
            if (type === "color") return "#ff0000";
            if (type === "password" || hint.includes("pass") || hint.includes("pwd")) return "Password123!";
            if (hint.includes("user") || hint.includes("login") || hint.includes("account")) return "testuser";
            if (hint.includes("first") && hint.includes("name")) return "Test";
            if (hint.includes("last") && hint.includes("name")) return "User";
            if (hint.includes("name")) return "Test User";
            if (hint.includes("zip") || hint.includes("postal")) return "12345";
            if (hint.includes("city") || hint.includes("town")) return "New York";
            if (hint.includes("state") || hint.includes("province")) return "NY";
            if (hint.includes("country")) return "US";
            if (hint.includes("address") || hint.includes("street")) return "123 Test St";
            if (hint.includes("message") || hint.includes("comment") || hint.includes("description") || hint.includes("note")) return "test message";
            if (hint.includes("search") || hint.includes("query") || hint.includes("keyword")) return "test";
            if (hint.includes("age")) return "25";
            if (type === "textarea") return "test input";
            if (type === "select") {
              const opts = Array.from(el.options).filter((o) => o.value && o.value !== "");
              return opts.length > 0 ? opts[0].value : "";
            }
            return "test";
          }

          function nativeSet(el, value) {
            const proto = el.tagName === "SELECT" ? HTMLSelectElement.prototype :
                          el.tagName === "TEXTAREA" ? HTMLTextAreaElement.prototype :
                          HTMLInputElement.prototype;
            const setter = Object.getOwnPropertyDescriptor(proto, "value")?.set;
            if (setter) {
              setter.call(el, value);
            } else {
              el.value = value;
            }
            el.dispatchEvent(new Event("input", { bubbles: true }));
            el.dispatchEvent(new Event("change", { bubbles: true }));
          }

          const root = formSelector ? document.querySelector(formSelector) : document;
          if (!root) throw new Error("Form root not found: " + formSelector);
          const allFields = Array.from((root || document).querySelectorAll(FILLABLE));

          let targetFilled = false;
          for (const el of allFields) {
            const rect = el.getBoundingClientRect();
            if (rect.width === 0 && rect.height === 0) continue; // skip invisible
            const elSelector = el.id ? "#" + CSS.escape(el.id) :
                               el.name ? `[name="${el.name}"]` :
                               null;
            // Check if this is the target field
            const isTarget = targetSelector && (
              el === document.querySelector(targetSelector) ||
              elSelector === targetSelector
            );
            if (isTarget) {
              nativeSet(el, attackPayload);
              targetFilled = true;
            } else {
              nativeSet(el, benignValue(el));
            }
          }

          if (!targetFilled && targetSelector) {
            // Fallback: try direct querySelector (covers hidden inputs when includeHidden=true)
            const targetEl = document.querySelector(targetSelector);
            if (targetEl) {
              nativeSet(targetEl, attackPayload);
              targetFilled = true;
            }
          }

          // When includeHidden=true, also force-set hidden inputs matching targetSelector
          if (includeHidden && targetSelector) {
            const hiddenEl = document.querySelector(targetSelector);
            if (hiddenEl && hiddenEl.getAttribute("type") === "hidden") {
              nativeSet(hiddenEl, attackPayload);
              targetFilled = true;
            }
          }

          sendResponse({ ok: true, result: { action, targetFilled, fieldsProcessed: allFields.length } });
          return false;
        }

        if (action === "scan_all_inputs") {
          // Returns ALL visible input elements on the page, including those not inside <form> tags.
          // Groups loose inputs together as a virtual form.
          const FILLABLE = 'input:not([type="hidden"]):not([type="submit"]):not([type="button"]):not([type="reset"]):not([type="file"]):not([type="image"]), textarea, select';
          const all = Array.from(document.querySelectorAll(FILLABLE)).filter((el) => {
            const rect = el.getBoundingClientRect();
            return rect.width > 0 || rect.height > 0;
          });
          const inputs = all.map((el) => ({
            selector: el.id ? "#" + CSS.escape(el.id) : el.name ? `[name="${CSS.escape(el.name)}"]` : null,
            type: (el.getAttribute("type") || el.tagName).toLowerCase(),
            name: el.name || "",
            id: el.id || "",
            placeholder: el.placeholder || "",
            inForm: !!el.closest("form"),
            formAction: el.closest("form")?.action || window.location.href,
            formMethod: (el.closest("form")?.method || "GET").toUpperCase(),
          })).filter((i) => i.selector);
          sendResponse({ ok: true, result: { action, inputs, pageUrl: window.location.href } });
          return false;
        }

        if (action === "extract_links") {
          const anchors = Array.from(document.querySelectorAll("a[href]"));
          const links = [];
          for (const a of anchors) {
            try {
              const href = a.href;
              if (href && !href.startsWith("javascript:") && !href.startsWith("mailto:")) {
                links.push(href);
              }
            } catch (e) { /* skip malformed hrefs */ }
          }
          sendResponse({ ok: true, result: { action, links: Array.from(new Set(links)) } });
          return false;
        }

        // Collects the form containing the target selector, serialises all filled fields,
        // and POSTs the submission to the MCP server which routes it through Burp proxy.
        // This guarantees every form submission appears in Burp history regardless of
        // whether the browser's proxy settings are configured.
        if (action === "submit_form_via_mcp") {
          const mcpUrl = "http://127.0.0.1:3200/ghostcrawler/proxy-request";
          const targetEl = payload.targetSelector ? document.querySelector(payload.targetSelector) : null;
          const form = targetEl?.closest("form") || document.querySelector("form");

          if (!form) {
            sendResponse({ ok: false, error: "No form found on page" });
            return false;
          }

          const formAction = form.action || window.location.href;
          const formMethod = (form.method || "GET").toUpperCase();
          const formData = new FormData(form);
          const params = new URLSearchParams(formData).toString();

          const requestUrl = formMethod === "GET"
            ? `${formAction}${params ? "?" + params : ""}`
            : formAction;
          const requestBody = formMethod === "POST" ? params : undefined;

          fetch(mcpUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              method: formMethod,
              url: requestUrl,
              contentType: formMethod === "POST" ? "application/x-www-form-urlencoded" : undefined,
              body: requestBody,
            }),
          })
            .then((r) => r.json())
            .then((data) => {
              sendResponse({ ok: true, result: { action, ...data } });
            })
            .catch((err) => {
              sendResponse({ ok: false, error: String(err) });
            });
          return true; // async sendResponse
        }

        if (action === "get_page_source") {
          sendResponse({ ok: true, result: { action, html: document.documentElement.outerHTML } });
          return false;
        }

        if (action === "execute_script") {
          try {
            // eslint-disable-next-line no-new-func
            const fn = new Function(String(payload.script || ""));
            const res = fn();
            sendResponse({ ok: true, result: { action, value: res ?? null } });
          } catch (e) {
            sendResponse({ ok: false, error: String(e) });
          }
          return false;
        }

        if (action === "query_elements") {
          const sel = payload.selector || "textarea, input[type='text'], input:not([type])";
          const elems = Array.from(document.querySelectorAll(sel)).slice(0, 100)
            .filter((el) => !(el.closest && el.closest("#ghostcrawler-live-hud")))
            .map((el) => {
            const inp = el;
            const id = inp.id || "";
            const name = inp.name || inp.getAttribute("name") || "";
            const type = inp.type || inp.tagName.toLowerCase() || "text";
            const value = (typeof inp.value === "string" ? inp.value : inp.getAttribute("value")) || "";
            const builtSel = id ? `#${id}` : name ? `[name="${name}"]` : null;
            return builtSel ? { selector: builtSel, id, name, type, value, placeholder: inp.placeholder || "", tagName: inp.tagName.toLowerCase() } : null;
          }).filter(Boolean);
          sendResponse({ ok: true, result: { action, elements: elems } });
          return false;
        }

        // "request" action is selector-free — must be checked before the selector guard below
        if (action === "request") {
          const requestUrl = payload.url || window.location.href;
          const method = String(payload.method || "GET").toUpperCase();
          const headers = payload.headers || {};
          const requestInit = {
            method,
            headers,
            body: payload.body,
          };

          fetch(requestUrl, requestInit)
            .then(async (response) => {
              const responseText = await response.text();
              sendResponse({
                ok: true,
                result: {
                  action,
                  url: requestUrl,
                  method,
                  status: response.status,
                  responseText: responseText.slice(0, 5000),
                },
              });
            })
            .catch((error) => {
              sendResponse({ ok: false, error: String(error) });
            });
          return true;
        }

        if (!payload.selector) {
          throw new Error("Missing selector");
        }

        const element = document.querySelector(payload.selector);
        if (!element) {
          throw new Error(`Element not found: ${payload.selector}`);
        }
        // Safety: never let the scanner click/type into its own HUD overlay
        // (e.g., heuristic submitSelector inadvertently matching the STOP button).
        if (element.closest && element.closest("#ghostcrawler-live-hud")) {
          throw new Error(`Refusing to operate on Ghostcrawler HUD element: ${payload.selector}`);
        }

        if (action === "clear") {
          if (element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement) {
            const proto = Object.getPrototypeOf(element);
            const desc = Object.getOwnPropertyDescriptor(proto, "value");
            if (desc?.set) desc.set.call(element, ""); else element.value = "";
            element.dispatchEvent(new Event("input", { bubbles: true }));
            element.dispatchEvent(new Event("change", { bubbles: true }));
          }
          sendResponse({ ok: true, result: { action, selector: payload.selector } });
          return false;
        }

        if (action === "click") {
          element.scrollIntoView({ behavior: "smooth", block: "center" });
          element.click();
          sendResponse({ ok: true, result: { action, selector: payload.selector } });
          return false;
        }

        if (action === "type") {
          if (!(element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement)) {
            throw new Error("Target is not an input or textarea");
          }
          setValue(element, String(payload.text || ""));
          sendResponse({
            ok: true,
            result: { action, selector: payload.selector, length: String(payload.text || "").length },
          });
          return false;
        }

        if (action === "extract_text") {
          const text = (element.textContent || "").trim();
          sendResponse({
            ok: true,
            result: { action, selector: payload.selector, text },
          });
          return false;
        }

        throw new Error(`Unsupported action: ${action}`);
      } catch (error) {
        sendResponse({ ok: false, error: String(error) });
        return false;
      }
    }

    if (message?.type === "ghostcrawler:scan-live-start") {
      startHudPolling(message.serverUrl);
      sendResponse({ ok: true });
      return false;
    }

    // Background (popup toggle) asks content to hide the HUD.
    if (message?.type === "ghostcrawler:hide-hud") {
      hudActive = false;
      stopHudPolling();
      hudRoot?.remove();
      hudRoot = null;
      sendResponse({ ok: true });
      return false;
    }

    // Background pushes live scan state so content script doesn't need to fetch localhost
    if (message?.type === "ghostcrawler:hud-push") {
      const state = message.state;
      const sig = `${state?.status}|${state?.progress}|${state?.currentTest}|${(state?.vulnerabilities||[]).length}`;
      if (sig !== hudLastSignature) {
        hudLastSignature = sig;
        const now = new Date().toLocaleTimeString();
        hudLog.push(`[${now}] ${state?.currentTest || state?.status || "update"}`);
        if (hudLog.length > 40) hudLog = hudLog.slice(-40);
      }
      // Re-activate persistence guardian if this is a freshly re-injected content script
      // (hudActive is false after a full-page navigation tears down the previous instance).
      if (!hudActive) {
        hudActive = true;
        ensureHudPersistence();
      }
      ensureHud();
      renderHud(state);
      // Check if server is asking for an auth choice
      if (state?.authChoice) {
        showAuthChoicePrompt(state.authChoice);
      }
      sendResponse({ ok: true });
      return false;
    }

    if (message?.type === "ghostcrawler:hud-auth-choice") {
      ensureHud();
      showAuthChoicePrompt(message.data || message);
      sendResponse({ ok: true });
      return false;
    }

    if (message?.type === "ghostcrawler:hud-probe-pending") {
      ensureHud();
      showProbePending(message.data || message);
      sendResponse({ ok: true });
      return false;
    }

    if (message?.type === "ghostcrawler:hud-probe-result") {
      ensureHud();
      showProbeResult(message.data || message);
      sendResponse({ ok: true });
      return false;
    }

    if (message?.type === "ghostcrawler:scan-live-stop") {
      stopHudPolling();
      sendResponse({ ok: true });
      return false;
    }

    if (message?.type === "ghostcrawler:scan") {
      runScan()
        .then((result) => sendResponse({ ok: true, result }))
        .catch((error) => sendResponse({ ok: false, error: String(error) }));
      return true;
    }

    if (message?.type === "ghostcrawler:trigger-one") {
      const detector = window.GhostcrawlerDetector;
      if (!detector?.triggerButtonByIndex || !detector?.fillFields) {
        sendResponse({ ok: false, error: "Detector unavailable" });
        return false;
      }
      // Fill fields immediately before triggering
      detector.fillFields(message.valuesMap || {});
      const index = message.index;
      sendResponse({ ok: true });
      detector.triggerButtonByIndex(index).catch(() => {});
      return false;
    }

    if (message?.type === "ghostcrawler:trigger") {
      const detector = window.GhostcrawlerDetector;
      if (!detector?.triggerButtons || !detector?.fillFields) {
        sendResponse({ ok: false, error: "Detector unavailable" });
        return false;
      }

      // Fill fields immediately before counting & triggering
      detector.fillFields(message.valuesMap || {});

      // Use the detector's method to count triggerable buttons
      const total = detector.getVisibleEnabledButtons ? detector.getVisibleEnabledButtons().length : 0;

      // Respond immediately — the trigger loop runs in the background
      sendResponse({ ok: true, result: { queued: true, total } });

      const delayMs = message.delayMs ?? 700;
      detector.triggerButtons(delayMs).catch(() => {});

      return false;
    }

    return false;
  });

  // ── Fetch / XHR endpoint discovery (SPA-aware) ───────────────────
  // Injects a MAIN-world script that patches fetch + XHR.send and reports
  // every observed network call back to the content script via custom event.
  // This catches GraphQL, REST and WebSocket endpoints the static crawler misses.
  const observedRequests = [];
  const OBSERVED_LIMIT = 500;
  try {
    window.addEventListener("ghostcrawler:net", (ev) => {
      const detail = ev.detail || {};
      if (!detail.url) return;
      observedRequests.push({
        ts: Date.now(),
        url: detail.url,
        method: String(detail.method || "GET").toUpperCase(),
        status: detail.status ?? null,
        contentType: detail.contentType || "",
        kind: detail.kind || "fetch",
      });
      if (observedRequests.length > OBSERVED_LIMIT) {
        observedRequests.splice(0, observedRequests.length - OBSERVED_LIMIT);
      }
    });

    // net-observer.js is injected into the main world by background.js
    // via chrome.scripting.executeScript({ world: "MAIN" }), which bypasses
    // the page's CSP. It dispatches ghostcrawler:net CustomEvents that we
    // listen for here in the isolated world.
  } catch { /* env without window */ }

  // Allow the agent to retrieve observed requests via browser_action observed_requests
  runtimeApi.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message?.type === "ghostcrawler:observed-requests") {
      sendResponse({ ok: true, result: { requests: observedRequests.slice(-200), total: observedRequests.length } });
      return false;
    }
    return false;
  });

  if (!alreadyLoaded && document instanceof HTMLDocument) {
    runScan().catch(() => {});
  }

  // Keepalive: ping background every 5s to prevent Chrome from killing the service worker.
  // Clear the interval if the extension context is invalidated (e.g. after reload).
  // Only start one timer per page — guard prevents duplicate timers on re-injection.
  if (!alreadyLoaded && document instanceof HTMLDocument) {
    const keepaliveTimer = setInterval(() => {
      try {
        runtimeApi.runtime.sendMessage({ type: "ghostcrawler:ping" }).catch((err) => {
          if (err && err.message && err.message.includes("Extension context invalidated")) {
            clearInterval(keepaliveTimer);
          }
        });
      } catch (e) {
        clearInterval(keepaliveTimer);
      }
    }, 5000);
  }
})();