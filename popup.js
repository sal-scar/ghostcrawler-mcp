(function () {
  const runtimeApi = globalThis.browser || globalThis.chrome;

  const queryActiveTab = () => new Promise((resolve) => runtimeApi.tabs.query({ active: true, currentWindow: true }, (tabs) => resolve(tabs[0])));
  const storageGet = (keys) => new Promise((resolve) => runtimeApi.storage.local.get(keys, resolve));
  const sendMessage = (tabId, message) => new Promise((resolve, reject) => {
    runtimeApi.tabs.sendMessage(tabId, message, (response) => {
      const lastError = runtimeApi.runtime.lastError;
      if (lastError) {
        reject(new Error(lastError.message));
        return;
      }

      resolve(response);
    });
  });

  const isConnectionError = (error) =>
    /Receiving end does not exist|Could not establish connection/i.test(error.message);

  const injectScripts = (tabId) => new Promise((resolve, reject) => {
    runtimeApi.scripting.executeScript(
      { target: { tabId }, files: ["detector.js", "content.js"] },
      () => {
        const lastError = runtimeApi.runtime.lastError;
        if (lastError) {
          reject(new Error(lastError.message));
        } else {
          resolve();
        }
      }
    );
  });

  const sendMessageWithInject = async (tabId, message) => {
    try {
      return await sendMessage(tabId, message);
    } catch (error) {
      if (!isConnectionError(error)) throw error;
      await injectScripts(tabId);
      // Brief pause so the injected scripts can register their listeners
      await new Promise((resolve) => setTimeout(resolve, 150));
      return await sendMessage(tabId, message);
    }
  };

  let currentTabId = null;

  const pageUrl = document.getElementById("pageUrl");
  const scanMeta = document.getElementById("scanMeta");
  const refreshButton = document.getElementById("refreshButton");
  // MCP is always enabled (auto-set on install); no UI toggle needed
  const MCP_BASE_URL_DEFAULT = "http://127.0.0.1:3200";
  const liveScanCard = document.getElementById("liveScanCard");
  const stopScanButton = document.getElementById("stopScanButton");
  const scanStatusPill = document.getElementById("scanStatus");
  const progressBar = document.getElementById("progressBar");
  const currentTestText = document.getElementById("currentTest");
  const vulnCount = document.getElementById("vulnCount");
  const vulnList = document.getElementById("vulnList");
  const captchaCard = document.getElementById("captchaCard");
  const captchaSolvedButton = document.getElementById("captchaSolvedButton");
  const captchaSkipButton = document.getElementById("captchaSkipButton");

  const setStatus = (message) => {
    console.log("[Status]", message);
  };

  // ── MCP Server Integration ──────────────────────────────────
  // MCP is always enabled; reads stored URL (set by onInstalled handler)
  const getMcpUrl = async () => {
    const { mcpUrl } = await storageGet(["mcpUrl"]);
    return normalizeMcpBaseUrl(mcpUrl || MCP_BASE_URL_DEFAULT);
  };

  const loadMCPSettings = async () => {
    // Load and apply the stored attack mode
    const { attackMode } = await storageGet(["attackMode"]);
    applyAttackMode(attackMode || "silent");
  };

  const applyAttackMode = (mode) => {
    const btn = document.getElementById("attackModeToggle");
    const desc = document.getElementById("attackModeDesc");
    if (!btn) return;
    if (mode === "live") {
      btn.textContent = "Live 👁";
      btn.style.background = "#7c3aed";
      btn.style.borderColor = "#7c3aed";
      if (desc) desc.textContent = "Browser navigates to each attack URL";
    } else {
      btn.textContent = "Silent";
      btn.style.background = "";
      btn.style.borderColor = "";
      if (desc) desc.textContent = "Attacks run via Burp proxy only";
    }
  };

  document.getElementById("attackModeToggle")?.addEventListener("click", async () => {
    const { attackMode } = await storageGet(["attackMode"]);
    const next = (attackMode || "silent") === "silent" ? "live" : "silent";
    await runtimeApi.storage.local.set({ attackMode: next });
    applyAttackMode(next);
    // Push to MCP server so current scan picks it up immediately
    try {
      const serverUrl = await getMcpUrl();
      await fetch(`${serverUrl}/ghostcrawler/settings`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ attackMode: next }),
      });
    } catch { /* server may be down — setting is saved locally regardless */ }
  });

  const showMcpMessage = (text, ok) => {
    const el = document.getElementById("wizardStatus");
    if (!el) return;
    el.textContent = text;
    el.style.color = ok ? "#4ade80" : "#dc2626";
  };

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
    } catch {
      // ignore parse issues; caller will surface user-friendly error.
    }
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

  const sendToMCP = async (scanResult) => {
    const serverUrl = await getMcpUrl();
    if (!serverUrl) {
      showMcpMessage("✗ MCP URL is empty. Check storage or restart VS Code.", false);
      return;
    }

    try {
      const syncResult = await new Promise((resolve, reject) => {
        runtimeApi.runtime.sendMessage(
          {
            type: "ghostcrawler:mcp-sync",
            serverUrl,
            scan: scanResult,
          },
          (response) => {
            const lastError = runtimeApi.runtime.lastError;
            if (lastError) {
              reject(new Error(lastError.message));
              return;
            }
            resolve(response);
          }
        );
      });

      if (!syncResult?.ok) {
        throw new Error(String(syncResult?.error || "Failed to fetch"));
      }

      if (syncResult?.serverUrl && syncResult.serverUrl !== serverUrl) {
        await runtimeApi.storage.local.set({ mcpUrl: syncResult.serverUrl });
      }

      showMcpMessage(`✓ Synced to MCP server at ${new Date().toLocaleTimeString()}`, true);
    } catch (error) {
      showMcpMessage(`✗ Failed to sync: ${String(error?.message || error)}. Check MCP URL and ensure server is running on 3200.`, false);
    }
  };

  // MCP settings listeners removed — settings are auto-managed via onInstalled

  // ── Stop Scan Button ────────────────────────────────────────
  const stopScan = async () => {
    stopScanButton.disabled = true;
    stopScanButton.textContent = "Stopping...";

    try {
      const serverUrl = await getMcpUrl();
      const response = await fetch(`${serverUrl}/ghostcrawler/scan-stop`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      
      const result = await response.json();
      showMcpMessage(`✓ Scan stopped at ${new Date().toLocaleTimeString()}`, true);
      
      liveScanCard.hidden = true;
      scanStatusPill.textContent = "Stopped";
      scanStatusPill.className = "pill pill--gray";
    } catch (error) {
      showMcpMessage(`✗ Failed to stop scan: ${String(error?.message || error)}`, false);
      stopScanButton.disabled = false;
      stopScanButton.textContent = "Stop Scan";
    }
  };

  stopScanButton.addEventListener("click", stopScan);

  // ── Scan Progress Polling ──────────────────────────────────────
  let scanPollInterval = null;

  const startScanProgressPolling = () => {
    if (scanPollInterval) return; // Already polling
    
    liveScanCard.hidden = false;
    scanStatusPill.textContent = "Scanning...";
    scanStatusPill.className = "pill pill--yellow";
    stopScanButton.disabled = false;
    stopScanButton.textContent = "Stop Scan";
    
    const pollProgress = async () => {
      try {
        const serverUrl = await getMcpUrl();
        const response = await fetch(`${serverUrl}/ghostcrawler/scan-progress`);
        
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }
        
        const progress = await response.json();
        
        // Update UI
        progressBar.style.width = `${progress.progress || 0}%`;
        currentTestText.textContent = progress.currentTest || "Running...";
        
        // Update status pill
        if (progress.status === "captcha-waiting") {
          scanStatusPill.textContent = "CAPTCHA";
          scanStatusPill.className = "pill pill--yellow";
          captchaCard.hidden = false;
          liveScanCard.hidden = false;
        } else if (progress.status === "completed") {
          scanStatusPill.textContent = "Complete";
          scanStatusPill.className = "pill pill--green";
          captchaCard.hidden = true;
          // Don't stop polling — AI may still be working (agent-active follows)
        } else if (progress.status === "agent-active") {
          scanStatusPill.textContent = "Agent working…";
          scanStatusPill.className = "pill pill--yellow";
          captchaCard.hidden = true;
        } else if (progress.status === "idle") {
          scanStatusPill.textContent = "Complete";
          scanStatusPill.className = "pill pill--green";
          captchaCard.hidden = true;
          stopScanProgressPolling();
        } else if (progress.status === "stopped") {
          scanStatusPill.textContent = "Stopped";
          scanStatusPill.className = "pill pill--gray";
          captchaCard.hidden = true;
          stopScanProgressPolling();
        } else {
          scanStatusPill.textContent = "Scanning...";
          scanStatusPill.className = "pill pill--yellow";
          captchaCard.hidden = true;
        }
        
        // Update findings
        const vulns = progress.vulnerabilities || [];
        vulnCount.textContent = vulns.length > 0 
          ? `${vulns.length} finding(s)` 
          : "No vulnerabilities found yet";
        
        // Show latest findings
        if (vulns.length > 0) {
          const list = document.createElement("ul");
          list.style.cssText = "margin: 0; padding: 0; list-style: none;";
          vulns.slice(-5).reverse().forEach(v => {
            const item = document.createElement("li");
            item.style.cssText = "padding: 8px; margin-bottom: 4px; background: rgba(220,38,38,0.1); border-radius: 4px; font-size: 12px;";
            item.innerHTML = `<strong>${v.severity || "Medium"}</strong>: ${v.type || "Finding"} - ${v.endpoint || ""}`;
            list.appendChild(item);
          });
          vulnList.innerHTML = "";
          vulnList.appendChild(list);
        }
        
      } catch (error) {
        console.error("[Scan Progress] Poll error:", error);
        // Don't stop polling on transient errors
      }
    };
    
    // Poll immediately, then every 2 seconds
    pollProgress();
    scanPollInterval = setInterval(pollProgress, 2000);
  };

  const stopScanProgressPolling = () => {
    if (scanPollInterval) {
      clearInterval(scanPollInterval);
      scanPollInterval = null;
    }
  };

  const signalCaptcha = async (skip) => {
    const serverUrl = await getMcpUrl();
    captchaSolvedButton.disabled = true;
    captchaSkipButton.disabled = true;
    try {
      await fetch(`${serverUrl}/ghostcrawler/captcha-solved`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ skip }),
      });
    } catch (e) {
      console.error("[CAPTCHA] Signal failed:", e);
    } finally {
      captchaCard.hidden = true;
      captchaSolvedButton.disabled = false;
      captchaSkipButton.disabled = false;
    }
  };

  captchaSolvedButton?.addEventListener("click", () => signalCaptcha(false));
  captchaSkipButton?.addEventListener("click", () => signalCaptcha(true));

  // ── Onboarding wizard ────────────────────────────────────────
  // Setup & Connection card
  const wizardCard = document.getElementById("wizardCard");
  const wizardVerify = document.getElementById("wizardVerify");
  const wizardStatus = document.getElementById("wizardStatus");
  const guideButton = document.getElementById("guideButton");

  guideButton?.addEventListener("click", () => {
    chrome.tabs.create({ url: chrome.runtime.getURL("guide.html") });
  });

  const probeMcp = async () => {
    try {
      const base = await getMcpUrl();
      const r = await fetch(`${base}/ghostcrawler/scan-progress`, { cache: "no-store" });
      return r.ok;
    } catch { return false; }
  };

  const refreshWizardVisibility = async () => {
    if (!wizardCard) return;
    // Always show the wizard — it's a persistent setup guide + connection checker.
    wizardCard.hidden = false;
    const reachable = await probeMcp();
    const pill = document.getElementById("wizardStatusPill");
    if (pill) {
      pill.textContent = reachable ? "MCP online ✓" : "MCP offline ✗";
      pill.style.background = reachable ? "#05422222" : "#fbbf2422";
      pill.style.color = reachable ? "#4ade80" : "#fbbf24";
      pill.style.borderColor = reachable ? "#4ade8044" : "#fbbf2444";
    }
    if (wizardStatus) wizardStatus.textContent = reachable ? "✓ MCP server reachable" : "✗ Not reachable — start the server and try again";
    if (wizardStatus) wizardStatus.style.color = reachable ? "#4ade80" : "#fbbf24";
  };

  wizardVerify?.addEventListener("click", async () => {
    if (wizardStatus) { wizardStatus.textContent = "Checking…"; wizardStatus.style.color = "#94a3b8"; }
    await refreshWizardVisibility();
  });

  refreshWizardVisibility();

  // On popup open: sync stored attack mode to the server so it's always current
  setTimeout(async () => {
    try {
      const { attackMode } = await storageGet(["attackMode"]);
      const serverUrl = await getMcpUrl();
      await fetch(`${serverUrl}/ghostcrawler/settings`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ attackMode: attackMode || "silent" }),
      });
    } catch { /* ignore — server may not be running yet */ }
  }, 300);

  // Auto-start polling if a scan might be running
  setTimeout(async () => {
    const serverUrl = await getMcpUrl();
    fetch(`${serverUrl}/ghostcrawler/scan-progress`)
        .then(r => r.json())
        .then(progress => {
          if (progress.status === "scanning" || progress.status === "captcha-waiting") {
            startScanProgressPolling();
          }
        })
        .catch(() => {});
  }, 500);

  // ────────────────────────────────────────────────────────────

  const readStoredScan = async (url) => {
    const stored = await storageGet(["ghostcrawlerScans"]);
    return stored.ghostcrawlerScans?.[url] || null;
  };

  const refreshScan = async () => {
    const tab = await queryActiveTab();
    if (!tab?.id || !tab.url) {
      pageUrl.textContent = "This tab is not scannable.";
      scanMeta.textContent = "";
      return;
    }

    const restrictedSchemes = ["chrome://", "chrome-extension://", "edge://", "about:", "moz-extension://", "devtools://"];
    if (restrictedSchemes.some(s => tab.url.startsWith(s))) {
      pageUrl.textContent = tab.url;
      scanMeta.textContent = "This page cannot be scanned (browser-internal URL).";
      return;
    }

    currentTabId = tab.id;
    pageUrl.textContent = tab.url;

    const stored = await readStoredScan(tab.url);
    if (stored?.scannedAt) {
      scanMeta.textContent = `Last scan: ${new Date(stored.scannedAt).toLocaleString()}`;
    }
  };

  refreshButton.addEventListener("click", refreshScan);
  loadMCPSettings();
  refreshScan().catch((error) => setStatus(`Unable to initialize popup: ${error.message}`));

  // Quick Reference toggle
  const helpToggle = document.getElementById("helpToggle");
  const helpBody = document.getElementById("helpBody");
  const helpChevron = document.getElementById("helpChevron");
  if (helpToggle && helpBody) {
    helpToggle.addEventListener("click", () => {
      const open = helpBody.style.display !== "none";
      helpBody.style.display = open ? "none" : "block";
      if (helpChevron) helpChevron.style.transform = open ? "" : "rotate(180deg)";
    });
  }
})();