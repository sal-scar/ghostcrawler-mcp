// Injected into the main world via chrome.scripting.executeScript to intercept
// fetch and XHR on the page. Dispatches ghostcrawler:net CustomEvents that the
// content script (isolated world) listens for.
(function () {
  if (window.__ghostcrawlerNetHooked) return;
  window.__ghostcrawlerNetHooked = true;

  const post = (d) => {
    try { window.dispatchEvent(new CustomEvent("ghostcrawler:net", { detail: d })); } catch (e) {}
  };

  const origFetch = window.fetch;
  if (typeof origFetch === "function") {
    window.fetch = function (input, init) {
      let url = "", method = "GET";
      try {
        if (typeof input === "string") { url = input; }
        else if (input && input.url) { url = input.url; method = input.method || "GET"; }
        if (init && init.method) method = init.method;
      } catch (e) {}
      const p = origFetch.apply(this, arguments);
      try {
        p.then((r) => {
          try { post({ url, method, status: r.status, contentType: r.headers && r.headers.get && r.headers.get("content-type") || "", kind: "fetch" }); } catch (e) {}
        }).catch(() => { try { post({ url, method, status: 0, kind: "fetch" }); } catch (e) {} });
      } catch (e) {}
      return p;
    };
  }

  try {
    const X = XMLHttpRequest && XMLHttpRequest.prototype;
    if (X && X.open && X.send) {
      const origOpen = X.open, origSend = X.send;
      X.open = function (method, url) { this.__gc_method = method; this.__gc_url = url; return origOpen.apply(this, arguments); };
      X.send = function () {
        try {
          this.addEventListener("loadend", () => {
            try { post({ url: this.__gc_url || "", method: this.__gc_method || "GET", status: this.status, contentType: this.getResponseHeader && this.getResponseHeader("content-type") || "", kind: "xhr" }); } catch (e) {}
          });
        } catch (e) {}
        return origSend.apply(this, arguments);
      };
    }
  } catch (e) {}
})();
