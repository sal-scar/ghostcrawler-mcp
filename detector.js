(function () {
  const addFinding = (findings, slug, name, confidence, evidence) => {
    const existing = findings.get(slug);

    if (!existing) {
      findings.set(slug, { slug, name, confidence, evidence: [evidence] });
      return;
    }

    existing.confidence = Math.max(existing.confidence, confidence);
    if (!existing.evidence.includes(evidence)) {
      existing.evidence.push(evidence);
    }
  };

  const hasAnySelector = (selectors) => selectors.some((selector) => document.querySelector(selector));

  const hasAnyScriptMatch = (patterns) => {
    const scripts = Array.from(document.scripts);
    return scripts.some((script) => {
      const source = script.src || script.textContent || "";
      return patterns.some((pattern) => pattern.test(source));
    });
  };

  const metaGenerator = () => document.querySelector('meta[name="generator"]')?.content || "";

  // Resolve the best human-readable label for a form field
  const getFieldLabel = (input) => {
    if (input.id) {
      const label = document.querySelector(`label[for="${CSS.escape(input.id)}"]`);
      if (label) return getVisibleText(label);
    }
    const wrapping = input.closest("label");
    if (wrapping) return getVisibleText(wrapping);
    if (input.getAttribute("aria-label")) return input.getAttribute("aria-label");
    const lbId = input.getAttribute("aria-labelledby");
    if (lbId) {
      const lbEl = document.getElementById(lbId);
      if (lbEl) return getVisibleText(lbEl);
    }
    return input.placeholder || input.name || input.id || input.type || "Field";
  };

  const FILLABLE_SELECTOR = 'input:not([type="hidden"]):not([type="submit"]):not([type="button"]):not([type="reset"]):not([type="checkbox"]):not([type="radio"]):not([type="file"]):not([type="image"]), textarea, select';

  const detectForms = () =>
    Array.from(document.querySelectorAll("form"))
      .map((form, formIndex) => {
        const fields = Array.from(form.querySelectorAll(FILLABLE_SELECTOR))
          .filter((el) => isLikelyVisible(el))
          .map((input, fieldIndex) => ({
            formIndex,
            fieldIndex,
            id: input.id || "",
            name: input.name || "",
            type: (input.getAttribute("type") || input.tagName.toLowerCase()),
            label: getFieldLabel(input),
            placeholder: input.placeholder || "",
            currentValue: input.value || ""
          }));
        return {
          formIndex,
          action: form.action || window.location.href,
          method: (form.method || "GET").toUpperCase(),
          fields
        };
      })
      .filter((f) => f.fields.length > 0);

  // Fill fields from a map of "formIndex:fieldIndex" -> value.
  // Uses the native value setter so React/Vue controlled inputs notice the change.
  const fillFields = (valuesMap) => {
    document.querySelectorAll("form").forEach((form, formIndex) => {
      Array.from(form.querySelectorAll(FILLABLE_SELECTOR))
        .filter((el) => isLikelyVisible(el))
        .forEach((input, fieldIndex) => {
          const key = `${formIndex}:${fieldIndex}`;
          if (!(key in valuesMap)) return;
          const proto =
            input.tagName === "SELECT" ? HTMLSelectElement.prototype :
            input.tagName === "TEXTAREA" ? HTMLTextAreaElement.prototype :
            HTMLInputElement.prototype;
          const nativeSetter = Object.getOwnPropertyDescriptor(proto, "value")?.set;
          if (nativeSetter) {
            nativeSetter.call(input, valuesMap[key]);
          } else {
            input.value = valuesMap[key];
          }
          input.dispatchEvent(new Event("input", { bubbles: true }));
          input.dispatchEvent(new Event("change", { bubbles: true }));
        });
    });
  };

  const getVisibleText = (element) => {
    const text = (element.innerText || element.textContent || "").replace(/\s+/g, " ").trim();
    return text;
  };

  const getButtonSelector = (element) => {
    if (element.id) {
      return `#${element.id}`;
    }

    const parts = [element.tagName.toLowerCase()];
    if (element.name) {
      parts.push(`[name="${element.name}"]`);
    }
    if (element.type) {
      parts.push(`[type="${element.type}"]`);
    }
    if (element.classList.length) {
      parts.push(`.${Array.from(element.classList).slice(0, 3).join(".")}`);
    }

    return parts.join("");
  };

  const isLikelyVisible = (element) => {
    // offsetWidth/Height are 0 when any ancestor has display:none
    if (element.offsetWidth === 0 && element.offsetHeight === 0) return false;
    const style = window.getComputedStyle(element);
    return style.display !== "none" && style.visibility !== "hidden" && style.opacity !== "0";
  };

  const detectButtons = () => {
    // Primary selector for obvious interactive elements
    const primary = Array.from(document.querySelectorAll(
      'button, input[type="button"], input[type="submit"], input[type="reset"]'
    ));

    // Links - treat separately
    const links = Array.from(document.querySelectorAll(
      'a[href]:not([href=""]):not([href="#"]), a[role="button"]'
    ));

    const allElements = [...primary, ...links];

    // Filter out any element that is a descendant of another element in the list
    const filtered = allElements.filter((el, _, arr) => {
      return !arr.some((other) => other !== el && other.contains(el));
    });

    // Deduplicate by text only, preferring buttons/inputs over other elements
    const textMap = new Map();
    
    for (const element of filtered) {
      const text = getVisibleText(element).toLowerCase().trim();
      if (!text) continue;
      
      const existing = textMap.get(text);
      if (!existing) {
        textMap.set(text, element);
        continue;
      }
      
      // If current element is a button/input and existing is not, replace it
      const currentIsButton = element.tagName === 'BUTTON' || element.tagName === 'INPUT';
      const existingIsButton = existing.tagName === 'BUTTON' || existing.tagName === 'INPUT';
      
      if (currentIsButton && !existingIsButton) {
        textMap.set(text, element);
      }
    }

    const deduplicated = Array.from(textMap.values());

    return deduplicated.map((element, index) => {
      const text = getVisibleText(element);
      const ariaLabel = element.getAttribute("aria-label") || "";
      const title = element.getAttribute("title") || "";
      const name = text || ariaLabel || title || element.getAttribute("value") || `Button ${index + 1}`;

      return {
        index: index + 1,
        name,
        selector: getButtonSelector(element),
        tag: element.tagName.toLowerCase(),
        type: element.getAttribute("type") || "",
        visible: isLikelyVisible(element),
        disabled: element.matches(":disabled") || element.getAttribute("aria-disabled") === "true",
        href: element.getAttribute("href") || "",
        text,
        ariaLabel,
        title
      };
    });
  };

  const detectFrameworks = () => {
    const findings = new Map();
    const generator = metaGenerator();
    const html = document.documentElement;
    const body = document.body;
    const nextData = document.getElementById("__NEXT_DATA__");
    const nuxtData = document.getElementById("__NUXT_DATA__") || document.getElementById("__NUXT__");

    if (window.__NEXT_DATA__ || nextData || hasAnyScriptMatch([/_next\//i])) {
      addFinding(findings, "nextjs", "Next.js", 0.98, "Found __NEXT_DATA__ marker or _next asset path");
    }

    if (window.__NUXT__ || nuxtData || hasAnyScriptMatch([/_nuxt\//i])) {
      addFinding(findings, "nuxt", "Nuxt", 0.98, "Found __NUXT__ marker or _nuxt asset path");
    }

    if (document.querySelector("astro-island") || hasAnyScriptMatch([/astro/i, /_astro\//i])) {
      addFinding(findings, "astro", "Astro", 0.96, "Found Astro island markup or Astro asset path");
    }

    if (window.__remixContext || hasAnyScriptMatch([/build\/routes/i, /entry\.client/i]) || document.querySelector('script[data-remix-run]')) {
      addFinding(findings, "remix", "Remix", 0.92, "Found Remix runtime marker");
    }

    if (window.__APOLLO_STATE__ && nextData) {
      addFinding(findings, "nextjs", "Next.js", 0.99, "Apollo state embedded alongside Next.js data");
    }

    if (window.__PREACT_DEVTOOLS__ || hasAnyScriptMatch([/preact/i])) {
      addFinding(findings, "preact", "Preact", 0.82, "Found Preact global or script reference");
    }

    if (window.__REACT_DEVTOOLS_GLOBAL_HOOK__ || hasAnySelector(["[data-reactroot]", "[data-reactid]"]) || hasAnyScriptMatch([/react(?:-dom)?(?:\.production|\.development)?(?:\.min)?\.js/i])) {
      addFinding(findings, "react", "React", 0.8, "Found React devtools hook, root attribute, or React asset");
    }

    if (hasAnySelector(["[data-v-app]", "[data-vue-meta]", "[data-server-rendered='true']"]) || window.__VUE__ || hasAnyScriptMatch([/vue(?:\.runtime|\.global)?(?:\.prod)?(?:\.min)?\.js/i])) {
      addFinding(findings, "vue", "Vue", 0.86, "Found Vue mount marker or script reference");
    }

    if (hasAnySelector(["[ng-version]", "[ng-app]", "[data-ng-app]"]) || hasAnyScriptMatch([/angular(?:\.min)?\.js/i, /runtime\.[a-z0-9]+\.js/i])) {
      addFinding(findings, "angular", "Angular", 0.84, "Found Angular bootstrap attributes or runtime asset");
    }

    if (hasAnySelector(["[data-svelte-h]", "[data-sveltekit-preload-data]"]) || hasAnyScriptMatch([/svelte/i, /_app\/immutable/i])) {
      addFinding(findings, "svelte", "Svelte or SvelteKit", 0.84, "Found Svelte hydration attribute or immutable app assets");
    }

    if (window.Alpine || hasAnySelector(["[x-data]", "[x-show]", "[x-bind]"]) || hasAnyScriptMatch([/alpine(?:\.min)?\.js/i])) {
      addFinding(findings, "alpine", "Alpine.js", 0.94, "Found Alpine directives or runtime");
    }

    if (window.Stimulus || hasAnySelector(["[data-controller]", "[data-action]"]) || hasAnyScriptMatch([/stimulus(?:\.umd)?(?:\.min)?\.js/i])) {
      addFinding(findings, "stimulus", "Stimulus", 0.88, "Found Stimulus controller markers or runtime");
    }

    if (window.litHtml || hasAnySelector(["[lit-part]", "[data-lit]"]) || hasAnyScriptMatch([/lit(?:-html|-element)?/i])) {
      addFinding(findings, "lit", "Lit", 0.74, "Found Lit markers or runtime reference");
    }

    if (window.Ember || hasAnySelector([".ember-view"]) || hasAnyScriptMatch([/ember(?:\.prod)?(?:\.min)?\.js/i])) {
      addFinding(findings, "ember", "Ember", 0.9, "Found Ember view marker or runtime");
    }

    if (window.Backbone || hasAnyScriptMatch([/backbone(?:\.min)?\.js/i])) {
      addFinding(findings, "backbone", "Backbone.js", 0.76, "Found Backbone global or runtime reference");
    }

    if (window.jQuery || window.$?.fn?.jquery || hasAnyScriptMatch([/jquery(?:\.min)?\.js/i])) {
      addFinding(findings, "jquery", "jQuery", 0.96, "Found jQuery global or runtime reference");
    }

    if (window.bootstrap || hasAnySelector(["[data-bs-toggle]", ".container", ".row"]) || hasAnyScriptMatch([/bootstrap(?:\.bundle)?(?:\.min)?\.(?:js|css)/i])) {
      addFinding(findings, "bootstrap", "Bootstrap", 0.68, "Found Bootstrap runtime, data attribute, or asset");
    }

    if (hasAnyScriptMatch([/tailwind(?:\.min)?\.css/i, /cdn\.tailwindcss\.com/i]) || hasAnySelector(["[class*='sm:']", "[class*='md:']", "[class*='lg:']"])) {
      addFinding(findings, "tailwind", "Tailwind CSS", 0.62, "Found Tailwind utility classes or asset reference");
    }

    if (/wordpress/i.test(generator) || body?.classList.contains("wp-site-blocks") || hasAnyScriptMatch([/wp-content/i, /wp-includes/i])) {
      addFinding(findings, "wordpress", "WordPress", 0.98, "Found WordPress generator, classes, or asset paths");
    }

    if (/drupal/i.test(generator) || hasAnySelector(["[data-drupal-selector]"]) || hasAnyScriptMatch([/sites\/default\/files/i, /drupalSettings/i])) {
      addFinding(findings, "drupal", "Drupal", 0.96, "Found Drupal selector, generator, or asset paths");
    }

    if (hasAnyScriptMatch([/cdn\.shopify\.com/i, /shopifycloud/i]) || window.Shopify || /shopify/i.test(generator)) {
      addFinding(findings, "shopify", "Shopify", 0.98, "Found Shopify runtime, asset, or generator");
    }

    if (hasAnyScriptMatch([/static\.wixstatic\.com/i, /wix-code/i]) || window.wixBiSession || /wix/i.test(generator)) {
      addFinding(findings, "wix", "Wix", 0.98, "Found Wix asset host or runtime markers");
    }

    if (hasAnyScriptMatch([/static\.squarespace\.com/i]) || /squarespace/i.test(generator)) {
      addFinding(findings, "squarespace", "Squarespace", 0.98, "Found Squarespace generator or asset host");
    }

    if (hasAnyScriptMatch([/webflow\.com/i, /webflow(?:\.min)?\.js/i]) || html?.hasAttribute("data-wf-page") || html?.hasAttribute("data-wf-site")) {
      addFinding(findings, "webflow", "Webflow", 0.98, "Found Webflow page markers or runtime");
    }

    if (hasAnyScriptMatch([/gatsby/i]) || window.___gatsby || document.getElementById("___gatsby")) {
      addFinding(findings, "gatsby", "Gatsby", 0.92, "Found Gatsby root or runtime marker");
    }

    return {
      scannedAt: new Date().toISOString(),
      page: {
        title: document.title,
        url: window.location.href
      },
      findings: Array.from(findings.values()).sort((left, right) => right.confidence - left.confidence),
      buttons: detectButtons(),
      forms: detectForms()
    };
  };

  // Returns all visible, enabled interactive button-like elements
  const getVisibleEnabledButtons = () => {
    const primary = Array.from(
      document.querySelectorAll(
        'button, input[type="button"], input[type="submit"], input[type="reset"], a[href], a[role="button"], [role="button"], [role="link"]'
      )
    );

    const secondary = Array.from(document.querySelectorAll('*'))
      .filter((el) => {
        if (primary.includes(el)) return false;
        const style = window.getComputedStyle(el);
        const hasPointer = style.cursor === 'pointer';
        const hasClick = el.onclick || el.hasAttribute('onclick');
        const hasLinkClass = /\b(link|btn|button)\b/i.test(el.className);
        return (hasPointer || hasClick || hasLinkClass) && el.textContent.trim().length > 0 && el.textContent.trim().length < 200;
      });

    return [...primary, ...secondary].filter(
      (el) =>
        isLikelyVisible(el) &&
        !el.matches(":disabled") &&
        el.getAttribute("aria-disabled") !== "true"
    );
  };

  // Intercepts all form submit events so form submissions go through fetch
  // instead of navigating the page. Attach at document capture level.
  const makeSubmitInterceptor = () => async (e) => {
    e.preventDefault();
    const form = e.target;
    const action = form.action || window.location.href;
    const method = (form.method || "GET").toUpperCase();
    const formData = new FormData(form);
    const params = new URLSearchParams(formData).toString();
    const url = method === "POST" ? action : `${action}${params ? "?" + params : ""}`;
    const init = method === "POST"
      ? { method: "POST", body: new URLSearchParams(formData), credentials: "include" }
      : { credentials: "include" };
    try { await fetch(url, init); } catch (_) {}
  };

  // Trigger a single element: fetch link targets, click everything else.
  // Form submissions are handled by the document-level submit interceptor.
  const triggerElement = async (el) => {
    const href = el.getAttribute("href") || "";
    if (href && href !== "#" && !href.startsWith("javascript:")) {
      const absoluteUrl = new URL(href, window.location.href).href;
      const response = await fetch(absoluteUrl, { credentials: "include" });
      return { method: "link-fetch", url: absoluteUrl, status: response.status };
    }
    el.click();
    return { method: "click" };
  };

  const triggerButtons = async (delayMs = 700) => {
    const elements = getVisibleEnabledButtons();
    const results = [];
    const submitInterceptor = makeSubmitInterceptor();
    document.addEventListener("submit", submitInterceptor, { capture: true });

    for (const el of elements) {
      let outcome;
      try {
        outcome = await triggerElement(el);
      } catch (error) {
        outcome = { method: "error", error: String(error) };
      }
      results.push({
        selector: getButtonSelector(el),
        name: getVisibleText(el) || el.getAttribute("aria-label") || el.getAttribute("value") || "(unnamed)",
        ...outcome
      });
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }

    document.removeEventListener("submit", submitInterceptor, { capture: true });
    return { triggered: results.length, results };
  };

  const triggerButtonByIndex = async (targetIndex) => {
    const elements = getVisibleEnabledButtons();
    const el = elements[targetIndex - 1];
    if (!el) return { ok: false, error: `No visible button at index ${targetIndex}` };

    const submitInterceptor = makeSubmitInterceptor();
    document.addEventListener("submit", submitInterceptor, { capture: true });
    try {
      const outcome = await triggerElement(el);
      return { ok: true, ...outcome };
    } catch (error) {
      return { ok: false, error: String(error) };
    } finally {
      document.removeEventListener("submit", submitInterceptor, { capture: true });
    }
  };

  window.GhostcrawlerDetector = { detectFrameworks, triggerButtons, triggerButtonByIndex, fillFields, getVisibleEnabledButtons };
})();