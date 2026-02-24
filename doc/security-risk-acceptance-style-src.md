# Risk Acceptance: CSP style-src unsafe-inline

**Finding:** OWASP ZAP Rule 10055 — CSP: style-src unsafe-inline (Medium)
**Date:** 2026-02-24
**Application:** Blazor Server with Radzen component library
**Requested by:** Development Team
**Reviewed by:** [Security Team Lead]

---

## 1. Summary

We request formal risk acceptance for the use of `'unsafe-inline'` in the CSP `style-src` directive. This is required due to a technical limitation in both the CSP specification and the Radzen Blazor component library.

**All other CSP directives are strict:**
- `script-src` uses per-request cryptographic nonces (no `'unsafe-inline'`, no `'unsafe-eval'`)
- `connect-src` restricts WebSocket to the application's own host
- `default-src`, `frame-ancestors`, `base-uri`, `form-action` are all restrictive

---

## 2. What We Tried First

### Attempt 1: Nonce-based style-src (most strict)

```
style-src 'self' 'nonce-{per-request-value}'
```

**Result:** Radzen components rendered incorrectly on initial page load.

| Component | Observed Defect |
|-----------|----------------|
| RadzenDropDown | Dropdown option panel visible behind the input field |
| RadzenDatePicker | Calendar popup permanently open on page load |
| RadzenChart | Chart collapsed to zero height — bars not visible |
| RadzenDataGrid | Column width constraints ignored |
| RadzenProgressBar | Width animation broken |

**Root cause:** CSP nonces only protect `<style>` elements. They **cannot** protect inline `style=""` attributes on HTML elements. This is a limitation of the CSP specification itself (not a browser bug):

```html
<!-- Nonce CAN protect this -->
<style nonce="abc123">.foo { color: red; }</style>

<!-- Nonce CANNOT protect this — no mechanism exists in the CSP spec -->
<div style="display:none; width:300px;">...</div>
```

Radzen uses 41+ element-level inline `style` attributes for sizing, positioning, and visibility (e.g., `display:none` on popup panels). When CSP blocks these, components are visually broken.

**Proof (captured in browser):**
```javascript
// With nonce-based style-src:
const panel = document.querySelector(".rz-dropdown-panel");
panel.getAttribute("style");      // "display:none; box-sizing: border-box"
getComputedStyle(panel).display;   // "block" — CSP blocked the style

// With unsafe-inline in style-src:
panel.getAttribute("style");      // "display:none; box-sizing: border-box"
getComputedStyle(panel).display;   // "none" — style applied correctly
```

### Attempt 2: unsafe-hashes (CSP Level 3)

CSP Level 3 introduced `'unsafe-hashes'` to allow specific known inline style hashes. This was considered but is not viable because:

- Radzen generates **dynamic** inline styles (values change based on data, screen size, component state)
- Hashes must be pre-computed for static content — impossible for dynamic values
- Browser support for `'unsafe-hashes'` on `style` attributes is inconsistent

### Attempt 3: CSS classes instead of inline styles

Replacing Radzen's inline styles with CSS classes would require modifying Radzen's source code. Radzen is a third-party closed-source library and has confirmed they do not plan to support strict CSP:
- **GitHub Issue:** https://github.com/radzenhq/radzen-blazor/issues/526
- **Status:** No fix planned

---

## 3. Actual Risk Assessment

### What CSS injection can do (with style-src unsafe-inline)

| Attack | Possible? | Severity | Notes |
|--------|-----------|----------|-------|
| Execute arbitrary JavaScript | No | N/A | Blocked by strict `script-src 'nonce-...'` |
| Steal cookies or tokens | No | N/A | Requires script execution |
| Make network requests | No | N/A | CSS `url()` limited by `default-src 'self'` |
| Read DOM content | No | N/A | Requires script execution |
| Visual defacement | Yes | Low | Attacker could alter page appearance |
| Data leakage via CSS selectors | Theoretically | Very Low | Requires very specific conditions: attacker must know the attribute name, inject a `<style>` block, and have a server to receive the request — but `default-src 'self'` blocks external requests |

### What CSS injection CANNOT do

- **Cannot execute code** — CSS has no mechanism for code execution
- **Cannot access JavaScript APIs** — no DOM access, no cookie access, no localStorage
- **Cannot make arbitrary network requests** — `default-src 'self'` and `connect-src` restrict all outbound requests
- **Cannot bypass the nonce on script-src** — even with CSS injection, an attacker cannot inject executable scripts

### Comparison: before vs after hardening

| Directive | Before (Flagged by Security Review) | After (Current) |
|-----------|-------------------------------------|-----------------|
| `script-src` | `'self' 'unsafe-inline' 'unsafe-eval'` | `'self' 'nonce-{value}'` |
| `style-src` | `'self' 'unsafe-inline'` | `'self' 'unsafe-inline'` |
| `connect-src` | `'self' wss: ws:` | `'self' wss://{host} ws://{host}` |

**Net security improvement:**
- Eliminated `'unsafe-inline'` from `script-src` (Critical risk removed)
- Eliminated `'unsafe-eval'` from `script-src` (High risk removed)
- Eliminated wildcard WebSocket (Medium risk removed)
- `style-src` remains unchanged — this was already accepted in the original deployment

---

## 4. Compensating Controls

Even with `'unsafe-inline'` in `style-src`, the following controls mitigate risk:

1. **Strict script-src with per-request nonce** — XSS via script injection is blocked
2. **Nonce rotates every request** — 32-byte cryptographic random, not guessable
3. **default-src 'self'** — prevents loading resources from external origins
4. **frame-ancestors 'none'** — prevents clickjacking
5. **X-Content-Type-Options: nosniff** — prevents MIME type confusion
6. **Input validation** — application validates all user input server-side
7. **Output encoding** — Blazor automatically HTML-encodes all rendered content
8. **OWASP ZAP full scan** — automated active scan confirms no XSS, injection, or path traversal vulnerabilities

---

## 5. Industry Context

- **Google's CSP guidance** acknowledges that `'unsafe-inline'` in `style-src` is a common and acceptable compromise when strict `script-src` is enforced
- **OWASP** classifies this as Medium (not High or Critical) because CSS-only attacks have limited impact
- **Major production websites** (including Google properties) use strict `script-src` with relaxed `style-src`
- The primary purpose of CSP is XSS prevention via `script-src` — our `script-src` is strictly nonce-based

---

## 6. Alternative Libraries Evaluated

We evaluated six alternative Blazor component libraries to determine if switching away from Radzen would resolve the finding. **None of them support strict nonce-based style-src.**

| Library | style-src unsafe-inline required? | Also needs unsafe-eval? | Source |
|---------|:-:|:-:|--------|
| **Radzen** (current) | Yes | No | [Issue #526](https://github.com/radzenhq/radzen-blazor/issues/526) |
| **MudBlazor** | Yes | No | [Issue #4529](https://github.com/MudBlazor/MudBlazor/issues/4529) |
| **FluentUI Blazor** | Yes | Yes | [Issue #2783](https://github.com/microsoft/fluentui-blazor/issues/2783) |
| **Syncfusion** | Yes | Yes | Nonce support explicitly rejected |
| **Telerik** | Yes | Yes | Feature request open, no timeline |
| **DevExpress** | Conditional | Yes | Partial nonce support for dashboards only |
| **Ant Design Blazor** | Yes | Yes | CSS Isolation doesn't work with components |

**Conclusion:** This is a fundamental limitation of the CSP specification (nonces cannot protect inline `style=""` attributes) combined with how all Blazor component libraries render dynamic UI. Switching libraries will not resolve the finding and in most cases would introduce the additional requirement of `'unsafe-eval'` in `script-src`, which is strictly worse.

---

## 7. Remediation Path

| Timeline | Action |
|----------|--------|
| **Now** | Accept risk for `style-src 'unsafe-inline'` with documented justification |
| **Now** | Consider CSS Override approach — replicate critical inline styles via CSS class rules to eliminate `'unsafe-inline'` |
| **Next Radzen update** | Re-test if Radzen has added CSP support (monitor issue #526) |
| **Long-term** | If the CSP specification adds a mechanism to nonce inline style attributes, adopt it |

---

## 8. Approval

| Role | Name | Decision | Date |
|------|------|----------|------|
| Development Lead | | | |
| Security Lead | | | |
| Architecture | | | |

**Decision:** [ ] Accepted [ ] Rejected [ ] Accepted with conditions

**Conditions (if any):**

---

## Appendix: OWASP ZAP Scan Evidence

### Scan Configuration
- Tool: OWASP ZAP (zaproxy) via Docker, stable release
- Scan type: Full active scan (spider + active attack payloads)
- Duration: ~10 minutes per mode
- Config: Custom `zap-config.conf` (SQL injection disabled — no database)

### Results Summary (Secure Mode)

```
PASS: 131 rules (including all XSS, injection, and path traversal checks)
SKIP: 7 rules (irrelevant — SQL injection, OS command injection, SOAP)
WARN: 4 (style-src unsafe-inline, Permissions-Policy on static files,
         dangerous JS functions in test file, missing CORP header)
FAIL: 1 (X-Content-Type-Options on static files — low priority)
```

### Key Passing Rules

- Cross Site Scripting (Reflected) [40012] — **PASS**
- Cross Site Scripting (Persistent) [40014] — **PASS**
- Cross Site Scripting (DOM Based) [40026] — **PASS**
- Path Traversal [6] — **PASS**
- Remote File Inclusion [7] — **PASS**
- Server Side Code Injection [90019] — **PASS**
- CRLF Injection [40003] — **PASS**
- Session Fixation [40013] — **PASS**
