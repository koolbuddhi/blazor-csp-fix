# CSP Hardening for Blazor Server - POC Findings & Migration Guide

This document captures the findings from the proof-of-concept (POC) project that validated Content Security Policy (CSP) hardening for a Blazor Server application using Radzen components. Use this as a reference when applying the same changes to the production application.

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [What We Tested](#what-we-tested)
3. [CSP Architecture Decisions](#csp-architecture-decisions)
4. [Finding 1: script-src Must Use Nonces, Not unsafe-inline](#finding-1-script-src-must-use-nonces-not-unsafe-inline)
5. [Finding 2: style-src Requires unsafe-inline for Radzen](#finding-2-style-src-requires-unsafe-inline-for-radzen)
6. [Finding 3: connect-src Must Restrict WebSocket Hosts](#finding-3-connect-src-must-restrict-websocket-hosts)
7. [Finding 4: Static Files Need Security Headers Too](#finding-4-static-files-need-security-headers-too)
8. [Finding 5: File Uploads Can Bypass CSP via self](#finding-5-file-uploads-can-bypass-csp-via-self)
9. [Final CSP Header (Production)](#final-csp-header-production)
10. [Step-by-Step Migration Guide](#step-by-step-migration-guide)
11. [OWASP ZAP Scan Results](#owasp-zap-scan-results)
12. [Security Trade-off Justification](#security-trade-off-justification)
13. [Testing Checklist](#testing-checklist)

---

## Executive Summary

| Aspect | Before (Insecure) | After (Secure) |
|--------|-------------------|----------------|
| `script-src` | `'self' 'unsafe-inline' 'unsafe-eval'` | `'self' 'nonce-{per-request}'` |
| `style-src` | `'self' 'unsafe-inline'` | `'self' 'unsafe-inline'` |
| `connect-src` | `'self' wss: ws:` | `'self' wss://{host} ws://{host}` |
| XSS via inline script | Possible | Blocked |
| XSS via eval() | Possible | Blocked |
| XSS via dynamic script injection | Possible | Blocked |
| Radzen components work | Yes | Yes |
| Blazor SignalR works | Yes | Yes |

**Key outcome**: `unsafe-inline` and `unsafe-eval` are fully removed from `script-src`. The only remaining `unsafe-inline` is in `style-src`, which is an accepted trade-off documented below.

---

## What We Tested

- .NET 8 Blazor Server with Interactive Server render mode
- Radzen Blazor component library (10 components)
- 25 automated integration tests (header validation)
- 8 Playwright browser tests (real Chromium)
- 15 curl-based security checks
- OWASP ZAP full active scan (spider + attack payloads)
- Manual browser verification of component rendering

---

## CSP Architecture Decisions

### Middleware Placement

```
HTTP Request
    |
    v
UseStaticFiles()      <-- Static files exit here (no CSP headers)
    |
    v
UseCsp()              <-- CSP middleware generates nonce, sets headers
    |
    v
MapRazorComponents()  <-- Nonce is available during SSR
```

**Why this order matters**: Static files (CSS, JS, images) are served before CSP middleware runs, so they don't get CSP or security headers. This is intentional for performance but means static files are not protected by `X-Content-Type-Options` etc. See [Finding 4](#finding-4-static-files-need-security-headers-too).

### Nonce Lifecycle

1. `CspMiddleware` generates a 32-byte cryptographic nonce per HTTP request
2. Nonce is stored in `HttpContext.Items["csp-nonce"]`
3. `App.razor` reads it during SSR and applies it to all `<script>` tags
4. `BlazorNonceService` (a `CircuitHandler`) holds the nonce for the SignalR circuit lifetime
5. Nonce rotates on every full page request (not on SignalR-driven partial updates)

---

## Finding 1: script-src Must Use Nonces, Not unsafe-inline

### Problem

The original CSP used `script-src 'self' 'unsafe-inline' 'unsafe-eval'`, which effectively disables all script-based XSS protection. Any injected `<script>` tag or `eval()` call executes freely.

### Solution

Replace with a per-request cryptographic nonce:

```csharp
var scriptSrc = $"script-src 'self' 'nonce-{nonce}'";
```

### What This Blocks

| Attack Vector | Before | After |
|--------------|--------|-------|
| `<script>alert('xss')</script>` injected via form input | Executes | **Blocked** |
| `eval('malicious code')` | Executes | **Blocked** |
| `document.createElement('script')` with inline code | Executes | **Blocked** |
| External JS from `'self'` origin (e.g., uploaded .js file) | Executes | Executes (see [Finding 5](#finding-5-file-uploads-can-bypass-csp-via-self)) |

### What You Must Do in the Production App

1. **Add nonce to every `<script>` tag** in `App.razor` / `_Host.cshtml`:
   ```html
   <script src="_framework/blazor.web.js" nonce="@_nonce"></script>
   <script src="_content/Radzen.Blazor/Radzen.Blazor.js" nonce="@_nonce"></script>
   ```

2. **Remove all inline event handlers** (`onclick`, `onload`, `onerror`):
   ```html
   <!-- BEFORE: violates CSP -->
   <button onclick="doSomething()">Click</button>

   <!-- AFTER: CSP compliant -->
   <button id="myBtn">Click</button>
   ```
   ```javascript
   // In external JS file
   document.getElementById('myBtn').addEventListener('click', doSomething);
   ```

3. **Move inline scripts to external files**:
   ```html
   <!-- BEFORE: violates CSP -->
   <script>
       Blazor.start({ ... });
   </script>

   <!-- AFTER: move to wwwroot/js/blazor-config.js -->
   <script src="js/blazor-config.js" nonce="@_nonce"></script>
   ```

4. **Search your codebase** for violations:
   ```bash
   # Find inline scripts
   grep -rn "<script" --include="*.razor" --include="*.cshtml" .
   # Find inline event handlers
   grep -rn "onclick\|onload\|onerror\|onsubmit\|onchange" --include="*.razor" --include="*.cshtml" .
   ```

---

## Finding 2: style-src Requires unsafe-inline for Radzen

### Problem

Initially, we set `style-src 'self' 'nonce-{value}'` for maximum strictness. This caused Radzen components to render incorrectly on the initial page load:

| Component | Symptom |
|-----------|---------|
| RadzenDropDown | Dropdown panel visible behind the input (should be hidden) |
| RadzenDatePicker | Calendar popup open on page load (should be closed) |
| RadzenChart | Collapsed to zero height (bars not visible) |
| RadzenDataGrid | Column widths ignored |
| RadzenProgressBar | Width animation broken |

**Components would fix themselves when clicked**, because Blazor's interactive mode (SignalR) re-renders components via JavaScript DOM manipulation, which bypasses CSP style restrictions.

### Root Cause

CSP nonces **only protect `<style>` tags**, not inline `style=""` attributes on HTML elements. This is a CSP specification limitation:

```html
<!-- Nonce CAN protect this -->
<style nonce="abc123">.foo { color: red; }</style>

<!-- Nonce CANNOT protect this (no mechanism exists) -->
<div style="display:none; width:300px;">...</div>
```

Radzen uses 41+ element-level inline styles for positioning, sizing, and visibility. For example, the DropDown panel uses `style="display:none"` to stay hidden until opened. When CSP blocks this, the panel is visible.

### Proof

We verified this programmatically in the browser:

```javascript
// BEFORE fix (style-src with nonce only):
const panel = document.querySelector(".rz-dropdown-panel");
panel.getAttribute("style");      // "display:none; box-sizing: border-box"
getComputedStyle(panel).display;   // "block"  <-- CSP blocked the style!

// AFTER fix (style-src with unsafe-inline):
panel.getAttribute("style");      // "display:none; box-sizing: border-box"
getComputedStyle(panel).display;   // "none"   <-- style applied correctly
```

### Solution

Use `'unsafe-inline'` in `style-src` only:

```csharp
var styleSrc = "style-src 'self' 'unsafe-inline'";
```

**This is an accepted trade-off.** See [Security Trade-off Justification](#security-trade-off-justification).

### What You Must Do in the Production App

1. Set `style-src 'self' 'unsafe-inline'` in your CSP middleware
2. Do NOT add `'unsafe-inline'` to `script-src` (that's the critical directive)
3. If you later remove Radzen or switch to a CSP-compatible library, you can tighten `style-src` to nonce-based

---

## Finding 3: connect-src Must Restrict WebSocket Hosts

### Problem

The initial CSP used bare protocol schemes for WebSocket:

```
connect-src 'self' wss: ws:
```

This allows WebSocket connections to **any host on the internet**. If an attacker achieves XSS, they could open a WebSocket to an attacker-controlled server to exfiltrate data, and CSP would not block it.

OWASP ZAP flagged this as **Medium** risk (rule 10055: CSP Wildcard Directive).

### Solution

Restrict WebSocket to the app's own host, derived dynamically from the request:

```csharp
var host = context.Request.Host.ToString();
var connectSrc = $"connect-src 'self' wss://{host} ws://{host}";
```

This produces (for example):
```
connect-src 'self' wss://myapp.example.com ws://myapp.example.com
```

Blazor's SignalR connection goes to the same host, so this doesn't break anything.

### What You Must Do in the Production App

1. Replace bare `wss: ws:` with host-specific URLs
2. Use `context.Request.Host` to derive the host dynamically (works across environments)
3. If the app uses a reverse proxy with a different public hostname, ensure the `Host` header is forwarded correctly (the proxy should set `X-Forwarded-Host` and `app.UseForwardedHeaders()` should be configured)
4. If the app connects to external WebSocket endpoints (e.g., third-party APIs), add those hosts explicitly:
   ```csharp
   var connectSrc = $"connect-src 'self' wss://{host} ws://{host} wss://api.example.com";
   ```

---

## Finding 4: Static Files Need Security Headers Too

### Problem

OWASP ZAP flagged `X-Content-Type-Options` header missing on static files (CSS, JS, images). This is because `UseStaticFiles()` is placed before the CSP middleware in the pipeline, so static files bypass all security headers.

### Why This Matters

Without `X-Content-Type-Options: nosniff`, a browser could MIME-sniff a file and interpret it as a different type. For example, a `.txt` file could be interpreted as JavaScript if it contains script-like content.

### What You Can Do in the Production App

Option A: Configure `StaticFileOptions` to add headers:

```csharp
app.UseStaticFiles(new StaticFileOptions
{
    OnPrepareResponse = ctx =>
    {
        ctx.Context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    }
});
```

Option B: Use a response headers middleware placed **before** `UseStaticFiles()`:

```csharp
app.Use(async (context, next) =>
{
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    await next();
});
app.UseStaticFiles();
app.UseCsp();  // CSP middleware for dynamic pages
```

### Note

This is a **low severity** issue. ZAP flags it as FAIL because of the config rule, but the real-world risk is minimal for CSS/JS/image files served from your own origin. Prioritize the `script-src` and `connect-src` fixes first.

---

## Finding 5: File Uploads Can Bypass CSP via self

### Problem

If your application allows file uploads and serves them as static files from the same origin, an attacker can upload a `.js` file and load it via a `<script src="/uploads/evil.js"></script>` tag. CSP allows this because the script is from `'self'`.

This works even with nonce-based CSP if the attacker can inject HTML that references the uploaded file.

### Solution

1. **Never serve user uploads as static files from the same origin**
2. Store uploads outside `wwwroot/` (e.g., `Data/uploads/`)
3. Serve via an API endpoint with:
   - `Content-Type: application/octet-stream` (prevents script execution)
   - `Content-Disposition: attachment` (forces download)
4. Validate file extensions and MIME types (reject `.js`, `.html`, `.svg`)
5. Use a GUID filename to prevent path guessing

### What You Must Do in the Production App

Audit all file upload endpoints and ensure:
- [ ] Uploaded files are NOT in `wwwroot/` or any static file directory
- [ ] Download endpoints set `Content-Disposition: attachment`
- [ ] File type validation rejects executable types (`.js`, `.html`, `.svg`, `.htm`)

---

## Finding 6: No Blazor UI Library Supports Strict style-src

### Problem

Given that `style-src 'unsafe-inline'` is required for Radzen, we evaluated whether switching to an alternative Blazor component library would eliminate the ZAP Medium finding.

### Libraries Evaluated

| Library | script-src nonce | style-src nonce | Needs unsafe-inline (styles) | Needs unsafe-eval | Notes |
|---------|:---:|:---:|:---:|:---:|-------|
| **Radzen** (current) | Yes | No | Yes | No | [Issue #526](https://github.com/radzenhq/radzen-blazor/issues/526) — no fix planned |
| **MudBlazor** | Yes | No | Yes | No | [Issue #4529](https://github.com/MudBlazor/MudBlazor/issues/4529) — open, unresolved |
| **FluentUI Blazor** | Partial | No | Yes | Yes (some) | [Issue #2783](https://github.com/microsoft/fluentui-blazor/issues/2783) — requires `unsafe-eval` |
| **Syncfusion** | No | No | Yes | Yes | Explicitly rejects nonce support — architectural decision |
| **Telerik** | No | No | Yes | Yes | Feature request filed, no timeline |
| **DevExpress** | No | Partial | Conditional | Yes | Best partial support, but still needs `unsafe-eval` |
| **Ant Design Blazor** | No | No | Yes | Yes | CSS Isolation doesn't work; forces inline styles |

### Root Cause

This is not a library-specific problem. It is a **fundamental incompatibility** between:

1. **CSP spec limitation**: Nonces can only protect `<style>` elements, not inline `style=""` attributes on HTML elements. No mechanism exists in CSP Level 2 or 3 to allow specific inline style attributes via nonce or hash.

2. **Blazor component architecture**: All Blazor component libraries use inline `style=""` attributes for dynamic sizing, positioning, and visibility (e.g., `display:none` on popup panels, `width:300px` on inputs, column widths in data grids). This is how Blazor renders component parameters like `Style="..."`.

### Conclusion

- **Switching libraries will not fix the ZAP Medium finding** — every library has the same limitation
- Radzen is actually one of the **better** options: it only needs `'unsafe-inline'` in `style-src`. Most alternatives additionally need `'unsafe-eval'` in `script-src`, which is strictly worse
- The only path to eliminate `'unsafe-inline'` from `style-src` is the **CSS Override approach**: replicate critical inline styles via CSS class rules in a nonced `<style>` block or external stylesheet

### What This Means for the Production App

1. Do NOT switch UI libraries solely to fix this CSP finding — it won't help
2. If switching libraries for other reasons, Radzen or MudBlazor are the best CSP options (no `unsafe-eval` needed)
3. The CSS Override approach (documented below) is the recommended technical path

---

## Final CSP Header (Production)

This is the validated CSP header from the POC:

```
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'nonce-{per-request-value}';
  style-src 'self' 'unsafe-inline';
  img-src 'self' data:;
  font-src 'self';
  connect-src 'self' wss://{host} ws://{host};
  frame-ancestors 'none';
  base-uri 'self';
  form-action 'self'
```

### Directive-by-Directive Explanation

| Directive | Value | Why |
|-----------|-------|-----|
| `default-src` | `'self'` | Fallback: only allow same-origin resources |
| `script-src` | `'self' 'nonce-...'` | Scripts must be from same origin with a matching nonce. Blocks all inline scripts, eval(), and dynamic script injection. |
| `style-src` | `'self' 'unsafe-inline'` | Allows same-origin stylesheets and inline styles. Required for Radzen component rendering. |
| `img-src` | `'self' data:` | Same-origin images plus data: URIs (used by some components for inline icons). |
| `font-src` | `'self'` | Same-origin fonts only. Add CDN origins if using Google Fonts, etc. |
| `connect-src` | `'self' wss://{host} ws://{host}` | Same-origin XHR/fetch plus WebSocket to same host only. Required for Blazor SignalR. |
| `frame-ancestors` | `'none'` | Prevents embedding in iframes (clickjacking protection). |
| `base-uri` | `'self'` | Prevents `<base>` tag injection that could redirect relative URLs. |
| `form-action` | `'self'` | Forms can only submit to same origin. |

### Additional Security Headers

These should also be set on all responses:

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

---

## Step-by-Step Migration Guide

Follow these steps to apply CSP hardening to the production application.

### Step 1: Audit Your Current State

```bash
# Find where CSP is currently set
grep -ri "Content-Security-Policy" --include="*.cs" --include="*.cshtml" --include="*.razor" .

# Find all inline scripts and event handlers
grep -rn "<script" --include="*.razor" --include="*.cshtml" .
grep -rn "onclick\|onload\|onerror\|onsubmit" --include="*.razor" --include="*.cshtml" .

# Find inline styles on elements (informational - these will be allowed)
grep -rn "style=" --include="*.razor" --include="*.cshtml" .
```

### Step 2: Create the Nonce Infrastructure

Create two files:

**`Services/BlazorNonceService.cs`**:
```csharp
using Microsoft.AspNetCore.Components.Server.Circuits;

public class BlazorNonceService : CircuitHandler
{
    public string Nonce { get; set; } = string.Empty;
}
```

**`Middleware/CspMiddleware.cs`** — copy from the POC (`BlazorCspDemo/Middleware/CspMiddleware.cs`), adapting the namespace. The key parts:
- Generate 32-byte nonce per request
- Store in `HttpContext.Items["csp-nonce"]`
- Build CSP header with `script-src 'self' 'nonce-{nonce}'`
- Use `style-src 'self' 'unsafe-inline'`
- Derive `connect-src` from `context.Request.Host`

### Step 3: Register in Program.cs

```csharp
// Services
builder.Services.TryAddEnumerable(
    ServiceDescriptor.Scoped<CircuitHandler, BlazorNonceService>(
        sp => sp.GetRequiredService<BlazorNonceService>()));
builder.Services.AddScoped<BlazorNonceService>();

// Middleware pipeline (order matters)
app.UseStaticFiles();   // Static files first (no CSP)
app.UseCsp();           // CSP for dynamic pages
app.MapRazorComponents<App>();
```

### Step 4: Wire Nonces into App.razor

```razor
@inject BlazorNonceService NonceService

<script src="_framework/blazor.web.js" nonce="@_nonce"></script>
<script src="_content/Radzen.Blazor/Radzen.Blazor.js" nonce="@_nonce"></script>
<!-- Add nonce to ALL script tags -->

@code {
    private string _nonce = string.Empty;

    [CascadingParameter]
    private HttpContext? HttpContext { get; set; }

    protected override void OnInitialized()
    {
        if (HttpContext?.Items["csp-nonce"] is string nonce)
        {
            _nonce = nonce;
            NonceService.Nonce = nonce;
        }
    }
}
```

### Step 5: Remove Inline Scripts and Event Handlers

For each violation found in Step 1:

| Pattern Found | Action |
|--------------|--------|
| `<script>...code...</script>` | Move code to `wwwroot/js/filename.js`, add `nonce="@_nonce"` to script tag |
| `onclick="handler()"` | Replace with `addEventListener` in external JS |
| `onload="init()"` | Replace with `addEventListener` in external JS |
| `javascript:void(0)` in href | Replace with `href="#"` and `addEventListener` for click |

### Step 6: Fix File Upload Endpoints

If the app has file upload functionality:

1. Move upload storage from `wwwroot/` to a non-served directory
2. Add file type validation (reject `.js`, `.html`, `.svg`)
3. Serve downloads with `Content-Disposition: attachment`
4. Rename files with GUIDs

### Step 7: Handle Development Mode

Add a development CSP relaxation for hot-reload:

```csharp
if (env.IsDevelopment())
{
    scriptSrc = $"script-src 'self' 'unsafe-inline' 'nonce-{nonce}'";
}
```

Note: CSP Level 2+ browsers ignore `'unsafe-inline'` when a nonce is present, so the nonce is still enforced in modern browsers even in dev mode.

### Step 8: Test

Run the automated tests from the POC or adapt them:

```bash
# Unit/integration tests
dotnet test

# Curl-based header checks
./BlazorCspDemo.Tests/Scripts/security-scan.sh

# OWASP ZAP full scan (requires Docker/Podman)
./BlazorCspDemo.Tests/Scripts/security-scan.sh --zap-full
```

---

## OWASP ZAP Scan Results

### Full Scan Summary (Secure Mode - After All Fixes)

| Category | Count | Details |
|----------|-------|---------|
| **PASS** | 131 | No XSS (reflected, persistent, DOM-based), no injection, no path traversal |
| **SKIP** | 7 | SQL injection and OS command injection (disabled in config - not applicable) |
| **WARN** | 4 | See below |
| **FAIL** | 1 | See below |
| **Medium** | 0 | Previously 1, now resolved |

### Warnings (Accepted)

| Rule | Finding | Justification |
|------|---------|---------------|
| 10055 | CSP: style-src unsafe-inline | Required for Radzen. script-src is strictly nonce-based. |
| 10063 | Permissions-Policy not set on static files | Static files bypass middleware. Low risk. |
| 10110 | Dangerous JS Functions in csp-test.js | Test file intentionally uses eval() to demonstrate CSP blocking. |
| 90004 | Cross-Origin-Resource-Policy missing | Informational. Not a vulnerability for same-origin apps. |

### Remaining FAIL (Low Priority)

| Rule | Finding | Remediation |
|------|---------|-------------|
| 10021 | X-Content-Type-Options missing on static files | Add via `StaticFileOptions.OnPrepareResponse`. See [Finding 4](#finding-4-static-files-need-security-headers-too). |

### Rules Disabled in ZAP Config

These are disabled in `zap-config.conf` because they're irrelevant to the app architecture:

- SQL Injection (40018-40024) — no database
- LDAP Injection (40015) — no LDAP
- Remote OS Command Injection (90020) — no shell exec
- SOAP Action Spoofing (90029) — not a SOAP API

**For the production app**: re-enable SQL injection rules if the app uses a database.

---

## Security Trade-off Justification

### Why unsafe-inline in style-src is Acceptable

Present this to the security review team:

**1. CSS injection attacks are fundamentally limited compared to script injection:**
- CSS cannot execute arbitrary code
- CSS cannot make network requests to exfiltrate data (except via `url()` in background-image, which `default-src 'self'` blocks)
- CSS cannot access cookies, localStorage, or the DOM
- The most a CSS injection can do is visual defacement or limited data leakage via attribute selectors

**2. The critical protection is in script-src:**
- `script-src 'self' 'nonce-{value}'` blocks all XSS vectors: inline scripts, eval(), dynamic script injection
- This is what security reviews primarily look for
- Nonce rotates per request (32-byte cryptographic random)

**3. The alternative breaks the application:**
- Without `'unsafe-inline'` in `style-src`, Radzen components render incorrectly on initial page load
- Popups appear open, dropdowns leak through, charts collapse
- This is a CSP specification limitation — nonces cannot protect inline `style=""` attributes on elements
- Radzen has confirmed they do not plan to support strict CSP ([issue #526](https://github.com/radzenhq/radzen-blazor/issues/526))

**4. Industry precedent:**
- Google's own CSP documentation acknowledges `'unsafe-inline'` for styles as a reasonable compromise
- Many major websites use strict `script-src` with relaxed `style-src`
- The OWASP ZAP scanner classifies this as a WARN, not a FAIL

### Risk Matrix

| CSP Directive | Risk if weakened | Our stance |
|---------------|-----------------|------------|
| `script-src 'unsafe-inline'` | **Critical** — enables XSS | Removed. Using nonce. |
| `script-src 'unsafe-eval'` | **High** — enables code injection | Removed entirely. |
| `style-src 'unsafe-inline'` | **Low** — limited CSS injection | Allowed (Radzen requirement). |
| `connect-src wss:` (wildcard) | **Medium** — data exfiltration via WebSocket | Restricted to app host only. |

---

## Testing Checklist

Use this when applying changes to the production app:

### Header Verification

- [ ] CSP header present on all dynamic pages
- [ ] `script-src` contains `'nonce-'` and does NOT contain `'unsafe-inline'` or `'unsafe-eval'`
- [ ] `style-src` contains `'self' 'unsafe-inline'`
- [ ] `connect-src` contains host-specific `wss://` URL, not bare `wss:`
- [ ] Nonce value changes on every page refresh
- [ ] `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy` all present

### Application Functionality

- [ ] Application loads without errors
- [ ] Blazor SignalR connection establishes (check browser console for WebSocket)
- [ ] All Radzen components render correctly on first load (no popups open, no layout shifts)
- [ ] Radzen DropDown, DatePicker, Chart, DataGrid all functional
- [ ] JS interop works (if used)
- [ ] File uploads work (if applicable) and uploads are NOT served from `wwwroot/`

### Browser Console

- [ ] No `Refused to execute inline script` errors
- [ ] No `Refused to apply inline style` errors (should be none with `'unsafe-inline'` in `style-src`)
- [ ] No SignalR/WebSocket connection failures
- [ ] No JavaScript errors

### Security Scan

- [ ] Run `security-scan.sh` - all 15 checks pass
- [ ] Run `security-scan.sh --zap-full` - no Medium or High findings
- [ ] No XSS findings (reflected, persistent, or DOM-based)
- [ ] No injection findings

---

## Files Reference

These are the key files from the POC that you should reference or copy:

| POC File | Purpose | Copy to Production? |
|----------|---------|-------------------|
| `BlazorCspDemo/Middleware/CspMiddleware.cs` | CSP header generation with nonce | Yes (adapt namespace) |
| `BlazorCspDemo/Services/BlazorNonceService.cs` | Nonce holder for SignalR circuits | Yes (adapt namespace) |
| `BlazorCspDemo/Components/App.razor` | Nonce wiring into script tags | Reference for pattern |
| `BlazorCspDemo.Tests/Scripts/security-scan.sh` | Automated security header checks | Yes (adapt URLs/ports) |
| `BlazorCspDemo.Tests/Scripts/zap-config.conf` | ZAP scan rule configuration | Yes (re-enable DB rules if needed) |
| `BlazorCspDemo.Tests/Integration/CspSecureHeaderTests.cs` | Integration test examples | Reference for writing tests |

---

## References

- [Microsoft: CSP for Blazor](https://learn.microsoft.com/en-us/aspnet/core/blazor/security/content-security-policy)
- [MDN: Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [Radzen CSP Issue #526](https://github.com/radzenhq/radzen-blazor/issues/526)
- [OWASP ZAP Full Scan](https://www.zaproxy.org/docs/docker/full-scan/)
- [Google CSP Evaluator](https://csp-evaluator.withgoogle.com/)
- [Damien Bowden: CSP Nonce in Blazor Web](https://damienbod.com/2024/02/19/using-a-csp-nonce-in-blazor-web/)
