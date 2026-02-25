# CSP Hardening Implementation Guide for Blazor Server + Radzen

> **Purpose**: Step-by-step guide to add Content Security Policy (CSP) hardening to a production Blazor Server application that uses Radzen components. Based on validated POC findings.
>
> **Target**: .NET 8 Blazor Server with Interactive Server render mode + Radzen Blazor UI library.
>
> **Result**: Eliminates `unsafe-inline` and `unsafe-eval` from `script-src`, and optionally eliminates `unsafe-inline` from `style-src` via the CSS Override approach.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Step 1: Audit Existing Codebase](#step-1-audit-existing-codebase)
3. [Step 2: Create the Nonce Service](#step-2-create-the-nonce-service)
4. [Step 3: Create the CSP Middleware](#step-3-create-the-csp-middleware)
5. [Step 4: Register Services in Program.cs](#step-4-register-services-in-programcs)
6. [Step 5: Wire Nonces into App.razor](#step-5-wire-nonces-into-apprazor)
7. [Step 6: Fix Inline Scripts and Event Handlers](#step-6-fix-inline-scripts-and-event-handlers)
8. [Step 7: Create the Radzen CSS Override File](#step-7-create-the-radzen-css-override-file)
9. [Step 8: Replace Inline Styles on Radzen Components](#step-8-replace-inline-styles-on-radzen-components)
10. [Step 9: Secure File Upload Endpoints](#step-9-secure-file-upload-endpoints)
11. [Step 10: Verify and Test](#step-10-verify-and-test)
12. [Troubleshooting](#troubleshooting)
13. [Quick Reference: Final CSP Header](#quick-reference-final-csp-header)

---

## 1. Prerequisites

- .NET 8 SDK
- Blazor Server app using Interactive Server render mode
- Radzen.Blazor NuGet package installed
- Access to `App.razor` (or `_Host.cshtml` for older project structure)
- Access to `Program.cs` (middleware pipeline)

---

## Step 1: Audit Existing Codebase

Before making changes, identify all CSP violations in the codebase. Run these searches from the project root:

```bash
# 1. Find where CSP headers are currently set (if any)
grep -rn "Content-Security-Policy" --include="*.cs" --include="*.cshtml" --include="*.razor" .

# 2. Find ALL inline scripts (each needs a nonce or must be moved to external file)
grep -rn "<script" --include="*.razor" --include="*.cshtml" .

# 3. Find inline event handlers (must be replaced with addEventListener)
grep -rn "onclick\|onload\|onerror\|onsubmit\|onchange\|onmouseover" --include="*.razor" --include="*.cshtml" .

# 4. Find inline styles on elements (informational — needed for CSS Override approach)
grep -rn 'style="' --include="*.razor" --include="*.cshtml" .

# 5. Find javascript: protocol usage (must be replaced)
grep -rn "javascript:" --include="*.razor" --include="*.cshtml" .

# 6. Find eval/Function usage in JS files
grep -rn "eval(\|new Function(" --include="*.js" .

# 7. Find file upload endpoints (security risk with 'self' CSP)
grep -rn "IFormFile\|ReadFormAsync\|SaveAs\|CopyToAsync" --include="*.cs" .
```

**Record all findings.** Each one must be addressed in the steps below.

---

## Step 2: Create the Nonce Service

Create a service that holds the CSP nonce for the duration of a Blazor SignalR circuit.

**Create file: `Services/BlazorNonceService.cs`**

```csharp
using Microsoft.AspNetCore.Components.Server.Circuits;

namespace YOUR_NAMESPACE.Services;

public class BlazorNonceService : CircuitHandler
{
    public string Nonce { get; set; } = string.Empty;
}
```

> **Replace `YOUR_NAMESPACE`** with your project's namespace (e.g., `MyApp.Services`).

### Why CircuitHandler?

Blazor Server uses SignalR circuits. The nonce is generated per HTTP request (during SSR), but components need access to it during the circuit's lifetime. `CircuitHandler` ensures the nonce is scoped to the circuit.

---

## Step 3: Create the CSP Middleware

Create middleware that generates a per-request cryptographic nonce and sets all security headers.

**Create file: `Middleware/CspMiddleware.cs`**

```csharp
using System.Security.Cryptography;

namespace YOUR_NAMESPACE.Middleware;

public class CspMiddleware
{
    private readonly RequestDelegate _next;

    public CspMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Generate a 32-byte cryptographic nonce per request
        var nonceBytes = new byte[32];
        RandomNumberGenerator.Fill(nonceBytes);
        var nonce = Convert.ToBase64String(nonceBytes);

        // Store nonce for access during SSR (App.razor reads this)
        context.Items["csp-nonce"] = nonce;

        var env = context.RequestServices.GetRequiredService<IWebHostEnvironment>();

        // Restrict WebSocket to app's own host (not bare wss:/ws: which allows any host)
        var host = context.Request.Host.ToString();
        var connectSrc = $"connect-src 'self' wss://{host} ws://{host}";

        // --- Script-src: nonce-based (blocks all inline scripts without nonce) ---
        var scriptSrc = $"script-src 'self' 'nonce-{nonce}'";

        // In Development, add unsafe-inline alongside nonce for hot-reload.
        // CSP Level 2+ browsers ignore unsafe-inline when a nonce is present,
        // so the nonce is still enforced in modern browsers.
        if (env.IsDevelopment())
        {
            scriptSrc = $"script-src 'self' 'unsafe-inline' 'nonce-{nonce}'";
        }

        // --- Style-src: nonce-based (CSS Override approach) ---
        // Critical Radzen inline styles are replicated via CSS class rules in
        // wwwroot/css/radzen-csp-overrides.css. JS DOM style manipulation
        // (element.style.x = ...) is NOT blocked by CSP style-src, so
        // interactive behavior works after Blazor's SignalR circuit connects.
        var styleSrc = $"style-src 'self' 'nonce-{nonce}'";

        // ALTERNATIVE: If the CSS Override approach causes issues with components
        // not tested in the POC, fall back to unsafe-inline for style-src:
        // var styleSrc = "style-src 'self' 'unsafe-inline'";

        var csp = string.Join("; ",
            "default-src 'self'",
            scriptSrc,
            styleSrc,
            "img-src 'self' data:",
            "font-src 'self'",
            connectSrc,
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "form-action 'self'"
        );

        context.Response.Headers.Append("Content-Security-Policy", csp);

        // Additional security headers
        context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
        context.Response.Headers.Append("X-Frame-Options", "DENY");
        context.Response.Headers.Append("Referrer-Policy", "strict-origin-when-cross-origin");
        context.Response.Headers.Append("Permissions-Policy",
            "camera=(), microphone=(), geolocation=()");

        await _next(context);
    }
}

public static class CspMiddlewareExtensions
{
    public static IApplicationBuilder UseCsp(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<CspMiddleware>();
    }
}
```

### Customization Notes

| Directive | When to modify |
|-----------|---------------|
| `img-src` | Add CDN origins if loading images from external sources (e.g., `img-src 'self' data: https://cdn.example.com`) |
| `font-src` | Add CDN origins if using Google Fonts (e.g., `font-src 'self' https://fonts.gstatic.com`) |
| `connect-src` | Add external API hosts if the app makes fetch/XHR calls to other origins |
| `frame-ancestors` | Change to `'self'` if the app needs to be embeddable in iframes on the same origin |
| `style-src` | Fall back to `'self' 'unsafe-inline'` if CSS Override approach causes issues (see comments in code) |

---

## Step 4: Register Services in Program.cs

Add the nonce service and CSP middleware to the application pipeline.

### 4a. Register the nonce service

Add these lines **after** other service registrations (e.g., `AddRazorComponents`, `AddRadzenComponents`):

```csharp
using Microsoft.AspNetCore.Components.Server.Circuits;
using Microsoft.Extensions.DependencyInjection.Extensions;
using YOUR_NAMESPACE.Services;
using YOUR_NAMESPACE.Middleware;

// ... existing service registrations ...

// Register BlazorNonceService as both a CircuitHandler and a directly-injectable service
builder.Services.AddScoped<BlazorNonceService>();
builder.Services.TryAddEnumerable(
    ServiceDescriptor.Scoped<CircuitHandler, BlazorNonceService>(
        sp => sp.GetRequiredService<BlazorNonceService>()));
```

### 4b. Add CSP middleware to the pipeline

**Order matters.** The CSP middleware must be placed:
- **After** `UseStaticFiles()` — so static files (CSS, JS, images) are served without CSP headers (for performance)
- **Before** `MapRazorComponents()` — so the nonce is available during SSR

```csharp
app.UseHttpsRedirection();

app.UseStaticFiles();        // <-- Static files exit here (no CSP)

app.UseCsp();                // <-- CSP middleware generates nonce, sets headers

app.UseAntiforgery();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();
```

### 4c. Static web assets in production

If you use Radzen (or any NuGet package with static assets) and run via `dotnet run` in Production mode, add this **before** `builder.Build()`:

```csharp
if (!builder.Environment.IsDevelopment())
{
    builder.WebHost.UseStaticWebAssets();
}
```

Without this, Radzen's CSS/JS files won't be served in production mode when running directly (not published).

---

## Step 5: Wire Nonces into App.razor

Modify `App.razor` (or `_Host.cshtml`) to inject the nonce into all `<script>` tags.

### 5a. Add the injection at the top of the file

```razor
@using YOUR_NAMESPACE.Services
@inject BlazorNonceService NonceService
```

### 5b. Add nonce to every `<script>` tag

Find every `<script>` tag in the file and add `nonce="@_nonce"`:

```html
<!-- Blazor framework -->
<script src="_framework/blazor.web.js" nonce="@_nonce"></script>

<!-- Radzen JS -->
<script src="_content/Radzen.Blazor/Radzen.Blazor.js" nonce="@_nonce"></script>

<!-- Any other script tags in your app -->
<script src="js/your-custom-script.js" nonce="@_nonce"></script>
```

**If you have inline scripts**, they also need the nonce:

```html
<script nonce="@_nonce">
    // This inline script will execute because it has the nonce
    console.log('CSP-compliant inline script');
</script>
```

### 5c. Add the CSS override stylesheet link

Add this in the `<head>` section, after other stylesheets:

```html
<link rel="stylesheet" href="css/radzen-csp-overrides.css" />
```

### 5d. Add the nonce wiring code

Add this `@code` block at the bottom of the file:

```razor
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

### How it works

1. During SSR, `HttpContext` is available as a cascading parameter
2. The middleware stored the nonce in `HttpContext.Items["csp-nonce"]`
3. `OnInitialized` reads it and applies it to `_nonce` (used in `<script>` tags)
4. It also sets `NonceService.Nonce` so other components can access it during the circuit

---

## Step 6: Fix Inline Scripts and Event Handlers

For each violation found in Step 1, apply the appropriate fix:

### 6a. Inline `<script>` blocks

Move code to an external `.js` file in `wwwroot/js/`:

```html
<!-- BEFORE: violates CSP -->
<script>
    Blazor.start({ configureSignalR: ... });
</script>

<!-- AFTER: move to wwwroot/js/blazor-config.js, add nonce -->
<script src="js/blazor-config.js" nonce="@_nonce"></script>
```

If you **must** keep an inline script, add `nonce="@_nonce"` to it.

### 6b. Inline event handlers

Replace with `addEventListener` in an external JS file:

```html
<!-- BEFORE: violates CSP -->
<button onclick="doSomething()">Click</button>

<!-- AFTER: CSP compliant -->
<button id="myBtn">Click</button>
```

```javascript
// In wwwroot/js/app.js
document.getElementById('myBtn').addEventListener('click', doSomething);
```

> **Note:** Blazor's `@onclick` directive is fine — it uses SignalR, not DOM event handlers.

### 6c. `javascript:` protocol

Replace with proper event handling:

```html
<!-- BEFORE -->
<a href="javascript:void(0)" onclick="toggle()">Toggle</a>

<!-- AFTER -->
<a href="#" @onclick="Toggle" @onclick:preventDefault>Toggle</a>
```

### 6d. `eval()` and `new Function()`

These are blocked by strict `script-src`. Refactor to avoid them. If a third-party library uses eval, you may need to add `'unsafe-eval'` to `script-src` for that specific case (document why).

---

## Step 7: Create the Radzen CSS Override File

This file replicates critical inline styles that Radzen components generate via `style=""` attributes. Without this, components render incorrectly during SSR when CSP blocks inline styles.

**Create file: `wwwroot/css/radzen-csp-overrides.css`**

```css
/*
 * Radzen CSP Overrides
 *
 * These CSS rules replicate the critical inline styles that Radzen components
 * generate via style="" attributes. When CSP blocks inline styles (strict
 * style-src without 'unsafe-inline'), these rules ensure components render
 * correctly during SSR.
 *
 * Note: JavaScript DOM style manipulation (element.style.x = ...) is NOT
 * blocked by CSP style-src — only HTML inline style="" attributes are.
 * So interactive behavior (opening dropdowns, positioning popups) still
 * works after Blazor's SignalR circuit takes over.
 */

/* ============================================================
 * 1. Popup / Dropdown Panels — must be hidden on initial render
 * ============================================================ */

/* RadzenDropDown: panel that holds the dropdown options list */
.rz-dropdown-panel {
    display: none;
    box-sizing: border-box;
}

/* RadzenDropDown: scrollable wrapper inside the panel */
.rz-dropdown-items-wrapper {
    max-height: 200px;
    overflow-x: hidden;
}

/* RadzenDatePicker: popup calendar container */
.rz-datepicker-popup-container {
    display: none;
}

/* ============================================================
 * 2. Calendar / DatePicker internals
 * ============================================================ */

.rz-calendar-view.rz-calendar-month-view {
    width: 100%;
}

/* ============================================================
 * 3. SVG / Chart defaults
 * ============================================================ */

.rz-chart svg {
    width: 100%;
    height: 100%;
    overflow: visible;
}

/* Axis and tick lines only — do NOT set fill:none on all paths,
   as that removes the fill color from data bar/series paths.
   Data bar fills come from Radzen theme CSS variables. */
.rz-chart svg path.rz-line,
.rz-chart svg path.rz-tick-line {
    fill: none;
    stroke-width: 1;
}

/* ============================================================
 * 4. Component sizing — replacements for inline Style params
 *    Use these CSS classes instead of Style="..." on components.
 *    Add more as needed for your specific component sizes.
 * ============================================================ */

.csp-w-300 { width: 300px; }
.csp-w-400 { width: 400px; }
.csp-w-500 { width: 500px; }
.csp-w-full { width: 100%; }
.csp-h-200 { height: 200px; }
.csp-h-300 { height: 300px; }
.csp-h-400 { height: 400px; }
.csp-h-24 { height: 24px; }
.csp-mb-1 { margin-bottom: 1rem; }
```

### Extending for additional components

If your app uses Radzen components not covered above (e.g., `RadzenDialog`, `RadzenMenu`, `RadzenSplitter`, `RadzenTooltip`), you may need to add more CSS rules. To identify what's needed:

1. Run the app with `style-src 'self' 'nonce-{nonce}'`
2. Open the page in Chrome DevTools
3. Look for visual rendering issues
4. Use this JS in the console to find all inline styles:
   ```javascript
   document.querySelectorAll('[style]').forEach(el => {
       const cls = el.className?.toString().split(' ')
           .filter(c => c.startsWith('rz-')).join(' ');
       if (cls) console.log(cls, '=>', el.getAttribute('style'));
   });
   ```
5. Add CSS rules for any critical styles (especially `display:none` on popup containers)

---

## Step 8: Replace Inline Styles on Radzen Components

Search your `.razor` files for Radzen components with `Style="..."` parameters and replace them with CSS classes from the override file.

```razor
@* BEFORE: inline styles blocked by CSP *@
<RadzenDropDown Style="width: 300px;" ... />
<RadzenDataGrid Style="margin-bottom: 1rem;" ... />
<RadzenDatePicker Style="width: 300px;" ... />
<RadzenChart Style="height: 200px;">
<RadzenProgressBar Style="height: 24px;" />

@* AFTER: CSS classes not blocked by CSP *@
<RadzenDropDown class="csp-w-300" ... />
<RadzenDataGrid class="csp-mb-1" ... />
<RadzenDatePicker class="csp-w-300" ... />
<RadzenChart class="csp-h-200">
<RadzenProgressBar class="csp-h-24" />
```

Also replace any inline `style="..."` on regular HTML elements:

```html
<!-- BEFORE -->
<div style="background: #f5f5f5; padding: 1rem;">...</div>

<!-- AFTER: move to your app.css or a component CSS file -->
<div class="my-custom-class">...</div>
```

### Finding all inline styles

```bash
grep -rn 'Style="' --include="*.razor" . | grep -i radzen
grep -rn 'style="' --include="*.razor" --include="*.cshtml" .
```

---

## Step 9: Secure File Upload Endpoints

If the app has file upload functionality, ensure uploaded files cannot bypass CSP:

### The risk

If uploads are served from `wwwroot/` (same origin), an attacker can upload a `.js` file and load it via `<script src="/uploads/evil.js"></script>`. CSP allows this because the script is from `'self'`.

### The fix

1. **Store uploads outside `wwwroot/`** (e.g., `Data/uploads/`)
2. **Validate file extensions** — reject `.js`, `.html`, `.svg`, `.htm`, `.css`
3. **Rename with GUIDs** — prevent path guessing
4. **Serve via API endpoint** with safe headers:
   ```csharp
   return Results.File(fileBytes, "application/octet-stream", originalFileName);
   // This sets Content-Disposition: attachment automatically
   ```

### Audit checklist

- [ ] No uploaded files are stored in `wwwroot/` or any static file directory
- [ ] Download endpoints return `Content-Type: application/octet-stream`
- [ ] Download endpoints return `Content-Disposition: attachment`
- [ ] File type validation rejects executable types (`.js`, `.html`, `.svg`, `.htm`)

---

## Step 10: Verify and Test

### 10a. Build and run

```bash
dotnet build
dotnet run
```

### 10b. Verify CSP header

```bash
# Check the CSP header on the homepage
curl -sI https://localhost:YOUR_PORT/ | grep -i content-security-policy

# Verify nonce is present
curl -sI https://localhost:YOUR_PORT/ | grep -o "'nonce-[^']*'"

# Verify nonce rotates (run twice, compare)
curl -sI https://localhost:YOUR_PORT/ | grep -o "'nonce-[^']*'" > /tmp/n1.txt
curl -sI https://localhost:YOUR_PORT/ | grep -o "'nonce-[^']*'" > /tmp/n2.txt
diff /tmp/n1.txt /tmp/n2.txt  # Should show differences
```

### 10c. Verify security headers

```bash
curl -sI https://localhost:YOUR_PORT/ | grep -iE "x-content-type|x-frame|referrer-policy|permissions-policy"
```

Expected:
```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

### 10d. Browser verification

1. Open the app in Chrome
2. Open DevTools (F12) > Console tab
3. Navigate through all pages
4. **Check for these errors**:
   - `Refused to execute inline script` — a `<script>` tag is missing its nonce
   - `Refused to apply inline style` — an inline `style=""` attribute was blocked (add a CSS override)
   - `Refused to evaluate a string as JavaScript` — `eval()` or `new Function()` is being called
5. Verify all Radzen components render correctly:
   - Dropdowns: panel hidden on load, opens on click
   - DatePicker: calendar hidden on load, opens on toggle
   - DataGrid: column widths correct
   - Chart: bars visible with correct colors and height
   - ProgressBar: fill visible at correct percentage
   - Tabs: switching works
   - Accordion: expand/collapse works

### 10e. Verify script-src blocks attacks

Open browser console and test:

```javascript
// These should all be BLOCKED by CSP:
eval('alert("xss")');                    // Refused to evaluate
new Function('alert("xss")')();          // Refused to evaluate
var s = document.createElement('script');
s.textContent = 'alert("xss")';
document.body.appendChild(s);            // Refused to execute inline script
```

### 10f. OWASP ZAP scan (optional but recommended)

If you have Docker/Podman:

```bash
# Start the app in Production mode
ASPNETCORE_ENVIRONMENT=Production ASPNETCORE_URLS="http://127.0.0.1:5199" \
    dotnet run --no-launch-profile &

# Run ZAP full scan
docker run --rm --network=host \
    ghcr.io/zaproxy/zaproxy:stable zap-full-scan.py \
    -t http://127.0.0.1:5199 \
    -r zap-report.html \
    -I

# On macOS with Docker Desktop, replace --network=host with:
# and use http://host.docker.internal:5199 as the target
```

**Expected ZAP results with CSS Override approach:**
- **0 Medium findings** (style-src unsafe-inline warning eliminated)
- **PASS**: All XSS, injection, and path traversal checks
- **WARN** (acceptable): Permissions-Policy on static files, Cross-Origin-Resource-Policy

---

## Troubleshooting

### Component renders incorrectly on first load but fixes itself after interaction

**Cause**: An inline `style=""` attribute is being blocked by CSP. The component fixes itself when Blazor's JavaScript takes over (JS DOM style manipulation is not blocked).

**Fix**: Identify the missing style and add a CSS rule to `radzen-csp-overrides.css`. Use DevTools to inspect the element and see what inline style was expected.

### Dropdown/popup panel is visible on page load

**Cause**: The panel's `display: none` inline style was blocked by CSP.

**Fix**: Ensure `.rz-dropdown-panel { display: none; }` is in the CSS override file. If it's a different popup component, find its CSS class and add a similar rule.

### Chart bars are outlines instead of solid fills

**Cause**: A CSS rule is setting `fill: none` too broadly on SVG paths.

**Fix**: Only target axis/tick lines, NOT data series paths:
```css
/* WRONG */
.rz-chart svg path { fill: none; }

/* CORRECT */
.rz-chart svg path.rz-line,
.rz-chart svg path.rz-tick-line { fill: none; stroke-width: 1; }
```

### "Refused to execute inline script" errors

**Cause**: A `<script>` tag is missing its `nonce` attribute.

**Fix**: Add `nonce="@_nonce"` to the script tag in `App.razor`.

### Hot-reload broken in development

**Cause**: Blazor's hot-reload uses inline scripts that don't have nonces.

**Fix**: The middleware already handles this — in Development mode, `unsafe-inline` is added alongside the nonce. Since CSP Level 2+ browsers ignore `unsafe-inline` when a nonce is present, the nonce is still enforced for security. Verify `IsDevelopment()` is being detected correctly.

### Blazor SignalR connection fails

**Cause**: `connect-src` doesn't include the correct WebSocket host.

**Fix**: The middleware derives the host dynamically from `context.Request.Host`. If you use a reverse proxy, ensure `X-Forwarded-Host` is forwarded and `app.UseForwardedHeaders()` is configured **before** the CSP middleware.

### Falling back to unsafe-inline for style-src

If the CSS Override approach causes issues with components not covered in the POC, you can fall back to the accepted-risk approach:

In `CspMiddleware.cs`, change:
```csharp
var styleSrc = $"style-src 'self' 'nonce-{nonce}'";
```
To:
```csharp
var styleSrc = "style-src 'self' 'unsafe-inline'";
```

This is a documented and acceptable trade-off. CSS injection is far more limited than script injection — it cannot execute code, access cookies, or make API calls.

---

## Quick Reference: Final CSP Header

### Strict (CSS Override — recommended)

```
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'nonce-{per-request-value}';
  style-src 'self' 'nonce-{per-request-value}';
  img-src 'self' data:;
  font-src 'self';
  connect-src 'self' wss://{host} ws://{host};
  frame-ancestors 'none';
  base-uri 'self';
  form-action 'self'
```

- No `unsafe-inline` in any directive
- Requires `wwwroot/css/radzen-csp-overrides.css`
- Must be re-tested after Radzen version updates

### Accepted Risk (fallback)

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

- `style-src 'unsafe-inline'` triggers ZAP warning (LOW risk)
- Simpler to maintain, no CSS override file needed

---

## Files Checklist

After implementation, your project should have these new/modified files:

| File | Action | Required? |
|------|--------|:---------:|
| `Services/BlazorNonceService.cs` | **Create** | Yes |
| `Middleware/CspMiddleware.cs` | **Create** | Yes |
| `Program.cs` | **Modify** — add service registration + middleware | Yes |
| `Components/App.razor` (or `_Host.cshtml`) | **Modify** — add nonce injection + CSS link | Yes |
| `wwwroot/css/radzen-csp-overrides.css` | **Create** | Yes (for strict mode) |
| `.razor` files with `Style="..."` | **Modify** — replace with CSS classes | Yes (for strict mode) |
| `.razor`/`.cshtml` files with inline scripts | **Modify** — add nonce or move to external file | Yes |
| Upload endpoints | **Modify** — move storage outside wwwroot | If applicable |
