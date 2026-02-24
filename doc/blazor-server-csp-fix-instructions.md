# Blazor Server CSP Security Fix — Agent Instructions

## Problem Statement

A security review flagged our Blazor Server application for using `unsafe-inline` and `unsafe-eval` in the Content Security Policy (CSP) header. These directives must be removed or replaced to pass the security review before deploying to customer environments.

**What was flagged:**

- `script-src 'unsafe-inline'` — allows arbitrary inline scripts, defeating XSS protection
- `script-src 'unsafe-eval'` — allows `eval()` and dynamic code execution
- `style-src 'unsafe-inline'` — allows arbitrary inline styles

**Target state:** A strict CSP using **nonces** and/or **SHA-256 hashes** instead of unsafe directives.

---

## Context: Why This Matters for Blazor Server

- **`unsafe-eval` is NOT required** for pure Blazor Server apps. It's only needed for Blazor WebAssembly (which uses `wasm-unsafe-eval`). If your app is purely Blazor Server, remove `unsafe-eval` entirely.
- **`unsafe-inline` for scripts** can be replaced with a per-request cryptographic **nonce** applied to legitimate `<script>` tags.
- **`unsafe-inline` for styles** cannot be fully replaced with nonces when using component libraries like Radzen, Syncfusion, Telerik, or DevExpress. CSP nonces only protect `<style>` tags — they cannot protect inline `style=""` attributes on elements, which these libraries use extensively. See `doc/csp-poc-findings.md` for the full analysis. The accepted trade-off is to keep `'unsafe-inline'` in `style-src` while making `script-src` strictly nonce-based.

---

## Implementation Steps

### Step 1: Identify Your .NET Version and Audit Current CSP

```bash
# Check the .NET version in the project file
grep -i "TargetFramework" *.csproj
```

- If `.NET 8` or later: full nonce support is available via `App.razor`.
- If `.NET 7` or earlier: **strongly recommend upgrading to .NET 8+** before proceeding. The nonce infrastructure is significantly better.

Then audit where the current CSP is set:

```bash
# Search for existing CSP configuration
grep -ri "Content-Security-Policy" --include="*.cs" --include="*.cshtml" --include="*.razor" --include="*.config" .
grep -ri "unsafe-inline\|unsafe-eval" --include="*.cs" --include="*.cshtml" --include="*.razor" .
```

Also check for any CSP `<meta>` tags in `_Host.cshtml`, `_Layout.cshtml`, or `App.razor`.

---

### Step 2: Audit Inline Scripts and Styles

Find all inline `<script>` and `<style>` blocks in your Razor/HTML files:

```bash
grep -rn "<script" --include="*.cshtml" --include="*.razor" --include="*.html" .
grep -rn "<style" --include="*.cshtml" --include="*.razor" --include="*.html" .
grep -rn "onclick\|onload\|onerror\|onsubmit" --include="*.cshtml" --include="*.razor" --include="*.html" .
```

**For each inline script found:**

1. If the script is static (e.g., `Blazor.start()` config), move it to an external `.js` file under `wwwroot/js/`.
2. If the script MUST remain inline (rare), it will need a nonce attribute.
3. Remove all inline event handlers (`onclick`, `onload`, etc.) and replace with `addEventListener` in external JS files.

**For each inline style found:**

1. Move inline styles to external `.css` files where possible.
2. For dynamic styles that must stay inline, apply nonces.

---

### Step 3: Create the Nonce Service (for .NET 8+ Blazor Server)

Create a new file `Services/BlazorNonceService.cs`:

```csharp
using Microsoft.AspNetCore.Components.Server.Circuits;

namespace YourApp.Services;

public class BlazorNonceService : CircuitHandler
{
    public string Nonce { get; set; } = string.Empty;
}
```

This service will hold the per-request nonce and make it available to Blazor components via dependency injection.

---

### Step 4: Create CSP Middleware

Create a new file `Middleware/CspMiddleware.cs`:

```csharp
using System.Security.Cryptography;
using YourApp.Services;

namespace YourApp.Middleware;

public class CspMiddleware
{
    private readonly RequestDelegate _next;

    public CspMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Generate a cryptographic nonce for this request
        var nonceBytes = new byte[32];
        RandomNumberGenerator.Fill(nonceBytes);
        var nonce = Convert.ToBase64String(nonceBytes);

        // Store nonce in HttpContext.Items so App.razor can access it
        context.Items["csp-nonce"] = nonce;

        // Set CSP header on the response
        // IMPORTANT: Do NOT include 'unsafe-inline' or 'unsafe-eval' in script-src
        var host = context.Request.Host.ToString();
        var csp = string.Join("; ",
            $"default-src 'self'",
            $"script-src 'self' 'nonce-{nonce}'",
            // style-src uses 'unsafe-inline' because CSP nonces cannot protect
            // inline style="" attributes on elements (only <style> tags).
            // Radzen/Syncfusion/Telerik require element-level inline styles.
            $"style-src 'self' 'unsafe-inline'",
            $"img-src 'self' data:",
            $"font-src 'self'",
            // Restrict WebSocket to app's own host (not bare wss: which allows any host)
            $"connect-src 'self' wss://{host} ws://{host}",
            $"frame-ancestors 'none'",
            $"base-uri 'self'",
            $"form-action 'self'"
        );

        context.Response.Headers.Append("Content-Security-Policy", csp);

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

**Important notes on the CSP directives:**

- `connect-src 'self' wss://{host} ws://{host}` — WebSocket access is restricted to the app's own host for Blazor Server's SignalR connection. Do NOT use bare `wss:` as it allows connections to any host (ZAP 10055 medium finding).
- `style-src 'self' 'unsafe-inline'` — required for Radzen and other UI libraries that use inline `style=""` attributes. CSP nonces cannot protect element-level inline styles (only `<style>` tags). See `doc/csp-poc-findings.md` for full analysis.
- If you use external CDNs (e.g., Bootstrap from a CDN, Google Fonts), add those origins explicitly (e.g., `style-src 'self' 'unsafe-inline' https://fonts.googleapis.com`).
- `frame-ancestors 'none'` prevents clickjacking (equivalent to `X-Frame-Options: DENY`).

---

### Step 5: Register Services and Middleware in `Program.cs`

```csharp
// --- Service Registration ---
// Add BEFORE builder.Build()

builder.Services.TryAddEnumerable(
    ServiceDescriptor.Scoped<CircuitHandler, BlazorNonceService>(
        sp => sp.GetRequiredService<BlazorNonceService>()));
builder.Services.AddScoped<BlazorNonceService>();

// --- Middleware Pipeline ---
// Add AFTER app.UseRouting() but BEFORE app.MapBlazorHub() / app.MapRazorComponents()

app.UseCsp();
```

Required `using` statements for `Program.cs`:

```csharp
using Microsoft.AspNetCore.Components.Server.Circuits;
using Microsoft.Extensions.DependencyInjection.Extensions;
using YourApp.Services;
using YourApp.Middleware;
```

---

### Step 6: Wire the Nonce into App.razor (or _Host.cshtml)

**If using .NET 8+ with `App.razor`:**

```razor
@using System.Security.Cryptography
@inject BlazorNonceService NonceService

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <base href="/" />

    @* Apply nonce to any inline styles if absolutely necessary *@
    <link rel="stylesheet" href="css/app.css" />
    <link rel="stylesheet" href="YourApp.styles.css" />

    <HeadOutlet @rendermode="InteractiveServer" />
</head>
<body>
    <Routes @rendermode="InteractiveServer" />

    @* Apply nonce to the Blazor script tag *@
    <script src="_framework/blazor.web.js" nonce="@_nonce"></script>

    @* If you have any remaining inline scripts, they MUST have the nonce *@
    @* Example: <script nonce="@_nonce">Blazor.start({...})</script> *@
</body>
</html>

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

**If using older `_Host.cshtml`:**

```cshtml
@{
    var nonce = (string)(HttpContext.Items["csp-nonce"] ?? "");
}
<!DOCTYPE html>
<html>
<head>
    <link rel="stylesheet" href="css/site.css" />
</head>
<body>
    <component type="typeof(App)" render-mode="ServerPrerendered" />
    <script src="_framework/blazor.server.js" nonce="@nonce"></script>
</body>
</html>
```

---

### Step 7: Fix Any Remaining Inline Scripts

If you have a `Blazor.start()` configuration block, move it to an external file:

**Before (inline — violates CSP):**
```html
<script>
    Blazor.start({
        configureSignalR: function (builder) {
            builder.withUrl("/_blazor");
        }
    });
</script>
```

**After (external file — CSP compliant):**

Create `wwwroot/js/blazor-config.js`:
```javascript
Blazor.start({
    configureSignalR: function (builder) {
        builder.withUrl("/_blazor");
    }
});
```

Then reference it:
```html
<script src="_framework/blazor.web.js" autostart="false"></script>
<script src="js/blazor-config.js"></script>
```

---

### Step 8: Handle Third-Party Component Libraries

Check if you use any of these and follow their specific CSP guidance:

| Library | Known CSP Requirements |
|---------|----------------------|
| **Syncfusion** | Requires `unsafe-eval` for some animation features; check if newer versions have fixed this |
| **Telerik** | Requires `unsafe-inline` in `style-src` for dynamic sizing; versions 6.x need `unsafe-eval` for Spreadsheet component |
| **DevExpress** | Supports nonce-based CSP via `.Nonce()` method; Knockout templates still need `unsafe-eval` |
| **MudBlazor** | Generally CSP-compatible; audit for inline styles |
| **Radzen** | Requires `unsafe-inline` in `style-src` for element-level inline styles (display:none, width, etc.). Does not plan to support strict CSP ([issue #526](https://github.com/radzenhq/radzen-blazor/issues/526)). |

**If a third-party library forces you to keep `unsafe-inline` for styles only**, this is a common acceptable compromise. Document it explicitly for the security reviewer:

```csharp
// Compromise: style-src uses 'unsafe-inline' due to [Library Name] v[X.Y]
// requirement for dynamic inline styles. Script-src is fully nonce-protected.
$"style-src 'self' 'unsafe-inline'",
```

---

### Step 9: Add Additional Security Headers

While fixing CSP, also add these recommended security headers in your middleware or `Program.cs`:

```csharp
context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
context.Response.Headers.Append("X-Frame-Options", "DENY");
context.Response.Headers.Append("Referrer-Policy", "strict-origin-when-cross-origin");
context.Response.Headers.Append("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
```

Alternatively, use the **`NetEscapades.AspNetCore.SecurityHeaders`** NuGet package which handles all of these in a structured way.

---

## Verification Checklist

After implementing the changes, verify each of these:

### 1. Application Functionality

- [ ] Application loads without errors
- [ ] SignalR connection establishes successfully (check browser console for WebSocket errors)
- [ ] All pages render correctly
- [ ] All interactive components work (buttons, forms, navigation)
- [ ] Any JS interop calls function properly

### 2. CSP Header Verification

Open browser DevTools → Network tab → check the response headers on the initial page load:

- [ ] `Content-Security-Policy` header is present
- [ ] Header does NOT contain `unsafe-inline` in `script-src` (it IS expected in `style-src`)
- [ ] Header does NOT contain `unsafe-eval` in `script-src`
- [ ] Header contains `nonce-` value in `script-src`
- [ ] `connect-src` contains host-specific `wss://` URL, not bare `wss:`
- [ ] Nonce value changes on each page refresh (verify by reloading)

### 3. Console Error Check

Open browser DevTools → Console tab:

- [ ] No CSP violation errors (these appear as `Refused to execute inline script...` or similar)
- [ ] No SignalR connection failures
- [ ] No JavaScript errors related to missing scripts

### 4. Automated Testing

```bash
# If you have existing tests, run them
dotnet test

# Check the CSP header programmatically
curl -s -D - https://localhost:5001 | grep -i "content-security-policy"
```

### 5. Security Scanner Re-test

Run the same security scanning tool used in the original review to confirm the findings are resolved.

---

## Development Environment Considerations

The nonce-based CSP will break **Browser Link** and the **hot-reload script** during development. To handle this, conditionally relax the CSP in Development only:

```csharp
public async Task InvokeAsync(HttpContext context)
{
    var nonceBytes = new byte[32];
    RandomNumberGenerator.Fill(nonceBytes);
    var nonce = Convert.ToBase64String(nonceBytes);

    context.Items["csp-nonce"] = nonce;

    var env = context.RequestServices.GetRequiredService<IWebHostEnvironment>();

    string csp;
    if (env.IsDevelopment())
    {
        // Relaxed CSP for development (Browser Link, hot reload)
        csp = string.Join("; ",
            $"default-src 'self'",
            $"script-src 'self' 'unsafe-inline' 'nonce-{nonce}'",
            $"style-src 'self' 'unsafe-inline'",
            $"connect-src 'self' wss: ws: http://localhost:* https://localhost:*"
        );
    }
    else
    {
        // Strict CSP for production
        var host = context.Request.Host.ToString();
        csp = string.Join("; ",
            $"default-src 'self'",
            $"script-src 'self' 'nonce-{nonce}'",
            $"style-src 'self' 'unsafe-inline'",
            $"img-src 'self' data:",
            $"font-src 'self'",
            $"connect-src 'self' wss://{host} ws://{host}",
            $"frame-ancestors 'none'",
            $"base-uri 'self'",
            $"form-action 'self'"
        );
    }

    context.Response.Headers.Append("Content-Security-Policy", csp);
    await _next(context);
}
```

**CRITICAL: Never deploy with the development CSP. The `env.IsDevelopment()` check ensures this automatically, but verify in your CI/CD pipeline.**

---

## Summary of Files to Create/Modify

| File | Action |
|------|--------|
| `Services/BlazorNonceService.cs` | **Create** — nonce holder service |
| `Middleware/CspMiddleware.cs` | **Create** — generates nonce, sets CSP header |
| `Program.cs` | **Modify** — register services and middleware |
| `App.razor` or `_Host.cshtml` | **Modify** — wire nonce into script/style tags |
| `wwwroot/js/blazor-config.js` | **Create** (if needed) — externalized inline scripts |
| Any `.razor`/`.cshtml` with inline scripts | **Modify** — add nonce or move to external files |

---

## References

- [Microsoft Official Docs: CSP for Blazor](https://learn.microsoft.com/en-us/aspnet/core/blazor/security/content-security-policy?view=aspnetcore-9.0)
- [Damien Bowden: Using a CSP Nonce in Blazor Web (2024)](https://damienbod.com/2024/02/19/using-a-csp-nonce-in-blazor-web/)
- [Damien Bowden: Revisiting CSP Nonce in Blazor (2025)](https://damienbod.com/2025/05/26/revisiting-using-a-content-security-policy-csp-nonce-in-blazor/)
- [GitHub: BlazorServerOidc reference implementation](https://github.com/damienbod/BlazorServerOidc)
