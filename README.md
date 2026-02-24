# Blazor Server CSP Security Demo

A .NET 8 Blazor Server application that demonstrates **Content Security Policy (CSP)** enforcement with two switchable modes:

- **Insecure mode** — uses `unsafe-inline` and `unsafe-eval` (the problem state flagged by security reviews)
- **Secure mode** — uses per-request cryptographic **nonces** (the fix)

The app includes [Radzen Blazor](https://blazor.radzen.com/) components to test real-world third-party library compatibility with strict CSP.

---

## Why This Exists

Security reviews commonly flag Blazor Server apps for using `unsafe-inline` and `unsafe-eval` in CSP headers. These directives effectively disable CSP's XSS protection. This demo project:

1. Shows **what a vulnerable CSP looks like** and proves that arbitrary scripts can execute
2. Shows **how to fix it** using per-request nonces without breaking Blazor functionality
3. Documents **which Radzen components break** under strict CSP (and why)
4. Provides a **live test page** to verify CSP enforcement in the browser

---

## Project Structure

```
BlazorCspDemo/
├── Program.cs                          # Service registration + middleware pipeline
├── appsettings.json                    # Contains "CspMode": "Secure" | "Insecure"
├── Services/
│   └── BlazorNonceService.cs           # Scoped CircuitHandler holding per-request nonce
├── Middleware/
│   └── CspMiddleware.cs                # Generates nonce, sets CSP + security headers
├── Components/
│   ├── App.razor                       # Wires nonce into <script> tags during SSR
│   ├── Layout/
│   │   ├── MainLayout.razor            # Includes RadzenComponents
│   │   └── NavMenu.razor               # CSP-safe nav (no inline onclick)
│   └── Pages/
│       ├── Home.razor                  # Landing page explaining both modes
│       ├── Counter.razor               # JS interop demo under CSP
│       ├── CspDemo.razor               # 4 live CSP tests with pass/fail indicators
│       └── RadzenDemo.razor            # 10 Radzen components for CSP compatibility testing
├── wwwroot/
│   └── js/
│       └── csp-test.js                 # External JS test functions (eval, dynamic scripts, etc.)
└── doc/
    ├── blazor-server-csp-fix-instructions.md   # Step-by-step fix instructions
    ├── implementation-plan.md                   # Architecture decisions and rationale
    └── validation-guide.md                      # Detailed testing checklist
```

---

## How It Works

### The Toggle

A single key in `appsettings.json` controls the CSP mode:

```json
{
  "CspMode": "Secure"
}
```

Change to `"Insecure"` and restart to switch modes.

### Request Flow

```
HTTP Request
    │
    ▼
CspMiddleware
    ├── Generates 32-byte cryptographic nonce (always)
    ├── Reads "CspMode" from IConfiguration
    ├── Insecure → CSP: script-src 'self' 'unsafe-inline' 'unsafe-eval'
    │   Secure   → CSP: script-src 'self' 'nonce-{value}'
    ├── Sets Content-Security-Policy response header
    ├── Sets additional security headers (X-Frame-Options, etc.)
    └── Stores nonce in HttpContext.Items["csp-nonce"]
            │
            ▼
      App.razor (SSR phase)
            ├── Reads nonce from HttpContext.Items
            ├── Sets NonceService.Nonce for Blazor components
            └── Renders <script nonce="@_nonce"> on all script tags
                    │
                    ▼
              Browser
                    ├── Insecure: all inline scripts run freely
                    └── Secure: only scripts with matching nonce execute
```

### Key Implementation Details

**`BlazorNonceService`** — A `CircuitHandler` registered as scoped. The nonce set during the initial HTTP request is preserved for the SignalR circuit's lifetime and accessible via `@inject` in any component.

**`CspMiddleware`** — Placed after `UseStaticFiles()` (so static files skip CSP headers) and before `MapRazorComponents()` (so the nonce is available during server-side rendering). In Development mode, `unsafe-inline` is added alongside the nonce for hot-reload compatibility — but CSP Level 2+ browsers ignore `unsafe-inline` when a nonce is present, so the nonce is still enforced.

**`App.razor`** — The nonce is read from `HttpContext.Items["csp-nonce"]` via a `[CascadingParameter]` and applied to every `<script>` tag: Blazor framework (`blazor.web.js`), Radzen JS, and the test script.

**NavMenu fix** — The default Blazor template includes an inline `onclick` handler in `NavMenu.razor` for mobile nav toggling. This violates CSP. We replaced it with an `addEventListener` in the external JS file — a common pattern when hardening Blazor apps for CSP.

---

## Prerequisites

- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) or later

---

## Running the App

```bash
cd BlazorCspDemo
dotnet run
```

Open the URL shown in the terminal (typically `https://localhost:5001` or `http://localhost:5180`).

### Switching Modes

```bash
# Method 1: Edit appsettings.json and restart
# Set "CspMode": "Secure" or "CspMode": "Insecure"
dotnet run

# Method 2: Environment variable (no file edit)
CspMode=Insecure dotnet run
CspMode=Secure dotnet run

# Method 3: Command-line argument
dotnet run --CspMode=Insecure
```

### Testing Production CSP

In Development, the middleware relaxes CSP for hot-reload. To test the strict production CSP:

```bash
ASPNETCORE_ENVIRONMENT=Production dotnet run
```

---

## Demo Pages

### Home (`/`)
Overview of both modes with a status indicator showing the current mode.

### CSP Demo (`/csp-demo`)
Four live tests that demonstrate CSP enforcement:

| Test | Secure Mode | Insecure Mode |
|------|-------------|---------------|
| Nonced inline script | PASS (has nonce) | PASS (unsafe-inline allows it) |
| `eval('2+2')` | BLOCKED | Executes (vulnerable) |
| Dynamic `<script>` injection | BLOCKED | Executes (vulnerable) |
| External JS function | PASS (always allowed) | PASS (always allowed) |

### Counter (`/counter`)
Two increment buttons — pure C# and JS interop — proving that external JS interop works under both CSP modes.

### Radzen Demo (`/radzen-demo`)
Ten Radzen components tested for CSP compatibility:

| Component | Purpose | CSP Risk |
|-----------|---------|----------|
| RadzenButton | Basic control | Low |
| RadzenTextBox | Form input | Low |
| RadzenDropDown | Known inline scripts ([issue #526](https://github.com/radzenhq/radzen-blazor/issues/526)) | High |
| RadzenDataGrid | Complex rendering | Medium (inline styles) |
| RadzenAccordion | `javascript:void(0)` usage | High |
| RadzenDatePicker | Popup behavior | Medium |
| RadzenChart | SVG rendering | Medium (inline styles) |
| RadzenNotification | Dynamic positioning | Medium |
| RadzenProgressBar | Animated width | Medium (inline styles) |
| RadzenTabs | Tab switching | Medium |

---

## Radzen CSP Compatibility

Radzen's official CSP guidance requires:

```
script-src 'self' 'unsafe-eval' 'wasm-unsafe-eval' 'unsafe-inline'
style-src 'self' 'unsafe-inline'
```

This effectively **disables CSP protection**. Radzen closed [issue #526](https://github.com/radzenhq/radzen-blazor/issues/526) stating they do not plan to support strict CSP. Their components use inline event handlers and `javascript:void(0)`, which cannot carry nonces.

**If your project uses Radzen and requires strict CSP, your options are:**

1. Accept Radzen's CSP requirements (weakens security posture)
2. Replace Radzen with a CSP-compatible component library
3. Contribute nonce support to Radzen upstream

---

## Security Headers

Both modes emit these additional security headers:

| Header | Value | Purpose |
|--------|-------|---------|
| `X-Content-Type-Options` | `nosniff` | Prevents MIME-type sniffing |
| `X-Frame-Options` | `DENY` | Prevents clickjacking |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Limits referrer information |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` | Restricts browser features |

---

## How to Verify

1. Open browser DevTools (F12) → **Network** tab → reload → click the document request → check **Response Headers** for `Content-Security-Policy`
2. Switch to **Console** tab → look for `Refused to execute inline script...` errors
3. Run the tests on the CSP Demo page
4. Interact with Radzen components and note console errors

See [`doc/validation-guide.md`](doc/validation-guide.md) for a complete step-by-step testing checklist.

---

## CSP Comparison

| Aspect | Secure Mode | Insecure Mode |
|--------|-------------|---------------|
| `unsafe-inline` in script-src | No | Yes |
| `unsafe-eval` in script-src | No | Yes |
| Nonce in CSP header | Yes (rotates per request) | No |
| `eval()` works | Blocked | Yes |
| Dynamic script injection | Blocked | Yes |
| Blazor framework loads | Yes | Yes |
| SignalR connection | Yes | Yes |
| External JS interop | Yes | Yes |
| Radzen components | Partially (see above) | Yes |

---

## References

- [Microsoft: CSP for Blazor](https://learn.microsoft.com/en-us/aspnet/core/blazor/security/content-security-policy)
- [Radzen CSP Issue #526](https://github.com/radzenhq/radzen-blazor/issues/526)
- [Radzen Forum: CSP Discussion](https://forum.radzen.com/t/content-security-policy/6614)
- [Damien Bowden: CSP Nonce in Blazor Web (2024)](https://damienbod.com/2024/02/19/using-a-csp-nonce-in-blazor-web/)
- [MDN: Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
