# Blazor Server CSP Demo Project — Implementation Plan

## Context

A security review flagged `unsafe-inline` and `unsafe-eval` in our Blazor Server app's Content Security Policy (CSP). This demo project demonstrates the problem (insecure defaults) alongside the fix (nonce-based CSP), toggled via a single config key. It also includes **Radzen Blazor components** to test real-world third-party library compatibility with strict CSP.

**Key finding on Radzen:** Radzen officially does **not** support strict CSP ([issue #526](https://github.com/radzenhq/radzen-blazor/issues/526) closed as "won't fix"). Components like `RadzenUpload`, `RadzenAccordion`, `RadzenPager`, and `RadzenDropDown` use inline event handlers and `javascript:void(0)`, requiring `'unsafe-inline'` in `script-src`. This demo will surface exactly which components break under strict CSP and document the required compromises.

### Radzen's Official CSP Requirements (from their latest docs)

Radzen's own CSP guidance page prescribes these directives:

```
script-src 'self' 'unsafe-eval' 'wasm-unsafe-eval' 'unsafe-inline'
style-src 'self' 'unsafe-inline'
```

**This is effectively a non-strict CSP.** Analysis:

| Directive | Concern |
|---|---|
| `script-src 'unsafe-inline'` | Allows **any** inline script — defeats XSS protection entirely. This is the exact directive flagged by security reviews. |
| `script-src 'unsafe-eval'` | Allows `eval()` and dynamic code execution. Not needed for pure Blazor Server (only for WebAssembly). |
| `script-src 'wasm-unsafe-eval'` | Only relevant for Blazor WebAssembly; unnecessary for Blazor Server. |
| `style-src 'unsafe-inline'` | Allows any inline style. No nonce/hash enforcement for styles. |

**No mention of nonces or hashes** — Radzen does not support them. Their "CSP support" is simply documenting the unsafe directives required, not making components work without them.

**Implications for production:**
1. **If Radzen is mandatory:** You must accept `'unsafe-inline'` at minimum for `style-src`. For `script-src`, you may be able to use nonces for your own scripts while still needing `'unsafe-inline'` for Radzen's inline event handlers — but `'unsafe-inline'` is ignored by browsers when a nonce is present (CSP Level 2+), so this compromise doesn't actually work for scripts. The realistic options are:
   - Accept Radzen's full CSP requirements (weakens security posture significantly)
   - Replace Radzen with a CSP-compatible library
   - Contribute CSP support upstream (Radzen said they'd accept PRs)
2. **If Radzen is optional:** Remove it and use nonce-based CSP as described in the instructions doc.

---

## Prerequisites

### Install .NET 8 SDK (not currently installed)

```bash
# Option A: Homebrew (macOS)
brew install dotnet@8

# Option B: Official installer
# https://dotnet.microsoft.com/download/dotnet/8.0

# Verify
dotnet --version
```

---

## Project Structure

All under `/Users/buddhima/Projects/code-exp/blazor-csp-fix/BlazorCspDemo/`:

```
BlazorCspDemo/
├── BlazorCspDemo.csproj
├── Program.cs
├── appsettings.json
├── appsettings.Development.json
├── Services/
│   └── BlazorNonceService.cs
├── Middleware/
│   └── CspMiddleware.cs
├── Components/
│   ├── App.razor
│   ├── Routes.razor
│   ├── _Imports.razor
│   ├── Layout/
│   │   ├── MainLayout.razor
│   │   └── NavMenu.razor
│   └── Pages/
│       ├── Home.razor
│       ├── Counter.razor
│       ├── CspDemo.razor
│       └── RadzenDemo.razor      ← NEW: Radzen component CSP test page
└── wwwroot/
    └── js/
        └── csp-test.js
```

---

## Implementation Steps

### Step 1: Scaffold Project & Add Radzen

```bash
cd /Users/buddhima/Projects/code-exp/blazor-csp-fix
dotnet new blazor --interactivity Server -n BlazorCspDemo
cd BlazorCspDemo
dotnet add package Radzen.Blazor
```

### Step 2: Create `Services/BlazorNonceService.cs`

Per-request nonce holder registered as a scoped `CircuitHandler`. The middleware sets the nonce; Blazor components read it via DI.

```csharp
using Microsoft.AspNetCore.Components.Server.Circuits;
namespace BlazorCspDemo.Services;

public class BlazorNonceService : CircuitHandler
{
    public string Nonce { get; set; } = string.Empty;
}
```

### Step 3: Create `Middleware/CspMiddleware.cs`

Core dual-mode logic:
- Reads `"CspMode"` from `IConfiguration` (`"Insecure"` or `"Secure"`)
- Always generates a cryptographic nonce and stores it in `HttpContext.Items["csp-nonce"]`
- **Insecure mode:** emits CSP with `'unsafe-inline' 'unsafe-eval'`
- **Secure mode:** emits CSP with `'nonce-{value}'` only (+ dev-mode relaxation for hot-reload)
- Always adds additional security headers (X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy)

### Step 4: Update `appsettings.json`

Add toggle key:
```json
{
  "CspMode": "Secure"
}
```

Switch to `"Insecure"` and restart to toggle.

### Step 5: Update `Program.cs`

- Register `BlazorNonceService` as scoped + `CircuitHandler`
- Register Radzen services (`builder.Services.AddRadzenComponents()`)
- Add `app.UseCsp()` middleware after `UseStaticFiles()`, before `MapRazorComponents()`

### Step 6: Create `wwwroot/js/csp-test.js`

External JS with test functions:
- `changeTextColor(id, color)` — safe DOM manipulation (works in both modes)
- `tryEval()` — attempts `eval('2+2')` (blocked in Secure mode)
- `tryDynamicScript()` — injects a `<script>` element (blocked in Secure mode)
- `incrementCounterJs(val)` — simple interop for Counter page

### Step 7: Update `Components/App.razor`

- Inject `BlazorNonceService`
- Read nonce from `HttpContext.Items["csp-nonce"]` via `[CascadingParameter] HttpContext`
- Apply `nonce="@_nonce"` to `<script src="_framework/blazor.web.js">` and all other script tags
- Include Radzen theme (`<RadzenTheme>`) and Radzen JS (`Radzen.Blazor.js`) with nonce

### Step 8: Update `Components/_Imports.razor`

Add Radzen namespaces:
```razor
@using Radzen
@using Radzen.Blazor
```

### Step 9: Create `Components/Pages/Home.razor`

Landing page explaining the two modes with cards (red=Insecure, green=Secure) and links to all demo pages.

### Step 10: Update `Components/Pages/Counter.razor`

Add JS interop button alongside the default C# button to demonstrate external JS interop works under both CSP modes.

### Step 11: Create `Components/Pages/CspDemo.razor`

Primary test page:
- Displays current CSP mode (badge: green/red)
- Shows full CSP header value
- Feature status table (unsafe-inline, unsafe-eval, nonce — active/inactive)
- **4 live tests** with pass/fail indicators:
  1. Nonced inline script test (should pass in both modes)
  2. `eval()` test (blocked in Secure mode)
  3. Dynamic script injection test (blocked in Secure mode)
  4. External JS function test (passes in both modes)

### Step 12: Create `Components/Pages/RadzenDemo.razor`

Radzen-specific CSP compatibility test page. Includes these components (selected to cover known CSP-problematic patterns):

| Component | Why Included | Expected CSP Issue |
|-----------|-------------|-------------------|
| `RadzenButton` | Basic control | Should work — no inline JS |
| `RadzenTextBox` | Form input | Should work |
| `RadzenDropDown` | Known to generate inline scripts ([issue #526](https://github.com/radzenhq/radzen-blazor/issues/526)) | May trigger CSP violation |
| `RadzenDataGrid` | Complex rendering | Inline styles likely |
| `RadzenAccordion` | Uses `javascript:void(0)` + inline onclick | Will trigger CSP violation |
| `RadzenUpload` | Uses inline `onchange` handler | Will trigger CSP violation |
| `RadzenNotification` | Dynamic content | Inline styles |
| `RadzenDialog` | Modal overlay | Dynamic positioning styles |
| `RadzenChart` | SVG rendering | Inline styles for sizing |
| `RadzenDatePicker` | Popup behavior | JavaScript navigation |

Page will display a results summary showing which components work and which trigger CSP console errors.

### Step 13: Update `Components/Layout/NavMenu.razor`

Add nav links for "CSP Demo" and "Radzen Demo" pages.

### Step 14: Add `RadzenComponents` to `MainLayout.razor`

```razor
<RadzenComponents @rendermode="InteractiveServer" />
```

---

## Toggle Mechanism

```
appsettings.json: "CspMode": "Secure" | "Insecure"
         ↓
CspMiddleware reads config on each request
         ↓
   ┌─────────────────────────┐     ┌──────────────────────────────┐
   │ Insecure                │     │ Secure                       │
   │ script-src 'unsafe-*'   │     │ script-src 'nonce-{value}'   │
   │ style-src 'unsafe-*'    │     │ style-src 'nonce-{value}'    │
   │ (nonce generated but    │     │ (no unsafe directives)       │
   │  ignored by browser)    │     │                              │
   └─────────────────────────┘     └──────────────────────────────┘
```

Switch: edit `appsettings.json` → restart (`dotnet run`).
Alt: `CspMode=Insecure dotnet run` via env var.

---

## Verification

### In Browser DevTools (both modes):

1. **Network tab** → check response headers for `Content-Security-Policy`
   - Insecure: contains `'unsafe-inline' 'unsafe-eval'`
   - Secure: contains `'nonce-<base64>'`, no unsafe directives
2. **Console tab** → look for `Refused to execute inline script...` errors (Secure mode)
3. **Nonce rotation** → refresh page, verify nonce value changes in CSP header

### Functional checks:
- Blazor loads and SignalR connects (both modes)
- Counter works via C# and JS interop (both modes)
- CSP Demo page: eval blocked in Secure, allowed in Insecure
- Radzen Demo page: note which components produce CSP violations in Secure mode vs working cleanly in Insecure mode

### Radzen-specific check:
- Open Console in Secure mode, navigate to Radzen Demo
- Interact with each component, document any CSP violation errors
- Compare behavior with Insecure mode (everything should work)
- This provides a concrete report of Radzen CSP compatibility

---

## Key Files to Create/Modify

| File | Action |
|------|--------|
| `Services/BlazorNonceService.cs` | Create |
| `Middleware/CspMiddleware.cs` | Create |
| `wwwroot/js/csp-test.js` | Create |
| `Components/Pages/CspDemo.razor` | Create |
| `Components/Pages/RadzenDemo.razor` | Create |
| `Program.cs` | Modify — register services + middleware |
| `Components/App.razor` | Modify — wire nonce into script tags, add Radzen assets |
| `Components/_Imports.razor` | Modify — add Radzen usings |
| `Components/Layout/NavMenu.razor` | Modify — add nav links |
| `Components/Layout/MainLayout.razor` | Modify — add `<RadzenComponents>` |
| `Components/Pages/Home.razor` | Modify — intro page |
| `Components/Pages/Counter.razor` | Modify — add JS interop demo |
| `appsettings.json` | Modify — add `CspMode` key |

---

## References

- [Instructions doc](doc/blazor-server-csp-fix-instructions.md) — nonce service + middleware patterns
- [Radzen CSP Issue #526](https://github.com/radzenhq/radzen-blazor/issues/526) — closed, won't implement
- [Radzen Forum: CSP Discussion](https://forum.radzen.com/t/content-security-policy/6614) — community workarounds
- [Microsoft Blazor CSP Docs](https://learn.microsoft.com/en-us/aspnet/core/blazor/security/content-security-policy)
- [Radzen Get Started](https://blazor.radzen.com/get-started) — setup instructions
