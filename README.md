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
├── Program.cs                          # Service registration + middleware pipeline + upload APIs
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
│       ├── RadzenDemo.razor            # 10 Radzen components for CSP compatibility testing
│       └── UploadDemo.razor            # File upload CSP bypass demonstration
├── wwwroot/
│   ├── js/
│   │   └── csp-test.js                 # External JS test functions + upload attack simulation
│   └── uploads/                        # Insecure upload storage (served as static files)
├── Data/
│   └── uploads/                        # Secure upload storage (outside wwwroot)
└── doc/
    ├── blazor-server-csp-fix-instructions.md   # Step-by-step fix instructions
    ├── implementation-plan.md                   # Architecture decisions and rationale
    └── validation-guide.md                      # Detailed testing checklist

BlazorCspDemo.Tests/
├── Helpers/
│   └── CspTestHelpers.cs              # Shared WebApplicationFactory + CSP header parser
├── Integration/                        # Tier 1: HTTP header tests (fast, no browser)
│   ├── CspSecureHeaderTests.cs         # 6 tests: nonce present, no unsafe-*, base64 validation
│   ├── CspInsecureHeaderTests.cs       # 4 tests: unsafe-* present, no nonce in header
│   ├── CspNonceRotationTests.cs        # 2 tests: unique nonce per request
│   ├── SecurityHeaderTests.cs          # 5 tests: X-Frame-Options, X-Content-Type, etc.
│   ├── StaticFileHeaderTests.cs        # 4 tests: static files skip CSP middleware
│   ├── CspDefaultModeTests.cs          # 1 test: missing config defaults to Secure
│   └── CspDevelopmentModeTests.cs      # 3 tests: dev vs prod CSP differences
├── Playwright/                         # Tier 2: Browser tests (real Chromium)
│   ├── PlaywrightFixture.cs            # Kestrel server + Playwright browser bootstrap
│   ├── CspSecureBrowserTests.cs        # 5 tests: eval blocked, dynamic script blocked, etc.
│   └── CspInsecureBrowserTests.cs      # 3 tests: eval succeeds, Blazor loads, JS interop
└── Scripts/
    ├── security-scan.sh                # Tier 3: curl-based header checks + optional OWASP ZAP
    └── zap-config.conf                 # ZAP scan rule configuration (disable noise, set thresholds)
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

**Upload API endpoints** — Three minimal API endpoints demonstrate insecure vs secure file upload patterns:
- `POST /api/upload/insecure` — Accepts any file, saves to `wwwroot/uploads/` (served as static files from `'self'`)
- `POST /api/upload/secure` — Validates file extension (only docx/pdf/images), saves outside wwwroot with a GUID filename
- `GET /api/download/{id}` — Serves securely-uploaded files with `Content-Type: application/octet-stream` and `Content-Disposition: attachment`

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
# HTTP + HTTPS (uses dev certificate)
ASPNETCORE_ENVIRONMENT=Production ASPNETCORE_URLS="https://localhost:7029;http://localhost:5180" dotnet run --no-launch-profile

# HTTP only (no certificate needed)
ASPNETCORE_ENVIRONMENT=Production ASPNETCORE_URLS="http://localhost:5180" dotnet run --no-launch-profile
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

### Upload Demo (`/upload-demo`)
Demonstrates why Google's CSP Evaluator flags `'self'` in `script-src` as a medium risk. If your app serves user-uploaded files as static content from the same origin, an attacker can upload a `.js` file and load it as a script — bypassing nonce-based CSP entirely.

The page has three sections:

**Insecure Upload (red card)** — Files saved to `wwwroot/uploads/` and served as static files via `UseStaticFiles()`. Since they come from the same origin, CSP treats them as `'self'`.

**Secure Upload (green card)** — Files validated (only docx/pdf/images), renamed with a GUID, stored outside wwwroot in `Data/uploads/`, and served via an API endpoint with `Content-Type: application/octet-stream` and `Content-Disposition: attachment`.

**Attack Simulation** — Uploads a crafted `.js` file to the insecure endpoint, then loads it as a `<script>` tag. Since the script is from `'self'`, CSP allows it even in Secure nonce mode.

| Scenario | CSP Mode | Upload Path | Script Executes? | Why |
|----------|----------|-------------|-----------------|-----|
| Upload .js to insecure path | **Secure** (nonce) | `wwwroot/uploads/` | **YES** | Script is from `'self'` |
| Upload .js to insecure path | Insecure | `wwwroot/uploads/` | **YES** | `unsafe-inline` allows everything |
| Upload .js to secure path | **Secure** (nonce) | `Data/uploads/` | **NO** | File type rejected; served as attachment |

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

## Automated Tests

The project includes a comprehensive test suite across three tiers. All 33 tests + 15 scan checks pass.

### Prerequisites

- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
- For Tier 2: Playwright Chromium browser (installed automatically, see below)
- For Tier 3 ZAP scan: Docker (optional)

### Tier 1: Integration Tests (25 tests, ~1.5s)

HTTP header validation using `WebApplicationFactory` — no browser needed.

```bash
dotnet test --filter "FullyQualifiedName~Integration"
```

Covers: nonce presence/rotation/format, `unsafe-inline`/`unsafe-eval` presence/absence, security headers (X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy), static file header isolation, default mode fail-safe, and dev vs production CSP differences.

### Tier 2: Playwright Browser Tests (8 tests, ~21s)

End-to-end tests using headless Chromium with a real Kestrel server and SignalR.

```bash
# Install Playwright Chromium (first time only)
# From the test project's bin directory, use the bundled Playwright CLI:
PLAYWRIGHT_BROWSERS_PATH=$HOME/Library/Caches/ms-playwright \
  BlazorCspDemo.Tests/bin/Debug/net8.0/.playwright/node/darwin-arm64/node \
  BlazorCspDemo.Tests/bin/Debug/net8.0/.playwright/package/cli.js install chromium

# Run tests
dotnet test --filter "FullyQualifiedName~Playwright"
```

Covers: Blazor SignalR connection in both modes, eval() blocked/allowed, dynamic script injection blocked, nonced inline script execution, external JS interop, and counter JS interop.

### Tier 3: Security Scan Script (15 checks)

Curl-based CSP and security header checks against a running instance.

```bash
# Run scan (curl checks only)
./BlazorCspDemo.Tests/Scripts/security-scan.sh

# Run scan + OWASP ZAP baseline (passive only, ~1-2 min)
./BlazorCspDemo.Tests/Scripts/security-scan.sh --zap

# Run scan + OWASP ZAP full scan (active spider + attack testing, ~5-15 min)
./BlazorCspDemo.Tests/Scripts/security-scan.sh --zap-full
```

Produces `security-scan-report.txt` with PASS/FAIL counts.

**ZAP scan modes:**

| Flag | Mode | What it does | Runtime |
|------|------|-------------|---------|
| `--zap` | Baseline | Passive checks only — inspects headers and responses, no attack traffic | ~1-2 min |
| `--zap-full` | Full | Active spider + active scan — crawls the app, sends attack payloads (XSS, injection, path traversal), tests CSP bypass vectors | ~5-15 min |

The full scan runs against both **Secure** and **Insecure** modes, producing two HTML reports for comparison:
- `zap-full-report.html` — Secure mode findings
- `zap-full-report-insecure.html` — Insecure mode findings

Scan rules are configured in `zap-config.conf` — SQL injection and other irrelevant rules are disabled for faster scans.

Requires Docker or Podman (with Docker alias). The ZAP Docker image (`ghcr.io/zaproxy/zaproxy:stable`, ~1.5 GB) is pulled automatically on first run.

### Run All Tests

```bash
dotnet test
```

---

## References

- [Microsoft: CSP for Blazor](https://learn.microsoft.com/en-us/aspnet/core/blazor/security/content-security-policy)
- [Radzen CSP Issue #526](https://github.com/radzenhq/radzen-blazor/issues/526)
- [Radzen Forum: CSP Discussion](https://forum.radzen.com/t/content-security-policy/6614)
- [Damien Bowden: CSP Nonce in Blazor Web (2024)](https://damienbod.com/2024/02/19/using-a-csp-nonce-in-blazor-web/)
- [MDN: Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
