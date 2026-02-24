# Blazor CSP Demo — Validation Guide

## Quick Start

```bash
cd BlazorCspDemo
dotnet run
```

Open `https://localhost:5001` (or the port shown in terminal output).

---

## Step 1: Validate Secure Mode (Default)

The app starts in Secure mode (`"CspMode": "Secure"` in `appsettings.json`).

### 1.1 Check CSP Header

1. Open Chrome/Edge DevTools (F12) → **Network** tab.
2. Reload the page (Ctrl+R / Cmd+R).
3. Click the first document request (the HTML page, usually the first entry).
4. Scroll to **Response Headers** and find `Content-Security-Policy`.

**Expected:**
```
script-src 'self' 'nonce-<base64value>'
style-src 'self' 'unsafe-inline'
connect-src 'self' wss://localhost:5001 ws://localhost:5001
```

**Verify:**
- [ ] Header is present
- [ ] `script-src` contains `nonce-` and does NOT contain `unsafe-inline` or `unsafe-eval`
- [ ] `style-src` contains `'unsafe-inline'` (required for Radzen component rendering)
- [ ] `connect-src` has host-specific `wss://` URL, NOT bare `wss:`

### 1.2 Verify Nonce Rotates

1. Note the nonce value from the CSP header.
2. Hard-refresh the page (Ctrl+Shift+R / Cmd+Shift+R).
3. Check the CSP header again.

**Expected:** The nonce value is different on each load.

### 1.3 Check Additional Security Headers

In the same Response Headers section:

- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options: DENY`
- [ ] `Referrer-Policy: strict-origin-when-cross-origin`
- [ ] `Permissions-Policy: camera=(), microphone=(), geolocation=()`

### 1.4 Run CSP Demo Page Tests

Navigate to **CSP Demo** in the sidebar.

| Test | Button | Expected Result (Secure Mode) |
|------|--------|-------------------------------|
| 1. Nonced Inline Script | "Run Nonced Inline Script Test" | **PASS** (green) — the inline script in App.razor has a valid nonce |
| 2. eval() | "Try eval()" | **BLOCKED** (green) — eval is not allowed without `unsafe-eval` |
| 3. Dynamic Script Injection | "Try Dynamic Script Injection" | **BLOCKED** (green) — injected scripts have no nonce |
| 4. External JS Function | "Change Color via External JS" | **PASS** (green) — external JS from `'self'` always works |

**Also check the Console tab (F12):**
- [ ] You should see `[CSP Demo] Inline script with nonce executed successfully.` (the nonced script ran)
- [ ] No CSP violation errors for the Blazor framework itself

### 1.5 Test Counter Page

Navigate to **Counter**.

| Action | Expected Result |
|--------|-----------------|
| Click "Click me (C# only)" | Counter increments (pure server-side, no JS involved) |
| Click "Click me (via JS Interop)" | Counter increments via `incrementCounterJs()` from external JS — should work |

### 1.6 Test Radzen Components (Secure Mode)

Navigate to **Radzen Demo**.

Open the **Console** tab in DevTools before interacting with components.

| # | Component | Action | What to Look For |
|---|-----------|--------|-----------------|
| 1 | RadzenButton | Click "Click Me" | Should work — check console for CSP errors |
| 2 | RadzenTextBox | Type text | Should work — check console |
| 3 | RadzenDropDown | Open dropdown, select an option | Known CSP issue area — check for `Refused to execute inline script` |
| 4 | RadzenDataGrid | Observe rendered table | Check for inline style violations |
| 5 | RadzenAccordion | Click accordion headers | Known to use `javascript:void(0)` — check console |
| 6 | RadzenDatePicker | Open date picker popup | Check for navigation/popup CSP errors |
| 7 | RadzenChart | Observe rendered chart | Check for inline style violations on SVG |
| 8 | RadzenNotification | Click "Show Notification" | Check if notification appears and console errors |
| 9 | RadzenProgressBar | Observe rendered bar | Check for inline style violations |
| 10 | RadzenTabs | Click between tabs | Check console for errors |

**Record your findings.** For each component, note:
- Does it render?
- Does it function (clicks, inputs)?
- Are there CSP violation errors in the console?

---

## Step 2: Validate Insecure Mode

### 2.1 Switch Mode

Edit `appsettings.json`:
```json
"CspMode": "Insecure"
```

Restart the app:
```bash
# Ctrl+C to stop, then:
dotnet run
```

Or use the environment variable override (no file edit needed):
```bash
CspMode=Insecure dotnet run
```

### 2.2 Check CSP Header

Repeat Step 1.1.

**Expected:**
```
script-src 'self' 'unsafe-inline' 'unsafe-eval'
style-src 'self' 'unsafe-inline'
```

**Verify:**
- [ ] Contains `unsafe-inline` in `script-src`
- [ ] Contains `unsafe-eval` in `script-src`
- [ ] Contains `unsafe-inline` in `style-src`
- [ ] Does **NOT** contain any `nonce-` values (nonce is generated but not included in the header)

### 2.3 Run CSP Demo Page Tests (Insecure Mode)

Navigate to **CSP Demo**.

| Test | Button | Expected Result (Insecure Mode) |
|------|--------|--------------------------------|
| 1. Nonced Inline Script | "Run Nonced Inline Script Test" | **PASS** — works because `unsafe-inline` allows all inline scripts |
| 2. eval() | "Try eval()" | **SUCCEEDED** (red) — eval is allowed, this is the insecure behavior |
| 3. Dynamic Script Injection | "Try Dynamic Script Injection" | **EXECUTED** (red) — dynamic scripts run freely, this is the vulnerability |
| 4. External JS Function | "Change Color via External JS" | **PASS** — always works |

**Key difference:** Tests 2 and 3 now succeed (shown in red), demonstrating why `unsafe-inline` and `unsafe-eval` are dangerous — arbitrary scripts can execute.

### 2.4 Test Radzen Components (Insecure Mode)

Navigate to **Radzen Demo**.

- [ ] All 10 components should render and function without any CSP errors
- [ ] Console should be clean (no `Refused to...` messages)

---

## Step 3: Compare Results

Create a comparison table from your observations:

| Component | Secure Mode | Insecure Mode | CSP Violation? |
|-----------|-------------|---------------|----------------|
| RadzenButton | ? | Works | |
| RadzenTextBox | ? | Works | |
| RadzenDropDown | ? | Works | |
| RadzenDataGrid | ? | Works | |
| RadzenAccordion | ? | Works | |
| RadzenDatePicker | ? | Works | |
| RadzenChart | ? | Works | |
| RadzenNotification | ? | Works | |
| RadzenProgressBar | ? | Works | |
| RadzenTabs | ? | Works | |

Fill in the "Secure Mode" column and "CSP Violation?" with the specific error messages from the console. This table documents exactly which Radzen components are incompatible with strict CSP.

---

## Step 4: Validate Development vs Production CSP

The middleware relaxes CSP in Development mode (adds `unsafe-inline` alongside the nonce for hot-reload compatibility). To test the true production CSP:

```bash
# Run in Production environment
ASPNETCORE_ENVIRONMENT=Production dotnet run
```

**Verify:**
- [ ] In Production + Secure mode: CSP header has nonce only, no `unsafe-inline`
- [ ] In Development + Secure mode: CSP header has both nonce and `unsafe-inline` (browsers with CSP Level 2+ ignore `unsafe-inline` when nonce is present)

---

## Step 5: Programmatic Verification (Optional)

```bash
# Check CSP header via curl
curl -s -D - https://localhost:5001 --insecure 2>/dev/null | grep -i "content-security-policy"

# Check all security headers
curl -s -D - https://localhost:5001 --insecure 2>/dev/null | grep -iE "content-security-policy|x-content-type|x-frame|referrer-policy|permissions-policy"
```

---

## Expected Summary

| Aspect | Secure Mode | Insecure Mode |
|--------|-------------|---------------|
| `unsafe-inline` in script-src | No | Yes |
| `unsafe-eval` in script-src | No | Yes |
| Nonce in CSP header | Yes | No |
| eval() works | No (blocked) | Yes |
| Dynamic script injection | No (blocked) | Yes |
| Nonced inline scripts | Yes (with nonce) | Yes (via unsafe-inline) |
| External JS | Yes | Yes |
| Blazor framework loads | Yes | Yes |
| SignalR connection | Yes | Yes |
| All Radzen components work | Partially (see table) | Yes |
| Security headers present | Yes | Yes |
