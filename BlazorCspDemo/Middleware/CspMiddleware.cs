using System.Security.Cryptography;

namespace BlazorCspDemo.Middleware;

public class CspMiddleware
{
    private readonly RequestDelegate _next;

    public CspMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var nonceBytes = new byte[32];
        RandomNumberGenerator.Fill(nonceBytes);
        var nonce = Convert.ToBase64String(nonceBytes);

        context.Items["csp-nonce"] = nonce;

        var config = context.RequestServices.GetRequiredService<IConfiguration>();
        var cspMode = config.GetValue<string>("CspMode") ?? "Secure";

        var env = context.RequestServices.GetRequiredService<IWebHostEnvironment>();

        // Restrict WebSocket connections to the app's own host rather than
        // allowing any host via bare wss:/ws: protocol schemes (ZAP 10055).
        var host = context.Request.Host.ToString();
        var connectSrc = $"connect-src 'self' wss://{host} ws://{host}";

        string csp;

        if (cspMode.Equals("Insecure", StringComparison.OrdinalIgnoreCase))
        {
            // MODE 1: INSECURE — the "problem state" flagged by security reviews
            csp = string.Join("; ",
                "default-src 'self'",
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
                "style-src 'self' 'unsafe-inline'",
                "img-src 'self' data:",
                "font-src 'self'",
                connectSrc,
                "frame-ancestors 'none'",
                "base-uri 'self'",
                "form-action 'self'"
            );
        }
        else
        {
            // MODE 2: SECURE — nonce-based CSP, no unsafe directives for scripts
            var scriptSrc = $"script-src 'self' 'nonce-{nonce}'";

            // style-src uses 'unsafe-inline' because CSP nonces only protect <style>
            // tags, not inline style="" attributes on elements. Radzen (and many UI
            // libraries) rely on element-level inline styles for positioning, sizing,
            // and visibility (e.g., display:none on popups). Without 'unsafe-inline',
            // these styles are blocked on initial SSR render, causing DatePicker popups
            // to appear open, DropDown panels to leak through, and Charts to collapse.
            // This is an accepted trade-off: CSS injection attacks are far more limited
            // than script injection, and script-src remains strictly nonce-based.
            var styleSrc = "style-src 'self' 'unsafe-inline'";

            // In Development, add unsafe-inline alongside nonce for hot-reload compatibility.
            // CSP Level 2+ browsers ignore unsafe-inline when a nonce is present.
            if (env.IsDevelopment())
            {
                scriptSrc = $"script-src 'self' 'unsafe-inline' 'nonce-{nonce}'";
            }

            csp = string.Join("; ",
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
        }

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
