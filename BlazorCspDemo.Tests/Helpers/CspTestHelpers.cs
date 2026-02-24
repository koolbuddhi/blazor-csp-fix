using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;

namespace BlazorCspDemo.Tests.Helpers;

/// <summary>
/// Custom WebApplicationFactory that allows configuring CspMode and Environment.
/// </summary>
public class CspWebApplicationFactory : WebApplicationFactory<Program>
{
    public string CspMode { get; set; } = "Secure";
    public string EnvironmentName { get; set; } = "Production";

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment(EnvironmentName);

        builder.ConfigureAppConfiguration((context, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["CspMode"] = CspMode
            });
        });
    }
}

/// <summary>
/// Utility methods for parsing CSP headers in tests.
/// </summary>
public static class CspHeaderParser
{
    /// <summary>
    /// Extracts a specific directive value from a full CSP header string.
    /// e.g., GetDirective("default-src 'self'; script-src 'self' 'nonce-abc'", "script-src")
    ///       returns "'self' 'nonce-abc'"
    /// </summary>
    public static string? GetDirective(string cspHeader, string directiveName)
    {
        var directives = cspHeader.Split(';', StringSplitOptions.TrimEntries);
        foreach (var directive in directives)
        {
            if (directive.StartsWith(directiveName, StringComparison.OrdinalIgnoreCase))
            {
                return directive[directiveName.Length..].Trim();
            }
        }
        return null;
    }

    /// <summary>
    /// Extracts the nonce value from a directive value string.
    /// e.g., ExtractNonce("'self' 'nonce-abc123='") returns "abc123="
    /// </summary>
    public static string? ExtractNonce(string directiveValue)
    {
        const string prefix = "'nonce-";
        var start = directiveValue.IndexOf(prefix, StringComparison.Ordinal);
        if (start < 0) return null;

        start += prefix.Length;
        var end = directiveValue.IndexOf('\'', start);
        if (end < 0) return null;

        return directiveValue[start..end];
    }
}
