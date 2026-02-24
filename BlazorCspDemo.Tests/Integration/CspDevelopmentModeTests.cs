using BlazorCspDemo.Tests.Helpers;
using FluentAssertions;

namespace BlazorCspDemo.Tests.Integration;

/// <summary>
/// Verifies differences between Development and Production CSP headers
/// in Secure mode. Development adds unsafe-inline alongside nonce for
/// hot-reload compatibility.
/// </summary>
public class CspDevelopmentModeTests : IDisposable
{
    private readonly CspWebApplicationFactory _devFactory;
    private readonly HttpClient _devClient;

    public CspDevelopmentModeTests()
    {
        _devFactory = new CspWebApplicationFactory { CspMode = "Secure", EnvironmentName = "Development" };
        _devClient = _devFactory.CreateClient();
    }

    public void Dispose()
    {
        _devClient.Dispose();
        _devFactory.Dispose();
    }

    [Fact]
    public async Task Development_ScriptSrc_HasBothNonceAndUnsafeInline()
    {
        var response = await _devClient.GetAsync("/");
        response.Headers.TryGetValues("Content-Security-Policy", out var values).Should().BeTrue();
        var csp = values!.First();

        var scriptSrc = CspHeaderParser.GetDirective(csp, "script-src");
        scriptSrc.Should().Contain("'nonce-");
        scriptSrc.Should().Contain("'unsafe-inline'",
            "Development mode adds unsafe-inline alongside nonce for hot-reload");
    }

    [Fact]
    public async Task Development_StyleSrc_HasUnsafeInlineWithoutNonce()
    {
        var response = await _devClient.GetAsync("/");
        response.Headers.TryGetValues("Content-Security-Policy", out var values).Should().BeTrue();
        var csp = values!.First();

        var styleSrc = CspHeaderParser.GetDirective(csp, "style-src");
        styleSrc.Should().Contain("'unsafe-inline'");
        // In dev mode, style-src uses unsafe-inline without nonce
        CspHeaderParser.ExtractNonce(styleSrc!).Should().BeNull();
    }

    [Fact]
    public async Task Production_ScriptSrc_NoUnsafeInline()
    {
        using var prodFactory = new CspWebApplicationFactory { CspMode = "Secure", EnvironmentName = "Production" };
        using var prodClient = prodFactory.CreateClient();

        var response = await prodClient.GetAsync("/");
        response.Headers.TryGetValues("Content-Security-Policy", out var values).Should().BeTrue();
        var csp = values!.First();

        var scriptSrc = CspHeaderParser.GetDirective(csp, "script-src");
        scriptSrc.Should().NotContain("'unsafe-inline'",
            "Production mode should NOT have unsafe-inline");
    }
}
