using BlazorCspDemo.Tests.Helpers;
using FluentAssertions;

namespace BlazorCspDemo.Tests.Integration;

/// <summary>
/// Verifies that static files served by UseStaticFiles() do NOT receive
/// CSP or security headers (because UseStaticFiles short-circuits before UseCsp middleware).
/// </summary>
public class StaticFileHeaderTests : IDisposable
{
    private readonly CspWebApplicationFactory _factory;
    private readonly HttpClient _client;

    public StaticFileHeaderTests()
    {
        _factory = new CspWebApplicationFactory { CspMode = "Secure", EnvironmentName = "Production" };
        _client = _factory.CreateClient();
    }

    public void Dispose()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    [Fact]
    public async Task AppCss_DoesNotHaveCspHeader()
    {
        var response = await _client.GetAsync("/app.css");
        response.Headers.Contains("Content-Security-Policy").Should().BeFalse(
            "static files are served before CSP middleware runs");
    }

    [Fact]
    public async Task FaviconPng_DoesNotHaveCspHeader()
    {
        var response = await _client.GetAsync("/favicon.png");
        response.Headers.Contains("Content-Security-Policy").Should().BeFalse();
    }

    [Fact]
    public async Task AppCss_DoesNotHaveXFrameOptions()
    {
        var response = await _client.GetAsync("/app.css");
        response.Headers.Contains("X-Frame-Options").Should().BeFalse();
    }

    [Fact]
    public async Task CspTestJs_DoesNotHaveCspHeader()
    {
        var response = await _client.GetAsync("/js/csp-test.js");
        response.Headers.Contains("Content-Security-Policy").Should().BeFalse();
    }
}
