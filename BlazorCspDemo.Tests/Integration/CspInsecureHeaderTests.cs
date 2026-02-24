using BlazorCspDemo.Tests.Helpers;
using FluentAssertions;

namespace BlazorCspDemo.Tests.Integration;

public class CspInsecureHeaderTests : IDisposable
{
    private readonly CspWebApplicationFactory _factory;
    private readonly HttpClient _client;

    public CspInsecureHeaderTests()
    {
        _factory = new CspWebApplicationFactory { CspMode = "Insecure", EnvironmentName = "Production" };
        _client = _factory.CreateClient();
    }

    public void Dispose()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    private async Task<string> GetCspHeader()
    {
        var response = await _client.GetAsync("/");
        response.Headers.TryGetValues("Content-Security-Policy", out var values).Should().BeTrue();
        return values!.First();
    }

    [Fact]
    public async Task ScriptSrc_ContainsUnsafeInline()
    {
        var csp = await GetCspHeader();
        var scriptSrc = CspHeaderParser.GetDirective(csp, "script-src");
        scriptSrc.Should().Contain("'unsafe-inline'");
    }

    [Fact]
    public async Task ScriptSrc_ContainsUnsafeEval()
    {
        var csp = await GetCspHeader();
        var scriptSrc = CspHeaderParser.GetDirective(csp, "script-src");
        scriptSrc.Should().Contain("'unsafe-eval'");
    }

    [Fact]
    public async Task StyleSrc_ContainsUnsafeInline()
    {
        var csp = await GetCspHeader();
        var styleSrc = CspHeaderParser.GetDirective(csp, "style-src");
        styleSrc.Should().Contain("'unsafe-inline'");
    }

    [Fact]
    public async Task ScriptSrc_DoesNotContainNonce()
    {
        var csp = await GetCspHeader();
        var scriptSrc = CspHeaderParser.GetDirective(csp, "script-src");
        scriptSrc.Should().NotContain("'nonce-");
    }
}
