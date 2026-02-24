using BlazorCspDemo.Tests.Helpers;
using FluentAssertions;

namespace BlazorCspDemo.Tests.Integration;

public class CspSecureHeaderTests : IClassFixture<CspWebApplicationFactory>, IDisposable
{
    private readonly CspWebApplicationFactory _factory;
    private readonly HttpClient _client;

    public CspSecureHeaderTests()
    {
        _factory = new CspWebApplicationFactory { CspMode = "Secure", EnvironmentName = "Production" };
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
    public async Task ScriptSrc_ContainsNonce()
    {
        var csp = await GetCspHeader();
        var scriptSrc = CspHeaderParser.GetDirective(csp, "script-src");
        scriptSrc.Should().NotBeNull();
        scriptSrc.Should().Contain("'nonce-");
    }

    [Fact]
    public async Task StyleSrc_ContainsNonce()
    {
        var csp = await GetCspHeader();
        var styleSrc = CspHeaderParser.GetDirective(csp, "style-src");
        styleSrc.Should().NotBeNull();
        styleSrc.Should().Contain("'nonce-");
    }

    [Fact]
    public async Task ScriptSrc_DoesNotContainUnsafeInline()
    {
        var csp = await GetCspHeader();
        var scriptSrc = CspHeaderParser.GetDirective(csp, "script-src");
        scriptSrc.Should().NotContain("'unsafe-inline'");
    }

    [Fact]
    public async Task ScriptSrc_DoesNotContainUnsafeEval()
    {
        var csp = await GetCspHeader();
        var scriptSrc = CspHeaderParser.GetDirective(csp, "script-src");
        scriptSrc.Should().NotContain("'unsafe-eval'");
    }

    [Fact]
    public async Task Nonce_Is32BytesBase64()
    {
        var csp = await GetCspHeader();
        var scriptSrc = CspHeaderParser.GetDirective(csp, "script-src")!;
        var nonce = CspHeaderParser.ExtractNonce(scriptSrc);
        nonce.Should().NotBeNullOrEmpty();

        // 32 bytes = 44 chars in base64 (with padding)
        var bytes = Convert.FromBase64String(nonce!);
        bytes.Should().HaveCount(32);
    }

    [Fact]
    public async Task ScriptSrc_And_StyleSrc_ShareSameNonce()
    {
        var csp = await GetCspHeader();
        var scriptSrc = CspHeaderParser.GetDirective(csp, "script-src")!;
        var styleSrc = CspHeaderParser.GetDirective(csp, "style-src")!;

        var scriptNonce = CspHeaderParser.ExtractNonce(scriptSrc);
        var styleNonce = CspHeaderParser.ExtractNonce(styleSrc);

        scriptNonce.Should().NotBeNullOrEmpty();
        scriptNonce.Should().Be(styleNonce);
    }
}
