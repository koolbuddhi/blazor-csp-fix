using BlazorCspDemo.Tests.Helpers;
using FluentAssertions;

namespace BlazorCspDemo.Tests.Integration;

public class CspNonceRotationTests : IDisposable
{
    private readonly CspWebApplicationFactory _factory;
    private readonly HttpClient _client;

    public CspNonceRotationTests()
    {
        _factory = new CspWebApplicationFactory { CspMode = "Secure", EnvironmentName = "Production" };
        _client = _factory.CreateClient();
    }

    public void Dispose()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    private async Task<string> GetNonceFromResponse()
    {
        var response = await _client.GetAsync("/");
        response.Headers.TryGetValues("Content-Security-Policy", out var values).Should().BeTrue();
        var csp = values!.First();
        var scriptSrc = CspHeaderParser.GetDirective(csp, "script-src")!;
        return CspHeaderParser.ExtractNonce(scriptSrc)!;
    }

    [Fact]
    public async Task TwoRequests_ProduceDifferentNonces()
    {
        var nonce1 = await GetNonceFromResponse();
        var nonce2 = await GetNonceFromResponse();

        nonce1.Should().NotBe(nonce2);
    }

    [Fact]
    public async Task TenRequests_AllNoncesUnique()
    {
        var nonces = new HashSet<string>();
        for (int i = 0; i < 10; i++)
        {
            var nonce = await GetNonceFromResponse();
            nonces.Add(nonce);
        }

        nonces.Should().HaveCount(10, "every request should generate a unique nonce");
    }
}
