using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using BlazorCspDemo.Tests.Helpers;
using FluentAssertions;

namespace BlazorCspDemo.Tests.Integration;

/// <summary>
/// Verifies that when the CspMode configuration key is missing entirely,
/// the middleware defaults to Secure mode (fail-safe behavior).
/// </summary>
public class CspDefaultModeTests : IDisposable
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _client;

    public CspDefaultModeTests()
    {
        _factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            // Override config with NO CspMode key at all
            builder.ConfigureAppConfiguration((context, config) =>
            {
                config.AddInMemoryCollection(new Dictionary<string, string?>());
            });
        });
        _client = _factory.CreateClient();
    }

    public void Dispose()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    [Fact]
    public async Task MissingCspMode_DefaultsToSecure()
    {
        var response = await _client.GetAsync("/");
        response.Headers.TryGetValues("Content-Security-Policy", out var values).Should().BeTrue();
        var csp = values!.First();

        var scriptSrc = CspHeaderParser.GetDirective(csp, "script-src");
        scriptSrc.Should().NotBeNull();
        scriptSrc.Should().Contain("'nonce-", "missing CspMode should default to Secure with nonce");
        scriptSrc.Should().NotContain("'unsafe-inline'");
        scriptSrc.Should().NotContain("'unsafe-eval'");
    }
}
