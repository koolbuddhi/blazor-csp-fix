using BlazorCspDemo.Tests.Helpers;
using FluentAssertions;

namespace BlazorCspDemo.Tests.Integration;

public class SecurityHeaderTests : IDisposable
{
    private readonly CspWebApplicationFactory _factory;
    private readonly HttpClient _client;

    public SecurityHeaderTests()
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
    public async Task XContentTypeOptions_IsNosniff()
    {
        var response = await _client.GetAsync("/");
        response.Headers.TryGetValues("X-Content-Type-Options", out var values).Should().BeTrue();
        values!.First().Should().Be("nosniff");
    }

    [Fact]
    public async Task XFrameOptions_IsDeny()
    {
        var response = await _client.GetAsync("/");
        response.Headers.TryGetValues("X-Frame-Options", out var values).Should().BeTrue();
        values!.First().Should().Be("DENY");
    }

    [Fact]
    public async Task ReferrerPolicy_IsStrictOriginWhenCrossOrigin()
    {
        var response = await _client.GetAsync("/");
        response.Headers.TryGetValues("Referrer-Policy", out var values).Should().BeTrue();
        values!.First().Should().Be("strict-origin-when-cross-origin");
    }

    [Fact]
    public async Task PermissionsPolicy_RestrictsApis()
    {
        var response = await _client.GetAsync("/");
        response.Headers.TryGetValues("Permissions-Policy", out var values).Should().BeTrue();
        values!.First().Should().Contain("camera=()");
        values!.First().Should().Contain("microphone=()");
        values!.First().Should().Contain("geolocation=()");
    }

    [Fact]
    public async Task SecurityHeaders_PresentInInsecureModeToo()
    {
        using var insecureFactory = new CspWebApplicationFactory { CspMode = "Insecure", EnvironmentName = "Production" };
        using var insecureClient = insecureFactory.CreateClient();

        var response = await insecureClient.GetAsync("/");
        response.Headers.TryGetValues("X-Content-Type-Options", out var xCto).Should().BeTrue();
        xCto!.First().Should().Be("nosniff");

        response.Headers.TryGetValues("X-Frame-Options", out var xfo).Should().BeTrue();
        xfo!.First().Should().Be("DENY");
    }
}
