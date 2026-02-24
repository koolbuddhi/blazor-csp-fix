using Microsoft.Playwright;
using FluentAssertions;

namespace BlazorCspDemo.Tests.Playwright;

public class CspInsecureBrowserTests : IAsyncLifetime
{
    private readonly PlaywrightFixture _fixture = new() { CspMode = "Insecure" };

    public Task InitializeAsync() => _fixture.InitializeAsync();
    public Task DisposeAsync() => _fixture.DisposeAsync();

    private async Task<IPage> CreatePage()
    {
        var page = await _fixture.Browser!.NewPageAsync();
        await page.GotoAsync(_fixture.BaseUrl + "/csp-demo");
        await page.WaitForSelectorAsync("h1", new() { Timeout = 15000 });
        // Wait for Blazor SignalR circuit to be ready
        await page.WaitForFunctionAsync("() => document.querySelector('[blazor-enhanced-nav]') !== null || window.Blazor !== undefined", null, new() { Timeout = 10000 });
        await page.WaitForTimeoutAsync(2000);
        return page;
    }

    [Fact]
    public async Task BlazorSignalR_Connects()
    {
        var page = await CreatePage();
        var heading = await page.TextContentAsync("h1");
        heading.Should().Contain("Content Security Policy Demo");
        await page.CloseAsync();
    }

    [Fact]
    public async Task Eval_Succeeds()
    {
        var page = await CreatePage();
        await page.ClickAsync("text=Try eval()");
        // Wait for Blazor to update the DOM with the result
        await page.WaitForSelectorAsync(".alert-success, .alert-danger", new() { Timeout = 10000 });
        var pageContent = await page.ContentAsync();
        pageContent.Should().Contain("SUCCEEDED",
            "eval() should succeed in Insecure mode");
        await page.CloseAsync();
    }

    [Fact]
    public async Task CounterJsInterop_Works()
    {
        var page = await _fixture.Browser!.NewPageAsync();
        await page.GotoAsync(_fixture.BaseUrl + "/counter");
        await page.WaitForSelectorAsync("h1", new() { Timeout = 15000 });
        await page.WaitForFunctionAsync("() => document.querySelector('[blazor-enhanced-nav]') !== null || window.Blazor !== undefined", null, new() { Timeout = 10000 });
        await page.WaitForTimeoutAsync(2000);

        await page.ClickAsync("text=Click me");
        await page.WaitForTimeoutAsync(1000);

        var pageContent = await page.ContentAsync();
        pageContent.Should().Contain("Current count:");
        await page.CloseAsync();
    }
}
