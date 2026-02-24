using Microsoft.Playwright;
using FluentAssertions;

namespace BlazorCspDemo.Tests.Playwright;

public class CspSecureBrowserTests : IAsyncLifetime
{
    private readonly PlaywrightFixture _fixture = new() { CspMode = "Secure" };

    public Task InitializeAsync() => _fixture.InitializeAsync();
    public Task DisposeAsync() => _fixture.DisposeAsync();

    private async Task<IPage> CreatePage()
    {
        var page = await _fixture.Browser!.NewPageAsync();
        await page.GotoAsync(_fixture.BaseUrl + "/csp-demo");
        // Wait for Blazor Server to connect via SignalR (the circuit must be established
        // before @onclick handlers work). We detect this by waiting for the Blazor
        // framework to remove the "components-reconnect-show" state or by just waiting
        // for the page to be truly interactive.
        await page.WaitForSelectorAsync("h1", new() { Timeout = 15000 });
        // Give Blazor time to establish the SignalR circuit
        await page.WaitForFunctionAsync("() => document.querySelector('[blazor-enhanced-nav]') !== null || window.Blazor !== undefined", null, new() { Timeout = 10000 });
        // Extra buffer for circuit establishment
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
    public async Task NoncedInlineScript_Executes()
    {
        var page = await CreatePage();
        await page.ClickAsync("text=Run Nonced Inline Script Test");
        // Wait for the result alert to appear (Blazor re-renders after @onclick)
        await page.WaitForSelectorAsync(".alert-success, .alert-danger", new() { Timeout = 10000 });
        var resultText = await page.TextContentAsync(".alert-success, .alert-danger");
        resultText.Should().Contain("PASS");
        await page.CloseAsync();
    }

    [Fact]
    public async Task Eval_IsBlocked()
    {
        var page = await CreatePage();
        await page.ClickAsync("text=Try eval()");
        // Wait for the alert to appear after the button click
        await page.WaitForSelectorAsync(".alert-success, .alert-danger", new() { Timeout = 10000 });
        var pageContent = await page.ContentAsync();
        pageContent.Should().Contain("BLOCKED",
            "eval() should be blocked in Secure mode");
        await page.CloseAsync();
    }

    [Fact]
    public async Task DynamicScript_IsBlocked()
    {
        var page = await CreatePage();
        await page.ClickAsync("text=Try Dynamic Script Injection");
        await page.WaitForTimeoutAsync(2000);
        var resultEl = await page.QuerySelectorAsync("#dynamic-script-result");
        var text = await resultEl!.TextContentAsync();
        text.Should().NotContain("Dynamic script executed",
            "dynamic script injection should be blocked in Secure mode");
        await page.CloseAsync();
    }

    [Fact]
    public async Task ExternalJs_Works()
    {
        var page = await CreatePage();
        await page.ClickAsync("text=Change Color via External JS");
        await page.WaitForSelectorAsync(".alert-success, .alert-danger", new() { Timeout = 10000 });
        var pageContent = await page.ContentAsync();
        pageContent.Should().Contain("External JS function executed",
            "external JS functions from 'self' should always work");
        await page.CloseAsync();
    }
}
