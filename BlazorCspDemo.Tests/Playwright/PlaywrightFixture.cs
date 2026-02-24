using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Microsoft.Playwright;

namespace BlazorCspDemo.Tests.Playwright;

/// <summary>
/// Starts the real Blazor app as a child process on a random port
/// and provides a Playwright browser instance for end-to-end tests.
/// This approach avoids duplicating DI registrations and supports
/// the full Blazor Server + SignalR pipeline.
/// </summary>
public class PlaywrightFixture : IAsyncLifetime
{
    private Process? _serverProcess;
    public string BaseUrl { get; private set; } = "";
    public IPlaywright? Playwright { get; private set; }
    public IBrowser? Browser { get; private set; }

    public string CspMode { get; set; } = "Secure";

    private static int GetRandomPort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    public async Task InitializeAsync()
    {
        var port = GetRandomPort();
        BaseUrl = $"http://127.0.0.1:{port}";

        var projectDir = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "BlazorCspDemo"));

        _serverProcess = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "dotnet",
                Arguments = $"run --no-launch-profile --project \"{projectDir}\"",
                Environment =
                {
                    ["ASPNETCORE_ENVIRONMENT"] = "Production",
                    ["ASPNETCORE_URLS"] = BaseUrl,
                    ["CspMode"] = CspMode
                },
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            }
        };

        _serverProcess.Start();

        // Wait for server to be ready (up to 30 seconds)
        using var httpClient = new HttpClient();
        var ready = false;
        for (int i = 0; i < 60; i++)
        {
            try
            {
                var response = await httpClient.GetAsync(BaseUrl);
                if (response.IsSuccessStatusCode || response.StatusCode == HttpStatusCode.OK)
                {
                    ready = true;
                    break;
                }
            }
            catch
            {
                // Server not ready yet
            }
            await Task.Delay(500);
        }

        if (!ready)
            throw new Exception($"Server did not start within 30 seconds on {BaseUrl}");

        // Launch Playwright browser
        Playwright = await Microsoft.Playwright.Playwright.CreateAsync();
        Browser = await Playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions
        {
            Headless = true
        });
    }

    public async Task DisposeAsync()
    {
        if (Browser is not null) await Browser.CloseAsync();
        Playwright?.Dispose();

        if (_serverProcess is not null && !_serverProcess.HasExited)
        {
            _serverProcess.Kill(entireProcessTree: true);
            await _serverProcess.WaitForExitAsync();
        }
        _serverProcess?.Dispose();
    }
}
