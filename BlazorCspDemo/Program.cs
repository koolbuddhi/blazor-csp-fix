using Microsoft.AspNetCore.Components.Server.Circuits;
using Microsoft.Extensions.DependencyInjection.Extensions;
using BlazorCspDemo.Components;
using BlazorCspDemo.Services;
using BlazorCspDemo.Middleware;
using Radzen;

var builder = WebApplication.CreateBuilder(args);

// Add Blazor services
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// Register Radzen services
builder.Services.AddRadzenComponents();

// Register BlazorNonceService as both a CircuitHandler and a directly-injectable service
builder.Services.AddScoped<BlazorNonceService>();
builder.Services.TryAddEnumerable(
    ServiceDescriptor.Scoped<CircuitHandler, BlazorNonceService>(
        sp => sp.GetRequiredService<BlazorNonceService>()));

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseStaticFiles();

// CSP middleware: after UseStaticFiles (so static files skip CSP headers),
// before MapRazorComponents (so nonce is available during SSR)
app.UseCsp();

app.UseAntiforgery();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
