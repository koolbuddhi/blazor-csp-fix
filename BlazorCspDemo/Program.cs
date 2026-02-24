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

// Enable static web assets from NuGet packages (e.g. Radzen) when running
// via 'dotnet run' in Production mode (the manifest is only auto-loaded in Development)
if (!builder.Environment.IsDevelopment())
{
    builder.WebHost.UseStaticWebAssets();
}

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

// --- File Upload Demo Endpoints ---

var insecureUploadPath = Path.Combine(app.Environment.WebRootPath, "uploads");
var secureUploadPath = Path.Combine(app.Environment.ContentRootPath, "Data", "uploads");
Directory.CreateDirectory(insecureUploadPath);
Directory.CreateDirectory(secureUploadPath);

// Insecure upload: saves to wwwroot/uploads/ (served as static files from 'self')
app.MapPost("/api/upload/insecure", async (HttpRequest request) =>
{
    var form = await request.ReadFormAsync();
    var file = form.Files.Count > 0 ? form.Files[0] : null;
    if (file is null || file.Length == 0)
        return Results.BadRequest(new { error = "No file provided." });

    var fileName = Path.GetFileName(file.FileName);
    var filePath = Path.Combine(insecureUploadPath, fileName);

    using var stream = new FileStream(filePath, FileMode.Create);
    await file.CopyToAsync(stream);

    return Results.Ok(new { url = $"/uploads/{fileName}", name = fileName });
}).DisableAntiforgery();

// Secure upload: validates extension, saves outside wwwroot with GUID name
app.MapPost("/api/upload/secure", async (HttpRequest request) =>
{
    var form = await request.ReadFormAsync();
    var file = form.Files.Count > 0 ? form.Files[0] : null;
    if (file is null || file.Length == 0)
        return Results.BadRequest(new { error = "No file provided." });

    var extension = Path.GetExtension(file.FileName).ToLowerInvariant();
    var allowedExtensions = new HashSet<string> { ".docx", ".pdf", ".png", ".jpg", ".jpeg", ".gif" };
    if (!allowedExtensions.Contains(extension))
        return Results.BadRequest(new { error = $"File type '{extension}' is not allowed. Only docx, pdf, and image files are accepted." });

    var id = Guid.NewGuid().ToString();
    var safeFileName = id + extension;
    var filePath = Path.Combine(secureUploadPath, safeFileName);

    // Store original filename in a sidecar metadata file
    await File.WriteAllTextAsync(filePath + ".meta", file.FileName);

    using var stream = new FileStream(filePath, FileMode.Create);
    await file.CopyToAsync(stream);

    return Results.Ok(new { url = $"/api/download/{id}", name = file.FileName, id });
}).DisableAntiforgery();

// Secure download: serves from outside wwwroot with Content-Disposition: attachment
app.MapGet("/api/download/{id}", async (string id) =>
{
    // Find the file by GUID prefix
    var files = Directory.GetFiles(secureUploadPath, id + ".*")
        .Where(f => !f.EndsWith(".meta"))
        .ToArray();

    if (files.Length == 0)
        return Results.NotFound(new { error = "File not found." });

    var filePath = files[0];
    var metaPath = filePath + ".meta";
    var originalName = File.Exists(metaPath)
        ? await File.ReadAllTextAsync(metaPath)
        : Path.GetFileName(filePath);

    var fileBytes = await File.ReadAllBytesAsync(filePath);
    return Results.File(fileBytes, "application/octet-stream", originalName);
});

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();

// Required for WebApplicationFactory<Program> in integration tests
public partial class Program { }
