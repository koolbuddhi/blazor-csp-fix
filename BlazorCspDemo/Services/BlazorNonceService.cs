using Microsoft.AspNetCore.Components.Server.Circuits;

namespace BlazorCspDemo.Services;

public class BlazorNonceService : CircuitHandler
{
    public string Nonce { get; set; } = string.Empty;
}
