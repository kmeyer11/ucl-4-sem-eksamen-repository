using SecurityMonitorService.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddHttpClient();
builder.Services.AddSingleton<SecurityAnalysisService>();
builder.Services.AddHostedService<LogMonitorBackgroundService>();

var app = builder.Build();

app.MapGet("/health", () => Results.Ok("OK"));

app.Run();
