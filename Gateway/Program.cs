using Yarp.ReverseProxy;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCors(options =>
{
	options.AddDefaultPolicy(policy =>
		policy.WithOrigins("https://localhost:7026")
			  .AllowAnyHeader()
			  .AllowAnyMethod()
	);
});

builder.Services.AddReverseProxy().LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));
var app = builder.Build();

app.UseCors();

app.MapGet("/health", () => Results.Ok("OK"));

app.MapReverseProxy();

app.Run();
