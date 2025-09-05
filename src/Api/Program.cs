var builder = WebApplication.CreateBuilder(args);

// Config
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Health checks
builder.Services.AddHealthChecks();

var app = builder.Build();

app.UseHttpsRedirection();

// Swagger (dev)
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Health endpoints
app.MapGet("/", () => Results.Redirect("/health"));
app.MapHealthChecks("/health");
app.MapGet("/ready", () => Results.Ok(new { status = "ready" }));

// API version v1 group (תתחיל מכאן)
var v1 = app.MapGroup("/api/v1");

// דוגמת endpoint
v1.MapGet("/ping", () => Results.Ok(new { pong = true, ts = DateTimeOffset.UtcNow }))
  .WithName("Ping")
  .WithOpenApi();

app.Run();
