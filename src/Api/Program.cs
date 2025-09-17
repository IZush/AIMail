using Google.Apis.Auth.OAuth2;
using Google.Apis.Gmail.v1;
using Google.Apis.Gmail.v1.Data;
using Google.Apis.Services;
using Microsoft.AspNetCore.Mvc;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Linq;
using Api.Models;          // for OAuthTokenResponse & OpenAI* DTOs
using System.Net.Http.Json;


// === Config helpers ===
string? GetEnv(string key, string? fallback = null) =>
    Environment.GetEnvironmentVariable(key) ?? fallback;

var builder = WebApplication.CreateBuilder(args);

// No DB yet — נשמור refresh token בזיכרון (להתנסות)
builder.Services.AddSingleton<TokenMemoryStore>();
builder.Services.AddHttpClient();

var app = builder.Build();

// בריאות/בדיקה
app.MapGet("/healthy", () => Results.Ok(new { ok = true }));

// === 2.1 Start OAuth (Redirect to Google) ===
app.MapGet("/auth/google/start", (HttpContext ctx) =>
{
    var clientId = Environment.GetEnvironmentVariable("GOOGLE_CLIENT_ID") ?? "";
    var origin = $"{ctx.Request.Scheme}://{ctx.Request.Host}";
    var redirectUri = $"{origin}/auth/google/callback";

    var scopes = new[] { GmailService.Scope.GmailReadonly, "openid", "email", "profile" };

    var url = "https://accounts.google.com/o/oauth2/v2/auth"
        + "?response_type=code"
        + $"&client_id={Uri.EscapeDataString(clientId)}"
        + $"&redirect_uri={Uri.EscapeDataString(redirectUri)}"
        + $"&scope={Uri.EscapeDataString(string.Join(" ", scopes))}"
        + "&access_type=offline&prompt=consent";

    return Results.Redirect(url);
});

// === 2.2 OAuth callback (Exchange code → refresh token) ===
app.MapGet("/auth/google/callback", async ([FromQuery] string code, TokenMemoryStore tokens) =>
{
    var clientId = GetEnv("GOOGLE_CLIENT_ID") ?? "";
    var clientSecret = GetEnv("GOOGLE_CLIENT_SECRET") ?? "";
    var redirectUri = GetEnv("GOOGLE_REDIRECT_URI") ?? "http://localhost:5173/auth/google/callback";

    var token = await ExchangeCodeForToken(clientId, clientSecret, redirectUri, code);

    if (!string.IsNullOrEmpty(token.RefreshToken))
        await tokens.SaveAsync("default", token.RefreshToken);

    return Results.Ok(new { connected = true, hasRefreshToken = !string.IsNullOrEmpty(token.RefreshToken) });
});

// === 3) רשימת הודעות (metadata) ===
app.MapGet("/api/gmail/messages", async (TokenMemoryStore tokens) =>
{
    var refresh = await tokens.GetAsync("default");
    if (string.IsNullOrEmpty(refresh)) return Results.BadRequest("Not connected");

    var clientId = Environment.GetEnvironmentVariable("GOOGLE_CLIENT_ID") ?? "";
    var clientSecret = Environment.GetEnvironmentVariable("GOOGLE_CLIENT_SECRET") ?? "";
    var gmail = await CreateGmailServiceAsync(clientId, clientSecret, refresh);

    var req = gmail.Users.Messages.List("me");
    req.LabelIds = "INBOX";
    req.MaxResults = 10;

    var list = await req.ExecuteAsync();
    var items = new List<object>();

    if (list.Messages != null)
    {
        foreach (var m in list.Messages)
        {
            var full = await gmail.Users.Messages.Get("me", m.Id).ExecuteAsync();
            var headers = full.Payload?.Headers?.ToDictionary(h => h.Name, h => h.Value) ?? new Dictionary<string, string>();
            items.Add(new {
                id = m.Id,
                threadId = m.ThreadId,
                date = headers.GetValueOrDefault("Date"),
                from = headers.GetValueOrDefault("From"),
                subject = headers.GetValueOrDefault("Subject"),
                snippet = full.Snippet
            });
        }
    }

    return Results.Ok(items);
});

// === 4) סיכום אימייל עם OpenAI (TL;DR) ===
app.MapPost("/api/gmail/summarize/{messageId}", async (string messageId, TokenMemoryStore tokens, IHttpClientFactory httpFactory) =>
{
    var refresh = await tokens.GetAsync("default");
    if (string.IsNullOrEmpty(refresh)) return Results.BadRequest("Not connected");

    var clientId = Environment.GetEnvironmentVariable("GOOGLE_CLIENT_ID") ?? "";
    var clientSecret = Environment.GetEnvironmentVariable("GOOGLE_CLIENT_SECRET") ?? "";
    var gmail = await CreateGmailServiceAsync(clientId, clientSecret, refresh);

    var msg = await gmail.Users.Messages.Get("me", messageId).ExecuteAsync();
    var bodyText = ExtractPlainText(msg) ?? msg.Snippet ?? "";
    if (string.IsNullOrWhiteSpace(bodyText)) return Results.BadRequest("No text to summarize");

    var key  = Environment.GetEnvironmentVariable("OPENAI_API_KEY") ?? "";
    var baseUrl = Environment.GetEnvironmentVariable("OPENAI_BASE_URL") ?? "https://api.openai.com/v1";
    var model = Environment.GetEnvironmentVariable("OPENAI_MODEL") ?? "gpt-4o-mini";

    var http = httpFactory.CreateClient();
    http.DefaultRequestHeaders.Authorization =
        new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", key);

    var payload = new {
        model,
        messages = new[] {
            new { role = "system", content = "Summarize emails into short, actionable TL;DR. Include bullets and actions." },
            new { role = "user", content = $"Summarize the following email:\n\n{bodyText}" }
        }
    };

    var resp = await http.PostAsJsonAsync($"{baseUrl}/chat/completions", payload);
    if (!resp.IsSuccessStatusCode)
        return Results.Problem($"OpenAI error: {await resp.Content.ReadAsStringAsync()}");

    var chat = await resp.Content.ReadFromJsonAsync<OpenAIChatResponse>();
    var summary = chat?.Choices.FirstOrDefault()?.Message?.Content ?? "";

    return Results.Ok(new { messageId, summary });
});

app.Run();


// ===== Helpers =====

static string CreateGoogleAuthUrl(string clientId, string redirectUri, IEnumerable<string> scopes)
{
    var scopeStr = string.Join(" ", scopes);
    var url = "https://accounts.google.com/o/oauth2/v2/auth" +
        "?response_type=code" +
        $"&client_id={Uri.EscapeDataString(clientId)}" +
        $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
        $"&scope={Uri.EscapeDataString(scopeStr)}" +
        "&access_type=offline" +
        "&prompt=consent";
    return url;
}

static async Task<(string AccessToken, string RefreshToken, DateTime ExpiresAt)>
    ExchangeCodeForToken(string clientId, string clientSecret, string redirectUri, string code)
{
    using var http = new HttpClient();
    var content = new FormUrlEncodedContent(new Dictionary<string, string> {
        ["code"] = code,
        ["client_id"] = clientId,
        ["client_secret"] = clientSecret,
        ["redirect_uri"] = redirectUri,
        ["grant_type"] = "authorization_code"
    });

    var resp = await http.PostAsync("https://oauth2.googleapis.com/token", content);
    resp.EnsureSuccessStatusCode();

    var token = await resp.Content.ReadFromJsonAsync<OAuthTokenResponse>();
    if (token is null) throw new Exception("Failed to parse token response");

    return (token.AccessToken, token.RefreshToken ?? "", DateTime.UtcNow.AddSeconds(token.ExpiresIn));
}

static async Task<string> RefreshAccessToken(string clientId, string clientSecret, string refreshToken)
{
    using var http = new HttpClient();
    var content = new FormUrlEncodedContent(new Dictionary<string, string> {
        ["client_id"] = clientId,
        ["client_secret"] = clientSecret,
        ["refresh_token"] = refreshToken,
        ["grant_type"] = "refresh_token"
    });

    var resp = await http.PostAsync("https://oauth2.googleapis.com/token", content);
    resp.EnsureSuccessStatusCode();

    var token = await resp.Content.ReadFromJsonAsync<OAuthTokenResponse>();
    return token?.AccessToken ?? "";
}

static async Task<GmailService> CreateGmailServiceAsync(string clientId, string clientSecret, string refreshToken)
{
    var access = await RefreshAccessToken(clientId, clientSecret, refreshToken);
    var cred = GoogleCredential.FromAccessToken(access);
    return new GmailService(new BaseClientService.Initializer {
        HttpClientInitializer = cred,
        ApplicationName = "AI Mail Assistant MVP",
    });
}


static string? ExtractPlainText(Message msg)
{
    if (msg.Payload == null) return null;
    return Walk(msg.Payload);

    static string? Walk(MessagePart part)
    {
        if (part.MimeType == "text/plain" && part.Body?.Data != null)
        {
            try
            {
                var data = part.Body.Data.Replace('-', '+').Replace('_', '/');
                var bytes = Convert.FromBase64String(data);
                return System.Text.Encoding.UTF8.GetString(bytes);
            }
            catch { }
        }
        if (part.Parts != null)
        {
            foreach (var p in part.Parts)
            {
                var t = Walk(p);
                if (!string.IsNullOrEmpty(t)) return t;
            }
        }
        return null;
    }
}

// in-memory token store (להחליף בהמשך ל-KMS/Key Vault + DB)
public class TokenMemoryStore
{
    private readonly Dictionary<string, string> _map = new();
    public Task SaveAsync(string key, string refreshToken) { _map[key] = refreshToken; return Task.CompletedTask; }
    public Task<string?> GetAsync(string key) { _map.TryGetValue(key, out var v); return Task.FromResult<string?>(v); }
}