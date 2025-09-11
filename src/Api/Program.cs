using Google.Apis.Auth.OAuth2;
using Google.Apis.Gmail.v1;
using Google.Apis.Gmail.v1.Data;
using Google.Apis.Services;
using Microsoft.AspNetCore.Mvc;
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
app.MapGet("/auth/google/start", () =>
{
    var clientId = GetEnv("GOOGLE_CLIENT_ID") ?? "";
    var redirectUri = GetEnv("GOOGLE_REDIRECT_URI") ?? "http://localhost:5173/auth/google/callback";

    var scopes = new[]
    {
        GmailService.Scope.GmailReadonly, // מינימום ל-MVP
        "openid", "email", "profile", "offline_access"
    };

    var url = CreateGoogleAuthUrl(clientId, redirectUri, scopes);
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

    var clientId = GetEnv("GOOGLE_CLIENT_ID") ?? "";
    var clientSecret = GetEnv("GOOGLE_CLIENT_SECRET") ?? "";
    var gmail = await CreateGmailServiceAsync(clientId, clientSecret, refresh);

    var listReq = gmail.Users.Messages.List("me");
    listReq.LabelIds = "INBOX";
    listReq.MaxResults = 10;

    var list = await listReq.ExecuteAsync();
    var results = new List<object>();

    if (list.Messages != null)
    {
        foreach (var m in list.Messages)
        {
            var full = await gmail.Users.Messages.Get("me", m.Id).ExecuteAsync();
            var headers = full.Payload?.Headers?.ToDictionary(h => h.Name, h => h.Value) ?? new Dictionary<string, string>();
            results.Add(new
            {
                id = m.Id,
                threadId = m.ThreadId,
                date = headers.GetValueOrDefault("Date"),
                from = headers.GetValueOrDefault("From"),
                subject = headers.GetValueOrDefault("Subject"),
                snippet = full.Snippet
            });
        }
    }

    return Results.Ok(results);
});

// === 4) סיכום אימייל עם OpenAI (TL;DR) ===
app.MapPost("/api/gmail/summarize/{messageId}", async (string messageId, TokenMemoryStore tokens, IHttpClientFactory httpFactory) =>
{
    var refresh = await tokens.GetAsync("default");
    if (string.IsNullOrEmpty(refresh)) return Results.BadRequest("Not connected");

    var clientId = GetEnv("GOOGLE_CLIENT_ID") ?? "";
    var clientSecret = GetEnv("GOOGLE_CLIENT_SECRET") ?? "";
    var gmail = await CreateGmailServiceAsync(clientId, clientSecret, refresh);

    var msg = await gmail.Users.Messages.Get("me", messageId).ExecuteAsync();
    var bodyText = ExtractPlainText(msg) ?? msg.Snippet ?? "";

    if (string.IsNullOrWhiteSpace(bodyText))
        return Results.BadRequest("No text to summarize");

    var openAiKey = GetEnv("OPENAI_API_KEY") ?? "";
    var openAiBase = GetEnv("OPENAI_BASE_URL") ?? "https://api.openai.com/v1";
    var openAiModel = GetEnv("OPENAI_MODEL") ?? "gpt-4o-mini";

    var http = httpFactory.CreateClient();
    http.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", openAiKey);

    var payload = new
    {
        model = openAiModel,
        messages = new[]
        {
            new { role = "system", content = "You summarize emails into short, actionable TL;DR with bullets, actions, and dates." },
            new { role = "user", content = $"Summarize the following email:\n\n{bodyText}" }
        }
    };

    var resp = await http.PostAsJsonAsync($"{openAiBase}/chat/completions", payload);
    if (!resp.IsSuccessStatusCode)
    {
        var err = await resp.Content.ReadAsStringAsync();
        return Results.Problem($"OpenAI error: {err}");
    }

    var json = await resp.Content.ReadFromJsonAsync<dynamic>();
    string summary = json?["choices"]?[0]?["message"]?["content"]?.ToString() ?? "";

    // No-retention בשלב זה — לא שומרים גוף/סיכום
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

static async Task<(string AccessToken, string RefreshToken, DateTime ExpiresAt)> ExchangeCodeForToken(
    string clientId, string clientSecret, string redirectUri, string code)
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
    var json = await resp.Content.ReadFromJsonAsync<dynamic>();
    string access = json?["access_token"]?.ToString() ?? "";
    string refresh = json?["refresh_token"]?.ToString() ?? "";
    int expiresIn = int.TryParse(json?["expires_in"]?.ToString() ?? "0", out int tmp) ? tmp : 0;
    return (access, refresh, DateTime.UtcNow.AddSeconds(expiresIn));
}

static async Task<GmailService> CreateGmailServiceAsync(string clientId, string clientSecret, string refreshToken)
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
    var json = await resp.Content.ReadFromJsonAsync<dynamic>();
    string access = json?["access_token"]?.ToString() ?? "";

    var cred = GoogleCredential.FromAccessToken(access);
    return new GmailService(new BaseClientService.Initializer
    {
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