using System.Text.Json.Serialization;

namespace Api.Models;

public sealed class OpenAIChatResponse
{
    [JsonPropertyName("choices")] public List<OpenAIChoice> Choices { get; set; } = new();
}

public sealed class OpenAIChoice
{
    [JsonPropertyName("message")] public OpenAIMessage Message { get; set; } = new();
}

public sealed class OpenAIMessage
{
    [JsonPropertyName("content")] public string? Content { get; set; }
}
