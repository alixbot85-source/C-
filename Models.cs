using System.Text.Json;
using System.Text.Json.Serialization;

namespace Iva.Auth;

/// <summary>Standard server envelope: { error: { code, message }, data: T }.</summary>
public sealed class ApiResponse<T>
{
    [JsonPropertyName("error")]
    public ApiError? Error { get; set; }

    [JsonPropertyName("data")]
    public T? Data { get; set; }
}

public sealed class ApiError
{
    /// <summary>May be numeric or string in the wire format; always read as string.</summary>
    [JsonPropertyName("code")]
    [JsonConverter(typeof(FlexibleStringConverter))]
    public string? Code { get; set; }

    [JsonPropertyName("message")]
    public string? Message { get; set; }
}

/// <summary>Result of the OTP request (Activation consumes Token + ReagentNumber).</summary>
public sealed class OtpRequestResult
{
    [JsonPropertyName("Token")]
    public string? Token { get; set; }

    [JsonPropertyName("ReagentNumber")]
    public string? ReagentNumber { get; set; }

    /// <summary>Any additional fields returned by the server.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? Extra { get; set; }
}

/// <summary>Token set returned by Activation and RefreshToken.</summary>
public sealed class TokenResult
{
    [JsonPropertyName("accessToken")]
    public string? AccessToken { get; set; }

    [JsonPropertyName("refreshToken")]
    public string? RefreshToken { get; set; }

    [JsonPropertyName("expiresIn")]
    public long? ExpiresIn { get; set; }

    [JsonPropertyName("tokenType")]
    public string? TokenType { get; set; }

    /// <summary>Base64 RSA modulus returned at login; source of the public key.</summary>
    [JsonPropertyName("key")]
    public string? Key { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? Extra { get; set; }
}

/// <summary>Reads a JSON string or number into a string property.</summary>
internal sealed class FlexibleStringConverter : JsonConverter<string?>
{
    public override string? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
        reader.TokenType switch
        {
            JsonTokenType.String => reader.GetString(),
            JsonTokenType.Number => reader.TryGetInt64(out var l) ? l.ToString() : reader.GetDouble().ToString(),
            JsonTokenType.Null => null,
            _ => reader.GetString(),
        };

    public override void Write(Utf8JsonWriter writer, string? value, JsonSerializerOptions options) =>
        writer.WriteStringValue(value);
}

/// <summary>A single HTTP request/response, surfaced for debugging.</summary>
public sealed record HttpExchange(string Method, string Url, int Status, string Body);

/// <summary>A prepared request payload, surfaced for debugging.</summary>
public sealed record RequestDump(string Label, string Json);

/// <summary>Thrown when the server returns a non-success error envelope.</summary>
public sealed class IvaApiException : Exception
{
    public string? Code { get; }

    public IvaApiException(string message, string? code = null) : base(message) => Code = code;
}
