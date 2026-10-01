using System.Text.Json;
using System.Text.Json.Serialization;

namespace Iva.Auth
{
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
                JsonTokenType.Number => reader.TryGetInt64(out var l) ? l.ToString(System.Globalization.CultureInfo.InvariantCulture) : reader.GetDouble().ToString(System.Globalization.CultureInfo.InvariantCulture),
                JsonTokenType.True => "true",
                JsonTokenType.False => "false",
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
}

namespace Iva.Auth.Payments
{
    /// <summary>Charge operator / catalog item.</summary>
    public sealed class ChargeOperator
    {
        [JsonPropertyName("id")]
        [JsonConverter(typeof(FlexibleStringConverter))]
        public string? Id { get; set; }

        [JsonPropertyName("code")]
        [JsonConverter(typeof(FlexibleStringConverter))]
        public string? Code { get; set; }

        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [JsonPropertyName("title")]
        public string? Title { get; set; }

        [JsonPropertyName("category")]
        public string? Category { get; set; }

        [JsonPropertyName("description")]
        public string? Description { get; set; }

        [JsonPropertyName("logoUrl")]
        public string? LogoUrl { get; set; }

        [JsonPropertyName("isActive")]
        public bool? IsActive { get; set; }

        [JsonPropertyName("amounts")]
        public List<long>? Amounts { get; set; }

        [JsonExtensionData]
        public Dictionary<string, JsonElement>? Extra { get; set; }
    }

    /// <summary>Card payment information for charge transactions.</summary>
    public sealed class CardPayment
    {
        [JsonPropertyName("pan")]
        public string? Pan { get; set; }

        [JsonPropertyName("cvv2")]
        public string? Cvv2 { get; set; }

        [JsonPropertyName("expireMonth")]
        public string? ExpireMonth { get; set; }

        [JsonPropertyName("expireYear")]
        public string? ExpireYear { get; set; }

        [JsonPropertyName("pin")]
        public string? Pin { get; set; }

        [JsonPropertyName("token")]
        public string? Token { get; set; }

        public void Validate()
        {
            if (string.IsNullOrWhiteSpace(Token) && string.IsNullOrWhiteSpace(Pan))
                throw new ArgumentException("Either Pan or Token must be provided for card payment.");
        }
    }

    /// <summary>Request payload for purchasing a charge.</summary>
    public sealed class ChargePurchaseRequest
    {
        [JsonPropertyName("amount")]
        public long Amount { get; set; }

        [JsonPropertyName("targetMobileNo")]
        public string? TargetMobileNo { get; set; }

        [JsonPropertyName("providerId")]
        public string? ProviderId { get; set; }

        [JsonPropertyName("card")]
        public CardPayment Card { get; set; } = new();

        [JsonPropertyName("orderId")]
        public long? OrderId { get; set; }

        [JsonPropertyName("extra")]
        public Dictionary<string, object?>? Extra { get; set; }
    }

    /// <summary>Result of a charge purchase operation.</summary>
    public sealed class ChargePurchaseResult
    {
        [JsonPropertyName("pin")]
        public string? Pin { get; set; }

        [JsonPropertyName("serial")]
        public string? Serial { get; set; }

        [JsonPropertyName("trackingCode")]
        public string? TrackingCode { get; set; }

        [JsonPropertyName("transactionId")]
        public string? TransactionId { get; set; }

        [JsonPropertyName("referenceNumber")]
        public string? ReferenceNumber { get; set; }

        [JsonPropertyName("status")]
        public string? Status { get; set; }

        [JsonPropertyName("cardHolderName")]
        public string? CardHolderName { get; set; }

        [JsonExtensionData]
        public Dictionary<string, JsonElement>? Extra { get; set; }

        public bool Success { get; set; }
        public string? ErrorCode { get; set; }
        public string? Message { get; set; }
        public string? UsedPhone { get; set; }
        public int RetryCount { get; set; }
    }
}

namespace Iva.Auth.Sessions
{
    /// <summary>Persisted session state for an account.</summary>
    public sealed class SessionData
    {
        [JsonPropertyName("phone")]
        public string Phone { get; set; } = string.Empty;

        [JsonPropertyName("token")]
        public string? Token { get; set; }

        [JsonPropertyName("refreshToken")]
        public string? RefreshToken { get; set; }

        [JsonPropertyName("expiresIn")]
        public long? ExpiresIn { get; set; }

        [JsonPropertyName("tokenType")]
        public string? TokenType { get; set; }

        [JsonPropertyName("accessTokenObtainedAt")]
        public long? AccessTokenObtainedAt { get; set; }

        [JsonPropertyName("sharedKey")]
        public string? SharedKey { get; set; }

        [JsonPropertyName("workingKey")]
        public string? WorkingKey { get; set; }

        [JsonPropertyName("rsaPublic")]
        public string? RsaPublic { get; set; }

        [JsonExtensionData]
        public Dictionary<string, JsonElement>? Extra { get; set; }
    }

    /// <summary>Persistence interface for session data.</summary>
    public interface ISessionRepository
    {
        SessionData? Load(string phone);
        void Save(SessionData session);
        bool Exists(string phone);
        bool Delete(string phone);
        IReadOnlyList<string> ListPhones();
    }

    /// <summary>File-based session storage (one JSON file per phone number).</summary>
    public sealed class FileSessionRepository : ISessionRepository
    {
        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            WriteIndented = true,
            PropertyNameCaseInsensitive = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        };

        private static readonly object ProcessLock = new();
        private readonly string _directory;

        public FileSessionRepository(string? directory = null)
        {
            _directory = directory ?? Path.Combine(AppContext.BaseDirectory, "sessions");
            Directory.CreateDirectory(_directory);
        }

        private string? GetFilePath(string phone)
        {
            if (string.IsNullOrWhiteSpace(phone)) return null;
            var sanitized = string.Concat(phone.Where(c => char.IsLetterOrDigit(c) || c is '-' or '_'));
            if (string.IsNullOrEmpty(sanitized)) return null;
            return Path.Combine(_directory, $"{sanitized}.json");
        }

        public SessionData? Load(string phone)
        {
            var path = GetFilePath(phone);
            if (path is null) return null;

            lock (ProcessLock)
            {
                if (!File.Exists(path)) return null;
                try
                {
                    var json = File.ReadAllText(path);
                    return JsonSerializer.Deserialize<SessionData>(json, JsonOptions);
                }
                catch
                {
                    return null;
                }
            }
        }

        public void Save(SessionData session)
        {
            if (session is null || string.IsNullOrWhiteSpace(session.Phone)) return;
            var path = GetFilePath(session.Phone);
            if (path is null) return;

            lock (ProcessLock)
            {
                var json = JsonSerializer.Serialize(session, JsonOptions);
                var tempPath = path + ".tmp";
                try
                {
                    File.WriteAllText(tempPath, json);
                    File.Move(tempPath, path, overwrite: true);
                }
                catch
                {
                    try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { }
                    throw;
                }
            }
        }

        public bool Exists(string phone)
        {
            var path = GetFilePath(phone);
            if (path is null) return false;

            lock (ProcessLock)
            {
                return File.Exists(path);
            }
        }

        public bool Delete(string phone)
        {
            var path = GetFilePath(phone);
            if (path is null) return false;

            lock (ProcessLock)
            {
                if (File.Exists(path))
                {
                    try
                    {
                        File.Delete(path);
                        return true;
                    }
                    catch
                    {
                        return false;
                    }
                }
                return false;
            }
        }

        public IReadOnlyList<string> ListPhones()
        {
            lock (ProcessLock)
            {
                if (!Directory.Exists(_directory)) return Array.Empty<string>();
                var files = Directory.GetFiles(_directory, "*.json");
                var result = new List<string>(files.Length);
                foreach (var file in files)
                {
                    var phone = Path.GetFileNameWithoutExtension(file);
                    if (!string.IsNullOrWhiteSpace(phone))
                        result.Add(phone);
                }
                return result;
            }
        }
    }
}
