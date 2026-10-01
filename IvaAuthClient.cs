using System.Net;
using System.Text;
using System.Text.Json;
using Iva.Auth.Payments;
using Iva.Auth.Sessions;

namespace Iva.Auth;

/// <summary>
/// Authentication client for the iva API. Port of the request builders
/// (modules 398/675/671/399) and the HTTP layer (module 98.js).
///
/// The three authentication operations send plain JSON bodies; they are listed
/// in SignExclude, so no body signing or encryption is applied to them.
/// The encryption layer (KeyExchange + AES/HMAC/RSA) is required only for
/// authenticated calls made afterwards.
/// </summary>
public sealed class IvaAuthClient : IDisposable
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    private static readonly JsonSerializerOptions JsonPretty = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly IvaOptions _opts;
    private readonly ISessionRepository? _sessions;
    private HttpClient? _proxyHttp;

    /// <summary>Lazily-built HttpClient that routes through the configured charge proxy.</summary>
    private HttpClient GetProxyClient()
    {
        if (_proxyHttp is not null) return _proxyHttp;

        var s = _opts.ChargeProxy;
        if (string.IsNullOrWhiteSpace(s))
            throw new InvalidOperationException("useProxy is true but ChargeProxy is not configured.");

        var p = s.Split(':');
        if (p.Length < 2 || !int.TryParse(p[1], out var port))
            throw new InvalidOperationException("ChargeProxy must be host:port:username:password.");
        var host = p[0];
        var user = p.Length > 2 ? p[2] : "";
        var pass = p.Length > 3 ? string.Join(":", p.Skip(3)) : "";

        var proxy = new System.Net.WebProxy(host, port);
        if (!string.IsNullOrEmpty(user))
            proxy.Credentials = new System.Net.NetworkCredential(user, pass);

        var handler = new HttpClientHandler { Proxy = proxy, UseProxy = true };
        _proxyHttp = new HttpClient(handler) { Timeout = _opts.Timeout };
        return _proxyHttp;
    }

    /// <summary>Phone number of the session currently in memory (if any).</summary>
    public string? CurrentPhone { get; private set; }

    public IKeyStore Store { get; }
    public IvaCrypto Crypto { get; }

    /// <summary>
    /// Raised after the access token is successfully refreshed. The argument is the
    /// new token set. Subscribe to log refresh events.
    /// </summary>
    public event Action<TokenResult>? TokenRefreshed;

    /// <summary>
    /// Raised for every HTTP response (debugging). Subscribe to echo raw responses.
    /// </summary>
    public event Action<HttpExchange>? ResponseReceived;

    /// <summary>
    /// Raised when a request payload is prepared (debugging), once with the plain
    /// (pre-encryption) view and once with the encrypted body that is actually sent.
    /// </summary>
    public event Action<RequestDump>? RequestPrepared;

    private void Log(string method, string url, int status, string body) =>
        ResponseReceived?.Invoke(new HttpExchange(method, url, status, body));

    private void LogRequest(string label, object payload) =>
        RequestPrepared?.Invoke(new RequestDump(label, JsonSerializer.Serialize(payload, JsonPretty)));

    public IvaAuthClient(
        IvaOptions? options = null,
        IKeyStore? store = null,
        HttpClient? http = null,
        ISessionRepository? sessions = null)
    {
        _opts = options ?? new IvaOptions();
        Store = store ?? new InMemoryKeyStore();
        Crypto = new IvaCrypto(Store, _opts.Security);
        _sessions = sessions;

        _ownsHttp = http is null;
        _http = http ?? new HttpClient();
        _http.Timeout = _opts.Timeout;
    }

    // =====================================================================
    // Public RSA key
    // =====================================================================

    /// <summary>
    /// Shaparak getKey (card-to-card flow only — NOT used for charge/payment).
    /// POST taking { keyId, transactionId } and returning { keyData, errors }.
    /// Kept for completeness; the charge channel uses SetPublicKey + KeyExchange instead.
    /// The raw response is echoed via ResponseReceived.
    /// </summary>
    public async Task<string> FetchPublicKeyAsync(
        string? keyId = null, string? transactionId = null, CancellationToken ct = default)
    {
        var body = new { keyId = keyId ?? _opts.KeyId, transactionId = transactionId ?? _opts.TransactionId };
        var json = JsonSerializer.Serialize(body, Json);

        using var req = new HttpRequestMessage(HttpMethod.Post, _opts.PublicKeyUrl)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        };

        using var res = await _http.SendAsync(req, ct).ConfigureAwait(false);
        var text = await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        Log("POST", _opts.PublicKeyUrl, (int)res.StatusCode, text);

        if (!res.IsSuccessStatusCode)
            throw new IvaApiException($"getKey failed (HTTP {(int)res.StatusCode}): {text}", ((int)res.StatusCode).ToString());

        string? keyData = null;
        try
        {
            using var doc = JsonDocument.Parse(text);
            var root = doc.RootElement;

            if (root.TryGetProperty("errors", out var errs) && errs.ValueKind == JsonValueKind.Array && errs.GetArrayLength() > 0)
                throw new IvaApiException("getKey returned errors: " + errs.GetRawText());

            keyData = TryGetString(root, "keyData")
                   ?? (root.TryGetProperty("data", out var d) && d.ValueKind == JsonValueKind.Object ? TryGetString(d, "keyData") : null)
                   ?? TryGetString(root, "data");
        }
        catch (JsonException)
        {
            // Non-JSON response; keyData stays null and we throw below with the raw text.
        }

        if (string.IsNullOrEmpty(keyData))
            throw new IvaApiException("getKey response did not contain keyData: " + text);

        Store.Set(StorageKeys.RsaPublic, keyData);
        return keyData;
    }

    /// <summary>Set the server RSA public key manually (PEM or base64).</summary>
    public void SetPublicKey(string pemOrBase64) => Store.Set(StorageKeys.RsaPublic, pemOrBase64);

    // =====================================================================
    // Key exchange (prerequisite for encrypted calls, not for the three ops)
    // =====================================================================

    /// <summary>
    /// Generate the data and working AES keys, RSA-encrypt them, and post them
    /// as DataKey / MacKey. Port of module 398.js.
    /// </summary>
    public async Task KeyExchangeAsync(CancellationToken ct = default)
    {
        var sharedKey = Crypto.GenerateKey();
        Store.Set(StorageKeys.SharedKey, Convert.ToBase64String(sharedKey));

        var workingKey = Crypto.GenerateKey();
        Store.Set(StorageKeys.WorkingKey, Convert.ToBase64String(workingKey));

        var sharedHex = Convert.ToHexString(sharedKey).ToLowerInvariant();
        var workingHex = Convert.ToHexString(workingKey).ToLowerInvariant();
        LogRequest("keyExchange (plain, pre-encryption)", new { sharedKeyHex = sharedHex, workingKeyHex = workingHex });

        // The app RSA-encrypts the hex string of each key.
        var dataKey = Crypto.RsaEncrypt(sharedHex);
        var macKey = Crypto.RsaEncrypt(workingHex);

        var sent = new { DataKey = dataKey, MacKey = macKey };
        LogRequest("keyExchange (sent)", sent);
        await PostTolerantAsync(IvaEndpoints.KeyExchange, sent, ct).ConfigureAwait(false);
    }

    // =====================================================================
    // 1) Request OTP: send the phone number, receive the SMS code.
    // =====================================================================

    /// <param name="phoneNumber">For example "09120000000".</param>
    /// <returns>Contains Token and ReagentNumber needed by VerifyCodeAsync.</returns>
    public Task<OtpRequestResult> RequestOtpAsync(string phoneNumber, CancellationToken ct = default)
    {
        CurrentPhone = phoneNumber;
        return PostDataAsync<OtpRequestResult>(IvaEndpoints.RegisterRequest,
            new { PhoneNumber = phoneNumber }, ct);
    }

    // =====================================================================
    // 2) Verify the OTP code and receive the token set.
    // =====================================================================

    /// <param name="verificationCode">The SMS code entered by the user.</param>
    /// <param name="token">Token from the RequestOtp result.</param>
    /// <param name="reagentNumber">ReagentNumber from the RequestOtp result.</param>
    public async Task<TokenResult> VerifyCodeAsync(
        string verificationCode, string? token, string? reagentNumber, CancellationToken ct = default)
    {
        var data = await PostDataAsync<TokenResult>(IvaEndpoints.Activation, new
        {
            VerificationCode = verificationCode,
            Token = token,
            ReagentNumber = reagentNumber,
        }, ct).ConfigureAwait(false);

        PersistTokens(data);
        SaveSession();
        return data;
    }

    // =====================================================================
    // 3) Refresh the access token.
    // =====================================================================

    /// <param name="refreshToken">If null, the stored refresh token is used.</param>
    public async Task<TokenResult> RefreshTokenAsync(string? refreshToken = null, CancellationToken ct = default)
    {
        var rt = refreshToken ?? Store.Get(StorageKeys.RefreshToken)
            ?? throw new InvalidOperationException("No refresh token available.");

        var data = await PostDataAsync<TokenResult>(IvaEndpoints.RefreshToken,
            new { RefreshToken = rt }, ct).ConfigureAwait(false);

        PersistTokens(data);
        SaveSession();

        // Notify subscribers (e.g. console logging) that a refresh happened.
        TokenRefreshed?.Invoke(data);
        return data;
    }

    /// <summary>Current access token formatted as an Authorization header value.</summary>
    public string Bearer() => "Bearer " + Store.Get(StorageKeys.Token);

    // =====================================================================
    // Secure channel (required before any encrypted/card call)
    // =====================================================================

    /// <summary>
    /// Ensure the encrypted channel is ready: fetch the server RSA public key if
    /// missing, then run the key exchange if the AES keys are not present.
    /// </summary>
    public async Task EnsureSecureChannelAsync(CancellationToken ct = default)
    {
        // Already have the AES keys (provided directly or from a prior exchange).
        if (Store.Has(StorageKeys.SharedKey) && Store.Has(StorageKeys.WorkingKey))
            return;

        // The charge/payment channel does NOT use Shaparak. It only needs the server
        // RSA public key to run the key exchange. Try to discover it automatically
        // from the app configuration; otherwise it must be provided via SetPublicKey.
        if (!Store.Has(StorageKeys.RsaPublic))
            await TryDiscoverPublicKeyAsync(ct).ConfigureAwait(false);

        if (!Store.Has(StorageKeys.RsaPublic))
            throw new InvalidOperationException(
                "RSA public key could not be found in the app configuration and is not set. " +
                "Provide it via SetPublicKey (the 'rsaPublic' value). Shaparak/getKey is only for card-to-card.");

        await KeyExchangeAsync(ct).ConfigureAwait(false);
        SaveSession();
    }

    /// <summary>
    /// Fetch the app configuration and scan it for a value that looks like the server
    /// RSA public key (PEM or a long base64/modulus), storing it when found. The raw
    /// configuration is echoed via ResponseReceived for inspection.
    /// </summary>
    public async Task TryDiscoverPublicKeyAsync(CancellationToken ct = default)
    {
        var version = _opts.AppVersion.Split('.');
        var query = new Dictionary<string, string?>
        {
            ["VersionCode"] = version.Length > 2 ? version[2] : _opts.AppVersion,
            ["ClientType"] = "3",
            ["MarketType"] = "4",
        };

        JsonElement config;
        try
        {
            config = await GetDataElementAsync(IvaEndpoints.AppConfiguration, query, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Log("GET", _opts.BaseAddress + IvaEndpoints.AppConfiguration, 0, "config discovery failed: " + ex.Message);
            return;
        }

        var key = FindPublicKey(config);
        if (!string.IsNullOrEmpty(key))
        {
            Store.Set(StorageKeys.RsaPublic, key!);
            Log("INFO", "rsaPublic discovered from app configuration", 200,
                key!.Length > 60 ? key[..60] + "..." : key);
        }
    }

    /// <summary>Recursively look for a public-key-like string in a JSON element.</summary>
    private static string? FindPublicKey(JsonElement el)
    {
        switch (el.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var prop in el.EnumerateObject())
                {
                    var name = prop.Name.ToLowerInvariant();
                    if (prop.Value.ValueKind == JsonValueKind.String)
                    {
                        var val = prop.Value.GetString() ?? "";
                        var nameMatch = (name.Contains("public") && name.Contains("key")) ||
                                        name.Contains("rsapublic") || name == "rsapublickey";
                        if (nameMatch && LooksLikeKey(val)) return val;
                    }
                    var nested = FindPublicKey(prop.Value);
                    if (nested is not null) return nested;
                }
                break;
            case JsonValueKind.Array:
                foreach (var item in el.EnumerateArray())
                {
                    var nested = FindPublicKey(item);
                    if (nested is not null) return nested;
                }
                break;
        }
        return null;
    }

    private static bool LooksLikeKey(string s)
    {
        if (string.IsNullOrWhiteSpace(s)) return false;
        if (s.Contains("BEGIN", StringComparison.Ordinal)) return true;
        var compact = s.Replace("\r", "").Replace("\n", "").Trim();
        return compact.Length >= 200 &&
               compact.All(c => char.IsLetterOrDigit(c) || c is '+' or '/' or '=');
    }

    // =====================================================================
    // Account profile (authenticated)
    // =====================================================================

    /// <summary>GET the signed-in user's profile (raw JSON). Auto-refreshes on a 401.</summary>
    public Task<JsonElement> GetProfileAsync(CancellationToken ct = default) =>
        GetDataElementAsync(IvaEndpoints.UserProfile, query: null, ct);

    // =====================================================================
    // Charge purchase
    // =====================================================================

    /// <summary>
    /// GET the pin-charge catalog (operators / amounts). The data section may be a
    /// bare array or an object wrapping an array, so the shape is probed flexibly.
    /// </summary>
    public async Task<IReadOnlyList<ChargeOperator>> GetChargeCatalogAsync(CancellationToken ct = default)
    {
        var data = await GetDataElementAsync(IvaEndpoints.ChargeCatalog, query: null, ct).ConfigureAwait(false);

        var array = FindFirstArray(data);
        if (array is null) return Array.Empty<ChargeOperator>();

        return array.Value.Deserialize<List<ChargeOperator>>(Json) ?? new List<ChargeOperator>();
    }

    /// <summary>Return the element itself if it is an array, otherwise the first array property.</summary>
    private static JsonElement? FindFirstArray(JsonElement el)
    {
        if (el.ValueKind == JsonValueKind.Array) return el;
        if (el.ValueKind == JsonValueKind.Object)
            foreach (var prop in el.EnumerateObject())
                if (prop.Value.ValueKind == JsonValueKind.Array)
                    return prop.Value;
        return null;
    }

    /// <summary>
    /// One-shot charge purchase: takes all the charge and card details at once (no
    /// step-by-step flow), runs the secure channel, and submits. When useProxy is
    /// true, only the charge request is routed through the configured proxy.
    /// </summary>
    public Task<ChargePurchaseResult> PurchaseChargeAsync(
        string providerCode, long amount, string targetMobileNo,
        string pan, string cvv2, string expireMonth, string expireYear, string pin,
        CancellationToken ct = default, bool useProxy = false)
    {
        var request = new ChargePurchaseRequest
        {
            Amount = amount,
            TargetMobileNo = targetMobileNo,
            ProviderId = providerCode,
            Card = new CardPayment
            {
                Pan = pan,
                Cvv2 = cvv2,
                ExpireMonth = expireMonth,
                ExpireYear = expireYear,
                Pin = pin,
            },
        };
        return BuyChargeAsync(request, ct, useProxy);
    }

    /// <summary>True when any configured message is a substring of the server message.</summary>
    internal static bool Contains(IEnumerable<string>? messages, string? serverMessage)
    {
        if (string.IsNullOrEmpty(serverMessage) || messages is null) return false;
        foreach (var m in messages)
            if (!string.IsNullOrEmpty(m) && serverMessage.Contains(m, StringComparison.Ordinal))
                return true;
        return false;
    }

    /// <summary>
    /// Resume a saved session and validate it: load it, probe with a profile call,
    /// and on failure try a single refresh + re-probe. Returns false when the session
    /// cannot be made usable. Mirrors AsanPardakht TryResumeSessionAsync.
    /// </summary>
    public async Task<bool> TryResumeSessionAsync(string phone, CancellationToken ct = default)
    {
        if (!TryResumeSession(phone)) return false;
        try
        {
            await GetProfileAsync(ct).ConfigureAwait(false);
            return true;
        }
        catch
        {
            try
            {
                await RefreshAuthAsync(ct).ConfigureAwait(false);
                await GetProfileAsync(ct).ConfigureAwait(false);
                return true;
            }
            catch { return false; }
        }
    }

    /// <summary>
    /// Buy a pin charge. Builds the payment body (AES-encrypting the card fields),
    /// applies the vendor content type, signs the body, and posts to payCharge.
    /// Requires a secure channel; it is established automatically when needed.
    /// </summary>
    public async Task<ChargePurchaseResult> BuyChargeAsync(
        ChargePurchaseRequest request, CancellationToken ct = default, bool useProxy = false)
    {
        ArgumentNullException.ThrowIfNull(request);
        request.Card.Validate();

        var contentType = PaymentContentType("payment.charge", request.Card);

        // Debug: always echo the intended request (raw, pre-encryption) FIRST, so it
        // is visible even if the secure channel / encryption step fails afterwards.
        LogRequest("charge (plain, pre-encryption)", new
        {
            endpoint = IvaEndpoints.PayCharge,
            contentType,
            paymentMedia = new
            {
                request.Card.Pan,
                request.Card.Cvv2,
                request.Card.Pin,
                ExpireDate = (request.Card.ExpireYear ?? "") + (request.Card.ExpireMonth ?? ""),
                request.Card.Token,
            },
            request.TargetMobileNo,
            request.ProviderId,
            request.Amount,
        });

        await EnsureSecureChannelAsync(ct).ConfigureAwait(false);

        // Rebuild the body each attempt: the card fields are AES-encrypted with the
        // current shared key, which a refresh + key exchange would rotate.
        long? orderId = request.OrderId; // keep a stable order id across retries
        Dictionary<string, object?> BuildBody()
        {
            var extra = new Dictionary<string, object?>
            {
                ["TTL"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["TargetMobileNo"] = request.TargetMobileNo,
                ["ProviderId"] = request.ProviderId,
            };
            if (request.Extra is not null)
                foreach (var kv in request.Extra) extra[kv.Key] = kv.Value;

            var body = CreatePaymentBody(request.Amount, request.Card, extra, pocketId: null, orderId);
            orderId ??= (long)body["OrderId"]!;
            return body;
        }

        var built = BuildBody();
        LogRequest("charge (sent, encrypted)", built);

        var (status, text) = await PostSignedOnceAsync(IvaEndpoints.PayCharge, built, contentType, ct, useProxy)
            .ConfigureAwait(false);

        // On 401: refresh (rotates keys via key exchange), rebuild, and retry once.
        if (status == HttpStatusCode.Unauthorized)
        {
            await RefreshAuthAsync(ct).ConfigureAwait(false);
            (status, text) = await PostSignedOnceAsync(IvaEndpoints.PayCharge, BuildBody(), contentType, ct, useProxy)
                .ConfigureAwait(false);
        }

        return ParseChargeOutcome(text, status);
    }

    /// <summary>
    /// Parse a charge response without throwing on a business error. A success
    /// envelope yields Success=true with the data; an error envelope yields
    /// Success=false with the server code and message (Persian text preserved).
    /// </summary>
    private static ChargePurchaseResult ParseChargeOutcome(string text, HttpStatusCode status)
    {
        try
        {
            var env = JsonSerializer.Deserialize<ApiResponse<ChargePurchaseResult>>(text, Json);
            if (env?.Error is { } err && !IsSuccessCode(err.Code))
                return new ChargePurchaseResult { Success = false, ErrorCode = err.Code, Message = err.Message };

            var data = env?.Data ?? new ChargePurchaseResult();
            data.Success = true;
            return data;
        }
        catch (JsonException)
        {
            return new ChargePurchaseResult { Success = false, ErrorCode = ((int)status).ToString(), Message = $"HTTP {(int)status}" };
        }
    }

    /// <summary>
    /// Build a payment body identical to the app's createPaymentBody:
    /// AES-encrypt Pan/Cvv2/Pin/ExpireDate; a saved Token is sent unencrypted.
    /// </summary>
    public Dictionary<string, object?> CreatePaymentBody(
        long amount, CardPayment card,
        IReadOnlyDictionary<string, object?>? extra = null,
        string? pocketId = null, long? orderId = null)
    {
        if (!Store.Has(StorageKeys.SharedKey))
            throw new InvalidOperationException("Secure channel not established. Call EnsureSecureChannelAsync first.");

        var media = new Dictionary<string, object?>();

        if (!string.IsNullOrEmpty(card.Cvv2))
            media["Cvv2"] = Crypto.AesEncrypt(card.Cvv2!);

        if (!string.IsNullOrEmpty(card.Pin))
            media["Pin"] = Crypto.AesEncrypt(card.Pin!);

        var expire = (card.ExpireYear ?? string.Empty) + PadLeft2(card.ExpireMonth);
        if (DigitsOnly(expire).Length == 4)
            media["ExpireDate"] = Crypto.AesEncrypt(expire);

        if (!string.IsNullOrEmpty(card.Token))
            media["Token"] = card.Token; // saved-card token, sent as-is
        else if (!string.IsNullOrEmpty(card.Pan))
            media["Pan"] = Crypto.AesEncrypt(card.Pan!);

        if (!string.IsNullOrEmpty(pocketId))
            media["PocketId"] = pocketId;

        var body = new Dictionary<string, object?> { ["paymentMedia"] = media };
        if (extra is not null)
            foreach (var kv in extra) body[kv.Key] = kv.Value;

        body["Amount"] = amount;
        body["OrderId"] = orderId ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        return body;
    }

    /// <summary>
    /// Build the vendor content type: application/vnd.sadad.&lt;api&gt;.&lt;variant&gt;+json,
    /// where variant is Token / Wallet / pan depending on the payment media.
    /// </summary>
    private static string PaymentContentType(string apiHeader, CardPayment card)
    {
        var variant = !string.IsNullOrEmpty(card.Token) ? "Token" : "pan";
        return $"application/vnd.sadad.{apiHeader}.{variant}+json";
    }

    private static string PadLeft2(string? s) =>
        string.IsNullOrEmpty(s) ? string.Empty : (s!.Length >= 2 ? s : s.PadLeft(2, '0'));

    private static string DigitsOnly(string s) =>
        new(s.Where(char.IsDigit).ToArray());

    // =====================================================================
    // HTTP plumbing
    // =====================================================================

    private void PersistTokens(TokenResult d)
    {
        if (!string.IsNullOrEmpty(d.RefreshToken)) Store.Set(StorageKeys.RefreshToken, d.RefreshToken!);
        if (!string.IsNullOrEmpty(d.AccessToken)) Store.Set(StorageKeys.Token, d.AccessToken!);
        if (d.ExpiresIn.HasValue) Store.Set(StorageKeys.AccessTokenExpTime, d.ExpiresIn.Value.ToString());
        if (!string.IsNullOrEmpty(d.TokenType)) Store.Set(StorageKeys.TokenType, d.TokenType!);
        Store.Set(StorageKeys.AccessTokenObtainedAt, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString());

        // The login response carries the server RSA public key as a base64 modulus in
        // the "key" field. Wrap it into a PEM (base64ToPublic) and store it, so the
        // client is self-contained and no external key source is needed.
        if (!string.IsNullOrEmpty(d.Key))
        {
            try { Store.Set(StorageKeys.RsaPublic, IvaCrypto.Base64ModulusToPem(d.Key!)); }
            catch { /* leave any pre-set key in place */ }
        }
    }

    // =====================================================================
    // Sessions (persisted per phone, next to the executable)
    // =====================================================================

    /// <summary>
    /// Load a previously saved session for the given phone into the store.
    /// Returns true when a session with an access token was restored.
    /// </summary>
    public bool TryResumeSession(string phone)
    {
        if (_sessions is null) return false;
        var s = _sessions.Load(phone);
        if (s is null || string.IsNullOrEmpty(s.Token)) return false;

        CurrentPhone = phone;
        SetOrRemove(StorageKeys.Token, s.Token);
        SetOrRemove(StorageKeys.RefreshToken, s.RefreshToken);
        SetOrRemove(StorageKeys.TokenType, s.TokenType);
        SetOrRemove(StorageKeys.AccessTokenExpTime, s.ExpiresIn?.ToString());
        SetOrRemove(StorageKeys.AccessTokenObtainedAt, s.AccessTokenObtainedAt?.ToString());
        SetOrRemove(StorageKeys.SharedKey, s.SharedKey);
        SetOrRemove(StorageKeys.WorkingKey, s.WorkingKey);
        SetOrRemove(StorageKeys.RsaPublic, s.RsaPublic);
        return true;
    }

    /// <summary>Persist the current in-memory session for CurrentPhone.</summary>
    public void SaveSession()
    {
        if (_sessions is null || string.IsNullOrEmpty(CurrentPhone)) return;

        _sessions.Save(new SessionData
        {
            Phone = CurrentPhone!,
            Token = Store.Get(StorageKeys.Token),
            RefreshToken = Store.Get(StorageKeys.RefreshToken),
            ExpiresIn = ParseLong(Store.Get(StorageKeys.AccessTokenExpTime)),
            TokenType = Store.Get(StorageKeys.TokenType),
            AccessTokenObtainedAt = ParseLong(Store.Get(StorageKeys.AccessTokenObtainedAt)),
            SharedKey = Store.Get(StorageKeys.SharedKey),
            WorkingKey = Store.Get(StorageKeys.WorkingKey),
            RsaPublic = Store.Get(StorageKeys.RsaPublic),
        });
    }

    /// <summary>True when a saved session exists for the phone.</summary>
    public bool HasSavedSession(string phone) => _sessions?.Exists(phone) ?? false;

    private void SetOrRemove(string key, string? value)
    {
        if (string.IsNullOrEmpty(value)) Store.Remove(key);
        else Store.Set(key, value);
    }

    private static long? ParseLong(string? s) =>
        long.TryParse(s, out var v) ? v : null;

    // =====================================================================
    // Auto-refresh
    // =====================================================================

    /// <summary>
    /// True when the access token is considered expired based on the stored
    /// obtained-at timestamp and expiresIn (seconds). Unknown values are treated
    /// as not expired.
    /// </summary>
    public bool IsAccessTokenExpired(int skewSeconds = 30)
    {
        var obtained = ParseLong(Store.Get(StorageKeys.AccessTokenObtainedAt));
        var expiresIn = ParseLong(Store.Get(StorageKeys.AccessTokenExpTime));
        if (obtained is null || expiresIn is null) return false;

        var expiresAt = obtained.Value + expiresIn.Value;
        return DateTimeOffset.UtcNow.ToUnixTimeSeconds() >= expiresAt - skewSeconds;
    }

    /// <summary>
    /// Refresh the token, then re-run the key exchange when an RSA public key is
    /// available (matching the original interceptor). Fires TokenRefreshed.
    /// </summary>
    public async Task RefreshAuthAsync(CancellationToken ct = default)
    {
        await RefreshTokenAsync(ct: ct).ConfigureAwait(false);
        if (Store.Has(StorageKeys.RsaPublic))
            await KeyExchangeAsync(ct).ConfigureAwait(false);
        SaveSession();
    }

    /// <summary>
    /// Send an authenticated request, transparently refreshing the token once on a
    /// 401 and retrying. Proactively refreshes first if the token looks expired.
    /// The factory must build a fresh request each time (a request can be sent once).
    /// </summary>
    public async Task<HttpResponseMessage> SendAuthorizedAsync(
        Func<HttpRequestMessage> requestFactory, CancellationToken ct = default)
    {
        if (IsAccessTokenExpired())
            await RefreshAuthAsync(ct).ConfigureAwait(false);

        var res = await SendOnceAsync(requestFactory(), ct).ConfigureAwait(false);
        if (res.StatusCode != HttpStatusCode.Unauthorized) return res;

        // Token rejected: refresh and retry exactly once.
        res.Dispose();
        await RefreshAuthAsync(ct).ConfigureAwait(false);
        return await SendOnceAsync(requestFactory(), ct).ConfigureAwait(false);
    }

    private async Task<HttpResponseMessage> SendOnceAsync(HttpRequestMessage req, CancellationToken ct)
    {
        string body = string.Empty;
        if (req.Content is not null)
            body = await req.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

        ApplyHeaders(req, req.RequestUri?.AbsolutePath ?? string.Empty, body);
        return await _http.SendAsync(req, ct).ConfigureAwait(false);
    }

    /// <summary>POST and return the envelope's data section.</summary>
    private async Task<T> PostDataAsync<T>(string path, object body, CancellationToken ct)
    {
        var envelope = await PostAsync<T>(path, body, ct).ConfigureAwait(false);
        return envelope.Data ?? throw new IvaApiException("Empty response data.");
    }

    /// <summary>
    /// POST where a 2xx with an empty or non-JSON body counts as success (e.g.
    /// keyExchange returns 200 with no body). Throws only on a non-2xx status or a
    /// parseable error envelope whose code is not 200.
    /// </summary>
    private async Task PostTolerantAsync(string path, object body, CancellationToken ct)
    {
        var json = JsonSerializer.Serialize(body, Json);
        using var req = new HttpRequestMessage(HttpMethod.Post, _opts.BaseAddress + path)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        };
        ApplyHeaders(req, path, json);

        using var res = await _http.SendAsync(req, ct).ConfigureAwait(false);
        var text = await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        Log("POST", _opts.BaseAddress + path, (int)res.StatusCode, text);

        if (!res.IsSuccessStatusCode)
            throw new IvaApiException($"{path} failed (HTTP {(int)res.StatusCode}).", ((int)res.StatusCode).ToString());

        if (!string.IsNullOrWhiteSpace(text))
        {
            try
            {
                var env = JsonSerializer.Deserialize<ApiResponse<JsonElement>>(text, Json);
                if (env?.Error is { } err && !IsSuccessCode(err.Code))
                    throw new IvaApiException(err.Message ?? "Operation failed.", err.Code);
            }
            catch (JsonException) { /* non-JSON 2xx body is fine */ }
        }
    }

    /// <summary>POST and return the full envelope, throwing on a non-success error code.</summary>
    private async Task<ApiResponse<T>> PostAsync<T>(string path, object body, CancellationToken ct)
    {
        var json = JsonSerializer.Serialize(body, Json);

        using var req = new HttpRequestMessage(HttpMethod.Post, _opts.BaseAddress + path)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        };
        ApplyHeaders(req, path, json);

        using var res = await _http.SendAsync(req, ct).ConfigureAwait(false);
        var text = await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        Log("POST", _opts.BaseAddress + path, (int)res.StatusCode, text);

        ApiResponse<T>? parsed;
        try
        {
            parsed = JsonSerializer.Deserialize<ApiResponse<T>>(text, Json);
        }
        catch (JsonException)
        {
            throw new IvaApiException($"Unexpected response (HTTP {(int)res.StatusCode}).");
        }

        parsed ??= new ApiResponse<T>();

        if (parsed.Error is { } err && !IsSuccessCode(err.Code))
            throw new IvaApiException(err.Message ?? "Operation failed.", err.Code);

        return parsed;
    }

    /// <summary>
    /// Authenticated GET that auto-refreshes on a 401 and returns the envelope's
    /// "data" element (cloned so it stays valid after the document is disposed).
    /// </summary>
    private async Task<JsonElement> GetDataElementAsync(
        string path, IReadOnlyDictionary<string, string?>? query, CancellationToken ct)
    {
        var url = _opts.BaseAddress + path + BuildQuery(query);
        using var res = await SendAuthorizedAsync(
            () => new HttpRequestMessage(HttpMethod.Get, url), ct).ConfigureAwait(false);

        var text = await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        Log("GET", url, (int)res.StatusCode, text);

        if (!res.IsSuccessStatusCode && string.IsNullOrWhiteSpace(text))
            throw new IvaApiException($"GET {path} failed (HTTP {(int)res.StatusCode}).", ((int)res.StatusCode).ToString());

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(text);
        }
        catch (JsonException)
        {
            throw new IvaApiException($"GET {path} returned invalid response (HTTP {(int)res.StatusCode}): {text}", ((int)res.StatusCode).ToString());
        }

        using (doc)
        {
            var root = doc.RootElement;
            ThrowIfErrorEnvelope(root, res.StatusCode);

            if (!res.IsSuccessStatusCode)
                throw new IvaApiException($"GET {path} failed (HTTP {(int)res.StatusCode}).", ((int)res.StatusCode).ToString());

            return root.TryGetProperty("data", out var data) ? data.Clone() : root.Clone();
        }
    }

    private static void ThrowIfErrorEnvelope(JsonElement root, HttpStatusCode status)
    {
        if (root.ValueKind != JsonValueKind.Object) return;
        if (!root.TryGetProperty("error", out var err) || err.ValueKind != JsonValueKind.Object) return;
        if (!err.TryGetProperty("code", out var code)) return;

        var codeStr = code.ValueKind == JsonValueKind.Number ? code.GetRawText() : code.GetString();
        if (codeStr is null || codeStr == "200") return;

        var message = err.TryGetProperty("message", out var m) ? m.GetString() : null;
        throw new IvaApiException(message ?? "Operation failed.", codeStr);
    }

    /// <summary>
    /// POST a signed body with a custom content type, sending exactly once and
    /// returning the status and raw text (the caller decides how to handle 401).
    /// </summary>
    private async Task<(HttpStatusCode Status, string Text)> PostSignedOnceAsync(
        string path, object body, string contentType, CancellationToken ct, bool useProxy = false)
    {
        var json = JsonSerializer.Serialize(body, Json);

        using var content = new StringContent(json, Encoding.UTF8);
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(contentType);

        using var req = new HttpRequestMessage(HttpMethod.Post, _opts.BaseAddress + path) { Content = content };
        ApplyHeaders(req, path, json);

        var http = useProxy ? GetProxyClient() : _http;
        using var res = await http.SendAsync(req, ct).ConfigureAwait(false);
        var text = await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        Log("POST", _opts.BaseAddress + path, (int)res.StatusCode, text);
        return (res.StatusCode, text);
    }

    private static T ParseEnvelopeData<T>(string text, HttpStatusCode status)
    {
        ApiResponse<T>? parsed;
        try { parsed = JsonSerializer.Deserialize<ApiResponse<T>>(text, Json); }
        catch (JsonException) { throw new IvaApiException($"Unexpected response (HTTP {(int)status})."); }

        parsed ??= new ApiResponse<T>();
        if (parsed.Error is { } err && !IsSuccessCode(err.Code))
            throw new IvaApiException(err.Message ?? "Operation failed.", err.Code);

        return parsed.Data ?? throw new IvaApiException("Empty response data.");
    }

    private static string BuildQuery(IReadOnlyDictionary<string, string?>? query)
    {
        if (query is null || query.Count == 0) return string.Empty;
        var parts = query.Where(kv => kv.Value is not null)
                         .Select(kv => $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value!)}");
        var joined = string.Join("&", parts);
        return joined.Length == 0 ? string.Empty : "?" + joined;
    }

    /// <summary>
    /// Build request headers. Authenticated calls get Authorization, version headers,
    /// and a Sign-Data HMAC. The authentication endpoints are excluded from signing.
    /// </summary>
    private void ApplyHeaders(HttpRequestMessage req, string path, string serializedBody)
    {
        if (Store.Has(StorageKeys.Token))
        {
            req.Headers.TryAddWithoutValidation("Authorization", "Bearer " + Store.Get(StorageKeys.Token));
            req.Headers.TryAddWithoutValidation("iva-versioncode", _opts.AppVersion.Replace(".", ""));
            req.Headers.TryAddWithoutValidation("iva-versionname", _opts.AppVersion);
        }

        // Sign only when there is a body and the endpoint is not excluded
        // (GET calls have no body, so they are not signed; matches the original).
        if (!string.IsNullOrEmpty(serializedBody) && !IvaEndpoints.SignExclude.Contains(path))
        {
            req.Headers.TryAddWithoutValidation("Sign-Data", Crypto.Hmac(serializedBody));
        }
    }

    private static bool IsSuccessCode(string? code) =>
        code is null || code == "200";

    private static string? TryGetString(JsonElement el, string name) =>
        el.ValueKind == JsonValueKind.Object && el.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString()
            : null;

    public void Dispose()
    {
        if (_ownsHttp) _http.Dispose();
        _proxyHttp?.Dispose();
    }
}
