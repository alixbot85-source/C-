namespace Iva.Auth;

/// <summary>Security parameters, mirrored from the app config (module 0.js).</summary>
public sealed class SecurityOptions
{
    public int RsaSize { get; set; } = 2048;
    public int AesKeySizeBits { get; set; } = 256;

    /// <summary>Zero IV used by the primary AES routine.</summary>
    public byte[] AesIv { get; set; } = new byte[16];

    /// <summary>Custom IV used only by the secondary AES routine (aesEncrypt2).</summary>
    public byte[] CustomIv { get; set; } =
        { 48, 148, 136, 186, 72, 57, 83, 116, 19, 138, 210, 230, 3, 165, 240, 35 };
}

/// <summary>Client configuration.</summary>
public sealed class IvaOptions
{
    public string ApiBaseUrl { get; set; } = "https://ivapwa.sadadpsp.ir";

    /// <summary>All API paths are served under this prefix.</summary>
    public string ApiPrefix { get; set; } = "/pwa/api";

    /// <summary>Endpoint that returns the server RSA public key (POST).</summary>
    public string PublicKeyUrl { get; set; } = "https://tsm.shaparak.ir/mobileApp/getKey";

    /// <summary>Optional keyId sent in the getKey request body.</summary>
    public string? KeyId { get; set; }

    /// <summary>Optional transactionId sent in the getKey request body.</summary>
    public string? TransactionId { get; set; }

    public string AppVersion { get; set; } = "3.10.24";

    public TimeSpan Timeout { get; set; } = TimeSpan.FromMilliseconds(65000);

    // ---- charge retry policy (modeled after the AsanPardakht client) ----

    /// <summary>Max same-account retries for a transient/retryable charge message.</summary>
    public int MaxChargeRetries { get; set; } = 10;

    /// <summary>Delay between same-account charge retries.</summary>
    public TimeSpan ChargeRetryDelay { get; set; } = TimeSpan.FromMilliseconds(500);

    /// <summary>
    /// Server messages (substring match) that trigger a charge retry. On each retry a
    /// fresh RANDOM account is picked.
    /// </summary>
    public List<string> RetryableStatusMessages { get; set; } = new()
    {
        "محدودیت روزانه تراکنش",
        "عملیات ناموفق بود",
        "سرویس در حال حاضر قادر به پاسخگویی نیست",
    };

    /// <summary>
    /// Subset of retryable messages meaning the account hit its own daily limit. Such
    /// an account is set aside for the rest of the call so its cap is never exceeded.
    /// </summary>
    public List<string> DailyLimitMessages { get; set; } = new()
    {
        "محدودیت روزانه تراکنش",
    };

    /// <summary>
    /// Optional proxy for the charge request (host:port:username:password). Unset by
    /// default; useProxy has no effect unless this is configured.
    /// </summary>
    public string? ChargeProxy { get; set; }

    public SecurityOptions Security { get; set; } = new();

    /// <summary>Full base address including the prefix.</summary>
    public string BaseAddress => ApiBaseUrl.TrimEnd('/') + ApiPrefix;
}
