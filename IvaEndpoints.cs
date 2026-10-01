namespace Iva.Auth;

/// <summary>
/// API endpoint paths (relative to the /pwa/api prefix), extracted from the app bundle.
/// </summary>
public static class IvaEndpoints
{
    public const string KeyExchange = "/v1/users/auth/keyExchange";

    /// <summary>Send phone number, server responds with an OTP via SMS.</summary>
    public const string RegisterRequest = "/v1/users/auth/verifyCode";

    /// <summary>Submit the OTP code, server responds with the token set.</summary>
    public const string Activation = "/v1/users/auth/token";

    /// <summary>Exchange a refresh token for a fresh access token.</summary>
    public const string RefreshToken = "/v1/users/auth/refreshtoken";

    /// <summary>Authenticated endpoint, handy for validating the access token.</summary>
    public const string UserProfile = "/v1/users/me";

    /// <summary>App configuration list (may carry the server RSA public key).</summary>
    public const string AppConfiguration = "/v1/baseInfo/configs/list";

    /// <summary>Pin-charge catalog (operators / amounts).</summary>
    public const string ChargeCatalog = "/v3/charges/pin/mobile/catalog";

    /// <summary>Pin-charge payment.</summary>
    public const string PayCharge = "/v1/charges/pin/payment";

    /// <summary>Topup (direct charge) payment.</summary>
    public const string TopupRequest = "/v1/charges/topup/payment";

    /// <summary>
    /// Endpoints whose request body is neither signed (Sign-Data) nor encrypted.
    /// All authentication endpoints belong here.
    /// </summary>
    public static readonly IReadOnlySet<string> SignExclude = new HashSet<string>
    {
        KeyExchange,
        RegisterRequest,
        Activation,
        RefreshToken,
    };
}

/// <summary>Storage keys used by the original app (kept identical for parity).</summary>
public static class StorageKeys
{
    public const string Token = "token";
    public const string RefreshToken = "refreshToken";
    public const string AccessTokenExpTime = "accessTokenExpTime";
    public const string TokenType = "tokenType";

    public const string AccessTokenObtainedAt = "accessTokenObtainedAt"; // unix seconds

    public const string SharedKey = "shared_key";   // AES data key (DataKey)
    public const string WorkingKey = "working_key"; // HMAC key (MacKey)
    public const string RsaPublic = "rsaPublic";    // server RSA public key

    public const string PichakRsaPublic = "pichakRSAPublic";
}
