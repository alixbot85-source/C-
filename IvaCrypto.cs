using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Iva.Auth;

/// <summary>
/// Cryptographic layer, a faithful port of the app crypto module (8.js).
///
/// Algorithms:
///   - AES-256-CBC, zero IV, PKCS7 padding, output as lowercase hex.
///   - HMAC-SHA256 over the request body, keyed with the working key, output base64
///     (this is the "Sign-Data" header).
///   - RSA-2048 PKCS#1 v1.5 encryption; the JSEncrypt result (base64) is re-encoded
///     to hex to match the original wire format.
///   - Key exchange: two random 32-byte AES keys (data key + working key); each key's
///     hex string is RSA-encrypted and sent as DataKey / MacKey.
///   - Pichak channel: RSA-OAEP with SHA-256 digest and MGF1-SHA1, via BouncyCastle
///     (the .NET native OAEP cannot mix SHA-256 with MGF1-SHA1).
/// </summary>
public sealed class IvaCrypto
{
    private readonly IKeyStore _store;
    private readonly SecurityOptions _sec;

    public IvaCrypto(IKeyStore store, SecurityOptions security)
    {
        _store = store;
        _sec = security;
    }

    // ---- key generation ----------------------------------------------------

    /// <summary>Generate a cryptographically random AES key (32 bytes by default).</summary>
    public byte[] GenerateKey(int? bytes = null) =>
        RandomNumberGenerator.GetBytes(bytes ?? _sec.AesKeySizeBits / 8);

    // ---- AES ---------------------------------------------------------------

    /// <summary>AES-256-CBC encrypt with the zero IV. Returns lowercase hex.</summary>
    public string AesEncrypt(string plaintext, string? keyBase64 = null) =>
        AesEncryptWithIv(plaintext, keyBase64, _sec.AesIv);

    /// <summary>AES-256-CBC encrypt with the custom IV (secondary routine).</summary>
    public string AesEncrypt2(string plaintext, string? keyBase64 = null, byte[]? iv = null) =>
        AesEncryptWithIv(plaintext, keyBase64, iv ?? _sec.CustomIv);

    /// <summary>AES-256-CBC decrypt of a hex input with the zero IV.</summary>
    public string AesDecrypt(string hex, string? keyBase64 = null) =>
        AesDecryptWithIv(hex, keyBase64, _sec.AesIv);

    private byte[] ResolveSharedKey(string? keyBase64)
    {
        var b64 = keyBase64 ?? _store.Get(StorageKeys.SharedKey)
            ?? throw new InvalidOperationException("Shared key is not set. Run KeyExchange first.");
        return Convert.FromBase64String(b64);
    }

    private string AesEncryptWithIv(string plaintext, string? keyBase64, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = ResolveSharedKey(keyBase64);
        aes.IV = iv;

        var data = Encoding.UTF8.GetBytes(plaintext);
        using var enc = aes.CreateEncryptor();
        var cipher = enc.TransformFinalBlock(data, 0, data.Length);
        return Convert.ToHexString(cipher).ToLowerInvariant();
    }

    private string AesDecryptWithIv(string hex, string? keyBase64, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = ResolveSharedKey(keyBase64);
        aes.IV = iv;

        var data = Convert.FromHexString(hex);
        using var dec = aes.CreateDecryptor();
        var plain = dec.TransformFinalBlock(data, 0, data.Length);
        return Encoding.UTF8.GetString(plain);
    }

    // ---- HMAC --------------------------------------------------------------

    /// <summary>
    /// HMAC-SHA256 over <paramref name="data"/>, keyed with the working key.
    /// Returns base64. This value goes into the "Sign-Data" header.
    /// </summary>
    public string Hmac(string data)
    {
        var keyB64 = _store.Get(StorageKeys.WorkingKey)
            ?? throw new InvalidOperationException("Working key is not set. Run KeyExchange first.");
        var key = Convert.FromBase64String(keyB64);
        using var hmac = new HMACSHA256(key);
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
        return Convert.ToBase64String(hash);
    }

    // ---- RSA (primary, PKCS#1 v1.5) ---------------------------------------

    /// <summary>
    /// RSA encrypt with PKCS#1 v1.5 padding using the stored server public key.
    /// Returns lowercase hex (matching base64ToHex(JSEncrypt.encrypt(...))).
    /// </summary>
    public string RsaEncrypt(string plaintext)
    {
        using var rsa = ImportPublicKey(
            _store.Get(StorageKeys.RsaPublic)
            ?? throw new InvalidOperationException("RSA public key is not set. Call FetchPublicKeyAsync first."));
        var cipher = rsa.Encrypt(Encoding.UTF8.GetBytes(plaintext), RSAEncryptionPadding.Pkcs1);
        return Convert.ToHexString(cipher).ToLowerInvariant();
    }

    // ---- RSA (pichak channel, OAEP SHA-256 / MGF1-SHA1) -------------------

    /// <summary>
    /// RSA-OAEP encrypt using SHA-256 as the OAEP digest and SHA-1 for MGF1,
    /// matching the pichak channel. Returns base64. Uses BouncyCastle.
    /// </summary>
    public string PichakRsaEncrypt(string plaintext, string? publicKey = null)
    {
        var key = publicKey ?? _store.Get(StorageKeys.PichakRsaPublic)
            ?? throw new InvalidOperationException("Pichak RSA public key is not set.");
        var rsaParams = ToBouncyPublicKey(key);

        var oaep = new OaepEncoding(
            new RsaEngine(),
            new Sha256Digest(),   // OAEP hash
            new Sha1Digest(),     // MGF1 hash
            null);
        oaep.Init(true, rsaParams);

        var input = Encoding.UTF8.GetBytes(plaintext);
        var output = oaep.ProcessBlock(input, 0, input.Length);
        return Convert.ToBase64String(output);
    }

    // ---- key import helpers -----------------------------------------------

    /// <summary>
    /// Import a public key that may be (a) a PEM block, (b) a base64 SPKI DER,
    /// or (c) a bare base64 RSA modulus (exponent assumed 65537).
    /// </summary>
    public static RSA ImportPublicKey(string key)
    {
        var rsa = RSA.Create();
        var trimmed = key.Trim();

        if (trimmed.Contains("BEGIN", StringComparison.Ordinal))
        {
            rsa.ImportFromPem(trimmed);
            return rsa;
        }

        var bytes = Convert.FromBase64String(StripBase64(trimmed));

        try
        {
            rsa.ImportSubjectPublicKeyInfo(bytes, out _);
            return rsa;
        }
        catch (CryptographicException)
        {
            // Treat the bytes as a raw modulus with the standard public exponent.
            rsa.ImportParameters(new RSAParameters
            {
                Modulus = bytes,
                Exponent = new byte[] { 0x01, 0x00, 0x01 },
            });
            return rsa;
        }
    }

    private static RsaKeyParameters ToBouncyPublicKey(string key)
    {
        var trimmed = key.Trim();

        if (trimmed.Contains("BEGIN", StringComparison.Ordinal))
        {
            var obj = new Org.BouncyCastle.OpenSsl.PemReader(new StringReader(trimmed)).ReadObject();
            return obj switch
            {
                RsaKeyParameters p => p,
                Org.BouncyCastle.Crypto.AsymmetricKeyParameter ak => (RsaKeyParameters)ak,
                _ => throw new InvalidOperationException("Unsupported PEM key material."),
            };
        }

        var der = Convert.FromBase64String(StripBase64(trimmed));
        try
        {
            return (RsaKeyParameters)PublicKeyFactory.CreateKey(der);
        }
        catch
        {
            var modulus = new Org.BouncyCastle.Math.BigInteger(1, der);
            var exponent = Org.BouncyCastle.Math.BigInteger.ValueOf(65537);
            return new RsaKeyParameters(false, modulus, exponent);
        }
    }

    private static string StripBase64(string s) =>
        s.Replace("\r", "").Replace("\n", "").Replace(" ", "");

    // ---- encoding helpers (kept for parity with 8.js) ---------------------

    public static string Base64ToHex(string base64) =>
        Convert.ToHexString(Convert.FromBase64String(base64)).ToLowerInvariant();

    public static string HexToBase64(string hex) =>
        Convert.ToBase64String(Convert.FromHexString(hex));

    /// <summary>
    /// Build an SPKI PEM from a bare base64 RSA modulus (exponent 65537),
    /// equivalent to base64ToPublic in 8.js.
    /// </summary>
    public static string Base64ModulusToPem(string base64Modulus)
    {
        const string spkiPrefix =
            "30820122300D06092A864886F70D01010105000382010F003082010A0282010100";
        const string spkiSuffix = "0203010001";
        var der = spkiPrefix + Base64ToHex(base64Modulus) + spkiSuffix;
        var b64 = HexToBase64(der);
        var lines = string.Join("\n",
            Enumerable.Range(0, (b64.Length + 63) / 64)
                      .Select(i => b64.Substring(i * 64, Math.Min(64, b64.Length - i * 64))));
        return $"-----BEGIN PUBLIC KEY-----\n{lines}\n-----END PUBLIC KEY-----";
    }
}
