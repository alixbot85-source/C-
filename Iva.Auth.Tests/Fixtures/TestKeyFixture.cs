using System.Security.Cryptography;
using System.Text;

namespace Iva.Auth.Tests.Fixtures;

/// <summary>
/// Provides RSA test keys and test helper methods for unit & integration testing.
/// Uses self-contained ephemeral test keys; never contains real secrets or production credentials.
/// </summary>
public static class TestKeyFixture
{
    private static readonly RSA Rsa = RSA.Create(2048);

    public static string PublicKeyPem { get; }
    public static string ModulusBase64 { get; }
    public static string ExponentBase64 { get; }

    static TestKeyFixture()
    {
        PublicKeyPem = Rsa.ExportSubjectPublicKeyInfoPem();
        var parameters = Rsa.ExportParameters(false);
        ModulusBase64 = Convert.ToBase64String(parameters.Modulus!);
        ExponentBase64 = Convert.ToBase64String(parameters.Exponent!);
    }

    public static string DecryptRsaHex(string hexCipher)
    {
        var cipherBytes = Convert.FromHexString(hexCipher);
        var plainBytes = Rsa.Decrypt(cipherBytes, RSAEncryptionPadding.Pkcs1);
        return Encoding.UTF8.GetString(plainBytes);
    }

    public static string DecryptAesHex(string hexCipher, byte[] key, byte[]? iv = null)
    {
        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = key;
        aes.IV = iv ?? new byte[16];

        var cipherBytes = Convert.FromHexString(hexCipher);
        using var decryptor = aes.CreateDecryptor();
        var plainBytes = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
        return Encoding.UTF8.GetString(plainBytes);
    }

    public static bool VerifyHmac(string data, string base64Signature, byte[] workingKey)
    {
        using var hmac = new HMACSHA256(workingKey);
        var computed = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(data)));
        return computed == base64Signature;
    }
}
