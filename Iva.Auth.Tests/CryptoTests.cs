using System.Security.Cryptography;
using System.Text;
using Iva.Auth.Tests.Fixtures;
using Xunit;

namespace Iva.Auth.Tests;

public class CryptoTests
{
    private readonly IKeyStore _store;
    private readonly SecurityOptions _sec;
    private readonly IvaCrypto _crypto;

    public CryptoTests()
    {
        _store = new InMemoryKeyStore();
        _sec = new SecurityOptions();
        _crypto = new IvaCrypto(_store, _sec);
    }

    [Fact]
    public void AesEncrypt_And_Decrypt_With_Zero_IV_Should_Match()
    {
        // Arrange
        var key = _crypto.GenerateKey(32);
        var keyBase64 = Convert.ToBase64String(key);
        var plaintext = "Sample Plaintext For AES Encryption Test 12345! @#$";

        // Act
        var encryptedHex = _crypto.AesEncrypt(plaintext, keyBase64);
        var decryptedText = _crypto.AesDecrypt(encryptedHex, keyBase64);

        // Assert
        Assert.NotNull(encryptedHex);
        Assert.Equal(plaintext, decryptedText);
    }

    [Fact]
    public void AesEncrypt2_With_Custom_IV_Should_Match()
    {
        // Arrange
        var key = _crypto.GenerateKey(32);
        var keyBase64 = Convert.ToBase64String(key);
        var plaintext = "Secondary AES Routine Test";

        // Act
        var encryptedHex = _crypto.AesEncrypt2(plaintext, keyBase64);
        var decryptedViaFixture = TestKeyFixture.DecryptAesHex(encryptedHex, key, _sec.CustomIv);

        // Assert
        Assert.Equal(plaintext, decryptedViaFixture);
    }

    [Fact]
    public void Hmac_Should_Produce_Consistent_Base64_Signatures()
    {
        // Arrange
        var workingKey = _crypto.GenerateKey(32);
        _store.Set(StorageKeys.WorkingKey, Convert.ToBase64String(workingKey));
        var data = "{\"Amount\":10000,\"TargetMobileNo\":\"09120000000\"}";

        // Act
        var signature1 = _crypto.Hmac(data);
        var signature2 = _crypto.Hmac(data);

        // Assert
        Assert.Equal(signature1, signature2);
        Assert.True(TestKeyFixture.VerifyHmac(data, signature1, workingKey));
    }

    [Fact]
    public void Hmac_Different_Data_Or_Key_Should_Produce_Different_Signature()
    {
        // Arrange
        var key1 = _crypto.GenerateKey(32);
        var key2 = _crypto.GenerateKey(32);
        _store.Set(StorageKeys.WorkingKey, Convert.ToBase64String(key1));

        var data1 = "Payload One";
        var data2 = "Payload Two";

        // Act
        var sig1 = _crypto.Hmac(data1);
        var sig2 = _crypto.Hmac(data2);

        _store.Set(StorageKeys.WorkingKey, Convert.ToBase64String(key2));
        var sig3 = _crypto.Hmac(data1);

        // Assert
        Assert.NotEqual(sig1, sig2);
        Assert.NotEqual(sig1, sig3);
    }

    [Fact]
    public void RsaEncrypt_With_Pkcs1_Should_Encrypt_And_Be_Decryptable()
    {
        // Arrange
        _store.Set(StorageKeys.RsaPublic, TestKeyFixture.PublicKeyPem);
        var plain = "SecretAESKeyHexFormat1234567890abcdef";

        // Act
        var hexCipher = _crypto.RsaEncrypt(plain);

        // Assert
        Assert.NotNull(hexCipher);
        var decrypted = TestKeyFixture.DecryptRsaHex(hexCipher);
        Assert.Equal(plain, decrypted);
    }

    [Fact]
    public void Base64ModulusToPem_Should_Wrap_Modulus_Into_Valid_SPKI_Pem()
    {
        // Arrange
        var modulus = TestKeyFixture.ModulusBase64;

        // Act
        var pem = IvaCrypto.Base64ModulusToPem(modulus);

        // Assert
        Assert.StartsWith("-----BEGIN PUBLIC KEY-----", pem);
        Assert.EndsWith("-----END PUBLIC KEY-----", pem);

        // Import the created PEM to verify ASN.1 validity
        using var importedRsa = IvaCrypto.ImportPublicKey(pem);
        Assert.NotNull(importedRsa);
    }

    [Fact]
    public void PichakRsaEncrypt_Should_Produce_Base64_Ciphertext()
    {
        // Act (Note: Tests internal algorithm logic, not live Pichak bank server)
        var ciphertext = _crypto.PichakRsaEncrypt("PichakTestMessage", TestKeyFixture.PublicKeyPem);

        // Assert
        Assert.NotNull(ciphertext);
        Assert.NotEmpty(ciphertext);
        var raw = Convert.FromBase64String(ciphertext);
        Assert.Equal(256, raw.Length); // 2048-bit RSA output
    }

    [Fact]
    public void CryptoGuards_Should_Throw_On_Null_Or_Empty_Inputs()
    {
        Assert.Throws<ArgumentException>(() => IvaCrypto.ImportPublicKey(""));
        Assert.Throws<ArgumentException>(() => IvaCrypto.ImportPublicKey("   "));
        Assert.Throws<ArgumentException>(() => IvaCrypto.Base64ModulusToPem(""));
    }
}
