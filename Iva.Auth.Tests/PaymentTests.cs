using System.Text.Json;
using Iva.Auth.Payments;
using Iva.Auth.Tests.Fixtures;
using Iva.Auth.Tests.MockApi;
using Xunit;

namespace Iva.Auth.Tests;

public class PaymentTests : IDisposable
{
    private readonly MockIvaApiHandler _mockHandler;
    private readonly HttpClient _httpClient;
    private readonly IvaAuthClient _client;

    public PaymentTests()
    {
        _mockHandler = new MockIvaApiHandler();
        _httpClient = new HttpClient(_mockHandler);
        var options = new IvaOptions { ApiBaseUrl = "https://ivaapi.sadadpsp.ir", ApiPrefix = "/pwa/api" };
        _client = new IvaAuthClient(options, store: new InMemoryKeyStore(), http: _httpClient);
    }

    public void Dispose()
    {
        _client.Dispose();
        _httpClient.Dispose();
        _mockHandler.Dispose();
    }

    [Fact]
    public void CardPayment_Validate_Should_Throw_When_Both_Pan_And_Token_Empty()
    {
        var card = new CardPayment();
        Assert.Throws<ArgumentException>(() => card.Validate());
    }

    [Fact]
    public void CardPayment_Validate_Should_Pass_When_Pan_Or_Token_Provided()
    {
        var cardWithPan = new CardPayment { Pan = "6037990000000000" };
        cardWithPan.Validate(); // should not throw

        var cardWithToken = new CardPayment { Token = "saved_card_token_123" };
        cardWithToken.Validate(); // should not throw
    }

    [Fact]
    public async Task BuyChargeAsync_Should_Encrypt_Card_Fields_With_Aes()
    {
        // Arrange: Setup secure channel
        _client.Store.Set(StorageKeys.Token, "valid_mock_token");
        _client.SetPublicKey(TestKeyFixture.PublicKeyPem);
        await _client.KeyExchangeAsync();

        var sharedKeyBytes = Convert.FromBase64String(_client.Store.Get(StorageKeys.SharedKey)!);

        var request = new ChargePurchaseRequest
        {
            Amount = 20000,
            TargetMobileNo = "09121112233",
            ProviderId = "MCI",
            Card = new CardPayment
            {
                Pan = "6037990000000000",
                Cvv2 = "456",
                ExpireMonth = "08",
                ExpireYear = "06",
                Pin = "654321"
            }
        };

        // Act
        var result = await _client.BuyChargeAsync(request);

        // Assert
        Assert.True(result.Success);

        var payReq = Assert.Single(_mockHandler.RecordedRequests.Where(r => r.Path.EndsWith(IvaEndpoints.PayCharge)));
        using var doc = JsonDocument.Parse(payReq.Body);
        var root = doc.RootElement;

        var media = root.GetProperty("paymentMedia");
        var encryptedPan = media.GetProperty("Pan").GetString();
        var encryptedCvv2 = media.GetProperty("Cvv2").GetString();
        var encryptedPin = media.GetProperty("Pin").GetString();
        var encryptedExpire = media.GetProperty("ExpireDate").GetString();

        Assert.NotNull(encryptedPan);
        Assert.NotNull(encryptedCvv2);
        Assert.NotNull(encryptedPin);
        Assert.NotNull(encryptedExpire);

        // Verify that decrypted values match original card data
        Assert.Equal("6037990000000000", TestKeyFixture.DecryptAesHex(encryptedPan, sharedKeyBytes));
        Assert.Equal("456", TestKeyFixture.DecryptAesHex(encryptedCvv2, sharedKeyBytes));
        Assert.Equal("654321", TestKeyFixture.DecryptAesHex(encryptedPin, sharedKeyBytes));
        Assert.Equal("0608", TestKeyFixture.DecryptAesHex(encryptedExpire, sharedKeyBytes));
    }

    [Fact]
    public async Task BuyChargeAsync_Should_Set_Sadad_ContentType_And_SignData_Header()
    {
        // Arrange
        _client.Store.Set(StorageKeys.Token, "valid_mock_token");
        _client.SetPublicKey(TestKeyFixture.PublicKeyPem);
        await _client.KeyExchangeAsync();

        var workingKeyBytes = Convert.FromBase64String(_client.Store.Get(StorageKeys.WorkingKey)!);

        var request = new ChargePurchaseRequest
        {
            Amount = 10000,
            TargetMobileNo = "09120000000",
            ProviderId = "MTN",
            Card = new CardPayment { Pan = "6037990000000000" }
        };

        // Act
        await _client.BuyChargeAsync(request);

        // Assert
        var payReq = Assert.Single(_mockHandler.RecordedRequests.Where(r => r.Path.EndsWith(IvaEndpoints.PayCharge)));

        Assert.Contains("application/vnd.sadad.payment.charge.pan+json", payReq.Headers["Content-Type"].First());
        Assert.Contains("Sign-Data", payReq.Headers.Keys);

        var signData = payReq.Headers["Sign-Data"].First();
        Assert.True(TestKeyFixture.VerifyHmac(payReq.Body, signData, workingKeyBytes));
    }

    [Fact]
    public async Task BuyChargeAsync_Saved_Card_Token_Should_Not_Be_Aes_Encrypted()
    {
        // Arrange
        _client.Store.Set(StorageKeys.Token, "valid_mock_token");
        _client.SetPublicKey(TestKeyFixture.PublicKeyPem);
        await _client.KeyExchangeAsync();

        var request = new ChargePurchaseRequest
        {
            Amount = 10000,
            TargetMobileNo = "09120000000",
            ProviderId = "MTN",
            Card = new CardPayment { Token = "token_card_abc123" }
        };

        // Act
        await _client.BuyChargeAsync(request);

        // Assert
        var payReq = Assert.Single(_mockHandler.RecordedRequests.Where(r => r.Path.EndsWith(IvaEndpoints.PayCharge)));
        Assert.Contains("application/vnd.sadad.payment.charge.Token+json", payReq.Headers["Content-Type"].First());

        using var doc = JsonDocument.Parse(payReq.Body);
        var media = doc.RootElement.GetProperty("paymentMedia");
        Assert.Equal("token_card_abc123", media.GetProperty("Token").GetString());
    }
}
