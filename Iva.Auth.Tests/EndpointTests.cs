using System.Net;
using Iva.Auth.Payments;
using Iva.Auth.Tests.Fixtures;
using Iva.Auth.Tests.MockApi;
using Xunit;

namespace Iva.Auth.Tests;

public class EndpointTests : IDisposable
{
    private readonly MockIvaApiHandler _mockHandler;
    private readonly HttpClient _httpClient;
    private readonly IvaAuthClient _client;

    public EndpointTests()
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
    public async Task Endpoint1_VerifyCode_Success_And_Negative()
    {
        // Success
        var res = await _client.RequestOtpAsync("09121111111");
        Assert.NotNull(res.Token);

        // Negative 400 Bad Request
        _mockHandler.ForceStatusForPath = HttpStatusCode.BadRequest;
        _mockHandler.ForceStatusPathPrefix = IvaEndpoints.RegisterRequest;
        await Assert.ThrowsAsync<IvaApiException>(() => _client.RequestOtpAsync("invalid_phone"));
    }

    [Fact]
    public async Task Endpoint2_Token_Success_And_Negative()
    {
        // Success
        var res = await _client.VerifyCodeAsync("12345", "token123", "0");
        Assert.NotNull(res.AccessToken);

        // Negative 400 Bad Request
        _mockHandler.ForceStatusForPath = HttpStatusCode.BadRequest;
        _mockHandler.ForceStatusPathPrefix = IvaEndpoints.Activation;
        await Assert.ThrowsAsync<IvaApiException>(() => _client.VerifyCodeAsync("wrong_code", "token123", "0"));
    }

    [Fact]
    public async Task Endpoint3_RefreshToken_Success_And_Negative()
    {
        // Setup existing token
        _client.Store.Set(StorageKeys.RefreshToken, "mock_initial_refresh_token");

        // Success
        var res = await _client.RefreshTokenAsync();
        Assert.NotNull(res.AccessToken);

        // Negative 401 Unauthorized
        _mockHandler.SimulateRefreshTokenFailure = true;
        await Assert.ThrowsAsync<IvaApiException>(() => _client.RefreshTokenAsync());
    }

    [Fact]
    public async Task Endpoint4_KeyExchange_Success_And_Negative()
    {
        _client.SetPublicKey(TestKeyFixture.PublicKeyPem);

        // Success
        await _client.KeyExchangeAsync();
        Assert.True(_client.Store.Has(StorageKeys.SharedKey));

        // Negative 500 Internal Server Error
        _mockHandler.ForceStatusForPath = HttpStatusCode.InternalServerError;
        _mockHandler.ForceStatusPathPrefix = IvaEndpoints.KeyExchange;
        await Assert.ThrowsAsync<IvaApiException>(() => _client.KeyExchangeAsync());
    }

    [Fact]
    public async Task Endpoint5_UserProfile_Success_And_Negative()
    {
        _client.Store.Set(StorageKeys.Token, "valid_mock_token");

        // Success
        var profile = await _client.GetProfileAsync();
        Assert.NotNull(profile);
        Assert.Equal("mock_user_1001", profile.GetProperty("userId").GetString());

        // Negative 403 Forbidden
        _mockHandler.ForceStatusForPath = HttpStatusCode.Forbidden;
        _mockHandler.ForceStatusPathPrefix = IvaEndpoints.UserProfile;
        await Assert.ThrowsAsync<IvaApiException>(() => _client.GetProfileAsync());
    }

    [Fact]
    public async Task Endpoint6_AppConfiguration_Success_And_KeyDiscovery()
    {
        _client.Store.Remove(StorageKeys.RsaPublic);

        // Act
        await _client.TryDiscoverPublicKeyAsync();

        // Assert
        Assert.True(_client.Store.Has(StorageKeys.RsaPublic));
        Assert.Equal(TestKeyFixture.PublicKeyPem, _client.Store.Get(StorageKeys.RsaPublic));
    }

    [Fact]
    public async Task Endpoint7_ChargeCatalog_Success_And_Negative()
    {
        _client.Store.Set(StorageKeys.Token, "valid_mock_token");

        // Success
        var catalog = await _client.GetChargeCatalogAsync();
        Assert.NotNull(catalog);
        Assert.Equal(2, catalog.Count);
        Assert.Equal("MCI", catalog[0].Code);

        // Negative 502 Bad Gateway
        _mockHandler.ForceStatusForPath = HttpStatusCode.BadGateway;
        _mockHandler.ForceStatusPathPrefix = IvaEndpoints.ChargeCatalog;
        await Assert.ThrowsAsync<IvaApiException>(() => _client.GetChargeCatalogAsync());
    }

    [Fact]
    public async Task Endpoint8_PayCharge_Success_And_Negative()
    {
        _client.Store.Set(StorageKeys.Token, "valid_mock_token");
        _client.SetPublicKey(TestKeyFixture.PublicKeyPem);
        await _client.KeyExchangeAsync();

        // Success
        var result = await _client.PurchaseChargeAsync(
            providerCode: "MCI",
            amount: 10000,
            targetMobileNo: "09121234567",
            pan: "6037990000000000",
            cvv2: "123",
            expireMonth: "12",
            expireYear: "05",
            pin: "123456");

        Assert.True(result.Success);
        Assert.Equal("1234567890123456", result.Pin);
        Assert.Equal("TRK_MOCK_12345", result.TrackingCode);

        // Negative 500 error
        _mockHandler.ForceStatusForPath = HttpStatusCode.InternalServerError;
        _mockHandler.ForceStatusPathPrefix = IvaEndpoints.PayCharge;

        var failResult = await _client.PurchaseChargeAsync(
            providerCode: "MCI", amount: 10000, targetMobileNo: "09121234567",
            pan: "6037990000000000", cvv2: "123", expireMonth: "12", expireYear: "05", pin: "123456");

        Assert.False(failResult.Success);
        Assert.Equal("500", failResult.ErrorCode);
    }
}
