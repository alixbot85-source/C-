using System.Text.Json;
using Iva.Auth.Sessions;
using Iva.Auth.Tests.Fixtures;
using Iva.Auth.Tests.MockApi;
using Xunit;

namespace Iva.Auth.Tests;

public class AuthenticationTests : IDisposable
{
    private readonly string _tempDir;
    private readonly ISessionRepository _sessionRepo;
    private readonly MockIvaApiHandler _mockHandler;
    private readonly HttpClient _httpClient;
    private readonly IvaOptions _options;
    private readonly IvaAuthClient _client;

    public AuthenticationTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "iva_test_auth_" + Guid.NewGuid().ToString("N"));
        _sessionRepo = new FileSessionRepository(_tempDir);
        _mockHandler = new MockIvaApiHandler();
        _httpClient = new HttpClient(_mockHandler);
        _options = new IvaOptions { ApiBaseUrl = "https://ivaapi.sadadpsp.ir", ApiPrefix = "/pwa/api" };
        _client = new IvaAuthClient(_options, store: new InMemoryKeyStore(), http: _httpClient, sessions: _sessionRepo);
    }

    public void Dispose()
    {
        _client.Dispose();
        _httpClient.Dispose();
        _mockHandler.Dispose();
        try { if (Directory.Exists(_tempDir)) Directory.Delete(_tempDir, true); } catch { }
    }

    [Fact]
    public async Task RequestOtpAsync_Should_Send_Correct_Payload_And_Return_Token()
    {
        // Act
        var res = await _client.RequestOtpAsync("09120000000");

        // Assert
        Assert.NotNull(res);
        Assert.Equal("mock_otp_flow_token_abc123", res.Token);
        Assert.Equal("0", res.ReagentNumber);
        Assert.Equal("09120000000", _client.CurrentPhone);

        var req = Assert.Single(_mockHandler.RecordedRequests.Where(r => r.Path.EndsWith(IvaEndpoints.RegisterRequest)));
        Assert.Equal("POST", req.Method);
        using var doc = JsonDocument.Parse(req.Body);
        Assert.Equal("09120000000", doc.RootElement.GetProperty("PhoneNumber").GetString());
    }

    [Fact]
    public async Task VerifyCodeAsync_Should_Return_Tokens_And_Persist_State()
    {
        // Arrange
        await _client.RequestOtpAsync("09120000000");

        // Act
        var res = await _client.VerifyCodeAsync("12345", "mock_otp_flow_token_abc123", "0");

        // Assert
        Assert.NotNull(res);
        Assert.Equal("mock_access_token_12345", res.AccessToken);
        Assert.Equal("mock_refresh_token_67890", res.RefreshToken);

        // Check in-memory store
        Assert.Equal("mock_access_token_12345", _client.Store.Get(StorageKeys.Token));
        Assert.Equal("mock_refresh_token_67890", _client.Store.Get(StorageKeys.RefreshToken));
        Assert.True(_client.Store.Has(StorageKeys.RsaPublic));

        // Check session repository persistence
        Assert.True(_client.HasSavedSession("09120000000"));
        var saved = _sessionRepo.Load("09120000000");
        Assert.NotNull(saved);
        Assert.Equal("mock_access_token_12345", saved.Token);
    }

    [Fact]
    public async Task KeyExchangeAsync_Should_Generate_Keys_And_Send_Rsa_Encrypted_Hex()
    {
        // Arrange
        _client.SetPublicKey(TestKeyFixture.PublicKeyPem);

        // Act
        await _client.KeyExchangeAsync();

        // Assert
        Assert.True(_client.Store.Has(StorageKeys.SharedKey));
        Assert.True(_client.Store.Has(StorageKeys.WorkingKey));

        var req = Assert.Single(_mockHandler.RecordedRequests.Where(r => r.Path.EndsWith(IvaEndpoints.KeyExchange)));
        Assert.Equal("POST", req.Method);

        using var doc = JsonDocument.Parse(req.Body);
        var dataKeyEncrypted = doc.RootElement.GetProperty("DataKey").GetString();
        var macKeyEncrypted = doc.RootElement.GetProperty("MacKey").GetString();

        Assert.NotNull(dataKeyEncrypted);
        Assert.NotNull(macKeyEncrypted);

        // Verify that decrypted RSA payload matches generated AES key in hex
        var decryptedDataKeyHex = TestKeyFixture.DecryptRsaHex(dataKeyEncrypted);
        var decryptedMacKeyHex = TestKeyFixture.DecryptRsaHex(macKeyEncrypted);

        var storedSharedKeyHex = Convert.ToHexString(Convert.FromBase64String(_client.Store.Get(StorageKeys.SharedKey)!)).ToLowerInvariant();
        var storedWorkingKeyHex = Convert.ToHexString(Convert.FromBase64String(_client.Store.Get(StorageKeys.WorkingKey)!)).ToLowerInvariant();

        Assert.Equal(storedSharedKeyHex, decryptedDataKeyHex);
        Assert.Equal(storedWorkingKeyHex, decryptedMacKeyHex);
    }

    [Fact]
    public async Task Full_Authentication_Flow_Should_Establish_Valid_Secure_Channel()
    {
        // 1. Request OTP
        var otpRes = await _client.RequestOtpAsync("09121234567");
        Assert.NotNull(otpRes.Token);

        // 2. Verify Code
        var tokenRes = await _client.VerifyCodeAsync("98765", otpRes.Token, otpRes.ReagentNumber);
        Assert.NotNull(tokenRes.AccessToken);

        // 3. Ensure Secure Channel (runs KeyExchange using key extracted from login)
        await _client.EnsureSecureChannelAsync();

        // 4. Authenticated profile call
        var profile = await _client.GetProfileAsync();
        Assert.Equal("mock_user_1001", profile.GetProperty("userId").GetString());

        // Verify Bearer Header
        var profileReq = Assert.Single(_mockHandler.RecordedRequests.Where(r => r.Path.EndsWith(IvaEndpoints.UserProfile)));
        Assert.Contains("Authorization", profileReq.Headers.Keys);
        Assert.Contains("Bearer mock_access_token_12345", profileReq.Headers["Authorization"].First());
    }

    [Fact]
    public async Task SendAuthorizedAsync_Should_AutoRefresh_On_401_And_Retry_Once()
    {
        // Arrange
        await _client.RequestOtpAsync("09121234567");
        await _client.VerifyCodeAsync("98765", "tok", "0");
        _mockHandler.Simulate401OnNextMeRequest = true;

        bool refreshFired = false;
        _client.TokenRefreshed += tr => refreshFired = true;

        // Act
        var profile = await _client.GetProfileAsync();

        // Assert
        Assert.True(refreshFired);
        Assert.Equal("mock_user_1001", profile.GetProperty("userId").GetString());
        Assert.Equal("mock_refreshed_access_token_99999", _client.Store.Get(StorageKeys.Token));

        // Verify two GET calls to /users/me and one POST to /refreshtoken
        var meCalls = _mockHandler.RecordedRequests.Where(r => r.Path.EndsWith(IvaEndpoints.UserProfile)).ToList();
        Assert.Equal(2, meCalls.Count);
        var refreshCall = Assert.Single(_mockHandler.RecordedRequests.Where(r => r.Path.EndsWith(IvaEndpoints.RefreshToken)));
        Assert.Equal("POST", refreshCall.Method);
    }

    [Fact]
    public async Task SendAuthorizedAsync_Should_Throw_When_RefreshToken_Also_Fails()
    {
        // Arrange
        await _client.RequestOtpAsync("09121234567");
        await _client.VerifyCodeAsync("98765", "tok", "0");
        _mockHandler.Simulate401OnNextMeRequest = true;
        _mockHandler.SimulateRefreshTokenFailure = true;

        // Act & Assert
        await Assert.ThrowsAsync<IvaApiException>(() => _client.GetProfileAsync());
    }

    [Fact]
    public void IsAccessTokenExpired_Should_Accurately_Detect_Expiration()
    {
        // Not expired
        _client.Store.Set(StorageKeys.AccessTokenObtainedAt, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString());
        _client.Store.Set(StorageKeys.AccessTokenExpTime, "3600");
        Assert.False(_client.IsAccessTokenExpired(skewSeconds: 30));

        // Expired in past
        _client.Store.Set(StorageKeys.AccessTokenObtainedAt, (DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 4000).ToString());
        _client.Store.Set(StorageKeys.AccessTokenExpTime, "3600");
        Assert.True(_client.IsAccessTokenExpired(skewSeconds: 30));
    }
}
