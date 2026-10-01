using System.Net;
using Iva.Auth.Tests.MockApi;
using Xunit;

namespace Iva.Auth.Tests;

public class ErrorHandlingTests : IDisposable
{
    private readonly MockIvaApiHandler _mockHandler;
    private readonly HttpClient _httpClient;
    private readonly IvaAuthClient _client;

    public ErrorHandlingTests()
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

    [Theory]
    [InlineData(HttpStatusCode.BadRequest, "400")]
    [InlineData(HttpStatusCode.Forbidden, "403")]
    [InlineData(HttpStatusCode.NotFound, "404")]
    [InlineData(HttpStatusCode.InternalServerError, "500")]
    [InlineData(HttpStatusCode.BadGateway, "502")]
    [InlineData(HttpStatusCode.ServiceUnavailable, "503")]
    public async Task HttpErrors_Should_Throw_IvaApiException_With_Correct_Code(HttpStatusCode status, string expectedCode)
    {
        _mockHandler.ForceStatusForPath = status;
        _mockHandler.ForceStatusPathPrefix = IvaEndpoints.RegisterRequest;

        var ex = await Assert.ThrowsAsync<IvaApiException>(() => _client.RequestOtpAsync("09120000000"));
        Assert.Equal(expectedCode, ex.Code);
    }

    [Fact]
    public async Task Malformed_Json_Response_Should_Throw_IvaApiException()
    {
        _mockHandler.ReturnMalformedJson = true;

        await Assert.ThrowsAsync<IvaApiException>(() => _client.RequestOtpAsync("09120000000"));
    }

    [Fact]
    public async Task Empty_Response_Body_Should_Throw_IvaApiException()
    {
        _mockHandler.ReturnEmptyBody = true;

        await Assert.ThrowsAsync<IvaApiException>(() => _client.RequestOtpAsync("09120000000"));
    }

    [Fact]
    public async Task Cancelled_Token_Should_Throw_OperationCanceledException()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => _client.RequestOtpAsync("09120000000", cts.Token));
    }
}
