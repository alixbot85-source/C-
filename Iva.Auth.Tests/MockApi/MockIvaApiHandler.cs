using System.Net;
using System.Text;
using System.Text.Json;
using Iva.Auth.Tests.Fixtures;

namespace Iva.Auth.Tests.MockApi;

public sealed record MockRecordedRequest(
    string Method,
    string Path,
    Dictionary<string, IEnumerable<string>> Headers,
    string Body);

/// <summary>
/// In-memory Mock HTTP message handler that simulates the 8 active IVA endpoints.
/// MOCK RESPONSE DERIVED FROM CURRENT CLIENT CONTRACT.
/// Mock tests do not prove compatibility with the live IVA/Sadad API.
/// </summary>
public sealed class MockIvaApiHandler : HttpMessageHandler
{
    private readonly object _lock = new();

    public List<MockRecordedRequest> RecordedRequests { get; } = new();

    public string MockAccessToken { get; set; } = "mock_access_token_12345";
    public string MockRefreshToken { get; set; } = "mock_refresh_token_67890";
    public string MockRefreshedAccessToken { get; set; } = "mock_refreshed_access_token_99999";
    public string MockRefreshedRefreshToken { get; set; } = "mock_refreshed_refresh_token_88888";

    // Fault injection flags
    public bool Simulate401OnNextMeRequest { get; set; }
    public bool Simulate401OnNextChargeRequest { get; set; }
    public bool SimulateRefreshTokenFailure { get; set; }
    public HttpStatusCode? ForceStatusForPath { get; set; }
    public string? ForceStatusPathPrefix { get; set; }
    public bool ReturnMalformedJson { get; set; }
    public bool ReturnEmptyBody { get; set; }

    public string? LastReceivedDataKeyHex { get; private set; }
    public string? LastReceivedMacKeyHex { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var path = request.RequestUri?.AbsolutePath ?? string.Empty;
        var method = request.Method.Method;
        var body = request.Content != null
            ? await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false)
            : string.Empty;

        var headersDict = request.Headers.ToDictionary(h => h.Key, h => h.Value);
        if (request.Content != null)
        {
            foreach (var h in request.Content.Headers)
                headersDict[h.Key] = h.Value;
        }

        lock (_lock)
        {
            RecordedRequests.Add(new MockRecordedRequest(method, path, headersDict, body));
        }

        // Global fault injection
        if (ForceStatusForPath.HasValue && ForceStatusPathPrefix != null && path.Contains(ForceStatusPathPrefix))
        {
            return CreateJsonResponse(ForceStatusForPath.Value, new
            {
                error = new { code = ((int)ForceStatusForPath.Value).ToString(), message = "Injected Mock Error" }
            });
        }

        if (ReturnMalformedJson)
            return CreateRawResponse(HttpStatusCode.OK, "INVALID_JSON_{{NOT_JSON}}");

        if (ReturnEmptyBody)
            return CreateRawResponse(HttpStatusCode.OK, "");

        // 1. POST /pwa/api/v1/users/auth/verifyCode
        if (path.EndsWith(IvaEndpoints.RegisterRequest, StringComparison.OrdinalIgnoreCase) && method == "POST")
        {
            var response = new
            {
                error = new { code = "200", message = "کد تأیید ارسال شد" },
                data = new
                {
                    Token = "mock_otp_flow_token_abc123",
                    ReagentNumber = "0"
                }
            };
            return CreateJsonResponse(HttpStatusCode.OK, response);
        }

        // 2. POST /pwa/api/v1/users/auth/token
        if (path.EndsWith(IvaEndpoints.Activation, StringComparison.OrdinalIgnoreCase) && method == "POST")
        {
            var response = new
            {
                error = new { code = "200", message = "ورود موفقیت‌آمیز" },
                data = new
                {
                    accessToken = MockAccessToken,
                    refreshToken = MockRefreshToken,
                    expiresIn = 3600L,
                    tokenType = "Bearer",
                    key = TestKeyFixture.ModulusBase64
                }
            };
            return CreateJsonResponse(HttpStatusCode.OK, response);
        }

        // 3. POST /pwa/api/v1/users/auth/refreshtoken
        if (path.EndsWith(IvaEndpoints.RefreshToken, StringComparison.OrdinalIgnoreCase) && method == "POST")
        {
            if (SimulateRefreshTokenFailure)
            {
                return CreateJsonResponse(HttpStatusCode.Unauthorized, new
                {
                    error = new { code = "401", message = "Refresh token expired or invalid." }
                });
            }

            var response = new
            {
                error = new { code = "200", message = "توکن تمدید شد" },
                data = new
                {
                    accessToken = MockRefreshedAccessToken,
                    refreshToken = MockRefreshedRefreshToken,
                    expiresIn = 3600L,
                    tokenType = "Bearer",
                    key = TestKeyFixture.ModulusBase64
                }
            };
            return CreateJsonResponse(HttpStatusCode.OK, response);
        }

        // 4. POST /pwa/api/v1/users/auth/keyExchange
        if (path.EndsWith(IvaEndpoints.KeyExchange, StringComparison.OrdinalIgnoreCase) && method == "POST")
        {
            try
            {
                using var doc = JsonDocument.Parse(body);
                if (doc.RootElement.TryGetProperty("DataKey", out var dk))
                    LastReceivedDataKeyHex = TestKeyFixture.DecryptRsaHex(dk.GetString()!);
                if (doc.RootElement.TryGetProperty("MacKey", out var mk))
                    LastReceivedMacKeyHex = TestKeyFixture.DecryptRsaHex(mk.GetString()!);
            }
            catch { }

            return CreateJsonResponse(HttpStatusCode.OK, new
            {
                error = new { code = "200", message = "کلیدها دریافت شد" },
                data = (object?)null
            });
        }

        // 5. GET /pwa/api/v1/users/me
        if (path.EndsWith(IvaEndpoints.UserProfile, StringComparison.OrdinalIgnoreCase) && method == "GET")
        {
            if (Simulate401OnNextMeRequest)
            {
                Simulate401OnNextMeRequest = false;
                return CreateJsonResponse(HttpStatusCode.Unauthorized, new
                {
                    error = new { code = "401", message = "Unauthorized access token." }
                });
            }

            return CreateJsonResponse(HttpStatusCode.OK, new
            {
                error = new { code = "200", message = "موفق" },
                data = new
                {
                    userId = "mock_user_1001",
                    phoneNumber = "09120000000",
                    displayName = "کاربر تستی"
                }
            });
        }

        // 6. GET /pwa/api/v1/baseInfo/configs/list
        if (path.EndsWith(IvaEndpoints.AppConfiguration, StringComparison.OrdinalIgnoreCase) && method == "GET")
        {
            return CreateJsonResponse(HttpStatusCode.OK, new
            {
                error = new { code = "200", message = "موفق" },
                data = new object[]
                {
                    new { key = "appVersion", value = "3.10.24" },
                    new { key = "rsaPublicKey", value = TestKeyFixture.PublicKeyPem }
                }
            });
        }

        // 7. GET /pwa/api/v3/charges/pin/mobile/catalog
        if (path.EndsWith(IvaEndpoints.ChargeCatalog, StringComparison.OrdinalIgnoreCase) && method == "GET")
        {
            return CreateJsonResponse(HttpStatusCode.OK, new
            {
                error = new { code = "200", message = "موفق" },
                data = new object[]
                {
                    new { id = "1", code = "MCI", name = "همراه اول", amounts = new long[] { 10000, 20000, 50000 } },
                    new { id = "2", code = "MTN", name = "ایرانسل", amounts = new long[] { 10000, 20000, 50000 } }
                }
            });
        }

        // 8. POST /pwa/api/v1/charges/pin/payment
        if (path.EndsWith(IvaEndpoints.PayCharge, StringComparison.OrdinalIgnoreCase) && method == "POST")
        {
            if (Simulate401OnNextChargeRequest)
            {
                Simulate401OnNextChargeRequest = false;
                return CreateJsonResponse(HttpStatusCode.Unauthorized, new
                {
                    error = new { code = "401", message = "Token expired during payment." }
                });
            }

            return CreateJsonResponse(HttpStatusCode.OK, new
            {
                error = new { code = "200", message = "تراکنش موفق" },
                data = new
                {
                    pin = "1234567890123456",
                    serial = "987654321098",
                    trackingCode = "TRK_MOCK_12345",
                    transactionId = "TXN_MOCK_67890",
                    referenceNumber = "REF_MOCK_112233",
                    status = "SUCCESS",
                    cardHolderName = "دارنده کارت آزمایشی"
                }
            });
        }

        // Default 404 for unmocked routes
        return CreateJsonResponse(HttpStatusCode.NotFound, new
        {
            error = new { code = "404", message = $"Endpoint {path} not found in mock." }
        });
    }

    private static HttpResponseMessage CreateJsonResponse(HttpStatusCode status, object payload)
    {
        var json = JsonSerializer.Serialize(payload);
        return new HttpResponseMessage(status)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
    }

    private static HttpResponseMessage CreateRawResponse(HttpStatusCode status, string rawBody)
    {
        return new HttpResponseMessage(status)
        {
            Content = new StringContent(rawBody, Encoding.UTF8, "application/json")
        };
    }
}
