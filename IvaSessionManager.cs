using System.Security.Cryptography;
using Iva.Auth.Payments;
using Iva.Auth.Sessions;

namespace Iva.Auth;

/// <summary>Reported when no usable account is found.</summary>
public sealed record NoSessionsEventArgs(bool WasEmptyFromStart, int DroppedCount, int RemainingCount);

/// <summary>
/// Multi-account manager (modeled after AsanPardakhtSessionManager). It does not keep
/// services in memory — the pool IS the session store (one file per number). Each call
/// mints a fresh <see cref="IvaAuthClient"/> bound to one account. Selection is random;
/// dead sessions are pruned. ChargeWallet distributes load across the accounts and, when
/// an account reports its own daily limit, sets it aside and moves to the next — so no
/// single account is pushed past its server-side cap.
/// </summary>
public sealed class IvaSessionManager
{
    private readonly IvaOptions _opts;
    private readonly ISessionRepository _store;

    public IvaSessionManager(IvaOptions? options = null, ISessionRepository? store = null)
    {
        _opts = options ?? new IvaOptions();
        _store = store ?? new FileSessionRepository();
    }

    /// <summary>Invoked whenever any account's token is refreshed.</summary>
    public Action<TokenResult>? OnRefresh { get; set; }

    /// <summary>Invoked when a charge cannot find any usable account.</summary>
    public Action<NoSessionsEventArgs>? OnNoSessionsAvailable { get; set; }

    /// <summary>Optional hook to configure each freshly minted service (e.g. attach debug echo).</summary>
    public Action<IvaAuthClient>? ConfigureService { get; set; }

    public IReadOnlyList<string> ListMobiles() => _store.ListPhones();
    public int Count => _store.ListPhones().Count;
    public void RemoveSession(string phone) => _store.Delete(phone);

    private IvaAuthClient NewService()
    {
        var client = new IvaAuthClient(_opts, sessions: _store);
        client.TokenRefreshed += t => OnRefresh?.Invoke(t);
        ConfigureService?.Invoke(client);
        return client;
    }

    /// <summary>
    /// Pick a random working account: shuffle the saved numbers, resume the first that
    /// validates, deleting any that cannot be refreshed. Returns null (and fires
    /// OnNoSessionsAvailable) when nothing usable remains.
    /// </summary>
    public async Task<IvaAuthClient?> RandomLoginAsync(CancellationToken ct = default)
        => await NextWorkingServiceAsync(exclude: null, random: true, ct).ConfigureAwait(false);

    /// <summary>
    /// Comprehensive charge: pick an account, charge it (the service retries transient
    /// messages on the same account), and on a daily-limit message set that account
    /// aside and try the next one. Returns the first success, or the last failure /
    /// a "no accounts" result.
    /// </summary>
    public async Task<ChargePurchaseResult> ChargeWalletAsync(
        string providerCode, long amount, string targetMobileNo,
        string pan, string cvv2, string expireMonth, string expireYear, string pin,
        CancellationToken ct = default)
    {
        var excluded = new HashSet<string>(StringComparer.Ordinal); // daily-limited accounts
        var attempts = 0;
        var max = Math.Max(0, _opts.MaxChargeRetries);
        ChargePurchaseResult? last = null;

        while (true)
        {
            using var service = await NextWorkingServiceAsync(excluded, random: true, ct).ConfigureAwait(false);
            if (service is null)
                return last ?? new ChargePurchaseResult { Success = false, ErrorCode = "no-accounts", Message = "هیچ اکانت فعالی موجود نیست" };

            var phone = service.CurrentPhone ?? "";

            var r = await service.PurchaseChargeAsync(
                providerCode, amount, targetMobileNo, pan, cvv2, expireMonth, expireYear, pin, ct).ConfigureAwait(false);
            r.UsedPhone = phone;
            r.RetryCount = attempts;

            if (r.Success)
                return r;

            last = r;

            // Stop on any non-retryable error.
            if (!IvaAuthClient.Contains(_opts.RetryableStatusMessages, r.Message))
                return r;

            // Daily limit: set this account aside so it is never pushed past its cap.
            if (IvaAuthClient.Contains(_opts.DailyLimitMessages, r.Message))
                excluded.Add(phone);

            attempts++;
            if (attempts > max)
                return r;

            await Task.Delay(_opts.ChargeRetryDelay, ct).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Find the next working account not in <paramref name="exclude"/>. Random order when
    /// requested. Dead/unrefreshable sessions are deleted as they are encountered.
    /// </summary>
    private async Task<IvaAuthClient?> NextWorkingServiceAsync(
        ISet<string>? exclude, bool random, CancellationToken ct)
    {
        var candidates = _store.ListPhones()
            .Where(m => exclude is null || !exclude.Contains(m))
            .ToList();

        var wasEmptyFromStart = candidates.Count == 0;
        if (random) Shuffle(candidates);

        var dropped = 0;
        foreach (var phone in candidates)
        {
            ct.ThrowIfCancellationRequested();

            var service = NewService();
            bool ok;
            try { ok = await service.TryResumeSessionAsync(phone, ct).ConfigureAwait(false); }
            catch { ok = false; }

            if (ok) return service;

            service.Dispose();
            _store.Delete(phone); // unrefreshable -> drop it
            dropped++;
        }

        OnNoSessionsAvailable?.Invoke(new NoSessionsEventArgs(wasEmptyFromStart, dropped, _store.ListPhones().Count));
        return null;
    }

    private static void Shuffle<T>(IList<T> list)
    {
        for (var i = list.Count - 1; i > 0; i--)
        {
            var j = RandomNumberGenerator.GetInt32(i + 1);
            (list[i], list[j]) = (list[j], list[i]);
        }
    }
}
