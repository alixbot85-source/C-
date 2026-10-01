using Iva.Auth.Sessions;
using Xunit;

namespace Iva.Auth.Tests;

public class SessionTests : IDisposable
{
    private readonly string _tempDir;
    private readonly FileSessionRepository _repo;

    public SessionTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "iva_session_tests_" + Guid.NewGuid().ToString("N"));
        _repo = new FileSessionRepository(_tempDir);
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_tempDir)) Directory.Delete(_tempDir, true); } catch { }
    }

    [Fact]
    public void Save_And_Load_Should_Preserve_All_Fields()
    {
        // Arrange
        var session = new SessionData
        {
            Phone = "09121234567",
            Token = "access_token_123",
            RefreshToken = "refresh_token_456",
            ExpiresIn = 3600,
            TokenType = "Bearer",
            AccessTokenObtainedAt = 1700000000,
            SharedKey = "shared_key_base64",
            WorkingKey = "working_key_base64",
            RsaPublic = "rsa_public_pem_data"
        };

        // Act
        _repo.Save(session);
        var loaded = _repo.Load("09121234567");

        // Assert
        Assert.NotNull(loaded);
        Assert.Equal("09121234567", loaded.Phone);
        Assert.Equal("access_token_123", loaded.Token);
        Assert.Equal("refresh_token_456", loaded.RefreshToken);
        Assert.Equal(3600, loaded.ExpiresIn);
        Assert.Equal("Bearer", loaded.TokenType);
        Assert.Equal(1700000000, loaded.AccessTokenObtainedAt);
        Assert.Equal("shared_key_base64", loaded.SharedKey);
        Assert.Equal("working_key_base64", loaded.WorkingKey);
        Assert.Equal("rsa_public_pem_data", loaded.RsaPublic);
    }

    [Fact]
    public void Delete_Should_Remove_File_And_Return_True()
    {
        // Arrange
        var session = new SessionData { Phone = "09129998877", Token = "tok" };
        _repo.Save(session);
        Assert.True(_repo.Exists("09129998877"));

        // Act
        var deleted = _repo.Delete("09129998877");

        // Assert
        Assert.True(deleted);
        Assert.False(_repo.Exists("09129998877"));
        Assert.Null(_repo.Load("09129998877"));
    }

    [Fact]
    public void Load_NonExistent_Should_Return_Null()
    {
        Assert.Null(_repo.Load("09990000000"));
        Assert.False(_repo.Exists("09990000000"));
    }

    [Fact]
    public void Load_Corrupted_Json_Should_Return_Null_Safely()
    {
        // Arrange
        var corruptFile = Path.Combine(_tempDir, "09120000000.json");
        File.WriteAllText(corruptFile, "{ NOT VALID JSON ");

        // Act
        var loaded = _repo.Load("09120000000");

        // Assert
        Assert.Null(loaded);
    }

    [Fact]
    public void Path_Traversal_Attempts_Should_Be_Sanitized()
    {
        // Arrange: Try path traversal attack
        var maliciousPhone = "../../etc/passwd";
        var session = new SessionData { Phone = maliciousPhone, Token = "tok_traversal" };

        // Act
        _repo.Save(session);

        // Assert: Sanitized file should be within _tempDir as etcpasswd.json
        var expectedFile = Path.Combine(_tempDir, "etcpasswd.json");
        Assert.True(File.Exists(expectedFile));
        Assert.False(File.Exists(Path.Combine(_tempDir, "../../etc/passwd")));
    }

    [Fact]
    public void Empty_Or_Whitespace_Phone_Should_Be_Safely_Ignored()
    {
        Assert.Null(_repo.Load(""));
        Assert.Null(_repo.Load("   "));
        Assert.False(_repo.Exists(""));
        Assert.False(_repo.Delete(""));
    }

    [Fact]
    public void Concurrent_Access_From_Multiple_Threads_Should_Be_ThreadSafe()
    {
        // Arrange
        const int threadCount = 8;
        const int operationsPerThread = 25;
        var exceptions = new List<Exception>();

        var threads = Enumerable.Range(0, threadCount).Select(threadId => new Thread(() =>
        {
            try
            {
                var phone = $"091233344{threadId:02d}";
                for (int i = 0; i < operationsPerThread; i++)
                {
                    _repo.Save(new SessionData { Phone = phone, Token = $"tok_{threadId}_{i}" });
                    var loaded = _repo.Load(phone);
                    Assert.NotNull(loaded);
                    _repo.ListPhones();
                }
                _repo.Delete(phone);
            }
            catch (Exception ex)
            {
                lock (exceptions) exceptions.Add(ex);
            }
        })).ToList();

        // Act
        threads.ForEach(t => t.Start());
        threads.ForEach(t => t.Join());

        // Assert
        Assert.Empty(exceptions);
    }
}
