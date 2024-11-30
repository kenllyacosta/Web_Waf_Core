using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Moq;

namespace Web.WafCore.Tests
{
    public class WafLibraryCoreTests
    {
        private readonly Mock<RequestDelegate> _nextMock;
        private readonly Mock<IMemoryCache> _cacheMock;
        private readonly Mock<ILogger<WafLibraryCore>> _loggerMock;
        private readonly WafConfiguration _options;
        private readonly WafLibraryCore _wafLibraryCore;

        public WafLibraryCoreTests()
        {
            _nextMock = new Mock<RequestDelegate>();
            _cacheMock = new Mock<IMemoryCache>();
            _loggerMock = new Mock<ILogger<WafLibraryCore>>();
            _options = new WafConfiguration
            {
                LogRequests = true,
                RateLimitRequests = true,
                BlockSQLInjection = true,
                BlockPathTraversal = true,
                BlockXSS = true,
                BlockCSRF = true,
                BlockCommandInjection = true,
                BlockLFI = true,
                BlockRFI = true,
                BlockRCE = true,
                BlockSSRF = true,
                BlockXXE = true,
                BlockLDAPInjection = true,
                BlockFileUploads = true,
                BlockBadUserAgents = true,
                BlockDoSAttacks = true,
                RateLimit = 150,
                MinutesToValidate = 1,
                WhitelistedIPs = ["127.0.0.1"],
                RequestLogLevel = LogLevel.Information,
                BlockedRequestLogLevel = LogLevel.Warning,
                SupportEmail = "info@dominio.com"
            };

            _wafLibraryCore = new WafLibraryCore(_nextMock.Object, _cacheMock.Object, _loggerMock.Object, _options);
        }

        [Fact]
        public async Task InvokeAsync_WhitelistedIP_ShouldCallNext()
        {
            // Arrange
            var context = new DefaultHttpContext();
            context.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("127.0.0.1");

            // Act
            await _wafLibraryCore.InvokeAsync(context);

            // Assert
            _nextMock.Verify(next => next(context), Times.Once);
        }
    }
}
