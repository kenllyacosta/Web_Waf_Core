using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Web.WafCore;

namespace Web.WafCore
{
    public class WafLibraryCore
    {
        private readonly RequestDelegate _next;
        private readonly IMemoryCache _cache;
        private static readonly object _lock = new object();
        private readonly ILogger<WafLibraryCore> _logger;
        private readonly WafConfiguration _options;

        public WafLibraryCore(RequestDelegate next, IMemoryCache memoryCache, ILogger<WafLibraryCore> logger, WafConfiguration options)
        {
            _next = next;
            _cache = memoryCache;
            _logger = logger;
            _options = options;

            ValidateConfiguration(_options);
        }

        public async Task InvokeAsync(HttpContext context)
        {
            if (_options.LogRequests)
                _logger.Log(_options.RequestLogLevel, "Received request: {RequestPath}", context.Request.Path);

            var clientIp = context.Connection.RemoteIpAddress?.ToString();

            if (_options.WhitelistedIPs.Contains(clientIp))
            {
                await _next(context);
                return;
            }

            // Detects too many requests
            if (_options.RateLimitRequests && TooManyRequestsFrom(clientIp))
            {
                _logger.Log(_options.BlockedRequestLogLevel, "Too many requests from IP: {ClientIp}", clientIp);
                context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                context.Response.ContentType = "text/html";
                await context.Response.WriteAsync(HTMLMessage(_options.TooManyRequestsMessage, _options.TooManyRequestsDescription));
                return;
            }

            // Detects SQL Injection
            if (_options.BlockSQLInjection && (context.Request.QueryString.Value.ToLower().Contains("1=1") || context.Request.QueryString.Value.ToLower().Contains("union select") || context.Request.QueryString.Value.Contains("--") || context.Request.QueryString.Value.ToLower().Contains("drop")))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                context.Response.ContentType = "text/html";
                await context.Response.WriteAsync(HTMLMessage(_options.SQLInjectionMessage, _options.SQLInjectionDescription));
                return;
            }

            // Detects path traversal
            if (_options.BlockPathTraversal && (context.Request.Path.Value.Contains("../") || context.Request.Path.Value.Contains("..\\") ||
                context.Request.QueryString.Value.Contains("../") || context.Request.QueryString.Value.Contains("..\\")))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                context.Response.ContentType = "text/html";
                await context.Response.WriteAsync(HTMLMessage(_options.PathTraversalMessage, _options.PathTraversalDescription));
                return;
            }

            // Detects XSS
            if (_options.BlockXSS && (context.Request.QueryString.Value.ToLower().Contains("script") || context.Request.QueryString.Value.ToLower().Contains("alert(")))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                context.Response.ContentType = "text/html";
                await context.Response.WriteAsync(HTMLMessage(_options.XSSMessage, _options.XSSDescription));
                return;
            }

            // Detects CSRF
            if (_options.BlockCSRF && (!context.Request.Headers["Referer"].ToString().Contains(context.Request.Host.ToString())))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                context.Response.ContentType = "text/html";
                await context.Response.WriteAsync(HTMLMessage(_options.CSRFMessage, _options.CSRFDescription));
                return;
            }

            // Detect Command Injection
            if (_options.BlockCommandInjection && (context.Request.Path.Value.Contains(";") || context.Request.QueryString.Value.Contains(";") || context.Request.QueryString.Value.Contains("&") || context.Request.QueryString.Value.Contains("|") || context.Request.QueryString.Value.Contains("$") || context.Request.QueryString.Value.Contains("`")))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                context.Response.ContentType = "text/html";
                await context.Response.WriteAsync(HTMLMessage(_options.CommandInjectionMessage, _options.CommandInjectionDescription));
                return;
            }

            // Detects LFI
            if (_options.BlockLFI && (context.Request.QueryString.Value.ToLower().Contains("/etc/passwd") || context.Request.QueryString.Value.ToLower().Contains("/etc/shadow") || context.Request.QueryString.Value.ToLower().Contains("/proc/self/environ")))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                context.Response.ContentType = "text/html";
                await context.Response.WriteAsync(HTMLMessage(_options.LFIMessage, _options.LFIDescription));
                return;
            }

            // Detect Remote File Inclusion
            if (_options.BlockRFI && (context.Request.QueryString.Value.ToLower().Contains("http") || context.Request.QueryString.Value.ToLower().Contains("https") || context.Request.QueryString.Value.ToLower().Contains("ftp")))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                context.Response.ContentType = "text/html";
                await context.Response.WriteAsync(HTMLMessage(_options.RFIMessage, _options.RFIDescription));
                return;
            }

            // Detects RCE
            if (_options.BlockRCE && (context.Request.QueryString.Value.ToLower().Contains("system") || context.Request.QueryString.Value.ToLower().Contains("exec") || context.Request.QueryString.Value.ToLower().Contains("shell_exec") || context.Request.QueryString.Value.ToLower().Contains("passthru")))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                context.Response.ContentType = "text/html";
                await context.Response.WriteAsync(HTMLMessage(_options.RCEMessage, _options.RCEMessage));
                return;
            }

            // Detects SSRF
            if (_options.BlockSSRF && context.Request.QueryString.Value.ToLower().Contains("localhost"))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                context.Response.ContentType = "text/html";
                await context.Response.WriteAsync(HTMLMessage(_options.SSRFMessage, _options.SSRFDescription));
                return;
            }

            // Detects XXE XML External Entity Injection
            if (_options.BlockXXE && (context.Request.QueryString.Value.ToUpper().Contains("!ENTITY") || context.Request.QueryString.Value.ToUpper().Contains("SYSTEM")))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                context.Response.ContentType = "text/html";
                await context.Response.WriteAsync(HTMLMessage(_options.XXEMessage, _options.XXEDescription));
                return;
            }

            // Detects LDAP injection
            if (_options.BlockLDAPInjection && (context.Request.QueryString.Value.Contains("*") || context.Request.QueryString.Value.Contains("(") || context.Request.QueryString.Value.Contains(")")))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                context.Response.ContentType = "text/html";
                await context.Response.WriteAsync(HTMLMessage(_options.LDAPInjectionMessage, _options.LDAPInjectionDescription));
                return;
            }

            // Detects DDOS 
            if (_options.BlockDoSAttacks && context.Request.QueryString.Value.Length > 2000)
            {
                context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
                context.Response.ContentType = "text/html";
                await context.Response.WriteAsync(HTMLMessage(_options.DoSAttackMessage, _options.DoSAttackDescription));
                return;
            }

            // Detect malicious user-agents
            if (_options.BlockBadUserAgents)
            {
                var userAgent = context.Request.Headers["User-Agent"].ToString().ToLower();
                if (userAgent.Contains("sqlmap") || userAgent.Contains("nmap") || userAgent.Contains("crawler"))
                {
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    context.Response.ContentType = "text/html";
                    await context.Response.WriteAsync(HTMLMessage(_options.BadUserAgentMessage, _options.BadUserAgentDescription));
                    return;
                }
            }

            if (_options.BlockFileUploads && context.Request.Method == "POST")
            {
                var contentType = context.Request.ContentType;
                if (contentType.Contains("multipart/form-data"))
                {
                    var form = await context.Request.ReadFormAsync();
                    foreach (var file in form.Files)
                    {
                        if (file.Length > 1000000)
                        {
                            context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
                            context.Response.ContentType = "text/html";
                            await context.Response.WriteAsync(HTMLMessage(_options.FileUploadMessage, _options.FileUploadDescription));
                            return;
                        }
                        if (file.FileName.EndsWith(".exe") || file.FileName.EndsWith(".dll") || file.FileName.EndsWith(".bat") || file.FileName.EndsWith(".js"))
                        {
                            context.Response.StatusCode = StatusCodes.Status403Forbidden;
                            context.Response.ContentType = "text/html";
                            await context.Response.WriteAsync(HTMLMessage(_options.FileUploadMessage, _options.FileUploadDescription));
                            return;
                        }
                    }
                }
            }

            await _next(context);
        }

        private bool TooManyRequestsFrom(string clientIp)
        {
            if (string.IsNullOrEmpty(clientIp))
                throw new ArgumentNullException(nameof(clientIp));

            lock (_lock)
            {
                // Retrieve or initialize the request timestamps for this IP
                var requestTimestamps = _cache.TryGetValue(key: clientIp, out List<DateTime> timestamps)
                    ? timestamps : new List<DateTime>();

                // Check if the current request exceeds the limit
                if (requestTimestamps.Count >= _options.RateLimit)
                    return true;

                // Record the current request
                requestTimestamps.Add(DateTime.UtcNow);

                // Update the cache entry explicitly to ensure consistency
                _cache.Set(clientIp, requestTimestamps, TimeSpan.FromMinutes(_options.MinutesToValidate));

                return false;
            }
        }

        private static void ValidateConfiguration(WafConfiguration options)
        {
            if (options.RateLimit <= 0)
                throw new ArgumentException("RateLimit must be greater than zero.");

            if (options.MinutesToValidate <= 0)
                throw new ArgumentException("MinutesToValidate must be greater than zero.");
        }

        private string HTMLMessage(string message, string description)
        {
            return $@"
                <!DOCTYPE html>
                <html lang='en'>
                <head>
                    <meta charset='UTF-8'>
                    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
                    <title>{message}</title>
                    <style>
                        body {{
                            font-family: Arial, sans-serif;
                            background-color: #f8f9fa;
                            color: #333;
                            text-align: center;
                            padding: 2rem;
                        }}
                        .container {{
                            max-width: 600px;
                            margin: auto;
                            background: #ffffff;
                            padding: 2rem;
                            border-radius: 8px;
                            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                        }}
                        h1 {{
                            font-size: 2.5rem;
                            color: #dc3545;
                        }}
                        p {{
                            font-size: 1.2rem;
                            margin-top: 1rem;
                            color: #555;
                        }}
                        a {{
                            color: #007bff;
                            text-decoration: none;
                            font-weight: bold;
                        }}
                        a:hover {{
                            text-decoration: underline;
                        }}
                    </style>
                </head>
                <body>
                    <div class='container'>
                        <h1>{message}</h1>
                        <p>{description}</p>
                        <p>If you believe this is an error, please contact <a href='mailto:{_options.SupportEmail}'>{_options.SupportEmail}</a>.</p>
                    </div>
                </body>
                </html>";
        }
    }

    public class WafConfiguration
    {
        public bool LogRequests { get; set; } = true;
        public bool RateLimitRequests { get; set; } = true;
        public bool BlockSQLInjection { get; set; } = true;
        public bool BlockPathTraversal { get; set; } = true;
        public bool BlockXSS { get; set; } = true;
        public bool BlockCSRF { get; set; } = true;
        public bool BlockCommandInjection { get; set; } = true;
        public bool BlockLFI { get; set; } = true;
        public bool BlockRFI { get; set; } = true;
        public bool BlockRCE { get; set; } = true;
        public bool BlockSSRF { get; set; } = true;
        public bool BlockXXE { get; set; } = true;
        public bool BlockLDAPInjection { get; set; } = true;
        public bool BlockFileUploads { get; set; } = true;
        public bool BlockBadUserAgents { get; set; } = true;
        public bool BlockDoSAttacks { get; set; } = true;
        public int RateLimit { get; set; } = 150;
        public int MinutesToValidate { get; set; } = 1;

        public List<string> WhitelistedIPs { get; set; } = new List<string>();
        public LogLevel RequestLogLevel { get; set; } = LogLevel.Information;
        public LogLevel BlockedRequestLogLevel { get; set; } = LogLevel.Warning;

        // Custom properties Messages
        public string TooManyRequestsMessage { get; set; } = "Too Many Requests";
        public string TooManyRequestsDescription { get; set; } = "You have exceeded the maximum allowed requests. Please wait a moment and try again.";

        public string SQLInjectionMessage { get; set; } = "SQL Injection attempt detected.";
        public string SQLInjectionDescription { get; set; } = "Your request was blocked due to a potential SQL Injection attack.";

        public string PathTraversalMessage { get; set; } = "Path Traversal attempt detected.";
        public string PathTraversalDescription { get; set; } = "Your request was blocked due to a potential Path Traversal attack.";

        public string XSSMessage { get; set; } = "XSS attempt detected.";
        public string XSSDescription { get; set; } = "Your request was blocked due to a potential Cross-Site Scripting (XSS) attack.";

        public string CSRFMessage { get; set; } = "CSRF attempt detected.";
        public string CSRFDescription { get; set; } = "Your request was blocked due to a potential Cross-Site Request Forgery (CSRF) attack.";

        public string CommandInjectionMessage { get; set; } = "Command Injection attempt detected.";
        public string CommandInjectionDescription { get; set; } = "Your request was blocked due to a potential Command Injection attack.";

        public string LFIMessage { get; set; } = "LFI attempt detected.";
        public string LFIDescription { get; set; } = "Your request was blocked due to a potential Local File Inclusion (LFI) attack.";

        public string RFIMessage { get; set; } = "RFI attempt detected.";
        public string RFIDescription { get; set; } = "Your request was blocked due to a potential Remote File Inclusion (RFI) attack.";

        public string RCEMessage { get; set; } = "RCE attempt detected.";
        public string RCEDescription { get; set; } = "Your request was blocked due to a potential Remote Code Execution (RCE) attack.";

        public string SSRFMessage { get; set; } = "SSRF attempt detected.";
        public string SSRFDescription { get; set; } = "Your request was blocked due to a potential Server-Side Request Forgery (SSRF) attack.";

        public string XXEMessage { get; set; } = "XXE attempt detected.";
        public string XXEDescription { get; set; } = "Your request was blocked due to a potential XML External Entity (XXE) attack.";

        public string LDAPInjectionMessage { get; set; } = "LDAP Injection attempt detected.";
        public string LDAPInjectionDescription { get; set; } = "Your request was blocked due to a potential LDAP Injection attack.";

        public string FileUploadMessage { get; set; } = "File upload attempt detected.";
        public string FileUploadDescription { get; set; } = "Your request was blocked due to a potential malicious file upload.";

        public string BadUserAgentMessage { get; set; } = "Malicious User-Agent detected.";
        public string BadUserAgentDescription { get; set; } = "Your request was blocked due to a detected malicious User-Agent.";

        public string DoSAttackMessage { get; set; } = "DoS attack detected.";
        public string DoSAttackDescription { get; set; } = "Your request was blocked due to a potential Denial of Service (DoS) attack.";


        public string SupportEmail { get; set; } = "info@dominio.com";
    }
}

namespace Microsoft.AspNetCore.Builder
{
    public static class WafMiddlewareExtensions
    {
        /// <summary>
        /// Custom values
        /// </summary>
        /// <param name="builder"></param>
        /// <param name="configureOptions"></param>
        /// <returns></returns>
        public static IApplicationBuilder UseWaf(this IApplicationBuilder builder, Action<WafConfiguration> configureOptions)
        {
            var options = new WafConfiguration();
            configureOptions(options);
            return builder.UseMiddleware<WafLibrary>(options);
        }

        /// <summary>
        /// Default values
        /// </summary>
        /// <param name="builder"></param>
        /// <returns></returns>
        public static IApplicationBuilder UseWaf(this IApplicationBuilder builder)
        {
            var options = new WafConfiguration();
            return builder.UseMiddleware<WafLibrary>(options);
        }
    }
}