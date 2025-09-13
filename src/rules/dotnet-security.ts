import { Rule } from "../components/SecureAIDirectory";

const dotnetSecurity: Rule = {
  id: "dotnet-security",
  title: "C#/.NET Security Guidelines",
  summary: "Comprehensive security practices for C# and .NET applications",
  body: `# C#/.NET Security Guidelines

## 1. Input Validation & Sanitization

### ASP.NET Core Model Validation
- Use Data Annotations for input validation
- Implement custom validators for complex validation logic
- Validate all user input at multiple layers
- Use model binding with proper validation

\`\`\`csharp
// Model with validation annotations
public class UserCreateModel
{
    [Required(ErrorMessage = "Username is required")]
    [StringLength(20, MinimumLength = 3, ErrorMessage = "Username must be between 3 and 20 characters")]
    [RegularExpression(@"^[a-zA-Z0-9_]+$", ErrorMessage = "Username can only contain alphanumeric characters and underscores")]
    public string Username { get; set; }

    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email format")]
    public string Email { get; set; }

    [Range(18, 120, ErrorMessage = "Age must be between 18 and 120")]
    public int Age { get; set; }

    [Required(ErrorMessage = "Password is required")]
    [MinLength(12, ErrorMessage = "Password must be at least 12 characters")]
    [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]", 
                      ErrorMessage = "Password must contain uppercase, lowercase, digit, and special character")]
    public string Password { get; set; }
}

// Controller with validation
[ApiController]
[Route("api/[controller]")]
public class UsersController : ControllerBase
{
    [HttpPost]
    public async Task<ActionResult<User>> CreateUser([FromBody] UserCreateModel model)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        // Additional server-side validation
        if (await _userService.UsernameExistsAsync(model.Username))
        {
            ModelState.AddModelError("Username", "Username already exists");
            return BadRequest(ModelState);
        }

        var user = await _userService.CreateUserAsync(model);
        return CreatedAtAction(nameof(GetUser), new { id = user.Id }, user);
    }
}
\`\`\`

### Input Sanitization
- Use AntiXSS library for HTML encoding
- Sanitize user input before processing
- Validate file uploads thoroughly
- Implement proper encoding for different contexts

\`\`\`csharp
// HTML sanitization service
public class InputSanitizationService
{
    public string SanitizeHtml(string input)
    {
        if (string.IsNullOrEmpty(input))
            return string.Empty;

        // Use HtmlEncoder for basic encoding
        return HtmlEncoder.Default.Encode(input);
    }

    public string SanitizeForJavaScript(string input)
    {
        if (string.IsNullOrEmpty(input))
            return string.Empty;

        return JavaScriptEncoder.Default.Encode(input);
    }

    public string SanitizeUrl(string url)
    {
        if (string.IsNullOrEmpty(url))
            return string.Empty;

        if (Uri.TryCreate(url, UriKind.Absolute, out Uri validatedUri))
        {
            if (validatedUri.Scheme == Uri.UriSchemeHttp || 
                validatedUri.Scheme == Uri.UriSchemeHttps)
            {
                return validatedUri.ToString();
            }
        }
        
        return string.Empty;
    }
}
\`\`\`

## 2. SQL Injection Prevention

### Entity Framework Core Security
- Use parameterized queries and LINQ
- Avoid raw SQL with string concatenation
- Use FromSqlRaw with parameters when raw SQL is necessary
- Implement proper error handling

\`\`\`csharp
// Safe Entity Framework queries
public class UserRepository
{
    private readonly ApplicationDbContext _context;

    public UserRepository(ApplicationDbContext context)
    {
        _context = context;
    }

    // Safe LINQ query
    public async Task<User> GetUserByUsernameAsync(string username)
    {
        return await _context.Users
            .FirstOrDefaultAsync(u => u.Username == username);
    }

    // Safe parameterized raw SQL
    public async Task<List<User>> GetActiveUsersAsync(DateTime since)
    {
        return await _context.Users
            .FromSqlRaw("SELECT * FROM Users WHERE IsActive = 1 AND LastLoginDate > {0}", since)
            .ToListAsync();
    }

    // Safe complex query with parameters
    public async Task<List<User>> SearchUsersAsync(string searchTerm, int minAge)
    {
        return await _context.Users
            .Where(u => u.Username.Contains(searchTerm) && u.Age >= minAge)
            .OrderBy(u => u.Username)
            .ToListAsync();
    }
}

// Avoid this - dangerous string concatenation
public async Task<List<User>> DangerousQuery(string username)
{
    // DON'T DO THIS - vulnerable to SQL injection
    var sql = $"SELECT * FROM Users WHERE Username = '{username}'";
    return await _context.Users.FromSqlRaw(sql).ToListAsync();
}
\`\`\`

### ADO.NET Security
- Use SqlParameter for all user inputs
- Validate parameters before use
- Use stored procedures when appropriate

\`\`\`csharp
// Safe ADO.NET usage
public class UserDataAccess
{
    private readonly string _connectionString;

    public UserDataAccess(string connectionString)
    {
        _connectionString = connectionString;
    }

    public async Task<User> GetUserByIdAsync(int userId)
    {
        using var connection = new SqlConnection(_connectionString);
        using var command = new SqlCommand("SELECT * FROM Users WHERE Id = @UserId", connection);
        
        command.Parameters.Add("@UserId", SqlDbType.Int).Value = userId;
        
        await connection.OpenAsync();
        using var reader = await command.ExecuteReaderAsync();
        
        if (await reader.ReadAsync())
        {
            return new User
            {
                Id = reader.GetInt32("Id"),
                Username = reader.GetString("Username"),
                Email = reader.GetString("Email")
            };
        }
        
        return null;
    }

    public async Task UpdateUserAsync(User user)
    {
        using var connection = new SqlConnection(_connectionString);
        using var command = new SqlCommand(
            "UPDATE Users SET Username = @Username, Email = @Email WHERE Id = @Id", 
            connection);
        
        command.Parameters.Add("@Username", SqlDbType.NVarChar, 50).Value = user.Username;
        command.Parameters.Add("@Email", SqlDbType.NVarChar, 100).Value = user.Email;
        command.Parameters.Add("@Id", SqlDbType.Int).Value = user.Id;
        
        await connection.OpenAsync();
        await command.ExecuteNonQueryAsync();
    }
}
\`\`\`

## 3. Authentication & Authorization

### ASP.NET Core Identity
- Use ASP.NET Core Identity for authentication
- Implement proper password policies
- Configure secure cookie settings
- Use two-factor authentication

\`\`\`csharp
// Identity configuration
public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddDbContext<ApplicationDbContext>(options =>
            options.UseSqlServer(connectionString));

        services.AddIdentity<ApplicationUser, IdentityRole>(options =>
        {
            // Password settings
            options.Password.RequireDigit = true;
            options.Password.RequireLowercase = true;
            options.Password.RequireNonAlphanumeric = true;
            options.Password.RequireUppercase = true;
            options.Password.RequiredLength = 12;
            options.Password.RequiredUniqueChars = 4;

            // Lockout settings
            options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(30);
            options.Lockout.MaxFailedAccessAttempts = 5;
            options.Lockout.AllowedForNewUsers = true;

            // User settings
            options.User.RequireUniqueEmail = true;
            options.SignIn.RequireConfirmedEmail = true;
        })
        .AddEntityFrameworkStores<ApplicationDbContext>()
        .AddDefaultTokenProviders();

        services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            options.Cookie.SameSite = SameSiteMode.Strict;
            options.ExpireTimeSpan = TimeSpan.FromHours(1);
            options.SlidingExpiration = true;
        });
    }
}
\`\`\`

### JWT Authentication
- Use secure JWT implementation
- Implement proper token validation
- Use short-lived access tokens
- Implement refresh token mechanism

\`\`\`csharp
// JWT service implementation
public class JwtService
{
    private readonly IConfiguration _configuration;
    private readonly UserManager<ApplicationUser> _userManager;

    public JwtService(IConfiguration configuration, UserManager<ApplicationUser> userManager)
    {
        _configuration = configuration;
        _userManager = userManager;
    }

    public async Task<string> GenerateTokenAsync(ApplicationUser user)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_configuration["Jwt:Key"]);
        var roles = await _userManager.GetRolesAsync(user);

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Iat, 
                     new DateTimeOffset(DateTime.UtcNow).ToUnixTimeSeconds().ToString(), 
                     ClaimValueTypes.Integer64)
        };

        claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(15), // Short-lived token
            Issuer = _configuration["Jwt:Issuer"],
            Audience = _configuration["Jwt:Audience"],
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), 
                                                       SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    public ClaimsPrincipal ValidateToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_configuration["Jwt:Key"]);

        try
        {
            var principal = tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = true,
                ValidIssuer = _configuration["Jwt:Issuer"],
                ValidateAudience = true,
                ValidAudience = _configuration["Jwt:Audience"],
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            }, out SecurityToken validatedToken);

            return principal;
        }
        catch
        {
            return null;
        }
    }
}
\`\`\`

### Authorization Policies
- Implement role-based and policy-based authorization
- Use attribute-based authorization
- Create custom authorization handlers

\`\`\`csharp
// Authorization policy configuration
public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddAuthorization(options =>
        {
            options.AddPolicy("AdminOnly", policy =>
                policy.RequireRole("Admin"));

            options.AddPolicy("MinimumAge", policy =>
                policy.Requirements.Add(new MinimumAgeRequirement(18)));

            options.AddPolicy("OwnerOrAdmin", policy =>
                policy.Requirements.Add(new OwnerOrAdminRequirement()));
        });

        services.AddScoped<IAuthorizationHandler, MinimumAgeHandler>();
        services.AddScoped<IAuthorizationHandler, OwnerOrAdminHandler>();
    }
}

// Custom authorization requirement and handler
public class OwnerOrAdminRequirement : IAuthorizationRequirement { }

public class OwnerOrAdminHandler : AuthorizationHandler<OwnerOrAdminRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        OwnerOrAdminRequirement requirement)
    {
        var user = context.User;

        if (user.IsInRole("Admin"))
        {
            context.Succeed(requirement);
            return Task.CompletedTask;
        }

        // Check if user owns the resource
        if (context.Resource is IOwnedResource resource && 
            user.FindFirst(ClaimTypes.NameIdentifier)?.Value == resource.OwnerId)
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}

// Controller with authorization
[ApiController]
[Route("api/[controller]")]
[Authorize]
public class DocumentsController : ControllerBase
{
    [HttpGet("{id}")]
    [Authorize(Policy = "OwnerOrAdmin")]
    public async Task<ActionResult<Document>> GetDocument(int id)
    {
        var document = await _documentService.GetByIdAsync(id);
        return Ok(document);
    }

    [HttpDelete("{id}")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> DeleteDocument(int id)
    {
        await _documentService.DeleteAsync(id);
        return NoContent();
    }
}
\`\`\`

## 4. Cross-Site Request Forgery (CSRF) Protection

### Anti-Forgery Tokens
- Use anti-forgery tokens for state-changing operations
- Configure anti-forgery token validation
- Implement proper token handling for AJAX requests

\`\`\`csharp
// Anti-forgery configuration
public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddAntiforgery(options =>
        {
            options.HeaderName = "X-CSRF-TOKEN";
            options.Cookie.Name = "__RequestVerificationToken";
            options.Cookie.HttpOnly = true;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            options.Cookie.SameSite = SameSiteMode.Strict;
        });
    }
}

// Controller with anti-forgery protection
[HttpPost]
[ValidateAntiForgeryToken]
public async Task<IActionResult> UpdateProfile(UserProfileModel model)
{
    if (ModelState.IsValid)
    {
        await _userService.UpdateProfileAsync(User.GetUserId(), model);
        return RedirectToAction("Profile");
    }
    return View(model);
}

// API controller with anti-forgery
[HttpPost]
[ValidateAntiForgeryToken]
public async Task<IActionResult> ApiUpdate([FromBody] UpdateModel model)
{
    // Token automatically validated
    await _service.UpdateAsync(model);
    return Ok();
}
\`\`\`

## 5. Cross-Site Scripting (XSS) Prevention

### Output Encoding
- Use Razor's automatic HTML encoding
- Implement proper encoding for different contexts
- Use Content Security Policy headers

\`\`\`html
@* Razor view with automatic encoding *@
<div>@Model.UserInput</div> @* Automatically HTML encoded *@

@* Unencoded output (use with caution) *@
<div>@Html.Raw(Model.SanitizedHtml)</div>

@* JavaScript context encoding *@
<script>
    var userData = @Html.JavaScriptStringEncode(Model.UserData);
</script>

@* URL context encoding *@
<a href="@Url.Encode(Model.UserUrl)">Link</a>
\`\`\`

\`\`\`csharp
// Content Security Policy middleware
public class SecurityHeadersMiddleware
{
    private readonly RequestDelegate _next;

    public SecurityHeadersMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        context.Response.Headers.Add("Content-Security-Policy",
            "default-src 'self'; " +
            "script-src 'self' 'nonce-{random}'; " +
            "style-src 'self' 'unsafe-inline'; " +
            "img-src 'self' data: https:; " +
            "font-src 'self'; " +
            "connect-src 'self'; " +
            "frame-ancestors 'none'");

        context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
        context.Response.Headers.Add("X-Frame-Options", "DENY");
        context.Response.Headers.Add("X-XSS-Protection", "1; mode=block");

        await _next(context);
    }
}
\`\`\`

## 6. File Upload Security

### Secure File Upload Implementation
- Validate file types using content inspection
- Implement file size limits
- Store files outside web root
- Scan for malware when possible

\`\`\`csharp
// File upload service
public class FileUploadService
{
    private readonly string[] _allowedExtensions = { ".jpg", ".jpeg", ".png", ".gif", ".pdf" };
    private readonly string[] _allowedMimeTypes = { "image/jpeg", "image/png", "image/gif", "application/pdf" };
    private readonly long _maxFileSize = 5 * 1024 * 1024; // 5MB
    private readonly string _uploadPath;

    public FileUploadService(IConfiguration configuration)
    {
        _uploadPath = configuration["FileUpload:Path"];
    }

    public async Task<string> UploadFileAsync(IFormFile file)
    {
        ValidateFile(file);

        var fileName = Path.GetRandomFileName() + Path.GetExtension(file.FileName);
        var filePath = Path.Combine(_uploadPath, fileName);

        Directory.CreateDirectory(_uploadPath);

        using (var fileStream = new FileStream(filePath, FileMode.Create))
        {
            await file.CopyToAsync(fileStream);
        }

        // Additional security: scan file content
        await ScanFileAsync(filePath);

        return fileName;
    }

    private void ValidateFile(IFormFile file)
    {
        if (file == null || file.Length == 0)
            throw new ArgumentException("File is required");

        if (file.Length > _maxFileSize)
            throw new ArgumentException("File size exceeds maximum allowed size");

        var extension = Path.GetExtension(file.FileName).ToLowerInvariant();
        if (!_allowedExtensions.Contains(extension))
            throw new ArgumentException("File type not allowed");

        if (!_allowedMimeTypes.Contains(file.ContentType))
            throw new ArgumentException("File content type not allowed");

        // Additional validation: check file signature
        ValidateFileSignature(file);
    }

    private void ValidateFileSignature(IFormFile file)
    {
        using var reader = new BinaryReader(file.OpenReadStream());
        var signatures = new Dictionary<string, List<byte[]>>
        {
            { ".jpg", new List<byte[]> { new byte[] { 0xFF, 0xD8, 0xFF } } },
            { ".png", new List<byte[]> { new byte[] { 0x89, 0x50, 0x4E, 0x47 } } },
            { ".pdf", new List<byte[]> { new byte[] { 0x25, 0x50, 0x44, 0x46 } } }
        };

        var extension = Path.GetExtension(file.FileName).ToLowerInvariant();
        if (signatures.ContainsKey(extension))
        {
            var headerBytes = reader.ReadBytes(4);
            var isValidSignature = signatures[extension].Any(signature =>
                headerBytes.Take(signature.Length).SequenceEqual(signature));

            if (!isValidSignature)
                throw new ArgumentException("File content does not match expected format");
        }
    }

    private async Task ScanFileAsync(string filePath)
    {
        // Implement virus scanning if available
        // Example: integrate with Windows Defender or third-party antivirus
    }
}
\`\`\`

## 7. Error Handling & Information Disclosure

### Secure Error Handling
- Implement global exception handling
- Don't expose sensitive information
- Log errors securely
- Use custom error pages

\`\`\`csharp
// Global exception handling middleware
public class ExceptionHandlingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ExceptionHandlingMiddleware> _logger;

    public ExceptionHandlingMiddleware(RequestDelegate next, ILogger<ExceptionHandlingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An unhandled exception occurred");
            await HandleExceptionAsync(context, ex);
        }
    }

    private static async Task HandleExceptionAsync(HttpContext context, Exception exception)
    {
        context.Response.ContentType = "application/json";

        var response = new
        {
            error = "An error occurred while processing your request",
            statusCode = 500
        };

        switch (exception)
        {
            case ValidationException:
                context.Response.StatusCode = 400;
                response = new { error = "Invalid input data", statusCode = 400 };
                break;
            case UnauthorizedAccessException:
                context.Response.StatusCode = 401;
                response = new { error = "Unauthorized access", statusCode = 401 };
                break;
            case NotFoundException:
                context.Response.StatusCode = 404;
                response = new { error = "Resource not found", statusCode = 404 };
                break;
            default:
                context.Response.StatusCode = 500;
                break;
        }

        var jsonResponse = JsonSerializer.Serialize(response);
        await context.Response.WriteAsync(jsonResponse);
    }
}

// Custom exception classes
public class ValidationException : Exception
{
    public ValidationException(string message) : base(message) { }
}

public class NotFoundException : Exception
{
    public NotFoundException(string message) : base(message) { }
}
\`\`\`

## 8. Configuration Security

### Secure Configuration Management
- Use Azure Key Vault or similar for secrets
- Implement configuration validation
- Use environment-specific settings
- Secure connection strings

\`\`\`csharp
// Secure configuration setup
public class Program
{
    public static void Main(string[] args)
    {
        CreateHostBuilder(args).Build().Run();
    }

    public static IHostBuilder CreateHostBuilder(string[] args) =>
        Host.CreateDefaultBuilder(args)
            .ConfigureAppConfiguration((context, config) =>
            {
                var environment = context.HostingEnvironment;
                
                config.AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                      .AddJsonFile($"appsettings.{environment.EnvironmentName}.json", 
                                 optional: true, reloadOnChange: true)
                      .AddEnvironmentVariables();

                // Add Azure Key Vault in production
                if (environment.IsProduction())
                {
                    var keyVaultEndpoint = config.Build()["KeyVault:Endpoint"];
                    if (!string.IsNullOrEmpty(keyVaultEndpoint))
                    {
                        config.AddAzureKeyVault(new Uri(keyVaultEndpoint), 
                                              new DefaultAzureCredential());
                    }
                }
            })
            .ConfigureWebHostDefaults(webBuilder =>
            {
                webBuilder.UseStartup<Startup>();
            });
}

// Configuration validation
public class DatabaseSettings
{
    public string ConnectionString { get; set; }
    
    [Required]
    [MinLength(10)]
    public string EncryptionKey { get; set; }
    
    [Range(1, 3600)]
    public int CommandTimeout { get; set; } = 30;
}

// Startup configuration
public void ConfigureServices(IServiceCollection services)
{
    // Validate configuration
    services.AddOptions<DatabaseSettings>()
            .Bind(Configuration.GetSection("Database"))
            .ValidateDataAnnotations()
            .ValidateOnStart();
}
\`\`\`

## 9. Logging & Monitoring

### Secure Logging Implementation
- Log security events appropriately
- Never log sensitive information
- Use structured logging
- Implement security monitoring

\`\`\`csharp
// Security audit logger
public class SecurityAuditLogger
{
    private readonly ILogger<SecurityAuditLogger> _logger;

    public SecurityAuditLogger(ILogger<SecurityAuditLogger> logger)
    {
        _logger = logger;
    }

    public void LogLoginSuccess(string userId, string ipAddress)
    {
        _logger.LogInformation("User {UserId} successfully logged in from {IpAddress}", 
                             userId, ipAddress);
    }

    public void LogLoginFailure(string username, string ipAddress, string reason)
    {
        _logger.LogWarning("Failed login attempt for user {Username} from {IpAddress}. Reason: {Reason}", 
                          username, ipAddress, reason);
    }

    public void LogPasswordChange(string userId)
    {
        _logger.LogInformation("Password changed for user {UserId}", userId);
    }

    public void LogSuspiciousActivity(string userId, string activity, string details)
    {
        _logger.LogWarning("Suspicious activity detected for user {UserId}. Activity: {Activity}, Details: {Details}", 
                          userId, activity, details);
    }

    public void LogDataAccess(string userId, string resource, string action)
    {
        _logger.LogInformation("User {UserId} performed {Action} on {Resource}", 
                             userId, action, resource);
    }
}

// Logging configuration (appsettings.json)
{
  "Serilog": {
    "Using": ["Serilog.Sinks.File", "Serilog.Sinks.Console"],
    "MinimumLevel": {
      "Default": "Information",
      "Override": {
        "Microsoft": "Warning",
        "System": "Warning"
      }
    },
    "WriteTo": [
      {
        "Name": "Console"
      },
      {
        "Name": "File",
        "Args": {
          "path": "logs/app-.txt",
          "rollingInterval": "Day",
          "retainedFileCountLimit": 30,
          "formatter": "Serilog.Formatting.Json.JsonFormatter"
        }
      }
    ],
    "Enrich": ["FromLogContext", "WithMachineName", "WithThreadId"]
  }
}
\`\`\`

## 10. API Security

### Secure API Implementation
- Implement proper authentication and authorization
- Use HTTPS for all endpoints
- Implement rate limiting
- Validate and sanitize all inputs

\`\`\`csharp
// Rate limiting implementation
public class RateLimitingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IMemoryCache _cache;
    private readonly RateLimitOptions _options;

    public RateLimitingMiddleware(RequestDelegate next, IMemoryCache cache, RateLimitOptions options)
    {
        _next = next;
        _cache = cache;
        _options = options;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var clientId = GetClientIdentifier(context);
        var key = $"rate_limit_{clientId}";

        if (_cache.TryGetValue(key, out int requestCount))
        {
            if (requestCount >= _options.MaxRequests)
            {
                context.Response.StatusCode = 429; // Too Many Requests
                await context.Response.WriteAsync("Rate limit exceeded");
                return;
            }
            _cache.Set(key, requestCount + 1, TimeSpan.FromMinutes(_options.WindowMinutes));
        }
        else
        {
            _cache.Set(key, 1, TimeSpan.FromMinutes(_options.WindowMinutes));
        }

        await _next(context);
    }

    private string GetClientIdentifier(HttpContext context)
    {
        return context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    }
}

public class RateLimitOptions
{
    public int MaxRequests { get; set; } = 100;
    public int WindowMinutes { get; set; } = 1;
}

// API controller with security attributes
[ApiController]
[Route("api/[controller]")]
[Authorize]
[EnableRateLimiting("DefaultPolicy")]
public class SecureApiController : ControllerBase
{
    private readonly IUserService _userService;
    private readonly ILogger<SecureApiController> _logger;

    public SecureApiController(IUserService userService, ILogger<SecureApiController> logger)
    {
        _userService = userService;
        _logger = logger;
    }

    [HttpGet("{id}")]
    [Authorize(Policy = "OwnerOrAdmin")]
    public async Task<ActionResult<UserDto>> GetUser(int id)
    {
        var user = await _userService.GetByIdAsync(id);
        if (user == null)
        {
            return NotFound();
        }

        _logger.LogInformation("User {UserId} accessed user data for {TargetUserId}", 
                             User.GetUserId(), id);

        return Ok(user.ToDto());
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<ActionResult<UserDto>> CreateUser([FromBody] CreateUserRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var user = await _userService.CreateAsync(request);
        return CreatedAtAction(nameof(GetUser), new { id = user.Id }, user.ToDto());
    }
}
\`\`\`

## Security Checklist for C#/.NET Applications

### Development Phase
- [ ] Input validation implemented with Data Annotations
- [ ] SQL injection prevention with Entity Framework/parameterized queries
- [ ] XSS protection with proper output encoding
- [ ] CSRF protection with anti-forgery tokens
- [ ] Authentication configured with ASP.NET Core Identity
- [ ] Authorization policies implemented
- [ ] Secure password policies configured
- [ ] File upload validation implemented

### Pre-Deployment
- [ ] Dependencies scanned for vulnerabilities
- [ ] Security headers configured
- [ ] HTTPS enforced with HSTS
- [ ] Error handling configured securely
- [ ] Logging configured properly (no sensitive data)
- [ ] Configuration secrets secured (Key Vault)
- [ ] Rate limiting implemented
- [ ] Security tests passed

### Post-Deployment
- [ ] Security monitoring active
- [ ] Log analysis and alerting configured
- [ ] Regular security audits scheduled
- [ ] Dependency updates automated
- [ ] Incident response procedures ready
- [ ] Performance monitoring active

## Common C#/.NET Security Vulnerabilities

1. **SQL Injection**
   - String concatenation in queries
   - Improper use of Entity Framework
   - Dynamic SQL construction

2. **Cross-Site Scripting (XSS)**
   - Unencoded output in Razor views
   - Using Html.Raw without sanitization
   - Missing Content Security Policy

3. **Cross-Site Request Forgery (CSRF)**
   - Missing anti-forgery tokens
   - Disabled CSRF validation
   - Improper token handling

4. **Insecure Authentication**
   - Weak password policies
   - Improper session management
   - Missing two-factor authentication

5. **Authorization Bypass**
   - Missing authorization attributes
   - Improper policy configuration
   - Client-side authorization only

6. **Sensitive Data Exposure**
   - Hardcoded secrets in configuration
   - Unencrypted sensitive data
   - Information disclosure in errors

7. **Security Misconfiguration**
   - Default configurations in production
   - Missing security headers
   - Excessive permissions

8. **Vulnerable Dependencies**
   - Outdated NuGet packages
   - Known security vulnerabilities
   - Unpatched components

9. **Insufficient Logging**
   - Missing security event logging
   - Inadequate monitoring
   - Logging sensitive information

10. **Broken Access Control**
    - Missing authorization checks
    - Privilege escalation vulnerabilities
    - Insecure direct object references`,
  tags: ["csharp", "dotnet", "backend", "security", "web", "enterprise", "authentication"]
};

export default dotnetSecurity;