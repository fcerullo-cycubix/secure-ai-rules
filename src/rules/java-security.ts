import { Rule } from "../components/SecureAIDirectory";

const javaSecurity: Rule = {
  id: "java-security",
  title: "Java/Spring Security Guidelines",
  summary: "Comprehensive security practices for Java and Spring Framework applications",
  body: `# Java/Spring Security Guidelines

## 1. Input Validation & Sanitization

### Spring Boot Validation
- Use Bean Validation (JSR-303/JSR-380) annotations
- Implement custom validators for complex validation logic
- Validate all user input at controller and service layers
- Use Spring's validation framework

\`\`\`java
// Bean validation with annotations
@Entity
public class User {
    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 20, message = "Username must be between 3 and 20 characters")
    @Pattern(regexp = "^[a-zA-Z0-9_]+$", message = "Username can only contain alphanumeric characters and underscores")
    private String username;
    
    @Email(message = "Invalid email format")
    @NotBlank(message = "Email is required")
    private String email;
    
    @Min(value = 18, message = "Age must be at least 18")
    @Max(value = 120, message = "Age must be less than 120")
    private Integer age;
}

// Controller validation
@RestController
public class UserController {
    
    @PostMapping("/users")
    public ResponseEntity<User> createUser(@Valid @RequestBody User user, BindingResult result) {
        if (result.hasErrors()) {
            throw new ValidationException("Invalid user data");
        }
        // Process valid user data
        return ResponseEntity.ok(userService.save(user));
    }
}
\`\`\`

### Input Sanitization
- Sanitize HTML content using libraries like OWASP Java HTML Sanitizer
- Escape special characters for different contexts
- Validate file uploads thoroughly
- Use parameterized queries to prevent SQL injection

\`\`\`java
// HTML sanitization
import org.owasp.html.PolicyFactory;
import org.owasp.html.Sanitizers;

@Service
public class ContentSanitizer {
    private static final PolicyFactory POLICY = Sanitizers.FORMATTING
            .and(Sanitizers.LINKS)
            .and(Sanitizers.BLOCKS);
    
    public String sanitizeHtml(String untrustedHtml) {
        return POLICY.sanitize(untrustedHtml);
    }
    
    public String escapeForJavaScript(String input) {
        return StringEscapeUtils.escapeEcmaScript(input);
    }
}
\`\`\`

## 2. SQL Injection Prevention

### JPA and Hibernate Security
- Use JPA queries with parameters
- Avoid dynamic query construction with string concatenation
- Use criteria API for complex queries
- Implement proper error handling

\`\`\`java
// Safe JPA queries
@Repository
public class UserRepository {
    
    @PersistenceContext
    private EntityManager entityManager;
    
    // Safe parameterized query
    public List<User> findByUsername(String username) {
        TypedQuery<User> query = entityManager.createQuery(
            "SELECT u FROM User u WHERE u.username = :username", User.class);
        query.setParameter("username", username);
        return query.getResultList();
    }
    
    // Safe criteria API usage
    public List<User> findUsersByCriteria(String username, String email) {
        CriteriaBuilder cb = entityManager.getCriteriaBuilder();
        CriteriaQuery<User> query = cb.createQuery(User.class);
        Root<User> user = query.from(User.class);
        
        List<Predicate> predicates = new ArrayList<>();
        if (username != null) {
            predicates.add(cb.equal(user.get("username"), username));
        }
        if (email != null) {
            predicates.add(cb.equal(user.get("email"), email));
        }
        
        query.where(predicates.toArray(new Predicate[0]));
        return entityManager.createQuery(query).getResultList();
    }
}

// Avoid this - dangerous string concatenation
public List<User> dangerousQuery(String username) {
    String sql = "SELECT * FROM users WHERE username = '" + username + "'"; // DON'T DO THIS
    return entityManager.createNativeQuery(sql, User.class).getResultList();
}
\`\`\`

### JDBC Security
- Use PreparedStatement instead of Statement
- Validate all parameters before setting them
- Use stored procedures when appropriate

\`\`\`java
// Safe JDBC usage
@Repository
public class UserJdbcRepository {
    
    @Autowired
    private JdbcTemplate jdbcTemplate;
    
    public User findById(Long id) {
        String sql = "SELECT * FROM users WHERE id = ?";
        return jdbcTemplate.queryForObject(sql, new Object[]{id}, new UserRowMapper());
    }
    
    public void updateUser(User user) {
        String sql = "UPDATE users SET username = ?, email = ? WHERE id = ?";
        jdbcTemplate.update(sql, user.getUsername(), user.getEmail(), user.getId());
    }
}
\`\`\`

## 3. Authentication & Authorization

### Spring Security Configuration
- Configure proper authentication mechanisms
- Implement role-based access control (RBAC)
- Use secure password encoding
- Configure session management properly

\`\`\`java
// Spring Security configuration
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig {
    
    @Autowired
    private UserDetailsService userDetailsService;
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }
    
    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/api/public/**").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/user/**").hasAnyRole("USER", "ADMIN")
                .anyRequest().authenticated()
            )
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .maximumSessions(1)
                .maxSessionsPreventsLogin(false)
            )
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            )
            .headers(headers -> headers
                .frameOptions().deny()
                .contentTypeOptions().and()
                .httpStrictTransportSecurity(hsts -> hsts
                    .maxAgeInSeconds(31536000)
                    .includeSubdomains(true)
                )
            );
        return http.build();
    }
}
\`\`\`

### JWT Security
- Use secure JWT implementation
- Implement proper token validation
- Use short-lived access tokens with refresh tokens
- Store JWTs securely

\`\`\`java
// JWT Security implementation
@Component
public class JwtTokenProvider {
    
    @Value("\${app.jwtSecret}")
    private String jwtSecret;
    
    @Value("\${app.jwtExpirationInMs}")
    private int jwtExpirationInMs;
    
    public String generateToken(Authentication authentication) {
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
        Date expiryDate = new Date(System.currentTimeMillis() + jwtExpirationInMs);
        
        return Jwts.builder()
                .setSubject(Long.toString(userPrincipal.getId()))
                .setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }
    
    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token);
            return true;
        } catch (SignatureException ex) {
            logger.error("Invalid JWT signature");
        } catch (MalformedJwtException ex) {
            logger.error("Invalid JWT token");
        } catch (ExpiredJwtException ex) {
            logger.error("Expired JWT token");
        } catch (UnsupportedJwtException ex) {
            logger.error("Unsupported JWT token");
        } catch (IllegalArgumentException ex) {
            logger.error("JWT claims string is empty");
        }
        return false;
    }
}
\`\`\`

## 4. Cross-Site Request Forgery (CSRF) Protection

### CSRF Configuration
- Enable CSRF protection for state-changing operations
- Use proper CSRF token handling
- Configure CSRF for REST APIs appropriately
- Implement SameSite cookie attributes

\`\`\`java
// CSRF configuration
@Configuration
public class CsrfConfig {
    
    @Bean
    public CsrfTokenRepository csrfTokenRepository() {
        HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
        repository.setHeaderName("X-XSRF-TOKEN");
        return repository;
    }
    
    // Custom CSRF configuration for APIs
    @Bean
    public SecurityFilterChain apiFilterChain(HttpSecurity http) throws Exception {
        http
            .requestMatchers("/api/**")
            .csrf(csrf -> csrf
                .csrfTokenRepository(csrfTokenRepository())
                .ignoringRequestMatchers("/api/auth/login") // Login endpoint
            );
        return http.build();
    }
}

// Controller with CSRF protection
@Controller
public class FormController {
    
    @PostMapping("/update-profile")
    public String updateProfile(@ModelAttribute User user, 
                               HttpServletRequest request) {
        // CSRF token automatically validated by Spring Security
        userService.updateUser(user);
        return "redirect:/profile";
    }
}
\`\`\`

## 5. Cross-Site Scripting (XSS) Prevention

### Template Security
- Use Thymeleaf with proper escaping
- Sanitize user content before rendering
- Implement Content Security Policy
- Validate and encode output

\`\`\`html
<!-- Thymeleaf template with automatic escaping -->
<div th:text="\${userInput}">User content (automatically escaped)</div>

<!-- Unescaped content (use with caution) -->
<div th:utext="\${sanitizedHtml}">Sanitized HTML content</div>

<!-- Attribute escaping -->
<input type="text" th:value="\${userInput}" />
\`\`\`

\`\`\`java
// Content Security Policy configuration
@Configuration
public class WebSecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .headers(headers -> headers
                .contentSecurityPolicy("default-src 'self'; " +
                    "script-src 'self' 'nonce-{random}'; " +
                    "style-src 'self' 'unsafe-inline'; " +
                    "img-src 'self' data: https:;")
            );
        return http.build();
    }
}
\`\`\`

## 6. File Upload Security

### Secure File Upload
- Validate file types using content inspection
- Implement file size limits
- Store uploaded files outside web root
- Scan files for malware when possible

\`\`\`java
// Secure file upload service
@Service
public class FileUploadService {
    
    private static final List<String> ALLOWED_CONTENT_TYPES = Arrays.asList(
        "image/jpeg", "image/png", "image/gif", "application/pdf"
    );
    
    private static final long MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB
    
    @Value("\${app.upload.dir}")
    private String uploadDir;
    
    public String uploadFile(MultipartFile file) throws IOException {
        validateFile(file);
        
        String fileName = UUID.randomUUID().toString() + "_" + 
                         StringUtils.cleanPath(file.getOriginalFilename());
        Path uploadPath = Paths.get(uploadDir);
        
        if (!Files.exists(uploadPath)) {
            Files.createDirectories(uploadPath);
        }
        
        Path filePath = uploadPath.resolve(fileName);
        Files.copy(file.getInputStream(), filePath, StandardCopyOption.REPLACE_EXISTING);
        
        return fileName;
    }
    
    private void validateFile(MultipartFile file) {
        if (file.isEmpty()) {
            throw new IllegalArgumentException("File is empty");
        }
        
        if (file.getSize() > MAX_FILE_SIZE) {
            throw new IllegalArgumentException("File size exceeds limit");
        }
        
        if (!ALLOWED_CONTENT_TYPES.contains(file.getContentType())) {
            throw new IllegalArgumentException("File type not allowed");
        }
        
        // Additional validation: check file signature
        try {
            String detectedType = Files.probeContentType(Paths.get(file.getOriginalFilename()));
            if (!ALLOWED_CONTENT_TYPES.contains(detectedType)) {
                throw new IllegalArgumentException("File content type mismatch");
            }
        } catch (IOException e) {
            throw new IllegalArgumentException("Could not determine file type");
        }
    }
}
\`\`\`

## 7. Error Handling & Information Disclosure

### Secure Error Handling
- Don't expose sensitive information in error messages
- Implement global exception handling
- Log errors securely
- Use custom error pages

\`\`\`java
// Global exception handler
@ControllerAdvice
public class GlobalExceptionHandler {
    
    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);
    
    @ExceptionHandler(ValidationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<ErrorResponse> handleValidationException(ValidationException ex) {
        logger.warn("Validation error: {}", ex.getMessage());
        return ResponseEntity.badRequest()
                .body(new ErrorResponse("Invalid input data", "VALIDATION_ERROR"));
    }
    
    @ExceptionHandler(AccessDeniedException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public ResponseEntity<ErrorResponse> handleAccessDenied(AccessDeniedException ex) {
        logger.warn("Access denied: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(new ErrorResponse("Access denied", "ACCESS_DENIED"));
    }
    
    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ResponseEntity<ErrorResponse> handleGenericException(Exception ex) {
        // Log full error details server-side
        logger.error("Unexpected error occurred", ex);
        
        // Return generic error message to client
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ErrorResponse("An error occurred", "INTERNAL_ERROR"));
    }
}

// Error response DTO
public class ErrorResponse {
    private String message;
    private String errorCode;
    private LocalDateTime timestamp;
    
    public ErrorResponse(String message, String errorCode) {
        this.message = message;
        this.errorCode = errorCode;
        this.timestamp = LocalDateTime.now();
    }
    
    // Getters and setters
}
\`\`\`

## 8. Dependency Security

### Maven/Gradle Security
- Use dependency check plugins
- Keep dependencies updated
- Use dependency lock files
- Audit third-party libraries

\`\`\`xml
<!-- Maven dependency check plugin -->
<plugin>
    <groupId>org.owasp</groupId>
    <artifactId>dependency-check-maven</artifactId>
    <version>8.4.0</version>
    <configuration>
        <failBuildOnCVSS>7</failBuildOnCVSS>
    </configuration>
    <executions>
        <execution>
            <goals>
                <goal>check</goal>
            </goals>
        </execution>
    </executions>
</plugin>
\`\`\`

\`\`\`gradle
// Gradle dependency check
plugins {
    id 'org.owasp.dependencycheck' version '8.4.0'
}

dependencyCheck {
    failBuildOnCVSS = 7
    format = 'ALL'
}
\`\`\`

## 9. Logging & Monitoring

### Secure Logging
- Log security events appropriately
- Never log sensitive information
- Use structured logging
- Implement log monitoring

\`\`\`java
// Secure logging configuration
@Component
public class SecurityAuditLogger {
    
    private static final Logger securityLogger = LoggerFactory.getLogger("SECURITY");
    
    @EventListener
    public void handleAuthenticationSuccess(AuthenticationSuccessEvent event) {
        securityLogger.info("Authentication successful for user: {}", 
                           event.getAuthentication().getName());
    }
    
    @EventListener
    public void handleAuthenticationFailure(AbstractAuthenticationFailureEvent event) {
        securityLogger.warn("Authentication failed for user: {} - Reason: {}", 
                           event.getAuthentication().getName(),
                           event.getException().getMessage());
    }
    
    public void logSecurityEvent(String event, String userId, String details) {
        securityLogger.info("Security event: {} - User: {} - Details: {}", 
                           event, userId, details);
    }
}

// Logging configuration (logback-spring.xml)
<configuration>
    <appender name="SECURITY" class="ch.qos.logback.core.rolling.RollingFileAppender">
        <file>logs/security.log</file>
        <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
            <fileNamePattern>logs/security.%d{yyyy-MM-dd}.log</fileNamePattern>
            <maxHistory>30</maxHistory>
        </rollingPolicy>
        <encoder>
            <pattern>%d{ISO8601} [%thread] %-5level %logger{36} - %msg%n</pattern>
        </encoder>
    </appender>
    
    <logger name="SECURITY" level="INFO" additivity="false">
        <appender-ref ref="SECURITY"/>
    </logger>
</configuration>
\`\`\`

## 10. API Security

### REST API Security
- Implement proper authentication for APIs
- Use HTTPS for all API endpoints
- Validate and sanitize all API inputs
- Implement rate limiting

\`\`\`java
// API security configuration
@RestController
@RequestMapping("/api/v1")
@PreAuthorize("hasRole('USER')")
public class ApiController {
    
    @GetMapping("/users/{id}")
    @PreAuthorize("hasRole('ADMIN') or @userService.isOwner(authentication.name, #id)")
    public ResponseEntity<User> getUser(@PathVariable @Min(1) Long id) {
        User user = userService.findById(id);
        return ResponseEntity.ok(user);
    }
    
    @PostMapping("/users")
    @RateLimited(requests = 5, timeWindow = 60) // Custom rate limiting annotation
    public ResponseEntity<User> createUser(@Valid @RequestBody CreateUserRequest request) {
        User user = userService.createUser(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(user);
    }
}

// Rate limiting implementation
@Component
@Aspect
public class RateLimitingAspect {
    
    private final RedisTemplate<String, String> redisTemplate;
    
    @Around("@annotation(rateLimited)")
    public Object rateLimit(ProceedingJoinPoint joinPoint, RateLimited rateLimited) throws Throwable {
        HttpServletRequest request = 
            ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
        
        String clientId = getClientIdentifier(request);
        String key = "rate_limit:" + clientId + ":" + joinPoint.getSignature().getName();
        
        String currentCount = redisTemplate.opsForValue().get(key);
        if (currentCount != null && Integer.parseInt(currentCount) >= rateLimited.requests()) {
            throw new RateLimitExceededException("Rate limit exceeded");
        }
        
        redisTemplate.opsForValue().increment(key);
        redisTemplate.expire(key, Duration.ofSeconds(rateLimited.timeWindow()));
        
        return joinPoint.proceed();
    }
}
\`\`\`

## Security Checklist for Java/Spring Applications

### Development Phase
- [ ] Input validation implemented on all endpoints
- [ ] SQL injection prevention with parameterized queries
- [ ] XSS protection with proper output encoding
- [ ] CSRF protection enabled
- [ ] Authentication and authorization configured
- [ ] Secure password encoding (BCrypt)
- [ ] File upload validation implemented
- [ ] Error handling configured securely

### Pre-Deployment
- [ ] Dependencies scanned for vulnerabilities
- [ ] Security headers configured
- [ ] HTTPS enforced
- [ ] Session management secured
- [ ] Logging configured properly
- [ ] API endpoints protected
- [ ] Rate limiting implemented
- [ ] Security tests passed

### Post-Deployment
- [ ] Security monitoring active
- [ ] Log analysis implemented
- [ ] Regular security audits scheduled
- [ ] Dependency updates managed
- [ ] Incident response procedures ready

## Common Java/Spring Security Vulnerabilities

1. **SQL Injection**
   - String concatenation in queries
   - Improper use of native queries
   - Dynamic query construction

2. **Cross-Site Scripting (XSS)**
   - Unescaped user input in templates
   - Improper output encoding
   - Missing Content Security Policy

3. **Cross-Site Request Forgery (CSRF)**
   - Disabled CSRF protection
   - Missing CSRF tokens
   - Improper token validation

4. **Insecure Authentication**
   - Weak password policies
   - Improper session management
   - Missing multi-factor authentication

5. **Authorization Bypass**
   - Missing access controls
   - Improper role validation
   - Client-side authorization only

6. **Sensitive Data Exposure**
   - Unencrypted sensitive data
   - Information disclosure in errors
   - Logging sensitive information

7. **Security Misconfiguration**
   - Default configurations
   - Missing security headers
   - Unnecessary features enabled

8. **Vulnerable Dependencies**
   - Outdated libraries
   - Known security vulnerabilities
   - Unpatched components

9. **Insufficient Logging**
   - Missing security event logging
   - Inadequate monitoring
   - Poor audit trails

10. **Broken Access Control**
    - Missing authorization checks
    - Privilege escalation
    - Direct object references`,
  tags: ["java", "spring", "backend", "security", "web", "enterprise", "authentication"]
};

export default javaSecurity;