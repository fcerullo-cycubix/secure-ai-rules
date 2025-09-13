import { Rule } from "../components/SecureAIDirectory";

const angularSecurity: Rule = {
  id: "angular-security",
  title: "Angular Security Guidelines",
  summary: "Essential security practices for Angular application development",
  body: `# Angular Application Security Guidelines

## 1. Cross-Site Scripting (XSS) Prevention

### Template Security
- Always use Angular's built-in template syntax and avoid direct DOM manipulation
- Use Ahead-of-Time (AOT) template compiler in production (mandatory)
- Never create templates by concatenating user input with template syntax
- Treat all values as untrusted by default

### Sanitization
- Use Angular's built-in sanitization for different security contexts:
  - HTML: Sanitizes script tags and dangerous elements
  - Style: Sanitizes CSS and removes JavaScript expressions
  - URL: Sanitizes URLs to prevent javascript: schemes
  - Resource URL: For trusted resources only
- Use DomSanitizer for explicit sanitization when needed
- Only use bypassSecurityTrust* methods after thorough inspection
- Choose the most specific trust method (e.g., bypassSecurityTrustUrl vs bypassSecurityTrustHtml)

### Dangerous Practices to Avoid
- Never use innerHTML with user-controlled data
- Avoid eval() and similar dynamic code execution
- Don't bypass Angular's sanitization without proper validation
- Avoid direct DOM manipulation via ElementRef.nativeElement

## 2. Content Security Policy (CSP)

### Implementation
- Configure CSP headers to prevent XSS attacks
- Use nonce-based CSP for inline scripts and styles
- Generate unique, unpredictable nonces for each request
- Enable Trusted Types enforcement for additional XSS protection
- Implement strict CSP policies that disallow unsafe-inline and unsafe-eval

### CSP Configuration Example
\`\`\`
Content-Security-Policy: 
  default-src 'self';
  script-src 'self' 'nonce-{random}';
  style-src 'self' 'nonce-{random}';
  object-src 'none';
  base-uri 'self';
\`\`\`

## 3. CSRF/XSRF Protection

### Built-in Protection
- Use Angular's HttpClient with built-in XSRF protection
- Configure XSRF cookie and header names if using custom implementation
- Ensure XSRF tokens are included in state-changing requests
- Implement proper server-side CSRF validation

### Configuration
\`\`\`typescript
HttpClientXsrfModule.withOptions({
  cookieName: 'XSRF-TOKEN',
  headerName: 'X-XSRF-TOKEN'
})
\`\`\`

## 4. Authentication & Authorization

### Secure Token Handling
- Use HttpOnly cookies for JWT tokens when possible
- Never store sensitive authentication data in localStorage
- Implement proper token refresh mechanisms
- Use secure session management practices

### Route Protection
- Implement route guards (CanActivate, CanActivateChild, CanLoad)
- Use role-based access control (RBAC)
- Validate permissions on both client and server side
- Implement proper logout and session cleanup

## 5. HTTP Security

### Secure Communication
- Use HTTPS exclusively in production
- Implement proper HTTP interceptors for authentication
- Set secure HTTP headers (HSTS, X-Frame-Options, X-Content-Type-Options)
- Handle HTTP errors securely without exposing sensitive information

### JSON Vulnerability Prevention
- Use Angular's built-in JSON vulnerability protection
- Prefix JSON responses with ")]}',\\n" to prevent JSON hijacking
- Validate all incoming JSON data

## 6. Dependency Management

### Security Updates
- Keep Angular and all dependencies updated regularly
- Monitor Angular security advisories and changelogs
- Use npm audit to identify and fix known vulnerabilities
- Avoid creating private, customized versions of Angular

### Package Security
- Review third-party packages for security vulnerabilities
- Use packages from trusted sources only
- Implement dependency pinning in package-lock.json
- Regularly audit and remove unused dependencies

## 7. Secure Build & Deployment

### Production Build
- Always use Angular CLI's production build (ng build --prod)
- Enable AOT compilation (enabled by default in production)
- Remove development-specific code and debug statements
- Implement proper source map handling for production

### Environment Configuration
- Use environment files correctly for different deployment stages
- Never commit sensitive configuration to version control
- Implement proper secrets management
- Use build-time environment variable substitution

## 8. Form Security

### Input Validation
- Use Angular's reactive forms with proper validation
- Implement both client-side and server-side validation
- Sanitize file uploads and validate file types/sizes
- Use TypeScript strict mode for type safety

### Form Best Practices
- Implement proper error handling that doesn't leak information
- Use CSRF protection for form submissions
- Validate form data before processing
- Implement rate limiting for form submissions

## 9. State Management Security

### NgRx/State Security
- Clear sensitive data from state on logout
- Implement proper state serialization/deserialization
- Use encrypted storage for sensitive state data if needed
- Validate state rehydration to prevent tampering

### Memory Management
- Clear sensitive data from memory when no longer needed
- Implement proper component cleanup in ngOnDestroy
- Avoid memory leaks that could expose sensitive data

## 10. Testing Security

### Security Testing
- Write tests specifically for security vulnerabilities
- Test XSS prevention mechanisms
- Test authentication and authorization flows
- Implement proper E2E security testing
- Use security-focused testing tools and libraries

### Test Data Security
- Never use production data in tests
- Use mock data for testing security scenarios
- Test error handling without exposing sensitive information

## Security Checklist for Angular Applications

### Development Phase
- [ ] AOT compilation enabled for production
- [ ] Strict TypeScript configuration
- [ ] CSP headers configured
- [ ] XSRF protection enabled
- [ ] Input sanitization implemented
- [ ] Secure authentication flow
- [ ] Route guards implemented
- [ ] Dependencies updated and audited

### Pre-Deployment
- [ ] Production build tested
- [ ] Security headers configured
- [ ] HTTPS enforced
- [ ] Source maps handled securely
- [ ] Environment variables secured
- [ ] Error handling reviewed
- [ ] Security tests passing

### Post-Deployment
- [ ] Security monitoring implemented
- [ ] Regular security audits scheduled
- [ ] Dependency update process established
- [ ] Incident response plan ready

## Common Vulnerabilities to Avoid

1. **Template Injection**: Never concatenate user input with template strings
2. **DOM-based XSS**: Avoid direct DOM manipulation with user data
3. **CSRF Attacks**: Always use XSRF protection for state-changing operations
4. **JSON Hijacking**: Use Angular's JSON prefix protection
5. **Dependency Vulnerabilities**: Keep packages updated and audited
6. **Information Disclosure**: Implement proper error handling
7. **Session Management Issues**: Use secure session practices
8. **Insecure Direct Object References**: Validate all user inputs and permissions`,
  tags: ["angular", "frontend", "web", "security", "xss", "csrf", "authentication"]
};

export default angularSecurity;
