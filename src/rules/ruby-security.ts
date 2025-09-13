import { Rule } from "../components/SecureAIDirectory";

const rubySecurity: Rule = {
  id: "ruby-security",
  title: "Ruby Security Guidelines",
  summary: "Comprehensive security guidelines for Ruby and Ruby on Rails applications",
  body: `# Ruby Security Guidelines

## Overview
This guide provides essential security practices for Ruby and Ruby on Rails applications. Following these guidelines helps protect your application against common security threats.

## Security Guidelines

### 1. Input Validation & Sanitization
Always validate and sanitize user input to prevent malicious data:

* Use strong parameters in Rails controllers
* Validate all user input before processing
* Implement whitelist validation
* Example:
  \`\`\`ruby
  # Secure parameter handling
  params.require(:user).permit(:name)
  \`\`\`

### 2. SQL Injection Prevention
Protect your database from unauthorized access:

* Use parameterized queries with Active Record
* Never interpolate user input directly into SQL queries
* Use scopes for complex queries
* Example:
  \`\`\`ruby
  # Safe database query
  User.where(name: params[:name])
  \`\`\`

### 3. Cross-Site Scripting (XSS) Prevention
Guard against malicious script injection:

* Use Rails built-in sanitizers for user content
* Enable and configure Content Security Policy headers
* Never trust user-provided HTML/JavaScript
* Example:
  \`\`\`ruby
  # Safe content rendering
  <%= sanitize user_content %>
  \`\`\`

### 4. Authentication & Sessions
Implement robust user authentication:

* Use secure password hashing with BCrypt
* Enable Multi-Factor Authentication (MFA)
* Set secure cookie flags and proper session management
* Example:
  \`\`\`ruby
  # Secure password handling
  has_secure_password
  validates :password, length: { minimum: 12 }
  \`\`\`

### 5. Cross-Site Request Forgery (CSRF) Protection
Prevent unauthorized commands from authenticated users:

* Enable Rails' built-in CSRF protection
* Use non-GET requests for state changes
* Validate CSRF tokens on form submissions
* Example:
  \`\`\`ruby
  # CSRF protection in controllers
  protect_from_forgery with: :exception
  \`\`\`

### 6. Secure File Uploads
Handle file uploads securely:

* Validate file types and sizes on both client and server
* Implement malware scanning for uploaded files
* Store files in secure, non-public locations
* Example:
  \`\`\`ruby
  # Secure file upload validation
  validates :file, presence: true,
    content_type: ['image/png', 'image/jpg'],
    size: { less_than: 5.megabytes }
  \`\`\`

### 7. Dependency Security
Maintain secure dependencies:

* Regularly run \`bundler-audit\` for vulnerability scanning
* Use \`Brakeman\` for static code analysis
* Keep all gems updated to their latest secure versions
* Example:
  \`\`\`ruby
  # Regular security checks
  bundle audit check --update
  brakeman --no-progress
  \`\`\`

### 8. Secure Logging & Monitoring
Implement proper logging practices:

* Never log sensitive information (passwords, tokens)
* Implement audit trails for critical actions
* Monitor logs for suspicious activities
* Example:
  \`\`\`ruby
  # Secure logging
  Rails.logger.info(
    'User #{user.id} performed #{action}'
  )
  \`\`\`

### 9. API Security
Secure your API endpoints:

* Implement token-based authentication
* Apply rate limiting to prevent abuse
* Version your APIs for secure updates
* Example:
  \`\`\`ruby
  # API rate limiting
  class Api::BaseController < ApplicationController
    include ActionController::HttpAuthentication::Token
    before_action :rate_limit, :authenticate_token
  end
  \`\`\`

### 10. Security Best Practices
General security guidelines:

* Keep Ruby and Rails versions updated
* Use security-focused gems like \`secure_headers\`
* Conduct regular security audits
* Follow OWASP security guidelines
* Example:
  \`\`\`ruby
  # Security headers configuration
  SecureHeaders::Configuration.default do |config|
    config.csp = { default_src: %w('self') }
  end
  \`\`\`

## Security Checklist for Ruby Applications

### Development Phase
- [ ] Strong parameters implemented in all controllers
- [ ] Input validation on all user inputs
- [ ] SQL injection prevention with Active Record
- [ ] XSS protection with built-in sanitizers
- [ ] CSRF protection enabled (protect_from_forgery)
- [ ] Secure password hashing with BCrypt
- [ ] File upload validation implemented
- [ ] Authentication system properly configured
- [ ] Authorization checks on all protected resources

### Pre-Deployment
- [ ] Dependencies audited with bundler-audit
- [ ] Static code analysis with Brakeman
- [ ] Security headers configured with secure_headers gem
- [ ] HTTPS enforced in production
- [ ] Database credentials secured
- [ ] Session configuration hardened
- [ ] Error handling configured to not expose sensitive info
- [ ] Logging configured properly (no sensitive data logged)

### Production Environment
- [ ] Ruby and Rails versions up to date
- [ ] Production secrets properly managed
- [ ] Database connections secured
- [ ] Rate limiting implemented
- [ ] Security monitoring active
- [ ] Regular security audits scheduled
- [ ] Backup and recovery procedures tested
- [ ] Incident response plan documented

### Ongoing Maintenance
- [ ] Regular gem updates and security patches
- [ ] Continuous security monitoring
- [ ] Log analysis for suspicious activities
- [ ] Periodic penetration testing
- [ ] Security training for development team
- [ ] Code review process includes security checks

## Common Ruby Vulnerabilities

1. **Mass Assignment Vulnerabilities**
   - Improper use of strong parameters
   - Allowing users to modify unintended attributes
   - Example: User.create(params[:user]) without filtering

2. **SQL Injection**
   - Direct string interpolation in database queries
   - Improper use of where() with user input
   - Not using parameterized queries for raw SQL

3. **Cross-Site Scripting (XSS)**
   - Using raw() or html_safe without proper sanitization
   - Not escaping user content in templates
   - Improper handling of rich text content

4. **Cross-Site Request Forgery (CSRF)**
   - Missing protect_from_forgery in controllers
   - Disabling CSRF protection without proper alternative
   - Not including CSRF tokens in AJAX requests

5. **Insecure Direct Object References**
   - Not validating user permissions before accessing resources
   - Using predictable IDs without authorization checks
   - Example: @post = Post.find(params[:id]) without ownership check

6. **Session Management Issues**
   - Weak session configuration
   - Not regenerating session IDs after authentication
   - Storing sensitive data in sessions or cookies

7. **File Upload Vulnerabilities**
   - Not validating file types and content
   - Storing uploaded files in publicly accessible directories
   - Not scanning uploads for malware

8. **Deserialization Vulnerabilities**
   - Using Marshal.load() with untrusted data
   - Unsafe YAML parsing with YAML.load()
   - Not validating serialized data before processing

9. **Command Injection**
   - Using system(), exec(), or backticks with user input
   - Not properly escaping shell commands
   - Using dangerous methods like eval() with user data

10. **Information Disclosure**
    - Exposing sensitive data in error messages
    - Not properly configuring development vs production environments
    - Logging sensitive information (passwords, tokens)

11. **Weak Authentication**
    - Not using secure password hashing (plain text, MD5)
    - Weak password policies
    - Missing multi-factor authentication

12. **Authorization Bypass**
    - Missing authorization checks in controllers
    - Improper role-based access control
    - Client-side authorization only

13. **Dependency Vulnerabilities**
    - Using gems with known security vulnerabilities
    - Not regularly updating dependencies
    - Including unnecessary gems that increase attack surface

14. **Configuration Security Issues**
    - Hardcoded secrets in code or configuration files
    - Insecure default configurations
    - Missing security headers

15. **Regular Expression Denial of Service (ReDoS)**
    - Using inefficient regular expressions with user input
    - Not setting timeouts for regex operations
    - Vulnerable regex patterns that can cause exponential backtracking`,
  tags: ["ruby", "rails", "backend", "security", "web", "authentication", "injection"]
};

export default rubySecurity;