import { Rule } from "../components/SecureAIDirectory";

const pythonSecurity: Rule = {
  id: "python-security",
  title: "Python/Django Security Guidelines",
  summary: "Comprehensive security practices for Python and Django applications",
  body: `# Python/Django Security Guidelines

## 1. Input Validation & Sanitization

### Django Forms & Validation
- Use Django's form validation system for all user input
- Implement custom validators for complex validation logic
- Always validate data on both client and server side
- Use Django's built-in field types with proper validation

\`\`\`python
# Secure form validation
class UserForm(forms.ModelForm):
    email = forms.EmailField(validators=[validate_email])
    age = forms.IntegerField(min_value=18, max_value=120)
    
    def clean_username(self):
        username = self.cleaned_data['username']
        if not username.isalnum():
            raise ValidationError('Username must be alphanumeric')
        return username
\`\`\`

### Input Sanitization
- Use Django's built-in HTML escaping (enabled by default)
- Sanitize user input before database operations
- Validate file uploads thoroughly
- Use whitelist validation over blacklist validation

## 2. SQL Injection Prevention

### Django ORM Best Practices
- Always use Django ORM for database operations
- Use parameterized queries when raw SQL is necessary
- Never use string concatenation for SQL queries
- Use Django's Q objects for complex queries

\`\`\`python
# Safe database queries
users = User.objects.filter(username=user_input)  # Safe
users = User.objects.raw("SELECT * FROM users WHERE id = %s", [user_id])  # Safe

# Avoid this
users = User.objects.raw(f"SELECT * FROM users WHERE name = '{name}'")  # Dangerous
\`\`\`

### Raw Query Security
- Use parameterized queries with cursor.execute()
- Validate and sanitize all parameters
- Use Django's connection.ops.quote_name() for dynamic table/column names

## 3. Cross-Site Scripting (XSS) Prevention

### Template Security
- Use Django's automatic HTML escaping (default behavior)
- Be cautious with |safe filter and mark_safe()
- Use |escape filter for user content in JavaScript contexts
- Implement Content Security Policy (CSP) headers

\`\`\`python
# Template security
{{ user_input }}  # Automatically escaped
{{ user_input|safe }}  # Only use after validation
{{ user_input|escapejs }}  # For JavaScript contexts
\`\`\`

### Content Security Policy
- Configure CSP headers using django-csp or custom middleware
- Use nonce-based CSP for inline scripts
- Restrict script sources to trusted domains

## 4. Cross-Site Request Forgery (CSRF) Protection

### Django CSRF Protection
- Always use Django's CSRF protection (enabled by default)
- Include {% csrf_token %} in all forms
- Use @csrf_exempt decorator sparingly and only when necessary
- Configure CSRF settings properly for AJAX requests

\`\`\`python
# CSRF protection in views
from django.views.decorators.csrf import csrf_protect

@csrf_protect
def my_view(request):
    if request.method == 'POST':
        # Process form data
        pass
\`\`\`

## 5. Authentication & Session Security

### Django Authentication
- Use Django's built-in authentication system
- Implement proper password policies
- Use Django's password validators
- Enable secure session configuration

\`\`\`python
# Secure password validation
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', 'OPTIONS': {'min_length': 12}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# Secure session settings
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
\`\`\`

### Two-Factor Authentication
- Implement 2FA using libraries like django-otp
- Use time-based or SMS-based authentication
- Provide backup codes for account recovery

## 6. File Upload Security

### Secure File Handling
- Validate file types using content inspection, not just extensions
- Limit file sizes and implement quotas
- Store uploaded files outside the web root
- Scan files for malware when possible

\`\`\`python
# Secure file upload validation
def validate_file_extension(value):
    allowed_extensions = ['.jpg', '.jpeg', '.png', '.pdf']
    ext = os.path.splitext(value.name)[1].lower()
    if ext not in allowed_extensions:
        raise ValidationError('Unsupported file extension.')

class DocumentForm(forms.Form):
    file = forms.FileField(validators=[validate_file_extension])
    
    def clean_file(self):
        file = self.cleaned_data['file']
        if file.size > 10 * 1024 * 1024:  # 10MB limit
            raise ValidationError('File too large.')
        return file
\`\`\`

## 7. Security Headers & HTTPS

### Django Security Settings
- Configure security-related settings in production
- Use HTTPS exclusively (SECURE_SSL_REDIRECT = True)
- Set proper security headers

\`\`\`python
# Security settings for production
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
X_FRAME_OPTIONS = 'DENY'
SECURE_SSL_REDIRECT = True
\`\`\`

## 8. Dependency Security

### Package Management
- Use pip-audit to scan for vulnerable dependencies
- Keep all packages updated to latest secure versions
- Use requirements.txt with pinned versions
- Regularly review and remove unused dependencies

\`\`\`bash
# Security checks
pip-audit  # Scan for vulnerabilities
safety check  # Alternative vulnerability scanner
pip list --outdated  # Check for updates
\`\`\`

### Virtual Environment Security
- Always use virtual environments
- Don't install packages globally
- Use tools like pipenv or poetry for better dependency management

## 9. Error Handling & Information Disclosure

### Secure Error Handling
- Set DEBUG = False in production
- Implement custom error pages (404, 500)
- Log errors securely without exposing sensitive data
- Use Django's logging framework properly

\`\`\`python
# Secure error handling
DEBUG = False
ALLOWED_HOSTS = ['yourdomain.com']

# Custom error views
def custom_404_view(request, exception):
    return render(request, '404.html', status=404)

def custom_500_view(request):
    return render(request, '500.html', status=500)
\`\`\`

## 10. API Security

### Django REST Framework Security
- Use proper authentication (Token, JWT, OAuth2)
- Implement rate limiting and throttling
- Validate and serialize all API data
- Use HTTPS for all API endpoints

\`\`\`python
# DRF security settings
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.TokenAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle'
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/hour',
        'user': '1000/hour'
    }
}
\`\`\`

## 11. Database Security

### Django Database Security
- Use database connection pooling
- Implement proper database user permissions
- Enable database query logging for monitoring
- Use database connection encryption

\`\`\`python
# Secure database configuration
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'OPTIONS': {
            'sslmode': 'require',
        },
        'CONN_MAX_AGE': 60,
    }
}
\`\`\`

## 12. Serialization Security

### Pickle Security
- Avoid using pickle for untrusted data
- Use JSON for data serialization when possible
- If pickle is necessary, validate and sanitize input

\`\`\`python
# Secure serialization
import json

# Safe serialization
data = json.dumps(user_data)
loaded_data = json.loads(data)

# Avoid pickle with untrusted data
# pickle.loads(untrusted_data)  # Dangerous
\`\`\`

## 13. Logging & Monitoring

### Secure Logging
- Log security events (failed logins, permission denials)
- Never log sensitive data (passwords, tokens)
- Implement log rotation and secure storage
- Monitor logs for suspicious activity

\`\`\`python
# Secure logging configuration
LOGGING = {
    'version': 1,
    'handlers': {
        'security_file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '/var/log/django/security.log',
            'maxBytes': 1024*1024*15,  # 15MB
            'backupCount': 10,
        },
    },
    'loggers': {
        'security': {
            'handlers': ['security_file'],
            'level': 'INFO',
        },
    },
}
\`\`\`

## Security Checklist for Django Applications

### Development Phase
- [ ] DEBUG = False in production
- [ ] Strong password policies implemented
- [ ] CSRF protection enabled
- [ ] XSS protection configured
- [ ] SQL injection prevention verified
- [ ] File upload security implemented
- [ ] Input validation on all forms
- [ ] Security headers configured

### Pre-Deployment
- [ ] Dependencies scanned for vulnerabilities
- [ ] HTTPS enforced
- [ ] Security middleware enabled
- [ ] Error handling secured
- [ ] Logging configured properly
- [ ] Database permissions restricted
- [ ] Static files served securely

### Post-Deployment
- [ ] Security monitoring implemented
- [ ] Regular security audits scheduled
- [ ] Backup and recovery procedures tested
- [ ] Incident response plan ready

## Common Python/Django Vulnerabilities

1. **SQL Injection**: Use ORM, avoid raw SQL with string concatenation
2. **XSS**: Use Django's auto-escaping, be careful with |safe filter
3. **CSRF**: Always use CSRF protection, include tokens in forms
4. **Insecure Direct Object References**: Validate object access permissions
5. **Security Misconfiguration**: Proper production settings, disable DEBUG
6. **Sensitive Data Exposure**: Secure error handling, proper logging
7. **Pickle Deserialization**: Avoid pickle with untrusted data
8. **Path Traversal**: Validate file paths, use os.path.join()`,
  tags: ["python", "django", "backend", "security", "web", "sql", "xss", "csrf"]
};

export default pythonSecurity;