import { Rule } from "../components/SecureAIDirectory";

const nodejsSecurity: Rule = {
  id: "nodejs-security",
  title: "Node.js/Express Security Guidelines",
  summary: "Essential security practices for Node.js and Express.js applications",
  body: `# Node.js/Express Security Guidelines

## 1. Input Validation & Sanitization

### Express Validation
- Use validation libraries like joi, express-validator, or yup
- Validate all incoming data (body, query, params, headers)
- Sanitize input to prevent injection attacks
- Implement input length limits

\`\`\`javascript
// Input validation with express-validator
const { body, validationResult } = require('express-validator');

app.post('/users', 
  body('email').isEmail().normalizeEmail(),
  body('age').isInt({ min: 18, max: 120 }),
  body('username').isAlphanumeric().trim().escape(),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    // Process validated data
  }
);
\`\`\`

### Data Sanitization
- Use libraries like DOMPurify for HTML sanitization
- Escape special characters in user input
- Validate file uploads thoroughly
- Implement content type validation

## 2. SQL/NoSQL Injection Prevention

### Database Security
- Use parameterized queries or prepared statements
- Use ORMs like Sequelize, Prisma, or Mongoose properly
- Never concatenate user input directly into queries
- Validate and sanitize database inputs

\`\`\`javascript
// Safe database queries
// With parameterized queries (MySQL)
const query = 'SELECT * FROM users WHERE id = ?';
db.query(query, [userId], (err, results) => {
  // Handle results
});

// With Mongoose (MongoDB)
User.findOne({ username: req.body.username }); // Safe

// Avoid this
const query = \`SELECT * FROM users WHERE name = '\${name}'\`; // Dangerous
\`\`\`

### NoSQL Injection Prevention
- Validate MongoDB query operators
- Use schema validation
- Sanitize object keys and values

\`\`\`javascript
// MongoDB injection prevention
const sanitize = require('mongo-sanitize');

app.post('/login', (req, res) => {
  const username = sanitize(req.body.username);
  const password = sanitize(req.body.password);
  
  User.findOne({ username, password }); // Safer
});
\`\`\`

## 3. Cross-Site Scripting (XSS) Prevention

### Template Security
- Use template engines with automatic escaping (Handlebars, Pug)
- Sanitize user content before rendering
- Implement Content Security Policy (CSP)
- Validate and encode output

\`\`\`javascript
// XSS prevention with helmet
const helmet = require('helmet');
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    scriptSrc: ["'self'"],
    imgSrc: ["'self'", "data:", "https:"]
  }
}));

// Safe template rendering (Handlebars auto-escapes)
// {{username}} - automatically escaped
// {{{username}}} - unescaped (use carefully)
\`\`\`

### Output Encoding
- Use libraries like he or validator for encoding
- Encode data based on output context (HTML, JavaScript, URL)
- Validate Rich Text Editor content

## 4. Cross-Site Request Forgery (CSRF) Protection

### CSRF Prevention
- Use CSRF tokens for state-changing operations
- Implement SameSite cookie attributes
- Validate origin and referer headers
- Use anti-CSRF libraries

\`\`\`javascript
// CSRF protection with csurf
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: true });

app.use(csrfProtection);

app.get('/form', (req, res) => {
  res.render('form', { csrfToken: req.csrfToken() });
});

app.post('/process', (req, res) => {
  // CSRF token automatically validated
  // Process form data
});
\`\`\`

## 5. Authentication & Session Management

### Secure Authentication
- Use established libraries like Passport.js
- Implement proper password hashing with bcrypt
- Use secure session configuration
- Implement account lockout mechanisms

\`\`\`javascript
// Secure password hashing
const bcrypt = require('bcrypt');
const saltRounds = 12;

// Hash password
const hashPassword = async (password) => {
  return await bcrypt.hash(password, saltRounds);
};

// Verify password
const verifyPassword = async (password, hash) => {
  return await bcrypt.compare(password, hash);
};

// Secure session configuration
app.use(session({
  secret: process.env.SESSION_SECRET,
  name: 'sessionId',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true, // HTTPS only
    httpOnly: true, // No client-side access
    maxAge: 1000 * 60 * 60 * 24, // 24 hours
    sameSite: 'strict'
  }
}));
\`\`\`

### JWT Security
- Use secure JWT practices
- Store JWTs securely (HttpOnly cookies preferred)
- Implement proper token expiration
- Use refresh tokens for long-term access

\`\`\`javascript
// JWT security best practices
const jwt = require('jsonwebtoken');

// Generate JWT
const generateToken = (payload) => {
  return jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: '15m',
    issuer: 'your-app',
    audience: 'your-users'
  });
};

// Verify JWT
const verifyToken = (token) => {
  return jwt.verify(token, process.env.JWT_SECRET);
};
\`\`\`

## 6. Security Headers & HTTPS

### Helmet.js Security
- Use Helmet.js for security headers
- Configure HTTPS enforcement
- Implement proper CORS policies
- Set security headers appropriately

\`\`\`javascript
// Comprehensive security headers with Helmet
const helmet = require('helmet');

app.use(helmet({
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"]
    }
  }
}));

// CORS configuration
const cors = require('cors');
app.use(cors({
  origin: ['https://yourdomain.com'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
\`\`\`

## 7. File Upload Security

### Secure File Handling
- Validate file types using magic bytes, not extensions
- Implement file size limits
- Store files outside web root
- Scan uploaded files for malware

\`\`\`javascript
// Secure file upload with multer
const multer = require('multer');
const path = require('path');

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, '/secure/uploads/'); // Outside web root
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/png', 'application/pdf'];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type'), false);
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
    files: 1
  }
});
\`\`\`

## 8. Error Handling & Information Disclosure

### Secure Error Handling
- Never expose sensitive information in errors
- Implement proper error logging
- Use generic error messages for production
- Set up proper error monitoring

\`\`\`javascript
// Secure error handling
const winston = require('winston');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error('Error occurred:', {
    error: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip
  });

  if (process.env.NODE_ENV === 'production') {
    res.status(500).json({ error: 'Internal Server Error' });
  } else {
    res.status(500).json({ error: err.message, stack: err.stack });
  }
});
\`\`\`

## 9. Rate Limiting & DDoS Protection

### Rate Limiting
- Implement rate limiting on all endpoints
- Use different limits for different endpoints
- Implement progressive delays for repeated violations
- Monitor and alert on rate limit violations

\`\`\`javascript
// Rate limiting with express-rate-limit
const rateLimit = require('express-rate-limit');

// General rate limiting
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP',
  standardHeaders: true,
  legacyHeaders: false
});

// Strict rate limiting for login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // 5 login attempts per IP
  skipSuccessfulRequests: true,
  message: 'Too many login attempts'
});

app.use('/api/', generalLimiter);
app.use('/auth/login', loginLimiter);
\`\`\`

## 10. Dependency Security

### Package Management
- Regularly audit dependencies with npm audit
- Use tools like Snyk for vulnerability scanning
- Keep dependencies updated
- Remove unused packages

\`\`\`bash
# Security checks
npm audit --audit-level high
npm audit fix

# Check for outdated packages
npm outdated

# Use security-focused tools
npx snyk test
npx retire
\`\`\`

### Package Security Best Practices
- Use package-lock.json for reproducible builds
- Verify package integrity
- Use minimal dependencies
- Review third-party code before adding dependencies

## 11. Environment & Configuration Security

### Environment Variables
- Use environment variables for sensitive configuration
- Never commit secrets to version control
- Use tools like dotenv for local development
- Validate required environment variables on startup

\`\`\`javascript
// Environment configuration
require('dotenv').config();

// Validate required environment variables
const requiredEnvVars = ['DATABASE_URL', 'JWT_SECRET', 'SESSION_SECRET'];
const missingVars = requiredEnvVars.filter(envVar => !process.env[envVar]);

if (missingVars.length > 0) {
  console.error('Missing required environment variables:', missingVars);
  process.exit(1);
}

// Use environment variables
const dbUrl = process.env.DATABASE_URL;
const jwtSecret = process.env.JWT_SECRET;
\`\`\`

## 12. API Security

### RESTful API Security
- Use HTTPS for all API endpoints
- Implement proper authentication and authorization
- Validate all API inputs
- Use appropriate HTTP methods and status codes

\`\`\`javascript
// API security middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Protected API route
app.get('/api/users', authenticateToken, (req, res) => {
  // Return user data
});
\`\`\`

## 13. Logging & Monitoring

### Security Logging
- Log all security-relevant events
- Never log sensitive data
- Implement log rotation
- Monitor logs for suspicious activity

\`\`\`javascript
// Security event logging
const logSecurityEvent = (event, req, additional = {}) => {
  logger.warn('Security event:', {
    event,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    url: req.url,
    method: req.method,
    timestamp: new Date().toISOString(),
    ...additional
  });
};

// Usage in authentication
app.post('/login', (req, res) => {
  // ... authentication logic
  
  if (authFailed) {
    logSecurityEvent('LOGIN_FAILED', req, { username: req.body.username });
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  logSecurityEvent('LOGIN_SUCCESS', req, { userId: user.id });
  // ... success logic
});
\`\`\`

## Security Checklist for Node.js Applications

### Development Phase
- [ ] Input validation on all endpoints
- [ ] SQL/NoSQL injection prevention
- [ ] XSS protection implemented
- [ ] CSRF protection enabled
- [ ] Secure authentication system
- [ ] Password hashing with bcrypt
- [ ] Rate limiting configured
- [ ] Security headers set with Helmet

### Pre-Deployment
- [ ] Dependencies audited for vulnerabilities
- [ ] Environment variables secured
- [ ] HTTPS enforced
- [ ] Error handling secured
- [ ] Logging configured properly
- [ ] File upload security implemented
- [ ] API endpoints protected

### Post-Deployment
- [ ] Security monitoring active
- [ ] Regular dependency updates scheduled
- [ ] Log monitoring implemented
- [ ] Incident response procedures ready

## Common Node.js Security Vulnerabilities

1. **Injection Attacks**: SQL/NoSQL injection, command injection
2. **Cross-Site Scripting (XSS)**: Reflected, stored, DOM-based XSS
3. **Cross-Site Request Forgery (CSRF)**: Unauthorized state changes
4. **Insecure Authentication**: Weak passwords, session management issues
5. **Security Misconfiguration**: Default settings, exposed debug info
6. **Sensitive Data Exposure**: Inadequate protection of sensitive data
7. **Broken Access Control**: Improper authorization checks
8. **Vulnerable Dependencies**: Outdated packages with known vulnerabilities
9. **Insufficient Logging**: Inadequate security event logging
10. **Server-Side Request Forgery (SSRF)**: Unvalidated server-side requests`,
  tags: ["nodejs", "express", "javascript", "backend", "security", "api", "web"]
};

export default nodejsSecurity;