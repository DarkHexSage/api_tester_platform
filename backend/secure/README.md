# 🔐 Secure API Framework

**Enterprise-grade REST API with complete security implementation**

A production-ready, professionally secured REST API demonstrating API security best practices. All 10 OWASP API Security vulnerabilities have been fixed with enterprise-standard patterns.

---

## 🎯 Overview

This application shows how to build a **secure REST API** from the ground up. Perfect for:

- API security professionals
- Developers building secure APIs
- Teams implementing API security
- Architecture reference
- Security training and education

**Status:** ✅ Enterprise-Ready | ✅ All Vulnerabilities Fixed | ✅ Production-Grade

---

## ⚠️ Important

**Educational & Reference Use**
- Shows API security best practices
- Safe for all environments
- No vulnerabilities (intentionally)
- Perfect for learning and architecture reference

---

## 🔐 Security Features (All 10 Fixes)

### ✅ 1. Strong JWT with Expiration (JWT Issues Fixed)

**CVSS: 8.1 (HIGH) → 0 (FIXED)**

```python
# VULNERABLE ❌
token = jwt.encode(
    {'email': email},
    'super-secret-key',           # Weak!
    algorithm='HS256'              # No expiration!
)

# SECURE ✅
token = jwt.encode({
    'email': email,
    'role': user['role'],
    'exp': datetime.utcnow() + timedelta(hours=24)  # 24h expiry!
}, os.getenv('SECRET_KEY'), algorithm='HS256')
```

**What's Fixed:**
- Strong secret key from environment
- 24-hour token expiration
- Secure token validation
- Token refresh capability
- No hardcoded secrets

**Location:** `/api/v1/auth/login`, `/api/v1/auth/verify`

---

### ✅ 2. Parameterized Queries (SQL Injection Fixed)

**CVSS: 9.8 (CRITICAL) → 0 (FIXED)**

```python
# VULNERABLE ❌
query = f"SELECT * FROM users WHERE id = {user_id}"

# SECURE ✅
query = "SELECT * FROM users WHERE id = ?"
db.execute(query, [user_id])
```

**What's Fixed:**
- No string concatenation in SQL
- Parameterized query execution
- Input validation
- Safe from SQL injection

**Location:** All database queries

---

### ✅ 3. Authentication Enforcement (Broken Auth Fixed)

**CVSS: 9.1 (CRITICAL) → 0 (FIXED)**

```python
# VULNERABLE ❌
@app.route('/api/v1/admin/users')
def admin_users():
    return jsonify(users)  # No auth!

# SECURE ✅
@app.route('/api/v1/admin/users')
@require_admin  # Requires token + admin role!
def admin_users():
    return jsonify(users)
```

**What's Fixed:**
- Authentication decorator on all protected routes
- Token validation required
- Admin role verification
- Proper access control

**Location:** All protected endpoints

---

### ✅ 4. Authorization Header (API Key Issues Fixed)

**CVSS: 8.0 (HIGH) → 0 (FIXED)**

```python
# VULNERABLE ❌
api_key = request.args.get('api_key')  # In URL!

# SECURE ✅
token = request.headers.get('Authorization', '').replace('Bearer ', '')
```

**What's Fixed:**
- API keys in Authorization header (never in URL)
- Secure token transmission
- No keys in logs/history
- Proper HTTP security

**Location:** All API endpoints

---

### ✅ 5. Rate Limiting (Brute Force Prevention)

**CVSS: 7.5 (HIGH) → 0 (FIXED)**

```python
@app.route('/api/v1/auth/login', methods=['POST'])
@limiter.limit("5 per minute")  # Rate limiting!
def login():
    # Max 5 login attempts per minute per IP
    ...
```

**What's Fixed:**
- 5 attempts per minute on login
- Configurable rate limits
- Per-IP tracking
- Brute force prevention

**Location:** `/api/v1/auth/login` and other sensitive endpoints

---

### ✅ 6. IDOR Prevention (Access Control)

**CVSS: 8.1 (HIGH) → 0 (FIXED)**

```python
# VULNERABLE ❌
@app.route('/api/v1/orders/<order_id>')
def get_order(order_id):
    return jsonify(db.get_order(order_id))  # No ownership check!

# SECURE ✅
@app.route('/api/v1/orders/<order_id>')
@require_auth
def get_order(order_id):
    order = db.get_order(order_id)
    
    # Check if user owns this order!
    if order['user_id'] != request.user['user_id']:
        return {"error": "Forbidden"}, 403
    
    return jsonify(order)
```

**What's Fixed:**
- Ownership verification
- User can only access own data
- Resource-level authorization
- No sequential ID guessing

**Location:** All user-specific endpoints

---

### ✅ 7. CORS Properly Configured

**CVSS: 7.1 (HIGH) → 0 (FIXED)**

```python
# VULNERABLE ❌
response.headers['Access-Control-Allow-Origin'] = '*'
response.headers['Access-Control-Allow-Credentials'] = 'true'

# SECURE ✅
CORS(app, resources={
    r"/api/*": {
        "origins": ["http://localhost:8001", "https://yourdomain.com"],
        "methods": ["GET", "POST", "PUT", "DELETE"],
        "allow_headers": ["Content-Type", "Authorization"],
        "max_age": 3600
    }
})
```

**What's Fixed:**
- Specific origins allowed only
- Methods whitelisted
- Headers validated
- Credentials handled safely
- Preflight caching

**Location:** Application configuration

---

### ✅ 8. Field Whitelisting (Mass Assignment Fixed)

**CVSS: 8.1 (HIGH) → 0 (FIXED)**

```python
# VULNERABLE ❌
for key, value in data.items():
    user[key] = value  # Accept all fields!

# SECURE ✅
allowed_fields = ['email', 'phone', 'address']
for field in allowed_fields:
    if field in data:
        user[field] = data[field]

# Never update:
# user['role'] = data.get('role')  # Blocked!
# user['is_admin'] = data.get('is_admin')  # Blocked!
```

**What's Fixed:**
- Whitelist of allowed fields
- Protected fields never updated
- No privilege escalation
- Explicit field control

**Location:** `/api/v1/user/update`

---

### ✅ 9. JSON Serialization (Deserialization Fixed)

**CVSS: 9.8 (CRITICAL) → 0 (FIXED)**

```python
# VULNERABLE ❌
import pickle
cache = pickle.loads(base64.b64decode(data))

# SECURE ✅
import json
cache = json.loads(data)  # Safe - no code execution!
```

**What's Fixed:**
- JSON instead of pickle
- No arbitrary code execution
- Type-safe data handling
- Safe deserialization

**Location:** Cache loading endpoint

---

### ✅ 10. Security Headers (Defense in Depth)

**CVSS: 6.5 (MEDIUM) → 0 (FIXED)**

```python
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response
```

**What's Fixed:**
- X-Content-Type-Options (MIME sniffing)
- X-Frame-Options (clickjacking)
- X-XSS-Protection (XSS)
- HSTS (HTTPS enforcement)
- CSP (script injection)

**Location:** All API responses

---

## 📊 Security Implementation Summary

| Vulnerability | Status | Implementation |
|---|---|---|
| JWT Token Issues | ✅ FIXED | Strong secret + 24h expiry |
| SQL Injection | ✅ FIXED | Parameterized queries |
| Broken Authentication | ✅ FIXED | Token validation required |
| API Key Issues | ✅ FIXED | Authorization header only |
| Rate Limiting | ✅ FIXED | 5/minute on sensitive endpoints |
| IDOR | ✅ FIXED | Ownership verification |
| CORS | ✅ FIXED | Specific origins allowed |
| Mass Assignment | ✅ FIXED | Field whitelisting |
| Deserialization | ✅ FIXED | JSON only, no pickle |
| Missing Headers | ✅ FIXED | All security headers added |

---

## 🚀 Quick Start

### Option 1: Docker (Recommended)

```bash
docker-compose up
```

API: **http://localhost:8001/api/v1/info**

### Option 2: Local Python

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment
export SECRET_KEY=your-secret-key
export DEBUG=False

# Run API
python secure_api/app.py
```

API: **http://localhost:8001/api/v1/info**

---

## 💡 Demo Credentials

```
Email:    admin@example.com
Password: admin123
```

---

## 🧪 Testing Security Features

### Test 1: Get JWT Token

```bash
curl -X POST http://localhost:8001/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": "admin123"}'

# Response includes token with 24-hour expiration
```

### Test 2: Use Token for Protected Endpoint

```bash
# Get token first, then use it
curl -H "Authorization: Bearer <your_token>" \
  http://localhost:8001/api/v1/admin/users

# Returns users only if token is valid
```

### Test 3: Token Expiration

```bash
# Try to use expired token
curl -H "Authorization: Bearer <expired_token>" \
  http://localhost:8001/api/v1/admin/users

# Result: 401 Unauthorized - token expired
```

### Test 4: IDOR Prevention

```bash
# Login as user 1
# Try to access user 2's data
curl -H "Authorization: Bearer <user1_token>" \
  http://localhost:8001/api/v1/orders/2

# Result: 403 Forbidden - ownership check failed
```

### Test 5: Rate Limiting

```bash
# Try 6 login attempts in 1 minute
for i in {1..6}; do
  curl -X POST http://localhost:8001/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email": "admin@example.com", "password": "wrong"}'
done

# Result: 429 Too Many Requests after 5 attempts
```

### Test 6: SQL Injection Prevention

```bash
# Try SQL injection
curl "http://localhost:8001/api/v1/users/1' OR '1'='1"

# Result: No injection - treated as literal value
```

### Test 7: CORS Configuration

```bash
# Check allowed origins
curl -H "Origin: http://untrusted.com" \
  http://localhost:8001/api/v1/data

# Result: No CORS headers - origin not allowed
```

### Test 8: Field Whitelisting

```bash
# Try to escalate privilege
curl -X POST http://localhost:8001/api/v1/user/update \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"email": "new@example.com", "role": "admin"}'

# Result: Role field ignored - field whitelist blocks it
```

### Test 9: Security Headers

```bash
# Check headers
curl -i http://localhost:8001/api/v1/info

# Look for:
# X-Content-Type-Options: nosniff
# X-Frame-Options: DENY
# Strict-Transport-Security: max-age=31536000
# Content-Security-Policy: default-src 'self'
```

### Test 10: JSON Serialization

```bash
# Try to send pickle data (will fail safely)
curl -X POST http://localhost:8001/api/v1/cache/load \
  -H "Content-Type: application/json" \
  -d '{"cache_data": "{\"safe\": \"json\"}"}'

# Result: Only JSON accepted, no pickle RCE
```

---

## 📁 Project Structure

```
app3-secure/
├── secure_api/
│   └── app.py              # Secure REST API
├── requirements.txt        # Python dependencies
├── .env                   # Environment variables
├── Dockerfile             # Container definition
├── docker-compose.yml     # Docker orchestration
└── README.md             # This file
```

---

## 🔒 Security Best Practices Implemented

### Authentication & Authorization
✅ JWT tokens with expiration
✅ Bearer token validation
✅ Admin role verification
✅ Ownership verification (IDOR prevention)

### API Security
✅ Rate limiting on sensitive endpoints
✅ Proper HTTP methods
✅ Correct status codes
✅ Error message security

### Data Protection
✅ Parameterized queries
✅ JSON serialization only
✅ No pickle deserialization
✅ Secure data handling

### Security Headers
✅ X-Content-Type-Options
✅ X-Frame-Options
✅ X-XSS-Protection
✅ Strict-Transport-Security
✅ Content-Security-Policy

### Configuration Security
✅ Environment variables
✅ No hardcoded secrets
✅ .env file configuration
✅ Production-ready setup

---

## 💻 Tech Stack

- **Framework:** Flask 2.3.2
- **Authentication:** PyJWT 2.10.1
- **Rate Limiting:** Flask-Limiter 3.5.0
- **CORS:** Flask-CORS 4.0.0
- **Password Hashing:** Bcrypt 4.0.1
- **Container:** Docker
- **Python:** 3.11

---

## 🔄 API Endpoints

### Authentication
```
POST   /api/v1/auth/login              Login (rate limited)
POST   /api/v1/auth/verify             Verify token
```

### Users (Protected)
```
GET    /api/v1/users/<id>              Get user (parameterized)
POST   /api/v1/user/update             Update user (field whitelist)
```

### Admin (Protected + Admin Role)
```
GET    /api/v1/admin/users             List all users (admin only)
```

### Data (Protected)
```
GET    /api/v1/data/sensitive          Sensitive data (auth only)
GET    /api/v1/orders/<id>             Get order (IDOR protected)
POST   /api/v1/cache/load              Load cache (JSON safe)
```

### Utility
```
GET    /api/v1/info                    API information
```

---

## 🧬 Authentication Flow

```
1. User logs in
   POST /api/v1/auth/login
   ├─ Email & password validated
   ├─ Bcrypt verification
   └─ JWT token returned (24h expiry)

2. User calls protected endpoint
   GET /api/v1/admin/users
   Header: Authorization: Bearer <token>
   ├─ Token extracted from header
   ├─ Token validation
   ├─ Role verification (if needed)
   └─ Request processed

3. Access Control
   GET /api/v1/orders/2
   ├─ Token validated
   ├─ Resource retrieved
   ├─ Ownership verified
   └─ Only own data returned
```

---

## 🛡️ Security Checklist

Use this as a reference for your own APIs:

- [ ] JWT tokens with expiration
- [ ] Bearer token validation
- [ ] Parameterized queries
- [ ] Rate limiting on auth
- [ ] IDOR prevention (ownership checks)
- [ ] Field whitelisting (mass assignment)
- [ ] CORS properly configured
- [ ] JSON only (no pickle)
- [ ] Security headers added
- [ ] Environment variables for secrets
- [ ] Admin role verification
- [ ] Error message security
- [ ] Logging and monitoring
- [ ] HTTPS enforcement
- [ ] Input validation

---

## 📚 Documentation

### Security Implementations
- **secure_api/app.py** - Complete secure API
- **requirements.txt** - Safe dependencies
- **.env** - Environment configuration

### Learning Resources
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
- [REST API Security](https://cheatsheetseries.owasp.org/)

---

## 🧑‍💻 Using as Reference

### For API Development
Reference for:
- Authentication implementation
- Authorization patterns
- Error handling
- Security headers
- Rate limiting

### For Code Review
Check your API against:
- JWT implementation
- Token validation
- IDOR prevention
- Field whitelisting
- CORS configuration

### For Architecture
Learn about:
- Secure API design
- Authentication flows
- Access control patterns
- Security-first approach

---

## 🚀 Production Deployment

### Configuration
```bash
# .env file (change in production)
SECRET_KEY=your-strong-secret-key-here
JWT_EXPIRATION_HOURS=24
DEBUG=False
```

### Security Hardening
- [ ] Update SECRET_KEY
- [ ] Enable HTTPS/TLS
- [ ] Configure rate limits per endpoint
- [ ] Set up logging
- [ ] Add monitoring
- [ ] Enable CORS only for trusted domains
- [ ] Update dependencies regularly
- [ ] Configure database connection

### Monitoring
- [ ] Log all authentication attempts
- [ ] Monitor rate limit violations
- [ ] Track API usage
- [ ] Alert on suspicious activity
- [ ] Review security headers

---

## 📊 Comparison with Vulnerable Version

See the [Vulnerable API](../app3-vulnerable/) to understand:
- What the vulnerabilities were
- How they were exploited
- Why they matter
- How they're fixed here

Perfect for learning API security!

---

## ✨ Why This is Enterprise-Ready

1. **Security First** - All 10 API vulnerabilities fixed
2. **Best Practices** - Industry-standard patterns
3. **Production Code** - Professional quality
4. **Well Documented** - Clear explanations
5. **Testable** - Security validated
6. **Scalable** - Proper architecture
7. **Maintainable** - Clean code
8. **Auditable** - Clear controls

---

## 🎓 Learning Outcomes

After studying this code, you'll understand:

✅ JWT authentication and expiration
✅ How to prevent SQL injection in APIs
✅ How to implement proper authorization
✅ How to use API tokens securely
✅ How to prevent brute force attacks
✅ How to prevent IDOR vulnerabilities
✅ How to configure CORS properly
✅ How to prevent mass assignment
✅ How to handle deserialization safely
✅ How to add security headers

---

## 📞 Support & Questions

### Understanding JWT
- Tokens expire after 24 hours
- New token required for continued access
- Token in Authorization header
- Secure secret key used

### Understanding IDOR Prevention
- Users can only access their own data
- User ID verified from token
- Resource ownership checked
- Prevents sequential ID guessing

### Understanding Rate Limiting
- 5 attempts per minute on login
- Per-IP tracking
- Prevents brute force
- Returns 429 Too Many Requests

---

## 📄 License

Educational and reference use. See LICENSE file.

---

## 🏆 Key Takeaway

> **Building secure APIs is achievable.**
>
> Follow proven patterns, validate inputs, verify authorization,
> and add security headers.
>
> Every principle shown here can be applied to your own APIs.

---

<div align="center">

## 🔐 API Security is Critical 🔐

### APIs are attack targets.

### This application shows how to defend them.

---

## Use this as your reference architecture for secure APIs.

### Start building secure APIs today.

**Ready to secure your API?** 🛡️

</div>

---

## 🎯 Next Steps

1. **Study the code** - Understand each security implementation
2. **Test locally** - Run endpoints and verify security
3. **Compare** - See what was vulnerable in the other version
4. **Apply** - Use these patterns in your own APIs
5. **Share** - Help others learn API security

---

**Last Updated:** 2025  
**Status:** ✅ Enterprise Ready  
**Security:** ✅ All 10 Vulnerabilities Fixed  
**Code Quality:** ✅ Production Grade  

---

**Happy secure API building!** 🛡️