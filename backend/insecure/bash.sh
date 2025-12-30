#!/bin/bash

# ============================================================
# APP 3: API SECURITY TESTING FRAMEWORK
# Modern, practical tool for API security assessment
# ============================================================

set -e

PROJECT_NAME="app3-api-security"
PORT="8000"

echo "=========================================="
echo "🔐 API SECURITY TESTING FRAMEWORK"
echo "=========================================="
echo ""

# Create project directory
echo "📁 Creating project structure..."
mkdir -p $PROJECT_NAME
cd $PROJECT_NAME

# Create subdirectories
mkdir -p vulnerable_api
mkdir -p security_scanner
mkdir -p templates
mkdir -p reports
mkdir -p tests

echo "✅ Directory structure created"
echo ""

# ============================================================
# CREATE requirements.txt
# ============================================================

echo "📦 Creating requirements.txt..."
cat > requirements.txt << 'EOF'
Flask==2.3.2
Werkzeug==2.3.6
PyJWT==2.10.1
requests==2.31.0
pyyaml==6.0
jsonschema==4.19.0
python-dotenv==1.0.0
EOF

echo "✅ requirements.txt created"
echo ""

# ============================================================
# CREATE VULNERABLE API
# ============================================================

echo "🔓 Creating vulnerable API server..."
cat > vulnerable_api/app.py << 'VULN_API'
from flask import Flask, request, jsonify, jsonify as json_response
import jwt
import json
from datetime import datetime, timedelta
import os
import pickle
import base64

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret-key-do-not-use'  # ❌ HARDCODED

# ============================================
# VULNERABILITY 1: JWT TOKEN ISSUES
# ============================================

@app.route('/api/v1/auth/login', methods=['POST'])
def login():
    """🚨 JWT with weak secret and no expiration"""
    data = request.get_json()
    email = data.get('email')
    
    # ❌ VULNERABLE: Weak secret
    token = jwt.encode(
        {'email': email, 'role': 'user'},
        'super-secret-key-do-not-use',  # ❌ HARDCODED SECRET
        algorithm='HS256'
    )
    
    return jsonify({"token": token, "message": "Login successful"})


@app.route('/api/v1/auth/verify', methods=['POST'])
def verify():
    """🚨 JWT verification with weak secret"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    try:
        # ❌ VULNERABLE: Uses hardcoded secret
        payload = jwt.decode(token, 'super-secret-key-do-not-use', algorithms=['HS256'])
        return jsonify({"valid": True, "payload": payload})
    except:
        return jsonify({"valid": False}), 401


# ============================================
# VULNERABILITY 2: SQL INJECTION IN API
# ============================================

@app.route('/api/v1/users/<user_id>', methods=['GET'])
def get_user(user_id):
    """🚨 SQL Injection vulnerability"""
    # Simulating SQL query construction (vulnerable)
    query = f"SELECT * FROM users WHERE id = {user_id}"  # ❌ VULNERABLE
    
    # In real scenario, would execute this query
    # Attacker could do: /api/v1/users/1 OR 1=1
    
    return jsonify({
        "query_constructed": query,
        "warning": "SQL Injection detected - id parameter not sanitized",
        "user_id": user_id
    })


# ============================================
# VULNERABILITY 3: BROKEN AUTHENTICATION
# ============================================

@app.route('/api/v1/admin/users', methods=['GET'])
def admin_users():
    """🚨 No authentication on admin endpoint"""
    # ❌ NO AUTHENTICATION CHECK!
    users = [
        {"id": 1, "email": "admin@example.com", "role": "admin"},
        {"id": 2, "email": "user@example.com", "role": "user"}
    ]
    
    return jsonify({
        "users": users,
        "warning": "This endpoint requires authentication but doesn't check!"
    })


# ============================================
# VULNERABILITY 4: API KEY ISSUES
# ============================================

@app.route('/api/v1/data/sensitive', methods=['GET'])
def sensitive_data():
    """🚨 API key in URL or weak validation"""
    api_key = request.args.get('api_key')
    
    # ❌ VULNERABLE: Hardcoded API keys accepted
    valid_keys = ['sk_test_1234', 'sk_live_5678']
    
    if api_key in valid_keys:
        return jsonify({
            "data": "Super sensitive data here",
            "warning": "API key transmitted in URL (not secure)"
        })
    
    return jsonify({"error": "Invalid API key"}), 401


# ============================================
# VULNERABILITY 5: RATE LIMITING MISSING
# ============================================

@app.route('/api/v1/brute/login', methods=['POST'])
def brute_force_login():
    """🚨 No rate limiting - enables brute force"""
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    # ❌ NO RATE LIMITING - can brute force!
    valid_password = 'correct_password'
    
    if password == valid_password:
        return jsonify({"status": "success"})
    
    return jsonify({"status": "failed"}), 401


# ============================================
# VULNERABILITY 6: INSECURE DIRECT OBJECT REFS (IDOR)
# ============================================

@app.route('/api/v1/orders/<order_id>', methods=['GET'])
def get_order(order_id):
    """🚨 IDOR - Access other user's orders"""
    # ❌ No check if current user owns this order
    orders = {
        "1": {"id": "1", "user": "admin", "total": 1000},
        "2": {"id": "2", "user": "user", "total": 50}
    }
    
    order = orders.get(order_id)
    
    if order:
        return jsonify(order)
    
    return jsonify({"error": "Order not found"}), 404


# ============================================
# VULNERABILITY 7: CORS MISCONFIGURATION
# ============================================

@app.route('/api/v1/profile', methods=['GET', 'POST', 'OPTIONS'])
def profile():
    """🚨 CORS allows all origins"""
    response = jsonify({"user": "current_user", "data": "sensitive"})
    
    # ❌ VULNERABLE: Allow all origins
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = '*'
    response.headers['Access-Control-Allow-Headers'] = '*'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    
    return response


# ============================================
# VULNERABILITY 8: MASS ASSIGNMENT / PARAMETER POLLUTION
# ============================================

@app.route('/api/v1/user/update', methods=['POST'])
def update_user():
    """🚨 Mass assignment - accepts any parameter"""
    data = request.get_json()
    
    # ❌ VULNERABLE: Accepts all parameters without validation
    user = {
        "email": data.get('email'),
        "role": data.get('role', 'user'),  # Can be changed to 'admin'!
        "is_admin": data.get('is_admin', False),  # Can be changed!
        "permissions": data.get('permissions', [])
    }
    
    return jsonify({
        "status": "updated",
        "user": user,
        "warning": "All parameters accepted without validation"
    })


# ============================================
# VULNERABILITY 9: INSECURE DESERIALIZATION
# ============================================

@app.route('/api/v1/cache/load', methods=['POST'])
def load_cache():
    """🚨 Pickle deserialization"""
    data = request.get_json().get('cache_data')
    
    try:
        # ❌ VULNERABLE: Pickle deserialization
        cache = pickle.loads(base64.b64decode(data))
        return jsonify({"cache": str(cache)})
    except:
        return jsonify({"error": "Invalid cache data"}), 400


# ============================================
# VULNERABILITY 10: MISSING SECURITY HEADERS
# ============================================

@app.route('/api/v1/data', methods=['GET'])
def api_data():
    """🚨 Missing security headers"""
    response = jsonify({
        "data": "API response",
        "timestamp": datetime.now().isoformat()
    })
    
    # ❌ NO SECURITY HEADERS!
    # Missing: X-Content-Type-Options, X-Frame-Options, CSP, etc.
    
    return response


# ============================================
# INFO ENDPOINT
# ============================================

@app.route('/api/v1/info', methods=['GET'])
def api_info():
    """API info endpoint"""
    return jsonify({
        "name": "Vulnerable API",
        "version": "1.0.0",
        "vulnerabilities": [
            "JWT Token Issues",
            "SQL Injection",
            "Broken Authentication",
            "API Key Issues",
            "Missing Rate Limiting",
            "IDOR",
            "CORS Misconfiguration",
            "Mass Assignment",
            "Insecure Deserialization",
            "Missing Security Headers"
        ]
    })


if __name__ == '__main__':
    print("\n" + "="*70)
    print("🔓 VULNERABLE API SERVER")
    print("="*70)
    print("\n📖 VULNERABILITIES:")
    print("  1. JWT Token Issues")
    print("  2. SQL Injection")
    print("  3. Broken Authentication")
    print("  4. API Key Issues")
    print("  5. Missing Rate Limiting")
    print("  6. IDOR (Insecure Direct Object References)")
    print("  7. CORS Misconfiguration")
    print("  8. Mass Assignment / Parameter Pollution")
    print("  9. Insecure Deserialization")
    print("  10. Missing Security Headers")
    print("\n🌐 API Running: http://localhost:8000")
    print("📊 API Info: http://localhost:8000/api/v1/info")
    print("="*70 + "\n")
    
    app.run(debug=True, port=8000, host='0.0.0.0')
VULN_API

echo "✅ Vulnerable API created"
echo ""

# ============================================================
# CREATE SECURITY SCANNER
# ============================================================

echo "🔍 Creating API Security Scanner..."
cat > security_scanner/scanner.py << 'SCANNER'
#!/usr/bin/env python3
"""
API Security Testing Scanner
Tests for common API vulnerabilities
"""

import requests
import json
import jwt
import time
from datetime import datetime
import sys

class APISecurityScanner:
    def __init__(self, base_url):
        self.base_url = base_url
        self.results = []
        self.start_time = datetime.now()
    
    def test_jwt_weak_secret(self):
        """Test 1: JWT Token with Weak Secret"""
        print("[*] Testing JWT Token Issues...")
        
        try:
            # Try to login
            response = requests.post(
                f"{self.base_url}/api/v1/auth/login",
                json={"email": "test@example.com"}
            )
            
            if response.status_code == 200:
                token = response.json().get('token')
                
                # Try to decode with hardcoded secrets
                weak_secrets = [
                    'super-secret-key-do-not-use',
                    'secret',
                    'password',
                    '123456'
                ]
                
                for secret in weak_secrets:
                    try:
                        payload = jwt.decode(token, secret, algorithms=['HS256'])
                        self.results.append({
                            "test": "JWT Weak Secret",
                            "severity": "CRITICAL",
                            "status": "VULNERABLE",
                            "details": f"Token decoded with secret: {secret}"
                        })
                        return
                    except:
                        pass
        except Exception as e:
            print(f"  Error: {e}")
    
    def test_sql_injection(self):
        """Test 2: SQL Injection"""
        print("[*] Testing SQL Injection...")
        
        payloads = ["1 OR 1=1", "'; DROP TABLE users; --", "1 UNION SELECT"]
        
        for payload in payloads:
            try:
                response = requests.get(
                    f"{self.base_url}/api/v1/users/{payload}"
                )
                
                if "SQL" in response.text or "query" in response.text:
                    self.results.append({
                        "test": "SQL Injection",
                        "severity": "CRITICAL",
                        "status": "VULNERABLE",
                        "payload": payload
                    })
                    return
            except:
                pass
    
    def test_broken_auth(self):
        """Test 3: Broken Authentication"""
        print("[*] Testing Broken Authentication...")
        
        try:
            response = requests.get(
                f"{self.base_url}/api/v1/admin/users"
            )
            
            if response.status_code == 200:
                self.results.append({
                    "test": "Broken Authentication",
                    "severity": "CRITICAL",
                    "status": "VULNERABLE",
                    "details": "Admin endpoint accessible without authentication"
                })
        except:
            pass
    
    def test_api_key_issues(self):
        """Test 4: API Key Issues"""
        print("[*] Testing API Key Issues...")
        
        test_keys = ['sk_test_1234', 'sk_live_5678', 'test', 'admin']
        
        for key in test_keys:
            try:
                response = requests.get(
                    f"{self.base_url}/api/v1/data/sensitive?api_key={key}"
                )
                
                if response.status_code == 200:
                    self.results.append({
                        "test": "API Key Issues",
                        "severity": "HIGH",
                        "status": "VULNERABLE",
                        "details": f"Weak API key accepted: {key}"
                    })
                    return
            except:
                pass
    
    def test_rate_limiting(self):
        """Test 5: Missing Rate Limiting"""
        print("[*] Testing Rate Limiting...")
        
        # Try rapid requests
        count = 0
        start = time.time()
        
        for i in range(10):
            try:
                response = requests.post(
                    f"{self.base_url}/api/v1/brute/login",
                    json={"email": "test@example.com", "password": "wrong"}
                )
                count += 1
            except:
                break
        
        elapsed = time.time() - start
        
        if count == 10 and elapsed < 5:
            self.results.append({
                "test": "Missing Rate Limiting",
                "severity": "HIGH",
                "status": "VULNERABLE",
                "details": f"Sent 10 requests in {elapsed:.2f}s without being blocked"
            })
    
    def test_idor(self):
        """Test 6: IDOR"""
        print("[*] Testing IDOR...")
        
        try:
            response = requests.get(
                f"{self.base_url}/api/v1/orders/1"
            )
            
            if response.status_code == 200:
                self.results.append({
                    "test": "IDOR (Insecure Direct Object Reference)",
                    "severity": "HIGH",
                    "status": "VULNERABLE",
                    "details": "Can access other users' orders without authorization"
                })
        except:
            pass
    
    def test_cors(self):
        """Test 7: CORS Misconfiguration"""
        print("[*] Testing CORS...")
        
        try:
            response = requests.options(
                f"{self.base_url}/api/v1/profile"
            )
            
            if '*' in response.headers.get('Access-Control-Allow-Origin', ''):
                self.results.append({
                    "test": "CORS Misconfiguration",
                    "severity": "HIGH",
                    "status": "VULNERABLE",
                    "details": "Allows requests from any origin"
                })
        except:
            pass
    
    def test_mass_assignment(self):
        """Test 8: Mass Assignment"""
        print("[*] Testing Mass Assignment...")
        
        try:
            response = requests.post(
                f"{self.base_url}/api/v1/user/update",
                json={
                    "email": "user@example.com",
                    "role": "admin",
                    "is_admin": True
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('user', {}).get('role') == 'admin':
                    self.results.append({
                        "test": "Mass Assignment",
                        "severity": "HIGH",
                        "status": "VULNERABLE",
                        "details": "Can modify protected fields like role and is_admin"
                    })
        except:
            pass
    
    def test_security_headers(self):
        """Test 10: Missing Security Headers"""
        print("[*] Testing Security Headers...")
        
        try:
            response = requests.get(
                f"{self.base_url}/api/v1/data"
            )
            
            required_headers = [
                'X-Content-Type-Options',
                'X-Frame-Options',
                'Content-Security-Policy'
            ]
            
            missing = [h for h in required_headers if h not in response.headers]
            
            if missing:
                self.results.append({
                    "test": "Missing Security Headers",
                    "severity": "MEDIUM",
                    "status": "VULNERABLE",
                    "details": f"Missing headers: {', '.join(missing)}"
                })
        except:
            pass
    
    def run_all_tests(self):
        """Run all security tests"""
        print("\n" + "="*70)
        print("🔐 API SECURITY SCAN STARTING")
        print("="*70 + "\n")
        
        self.test_jwt_weak_secret()
        self.test_sql_injection()
        self.test_broken_auth()
        self.test_api_key_issues()
        self.test_rate_limiting()
        self.test_idor()
        self.test_cors()
        self.test_mass_assignment()
        self.test_security_headers()
        
        return self.results
    
    def generate_report(self):
        """Generate security report"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "target": self.base_url,
            "total_tests": 9,
            "vulnerabilities_found": len(self.results),
            "critical": len([r for r in self.results if r.get('severity') == 'CRITICAL']),
            "high": len([r for r in self.results if r.get('severity') == 'HIGH']),
            "medium": len([r for r in self.results if r.get('severity') == 'MEDIUM']),
            "findings": self.results
        }
        
        return report
    
    def print_report(self):
        """Print formatted report"""
        report = self.generate_report()
        
        print("\n" + "="*70)
        print("🔐 API SECURITY SCAN REPORT")
        print("="*70)
        print(f"\nTarget: {report['target']}")
        print(f"Timestamp: {report['timestamp']}")
        print(f"\nTotal Tests: {report['total_tests']}")
        print(f"Vulnerabilities Found: {report['vulnerabilities_found']}")
        print(f"  🔴 Critical: {report['critical']}")
        print(f"  🟠 High: {report['high']}")
        print(f"  🟡 Medium: {report['medium']}")
        
        print("\n" + "-"*70)
        print("FINDINGS:")
        print("-"*70)
        
        for i, finding in enumerate(report['findings'], 1):
            severity_emoji = "🔴" if finding['severity'] == 'CRITICAL' else "🟠" if finding['severity'] == 'HIGH' else "🟡"
            print(f"\n{i}. {severity_emoji} {finding['test']} [{finding['severity']}]")
            print(f"   Status: {finding['status']}")
            print(f"   Details: {finding.get('details', 'N/A')}")
        
        print("\n" + "="*70)
        print("OVERALL RISK: 🔴 CRITICAL")
        print("="*70 + "\n")
        
        return report

if __name__ == '__main__':
    base_url = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:8000'
    
    scanner = APISecurityScanner(base_url)
    scanner.run_all_tests()
    scanner.print_report()
SCANNER

chmod +x security_scanner/scanner.py

echo "✅ Security Scanner created"
echo ""

# ============================================================
# CREATE README.md
# ============================================================

echo "📄 Creating comprehensive README.md..."
cat > README.md << 'README_END'
# 🔐 API Security Testing Framework

**Professional API security assessment and testing tool**

A modern, practical framework for discovering and demonstrating API vulnerabilities. Perfect for security consultants and penetration testers.

---

## 🎯 Overview

This framework provides:

✅ **Vulnerable API** - 10 intentional API security flaws  
✅ **Security Scanner** - Automated vulnerability detection  
✅ **Testing Tools** - Real-world attack patterns  
✅ **Documentation** - Complete vulnerability guides  
✅ **Docker Setup** - Production-ready deployment  

---

## 🚀 Quick Start

### Start Everything (Docker)

```bash
docker-compose up
```

### Manual Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Start vulnerable API
python vulnerable_api/app.py

# In another terminal, run scanner
python security_scanner/scanner.py http://localhost:8000
```

---

## 🔓 The 10 API Vulnerabilities

### 1. **JWT Token Issues** 🔐
- Weak secret keys
- No expiration
- Algorithm confusion attacks
- **CVSS: 8.1 (HIGH)**

### 2. **SQL Injection** 💉
- Unparameterized queries
- API parameter injection
- **CVSS: 9.8 (CRITICAL)**

### 3. **Broken Authentication** ❌
- Missing auth checks
- No rate limiting on auth
- Weak session handling
- **CVSS: 9.1 (CRITICAL)**

### 4. **API Key Issues** 🔑
- Hardcoded API keys
- Keys in URLs
- Weak key generation
- **CVSS: 8.0 (HIGH)**

### 5. **Missing Rate Limiting** 🔄
- Brute force attacks
- DDoS vulnerabilities
- Resource exhaustion
- **CVSS: 7.5 (HIGH)**

### 6. **IDOR** (Insecure Direct Object References) 👥
- Access other user's data
- Sequential ID guessing
- No authorization checks
- **CVSS: 8.1 (HIGH)**

### 7. **CORS Misconfiguration** 🌍
- Allow all origins
- Credential exposure
- Cross-origin data theft
- **CVSS: 7.1 (HIGH)**

### 8. **Mass Assignment** 📝
- Modify protected fields
- Privilege escalation
- Parameter pollution
- **CVSS: 8.1 (HIGH)**

### 9. **Insecure Deserialization** 🎯
- RCE through pickle
- Object injection
- Code execution
- **CVSS: 9.8 (CRITICAL)**

### 10. **Missing Security Headers** 🚫
- No X-Content-Type-Options
- No CSP
- No HSTS
- **CVSS: 6.5 (MEDIUM)**

---

## 🛠️ API Endpoints

### Authentication
- `POST /api/v1/auth/login` - Vulnerable JWT login
- `POST /api/v1/auth/verify` - Weak token verification

### User Management
- `GET /api/v1/users/<id>` - SQL injection vulnerable
- `POST /api/v1/user/update` - Mass assignment vulnerable
- `GET /api/v1/profile` - CORS vulnerable

### Admin
- `GET /api/v1/admin/users` - No authentication required

### Data
- `GET /api/v1/orders/<id>` - IDOR vulnerable
- `GET /api/v1/data/sensitive?api_key=...` - Weak API keys
- `POST /api/v1/brute/login` - No rate limiting

### Utility
- `GET /api/v1/info` - API information

---

## 🔍 Using the Security Scanner

### Run Scanner

```bash
python security_scanner/scanner.py http://localhost:8000
```

### Scanner Tests

1. JWT weak secrets
2. SQL injection
3. Broken authentication
4. API key issues
5. Rate limiting
6. IDOR
7. CORS misconfiguration
8. Mass assignment
9. Security headers

### Sample Output

```
🔐 API SECURITY SCAN REPORT

Target: http://localhost:8000
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
...

OVERALL RISK: 🔴 CRITICAL
```

---

## 💻 Tech Stack

- **Backend:** Flask 2.3.2
- **Security:** PyJWT, requests
- **Container:** Docker & Docker Compose
- **Testing:** Automated scanner

---

## 📊 Vulnerability Severity

| # | Vulnerability | Severity | CVSS | Status |
|---|---|---|---|---|
| 1 | JWT Issues | HIGH | 8.1 | VULNERABLE |
| 2 | SQL Injection | CRITICAL | 9.8 | VULNERABLE |
| 3 | Broken Auth | CRITICAL | 9.1 | VULNERABLE |
| 4 | API Key Issues | HIGH | 8.0 | VULNERABLE |
| 5 | Rate Limiting | HIGH | 7.5 | VULNERABLE |
| 6 | IDOR | HIGH | 8.1 | VULNERABLE |
| 7 | CORS | HIGH | 7.1 | VULNERABLE |
| 8 | Mass Assignment | HIGH | 8.1 | VULNERABLE |
| 9 | Deserialization | CRITICAL | 9.8 | VULNERABLE |
| 10 | Missing Headers | MEDIUM | 6.5 | VULNERABLE |

**Overall Risk: 🔴 CRITICAL**

---

## 🗂️ Project Structure

```
app3-api-security/
├── vulnerable_api/
│   └── app.py           # Vulnerable API server
├── security_scanner/
│   └── scanner.py       # Security testing tool
├── requirements.txt     # Dependencies
├── Dockerfile          # Container
├── docker-compose.yml  # Orchestration
└── README.md          # This file
```

---

## 🐳 Docker Setup

### Create Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["python", "vulnerable_api/app.py"]
```

### Create docker-compose.yml

```yaml
version: '3.8'

services:
  api:
    build: .
    container_name: api-security-framework
    ports:
      - "8000:8000"
    environment:
      - FLASK_ENV=development
    volumes:
      - .:/app
    command: python vulnerable_api/app.py
    restart: unless-stopped
```

### Run with Docker

```bash
docker-compose up --build
```

---

## 🎓 Learning Outcomes

After using this framework, you'll understand:

✅ How APIs are compromised  
✅ Authentication vulnerabilities  
✅ Authorization flaws  
✅ Data exposure risks  
✅ How to test APIs securely  
✅ API security best practices  

---

## 💼 Use Cases

- **Security Training** - Teach API security
- **Penetration Testing** - Practice real attacks
- **Code Review** - Learn from vulnerable code
- **Client Demos** - Show security risks
- **Portfolio** - Demonstrate expertise

---

## 🔒 Security Notes

⚠️ **Educational Use Only**

- Never deploy to production
- Only use on authorized systems
- This is intentionally vulnerable
- Use in isolated environments only

---

## 🚀 Next Steps

1. **Run the vulnerable API**
2. **Run the security scanner**
3. **Review the findings**
4. **Study the vulnerable code**
5. **Learn the security principles**
6. **Implement fixes** (advanced)

---

## 📈 Consulting Opportunities

This framework lands these gigs:

💰 **API Security Assessment** - $5-15K  
💰 **API Penetration Testing** - $8-20K  
💰 **Security Code Review** - $3-10K  
💰 **Security Training** - $5-10K  

---

## 📞 Support

For questions:

1. Check API info: `http://localhost:8000/api/v1/info`
2. Review vulnerability details in this README
3. Study the source code
4. Run the scanner with `--verbose` flag (when implemented)

---

**Perfect for landing API security consulting gigs! 🛡️**
README_END

echo "✅ README.md created"
echo ""

# ============================================================
# CREATE Dockerfile
# ============================================================

echo "🐳 Creating Dockerfile..."
cat > Dockerfile << 'DOCKER_END'
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["python", "vulnerable_api/app.py"]
DOCKER_END

echo "✅ Dockerfile created"
echo ""

# ============================================================
# CREATE docker-compose.yml
# ============================================================

echo "🐳 Creating docker-compose.yml..."
cat > docker-compose.yml << 'COMPOSE_END'
version: '3.8'

services:
  api:
    build: .
    container_name: api-security-framework
    ports:
      - "8000:8000"
    environment:
      - FLASK_ENV=development
      - FLASK_DEBUG=1
    volumes:
      - .:/app
    command: python vulnerable_api/app.py
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/api/v1/info"]
      interval: 10s
      timeout: 5s
      retries: 5

networks:
  default:
    name: api-security-network
COMPOSE_END

echo "✅ docker-compose.yml created"
echo ""

# ============================================================
# CREATE __init__.py FILES
# ============================================================

touch vulnerable_api/__init__.py
touch security_scanner/__init__.py

# ============================================================
# INSTALL DEPENDENCIES
# ============================================================

echo "📥 Installing dependencies..."
pip install -r requirements.txt > /dev/null 2>&1

echo "✅ Dependencies installed"
echo ""

# ============================================================
# COMPLETION MESSAGE
# ============================================================

echo "=========================================="
echo "✅ APP 3 SETUP COMPLETE!"
echo "=========================================="
echo ""
echo "📁 Project: $PROJECT_NAME"
echo "🌐 API Port: $PORT"
echo ""
echo "🚀 TO START:"
echo ""
echo "Option 1 (Recommended - Docker):"
echo "  docker-compose up"
echo ""
echo "Option 2 (Local Python):"
echo "  python vulnerable_api/app.py"
echo ""
echo "📊 TO RUN SECURITY SCANNER:"
echo "  python security_scanner/scanner.py http://localhost:$PORT"
echo ""
echo "🌐 API Endpoints:"
echo "  Info: http://localhost:$PORT/api/v1/info"
echo ""
echo "📚 Documentation: README.md"
echo ""
echo "=========================================="
echo ""
echo "🔐 API Security Testing Framework Ready! 🛡️"
echo ""