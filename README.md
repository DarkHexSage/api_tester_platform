# 🔐 API Security Testing Suite

<div align="center">

> **Educational platform for mastering API security** — Compare secure vs insecure implementations across **10 OWASP Top vulnerabilities**

[![Python](https://img.shields.io/badge/Python-3.9%2B-3776ab?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.0%2B-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![React](https://img.shields.io/badge/React-18%2B-61dafb?style=for-the-badge&logo=react&logoColor=white)](https://react.dev/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ed?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)

[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-336791?style=for-the-badge&logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010-ff6b00?style=for-the-badge&logo=owasp&logoColor=white)](https://owasp.org/)
[![License](https://img.shields.io/badge/License-Educational-green?style=for-the-badge)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)](#)

<br>

**[Quick Start](#-quick-start)** • **[Features](#features)** • **[Endpoints](#-endpoints-overview)** • **[Testing Guide](#-real-world-testing-examples)** • **[Learn More](#-key-learnings)**

</div>

---

## ✨ Features

| Feature | Details |
|---------|---------|
| 🔄 **Dual API Mode** | Compare secure & insecure implementations side-by-side |
| 🛣️ **17 Endpoints** | Full CRUD operations with real production vulnerabilities |
| 🎯 **Real Vulnerabilities** | All 10 OWASP Top flaws demonstrated with live examples |
| 📊 **Interactive Dashboard** | Test both APIs simultaneously with live feedback |
| 🎨 **Glass UI** | Professional modern interface with real-time validation |
| 🐳 **Docker Ready** | One-command setup with docker-compose |
| 📚 **Educational** | Learn by exploiting vs defending the same endpoints |

---

## 🚀 Quick Start

### Option 1: Docker Compose (Recommended) ⭐
```bash
docker-compose up -d
```

Access the suite:
- **Dashboard:** http://localhost:5000
- **Secure API:** http://localhost:8001
- **Insecure API:** http://localhost:8000

### Option 2: Local Development

**Backend Setup:**
```bash
pip install -r requirements.txt
python app.py  # Runs on http://localhost:8001 & 8000
```

**Frontend Setup:**
```bash
cd frontend
npm install
npm start  # Runs on http://localhost:5000
```

---

## 🔐 Security Comparison Matrix

### Secure API (Port 8001) ✅

```
Authentication      │ JWT + bcrypt (24h expiration)
Authorization       │ Role-based access control
Input Validation    │ Strict (email, password strength)
SQL Injection       │ Parameterized queries
Rate Limiting       │ 5 attempts/minute
IDOR Protection     │ Ownership verification
API Keys           │ Bearer token in headers
Mass Assignment     │ Field whitelisting
CORS               │ Restricted origins
Security Headers   │ CSP, X-Frame, HSTS, etc
```

### Insecure API (Port 8000) ❌

```
Authentication      │ ❌ Weak JWT (hardcoded secret)
Authorization       │ ❌ NONE
Input Validation    │ ❌ NONE
SQL Injection       │ ❌ String concatenation
Rate Limiting       │ ❌ NONE
IDOR Protection     │ ❌ NONE
API Keys           │ ❌ URL parameters
Mass Assignment     │ ❌ All fields accepted
CORS               │ ❌ Allows all origins (*)
Security Headers   │ ❌ NONE
```

---

## 💡 Real-World Testing Examples

### Test 1: Weak Password Validation
<details>
<summary><strong>Expand to see responses</strong></summary>

**Secure API ✅**
```bash
curl -X POST http://localhost:8001/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"123"}'
```
Response: **400 Bad Request**
```json
{"error": "Password must be at least 8 characters with mixed case"}
```

**Insecure API ❌**
```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"123"}'
```
Response: **201 Created** (Password exposed in response!)
```json
{"id": 1, "email": "test@example.com", "password": "123"}
```
</details>

### Test 2: Unauthenticated User Enumeration
<details>
<summary><strong>Expand to see responses</strong></summary>

**Secure API ✅**
```bash
curl http://localhost:8001/api/v1/users
```
Response: **401 Unauthorized**
```json
{"error": "Authentication required"}
```

**Insecure API ❌**
```bash
curl http://localhost:8000/api/v1/users
```
Response: **200 OK** - ALL USERS EXPOSED!
```json
[
  {"id": 1, "email": "admin@example.com", "password": "admin123"},
  {"id": 2, "email": "user@example.com", "password": "password123"}
]
```
</details>

### Test 3: User Impersonation (Create Orders)
<details>
<summary><strong>Expand to see responses</strong></summary>

**Secure API ✅**
```bash
curl -X POST http://localhost:8001/api/v1/orders \
  -H "Authorization: Bearer <valid_token>" \
  -H "Content-Type: application/json" \
  -d '{"total":99.99,"items":["item1","item2"]}'
```
Response: **201 Created** (Order created for authenticated user only)

**Insecure API ❌**
```bash
curl -X POST http://localhost:8000/api/v1/orders \
  -H "Content-Type: application/json" \
  -d '{"user_id":999,"total":1000000,"items":["free_item"]}'
```
Response: **201 Created** (Order created as ANY user!)
```json
{"id": 100, "user_id": 999, "total": 1000000, "created_by": "attacker"}
```
</details>

### Test 4: SQL Injection
<details>
<summary><strong>Expand to see responses</strong></summary>

**Secure API ✅**
```bash
curl http://localhost:8001/api/v1/users/1%20OR%201=1
```
Response: **404 Not Found** (Safe parameterized query)

**Insecure API ❌**
```bash
curl http://localhost:8000/api/v1/users/1%20OR%201=1
```
Response: **200 OK** (Vulnerable!)
```json
[
  {"id": 1, "email": "admin@example.com"},
  {"id": 2, "email": "user@example.com"}
]
```
Raw Query: `SELECT * FROM users WHERE id = 1 OR 1=1`
</details>

### Test 5: IDOR (Insecure Direct Object Reference)
<details>
<summary><strong>Expand to see responses</strong></summary>

**Secure API ✅**
```bash
curl -H "Authorization: Bearer <user2_token>" \
     http://localhost:8001/api/v1/orders/1
```
Response: **403 Forbidden** (Ownership check enforced)

**Insecure API ❌**
```bash
curl http://localhost:8000/api/v1/orders/1
curl http://localhost:8000/api/v1/orders/2
curl http://localhost:8000/api/v1/orders/999
```
Response: **200 OK** (Returns anyone's order!)
```json
{"id": 1, "user_id": 2, "total": 500.00, "items": [...]}
```
</details>

### Test 6: Mass Assignment / Privilege Escalation
<details>
<summary><strong>Expand to see responses</strong></summary>

**Secure API ✅**
```bash
curl -X POST http://localhost:8001/api/v1/user/update \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"name":"John","role":"admin"}'
```
Response: **200 OK** (Field ignored, role stays "user")
```json
{"name": "John", "role": "user"}
```

**Insecure API ❌**
```bash
curl -X POST http://localhost:8000/api/v1/user/update \
  -H "Content-Type: application/json" \
  -d '{"name":"Hacker","role":"admin","email":"new@example.com"}'
```
Response: **200 OK** (User is now admin!)
```json
{"name": "Hacker", "role": "admin", "email": "new@example.com"}
```
</details>

### Test 7: Brute Force / No Rate Limiting
<details>
<summary><strong>Expand to see responses</strong></summary>

**Secure API ✅**
```bash
# Requests 1-5: 200 OK
# Request 6+: 429 Too Many Requests (Rate limited)
```

**Insecure API ❌**
```bash
for i in {1..100}; do
  curl -X POST http://localhost:8000/api/v1/auth/login \
    -d '{"email":"admin@example.com","password":"attempt'$i'"}'
done
# All 100 requests succeed instantly - NO RATE LIMITING!
```
</details>

---

## 🛣️ Endpoints Overview

### Secure API (8001) - 17 Protected Endpoints

```yaml
Authentication:
  POST   /api/v1/auth/register       ✅ Input validation + password hashing
  POST   /api/v1/auth/login          ✅ Secure JWT with expiration
  POST   /api/v1/auth/verify         ✅ Token validation

User Management:
  GET    /api/v1/users               ✅ Authentication required
  GET    /api/v1/users/:id           ✅ Parameterized queries
  GET    /api/v1/admin/users         ✅ Admin role enforcement
  POST   /api/v1/user/update         ✅ Field whitelisting

Data Access:
  GET    /api/v1/products            ✅ Auth required
  GET    /api/v1/data                ✅ Own data only (IDOR proof)
  GET    /api/v1/data/sensitive      ✅ Bearer token auth
  GET|POST /api/v1/profile           ✅ CORS protected

Order Management:
  GET|POST /api/v1/orders            ✅ Ownership verification
  GET    /api/v1/orders/:id          ✅ IDOR prevention

Utilities:
  POST   /api/v1/cache/load          ✅ JSON only (no pickle)
  GET    /health                     ✅ Security headers
  GET    /api/v1/info                ✅ Safe information
```

### Insecure API (8000) - 17 Vulnerable Endpoints

```yaml
Authentication:
  POST   /api/v1/auth/register       ❌ No validation
  POST   /api/v1/auth/login          ❌ Weak JWT secret
  POST   /api/v1/auth/verify         ❌ Hardcoded secret

User Management:
  GET    /api/v1/users               ❌ NO AUTH - Full enumeration
  GET    /api/v1/users/:id           ❌ SQL injection vulnerable
  GET    /api/v1/admin/users         ❌ NO AUTH - Anyone is admin
  POST   /api/v1/user/update         ❌ Mass assignment

Data Access:
  GET    /api/v1/products            ❌ No authentication
  GET    /api/v1/data                ❌ IDOR - Access anyone's data
  GET    /api/v1/data/sensitive      ❌ API key in URL parameter
  GET|POST /api/v1/profile           ❌ CORS allow all origins

Order Management:
  GET|POST /api/v1/orders            ❌ Can impersonate any user
  GET    /api/v1/orders/:id          ❌ IDOR - Full access

Utilities:
  POST   /api/v1/cache/load          ❌ Pickle RCE vulnerability
  POST   /api/v1/brute/login         ❌ No rate limiting
  GET    /api/v1/info                ❌ No security headers
```

---

## 🎯 Test Credentials

```yaml
Admin Account:
  Email:    admin@example.com
  Password: admin123

Regular User:
  Email:    user@example.com
  Password: password123

Test User:
  Email:    test@example.com
  Password: password123
```

---

## 📋 10 OWASP Top Vulnerabilities Demonstrated

| # | Vulnerability | Secure Pattern | Insecure Pattern |
|---|---|---|---|
| 1️⃣ | **JWT Token Issues** | Strong secret, 24h expiration | Hardcoded secret, no expiration |
| 2️⃣ | **SQL Injection** | Parameterized queries | String concatenation |
| 3️⃣ | **Broken Authentication** | bcrypt + validation | Plain text passwords |
| 4️⃣ | **API Key Issues** | Bearer headers | URL parameters |
| 5️⃣ | **Missing Rate Limiting** | 5 req/min enforcement | Unlimited requests |
| 6️⃣ | **IDOR** | Ownership verification | Direct object access |
| 7️⃣ | **CORS Misconfiguration** | Restricted origins | Allow all (*) |
| 8️⃣ | **Mass Assignment** | Field whitelisting | Accept any field |
| 9️⃣ | **Insecure Deserialization** | JSON only | Pickle RCE |
| 🔟 | **Missing Security Headers** | CSP, HSTS, X-Frame | No headers |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    API Testing Suite                         │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌────────────────┐  ┌────────────────┐  ┌──────────────┐  │
│  │  Dashboard     │  │  Secure API    │  │ Insecure API │  │
│  │  (React)       │  │  Port 8001     │  │  Port 8000   │  │
│  │  Port 5000     │  │  ✅ Hardened   │  │  ❌ Vulns    │  │
│  └────────────────┘  └────────────────┘  └──────────────┘  │
│          │                   │                   │            │
│          └───────────────────┴───────────────────┘            │
│                               │                               │
│                      ┌────────────────┐                       │
│                      │  PostgreSQL    │                       │
│                      │  Data Storage  │                       │
│                      └────────────────┘                       │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Requirements

| Tool | Version | Purpose |
|------|---------|---------|
| 🐳 Docker | Latest | Containerization |
| 🐳 Docker Compose | Latest | Orchestration |
| 🟢 Node.js | 18+ | Frontend build (local only) |
| 🐍 Python | 3.9+ | Backend runtime (local only) |
| 🗄️ PostgreSQL | 13+ | Database (included in compose) |

---

## 📦 Installation & Usage

### Start Services
```bash
# Launch entire suite
docker-compose up -d

# Follow logs in real-time
docker-compose logs -f
```

### Access Points
```
Dashboard:     http://localhost:5000
Secure API:    http://localhost:8001/api/v1
Insecure API:  http://localhost:8000/api/v1
Health Check:  http://localhost:8001/health
```

### Stop Services
```bash
docker-compose down
```

### Complete Reset
```bash
docker-compose down -v
docker-compose build --no-cache
docker-compose up -d
```

### View Logs
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f secure-api
docker-compose logs -f insecure-api
docker-compose logs -f react-dashboard
```

---

## 📚 Key Learnings

By completing this hands-on suite, you'll master:

✅ **Authentication & Authorization**
- Implementing JWT with bcrypt hashing
- Role-based access control (RBAC)
- Secure session management

✅ **Input Validation**
- Parameterized SQL queries
- Input sanitization techniques
- Password strength requirements

✅ **API Security**
- Bearer token authentication
- Rate limiting & DDoS protection
- CORS policy configuration

✅ **Access Control**
- IDOR vulnerability prevention
- Ownership verification patterns
- Field whitelisting

✅ **Secure Coding**
- Password hashing best practices
- Security headers implementation
- Insecure deserialization risks

✅ **All 10 OWASP Top API Vulnerabilities**
- Live examples of each vulnerability
- Secure implementation patterns
- Real-world exploit demonstrations

---

## ❓ FAQ

**Q: Is the Secure API production-ready?**  
A: The security patterns follow OWASP best practices and can be adapted for production use. Always conduct thorough security testing before deployment.

**Q: Why compare vulnerable code side-by-side?**  
A: Side-by-side comparison is one of the most effective learning methods. Seeing the attack vs. defense together reinforces security principles.

**Q: How long does setup take?**  
A: Under 1 minute with Docker Compose. Run `docker-compose up -d` and you're ready to test.

**Q: Can I modify the code?**  
A: Absolutely! Both APIs are educational tools. Modify, experiment, and learn by breaking things.

**Q: What if I want to test locally?**  
A: Use Option 2 (Local Development). Install requirements and run `python app.py` for the backend.

**Q: Are there any prerequisites?**  
A: Just Docker & Docker Compose. Everything else is included in the containers.

---

## ⚠️ Important Disclaimer

### The Insecure API is intentionally vulnerable for educational purposes only

```
🚫 DO NOT use insecure patterns in production
🚫 DO NOT expose this suite to the internet
🚫 DO NOT deploy vulnerable code to any public environment
✅ DO use in controlled learning/lab environments
✅ DO follow Secure API patterns for real applications
✅ DO conduct security audits before production deployment
```

---

## 🎓 Educational Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP API Security](https://owasp.org/www-project-api-security/)
- [Flask Security Best Practices](https://flask.palletsprojects.com/en/2.3.x/security/)
- [JWT Authentication](https://jwt.io/)
- [CORS Explained](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)

---

## 📈 Project Stats

| Metric | Value |
|--------|-------|
| 🔐 OWASP Vulnerabilities | 10 |
| 🛣️ Total Endpoints | 34 (17 × 2) |
| 📊 Test Cases | 30+ |
| 🐳 Docker Services | 4 |
| 📚 Documentation | Comprehensive |
| ⏱️ Setup Time | < 1 minute |

---

## 🤝 Demo

---

[api_tester.webm](https://github.com/user-attachments/assets/8f35b114-6235-419c-ad00-5be8307a1d59)

[Demo](https://adragportfolio.info.gf/security-api)

---

<div align="center">

### Made with ❤️ for Security Engineers

**Built for:** Full-stack security engineering portfolio  
**Last Updated:** January 2026
**Version:** 2.0.0

<br>

[![GitHub](https://img.shields.io/badge/GitHub-181717?style=for-the-badge&logo=github)](https://github.com/)
[![Security](https://img.shields.io/badge/Security-First-red?style=for-the-badge&logo=security)](https://owasp.org/)
[![Learning](https://img.shields.io/badge/Learning-Focused-blue?style=for-the-badge&logo=brain)](https://www.owasp.org/)

</div>

---

<details>
<summary><strong>📄 License & Attribution</strong></summary>

Educational project for learning API security. OWASP content used under creative commons license.

</details>
