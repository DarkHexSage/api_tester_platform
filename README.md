# API Testing Console - Unified Security Suite

A professional-grade API testing dashboard combining secure and insecure API implementations for educational and comparative testing.

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [API Endpoints](#api-endpoints)
- [Testing Guide](#testing-guide)
- [Security Comparison](#security-comparison)
- [Advanced Usage](#advanced-usage)
- [Troubleshooting](#troubleshooting)
- [Demo](#demo)

---

## Overview

This suite provides:

- **Secure API**: Production-ready implementation with best practices
- **Insecure API**: Intentionally vulnerable for learning security flaws
- **Testing Dashboard**: Professional frontend to test and compare both APIs

### Key Features

- Toggle between Secure and Insecure APIs
- Full HTTP method support (GET, POST, PUT, PATCH, DELETE)
- Custom header management
- Request body editing with JSON validation
- Real-time response display with status codes
- Response time metrics
- Glass morphism UI design
- Professional typography

---

## Quick Start

### Prerequisites

- Docker & Docker Compose
- Modern web browser
- 20 minutes

### Running the Suite

```bash
# From your project root
docker-compose down -v
docker-compose build --no-cache
docker-compose up -d

# Wait for services to start
sleep 10

# Check status
docker ps
```

### Access the Dashboard

```
Frontend:      http://localhost:5000
Secure API:    http://localhost:3000
Insecure API:  http://localhost:3001
Database:      localhost:5432
```

---

## Architecture

```
┌─────────────────────────────────────────┐
│      Frontend Dashboard (React)         │
│  http://localhost:5000                  │
│  - Glass morphism UI                    │
│  - Dual API testing mode                │
│  - Real-time response visualization     │
└────────────┬────────────────────────────┘
             │
      ┌──────┴──────┐
      │             │
      ▼             ▼
┌──────────────┐ ┌──────────────┐
│ Secure API   │ │ Insecure API │
│ :3000        │ │ :3001        │
│ Flask        │ │ Flask        │
│ Best Practices
│ JWT, Validation
│ Rate Limiting │ │ No Security  │
│ Security     │ │ SQL Injection│
│ Headers      │ │ No Auth      │
└──────┬───────┘ └──────┬───────┘
       │                │
       └────────┬───────┘
                │
                ▼
        ┌──────────────┐
        │ PostgreSQL   │
        │ :5432        │
        └──────────────┘
```

---

## API Endpoints

### Secure API (Protected)

Base URL: `http://localhost:3000`

#### Authentication

```
POST /api/v1/auth/register
POST /api/v1/auth/login
POST /api/v1/auth/refresh
```

#### Users

```
GET    /api/v1/users
GET    /api/v1/users/:id
POST   /api/v1/users
PUT    /api/v1/users/:id
DELETE /api/v1/users/:id
```

#### Data

```
GET  /api/v1/data
POST /api/v1/data
```

#### Health

```
GET /health
GET /api/v1/info
```

---

### Insecure API (Vulnerable)

Base URL: `http://localhost:3001`

#### Authentication (No Protection)

```
POST /api/v1/auth/register
POST /api/v1/auth/login
```

#### Users (No Authorization)

```
GET    /api/v1/users
GET    /api/v1/users/:id
POST   /api/v1/users
PUT    /api/v1/users/:id
DELETE /api/v1/users/:id
```

#### Data (No Validation)

```
GET  /api/v1/data
POST /api/v1/data
```

#### Health (No Rate Limiting)

```
GET /health
GET /api/v1/info
```

---

## Testing Guide

### Test 1: Basic Health Check

**Purpose**: Verify API connectivity

**Steps**:

1. Open http://localhost:5000
2. Toggle to **Secure API**
3. Endpoint: `/health`
4. Method: `GET`
5. Click **Send**

**Expected Response (Secure)**:
```json
{
  "status": "ok",
  "timestamp": "2025-12-30T00:00:00Z"
}
```

**Expected Response (Insecure)**:
```json
{
  "status": "running",
  "message": "API is operational"
}
```

---

### Test 2: API Information

**Purpose**: View API implementation details

**Endpoint**: `/api/v1/info`
**Method**: `GET`

**Secure API Response**:
```json
{
  "name": "Secure API",
  "version": "1.0.0",
  "security": [
    "JWT Authentication",
    "Input Validation",
    "Rate Limiting",
    "CORS Protection",
    "Security Headers"
  ]
}
```

**Insecure API Response**:
```json
{
  "name": "Insecure API",
  "version": "1.0.0",
  "features": [
    "No authentication",
    "No validation",
    "SQL injection possible",
    "CORS misconfigured"
  ]
}
```

---

### Test 3: User Registration

**Purpose**: Test authentication implementation

**Endpoint**: `/api/v1/auth/register`
**Method**: `POST`

**Request Body**:
```json
{
  "username": "testuser",
  "email": "test@example.com",
  "password": "SecurePass123!",
  "name": "Test User"
}
```

**Secure API Response** (Status 201):
```json
{
  "id": "user-123",
  "username": "testuser",
  "email": "test@example.com",
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "expiresIn": 3600
}
```

**Insecure API Response** (Status 200, No Validation):
```json
{
  "id": 1,
  "username": "testuser",
  "email": "test@example.com",
  "password": "SecurePass123!"
}
```

**Security Differences**:
- ✅ Secure: Password hashed, JWT token returned, validation enforced
- ❌ Insecure: Password stored plain text, no token, no input validation

---

### Test 4: User Login

**Purpose**: Test authentication mechanism

**Endpoint**: `/api/v1/auth/login`
**Method**: `POST`

**Request Body**:
```json
{
  "username": "testuser",
  "password": "SecurePass123!"
}
```

**Secure API Response** (Status 200):
```json
{
  "user": {
    "id": "user-123",
    "username": "testuser",
    "email": "test@example.com"
  },
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expiresIn": 3600,
  "refreshToken": "refresh-token-xyz"
}
```

**Insecure API Response** (Status 200, No Validation):
```json
{
  "id": 1,
  "username": "testuser",
  "email": "test@example.com",
  "authenticated": true
}
```

**Security Differences**:
- ✅ Secure: JWT tokens, expiration, refresh mechanism
- ❌ Insecure: No tokens, no expiration, no security validation

---

### Test 5: Get Protected Data

**Purpose**: Test authorization

**Endpoint**: `/api/v1/users/1`
**Method**: `GET`

**Without Authorization**:

**Secure API Response** (Status 401):
```json
{
  "error": "Unauthorized",
  "message": "No token provided"
}
```

**Insecure API Response** (Status 200, Data Exposed):
```json
{
  "id": 1,
  "username": "testuser",
  "email": "test@example.com",
  "phone": "555-1234",
  "address": "123 Main St"
}
```

**With Authorization Header**:

Add header:
```json
{
  "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Secure API Response** (Status 200, Authorized):
```json
{
  "id": "user-123",
  "username": "testuser",
  "email": "test@example.com"
}
```

**Security Differences**:
- ✅ Secure: Requires valid JWT token
- ❌ Insecure: No authentication required, data exposed

---

### Test 6: SQL Injection Vulnerability

**Purpose**: Demonstrate input validation differences

**Endpoint**: `/api/v1/users/1`
**Method**: `GET`

**Test Payload**: `1 OR 1=1`

**Secure API Response** (Status 400):
```json
{
  "error": "Invalid input",
  "message": "User ID must be numeric"
}
```

**Insecure API Response** (Status 200, Vulnerable):
```json
[
  {
    "id": 1,
    "username": "user1",
    "email": "user1@example.com"
  },
  {
    "id": 2,
    "username": "user2",
    "email": "user2@example.com"
  },
  ...
]
```

**Security Differences**:
- ✅ Secure: Input validation, parameterized queries
- ❌ Insecure: No validation, SQL injection possible

---

### Test 7: Rate Limiting

**Purpose**: Test DoS protection

**Setup**: Send multiple rapid requests to `/api/v1/users`

**Secure API Response** (After 100 requests/minute):
```json
{
  "error": "Too many requests",
  "message": "Rate limit exceeded",
  "retryAfter": 60
}
```

**Insecure API Response** (No Limit):
```json
{
  "users": [...]
}
```

**Security Differences**:
- ✅ Secure: Rate limiting, anti-DoS protection
- ❌ Insecure: No rate limiting, vulnerable to abuse

---

### Test 8: CORS Policy

**Purpose**: Test cross-origin security

**Test**: Open browser console and make fetch request from different origin

**Secure API Response**:
```
Access-Control-Allow-Origin: http://localhost:5000
Access-Control-Allow-Methods: GET, POST, PUT, DELETE
Access-Control-Allow-Headers: Content-Type, Authorization
```

**Insecure API Response**:
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: *
Access-Control-Allow-Headers: *
```

**Security Differences**:
- ✅ Secure: Restrictive CORS, whitelist only allowed origins
- ❌ Insecure: Open CORS, allows any origin

---

## Security Comparison

### Feature Matrix

| Feature | Secure | Insecure |
|---------|--------|----------|
| **Authentication** | JWT with expiration | None |
| **Input Validation** | Strict type checking | None |
| **SQL Injection Protection** | Parameterized queries | Raw queries |
| **Rate Limiting** | Yes (100 req/min) | No |
| **CORS Policy** | Restrictive | Open |
| **Password Hashing** | bcrypt | Plain text |
| **Security Headers** | HSTS, X-Frame, CSP | None |
| **HTTPS** | Required | HTTP only |
| **Error Messages** | Generic | Detailed (info leakage) |
| **Token Expiration** | 1 hour | N/A |
| **Refresh Tokens** | Yes | No |
| **API Versioning** | v1 | v1 |
| **Logging** | Security events | Minimal |
| **Authorization** | Role-based | None |
| **Data Encryption** | At rest & transit | Transit only |

---

## Advanced Usage

### Custom Headers

Test custom authentication schemes:

1. Click **Secure API**
2. Add Headers (JSON):
```json
{
  "Authorization": "Bearer YOUR_JWT_TOKEN",
  "X-API-Key": "your-api-key",
  "X-Request-ID": "123456"
}
```
3. Send request

### Request Body Testing

Test POST/PUT operations:

1. Select Method: `POST`
2. Endpoint: `/api/v1/users`
3. Body:
```json
{
  "username": "newuser",
  "email": "new@example.com",
  "password": "SecurePass123!",
  "name": "New User"
}
```
4. Send and observe response

### Comparing Responses

**Side-by-side comparison**:

1. Send request to **Secure API**, note response time
2. Toggle to **Insecure API**
3. Send same request, compare:
   - Status code
   - Response time
   - Data returned
   - Security headers

### Testing Error Handling

1. **Invalid endpoint**: `/api/v1/nonexistent`
   - Secure: 404 "Not Found"
   - Insecure: 404 with stack trace

2. **Missing required fields**: Send incomplete JSON
   - Secure: 400 "Validation failed"
   - Insecure: 500 with database error

3. **Type mismatch**: Send string where number expected
   - Secure: 400 "Invalid type"
   - Insecure: 500 database error

---

## Troubleshooting

### Frontend Not Loading

```bash
# Check frontend logs
docker-compose logs frontend

# Verify container is running
docker ps | grep frontend

# Rebuild without cache
docker-compose build --no-cache frontend
docker-compose up -d frontend
```

### APIs Not Responding

```bash
# Check API logs
docker-compose logs secure-api
docker-compose logs insecure-api

# Verify database connection
docker-compose logs postgres

# Test connectivity
curl http://localhost:3000/health
curl http://localhost:3001/health
```

### Database Connection Issues

```bash
# Check database logs
docker-compose logs postgres

# Verify database is running
docker exec security-api-db psql -U postgres -l

# Reset database
docker-compose down -v
docker-compose up -d
```

### CORS Errors

**Browser Console Error**:
```
Access to XMLHttpRequest at 'http://localhost:3000' blocked by CORS policy
```

**Solution**:
- Ensure frontend runs on `localhost:5000`
- Check CORS headers in API responses
- Verify API CORS configuration

---

### Security Testing Checklist

- [ ] Test all HTTP methods
- [ ] Test with and without authentication
- [ ] Try invalid input formats
- [ ] Check error message leakage
- [ ] Test rate limiting
- [ ] Verify CORS headers
- [ ] Check security headers
- [ ] Test token expiration
- [ ] Try privilege escalation
- [ ] Test data access control

---

## Performance Metrics

### Expected Response Times

| Operation | Secure | Insecure | Notes |
|-----------|--------|----------|-------|
| GET /health | 10-20ms | 5-10ms | Secure adds validation |
| GET /users | 50-100ms | 30-50ms | Database queries |
| POST register | 100-200ms | 50-100ms | Secure hashes password |
| POST login | 150-250ms | 50-100ms | Secure validates token |
| GET /users/:id | 20-40ms | 10-20ms | Direct lookup |

### Observations

- Secure API is slower due to validation/encryption
- Insecure API responds faster (no security overhead)
- Database queries dominate response time
- Network latency is the bottleneck

---

## API Documentation

### Status Codes

| Code | Meaning | Secure API | Insecure API |
|------|---------|-----------|-------------|
| 200 | OK | Success | Success |
| 201 | Created | Resource created | Resource created |
| 400 | Bad Request | Validation error | Sometimes skipped |
| 401 | Unauthorized | No token | Never returned |
| 403 | Forbidden | No permission | Never returned |
| 404 | Not Found | Endpoint missing | Endpoint missing |
| 429 | Rate Limited | After limit | Never returned |
| 500 | Server Error | Rare | Frequent |

---

### External Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [REST API Security](https://cheatsheetseries.owasp.org/cheatsheets/REST_Assessment_Cheat_Sheet.html)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)

---

---
## Demo

[api_tester.webm](https://github.com/user-attachments/assets/8f35b114-6235-419c-ad00-5be8307a1d59)
- Demo: [Demo](https://adragportfolio.info.gf/security-api)

---

## License

MIT License - See LICENSE file for details

---

## Author

**DarkHexSage** - Security Engineer & Full-Stack Developer

- GitHub: [@DarkHexSage](https://github.com/DarkHexSage)

---

## Disclaimer

**The Insecure API is intentionally vulnerable for educational purposes only.**

- Do NOT use vulnerable patterns in production
- Do NOT expose to the internet
- Use only in controlled learning environments
- Always follow the Secure API patterns for real applications

---

**Built with ❤️ for the security community**

Last Updated: December 2025
Version: 1.0.0
