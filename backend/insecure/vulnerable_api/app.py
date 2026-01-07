from flask import Flask, request, jsonify
import jwt
import json
from datetime import datetime, timedelta
import os
import pickle
import base64

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret-key-do-not-use'  # ❌ HARDCODED

# ============================================
# SIMPLE IN-MEMORY DATABASE
# ============================================

users_db = [
    {
        "id": 1,
        "email": "admin@example.com",
        "password": "admin123",  # ❌ PLAIN TEXT
        "role": "admin"
    },
    {
        "id": 2,
        "email": "user@example.com",
        "password": "password123",  # ❌ PLAIN TEXT
        "role": "user"
    }
]

next_user_id = 3

# ============================================
# VULNERABILITY 1: JWT TOKEN ISSUES
# ============================================

@app.route('/api/v1/auth/login', methods=['POST'])
def login():
    """🚨 JWT with weak secret and no expiration"""
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    # ❌ VULNERABLE: No password validation, creates token for any email
    user = next((u for u in users_db if u['email'] == email), None)
    
    # ❌ VULNERABLE: Weak secret
    token = jwt.encode(
        {'email': email, 'role': user.get('role', 'user') if user else 'user'},
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
# SIMPLE REGISTER ENDPOINT
# ============================================

@app.route('/api/v1/auth/register', methods=['POST'])
def register():
    """❌ VULNERABLE: No validation, plain text password"""
    global next_user_id
    
    data = request.get_json()
    
    # ❌ NO VALIDATION - accepts anything!
    new_user = {
        "id": next_user_id,
        "email": data.get('email'),
        "password": data.get('password'),  # ❌ PLAIN TEXT!
        "role": "user"
    }
    
    users_db.append(new_user)
    next_user_id += 1
    
    # ❌ PASSWORD RETURNED IN RESPONSE!
    return jsonify({
        "status": "registered",
        "user": new_user
    }), 201

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
# SIMPLE USERS LIST ENDPOINT
# ============================================

@app.route('/api/v1/users', methods=['GET'])
def list_users():
    """❌ VULNERABLE: No authentication, returns all with passwords"""
    
    # ❌ NO AUTH CHECK!
    # ❌ RETURNS PASSWORDS!
    
    return jsonify({
        "status": "success",
        "users": users_db,
        "warning": "All user data exposed including passwords!"
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
    user = next((u for u in users_db if u['email'] == email and u['password'] == password), None)
    
    if user:
        return jsonify({"status": "success", "user": user})
    
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
        ],
        "endpoints": {
            "auth": [
                "POST /api/v1/auth/register - Register user (no validation)",
                "POST /api/v1/auth/login - Login (weak JWT)",
                "POST /api/v1/auth/verify - Verify token"
            ],
            "users": [
                "GET /api/v1/users - List all users (no auth, password exposed)",
                "GET /api/v1/users/<id> - Get user (SQL injection)"
            ],
            "vulnerabilities": [
                "GET /api/v1/admin/users - Admin endpoint (no auth)",
                "GET /api/v1/data/sensitive - Sensitive data (API key in URL)",
                "POST /api/v1/brute/login - Brute force test (no rate limit)",
                "GET /api/v1/orders/<id> - IDOR test",
                "GET|POST /api/v1/profile - CORS test",
                "POST /api/v1/user/update - Mass assignment test",
                "POST /api/v1/cache/load - Pickle RCE test",
                "GET /api/v1/data - Missing security headers test"
            ]
        }
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
    print("\n📋 ENDPOINTS:")
    print("  Auth: /api/v1/auth/register, /api/v1/auth/login, /api/v1/auth/verify")
    print("  Users: /api/v1/users, /api/v1/users/<id>")
    print("  Vulnerabilities: /api/v1/admin/users, /api/v1/data/sensitive, etc.")
    print("="*70 + "\n")
    
    app.run(debug=True, port=8000, host='0.0.0.0')
