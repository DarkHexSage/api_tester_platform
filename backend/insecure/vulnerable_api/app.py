from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
import json
from datetime import datetime, timedelta
import os
import pickle
import base64

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret-key-do-not-use'  # ❌ HARDCODED

# ✅ CORS Configuration
CORS(app, resources={
    r"/api/*": {
        "origins": "*",
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "max_age": 3600
    }
})

@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response

# ============================================
# IN-MEMORY DATABASE
# ============================================

users_db = [
    {
        "id": 1,
        "username": "admin",
        "email": "admin@example.com",
        "password": "admin123",  # ❌ Plain text password
        "name": "Admin User",
        "created_at": datetime.now().isoformat()
    },
    {
        "id": 2,
        "username": "testuser",
        "email": "test@example.com",
        "password": "password123",  # ❌ Plain text password
        "name": "Test User",
        "created_at": datetime.now().isoformat()
    }
]

data_storage = [
    {"id": 1, "title": "Item 1", "content": "Sensitive content here", "user_id": 1},
    {"id": 2, "title": "Item 2", "content": "More data", "user_id": 2}
]

next_user_id = 3
next_data_id = 3

# ============================================
# VULNERABILITY 1: JWT TOKEN ISSUES
# ============================================

@app.route('/api/v1/auth/register', methods=['POST', 'OPTIONS'])
def register():
    """🚨 VULNERABLE: Register without validation"""
    if request.method == 'OPTIONS':
        return '', 204
    
    global next_user_id
    
    data = request.get_json()
    
    # ❌ VULNERABLE: No input validation
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    name = data.get('name', '')
    
    # ❌ VULNERABLE: No duplicate checking
    # ❌ VULNERABLE: No password validation
    
    new_user = {
        "id": next_user_id,
        "username": username,
        "email": email,
        "password": password,  # ❌ Stored in plain text!
        "name": name,
        "created_at": datetime.now().isoformat()
    }
    
    users_db.append(new_user)
    next_user_id += 1
    
    # ❌ VULNERABLE: Returns password in response
    return jsonify({
        "status": "success",
        "message": "User registered",
        "user": new_user
    }), 201


@app.route('/api/v1/auth/login', methods=['POST', 'OPTIONS'])
def login():
    """🚨 JWT with weak secret and no expiration"""
    if request.method == 'OPTIONS':
        return '', 204
    
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    # ❌ VULNERABLE: Minimal validation
    user = next((u for u in users_db if u['email'] == email and u['password'] == password), None)
    
    if not user:
        # Still return token for any email (very vulnerable!)
        user = {"id": None, "email": email, "username": email.split('@')[0], "role": "user"}
    
    # ❌ VULNERABLE: Weak secret
    token = jwt.encode(
        {'email': email, 'role': 'user', 'user_id': user.get('id')},
        'super-secret-key-do-not-use',  # ❌ HARDCODED SECRET
        algorithm='HS256'
    )
    
    return jsonify({
        "status": "success",
        "token": token,
        "message": "Login successful",
        "user": {
            "id": user.get('id'),
            "email": user.get('email'),
            "username": user.get('username')
        }
    })


@app.route('/api/v1/auth/verify', methods=['POST', 'OPTIONS'])
def verify():
    """🚨 JWT verification with weak secret"""
    if request.method == 'OPTIONS':
        return '', 204
    
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    try:
        # ❌ VULNERABLE: Uses hardcoded secret
        payload = jwt.decode(token, 'super-secret-key-do-not-use', algorithms=['HS256'])
        return jsonify({"valid": True, "payload": payload})
    except:
        return jsonify({"valid": False}), 401


# ============================================
# VULNERABILITY 2: SQL INJECTION
# ============================================

@app.route('/api/v1/users', methods=['GET', 'OPTIONS'])
def list_users():
    """🚨 VULNERABLE: No auth, returns all users"""
    if request.method == 'OPTIONS':
        return '', 204
    
    # ❌ NO AUTHENTICATION REQUIRED
    # ❌ RETURNS PASSWORDS
    
    return jsonify({
        "status": "success",
        "count": len(users_db),
        "users": users_db,
        "warning": "All user data exposed including passwords!"
    })


@app.route('/api/v1/users/<user_id>', methods=['GET', 'OPTIONS'])
def get_user(user_id):
    """🚨 SQL Injection vulnerability"""
    if request.method == 'OPTIONS':
        return '', 204
    
    # Simulating SQL query construction (vulnerable)
    query = f"SELECT * FROM users WHERE id = {user_id}"  # ❌ VULNERABLE
    
    # Attacker could do: /api/v1/users/1 OR 1=1
    
    try:
        uid = int(user_id)
        user = next((u for u in users_db if u['id'] == uid), None)
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        return jsonify({
            "query_constructed": query,
            "warning": "SQL Injection detected - id parameter not sanitized",
            "user": user
        })
    except:
        return jsonify({
            "query_constructed": query,
            "warning": "SQL Injection attempt detected in query",
            "error": "Invalid query"
        }), 400


@app.route('/api/v1/users', methods=['POST', 'OPTIONS'])
def create_user():
    """🚨 VULNERABLE: Create user without validation"""
    if request.method == 'OPTIONS':
        return '', 204
    
    global next_user_id
    
    data = request.get_json()
    
    # ❌ NO VALIDATION
    new_user = {
        "id": next_user_id,
        "username": data.get('username'),
        "email": data.get('email'),
        "password": data.get('password'),  # ❌ Plain text
        "name": data.get('name', ''),
        "created_at": datetime.now().isoformat()
    }
    
    users_db.append(new_user)
    next_user_id += 1
    
    return jsonify({
        "status": "success",
        "user": new_user
    }), 201


@app.route('/api/v1/users/<int:user_id>', methods=['PUT', 'OPTIONS'])
def update_user_endpoint(user_id):
    """🚨 VULNERABLE: Update without authorization"""
    if request.method == 'OPTIONS':
        return '', 204
    
    data = request.get_json()
    
    user = next((u for u in users_db if u['id'] == user_id), None)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # ❌ NO OWNERSHIP CHECK
    # ❌ MASS ASSIGNMENT - accepts all fields
    user.update(data)
    
    return jsonify({
        "status": "updated",
        "user": user,
        "warning": "No ownership verification, mass assignment allowed!"
    })


@app.route('/api/v1/users/<int:user_id>', methods=['DELETE', 'OPTIONS'])
def delete_user(user_id):
    """🚨 VULNERABLE: Delete without authorization"""
    if request.method == 'OPTIONS':
        return '', 204
    
    global users_db
    
    # ❌ NO OWNERSHIP CHECK
    user = next((u for u in users_db if u['id'] == user_id), None)
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    users_db = [u for u in users_db if u['id'] != user_id]
    
    return jsonify({
        "status": "deleted",
        "message": f"User {user_id} deleted",
        "warning": "No authorization checks!"
    })


# ============================================
# VULNERABILITY 3: BROKEN AUTHENTICATION
# ============================================

@app.route('/api/v1/admin/users', methods=['GET', 'OPTIONS'])
def admin_users():
    """🚨 No authentication on admin endpoint"""
    if request.method == 'OPTIONS':
        return '', 204
    
    # ❌ NO AUTHENTICATION CHECK!
    return jsonify({
        "status": "success",
        "users": users_db,
        "warning": "Admin endpoint with NO authentication!"
    })


# ============================================
# VULNERABILITY 4: API KEY ISSUES
# ============================================

@app.route('/api/v1/data/sensitive', methods=['GET', 'OPTIONS'])
def sensitive_data():
    """🚨 API key in URL or weak validation"""
    if request.method == 'OPTIONS':
        return '', 204
    
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

@app.route('/api/v1/brute/login', methods=['POST', 'OPTIONS'])
def brute_force_login():
    """🚨 No rate limiting - enables brute force"""
    if request.method == 'OPTIONS':
        return '', 204
    
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    # ❌ NO RATE LIMITING - can brute force!
    user = next((u for u in users_db if u['email'] == email and u['password'] == password), None)
    
    if user:
        return jsonify({
            "status": "success",
            "message": "Login successful",
            "user": user
        })
    
    return jsonify({"status": "failed"}), 401


# ============================================
# VULNERABILITY 6: INSECURE DIRECT OBJECT REFS (IDOR)
# ============================================

@app.route('/api/v1/orders/<order_id>', methods=['GET', 'OPTIONS'])
def get_order(order_id):
    """🚨 IDOR - Access other user's orders"""
    if request.method == 'OPTIONS':
        return '', 204
    
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
    if request.method == 'OPTIONS':
        return '', 204
    
    response = jsonify({"user": "current_user", "data": "sensitive"})
    
    # ❌ VULNERABLE: Allow all origins (already set globally, but explicit here too)
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = '*'
    response.headers['Access-Control-Allow-Headers'] = '*'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    
    return response


# ============================================
# VULNERABILITY 8: MASS ASSIGNMENT / PARAMETER POLLUTION
# ============================================

@app.route('/api/v1/user/update', methods=['POST', 'OPTIONS'])
def update_user_mass_assignment():
    """🚨 Mass assignment - accepts any parameter"""
    if request.method == 'OPTIONS':
        return '', 204
    
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

@app.route('/api/v1/cache/load', methods=['POST', 'OPTIONS'])
def load_cache():
    """🚨 Pickle deserialization"""
    if request.method == 'OPTIONS':
        return '', 204
    
    data = request.get_json().get('cache_data')
    
    try:
        # ❌ VULNERABLE: Pickle deserialization
        cache = pickle.loads(base64.b64decode(data))
        return jsonify({"cache": str(cache)})
    except Exception as e:
        return jsonify({"error": "Invalid cache data", "details": str(e)}), 400


# ============================================
# VULNERABILITY 10: MISSING SECURITY HEADERS + DATA ENDPOINTS
# ============================================

@app.route('/api/v1/data', methods=['GET', 'OPTIONS'])
def api_data_get():
    """🚨 Missing security headers"""
    if request.method == 'OPTIONS':
        return '', 204
    
    response = jsonify({
        "status": "success",
        "data": data_storage,
        "timestamp": datetime.now().isoformat()
    })
    
    # ❌ NO SECURITY HEADERS!
    # Missing: X-Content-Type-Options, X-Frame-Options, CSP, etc.
    
    return response


@app.route('/api/v1/data', methods=['POST', 'OPTIONS'])
def api_data_create():
    """🚨 VULNERABLE: Create data without validation"""
    if request.method == 'OPTIONS':
        return '', 204
    
    global next_data_id
    
    data = request.get_json()
    
    # ❌ NO VALIDATION
    new_data = {
        "id": next_data_id,
        "title": data.get('title'),
        "content": data.get('content'),
        "user_id": data.get('user_id'),  # ❌ Can set any user_id
        "created_at": datetime.now().isoformat()
    }
    
    data_storage.append(new_data)
    next_data_id += 1
    
    return jsonify({
        "status": "success",
        "data": new_data
    }), 201


# ============================================
# HEALTH & INFO ENDPOINTS
# ============================================

@app.route('/health', methods=['GET', 'OPTIONS'])
def health():
    """Health check endpoint"""
    if request.method == 'OPTIONS':
        return '', 204
    
    return jsonify({"status": "ok", "service": "Insecure API"})


@app.route('/api/v1/info', methods=['GET', 'OPTIONS'])
def api_info():
    """API info endpoint"""
    if request.method == 'OPTIONS':
        return '', 204
    
    return jsonify({
        "name": "Vulnerable API",
        "version": "1.0.0",
        "description": "Intentionally vulnerable API for security testing",
        "base_url": "http://localhost:3001",
        "endpoints": {
            "authentication": {
                "register": "POST /api/v1/auth/register",
                "login": "POST /api/v1/auth/login",
                "verify": "POST /api/v1/auth/verify"
            },
            "users": {
                "list": "GET /api/v1/users",
                "get": "GET /api/v1/users/:id",
                "create": "POST /api/v1/users",
                "update": "PUT /api/v1/users/:id",
                "delete": "DELETE /api/v1/users/:id"
            },
            "data": {
                "list": "GET /api/v1/data",
                "create": "POST /api/v1/data"
            },
            "admin": {
                "users": "GET /api/v1/admin/users"
            },
            "security": {
                "profile": "GET|POST /api/v1/profile",
                "sensitive": "GET /api/v1/data/sensitive",
                "update": "POST /api/v1/user/update",
                "cache": "POST /api/v1/cache/load",
                "brute": "POST /api/v1/brute/login",
                "orders": "GET /api/v1/orders/:id"
            }
        },
        "vulnerabilities": [
            "1. JWT Token Issues (weak secret, no expiration)",
            "2. SQL Injection (string concatenation in queries)",
            "3. Broken Authentication (no auth checks)",
            "4. API Key Issues (keys in URL)",
            "5. Missing Rate Limiting (brute force possible)",
            "6. IDOR (no ownership verification)",
            "7. CORS Misconfiguration (allows all origins)",
            "8. Mass Assignment (accepts all parameters)",
            "9. Insecure Deserialization (pickle usage)",
            "10. Missing Security Headers (no CSP, etc)"
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
    print("\n🌐 API Running: http://localhost:3001")
    print("📊 API Info: http://localhost:3001/api/v1/info")
    print("\n📋 ENDPOINTS:")
    print("  Auth:")
    print("    - POST /api/v1/auth/register")
    print("    - POST /api/v1/auth/login")
    print("  Users:")
    print("    - GET    /api/v1/users")
    print("    - GET    /api/v1/users/<id>")
    print("    - POST   /api/v1/users")
    print("    - PUT    /api/v1/users/<id>")
    print("    - DELETE /api/v1/users/<id>")
    print("  Data:")
    print("    - GET    /api/v1/data")
    print("    - POST   /api/v1/data")
    print("="*70 + "\n")
    
    app.run(debug=True, port=3001, host='0.0.0.0')
