from flask import Flask, request, jsonify, jsonify as json_response
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
    r"/security-api/*": {
        "origins": "*",
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "max_age": 3600
    },
    r"/api/*": {
        "origins": "*",
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "max_age": 3600
    }
})

# ✅ CORS Headers
@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response

# ============================================
# VULNERABILITY 1: JWT TOKEN ISSUES
# ============================================

@app.route('/security-api/insecure/api/auth/login', methods=['POST', 'OPTIONS'])
@app.route('/api/v1/auth/login', methods=['POST', 'OPTIONS'])
def login():
    """🚨 JWT with weak secret and no expiration"""
    if request.method == 'OPTIONS':
        return '', 204
    
    data = request.get_json()
    email = data.get('email')
    
    # ❌ VULNERABLE: Weak secret
    token = jwt.encode(
        {'email': email, 'role': 'user'},
        'super-secret-key-do-not-use',  # ❌ HARDCODED SECRET
        algorithm='HS256'
    )
    
    return jsonify({"token": token, "message": "Login successful"})


@app.route('/security-api/insecure/api/auth/verify', methods=['POST', 'OPTIONS'])
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
# VULNERABILITY 2: SQL INJECTION IN API
# ============================================

@app.route('/security-api/insecure/api/users/<user_id>', methods=['GET', 'OPTIONS'])
@app.route('/api/v1/users/<user_id>', methods=['GET', 'OPTIONS'])
def get_user(user_id):
    """🚨 SQL Injection vulnerability"""
    if request.method == 'OPTIONS':
        return '', 204
    
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

@app.route('/security-api/insecure/api/admin/users', methods=['GET', 'OPTIONS'])
@app.route('/api/v1/admin/users', methods=['GET', 'OPTIONS'])
def admin_users():
    """🚨 No authentication on admin endpoint"""
    if request.method == 'OPTIONS':
        return '', 204
    
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

@app.route('/security-api/insecure/api/data/sensitive', methods=['GET', 'OPTIONS'])
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

@app.route('/security-api/insecure/api/brute/login', methods=['POST', 'OPTIONS'])
@app.route('/api/v1/brute/login', methods=['POST', 'OPTIONS'])
def brute_force_login():
    """🚨 No rate limiting - enables brute force"""
    if request.method == 'OPTIONS':
        return '', 204
    
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

@app.route('/security-api/insecure/api/orders/<order_id>', methods=['GET', 'OPTIONS'])
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

@app.route('/security-api/insecure/api/profile', methods=['GET', 'POST', 'OPTIONS'])
@app.route('/api/v1/profile', methods=['GET', 'POST', 'OPTIONS'])
def profile():
    """🚨 CORS allows all origins"""
    if request.method == 'OPTIONS':
        return '', 204
    
    response = jsonify({"user": "current_user", "data": "sensitive"})
    
    # ❌ VULNERABLE: Allow all origins (but CORS decorator handles this)
    # response.headers['Access-Control-Allow-Origin'] = '*'
    
    return response


# ============================================
# VULNERABILITY 8: MASS ASSIGNMENT / PARAMETER POLLUTION
# ============================================

@app.route('/security-api/insecure/api/user/update', methods=['POST', 'OPTIONS'])
@app.route('/api/v1/user/update', methods=['POST', 'OPTIONS'])
def update_user():
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

@app.route('/security-api/insecure/api/cache/load', methods=['POST', 'OPTIONS'])
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
    except:
        return jsonify({"error": "Invalid cache data"}), 400


# ============================================
# VULNERABILITY 10: MISSING SECURITY HEADERS
# ============================================

@app.route('/security-api/insecure/api/data', methods=['GET', 'OPTIONS'])
@app.route('/api/v1/data', methods=['GET', 'OPTIONS'])
def api_data():
    """🚨 Missing security headers"""
    if request.method == 'OPTIONS':
        return '', 204
    
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

@app.route('/security-api/insecure/api/info', methods=['GET', 'OPTIONS'])
@app.route('/api/v1/info', methods=['GET', 'OPTIONS'])
def api_info():
    """API info endpoint"""
    if request.method == 'OPTIONS':
        return '', 204
    
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


# ============================================
# HEALTH CHECK
# ============================================

@app.route('/health', methods=['GET', 'OPTIONS'])
def health():
    """Health check endpoint"""
    if request.method == 'OPTIONS':
        return '', 204
    
    return jsonify({"status": "ok"})


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
    print("\n📊 Test Endpoints:")
    print("   - /security-api/insecure/api/info (GET)")
    print("   - /api/v1/info (GET)")
    print("   - /security-api/insecure/api/auth/login (POST)")
    print("   - /api/v1/auth/login (POST)")
    print("="*70 + "\n")
    
    app.run(debug=True, port=8000, host='0.0.0.0')
