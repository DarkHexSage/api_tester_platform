from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
import json
import os
import pickle
import base64
from datetime import datetime, timedelta

app = Flask(__name__)

# ============================================
# INSECURE CONFIGURATION
# ============================================

# ❌ VULNERABILITY 1: Hardcoded weak secret
app.config['SECRET_KEY'] = 'super-secret-key-do-not-use'

# ❌ NO RATE LIMITING - will be added per endpoint

# ❌ VULNERABILITY 7: CORS allows all origins
CORS(app, resources={
    r"/security-api/*": {
        "origins": "*",  # ❌ ALLOWS ALL!
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": "*",
        "max_age": 3600
    }
})

# ❌ NO SECURITY HEADERS

@app.after_request
def add_headers(response):
    # ❌ VULNERABILITY 10: Missing security headers
    # NOT adding X-Content-Type-Options, X-Frame-Options, CSP, etc.
    return response

# ============================================
# DATABASE (with vulnerable data)
# ============================================

# ❌ VULNERABILITY 6: Passwords in plain text
users = [
    {
        "id": 1,
        "username": "admin",
        "email": "admin@example.com",
        "password": "admin123",  # ❌ PLAIN TEXT!
        "name": "Admin User",
        "role": "admin",
        "created_at": datetime.now().isoformat()
    },
    {
        "id": 2,
        "username": "testuser",
        "email": "user@example.com",
        "password": "password123",  # ❌ PLAIN TEXT!
        "name": "Test User",
        "role": "user",
        "created_at": datetime.now().isoformat()
    }
]

products = [
    {"id": 1, "user_id": 1, "name": "Laptop", "price": 1299.99, "created_at": datetime.now().isoformat()},
    {"id": 2, "user_id": 2, "name": "Phone", "price": 999.99, "created_at": datetime.now().isoformat()},
]

orders = [
    {"id": 1, "user_id": 1, "total": 1299.99, "items": ["Laptop"], "created_at": datetime.now().isoformat()},
    {"id": 2, "user_id": 2, "total": 999.99, "items": ["Phone"], "created_at": datetime.now().isoformat()},
]

data_storage = [
    {"id": 1, "user_id": 1, "title": "Item 1", "content": "Vulnerable data", "created_at": datetime.now().isoformat()},
    {"id": 2, "user_id": 2, "title": "Item 2", "content": "More data", "created_at": datetime.now().isoformat()},
]

next_user_id = 3
next_product_id = 3
next_order_id = 3
next_data_id = 3

# ============================================
# AUTHENTICATION ENDPOINTS
# ============================================

@app.route('/security-api/insecure/api/auth/register', methods=['POST', 'OPTIONS'])
def register():
    """❌ VULNERABLE: No validation, no password hashing"""
    if request.method == 'OPTIONS':
        return '', 204
    
    global next_user_id
    
    data = request.get_json()
    
    # ❌ VULNERABILITY 1 & 8: NO VALIDATION
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    name = data.get('name', '')
    
    # ❌ NO CHECK for required fields
    # ❌ NO EMAIL VALIDATION
    # ❌ NO PASSWORD STRENGTH CHECK
    # ❌ NO DUPLICATE CHECKING
    
    new_user = {
        "id": next_user_id,
        "username": username,
        "email": email,
        "password": password,  # ❌ PLAIN TEXT!
        "name": name,
        "role": "user",
        "created_at": datetime.now().isoformat()
    }
    
    users.append(new_user)
    next_user_id += 1
    
    # ❌ VULNERABILITY 8: Password returned in response!
    return jsonify({
        "status": "success",
        "message": "User registered",
        "user": new_user  # ❌ PASSWORD EXPOSED!
    }), 201

@app.route('/security-api/insecure/api/auth/login', methods=['POST', 'OPTIONS'])
def login():
    """❌ VULNERABILITY 1: Weak JWT with no expiration"""
    if request.method == 'OPTIONS':
        return '', 204
    
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    # ❌ NO VALIDATION
    user = next((u for u in users if u['email'] == email and u['password'] == password), None)
    
    # ❌ If no user found, still create token! (Very vulnerable!)
    if not user:
        user = {"id": None, "email": email, "username": email.split('@')[0], "role": "user"}
    
    # ❌ VULNERABILITY 1: Weak secret, no expiration
    token = jwt.encode(
        {'email': email, 'role': user.get('role', 'user'), 'user_id': user.get('id')},
        'super-secret-key-do-not-use',  # ❌ HARDCODED!
        algorithm='HS256'
    )
    
    return jsonify({
        "status": "success",
        "token": token,
        "message": "Login successful"
    })

@app.route('/security-api/insecure/api/auth/verify', methods=['POST', 'OPTIONS'])
def verify():
    """❌ VULNERABLE: Uses weak secret"""
    if request.method == 'OPTIONS':
        return '', 204
    
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    try:
        # ❌ VULNERABILITY 1: Weak secret
        payload = jwt.decode(token, 'super-secret-key-do-not-use', algorithms=['HS256'])
        return jsonify({"valid": True, "payload": payload})
    except:
        return jsonify({"valid": False}), 401

# ============================================
# USER ENDPOINTS
# ============================================

@app.route('/security-api/insecure/api/users', methods=['GET', 'OPTIONS'])
def list_users():
    """❌ VULNERABILITY 3: No authentication required"""
    if request.method == 'OPTIONS':
        return '', 204
    
    # ❌ NO AUTH CHECK!
    # ❌ RETURNS PASSWORDS!
    
    return jsonify({
        "status": "success",
        "count": len(users),
        "users": users  # ❌ ALL DATA + PASSWORDS EXPOSED!
    })

@app.route('/security-api/insecure/api/users/<user_id>', methods=['GET', 'OPTIONS'])
def get_user(user_id):
    """❌ VULNERABILITY 2: SQL Injection"""
    if request.method == 'OPTIONS':
        return '', 204
    
    # ❌ VULNERABILITY 2: String concatenation = SQL injection!
    query = f"SELECT * FROM users WHERE id = {user_id}"  # ❌ VULNERABLE!
    
    # Try: /security-api/insecure/api/users/1 OR 1=1
    
    try:
        uid = int(user_id)
        user = next((u for u in users if u['id'] == uid), None)
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        return jsonify({
            "query_constructed": query,
            "warning": "SQL Injection vulnerability - id parameter not sanitized",
            "user": user  # ❌ PASSWORD EXPOSED!
        })
    except:
        return jsonify({
            "query_constructed": query,
            "warning": "SQL Injection detected",
            "error": "Invalid query"
        }), 400

@app.route('/security-api/insecure/api/users', methods=['POST', 'OPTIONS'])
def create_user():
    """❌ VULNERABLE: No validation or auth"""
    if request.method == 'OPTIONS':
        return '', 204
    
    global next_user_id
    
    data = request.get_json()
    
    # ❌ NO VALIDATION
    new_user = {
        "id": next_user_id,
        "username": data.get('username'),
        "email": data.get('email'),
        "password": data.get('password'),  # ❌ PLAIN TEXT!
        "name": data.get('name', ''),
        "role": "user",
        "created_at": datetime.now().isoformat()
    }
    
    users.append(new_user)
    next_user_id += 1
    
    return jsonify({
        "status": "success",
        "user": new_user  # ❌ PASSWORD EXPOSED!
    }), 201

@app.route('/security-api/insecure/api/users/<int:user_id>', methods=['PUT', 'OPTIONS'])
def update_user(user_id):
    """❌ VULNERABILITY 8: Mass assignment - accepts any field"""
    if request.method == 'OPTIONS':
        return '', 204
    
    data = request.get_json()
    
    user = next((u for u in users if u['id'] == user_id), None)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # ❌ NO OWNERSHIP CHECK!
    # ❌ MASS ASSIGNMENT - updates ANY field!
    user.update(data)
    
    return jsonify({
        "status": "updated",
        "user": user,
        "warning": "No ownership verification, all fields accepted!"
    })

@app.route('/security-api/insecure/api/users/<int:user_id>', methods=['DELETE', 'OPTIONS'])
def delete_user(user_id):
    """❌ VULNERABLE: No auth or ownership check"""
    if request.method == 'OPTIONS':
        return '', 204
    
    global users
    
    # ❌ NO AUTH!
    # ❌ NO OWNERSHIP CHECK!
    
    user = next((u for u in users if u['id'] == user_id), None)
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    users = [u for u in users if u['id'] != user_id]
    
    return jsonify({
        "status": "deleted",
        "message": f"User {user_id} deleted - no auth required!"
    })

# ============================================
# PRODUCT ENDPOINTS
# ============================================

@app.route('/security-api/insecure/api/products', methods=['GET', 'OPTIONS'])
def list_products():
    """❌ VULNERABLE: No authentication"""
    if request.method == 'OPTIONS':
        return '', 204
    
    # ❌ NO AUTH!
    return jsonify({
        "status": "success",
        "count": len(products),
        "products": products
    })

@app.route('/security-api/insecure/api/products/<int:product_id>', methods=['GET', 'OPTIONS'])
def get_product(product_id):
    """❌ VULNERABLE: No authentication"""
    if request.method == 'OPTIONS':
        return '', 204
    
    product = next((p for p in products if p['id'] == product_id), None)
    
    if not product:
        return jsonify({"error": "Product not found"}), 404
    
    return jsonify({
        "status": "success",
        "product": product
    })

@app.route('/security-api/insecure/api/products', methods=['POST', 'OPTIONS'])
def create_product():
    """❌ VULNERABLE: No validation or auth"""
    if request.method == 'OPTIONS':
        return '', 204
    
    global next_product_id
    
    data = request.get_json()
    
    # ❌ NO VALIDATION
    new_product = {
        "id": next_product_id,
        "user_id": data.get('user_id'),  # ❌ Can set any user_id!
        "name": data.get('name'),
        "price": data.get('price'),
        "created_at": datetime.now().isoformat()
    }
    
    products.append(new_product)
    next_product_id += 1
    
    return jsonify({
        "status": "success",
        "product": new_product
    }), 201

# ============================================
# ORDER ENDPOINTS
# ============================================

@app.route('/security-api/insecure/api/orders', methods=['GET', 'OPTIONS'])
def list_orders():
    """❌ VULNERABILITY 3: No auth - returns ALL orders"""
    if request.method == 'OPTIONS':
        return '', 204
    
    # ❌ NO AUTH!
    # ❌ RETURNS ALL ORDERS FROM ALL USERS!
    
    return jsonify({
        "status": "success",
        "count": len(orders),
        "orders": orders
    })

@app.route('/security-api/insecure/api/orders/<int:order_id>', methods=['GET', 'OPTIONS'])
def get_order(order_id):
    """❌ VULNERABILITY 6: IDOR - No ownership check"""
    if request.method == 'OPTIONS':
        return '', 204
    
    # ❌ NO AUTH!
    # ❌ NO OWNERSHIP CHECK!
    
    order = next((o for o in orders if o['id'] == order_id), None)
    
    if not order:
        return jsonify({"error": "Order not found"}), 404
    
    # Anyone can access any order!
    return jsonify({
        "status": "success",
        "order": order,
        "warning": "No ownership verification - IDOR vulnerability!"
    })

@app.route('/security-api/insecure/api/orders', methods=['POST', 'OPTIONS'])
def create_order():
    """❌ VULNERABLE: Can set any user_id"""
    if request.method == 'OPTIONS':
        return '', 204
    
    global next_order_id
    
    data = request.get_json()
    
    # ❌ CAN SET ANY USER_ID!
    # ❌ NO VALIDATION!
    
    new_order = {
        "id": next_order_id,
        "user_id": data.get('user_id'),  # ❌ ATTACKER CAN SET THIS!
        "total": data.get('total'),
        "items": data.get('items', []),
        "created_at": datetime.now().isoformat()
    }
    
    orders.append(new_order)
    next_order_id += 1
    
    return jsonify({
        "status": "success",
        "order": new_order
    }), 201

# ============================================
# ADMIN ENDPOINTS
# ============================================

@app.route('/security-api/insecure/api/admin/users', methods=['GET', 'OPTIONS'])
def admin_users():
    """❌ VULNERABILITY 3: No auth on admin endpoint"""
    if request.method == 'OPTIONS':
        return '', 204
    
    # ❌ NO AUTHENTICATION!
    # ❌ NO ADMIN ROLE CHECK!
    # Anyone can access this!
    
    return jsonify({
        "status": "success",
        "users": users,  # ❌ ALL USERS WITH PASSWORDS!
        "warning": "Admin endpoint with NO authentication!"
    })

# ============================================
# DATA ENDPOINTS
# ============================================

@app.route('/security-api/insecure/api/data', methods=['GET', 'OPTIONS'])
def list_data():
    """❌ VULNERABLE: No auth"""
    if request.method == 'OPTIONS':
        return '', 204
    
    # ❌ NO AUTH!
    # ❌ RETURNS ALL DATA FROM ALL USERS!
    
    return jsonify({
        "status": "success",
        "count": len(data_storage),
        "data": data_storage
    })

@app.route('/security-api/insecure/api/data', methods=['POST', 'OPTIONS'])
def create_data():
    """❌ VULNERABLE: Can set any user_id"""
    if request.method == 'OPTIONS':
        return '', 204
    
    global next_data_id
    
    data = request.get_json()
    
    # ❌ CAN SET ANY USER_ID!
    
    new_data = {
        "id": next_data_id,
        "user_id": data.get('user_id'),  # ❌ ATTACKER CAN SET!
        "title": data.get('title'),
        "content": data.get('content'),
        "created_at": datetime.now().isoformat()
    }
    
    data_storage.append(new_data)
    next_data_id += 1
    
    return jsonify({
        "status": "success",
        "data": new_data
    }), 201

# ============================================
# SECURITY TEST ENDPOINTS
# ============================================

@app.route('/security-api/insecure/api/data/sensitive', methods=['GET', 'OPTIONS'])
def sensitive_data():
    """❌ VULNERABILITY 4: API key in URL"""
    if request.method == 'OPTIONS':
        return '', 204
    
    api_key = request.args.get('api_key')
    
    # ❌ API KEY IN URL!
    # ❌ HARDCODED KEYS!
    
    valid_keys = ['sk_test_1234', 'sk_live_5678']
    
    if api_key in valid_keys:
        return jsonify({
            "status": "success",
            "data": "Sensitive data here",
            "warning": "API key transmitted in URL - visible in browser history!"
        })
    
    return jsonify({"error": "Invalid API key"}), 401

@app.route('/security-api/insecure/api/profile', methods=['GET', 'POST', 'OPTIONS'])
def profile():
    """❌ VULNERABILITY 7: CORS allows all"""
    if request.method == 'OPTIONS':
        return '', 204
    
    response = jsonify({"user": "current_user", "data": "sensitive"})
    
    # ❌ CORS allows ALL origins!
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = '*'
    response.headers['Access-Control-Allow-Headers'] = '*'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    
    return response

@app.route('/security-api/insecure/api/user/update', methods=['POST', 'OPTIONS'])
def update_user_mass_assignment():
    """❌ VULNERABILITY 8: Mass assignment"""
    if request.method == 'OPTIONS':
        return '', 204
    
    data = request.get_json()
    
    # ❌ ACCEPTS ALL PARAMETERS!
    user = {
        "email": data.get('email'),
        "role": data.get('role', 'user'),  # ❌ Can change to admin!
        "is_admin": data.get('is_admin', False),  # ❌ Can set true!
        "permissions": data.get('permissions', [])
    }
    
    return jsonify({
        "status": "updated",
        "user": user,
        "warning": "All parameters accepted - mass assignment vulnerability!"
    })

@app.route('/security-api/insecure/api/cache/load', methods=['POST', 'OPTIONS'])
def load_cache():
    """❌ VULNERABILITY 9: Pickle deserialization"""
    if request.method == 'OPTIONS':
        return '', 204
    
    data = request.get_json().get('cache_data')
    
    try:
        # ❌ PICKLE DESERIALIZATION = CODE EXECUTION!
        cache = pickle.loads(base64.b64decode(data))
        return jsonify({
            "status": "success",
            "cache": str(cache),
            "warning": "Using pickle - allows arbitrary code execution!"
        })
    except Exception as e:
        return jsonify({"error": "Invalid cache data", "details": str(e)}), 400

@app.route('/security-api/insecure/api/brute/login', methods=['POST', 'OPTIONS'])
def brute_force_login():
    """❌ VULNERABILITY 5: No rate limiting"""
    if request.method == 'OPTIONS':
        return '', 204
    
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    # ❌ NO RATE LIMITING!
    # Try 1000 requests/second!
    
    user = next((u for u in users if u['email'] == email and u['password'] == password), None)
    
    if user:
        return jsonify({
            "status": "success",
            "message": "Login successful",
            "user": user
        })
    
    return jsonify({"status": "failed"}), 401

# ============================================
# INFO & HEALTH
# ============================================

@app.route('/security-api/insecure/api/health', methods=['GET', 'OPTIONS'])
def health():
    """Health check"""
    if request.method == 'OPTIONS':
        return '', 204
    
    return jsonify({"status": "ok", "service": "Insecure API"})

@app.route('/security-api/insecure/api/info', methods=['GET', 'OPTIONS'])
def api_info():
    """API information"""
    if request.method == 'OPTIONS':
        return '', 204
    
    return jsonify({
        "name": "Insecure API",
        "version": "1.0",
        "description": "Intentionally vulnerable API for security testing",
        "type": "VULNERABLE - All 10 OWASP vulnerabilities present",
        "endpoints": {
            "authentication": {
                "register": "POST /security-api/insecure/api/auth/register",
                "login": "POST /security-api/insecure/api/auth/login",
                "verify": "POST /security-api/insecure/api/auth/verify"
            },
            "users": {
                "list": "GET /security-api/insecure/api/users",
                "get": "GET /security-api/insecure/api/users/:id",
                "create": "POST /security-api/insecure/api/users",
                "update": "PUT /security-api/insecure/api/users/:id",
                "delete": "DELETE /security-api/insecure/api/users/:id"
            },
            "products": {
                "list": "GET /security-api/insecure/api/products",
                "get": "GET /security-api/insecure/api/products/:id",
                "create": "POST /security-api/insecure/api/products"
            },
            "orders": {
                "list": "GET /security-api/insecure/api/orders",
                "get": "GET /security-api/insecure/api/orders/:id",
                "create": "POST /security-api/insecure/api/orders"
            },
            "data": {
                "list": "GET /security-api/insecure/api/data",
                "create": "POST /security-api/insecure/api/data"
            },
            "admin": {
                "users": "GET /security-api/insecure/api/admin/users"
            }
        },
        "vulnerabilities": [
            "❌ VULN 1: JWT Token Issues (weak secret, no expiration)",
            "❌ VULN 2: SQL Injection (string concatenation in queries)",
            "❌ VULN 3: Broken Authentication (no auth on endpoints)",
            "❌ VULN 4: API Key Issues (keys in URL, hardcoded)",
            "❌ VULN 5: Missing Rate Limiting (brute force possible)",
            "❌ VULN 6: IDOR (no ownership verification)",
            "❌ VULN 7: CORS Misconfiguration (allows all origins)",
            "❌ VULN 8: Mass Assignment (accepts all parameters)",
            "❌ VULN 9: Insecure Deserialization (pickle usage)",
            "❌ VULN 10: Missing Security Headers (no CSP, etc)"
        ]
    })

if __name__ == '__main__':
    print("\n" + "="*70)
    print("🔓 INSECURE API SERVER")
    print("="*70)
    print("\n❌ VULNERABILITIES:")
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
    print("\n📋 ENDPOINT PATHS:")
    print("  /security-api/insecure/api/auth/register")
    print("  /security-api/insecure/api/auth/login")
    print("  /security-api/insecure/api/users")
    print("  /security-api/insecure/api/products")
    print("  /security-api/insecure/api/orders")
    print("  /security-api/insecure/api/data")
    print("  /security-api/insecure/api/admin/users")
    print("\n🌐 API: http://localhost:8000")
    print("📊 Info: http://localhost:8000/security-api/insecure/api/info")
    print("="*70 + "\n")
    
    app.run(debug=True, port=8000, host='0.0.0.0')
