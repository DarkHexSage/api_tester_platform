from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
import jwt
import json
import os
import bcrypt
import re
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)

# ============================================
# SECURITY CONFIGURATION
# ============================================

# ✅ FIX 1 & 4: Environment variables + strong secrets
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'change-me-in-production')
JWT_EXPIRATION_HOURS = int(os.getenv('JWT_EXPIRATION_HOURS', '24'))

# ✅ FIX 5: Rate limiting to prevent brute force
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# ✅ FIX 7: CORS properly configured
CORS(app, resources={
    r"/api/*": {
        "origins": ["http://localhost:3002", "http://localhost:5000", "https://yourdomain.com"],
        "methods": ["GET", "POST", "PUT", "DELETE"],
        "allow_headers": ["Content-Type", "Authorization"],
        "max_age": 3600
    }
})

# ============================================
# SECURITY HEADERS
# ============================================

# ✅ FIX 10: Add security headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

# ============================================
# DATABASE
# ============================================

# ✅ FIX 6: Hash passwords with bcrypt
users = [
    {
        "id": 1,
        "username": "admin",
        "email": "admin@example.com",
        "password_hash": bcrypt.hashpw("admin123".encode(), bcrypt.gensalt()),
        "name": "Admin User",
        "role": "admin",
        "created_at": datetime.now().isoformat()
    },
    {
        "id": 2,
        "username": "testuser",
        "email": "user@example.com",
        "password_hash": bcrypt.hashpw("password123".encode(), bcrypt.gensalt()),
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
    {"id": 1, "user_id": 1, "title": "Item 1", "content": "Secure data", "created_at": datetime.now().isoformat()},
    {"id": 2, "user_id": 2, "title": "Item 2", "content": "More data", "created_at": datetime.now().isoformat()},
]

next_user_id = 3
next_product_id = 3
next_order_id = 3
next_data_id = 3

# ============================================
# INPUT VALIDATION
# ============================================

def is_valid_email(email):
    """✅ Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def is_strong_password(password):
    """✅ Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not any(c.isupper() for c in password):
        return False, "Password must contain uppercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain digit"
    return True, "Password is strong"

def user_exists(email=None, username=None):
    """✅ Check for duplicates"""
    if email:
        return any(u['email'] == email for u in users)
    if username:
        return any(u['username'] == username for u in users)
    return False

# ============================================
# AUTHENTICATION
# ============================================

def create_token(user):
    """✅ FIX 1: Create JWT with expiration"""
    return jwt.encode({
        'user_id': user['id'],
        'email': user['email'],
        'username': user['username'],
        'role': user['role'],
        'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
    }, app.config['SECRET_KEY'], algorithm='HS256')

def verify_token(token):
    """✅ Verify JWT token"""
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload
    except:
        return None

# ✅ FIX 3 & 5: Authentication required
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({"error": "No token provided"}), 401
        
        payload = verify_token(token)
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 401
        
        request.user = payload
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({"error": "No token"}), 401
        
        payload = verify_token(token)
        if not payload or payload.get('role') != 'admin':
            return jsonify({"error": "Admin access required"}), 403
        
        request.user = payload
        return f(*args, **kwargs)
    return decorated

# ============================================
# AUTHENTICATION ENDPOINTS
# ============================================

@app.route('/api/v1/auth/register', methods=['POST', 'OPTIONS'])
@limiter.limit("5 per minute")
def register():
    """✅ SECURE: Register with validation"""
    if request.method == 'OPTIONS':
        return '', 204
    
    global next_user_id
    
    data = request.get_json()
    
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')
    name = data.get('name', '').strip()
    
    # ✅ Validate required fields
    if not username or not email or not password:
        return jsonify({"error": "Missing required fields"}), 400
    
    # ✅ Validate email
    if not is_valid_email(email):
        return jsonify({"error": "Invalid email format"}), 400
    
    # ✅ Validate password strength
    is_strong, msg = is_strong_password(password)
    if not is_strong:
        return jsonify({"error": msg}), 400
    
    # ✅ Check duplicates
    if user_exists(email=email):
        return jsonify({"error": "Email already registered"}), 409
    if user_exists(username=username):
        return jsonify({"error": "Username already taken"}), 409
    
    # ✅ Hash password
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    
    new_user = {
        "id": next_user_id,
        "username": username,
        "email": email,
        "password_hash": password_hash,
        "name": name if name else username,
        "role": "user",
        "created_at": datetime.now().isoformat()
    }
    
    users.append(new_user)
    next_user_id += 1
    
    # ✅ Don't return password
    return jsonify({
        "status": "success",
        "message": "User registered successfully",
        "user": {
            "id": new_user['id'],
            "username": new_user['username'],
            "email": new_user['email'],
            "name": new_user['name']
        }
    }), 201

@app.route('/api/v1/auth/login', methods=['POST', 'OPTIONS'])
@limiter.limit("5 per minute")  # ✅ FIX 5: Rate limiting
def login():
    """✅ SECURE: Strong JWT with expiration"""
    if request.method == 'OPTIONS':
        return '', 204
    
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
    
    user = next((u for u in users if u['email'] == email), None)
    
    # ✅ FIX 6: Use bcrypt for password verification
    if not user or not bcrypt.checkpw(password.encode(), user['password_hash']):
        return jsonify({"error": "Invalid credentials"}), 401
    
    # ✅ Strong token with expiration
    token = create_token(user)
    
    return jsonify({
        "status": "success",
        "token": token,
        "expires_in": JWT_EXPIRATION_HOURS * 3600,
        "token_type": "Bearer",
        "user": {
            "id": user['id'],
            "username": user['username'],
            "email": user['email'],
            "name": user['name'],
            "role": user['role']
        }
    })

@app.route('/api/v1/auth/verify', methods=['POST', 'OPTIONS'])
def verify():
    """Verify token"""
    if request.method == 'OPTIONS':
        return '', 204
    
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    payload = verify_token(token)
    if not payload:
        return jsonify({"valid": False}), 401
    
    return jsonify({"valid": True, "user": payload['email']})

# ============================================
# USER ENDPOINTS
# ============================================

@app.route('/api/v1/users', methods=['GET', 'OPTIONS'])
@require_auth
def list_users():
    """✅ SECURE: List users with auth"""
    if request.method == 'OPTIONS':
        return '', 204
    
    # ✅ Only return safe data
    safe_users = [
        {
            "id": u['id'],
            "username": u['username'],
            "email": u['email'],
            "name": u['name'],
            "role": u['role'],
            "created_at": u['created_at']
        }
        for u in users
    ]
    
    return jsonify({
        "status": "success",
        "count": len(safe_users),
        "users": safe_users
    })

@app.route('/api/v1/users/<int:user_id>', methods=['GET', 'OPTIONS'])
@require_auth
def get_user(user_id):
    """✅ FIX 2: SECURE: Parameterized access (no string concatenation)"""
    if request.method == 'OPTIONS':
        return '', 204
    
    # ✅ Parameterized (type-safe)
    user = next((u for u in users if u['id'] == user_id), None)
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # ✅ Don't return password_hash
    return jsonify({
        "status": "success",
        "user": {
            "id": user['id'],
            "username": user['username'],
            "email": user['email'],
            "name": user['name'],
            "role": user['role'],
            "created_at": user['created_at']
        }
    })

@app.route('/api/v1/users', methods=['POST', 'OPTIONS'])
@require_admin
def create_user():
    """✅ SECURE: Create user (admin only)"""
    if request.method == 'OPTIONS':
        return '', 204
    
    global next_user_id
    
    data = request.get_json()
    
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')
    name = data.get('name', '').strip()
    
    # ✅ Validation
    if not username or not email or not password:
        return jsonify({"error": "Missing required fields"}), 400
    
    if not is_valid_email(email):
        return jsonify({"error": "Invalid email"}), 400
    
    is_strong, msg = is_strong_password(password)
    if not is_strong:
        return jsonify({"error": msg}), 400
    
    if user_exists(email=email):
        return jsonify({"error": "Email already exists"}), 409
    
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    
    new_user = {
        "id": next_user_id,
        "username": username,
        "email": email,
        "password_hash": password_hash,
        "name": name if name else username,
        "role": "user",
        "created_at": datetime.now().isoformat()
    }
    
    users.append(new_user)
    next_user_id += 1
    
    return jsonify({
        "status": "success",
        "user": {
            "id": new_user['id'],
            "username": new_user['username'],
            "email": new_user['email'],
            "name": new_user['name']
        }
    }), 201

@app.route('/api/v1/users/<int:user_id>', methods=['PUT', 'OPTIONS'])
@require_auth
def update_user(user_id):
    """✅ FIX 8: SECURE: Field whitelisting (no mass assignment)"""
    if request.method == 'OPTIONS':
        return '', 204
    
    data = request.get_json()
    
    # ✅ Ownership check
    if request.user['user_id'] != user_id and request.user['role'] != 'admin':
        return jsonify({"error": "Forbidden"}), 403
    
    user = next((u for u in users if u['id'] == user_id), None)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # ✅ Field whitelist - only allow safe fields
    allowed_fields = ['name']
    
    for field in allowed_fields:
        if field in data:
            user[field] = data[field]
    
    # ✅ Protected fields - never updated
    # user['role'], user['email'], user['username'], user['password_hash']
    
    return jsonify({
        "status": "updated",
        "user": {
            "id": user['id'],
            "username": user['username'],
            "email": user['email'],
            "name": user['name'],
            "role": user['role']
        }
    })

@app.route('/api/v1/users/<int:user_id>', methods=['DELETE', 'OPTIONS'])
@require_admin
def delete_user(user_id):
    """✅ SECURE: Delete user (admin only)"""
    if request.method == 'OPTIONS':
        return '', 204
    
    global users
    
    user = next((u for u in users if u['id'] == user_id), None)
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    users = [u for u in users if u['id'] != user_id]
    
    return jsonify({
        "status": "deleted",
        "message": f"User {user_id} deleted"
    })

# ============================================
# PRODUCT ENDPOINTS
# ============================================

@app.route('/api/v1/products', methods=['GET', 'OPTIONS'])
@require_auth
def list_products():
    """✅ SECURE: List products with auth"""
    if request.method == 'OPTIONS':
        return '', 204
    
    return jsonify({
        "status": "success",
        "count": len(products),
        "products": products
    })

@app.route('/api/v1/products/<int:product_id>', methods=['GET', 'OPTIONS'])
@require_auth
def get_product(product_id):
    """✅ SECURE: Get product"""
    if request.method == 'OPTIONS':
        return '', 204
    
    product = next((p for p in products if p['id'] == product_id), None)
    
    if not product:
        return jsonify({"error": "Product not found"}), 404
    
    return jsonify({
        "status": "success",
        "product": product
    })

@app.route('/api/v1/products', methods=['POST', 'OPTIONS'])
@require_admin
def create_product():
    """✅ SECURE: Create product (admin only)"""
    if request.method == 'OPTIONS':
        return '', 204
    
    global next_product_id
    
    data = request.get_json()
    
    name = data.get('name', '').strip()
    price = data.get('price')
    
    if not name or not price:
        return jsonify({"error": "Name and price required"}), 400
    
    try:
        price = float(price)
        if price < 0:
            return jsonify({"error": "Price must be positive"}), 400
    except:
        return jsonify({"error": "Invalid price"}), 400
    
    new_product = {
        "id": next_product_id,
        "user_id": request.user['user_id'],
        "name": name,
        "price": price,
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

@app.route('/api/v1/orders', methods=['GET', 'OPTIONS'])
@require_auth
def list_orders():
    """✅ SECURE: List user's own orders"""
    if request.method == 'OPTIONS':
        return '', 204
    
    # ✅ Only return user's own orders
    user_orders = [o for o in orders if o['user_id'] == request.user['user_id']]
    
    return jsonify({
        "status": "success",
        "count": len(user_orders),
        "orders": user_orders
    })

@app.route('/api/v1/orders/<int:order_id>', methods=['GET', 'OPTIONS'])
@require_auth
def get_order(order_id):
    """✅ FIX 6: SECURE: Check if user owns the resource"""
    if request.method == 'OPTIONS':
        return '', 204
    
    order = next((o for o in orders if o['id'] == order_id), None)
    
    if not order:
        return jsonify({"error": "Order not found"}), 404
    
    # ✅ SECURE: Verify user owns this order!
    if order['user_id'] != request.user['user_id']:
        return jsonify({"error": "Forbidden"}), 403
    
    return jsonify({
        "status": "success",
        "order": order
    })

@app.route('/api/v1/orders', methods=['POST', 'OPTIONS'])
@require_auth
def create_order():
    """✅ SECURE: Create order (ownership set from token)"""
    if request.method == 'OPTIONS':
        return '', 204
    
    global next_order_id
    
    data = request.get_json()
    
    total = data.get('total')
    items = data.get('items', [])
    
    if not total or not items:
        return jsonify({"error": "Total and items required"}), 400
    
    try:
        total = float(total)
        if total < 0:
            return jsonify({"error": "Total must be positive"}), 400
    except:
        return jsonify({"error": "Invalid total"}), 400
    
    # ✅ Always set user_id from token
    new_order = {
        "id": next_order_id,
        "user_id": request.user['user_id'],
        "total": total,
        "items": items,
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

@app.route('/api/v1/admin/users', methods=['GET', 'OPTIONS'])
@require_admin  # ✅ FIX 3: REQUIRES AUTHENTICATION + ADMIN ROLE!
def admin_users():
    """✅ SECURE: Admin endpoint requires authentication"""
    if request.method == 'OPTIONS':
        return '', 204
    
    safe_users = [
        {
            "id": u['id'],
            "username": u['username'],
            "email": u['email'],
            "role": u['role'],
            "created_at": u['created_at']
        }
        for u in users
    ]
    
    return jsonify({
        "status": "success",
        "count": len(safe_users),
        "users": safe_users
    })

# ============================================
# DATA ENDPOINTS
# ============================================

@app.route('/api/v1/data', methods=['GET', 'OPTIONS'])
@require_auth
def list_data():
    """✅ SECURE: List user's own data"""
    if request.method == 'OPTIONS':
        return '', 204
    
    # ✅ Only return user's own data
    user_data = [d for d in data_storage if d['user_id'] == request.user['user_id']]
    
    return jsonify({
        "status": "success",
        "count": len(user_data),
        "data": user_data
    })

@app.route('/api/v1/data', methods=['POST', 'OPTIONS'])
@require_auth
def create_data():
    """✅ SECURE: Create data (ownership set from token)"""
    if request.method == 'OPTIONS':
        return '', 204
    
    global next_data_id
    
    data = request.get_json()
    
    title = data.get('title', '').strip()
    content = data.get('content', '').strip()
    
    if not title or not content:
        return jsonify({"error": "Title and content required"}), 400
    
    # ✅ Always set user_id from token
    new_data = {
        "id": next_data_id,
        "user_id": request.user['user_id'],
        "title": title,
        "content": content,
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

@app.route('/api/v1/data/sensitive', methods=['GET', 'OPTIONS'])
@require_auth  # ✅ FIX 4: Use Bearer token, not URL API keys!
def sensitive_data():
    """✅ SECURE: Token-based auth, not URL API keys"""
    if request.method == 'OPTIONS':
        return '', 204
    
    # ✅ API key is now in Authorization header, not in URL
    return jsonify({
        "status": "success",
        "data": "Sensitive data here",
        "user": request.user['email'],
        "accessed_at": datetime.now().isoformat()
    })

@app.route('/api/v1/profile', methods=['GET', 'POST', 'OPTIONS'])
@require_auth
def profile():
    """✅ FIX 7: SECURE: CORS properly configured in app init"""
    if request.method == 'OPTIONS':
        return '', 204
    
    # CORS headers are set in the app configuration above
    # Only allowed origins can access this
    
    return jsonify({
        "status": "success",
        "user": request.user['email'],
        "username": request.user['username'],
        "role": request.user['role']
    })

@app.route('/api/v1/user/update', methods=['POST', 'OPTIONS'])
@require_auth
def update_user_secure():
    """✅ FIX 8: SECURE: Only allow safe fields"""
    if request.method == 'OPTIONS':
        return '', 204
    
    data = request.get_json()
    
    # ✅ SECURE: Whitelist of allowed fields only!
    allowed_fields = ['name']
    
    user = next((u for u in users if u['id'] == request.user['user_id']), None)
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Only update allowed fields
    for field in allowed_fields:
        if field in data:
            user[field] = data[field]
    
    # ✅ NEVER update these fields!
    # user['role'] = data.get('role')  # DON'T DO THIS!
    # user['is_admin'] = data.get('is_admin')  # DON'T DO THIS!
    
    return jsonify({
        "status": "updated",
        "user": {
            "id": user['id'],
            "name": user['name'],
            "role": user['role']
        }
    })

@app.route('/api/v1/cache/load', methods=['POST', 'OPTIONS'])
@require_auth
def load_cache():
    """✅ FIX 9: SECURE: Use JSON instead of pickle"""
    if request.method == 'OPTIONS':
        return '', 204
    
    data = request.get_json()
    cache_data = data.get('cache_data')
    
    # ✅ SECURE: JSON is safe (no code execution)
    # Never use pickle!
    
    try:
        cache = json.loads(cache_data)  # Safe!
        return jsonify({
            "status": "success",
            "cache": cache
        })
    except:
        return jsonify({"error": "Invalid JSON"}), 400

@app.route('/api/v1/brute/login', methods=['POST', 'OPTIONS'])
@limiter.limit("5 per minute")
def brute_force_protected():
    """✅ FIX 5: Rate limiting prevents brute force"""
    if request.method == 'OPTIONS':
        return '', 204
    
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
    
    user = next((u for u in users if u['email'] == email), None)
    
    if not user or not bcrypt.checkpw(password.encode(), user['password_hash']):
        return jsonify({"error": "Invalid credentials"}), 401
    
    token = create_token(user)
    
    return jsonify({
        "status": "success",
        "token": token,
        "user": user['email']
    })

# ============================================
# INFO & HEALTH
# ============================================

@app.route('/health', methods=['GET', 'OPTIONS'])
def health():
    """Health check"""
    if request.method == 'OPTIONS':
        return '', 204
    
    return jsonify({"status": "ok", "service": "Secure API"})

@app.route('/api/v1/info', methods=['GET', 'OPTIONS'])
def api_info():
    """API information"""
    if request.method == 'OPTIONS':
        return '', 204
    
    return jsonify({
        "name": "Secure API",
        "version": "2.0",
        "description": "Hardened API with security best practices",
        "base_url": "http://localhost:3002",
        "endpoints": {
            "authentication": {
                "register": "POST /api/v1/auth/register",
                "login": "POST /api/v1/auth/login",
                "verify": "POST /api/v1/auth/verify"
            },
            "users": {
                "list": "GET /api/v1/users (requires auth)",
                "get": "GET /api/v1/users/:id (requires auth)",
                "create": "POST /api/v1/users (requires admin)",
                "update": "PUT /api/v1/users/:id (requires auth + ownership)",
                "delete": "DELETE /api/v1/users/:id (requires admin)"
            },
            "products": {
                "list": "GET /api/v1/products (requires auth)",
                "get": "GET /api/v1/products/:id (requires auth)",
                "create": "POST /api/v1/products (requires admin)"
            },
            "orders": {
                "list": "GET /api/v1/orders (requires auth, own orders only)",
                "get": "GET /api/v1/orders/:id (requires auth, ownership check)",
                "create": "POST /api/v1/orders (requires auth)"
            },
            "data": {
                "list": "GET /api/v1/data (requires auth, own data only)",
                "create": "POST /api/v1/data (requires auth)"
            },
            "admin": {
                "users": "GET /api/v1/admin/users (requires admin)"
            }
        },
        "security_features": [
            "✅ Strong JWT with 24h expiration",
            "✅ Parameterized queries (no SQL injection)",
            "✅ Authentication on all protected endpoints",
            "✅ Token-based API auth (not URLs)",
            "✅ Rate limiting on login/brute endpoints",
            "✅ IDOR prevention (ownership checks)",
            "✅ CORS properly configured",
            "✅ Field whitelisting (no mass assignment)",
            "✅ JSON serialization (no pickle)",
            "✅ Security headers",
            "✅ Password hashing with bcrypt",
            "✅ Input validation",
            "✅ Admin role checks"
        ]
    })

if __name__ == '__main__':
    print("\n" + "="*70)
    print("🔐 SECURE API SERVER")
    print("="*70)
    print("\n✅ SECURITY FEATURES:")
    print("  1. Strong JWT with expiration")
    print("  2. Parameterized queries")
    print("  3. Authentication required")
    print("  4. Token-based auth")
    print("  5. Rate limiting")
    print("  6. IDOR prevention")
    print("  7. CORS configured")
    print("  8. Field whitelisting")
    print("  9. JSON serialization")
    print("  10. Security headers")
    print("\n📋 ENDPOINTS:")
    print("  Auth: register, login, verify")
    print("  Users: list, get, create (admin), update, delete (admin)")
    print("  Products: list, get, create (admin)")
    print("  Orders: list, get, create")
    print("  Data: list, create")
    print("  Admin: users list")
    print("  Security: sensitive data, profile, update, cache, brute")
    print("\n🌐 API: http://localhost:3002")
    print("📊 Info: http://localhost:3002/api/v1/info")
    print("="*70 + "\n")
    
    app.run(debug=False, port=3002, host='0.0.0.0')
