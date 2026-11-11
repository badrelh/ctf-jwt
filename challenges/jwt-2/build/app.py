
import os
import json
import base64
import hmac
import hashlib
from functools import wraps
from flask import Flask, request, jsonify, render_template, send_from_directory

app = Flask(__name__)

# Configuration - Read from secrets or use defaults for development
def read_secret(secret_name, default_value=None):
    """Read secret from /run/secrets/<secret_name>, or from the environment, or return default.

    A secret file may hold the bare value, or a KEY=VALUE line with KEY == secret_name.
    Only that exact line is parsed, so values that contain '=' are kept intact.
    """
    secret_path = f"/run/secrets/{secret_name}"
    try:
        if os.path.exists(secret_path):
            with open(secret_path, 'r') as f:
                content = f.read().strip()
            prefix = f"{secret_name}="
            for line in content.splitlines():
                if line.startswith(prefix):
                    return line[len(prefix):].strip()
            return content
    except Exception:
        pass
    return os.environ.get(secret_name, default_value)


# Configuration values
PORT = int(read_secret('PORT', '5000'))
GUEST_USERNAME = read_secret('GUEST_USERNAME', 'developer')
GUEST_PASSWORD = read_secret('GUEST_PASSWORD', 'dev2024!')
FLAG_USER = read_secret('FLAG_USER', 'FLAG{jwt_weak_user_dev}')
FLAG_ADMIN = read_secret('FLAG_ADMIN', 'FLAG{jwt_weak_admin_dev}')
JWT_SECRET = read_secret('JWT_SECRET', 'ronaldo7')

# API prefix
API_PREFIX = '/api/jwt-2'


# ============================================
# JWT Helper Functions
# ============================================

def base64url_encode(data):
    """Base64url encode without padding."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def base64url_decode(data):
    """Base64url decode with padding fix."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)


def create_jwt(payload, secret, algorithm='HS256'):
    """Create a JWT token."""
    header = {'alg': algorithm, 'typ': 'JWT'}
    header_encoded = base64url_encode(json.dumps(header))
    payload_encoded = base64url_encode(json.dumps(payload))
    
    if algorithm == 'HS256':
        signature = hmac.new(
            secret.encode('utf-8'),
            f"{header_encoded}.{payload_encoded}".encode('utf-8'),
            hashlib.sha256
        ).digest()
        signature_encoded = base64url_encode(signature)
    else:
        signature_encoded = ''
    
    return f"{header_encoded}.{payload_encoded}.{signature_encoded}"


def verify_jwt(token, secret):
    """
    Standard JWT verification with HS256.
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None, "Invalid token format"
        
        header_encoded, payload_encoded, signature_encoded = parts
        
        header = json.loads(base64url_decode(header_encoded))
        algorithm = header.get('alg', 'HS256')
        
        # Only accept HS256
        if algorithm != 'HS256':
            return None, f"Unsupported algorithm: {algorithm}"
        
        expected_signature = hmac.new(
            secret.encode('utf-8'),
            f"{header_encoded}.{payload_encoded}".encode('utf-8'),
            hashlib.sha256
        ).digest()
        
        actual_signature = base64url_decode(signature_encoded)
        
        if hmac.compare_digest(expected_signature, actual_signature):
            payload = json.loads(base64url_decode(payload_encoded))
            return payload, None
        else:
            return None, "Invalid signature"
        
    except Exception as e:
        return None, f"Token verification failed: {str(e)}"


def token_required(f):
    """Decorator to require valid JWT token."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid Authorization header'}), 401
        
        token = auth_header[7:]  
        payload, error = verify_jwt(token, JWT_SECRET)
        
        if error:
            return jsonify({'error': error}), 401
        
        request.jwt_payload = payload
        return f(*args, **kwargs)
    
    return decorated


# ============================================
# Static Files & Frontend Routes
# ============================================

@app.route('/')
def index():
    """Serve the main frontend page."""
    return render_template('index.html', api_prefix=API_PREFIX)


@app.route('/health')
def health():
    """Health check endpoint."""
    return 'ok'


@app.route('/robots.txt')
def robots():
    """
    Robots.txt with vague hints .
    """
    robots_content = """User-agent: *
Disallow: /static/.well-known/
Disallow: /assets/
# Security through obscurity is never the answer
# Our developers sometimes leave notes in strange places...
"""
    return robots_content, 200, {'Content-Type': 'text/plain'}


@app.route('/static/.well-known/leak.txt')
def well_known_leak():
    """
    Hidden leak file - contains hint about where to find password.
    Part of the credential hunt.
    """
    content = """# Developer Notes - CONFIDENTIAL
# =================================
# 
# imagine website with HTML only 
#
"""
    return content, 200, {'Content-Type': 'text/plain'}


@app.route('/assets/notes.txt')
def assets_notes():
    """
    Another hidden file with partial info.
    """
    content = """Project Notes
=============
TODO:
- [ ] Remove debug credentials before production
- [ ] Check for hardcoded values in source code
- [ ] Ensure all secrets are stored securely
"""
    return content, 200, {'Content-Type': 'text/plain'}


@app.route('/static/<path:filename>')
def serve_static(filename):
    """Serve static files."""
    return send_from_directory('static', filename)


# ============================================
# API Endpoints
# ============================================

@app.route(f'{API_PREFIX}/login', methods=['POST'])
def login():
    """
    Login endpoint - authenticates user and returns JWT token.
    Accepts JSON: {"username": "...", "password": "..."}
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON body'}), 400
        
        username = data.get('username', '')
        password = data.get('password', '')
        
        if username == GUEST_USERNAME and password == GUEST_PASSWORD:
            payload = {
                'username': username,
                'role': 'user'
            }
            token = create_jwt(payload, JWT_SECRET)
            
            return jsonify({
                'message': 'Login successful',
                'token': token
            })
        
        return jsonify({'error': 'Invalid credentials'}), 401
        
    except Exception as e:
        return jsonify({'error': f'Login failed: {str(e)}'}), 500


@app.route(f'{API_PREFIX}/me', methods=['GET'])
@token_required
def me():
    """
    User profile endpoint - returns user info and FLAG_USER.
    Requires valid JWT token.
    """
    payload = request.jwt_payload
    username = payload.get('username', 'unknown')
    role = payload.get('role', 'unknown')
    
    return jsonify({
        'username': username,
        'role': role,
        'flag': FLAG_USER,
        'message': f'Welcome {username}! You have successfully authenticated.'
    })


@app.route(f'{API_PREFIX}/admin', methods=['GET'])
@token_required
def admin():
    """
    Admin endpoint - returns FLAG_ADMIN only if role=admin.
    """
    payload = request.jwt_payload
    role = payload.get('role', '')
    
    if role != 'admin':
        return jsonify({
            'error': 'Access denied. Admin role required.',
            'your_role': role
        }), 403
    
    return jsonify({
        'message': 'Welcome Admin!',
        'flag': FLAG_ADMIN,
        'secret': 'You have successfully cracked the weak JWT secret!'
    })


# ============================================
# Error Handlers
# ============================================

@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors."""
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def internal_error(e):
    """Handle 500 errors."""
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT, debug=False)
