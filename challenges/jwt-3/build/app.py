
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
GUEST_USERNAME = read_secret('GUEST_USERNAME', 'analyst')
GUEST_PASSWORD = read_secret('GUEST_PASSWORD', 'sec@2024')
FLAG_USER = read_secret('FLAG_USER', 'FLAG{jwt_confusion_user_dev}')
FLAG_ADMIN = read_secret('FLAG_ADMIN', 'FLAG{jwt_confusion_admin_dev}')

# RSA keys for RS256 signing
# Loaded from env if provided, otherwise a fresh pair is generated at startup
# so no private key is stored in the repository.
def load_rsa_keys():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_pem = read_secret('JWT_PRIVATE_KEY')
    if private_pem:
        private_pem = private_pem.replace('\\n', '\n')
        private_key = serialization.load_pem_private_key(private_pem.encode('utf-8'), password=None)
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode('utf-8')

    public_pem = read_secret('JWT_PUBLIC_KEY')
    if public_pem:
        public_pem = public_pem.replace('\\n', '\n')
    else:
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode('utf-8')
    return private_pem, public_pem


JWT_PRIVATE_KEY, JWT_PUBLIC_KEY = load_rsa_keys()

# API prefix
API_PREFIX = '/api/jwt-3'


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


def create_jwt_rs256(payload, private_key):
    """Create a JWT token using RS256."""
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.backends import default_backend
        
        header = {'alg': 'RS256', 'typ': 'JWT'}
        header_encoded = base64url_encode(json.dumps(header))
        payload_encoded = base64url_encode(json.dumps(payload))
        
        message = f"{header_encoded}.{payload_encoded}".encode('utf-8')
        
        # Load private key
        key = serialization.load_pem_private_key(
            private_key.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
        
        # Sign with RS256
        signature = key.sign(
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        signature_encoded = base64url_encode(signature)
        return f"{header_encoded}.{payload_encoded}.{signature_encoded}"
        
    except ImportError:
        return create_jwt_hs256(payload, 'fallback_secret')


def create_jwt_hs256(payload, secret):
    """Create a JWT token using HS256."""
    header = {'alg': 'HS256', 'typ': 'JWT'}
    header_encoded = base64url_encode(json.dumps(header))
    payload_encoded = base64url_encode(json.dumps(payload))
    
    signature = hmac.new(
        secret.encode('utf-8') if isinstance(secret, str) else secret,
        f"{header_encoded}.{payload_encoded}".encode('utf-8'),
        hashlib.sha256
    ).digest()
    signature_encoded = base64url_encode(signature)
    
    return f"{header_encoded}.{payload_encoded}.{signature_encoded}"


def verify_jwt_vulnerable(token, public_key):
    """
    MY SUPER VULNERABLE VERIFICATION FUNCTION
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None, "Invalid token format"
        
        header_encoded, payload_encoded, signature_encoded = parts
        
        header = json.loads(base64url_decode(header_encoded))
        algorithm = header.get('alg', 'RS256')
        
        message = f"{header_encoded}.{payload_encoded}".encode('utf-8')
        actual_signature = base64url_decode(signature_encoded)
        

        if algorithm == 'HS256':
            expected_signature = hmac.new(
                public_key.encode('utf-8'),
                message,
                hashlib.sha256
            ).digest()
            
            if hmac.compare_digest(expected_signature, actual_signature):
                payload = json.loads(base64url_decode(payload_encoded))
                return payload, None
            else:
                return None, "Invalid signature"
        
        elif algorithm == 'RS256':
            try:
                from cryptography.hazmat.primitives import hashes, serialization
                from cryptography.hazmat.primitives.asymmetric import padding
                from cryptography.hazmat.backends import default_backend
                
                key = serialization.load_pem_public_key(
                    public_key.encode('utf-8'),
                    backend=default_backend()
                )
                
                try:
                    key.verify(
                        actual_signature,
                        message,
                        padding.PKCS1v15(),
                        hashes.SHA256()
                    )
                    payload = json.loads(base64url_decode(payload_encoded))
                    return payload, None
                except Exception:
                    return None, "Invalid signature"
                    
            except ImportError:
                return None, "RS256 verification not available"
        
        else:
            return None, f"Unsupported algorithm: {algorithm}"
        
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
        payload, error = verify_jwt_vulnerable(token, JWT_PUBLIC_KEY)
        
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
    Robots.txt with obscure hints (hard difficulty).
    """
    robots_content = """User-agent: *
Disallow: /old/
Disallow: /backup/
# Legacy endpoints should be cleaned up
# "The past often holds the key to the present"
"""
    return robots_content, 200, {'Content-Type': 'text/plain'}


@app.route('/old/config.old')
def old_config():
    """
    Old config file - contains credentials in hex format (hard).
    First part of credentials.
    """
    # Hex values for maintainability:
    # user_id: 0x616e616c797374 decodes to 'analyst'
    # auth_p1: 0x73656340 decodes to 'sec@'
    content = """# Legacy Configuration File
# ===========================
# Version: 0.1.0 (deprecated)
# 
# Auth Configuration (obfuscated):
# user_id: 0x616e616c797374
# auth_p1: 0x73656340
#
# Note: Second part of auth token is elsewhere
# Hint: Check the backup directory for more
"""
    return content, 200, {'Content-Type': 'text/plain'}


@app.route('/backup/auth.bak')
def backup_auth():
    """
    Backup file with second part of credentials (base64).
    """
    # Password part 2 '2024' in base64: MjAyNA==
    content = """# Auth backup - CONFIDENTIAL
# Created: 2024-01-01
#
# auth_p2 (encoded): MjAyNA==
#
# Full auth: combine hex username + hex p1 + base64 p2
"""
    return content, 200, {'Content-Type': 'text/plain'}


@app.route('/api/jwt-3/pubkey')
def get_public_key():
    """
    Exposed public key endpoint.
    This is intentionally exposed - needed for the confusion attack.
    """
    return JWT_PUBLIC_KEY, 200, {'Content-Type': 'text/plain'}


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
    Login endpoint - authenticates user and returns JWT token (RS256).
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
            token = create_jwt_rs256(payload, JWT_PRIVATE_KEY)
            
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
        'secret': 'You have successfully exploited the JWT algorithm confusion vulnerability!'
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
