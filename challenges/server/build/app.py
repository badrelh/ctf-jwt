import os
import base64
import time
from functools import wraps
from typing import Dict

import jwt
import requests
from flask import Flask, jsonify, request, render_template, send_from_directory, abort

app = Flask(__name__)

# ---------------------------
# Secrets utils 
# ---------------------------
def parse_env_file(content: str) -> Dict[str, str]:
    env: Dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        if k:
            env[k] = v
    return env

def load_secrets(secret_name: str, defaults: Dict[str, str]) -> Dict[str, str]:
    secret_path = os.path.join("/run/secrets", secret_name)
    cfg = dict(defaults)

    try:
        if os.path.exists(secret_path):
            with open(secret_path, "r", encoding="utf-8") as f:
                parsed = parse_env_file(f.read())
            cfg.update(parsed)
        else:
            for k in defaults.keys():
                if os.environ.get(k):
                    cfg[k] = os.environ[k]
    except Exception:
        pass

    return cfg

DEFAULTS = {
    "PORT": "5004",
    "GUEST_USERNAME": "guest",
    "GUEST_PASSWORD": "passwordguest",
    "JWT_SECRET": "dev-secret",
    "FLAG_USER": "FLAG{USER_SSRF}",
    "FLAG_INTERNAL": "FLAG{SSRF_success}",
    "UPLOAD_DIR": "/app/images",
}

config = load_secrets("ssrf_env", DEFAULTS)

PORT = int(config.get("PORT", "5004"))
JWT_SECRET = config.get("JWT_SECRET", "dev-secret")
UPLOAD_DIR = config.get("UPLOAD_DIR", "/app/images")

# ---------------------------
# JWT helpers
# ---------------------------
def issue_token(username: str, role: str) -> str:
    payload = {
        "username": username,
        "role": role,
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def require_jwt(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"message": "Authorization header missing"}), 401
        token = auth.split(" ", 1)[1].strip()
        if not token:
            return jsonify({"message": "Token missing"}), 401
        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except Exception as e:
            return jsonify({"message": "Token verification failed", "error": str(e)}), 401
        request.user = decoded  
        return fn(*args, **kwargs)
    return wrapper

# ---------------------------
# Frontend pages
# ---------------------------
@app.get("/")
def home():
    return render_template("index.html")

@app.get("/guest")
def guest_page():
    return render_template("guest.html")

@app.get("/user")
def user_page():
    return render_template("user.html")

@app.get("/admin")
def admin_page():
    return render_template("admin.html")

@app.get("/health")
def health():
    return "ok", 200

# Serve robots from static
@app.get("/robots.txt")
def robots():
    return send_from_directory("static", "robots.txt")

# ---------------------------
# Credential hunt endpoints (dirsearch friendly)
# ---------------------------
@app.get("/backup/creds.bak")
def backup_creds():
    raw = f"{config['GUEST_USERNAME']}:{config['GUEST_PASSWORD']}".encode("utf-8")
    b64 = base64.b64encode(raw).decode("ascii")
    return (
        "# backup file\n"
        "# \n"
        f"{b64}\n",
        200,
        {"Content-Type": "text/plain; charset=utf-8"},
    )

# ---------------------------
# Internal flag endpoint
# ---------------------------
@app.get("/internal/flag")
def internal_flag():
    raw_ip = request.remote_addr or ""
    ip = raw_ip.replace("::ffff:", "")
    # Loopback only: the SSRF request comes from inside the container. Docker's bridge
    # gateway (172.x) is what the host's published port looks like, so it must not match.
    if ip == "127.0.0.1" or ip == "::1":
        return config["FLAG_INTERNAL"], 200
    return "Access refused", 403

# http://127.0.0.1:5004/internal/flag

# ---------------------------
# API: login + me
# ---------------------------
@app.post("/server/login")
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", ""))
    password = str(data.get("password", ""))

    if username == config["GUEST_USERNAME"] and password == config["GUEST_PASSWORD"]:
        token = issue_token(username=username, role="user")
        return jsonify({"message": "login successful", "token": token}), 200

    return jsonify({"message": "login failed"}), 401

@app.get("/server/me")
@require_jwt
def me():
    user = getattr(request, "user", {})  # type: ignore
    return jsonify(
        {
            "username": user.get("username"),
            "role": user.get("role"),
            "flag_user": config["FLAG_USER"],
        }
    ), 200

# ---------------------------
# API: profile image upload
# ---------------------------
def fetch_raw(url: str, timeout: int = 8):
    r = requests.get(
        url,
        timeout=timeout,
        allow_redirects=True,
        headers={
            "User-Agent": "CTF-ImageProxy/1.0",
            "Accept": "*/*",
        },
        stream=True,
    )
    content_type = r.headers.get("Content-Type", "")
    data = r.content
    return r.status_code, content_type, data

@app.post("/server/profile-image")
@require_jwt
def profile_image():
    data = request.get_json(silent=True) or {}
    url = str(data.get("url", "")).strip()

    if not url:
        return jsonify({"message": "URL missing"}), 400
    if not (url.lower().startswith("http://") or url.lower().startswith("https://")):
        return jsonify({"message": "Invalid URL format"}), 400

    try:
        status, content_type, body = fetch_raw(url)

        if not content_type.lower().startswith("image/"):
            text = body.decode("utf-8", errors="replace")
            if len(text) > 20000:
                text = text[:20000] + "\n[truncated]"
            return jsonify(
                {
                    "message": "Non-image content detected",
                    "status": status,
                    "type": content_type,
                    "content": text,
                }
            ), 200

        os.makedirs(UPLOAD_DIR, exist_ok=True)
        ext = "bin"
        try:
            ext = content_type.split("/")[1].split(";")[0].strip() or "bin"
        except Exception:
            ext = "bin"

        filename = f"profile_{int(time.time()*1000)}.{ext}"
        path = os.path.join(UPLOAD_DIR, filename)

        with open(path, "wb") as f:
            f.write(body)

        return jsonify(
            {
                "message": "Image saved",
                "status": status,
                "url": f"/images/{filename}",
                "size": len(body),
                "type": content_type,
            }
        ), 200

    except Exception as e:
        return jsonify({"message": "Internal error", "error": str(e)}), 500

# Serve saved images
@app.get("/images/<path:filename>")
def images(filename: str):
    return send_from_directory(UPLOAD_DIR, filename)
