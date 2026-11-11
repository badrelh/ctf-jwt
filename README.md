# CTF JWT Security Challenges

A collection of four Flask CTF challenges focused on JWT (JSON Web Token) security and on web flaws around it. The challenges are designed to be imported into [CTFd](https://ctfd.io) with [ctfcli](https://github.com/CTFd/ctfcli).

> **Warning:** these applications are intentionally vulnerable. Run them locally or on an isolated lab network only. Do not expose them to the internet.

## Challenges

| # | Challenge | Category | Points (user + admin) | Topic |
|---|-----------|----------|-----------------------|-------|
| 1 | First JWT | Web Security | 100 + 200 | `alg: none` acceptance |
| 2 | Second JWT | Web Security | 150 + 250 | Weak HS256 secret, credentials split across files |
| 3 | Third JWT | Web Security | 200 + 350 | RS256 → HS256 algorithm confusion |
| 4 | Server | Web Security | 150 + 300 | Hidden paths, SSRF to an internal endpoint |

Each challenge has two flags (user and admin). `challenge.yml` sets `logic: all`, so a team needs both flags to solve it. The `value` in `challenge.yml` is the total of the two points.

### 1. First JWT
A JWT algorithm validation challenge. Find the guest credentials in `robots.txt` and the backup file, log in, then forge a token with `alg: none` to get the admin role.

### 2. Second JWT
The guest credentials are split across several files and encoded. The JWT is signed with HS256 using a weak secret that you can crack, then forged with the admin role.

### 3. Third JWT
Credentials are obfuscated (hex, base64) across legacy files. The API signs tokens with RS256 and exposes its public key. Abuse the verifier's trust in the `alg` header to forge an HS256 token signed with that public key.

### 4. Server
A Flask backend with a profile-image feature that fetches remote URLs. Find the guest credentials, then use the server-side fetch (SSRF) to reach an endpoint that is only reachable from inside the container.

## Structure

```
challenges/<challenge-name>/
├── challenge.yml          # ctfcli challenge definition (CTFd integration)
└── build/                 # Docker build context
    ├── Dockerfile
    ├── app.py             # Flask backend application
    ├── requirements.txt
    ├── templates/         # HTML templates
    └── static/            # CSS, JavaScript, and static assets
```

## Running a challenge locally

```bash
cd challenges/<challenge-name>/build
docker build -t jwt-<name> .
docker run -p 5000:5000 -e PORT=5000 jwt-<name>
```

Then open http://localhost:5000.

## Configuration

Every value below can be set as an environment variable. If it is not set, the built-in default is used. The defaults are the intended challenge values (for example `guest` / `guest123`), so you only need to set them when you deploy your own copy.

| Variable | Used by | Description |
|----------|---------|-------------|
| `PORT` | all | Listening port (jwt-1/2/3: 5000, server: 5004) |
| `GUEST_USERNAME` | all | Guest account username |
| `GUEST_PASSWORD` | all | Guest account password |
| `FLAG_USER` | all | User flag |
| `FLAG_ADMIN` | jwt-1, jwt-2, jwt-3 | Admin flag |
| `FLAG_INTERNAL` | server | Flag returned by the internal endpoint |
| `JWT_SECRET` | jwt-1, jwt-2, server | HMAC secret (jwt-2 default is the weak secret to crack) |
| `JWT_PRIVATE_KEY` | jwt-3 | Optional PEM private key. If unset, a fresh RSA key is generated at startup |
| `JWT_PUBLIC_KEY` | jwt-3 | Optional PEM public key. Derived from the private key if unset |

Values can also be read from `/run/secrets/<NAME>` (Docker secrets).

When you change a flag or secret, update the matching flag in `challenge.yml` so CTFd accepts the answer.

## Importing into CTFd with ctfcli

Install ctfcli and point it at your CTFd instance (see the [ctfcli documentation](https://docs.ctfd.io/docs/management/ctfcli/challenges)):

```bash
pip install ctfcli
ctf init
ctf challenge install challenges/jwt-1
```

Repeat for `jwt-2`, `jwt-3` and `server`.

`connection_info` in each `challenge.yml` points to the local container ports (jwt-1: 5001, jwt-2: 5002, jwt-3: 5003, server: 5004). Change it to the public URL of the deployed container before you install.

## Tests

The tests use pytest. The API tests call the challenge containers and CTFd directly. The UI tests drive a real browser with Playwright. Both expect the four challenge containers to be running on ports 5001 to 5004, and CTFd on port 8000.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r tests/requirements-dev.txt

# API tests, in parallel (set CTFD_ADMIN_TOKEN to include the CTFd checks)
CTFD_ADMIN_TOKEN=<token> pytest tests/api -n 4

# Browser tests (use your installed Chrome, or drop the option to use Playwright's Chromium)
python -m playwright install chromium    # only if you do not pass --browser-channel
pytest tests/ui --browser-channel chrome
```

Environment variables:
- `CTFD_URL` (default `http://localhost:8000`)
- `CTFD_ADMIN_TOKEN` (CTFd admin API token; the CTFd checks are skipped without it)
- `JWT1_URL`, `JWT2_URL`, `JWT3_URL`, `SERVER_URL` to point at other hosts

## Git hooks

`.githooks/pre-commit` runs before each commit. It blocks secret and Terraform state files, refuses private key material, and checks that staged Python and YAML files parse. Enable it once per clone:

```bash
git config core.hooksPath .githooks
```
