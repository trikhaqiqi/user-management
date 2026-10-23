#!/usr/bin/env python3
"""End-to-end scenarios against a running gateway.

Reads codes and reset tokens from the mock mail provider: Mailpit when
MAILPIT_URL is set, otherwise the file outbox (MAIL_OUTBOX_DIR). Between
sections it clears this run's rate-limit counters in Redis (REDIS_CLI) so
the scenarios don't trip the limits they aren't testing.

Usage: python3 scripts/e2e.py   (env: BASE_URL, AUTH_URL, MAILPIT_URL, OUTBOX_DIR, REDIS_CLI)
"""
import concurrent.futures as cf
import email
import glob
import json
import os
import re
import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.request

BASE = os.environ.get("BASE_URL", "http://localhost:8080")
AUTH_DIRECT = os.environ.get("AUTH_URL", "http://localhost:8091")
MAILPIT = os.environ.get("MAILPIT_URL", "")
OUTBOX = os.environ.get("OUTBOX_DIR", os.path.join(os.path.dirname(__file__), "..", "tmp", "outbox"))
REDIS_CLI = os.environ.get("REDIS_CLI", "redis-cli")
RUN = str(int(time.time()))
PASSWORD = "S3cure-pass-" + RUN

passed, failed = 0, 0


def call(method, path, body=None, token=None, headers=None, base=BASE, raw=None):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(base + path, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read() or b"{}"), r.headers
    except urllib.error.HTTPError as e:
        payload = e.read()
        try:
            return e.code, json.loads(payload or b"{}"), e.headers
        except json.JSONDecodeError:
            return e.code, {"raw": payload.decode(errors="replace")}, e.headers


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  \033[32mPASS\033[0m {name}")
    else:
        failed += 1
        print(f"  \033[31mFAIL\033[0m {name} {detail}")


def expect(name, res, status, code=None):
    st, body, _ = res
    got_code = (body.get("error") or {}).get("code")
    ok = st == status and (code is None or got_code == code)
    check(name, ok, f"-> got {st} {got_code} {json.dumps(body)[:300]}")
    return body


def section(title):
    print(f"\n== {title}")
    reset_limits()


def reset_limits():
    try:
        for pattern in ("gw:*", "auth:login_fail:*"):
            keys = subprocess.run([*shlex.split(REDIS_CLI), "--scan", "--pattern", pattern], capture_output=True, text=True).stdout.split()
            if keys:
                subprocess.run([*shlex.split(REDIS_CLI), "DEL", *keys], capture_output=True)
    except FileNotFoundError:
        pass


def mails_to(addr):
    """Plain-text bodies of messages to addr, newest first."""
    if MAILPIT:
        with urllib.request.urlopen(f"{MAILPIT}/api/v1/search?query=to:{addr}&limit=20") as r:
            ids = [m["ID"] for m in json.load(r)["messages"]]
        out = []
        for i in ids:
            with urllib.request.urlopen(f"{MAILPIT}/api/v1/message/{i}") as r:
                out.append(json.load(r)["Text"])
        return out
    bodies = []
    for path in sorted(glob.glob(os.path.join(OUTBOX, "*.eml")), reverse=True):
        with open(path) as f:
            msg = email.message_from_file(f)
        if msg["To"] == addr:
            bodies.append(msg.get_payload())
    return bodies


def wait_mail(addr, pattern, newer_than=0):
    for _ in range(40):
        bodies = mails_to(addr)
        if len(bodies) > newer_than:
            m = re.search(pattern, bodies[0])
            if m:
                return m.group(1)
        time.sleep(0.25)
    raise SystemExit(f"no mail to {addr} matching {pattern}")


def otp_for(addr, before):
    return wait_mail(addr, r"(?:code is|address):\s*(\d{6})", before)


def register(name, addr):
    before = len(mails_to(addr))
    res = call("POST", "/api/v1/auth/register", {"name": name, "email": addr, "password": PASSWORD})
    return res, before


def login(addr, password=None):
    return call("POST", "/api/v1/auth/login", {"email": addr, "password": password or PASSWORD})


# ---------------------------------------------------------------------------
alice = f"alice.{RUN}@example.com"
bob = f"bob.{RUN}@example.com"

section("Registration & validation")
res, before = register("Alice", alice)
body = expect("register returns 201", res, 201)
check("response never contains the OTP", "otp" not in json.dumps(body).lower() and not re.search(r"\b\d{6}\b", json.dumps(body.get("data", {}).get("email", ""))))
check("account starts unverified", body.get("data", {}).get("status") == "pending_verification")
expect("duplicate email (different case) is rejected", register("Alice2", alice.upper())[0], 409, "EMAIL_ALREADY_REGISTERED")
expect("weak password is rejected", call("POST", "/api/v1/auth/register", {"name": "X", "email": f"x.{RUN}@example.com", "password": "short"}), 400, "VALIDATION_ERROR")
expect("invalid email is rejected", call("POST", "/api/v1/auth/register", {"name": "X", "email": "nope", "password": PASSWORD}), 400, "VALIDATION_ERROR")
expect("unknown field is rejected", call("POST", "/api/v1/auth/register", {"name": "X", "email": f"y.{RUN}@example.com", "password": PASSWORD, "status": "active"}), 400, "VALIDATION_ERROR")
expect("malformed JSON is rejected", call("POST", "/api/v1/auth/register", raw=b"{nope"), 400, "INVALID_JSON")
expect("login before verification is refused", login(alice), 403, "EMAIL_NOT_VERIFIED")

section("OTP verification")
code = otp_for(alice, before)
wrong = "000000" if code != "000000" else "111111"
expect("wrong OTP is rejected", call("POST", "/api/v1/auth/verify-otp", {"email": alice, "otp": wrong}), 400, "INVALID_OTP")
expect("resend inside cooldown is throttled", call("POST", "/api/v1/auth/resend-otp", {"email": alice}), 429, "OTP_RESEND_COOLDOWN")
expect("resend for unknown email is generic", call("POST", "/api/v1/auth/resend-otp", {"email": f"ghost.{RUN}@example.com"}), 200)
with cf.ThreadPoolExecutor(5) as ex:
    results = list(ex.map(lambda _: call("POST", "/api/v1/auth/verify-otp", {"email": alice, "otp": code})[0], range(5)))
check("5 concurrent verifications with the right code: exactly one succeeds", results.count(200) == 1, str(results))
expect("used OTP cannot be replayed", call("POST", "/api/v1/auth/verify-otp", {"email": alice, "otp": code}), 400, "INVALID_OTP")

section("OTP attempt limit")
res, before = register("Bob", bob)
otp_for(bob, before)
statuses = [call("POST", "/api/v1/auth/verify-otp", {"email": bob, "otp": "123450"})[1].get("error", {}).get("code") for _ in range(5)]
check("5th wrong attempt exhausts the code", statuses[-1] == "OTP_ATTEMPTS_EXCEEDED", str(statuses))
real = otp_for(bob, before)
expect("even the right code fails after exhaustion", call("POST", "/api/v1/auth/verify-otp", {"email": bob, "otp": real}), 400, "INVALID_OTP")

section("Login")
expect("wrong password gives generic 401", login(alice, "Wrong-pass-1"), 401, "INVALID_CREDENTIALS")
expect("unknown email gives the same generic 401", login(f"nobody.{RUN}@example.com"), 401, "INVALID_CREDENTIALS")
body = expect("login succeeds", login(alice.upper()), 200)
tokens = body["data"]
check("token pair returned", tokens.get("token_type") == "Bearer" and tokens.get("access_token") and tokens.get("refresh_token"))

section("Authenticated access & gateway trust boundary")
access = tokens["access_token"]
me = expect("GET /users/me with token", call("GET", "/api/v1/users/me", token=access), 200)
check("profile hides password hash", "password" not in json.dumps(me))
expect("no token is rejected", call("GET", "/api/v1/users/me"), 401, "MISSING_TOKEN")
expect("tampered token is rejected", call("GET", "/api/v1/users/me", token=access[:-4] + "AAAA"), 401, "INVALID_TOKEN")
alg_none = access.split(".")[0][:0] + "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." + access.split(".")[1] + "."
expect("alg=none token is rejected", call("GET", "/api/v1/users/me", token=alg_none), 401, "INVALID_TOKEN")
expect("forged X-User-ID without token is rejected", call("GET", "/api/v1/users/me", headers={"X-User-ID": me["data"]["id"]}), 401, "MISSING_TOKEN")
try:
    expect("calling auth-service directly (no internal token) is rejected",
           call("POST", "/api/v1/auth/login", {"email": alice, "password": PASSWORD}, base=AUTH_DIRECT, headers={"X-Internal-Token": "guess"}), 401, "UNTRUSTED_CALLER")
except urllib.error.URLError:
    print("  (skipped direct-call check: auth-service not reachable from here)")

section("Profile update")
upd = expect("PATCH name and phone", call("PATCH", "/api/v1/users/me", {"name": "Alice Liddell", "phone_number": "+6281234567890"}, token=access), 200)
check("profile updated", upd["data"]["name"] == "Alice Liddell" and upd["data"]["phone_number"] == "+6281234567890")
for field, value in (("email", "evil@example.com"), ("status", "active"), ("email_verified", True), ("id", "x")):
    expect(f"protected field '{field}' cannot be modified", call("PATCH", "/api/v1/users/me", {field: value}, token=access), 400, "VALIDATION_ERROR")
expect("empty patch is rejected", call("PATCH", "/api/v1/users/me", {}, token=access), 400, "NO_CHANGES")
expect("invalid phone is rejected", call("PATCH", "/api/v1/users/me", {"phone_number": "0812"}, token=access), 400, "VALIDATION_ERROR")
cleared = expect("empty phone clears it", call("PATCH", "/api/v1/users/me", {"phone_number": ""}, token=access), 200)
check("phone cleared", cleared["data"]["phone_number"] is None)

section("Refresh rotation & reuse detection")
r1 = tokens["refresh_token"]
rot = expect("refresh rotates", call("POST", "/api/v1/auth/refresh", {"refresh_token": r1}), 200)["data"]
check("new refresh token differs", rot["refresh_token"] != r1)
expect("old refresh token reuse is detected", call("POST", "/api/v1/auth/refresh", {"refresh_token": r1}), 401, "REFRESH_TOKEN_REUSED")
expect("...and the whole session is revoked (new refresh fails)", call("POST", "/api/v1/auth/refresh", {"refresh_token": rot["refresh_token"]}), 401, "INVALID_REFRESH_TOKEN")
expect("...and its access token stops working immediately", call("GET", "/api/v1/users/me", token=rot["access_token"]), 401, "SESSION_REVOKED")

fresh = login(alice)[1]["data"]
with cf.ThreadPoolExecutor(5) as ex:
    results = list(ex.map(lambda _: call("POST", "/api/v1/auth/refresh", {"refresh_token": fresh["refresh_token"]})[0], range(5)))
check("5 concurrent refreshes with one token: exactly one succeeds", results.count(200) == 1, str(results))

section("Logout")
s = login(alice)[1]["data"]
expect("logout", call("POST", "/api/v1/auth/logout", {"refresh_token": s["refresh_token"]}), 200)
expect("refresh after logout fails", call("POST", "/api/v1/auth/refresh", {"refresh_token": s["refresh_token"]}), 401, "INVALID_REFRESH_TOKEN")
expect("access token after logout fails", call("GET", "/api/v1/users/me", token=s["access_token"]), 401, "SESSION_REVOKED")
expect("logout is idempotent", call("POST", "/api/v1/auth/logout", {"refresh_token": s["refresh_token"]}), 200)

section("Change password")
a = login(alice)[1]["data"]
b = login(alice)[1]["data"]
expect("wrong current password", call("POST", "/api/v1/auth/change-password", {"current_password": "Nope-12345", "new_password": "N3w-pass-" + RUN}, token=a["access_token"]), 400, "INVALID_CURRENT_PASSWORD")
expect("same password rejected", call("POST", "/api/v1/auth/change-password", {"current_password": PASSWORD, "new_password": PASSWORD}, token=a["access_token"]), 400, "VALIDATION_ERROR")
NEWPW = "N3w-pass-" + RUN
expect("change password", call("POST", "/api/v1/auth/change-password", {"current_password": PASSWORD, "new_password": NEWPW}, token=a["access_token"]), 200)
expect("current session keeps working", call("GET", "/api/v1/users/me", token=a["access_token"]), 200)
expect("other sessions are signed out", call("GET", "/api/v1/users/me", token=b["access_token"]), 401, "SESSION_REVOKED")
expect("old password no longer works", login(alice), 401, "INVALID_CREDENTIALS")
PASSWORD = NEWPW

section("Forgot / reset password")
s1 = login(alice)[1]["data"]
before = len(mails_to(alice))
expect("forgot-password (existing)", call("POST", "/api/v1/auth/forgot-password", {"email": alice}), 200)
ghost = expect("forgot-password (unknown) gives identical response", call("POST", "/api/v1/auth/forgot-password", {"email": f"ghost.{RUN}@example.com"}), 200)
token = wait_mail(alice, r"reset token with POST /api/v1/auth/reset-password:\s*(\S+)", before)
expect("reset with weak password is rejected (token not consumed)", call("POST", "/api/v1/auth/reset-password", {"token": token, "new_password": "weak"}), 400, "VALIDATION_ERROR")
RESETPW = "R3set-pass-" + RUN
expect("reset password", call("POST", "/api/v1/auth/reset-password", {"token": token, "new_password": RESETPW}), 200)
expect("reset token cannot be reused", call("POST", "/api/v1/auth/reset-password", {"token": token, "new_password": RESETPW + "x"}), 400, "INVALID_RESET_TOKEN")
expect("existing sessions revoked after reset", call("POST", "/api/v1/auth/refresh", {"refresh_token": s1["refresh_token"]}), 401, "INVALID_REFRESH_TOKEN")
expect("bogus reset token rejected", call("POST", "/api/v1/auth/reset-password", {"token": "x" * 43, "new_password": RESETPW}), 400, "INVALID_RESET_TOKEN")
PASSWORD = RESETPW
expect("login with new password", login(alice), 200)

section("Reset verifies a pending account (email ownership proven)")
before = len(mails_to(bob))
call("POST", "/api/v1/auth/forgot-password", {"email": bob})
tok = wait_mail(bob, r"reset token with POST /api/v1/auth/reset-password:\s*(\S+)", before)
expect("reset on pending account", call("POST", "/api/v1/auth/reset-password", {"token": tok, "new_password": PASSWORD}), 200)
expect("bob can now log in", login(bob), 200)

section("Change email")
s = login(alice)[1]["data"]
expect("change to an email already in use", call("POST", "/api/v1/users/me/change-email", {"new_email": bob, "current_password": PASSWORD}, token=s["access_token"]), 409, "EMAIL_ALREADY_REGISTERED")
expect("change requires correct password", call("POST", "/api/v1/users/me/change-email", {"new_email": f"new.{RUN}@example.com", "current_password": "Wrong-123"}, token=s["access_token"]), 400, "INVALID_CURRENT_PASSWORD")
new_alice = f"alice.new.{RUN}@example.com"
before = len(mails_to(new_alice))
expect("request email change", call("POST", "/api/v1/users/me/change-email", {"new_email": new_alice, "current_password": PASSWORD}, token=s["access_token"]), 202)
me = call("GET", "/api/v1/users/me", token=s["access_token"])[1]["data"]
check("email unchanged until verified", me["email"] == alice)
code = otp_for(new_alice, before)
expect("wrong code rejected", call("POST", "/api/v1/users/me/change-email/verify", {"otp": "000000" if code != "000000" else "111111"}, token=s["access_token"]), 400, "INVALID_OTP")
done = expect("verify email change", call("POST", "/api/v1/users/me/change-email/verify", {"otp": code}, token=s["access_token"]), 200)
check("email updated", done["data"]["email"] == new_alice)
expect("old email no longer logs in", login(alice), 401, "INVALID_CREDENTIALS")
expect("new email logs in", login(new_alice), 200)

section("Deactivation")
s = login(new_alice)[1]["data"]
expect("deactivate requires correct password", call("POST", "/api/v1/users/me/deactivate", {"current_password": "Wrong-123"}, token=s["access_token"]), 400, "INVALID_CURRENT_PASSWORD")
expect("deactivate", call("POST", "/api/v1/users/me/deactivate", {"current_password": PASSWORD}, token=s["access_token"]), 200)
expect("access token rejected immediately", call("GET", "/api/v1/users/me", token=s["access_token"]), 401, "SESSION_REVOKED")
expect("refresh token rejected", call("POST", "/api/v1/auth/refresh", {"refresh_token": s["refresh_token"]}), 401, "INVALID_REFRESH_TOKEN")
expect("login refused", login(new_alice), 403, "ACCOUNT_DEACTIVATED")
expect("forgot-password stays generic", call("POST", "/api/v1/auth/forgot-password", {"email": new_alice}), 200)

section("Rate limiting")
statuses = [login(bob, "Wrong-pass-1")[1].get("error", {}).get("code") for _ in range(6)]
check("per-account lockout after 5 failures", statuses[-1] == "TOO_MANY_LOGIN_ATTEMPTS", str(statuses))
_, _, hdrs = login(bob, "Wrong-pass-1")
check("lockout carries Retry-After", hdrs.get("Retry-After") is not None)
reset_limits()
codes = [call("POST", "/api/v1/auth/resend-otp", {"email": f"rl.{RUN}@example.com"})[0] for _ in range(12)]
check("gateway per-IP limit on auth endpoints (10/min)", codes[:10] == [200] * 10 and codes[10] == 429, str(codes))
reset_limits()

section("Logs contain no secrets")
LOG_DIR = os.environ.get("LOG_DIR", os.path.join(os.path.dirname(__file__), "..", "tmp", "logs"))
log_files = glob.glob(os.path.join(LOG_DIR, "*.log"))
if log_files and not MAILPIT:
    time.sleep(0.5)  # let the last access-log lines flush
    logs = "".join(open(f).read() for f in log_files)
    sent = set()
    for path in glob.glob(os.path.join(OUTBOX, "*.eml")):
        body = email.message_from_file(open(path)).get_payload()
        sent.update(re.findall(r"(?:code is|address):\s*(\d{6})", body))
        sent.update(re.findall(r"reset-password:\s*(\S+)", body))
    leaked = [x for x in sent if re.search(r"(?<![0-9A-Za-z_-])" + re.escape(x) + r"(?![0-9A-Za-z_-])", logs)]
    check(f"none of the {len(sent)} emailed OTPs/reset tokens appear in logs", not leaked, str(leaked[:3]))
    check("no JWT appears in logs", not re.search(r"eyJ[A-Za-z0-9_-]{20,}\.", logs))
    check("no password or token field is logged unredacted",
          not re.search(r'"(?:password|new_password|current_password|refresh_token|access_token|otp|token)":"(?!\[REDACTED\])', logs))
    check(f"this run's password never appears in logs", PASSWORD not in logs and NEWPW not in logs)
else:
    print("  (skipped: run against `make run` with the file mail driver to scan logs)")

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
