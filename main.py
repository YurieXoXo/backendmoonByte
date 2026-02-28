import os
import sqlite3
import json
from datetime import datetime, timedelta
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse, JSONResponse
from pydantic import BaseModel
from jose import jwt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

app = FastAPI()

# ================= CONFIG =================
SECRET_KEY = os.getenv("ADMIN_SECRET_KEY", "dev_secret")
ALGORITHM = "HS256"
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "password")
PRIVATE_KEY_PEM = os.getenv("PRIVATE_KEY", "").encode()

if not PRIVATE_KEY_PEM:
    raise RuntimeError("PRIVATE_KEY environment variable not set")

private_key = serialization.load_pem_private_key(
    PRIVATE_KEY_PEM, password=None, backend=default_backend()
)

DB = "licenses.db"

# How many seconds before a user is considered "offline"
ONLINE_TIMEOUT_SECONDS = 90


# ================= DATABASE =================
def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            key TEXT PRIMARY KEY,
            expires TEXT,
            hwid TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS online_users (
            username TEXT PRIMARY KEY,
            last_seen TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


init_db()


# ================= HELPERS =================
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def cleanup_stale_users(conn):
    """Remove users who haven't sent a heartbeat within the timeout window."""
    cutoff = (datetime.utcnow() - timedelta(seconds=ONLINE_TIMEOUT_SECONDS)).isoformat()
    conn.execute("DELETE FROM online_users WHERE last_seen < ?", (cutoff,))
    conn.commit()


# ================= ADMIN AUTH =================
def create_token(username: str):
    expire = datetime.utcnow() + timedelta(hours=2)
    return jwt.encode({"sub": username, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(token: str):
    try:
        jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return True
    except:
        return False


# ================= ADMIN LOGIN PAGE =================
@app.get("/admin", response_class=HTMLResponse)
def login_page():
    return """
<h2>Admin Login</h2>
<form method="post" action="/admin/login">
    <input name="username" placeholder="Username" /><br/>
    <input name="password" type="password" placeholder="Password" /><br/>
    <button type="submit">Login</button>
</form>
"""


@app.post("/admin/login")
def login(username: str = Form(...), password: str = Form(...)):
    if username != ADMIN_USERNAME or password != ADMIN_PASSWORD:
        return RedirectResponse("/admin", status_code=302)
    token = create_token(username)
    response = RedirectResponse("/admin/dashboard", status_code=302)
    response.set_cookie("token", token, httponly=True)
    return response


# ================= ADMIN DASHBOARD =================
@app.get("/admin/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    token = request.cookies.get("token")
    if not token or not verify_token(token):
        return RedirectResponse("/admin", status_code=302)

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    # --- license keys ---
    c.execute("SELECT * FROM licenses")
    keys = c.fetchall()

    # --- online users ---
    cleanup_stale_users(conn)
    c.execute("SELECT username, last_seen FROM online_users ORDER BY username")
    online = c.fetchall()
    conn.close()

    rows = ""
    for k in keys:
        rows += f"""
<tr>
    <td>{k[0]}</td>
    <td>{k[1]}</td>
    <td>{k[2] or ""}</td>
    <td>
        <form method="post" action="/admin/remove" style="display:inline">
            <input type="hidden" name="key" value="{k[0]}" />
            <button type="submit">Remove</button>
        </form>
    </td>
</tr>"""

    online_rows = ""
    for u in online:
        online_rows += f"<tr><td>{u[0]}</td><td>{u[1]}</td></tr>"

    return f"""
<h2>License Dashboard</h2>

<h3>Add Key</h3>
<form method="post" action="/admin/add">
    <input name="key" placeholder="License Key" />
    <input name="days" type="number" placeholder="Days" value="30" />
    <button type="submit">Add</button>
</form>

<h3>Existing Keys</h3>
<table border="1" cellpadding="4">
    <tr><th>Key</th><th>Expires</th><th>HWID</th><th>Action</th></tr>
    {rows}
</table>

<h3>Online Users ({len(online)})</h3>
<table border="1" cellpadding="4">
    <tr><th>Username</th><th>Last Seen (UTC)</th></tr>
    {online_rows}
</table>
"""


@app.post("/admin/add")
def add_key(request: Request, key: str = Form(...), days: int = Form(...)):
    token = request.cookies.get("token")
    if not token or not verify_token(token):
        return RedirectResponse("/admin", status_code=302)
    expires = (datetime.utcnow() + timedelta(days=days)).strftime("%Y-%m-%d")
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute(
        "INSERT OR REPLACE INTO licenses (key, expires, hwid) VALUES (?, ?, ?)",
        (key.strip(), expires, None),
    )
    conn.commit()
    conn.close()
    return RedirectResponse("/admin/dashboard", status_code=302)


@app.post("/admin/remove")
def remove_key(request: Request, key: str = Form(...)):
    token = request.cookies.get("token")
    if not token or not verify_token(token):
        return RedirectResponse("/admin", status_code=302)
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("DELETE FROM licenses WHERE key=?", (key.strip(),))
    conn.commit()
    conn.close()
    return RedirectResponse("/admin/dashboard", status_code=302)


# ================= USER VALIDATION =================
class LicenseRequest(BaseModel):
    key: str
    hwid: str


@app.post("/validate")
def validate_license(data: LicenseRequest):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT key, expires, hwid FROM licenses WHERE key=?", (data.key.strip(),))
    record = c.fetchone()
    conn.close()

    if not record:
        return {"valid": False}

    key, expires, stored_hwid = record

    if datetime.strptime(expires, "%Y-%m-%d") < datetime.utcnow():
        return {"valid": False}

    # HWID binding
    if not stored_hwid:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute("UPDATE licenses SET hwid=? WHERE key=?", (data.hwid, data.key))
        conn.commit()
        conn.close()
    elif stored_hwid != data.hwid:
        return {"valid": False}

    payload = {"valid": True, "expires": expires}
    message = json.dumps(payload).encode()
    signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())

    return {"data": payload, "signature": signature.hex()}


# ================= ONLINE / HEARTBEAT =================
class HeartbeatRequest(BaseModel):
    username: str


@app.post("/heartbeat")
def heartbeat(data: HeartbeatRequest):
    """
    Client calls this every ~60 seconds to signal the user is online.
    """
    username = data.username.strip()
    if not username:
        return JSONResponse({"error": "username required"}, status_code=400)

    now = datetime.utcnow().isoformat()
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute(
        "INSERT OR REPLACE INTO online_users (username, last_seen) VALUES (?, ?)",
        (username, now),
    )
    conn.commit()
    conn.close()
    return {"status": "ok"}


@app.get("/online-users")
def online_users(format: str = "json"):
    """
    Returns the list of currently online MoonByte users.
    Supports ?format=json (default) or ?format=text (one name per line).
    """
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    cleanup_stale_users(conn)
    c.execute("SELECT username FROM online_users ORDER BY username")
    names = [row[0] for row in c.fetchall()]
    conn.close()

    if format == "text":
        return PlainTextResponse("\n".join(names))

    return JSONResponse(names)


@app.post("/logout")
def logout_user(data: HeartbeatRequest):
    """
    Optional: client calls this on shutdown to immediately remove the user.
    """
    username = data.username.strip()
    if not username:
        return JSONResponse({"error": "username required"}, status_code=400)

    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("DELETE FROM online_users WHERE username=?", (username,))
    conn.commit()
    conn.close()
    return {"status": "removed"}
