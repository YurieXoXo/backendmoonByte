import os
import sqlite3
from datetime import datetime, timedelta
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from jose import jwt

app = FastAPI()

# ---------- CONFIG ----------
SECRET_KEY = os.getenv("ADMIN_SECRET_KEY", "dev_secret")
ALGORITHM = "HS256"

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "password")

DB = "licenses.db"

# ---------- DATABASE ----------
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
    conn.commit()
    conn.close()

init_db()

# ---------- TOKEN ----------
def create_token(username: str):
    expire = datetime.utcnow() + timedelta(hours=2)
    return jwt.encode({"sub": username, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str):
    try:
        jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return True
    except:
        return False

# ---------- LOGIN PAGE ----------
@app.get("/admin", response_class=HTMLResponse)
def login_page():
    return """
    <h2>Admin Login</h2>
    <form method="post" action="/admin/login">
        <input name="username" placeholder="Username" required><br><br>
        <input name="password" type="password" placeholder="Password" required><br><br>
        <button type="submit">Login</button>
    </form>
    """

@app.post("/admin/login")
def login(username: str = Form(...), password: str = Form(...)):
    if username != ADMIN_USERNAME or password != ADMIN_PASSWORD:
        return RedirectResponse("/admin", status_code=302)

    token = create_token(username)
    response = RedirectResponse("/admin/dashboard", status_code=302)
    response.set_cookie("token", token)
    return response

# ---------- DASHBOARD ----------
@app.get("/admin/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    token = request.cookies.get("token")
    if not token or not verify_token(token):
        return RedirectResponse("/admin", status_code=302)

    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT * FROM licenses")
    keys = c.fetchall()
    conn.close()

    rows = ""
    for k in keys:
        rows += f"""
        <tr>
            <td>{k[0]}</td>
            <td>{k[1]}</td>
            <td>{k[2]}</td>
            <td>
                <form method="post" action="/admin/remove">
                    <input type="hidden" name="key" value="{k[0]}">
                    <button type="submit">Remove</button>
                </form>
            </td>
        </tr>
        """

    return f"""
    <h2>License Dashboard</h2>

    <h3>Add Key</h3>
    <form method="post" action="/admin/add">
        <input name="key" placeholder="License Key" required>
        <input name="days" type="number" placeholder="Days Valid" required>
        <button type="submit">Add</button>
    </form>

    <h3>Existing Keys</h3>
    <table border="1">
        <tr>
            <th>Key</th>
            <th>Expires</th>
            <th>HWID</th>
            <th>Action</th>
        </tr>
        {rows}
    </table>
    """

# ---------- ADD KEY ----------
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
        (key, expires, None)
    )
    conn.commit()
    conn.close()

    return RedirectResponse("/admin/dashboard", status_code=302)

# ---------- REMOVE KEY ----------
@app.post("/admin/remove")
def remove_key(request: Request, key: str = Form(...)):
    token = request.cookies.get("token")
    if not token or not verify_token(token):
        return RedirectResponse("/admin", status_code=302)

    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("DELETE FROM licenses WHERE key=?", (key,))
    conn.commit()
    conn.close()

    return RedirectResponse("/admin/dashboard", status_code=302)
