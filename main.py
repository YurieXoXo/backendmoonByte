import os
import sqlite3
from datetime import datetime, timedelta
from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt
from passlib.context import CryptContext
from fastapi.templating import Jinja2Templates

app = FastAPI()

# ---------- CONFIG ----------
SECRET_KEY = os.getenv("ADMIN_SECRET_KEY", "dev_secret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "password")

DB = "licenses.db"

security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
templates = Jinja2Templates(directory="templates")

# ---------- DATABASE INIT ----------
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

# ---------- AUTH ----------
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except:
        raise HTTPException(status_code=403, detail="Invalid token")

# ---------- LOGIN PAGE ----------
@app.get("/admin", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/admin/login")
def login(username: str = Form(...), password: str = Form(...)):
    if username != ADMIN_USERNAME or password != ADMIN_PASSWORD:
        return RedirectResponse("/admin", status_code=302)

    token = create_access_token({"sub": username})
    response = RedirectResponse("/admin/dashboard", status_code=302)
    response.set_cookie("token", token)
    return response

# ---------- DASHBOARD ----------
@app.get("/admin/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    token = request.cookies.get("token")
    if not token:
        return RedirectResponse("/admin")

    try:
        jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except:
        return RedirectResponse("/admin")

    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT * FROM licenses")
    keys = c.fetchall()
    conn.close()

    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "keys": keys}
    )

# ---------- ADD KEY ----------
@app.post("/admin/add")
def add_key(request: Request, key: str = Form(...), days: int = Form(...)):
    token = request.cookies.get("token")
    if not token:
        return RedirectResponse("/admin")

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
    if not token:
        return RedirectResponse("/admin")

    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("DELETE FROM licenses WHERE key=?", (key,))
    conn.commit()
    conn.close()

    return RedirectResponse("/admin/dashboard", status_code=302)
