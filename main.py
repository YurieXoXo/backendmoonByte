from fastapi import FastAPI
from pydantic import BaseModel
from datetime import datetime
import sqlite3
import hashlib
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key

app = FastAPI()

# Load or generate RSA private key
with open("private_key.pem", "rb") as f:
    private_key = load_pem_private_key(f.read(), password=None)

DB = "licenses.db"

class LicenseRequest(BaseModel):
    key: str
    hwid: str

def get_license(key):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT key, expires, hwid FROM licenses WHERE key=?", (key,))
    result = c.fetchone()
    conn.close()
    return result

@app.post("/validate")
def validate_license(data: LicenseRequest):
    record = get_license(data.key)

    if not record:
        return {"valid": False}

    key, expires, stored_hwid = record

    if datetime.strptime(expires, "%Y-%m-%d") < datetime.utcnow():
        return {"valid": False}

    if stored_hwid and stored_hwid != data.hwid:
        return {"valid": False}

    if not stored_hwid:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute("UPDATE licenses SET hwid=? WHERE key=?", (data.hwid, data.key))
        conn.commit()
        conn.close()

    payload = {
        "valid": True,
        "expires": expires
    }

    message = json.dumps(payload).encode()

    signature = private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    return {
        "data": payload,
        "signature": signature.hex()
    }