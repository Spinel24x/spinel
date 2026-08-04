import os
import json
import uuid
import sqlite3
import subprocess
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext
from apscheduler.schedulers.background import BackgroundScheduler
import uvicorn

# ==================== Settings ====================
CF_DOMAIN = os.getenv("CF_DOMAIN", "")
USER_PASS = os.getenv("USER_PASS", "admin123")
PORT = int(os.getenv("PORT", "8000"))
DB_PATH = "/app/data/panel.db"
XRAY_PORT = 8080

print("=" * 50)
print(f"CF_DOMAIN: {CF_DOMAIN or 'NOT SET'}")
print(f"USER_PASS: {USER_PASS}")
print("=" * 50)

# ==================== Database ====================
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uuid TEXT UNIQUE NOT NULL,
            name TEXT DEFAULT '',
            remarks TEXT DEFAULT '',
            enabled INTEGER DEFAULT 1,
            traffic_limit_gb REAL DEFAULT 0,
            traffic_used_gb REAL DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now','localtime')),
            expire_at TEXT DEFAULT NULL
        );
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            config_id INTEGER DEFAULT NULL,
            FOREIGN KEY(config_id) REFERENCES configs(id)
        );
    """)
    conn.commit()
    conn.close()

init_db()

# ==================== Password Hashing ====================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def create_default_admin():
    conn = get_db()
    admin = conn.execute("SELECT * FROM users WHERE username = 'admin'").fetchone()
    hashed = pwd_context.hash(USER_PASS)
    if not admin:
        conn.execute(
            "INSERT INTO users (username, password, is_admin) VALUES ('admin', ?, 1)",
            (hashed,)
        )
    else:
        conn.execute("UPDATE users SET password = ? WHERE username = 'admin'", (hashed,))
    conn.commit()
    conn.close()

create_default_admin()

# ==================== Xray Manager ====================
xray_process = None

def generate_vless_link(config_uuid: str, remarks: str = "", name: str = "") -> str:
    if not CF_DOMAIN:
        return ""
    ws_path = f"/{config_uuid}"
    remark_text = remarks or name or "VLESS"
    return (
        f"vless://{config_uuid}@{CF_DOMAIN}:443"
        f"?encryption=none&security=tls&sni={CF_DOMAIN}"
        f"&alpn=h2,http/1.1&type=ws&host={CF_DOMAIN}"
        f"&path={ws_path}#{remark_text}"
    )

def build_xray_config():
    conn = get_db()
    configs = conn.execute("SELECT * FROM configs WHERE enabled = 1").fetchall()
    conn.close()

    inbounds = []
    for conf in configs:
        ws_path = f"/{conf['uuid']}"
        inbounds.append({
            "port": XRAY_PORT,
            "protocol": "vless",
            "settings": {
                "clients": [{"id": conf["uuid"], "flow": "xtls-rprx-vision"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {"path": ws_path}
            }
        })

    if not inbounds:
        dummy_uuid = str(uuid.uuid4())
        inbounds.append({
            "port": XRAY_PORT,
            "protocol": "vless",
            "settings": {
                "clients": [{"id": dummy_uuid, "flow": "xtls-rprx-vision"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {"path": f"/{dummy_uuid}"}
            }
        })

    config_data = {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": [{"protocol": "freedom", "settings": {}}]
    }

    Path("/app/configs").mkdir(parents=True, exist_ok=True)
    with open("/app/configs/active.json", "w") as f:
        json.dump(config_data, f, indent=2)

def restart_xray():
    global xray_process
    try:
        if xray_process and xray_process.poll() is None:
            xray_process.terminate()
            xray_process.wait(timeout=5)
    except:
        pass

    build_xray_config()
    xray_process = subprocess.Popen(
        ["/usr/local/bin/xray", "run", "-config", "/app/configs/active.json"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

# ==================== Session Manager ====================
sessions = {}

def get_current_user(request: Request):
    session_id = request.cookies.get("session_id")
    if not session_id or session_id not in sessions:
        raise HTTPException(status_code=401)
    return sessions[session_id]

def require_admin(request: Request):
    user = get_current_user(request)
    if not user.get("is_admin"):
        raise HTTPException(status_code=403)
    return user

# ==================== FastAPI App ====================
@asynccontextmanager
async def lifespan(app: FastAPI):
    restart_xray()
    scheduler = BackgroundScheduler()
    scheduler.add_job(restart_xray, 'interval', hours=6)
    scheduler.start()
    yield
    if scheduler.running:
        scheduler.shutdown()

app = FastAPI(lifespan=lifespan)

# Mount static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# ==================== Pages ====================
@app.get("/", response_class=RedirectResponse)
async def root():
    return RedirectResponse("/login")

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    try:
        get_current_user(request)
        return templates.TemplateResponse("dashboard.html", {"request": request})
    except HTTPException:
        return RedirectResponse("/login")

# ==================== Auth API ====================
@app.post("/api/login")
async def api_login(request: Request, username: str = Form(...), password: str = Form(...)):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()

    if not user or not pwd_context.verify(password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    session_id = secrets.token_hex(32)
    sessions[session_id] = {
        "id": user["id"],
        "username": user["username"],
        "is_admin": bool(user["is_admin"]),
        "config_id": user["config_id"]
    }

    response = JSONResponse({
        "success": True,
        "redirect": "/dashboard",
        "is_admin": bool(user["is_admin"]),
        "username": user["username"]
    })
    response.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True,
        samesite="lax",
        max_age=86400
    )
    return response

@app.post("/api/logout")
async def api_logout(request: Request):
    session_id = request.cookies.get("session_id")
    if session_id and session_id in sessions:
        del sessions[session_id]
    response = JSONResponse({"success": True})
    response.delete_cookie("session_id")
    return response

@app.get("/api/me")
async def api_me(request: Request):
    user = get_current_user(request)
    return {
        "username": user["username"],
        "is_admin": user["is_admin"],
        "config_id": user["config_id"]
    }

# ==================== Configs API ====================
@app.get("/api/configs")
async def get_configs(request: Request):
    require_admin(request)
    conn = get_db()
    rows = conn.execute("SELECT * FROM configs ORDER BY created_at DESC").fetchall()
    conn.close()

    return [{
        "id": r["id"],
        "uuid": r["uuid"],
        "name": r["name"],
        "remarks": r["remarks"],
        "enabled": bool(r["enabled"]),
        "traffic_limit_gb": r["traffic_limit_gb"],
        "traffic_used_gb": r["traffic_used_gb"],
        "created_at": r["created_at"],
        "expire_at": r["expire_at"],
        "vless_link": generate_vless_link(r["uuid"], r["remarks"], r["name"]),
        "domain_set": bool(CF_DOMAIN)
    } for r in rows]

@app.post("/api/configs")
async def create_config(
    request: Request,
    name: str = Form(""),
    remarks: str = Form(""),
    traffic_limit_gb: float = Form(0),
    expire_days: int = Form(0)
):
    require_admin(request)
    new_uuid = str(uuid.uuid4())
    expire_at = None
    if expire_days > 0:
        expire_at = (datetime.now() + timedelta(days=expire_days)).strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db()
    conn.execute(
        "INSERT INTO configs (uuid, name, remarks, traffic_limit_gb, expire_at) VALUES (?, ?, ?, ?, ?)",
        (new_uuid, name or "Unnamed", remarks, traffic_limit_gb, expire_at)
    )
    conn.commit()
    conn.close()

    restart_xray()
    return {
        "success": True,
        "uuid": new_uuid,
        "link": generate_vless_link(new_uuid, remarks, name),
        "domain_set": bool(CF_DOMAIN)
    }

@app.put("/api/configs/{config_id}")
async def update_config(
    request: Request,
    config_id: int,
    name: str = Form(""),
    remarks: str = Form(""),
    traffic_limit_gb: float = Form(0),
    expire_days: int = Form(0)
):
    require_admin(request)
    expire_at = None
    if expire_days > 0:
        expire_at = (datetime.now() + timedelta(days=expire_days)).strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db()
    conn.execute(
        "UPDATE configs SET name = ?, remarks = ?, traffic_limit_gb = ?, expire_at = ? WHERE id = ?",
        (name, remarks, traffic_limit_gb, expire_at, config_id)
    )
    conn.commit()
    conn.close()

    restart_xray()
    return {"success": True}

@app.delete("/api/configs/{config_id}")
async def delete_config(request: Request, config_id: int):
    require_admin(request)
    conn = get_db()
    conn.execute("DELETE FROM configs WHERE id = ?", (config_id,))
    conn.execute("UPDATE users SET config_id = NULL WHERE config_id = ?", (config_id,))
    conn.commit()
    conn.close()
    restart_xray()
    return {"success": True}

@app.patch("/api/configs/{config_id}/toggle")
async def toggle_config(request: Request, config_id: int):
    require_admin(request)
    conn = get_db()
    row = conn.execute("SELECT enabled FROM configs WHERE id = ?", (config_id,)).fetchone()
    if row:
        new_val = 0 if row["enabled"] else 1
        conn.execute("UPDATE configs SET enabled = ? WHERE id = ?", (new_val, config_id))
        conn.commit()
        restart_xray()
    conn.close()
    return {"success": True}

# ==================== Users API ====================
@app.get("/api/users")
async def get_users(request: Request):
    require_admin(request)
    conn = get_db()
    rows = conn.execute("""
        SELECT u.id, u.username, u.is_admin, u.config_id, c.uuid as cuuid, c.name as cname
        FROM users u
        LEFT JOIN configs c ON u.config_id = c.id
        ORDER BY u.id DESC
    """).fetchall()
    conn.close()
    return [{
        "id": r["id"],
        "username": r["username"],
        "is_admin": bool(r["is_admin"]),
        "config_id": r["config_id"],
        "config_uuid": r["cuuid"],
        "config_name": r["cname"]
    } for r in rows]

@app.post("/api/users")
async def create_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    config_id: Optional[int] = Form(None)
):
    require_admin(request)
    hashed = pwd_context.hash(password)
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, password, config_id) VALUES (?, ?, ?)",
            (username, hashed, config_id)
        )
        conn.commit()
        return {"success": True}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already exists")
    finally:
        conn.close()

@app.delete("/api/users/{user_id}")
async def delete_user(request: Request, user_id: int):
    require_admin(request)
    conn = get_db()
    user = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
    if user and user["username"] == "admin":
        conn.close()
        raise HTTPException(status_code=400, detail="Cannot delete main admin")
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return {"success": True}

@app.patch("/api/users/{user_id}/assign")
async def assign_config(request: Request, user_id: int, config_id: int = Form(...)):
    require_admin(request)
    conn = get_db()
    conn.execute("UPDATE users SET config_id = ? WHERE id = ?", (config_id, user_id))
    conn.commit()
    conn.close()
    return {"success": True}

# ==================== My Config API ====================
@app.get("/api/my-config")
async def my_config(request: Request):
    user = get_current_user(request)
    if not user.get("config_id"):
        return {"has_config": False}

    conn = get_db()
    row = conn.execute("SELECT * FROM configs WHERE id = ?", (user["config_id"],)).fetchone()
    conn.close()

    if not row:
        return {"has_config": False}

    return {
        "has_config": True,
        "id": row["id"],
        "uuid": row["uuid"],
        "name": row["name"],
        "remarks": row["remarks"],
        "vless_link": generate_vless_link(row["uuid"], row["remarks"], row["name"]),
        "domain_set": bool(CF_DOMAIN)
    }

# ==================== Health Check ====================
@app.get("/health")
async def health():
    return {
        "status": "ok",
        "xray": "running" if (xray_process and xray_process.poll() is None) else "stopped",
        "cf_domain": CF_DOMAIN or "not set"
    }

# ==================== Run ====================
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=PORT)
