import os
import json
import uuid
import sqlite3
import subprocess
import secrets
import asyncio
import socket
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Form, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse, Response
from passlib.context import CryptContext
from apscheduler.schedulers.background import BackgroundScheduler
import uvicorn

# ==================== Settings ====================
CF_DOMAIN = os.getenv("CF_DOMAIN", "")
USER_PASS = os.getenv("USER_PASS", "admin123")
PANEL_PORT = int(os.getenv("PORT", "8080"))
DB_PATH = "/app/data/panel.db"
XRAY_PORT = 10000

print("=" * 50)
print(f"CF_DOMAIN: {CF_DOMAIN or 'NOT SET'}")
print(f"Panel: {PANEL_PORT} | Xray: {XRAY_PORT}")
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
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def create_default_admin():
    conn = get_db()
    admin = conn.execute("SELECT * FROM users WHERE username = 'admin'").fetchone()
    hashed = pwd_context.hash(USER_PASS)
    if not admin:
        conn.execute("INSERT INTO users (username, password, is_admin) VALUES ('admin', ?, 1)", (hashed,))
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
    remark_text = remarks or name or "VLESS"
    return (
        f"vless://{config_uuid}@{CF_DOMAIN}:443"
        f"?encryption=none&security=tls&sni={CF_DOMAIN}"
        f"&fp=chrome&type=ws&host={CF_DOMAIN}"
        f"&path=%2Fws#{remark_text}"
    )

def build_xray_config():
    conn = get_db()
    configs = conn.execute("SELECT * FROM configs WHERE enabled = 1").fetchall()
    conn.close()

    clients = []
    for conf in configs:
        clients.append({"id": conf["uuid"], "flow": "xtls-rprx-vision"})

    if not clients:
        dummy_uuid = str(uuid.uuid4())
        clients = [{"id": dummy_uuid, "flow": "xtls-rprx-vision"}]

    config_data = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": XRAY_PORT,
            "protocol": "vless",
            "settings": {"clients": clients, "decryption": "none"},
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": {"path": "/ws"}
            }
        }],
        "outbounds": [{"protocol": "freedom", "settings": {}, "tag": "direct"}]
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
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    import threading
    def log_xray():
        if xray_process and xray_process.stdout:
            for line in xray_process.stdout:
                line_str = line.decode().strip()
                if line_str:
                    print(f"XRAY: {line_str}")
    threading.Thread(target=log_xray, daemon=True).start()

# ==================== Session ====================
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

# ==================== HTML ====================
LOGIN_HTML = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Login</title>
<style>body{font-family:sans-serif;background:#1a1a2e;color:#eee;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
form{background:#16213e;padding:40px;border-radius:16px;width:350px}
h2{color:#7c5cfc;text-align:center}input{width:100%;padding:12px;margin:10px 0;background:#0f3460;border:none;border-radius:8px;color:#fff}
button{width:100%;padding:14px;background:#7c5cfc;border:none;border-radius:8px;color:#fff;font-weight:bold;cursor:pointer}
#e{color:#ff6b6b;text-align:center;display:none}</style></head><body>
<form id="f"><h2>VLESS Panel</h2>
<input type="text" id="u" placeholder="Username (admin)" required>
<input type="password" id="p" placeholder="Password" required>
<div id="e"></div><button type="submit">Login</button></form>
<script>document.getElementById('f').onsubmit=async function(e){e.preventDefault();var err=document.getElementById('e');err.style.display='none';var d=new FormData();d.append('username',document.getElementById('u').value);d.append('password',document.getElementById('p').value);try{var r=await fetch('/api/login',{method:'POST',body:d});var j=await r.json();if(r.ok){window.location.href=j.redirect;}else{err.textContent=j.detail||'Error';err.style.display='block';}}catch(ex){err.textContent='Connection error';err.style.display='block';}};</script></body></html>"""

DASHBOARD_HTML = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Dashboard</title>
<style>body{font-family:sans-serif;background:#1a1a2e;color:#eee;margin:0;padding:20px}
.h{display:flex;justify-content:space-between;align-items:center;background:#16213e;padding:15px 25px;border-radius:12px;margin-bottom:20px}
.h h2{color:#7c5cfc;margin:0}.h span{color:#aaa;font-size:14px}.h button{background:#e74c3c;border:none;color:#fff;padding:8px 18px;border-radius:6px;cursor:pointer}
.t{display:flex;gap:5px;margin-bottom:20px}.tb{padding:10px 20px;background:#16213e;border:none;color:#aaa;cursor:pointer;border-radius:8px 8px 0 0}
.tb.ac{background:#7c5cfc;color:#fff}.pn{display:none;background:#16213e;padding:25px;border-radius:0 12px 12px 12px;margin-bottom:20px}.pn.ac{display:block}
input{padding:10px;margin:5px;background:#0f3460;border:none;border-radius:6px;color:#fff;min-width:120px}
.bt{background:#7c5cfc;border:none;color:#fff;padding:10px 20px;border-radius:6px;cursor:pointer;margin:5px}
.bs{padding:5px 12px;border:none;border-radius:4px;cursor:pointer;margin:2px;color:#fff;font-size:12px}
.bc{background:#27ae60}.btg{background:#f39c12}.bd{background:#e74c3c}.be{background:#3498db}
.it{display:flex;justify-content:space-between;align-items:center;padding:12px;background:#0f3460;border-radius:8px;margin:8px 0;flex-wrap:wrap;gap:10px}
.it.di{opacity:0.5}.ii{flex:1}.uu{color:#7c5cfc;font-family:monospace;font-size:11px}.ia{display:flex;gap:5px;flex-wrap:wrap}
.bg{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px}.bok{background:rgba(39,174,96,0.3);color:#2ecc71}.ber{background:rgba(231,76,60,0.3);color:#e74c3c}
.to{position:fixed;bottom:20px;right:20px;padding:15px 25px;border-radius:8px;color:#fff;display:none;z-index:99}.tok{background:#27ae60}.ter{background:#e74c3c}</style></head><body>
<div class="h"><h2>VLESS Panel</h2><div><span id="ud"></span> <span id="cd"></span> <button id="lo">Logout</button></div></div>
<div class="t"><button class="tb ac" data-tab="configs">Configs</button><button class="tb" data-tab="users">Users</button><button class="tb" data-tab="me">Account</button></div>
<div class="pn ac" id="pn-configs"><h3 style="color:#7c5cfc">Create Config</h3>
<div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:20px">
<input type="text" id="cn" placeholder="Name"><input type="text" id="cr" placeholder="Remarks">
<input type="number" id="ct" placeholder="Traffic GB" value="0"><input type="number" id="ce" placeholder="Expire days" value="0">
<button class="bt" id="cfs">Create</button></div><h3 style="color:#7c5cfc">Config List</h3><div id="cl"></div></div>
<div class="pn" id="pn-users"><h3 style="color:#7c5cfc">Add User</h3>
<div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:20px">
<input type="text" id="un" placeholder="Username"><input type="password" id="up" placeholder="Password">
<input type="number" id="uc" placeholder="Config ID"><button class="bt" id="ufs">Add User</button></div>
<h3 style="color:#7c5cfc">User List</h3><div id="ul"></div></div>
<div class="pn" id="pn-me"><h3 style="color:#7c5cfc">My Config</h3><div id="mc"></div></div>
<div class="to" id="to"></div>
<script>var isAdmin=false;
function S(m,t){t=t||'ok';var x=document.getElementById('to');x.textContent=m;x.className='to t'+t;x.style.display='block';setTimeout(function(){x.style.display='none';},3000);}
function esc(s){return(s||'').replace(/\\\\/g,'\\\\\\\\').replace(/'/g,"\\\\'");}
document.getElementById('lo').onclick=async function(){await fetch('/api/logout',{method:'POST'});window.location.href='/login';};
document.querySelectorAll('.tb').forEach(function(b){b.onclick=function(){document.querySelectorAll('.tb').forEach(function(x){x.classList.remove('ac');});document.querySelectorAll('.pn').forEach(function(x){x.classList.remove('ac');});b.classList.add('ac');document.getElementById('pn-'+b.dataset.tab).classList.add('ac');};});
async function LC(){var r=await fetch('/api/configs');var c=await r.json();var h=document.getElementById('cl');if(!c.length){h.innerHTML='<p style="color:#888">No configs</p>';return;}
h.innerHTML=c.map(function(x){return'<div class="it'+(x.enabled?'':' di')+'"><div class="ii"><strong>'+(x.name||'Unnamed')+'</strong> <span class="bg '+(x.enabled?'bok':'ber')+'">'+(x.enabled?'Active':'Disabled')+'</span>'+(x.remarks?'<br><small>'+x.remarks+'</small>':'')+'<br><code class="uu">'+x.uuid+'</code><br><small>'+x.traffic_used_gb+'/'+(x.traffic_limit_gb||'∞')+' GB | '+(x.expire_at||'Never')+'</small>'+(x.domain_set?'<br><small style="color:#2ecc71">Ready</small>':'<br><small style="color:#e74c3c">No Domain</small>')+'</div><div class="ia">'+(x.vless_link?'<button class="bs bc" onclick="cp(\\''+esc(x.vless_link)+'\\')">Copy</button>':'')+'<button class="bs be" onclick="EC('+x.id+',\\''+esc(x.name)+'\\',\\''+esc(x.remarks)+'\\','+x.traffic_limit_gb+')">Edit</button><button class="bs btg" onclick="TG('+x.id+')">'+(x.enabled?'Disable':'Enable')+'</button><button class="bs bd" onclick="DC('+x.id+')">Del</button></div></div>';}).join('');}
async function TG(id){await fetch('/api/configs/'+id+'/toggle',{method:'PATCH'});LC();}
async function DC(id){if(!confirm('Delete?'))return;await fetch('/api/configs/'+id,{method:'DELETE'});S('Deleted');LC();}
async function EC(id,nm,rm,tr){var n=prompt('Name:',nm);if(n===null)return;var r=prompt('Remarks:',rm);if(r===null)return;var t=prompt('Traffic:',tr);if(t===null)return;var f=new FormData();f.append('name',n);f.append('remarks',r);f.append('traffic_limit_gb',t);f.append('expire_days','0');var x=await fetch('/api/configs/'+id,{method:'PUT',body:f});var j=await x.json();if(j.success){S('Updated');LC();}else{S('Error','err');}}
function cp(link){navigator.clipboard.writeText(link).then(function(){S('Copied!');}).catch(function(){prompt('Copy:',link);});}
async function LU(){var r=await fetch('/api/users');var u=await r.json();var h=document.getElementById('ul');if(!u.length){h.innerHTML='<p style="color:#888">No users</p>';return;}
h.innerHTML=u.map(function(x){return'<div class="it"><div class="ii"><strong>'+x.username+(x.is_admin?' <span style="color:#f39c12">(Admin)</span>':'')+'</strong>'+(x.config_name?'<br><small>Config: '+x.config_name+'</small>':'<br><small style="color:#888">No config</small>')+'</div><div class="ia">'+(!x.is_admin?'<button class="bs bd" onclick="DU('+x.id+')">Del</button>':'')+'</div></div>';}).join('');}
async function DU(id){if(!confirm('Delete?'))return;await fetch('/api/users/'+id,{method:'DELETE'});S('Deleted');LU();}
async function LMC(){var r=await fetch('/api/my-config');var d=await r.json();var h=document.getElementById('mc');if(!d.has_config){h.innerHTML='<p style="color:#888">No config assigned.</p>';return;}
h.innerHTML='<p><strong>Name:</strong> '+(d.name||'Unnamed')+'</p>'+(d.remarks?'<p><strong>Remarks:</strong> '+d.remarks+'</p>':'')+'<p><strong>UUID:</strong> <code style="color:#7c5cfc">'+d.uuid+'</code></p>'+(d.vless_link?'<p style="color:#2ecc71">Ready</p><button class="bt" onclick="cp(\\''+esc(d.vless_link)+'\\')">Copy Link</button>':'<p style="color:#e74c3c">No domain configured</p>');}
document.addEventListener('DOMContentLoaded',async function(){
try{var r=await fetch('/api/me');if(!r.ok){window.location.href='/login';return;}var u=await r.json();isAdmin=u.is_admin;
document.getElementById('ud').textContent=u.username+(u.is_admin?' (Admin)':'');
var hr=await fetch('/health');var h=await hr.json();
document.getElementById('cd').innerHTML=h.cf_domain&&h.cf_domain!=='not set'?'<span class="bg bok">Domain OK</span>':'<span class="bg ber">No Domain</span>';
document.getElementById('cfs').onclick=async function(){var f=new FormData();f.append('name',document.getElementById('cn').value);f.append('remarks',document.getElementById('cr').value);f.append('traffic_limit_gb',document.getElementById('ct').value);f.append('expire_days',document.getElementById('ce').value);var x=await fetch('/api/configs',{method:'POST',body:f});var j=await x.json();if(j.success){S('Created!');document.getElementById('cn').value='';document.getElementById('cr').value='';document.getElementById('ct').value='0';document.getElementById('ce').value='0';LC();}else{S('Error','err');}};
document.getElementById('ufs').onclick=async function(){var f=new FormData();f.append('username',document.getElementById('un').value);f.append('password',document.getElementById('up').value);var cid=document.getElementById('uc').value;if(cid)f.append('config_id',cid);var x=await fetch('/api/users',{method:'POST',body:f});var j=await x.json();if(j.success){S('User added!');document.getElementById('un').value='';document.getElementById('up').value='';document.getElementById('uc').value='';LU();}else{S(j.detail||'Error','err');}};
if(isAdmin){LC();LU();}else{document.querySelectorAll('.tb').forEach(function(b){if(b.dataset.tab!=='me')b.style.display='none';});LMC();}}catch(ex){window.location.href='/login';}});</script></body></html>"""

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

# Routes
@app.get("/", response_class=RedirectResponse)
async def root(): return RedirectResponse("/login")

@app.get("/login", response_class=HTMLResponse)
async def login_page(): return HTMLResponse(content=LOGIN_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    try:
        get_current_user(request)
        return HTMLResponse(content=DASHBOARD_HTML)
    except HTTPException:
        return RedirectResponse("/login")

@app.post("/api/login")
async def api_login(response: Response, username: str = Form(...), password: str = Form(...)):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if not user or not pwd_context.verify(password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    session_id = secrets.token_hex(32)
    sessions[session_id] = {"id": user["id"], "username": user["username"], "is_admin": bool(user["is_admin"]), "config_id": user["config_id"]}
    resp = JSONResponse({"success": True, "redirect": "/dashboard"})
    resp.set_cookie(key="session_id", value=session_id, httponly=True, samesite="lax", max_age=86400, path="/")
    return resp

@app.post("/api/logout")
async def api_logout(request: Request):
    session_id = request.cookies.get("session_id")
    if session_id and session_id in sessions: del sessions[session_id]
    resp = JSONResponse({"success": True}); resp.delete_cookie("session_id", path="/"); return resp

@app.get("/api/me")
async def api_me(request: Request):
    user = get_current_user(request)
    return {"username": user["username"], "is_admin": user["is_admin"], "config_id": user["config_id"]}

@app.get("/api/configs")
async def get_configs(request: Request):
    require_admin(request)
    conn = get_db(); rows = conn.execute("SELECT * FROM configs ORDER BY created_at DESC").fetchall(); conn.close()
    return [{"id": r["id"], "uuid": r["uuid"], "name": r["name"], "remarks": r["remarks"], "enabled": bool(r["enabled"]), "traffic_limit_gb": r["traffic_limit_gb"], "traffic_used_gb": r["traffic_used_gb"], "created_at": r["created_at"], "expire_at": r["expire_at"], "vless_link": generate_vless_link(r["uuid"], r["remarks"], r["name"]), "domain_set": bool(CF_DOMAIN)} for r in rows]

@app.post("/api/configs")
async def create_config(request: Request, name: str = Form(""), remarks: str = Form(""), traffic_limit_gb: float = Form(0), expire_days: int = Form(0)):
    require_admin(request)
    new_uuid = str(uuid.uuid4())
    expire_at = (datetime.now() + timedelta(days=expire_days)).strftime("%Y-%m-%d %H:%M:%S") if expire_days > 0 else None
    conn = get_db()
    conn.execute("INSERT INTO configs (uuid, name, remarks, traffic_limit_gb, expire_at) VALUES (?, ?, ?, ?, ?)", (new_uuid, name or "Unnamed", remarks, traffic_limit_gb, expire_at))
    conn.commit(); conn.close()
    restart_xray()
    return {"success": True, "uuid": new_uuid, "link": generate_vless_link(new_uuid, remarks, name), "domain_set": bool(CF_DOMAIN)}

@app.put("/api/configs/{config_id}")
async def update_config(request: Request, config_id: int, name: str = Form(""), remarks: str = Form(""), traffic_limit_gb: float = Form(0), expire_days: int = Form(0)):
    require_admin(request)
    expire_at = (datetime.now() + timedelta(days=expire_days)).strftime("%Y-%m-%d %H:%M:%S") if expire_days > 0 else None
    conn = get_db()
    conn.execute("UPDATE configs SET name=?, remarks=?, traffic_limit_gb=?, expire_at=? WHERE id=?", (name, remarks, traffic_limit_gb, expire_at, config_id))
    conn.commit(); conn.close(); restart_xray(); return {"success": True}

@app.delete("/api/configs/{config_id}")
async def delete_config(request: Request, config_id: int):
    require_admin(request)
    conn = get_db()
    conn.execute("DELETE FROM configs WHERE id = ?", (config_id,))
    conn.execute("UPDATE users SET config_id = NULL WHERE config_id = ?", (config_id,))
    conn.commit(); conn.close(); restart_xray(); return {"success": True}

@app.patch("/api/configs/{config_id}/toggle")
async def toggle_config(request: Request, config_id: int):
    require_admin(request)
    conn = get_db()
    row = conn.execute("SELECT enabled FROM configs WHERE id = ?", (config_id,)).fetchone()
    if row: conn.execute("UPDATE configs SET enabled = ? WHERE id = ?", (0 if row["enabled"] else 1, config_id)); conn.commit(); restart_xray()
    conn.close(); return {"success": True}

@app.get("/api/users")
async def get_users(request: Request):
    require_admin(request)
    conn = get_db()
    rows = conn.execute("SELECT u.id, u.username, u.is_admin, u.config_id, c.uuid as cuuid, c.name as cname FROM users u LEFT JOIN configs c ON u.config_id = c.id ORDER BY u.id DESC").fetchall()
    conn.close()
    return [{"id": r["id"], "username": r["username"], "is_admin": bool(r["is_admin"]), "config_id": r["config_id"], "config_uuid": r["cuuid"], "config_name": r["cname"]} for r in rows]

@app.post("/api/users")
async def create_user(request: Request, username: str = Form(...), password: str = Form(...), config_id: Optional[int] = Form(None)):
    require_admin(request)
    hashed = pwd_context.hash(password)
    conn = get_db()
    try:
        conn.execute("INSERT INTO users (username, password, config_id) VALUES (?, ?, ?)", (username, hashed, config_id))
        conn.commit(); return {"success": True}
    except sqlite3.IntegrityError: raise HTTPException(status_code=400, detail="Username already exists")
    finally: conn.close()

@app.delete("/api/users/{user_id}")
async def delete_user(request: Request, user_id: int):
    require_admin(request)
    conn = get_db()
    user = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
    if user and user["username"] == "admin": conn.close(); raise HTTPException(status_code=400, detail="Cannot delete admin")
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,)); conn.commit(); conn.close()
    return {"success": True}

@app.get("/api/my-config")
async def my_config(request: Request):
    user = get_current_user(request)
    if not user.get("config_id"): return {"has_config": False}
    conn = get_db(); row = conn.execute("SELECT * FROM configs WHERE id = ?", (user["config_id"],)).fetchone(); conn.close()
    if not row: return {"has_config": False}
    return {"has_config": True, "id": row["id"], "uuid": row["uuid"], "name": row["name"], "remarks": row["remarks"], "vless_link": generate_vless_link(row["uuid"], row["remarks"], row["name"]), "domain_set": bool(CF_DOMAIN)}

@app.get("/health")
async def health():
    return {"status": "ok", "xray": "running" if (xray_process and xray_process.poll() is None) else "stopped", "cf_domain": CF_DOMAIN or "not set"}

# ==================== WebSocket Proxy - Simple TCP ====================
@app.websocket("/ws")
async def ws_proxy(ws: WebSocket):
    """پروکسی ساده WebSocket به Xray"""
    await ws.accept()
    print("WS: Client connected")
    
    # وصل شدن مستقیم به Xray با socket
    xray_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        xray_sock.connect(("127.0.0.1", XRAY_PORT))
        print(f"WS: Connected to Xray on port {XRAY_PORT}")
        
        # ارسال WebSocket upgrade request به Xray
        upgrade = (
            "GET /ws HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        )
        xray_sock.send(upgrade.encode())
        
        # خوندن response از Xray
        response = xray_sock.recv(4096)
        print(f"WS: Xray response: {response[:100]}")
        
        if b"101" not in response:
            print("WS: Xray did not upgrade")
            await ws.close()
            return
        
        async def forward_from_client():
            try:
                while True:
                    data = await ws.receive_bytes()
                    xray_sock.send(data)
            except:
                pass
        
        async def forward_to_client():
            try:
                while True:
                    data = await asyncio.get_event_loop().run_in_executor(None, xray_sock.recv, 4096)
                    if not data:
                        break
                    await ws.send_bytes(data)
            except:
                pass
        
        task1 = asyncio.create_task(forward_from_client())
        task2 = asyncio.create_task(forward_to_client())
        await asyncio.wait([task1, task2], return_when=asyncio.FIRST_COMPLETED)
        for t in [task1, task2]:
            if not t.done(): t.cancel()
            
    except Exception as e:
        print(f"WS Error: {e}")
    finally:
        xray_sock.close()
        try: await ws.close()
        except: pass

if __name__ == "__main__":
    print(f"Starting on port {PANEL_PORT}")
    uvicorn.run("main:app", host="0.0.0.0", port=PANEL_PORT)
