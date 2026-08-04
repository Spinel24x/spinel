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
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse, Response
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
        inbounds.append({
            "port": XRAY_PORT,
            "protocol": "vless",
            "settings": {
                "clients": [{"id": conf["uuid"], "flow": "xtls-rprx-vision"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {"path": f"/{conf['uuid']}"}
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
    Path("/app/configs").mkdir(parents=True, exist_ok=True)
    with open("/app/configs/active.json", "w") as f:
        json.dump({"log": {"loglevel": "warning"}, "inbounds": inbounds, "outbounds": [{"protocol": "freedom", "settings": {}}]}, f, indent=2)

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

# ==================== HTML ====================
LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Login - VLESS Panel</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',Tahoma,sans-serif;background:linear-gradient(135deg,#0d0d2b 0%,#1a1a4e 50%,#0d0d2b 100%);color:#e0e0e0;min-height:100vh;display:flex;align-items:center;justify-content:center}
.box{width:400px;background:rgba(255,255,255,0.05);backdrop-filter:blur(10px);border:1px solid rgba(255,255,255,0.1);border-radius:16px;padding:40px 30px}
.box h1{text-align:center;color:#7c5cfc;margin-bottom:8px}
.box p{text-align:center;color:#888;margin-bottom:30px}
.fg{margin-bottom:20px}
.fg label{display:block;margin-bottom:8px;color:#bbb}
.fg input{width:100%;padding:12px;background:rgba(0,0,0,0.3);border:1px solid rgba(255,255,255,0.1);border-radius:10px;color:#fff;font-size:15px;outline:none}
.fg input:focus{border-color:#7c5cfc}
.btn{width:100%;padding:14px;background:linear-gradient(135deg,#6c3ce0,#4a28c4);border:none;border-radius:10px;color:#fff;font-size:16px;font-weight:bold;cursor:pointer}
.err{display:none;padding:10px;background:rgba(255,50,50,0.2);border-radius:8px;color:#ff6b6b;margin-bottom:15px;text-align:center}
</style>
</head>
<body>
<div class="box">
<h1>VLESS Panel</h1>
<p>Cloudflare Worker + Railway</p>
<form id="f">
<div class="fg"><label>Username</label><input type="text" id="u" required placeholder="admin"></div>
<div class="fg"><label>Password</label><input type="password" id="p" required></div>
<div class="err" id="e"></div>
<button type="submit" class="btn">Login</button>
</form>
</div>
<script>
document.getElementById('f').onsubmit = async function(ev){
ev.preventDefault();
var e=document.getElementById('e');e.style.display='none';
var d=new FormData();
d.append('username',document.getElementById('u').value);
d.append('password',document.getElementById('p').value);
try{
var r=await fetch('/api/login',{method:'POST',body:d});
var j=await r.json();
if(r.ok&&j.success){window.location.href='/dashboard';}
else{e.textContent=j.detail||'Login failed';e.style.display='block';}
}catch(ex){e.textContent='Connection error';e.style.display='block';}
};
</script>
</body>
</html>"""

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Dashboard - VLESS Panel</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',Tahoma,sans-serif;background:linear-gradient(135deg,#0d0d2b 0%,#1a1a4e 50%,#0d0d2b 100%);color:#e0e0e0;min-height:100vh}
.ctn{max-width:1100px;margin:0 auto;padding:20px}
.hdr{display:flex;justify-content:space-between;align-items:center;padding:20px;background:rgba(255,255,255,0.05);border-radius:16px;margin-bottom:25px;border:1px solid rgba(255,255,255,0.08);flex-wrap:wrap;gap:10px}
.hdr h1{font-size:24px;color:#7c5cfc}
.ha{display:flex;align-items:center;gap:15px;flex-wrap:wrap}
.ha span{color:#aaa;font-size:14px}
.blo{padding:8px 20px;background:rgba(255,0,0,0.2);border:1px solid rgba(255,0,0,0.3);border-radius:8px;color:#ff6b6b;cursor:pointer;font-size:14px}
.tb{display:flex;gap:5px;margin-bottom:20px}
.tbb{padding:12px 25px;background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.08);border-radius:10px 10px 0 0;color:#aaa;cursor:pointer;font-size:15px;white-space:nowrap}
.tbb.act{background:rgba(124,92,252,0.2);border-color:#7c5cfc;color:#fff}
.pn{display:none}
.pn.act{display:block}
.cd{background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:14px;padding:25px;margin-bottom:20px}
.cd h3{color:#7c5cfc;margin-bottom:20px;font-size:18px}
.fr{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:10px}
.fr input{flex:1;min-width:120px;padding:10px;background:rgba(0,0,0,0.3);border:1px solid rgba(255,255,255,0.1);border-radius:8px;color:#fff;font-size:14px;outline:none}
.fr input:focus{border-color:#7c5cfc}
.bt{padding:10px 25px;background:linear-gradient(135deg,#6c3ce0,#4a28c4);border:none;border-radius:8px;color:#fff;font-weight:bold;cursor:pointer;white-space:nowrap}
.bs{padding:6px 14px;font-size:13px;border:none;border-radius:6px;cursor:pointer;margin:2px;color:#fff}
.bs:hover{opacity:0.8}
.bc{background:#27ae60}.btg{background:#f39c12}.bd{background:#e74c3c}.be{background:#3498db}
.it{display:flex;justify-content:space-between;align-items:center;padding:15px;background:rgba(0,0,0,0.25);border-radius:10px;margin-bottom:10px;gap:15px;flex-wrap:wrap}
.it.di{opacity:0.5}
.ii{flex:1;min-width:200px}
.ii strong{display:block;color:#e0e0e0;margin-bottom:5px}
.ii small{color:#888;font-size:12px}
.uu{color:#7c5cfc;font-family:monospace;font-size:12px;word-break:break-all}
.ia{display:flex;gap:8px;flex-wrap:wrap}
.bg{display:inline-block;padding:3px 10px;border-radius:20px;font-size:12px;font-weight:bold}
.bok{background:rgba(39,174,96,0.2);color:#2ecc71;border:1px solid rgba(39,174,96,0.3)}
.ber{background:rgba(231,76,60,0.2);color:#e74c3c;border:1px solid rgba(231,76,60,0.3)}
.to{position:fixed;bottom:30px;right:30px;padding:15px 25px;border-radius:10px;color:#fff;font-weight:bold;z-index:1000;display:none}
.tok{background:#27ae60}.ter{background:#e74c3c}
@media(max-width:768px){.ctn{padding:10px}.hdr{flex-direction:column}.fr{flex-direction:column}.it{flex-direction:column;align-items:flex-start}.ia{width:100%;justify-content:flex-end}}
</style>
</head>
<body>
<div class="ctn">
<div class="hdr"><h1>VLESS Panel</h1><div class="ha"><span id="ud"></span><span id="cd"></span><button class="blo" id="lo">Logout</button></div></div>
<div class="tb"><button class="tbb act" data-tab="configs">Configs</button><button class="tbb" data-tab="users">Users</button><button class="tbb" data-tab="me">My Account</button></div>
<div class="pn act" id="pn-configs">
<div class="cd"><h3>Create New Config</h3><form id="cf"><div class="fr"><input type="text" id="cn" placeholder="Config Name"><input type="text" id="cr" placeholder="Remarks (in VLESS link)"><input type="number" id="ct" placeholder="Traffic (GB)" value="0" min="0"><input type="number" id="ce" placeholder="Expire (Days)" value="0" min="0"><button type="submit" class="bt">Create</button></div></form></div>
<div class="cd"><h3>Configs List</h3><div id="cl">Loading...</div></div>
</div>
<div class="pn" id="pn-users">
<div class="cd"><h3>Add User</h3><form id="uf"><div class="fr"><input type="text" id="un" placeholder="Username" required><input type="password" id="up" placeholder="Password" required><input type="number" id="uc" placeholder="Config ID (optional)"><button type="submit" class="bt">Add User</button></div></form></div>
<div class="cd"><h3>Users List</h3><div id="ul">Loading...</div></div>
</div>
<div class="pn" id="pn-me"><div class="cd"><h3>My VLESS Config</h3><div id="mc">Loading...</div></div></div>
</div>
<div class="to" id="to"></div>
<script>
var isAdmin=false;
function S(m,t){t=t||'ok';var x=document.getElementById('to');x.textContent=m;x.className='to t'+t;x.style.display='block';setTimeout(function(){x.style.display='none';},3000);}
function esc(s){return (s||'').replace(/\\\\/g,'\\\\\\\\').replace(/'/g,"\\\\'");}
document.getElementById('lo').onclick=async function(){await fetch('/api/logout',{method:'POST'});window.location.href='/login';};
document.querySelectorAll('.tbb').forEach(function(b){b.onclick=function(){document.querySelectorAll('.tbb').forEach(function(x){x.classList.remove('act');});document.querySelectorAll('.pn').forEach(function(x){x.classList.remove('act');});b.classList.add('act');document.getElementById('pn-'+b.dataset.tab).classList.add('act');};});
async function LC(){if(!isAdmin)return;var r=await fetch('/api/configs');var c=await r.json();var h=document.getElementById('cl');if(!c.length){h.innerHTML='<p style="color:#888;text-align:center;padding:20px;">No configs yet.</p>';return;}h.innerHTML=c.map(function(x){return'<div class="it'+(x.enabled?'':' di')+'"><div class="ii"><strong>'+(x.name||'Unnamed')+'</strong> <span class="bg '+(x.enabled?'bok':'ber')+'">'+(x.enabled?'Active':'Disabled')+'</span>'+(x.remarks?'<br><small>'+x.remarks+'</small>':'')+'<br><code class="uu">'+x.uuid+'</code><br><small>'+x.traffic_used_gb+'/'+(x.traffic_limit_gb||'∞')+' GB</small><br><small>'+(x.expire_at||'No expiry')+'</small>'+(x.domain_set?'<br><small style="color:#2ecc71;">Link ready</small>':'<br><small style="color:#e74c3c;">Set CF_DOMAIN</small>')+'</div><div class="ia">'+(x.vless_link?'<button class="bs bc" onclick="cp(\''+esc(x.vless_link)+'\')">Copy</button>':'')+'<button class="bs be" onclick="EC('+x.id+',\''+esc(x.name)+'\',\''+esc(x.remarks)+'\','+x.traffic_limit_gb+')">Edit</button><button class="bs btg" onclick="TG('+x.id+')">'+(x.enabled?'Disable':'Enable')+'</button><button class="bs bd" onclick="DC('+x.id+')">Del</button></div></div>';}).join('');}
async function TG(id){await fetch('/api/configs/'+id+'/toggle',{method:'PATCH'});LC();}
async function DC(id){if(!confirm('Delete?'))return;await fetch('/api/configs/'+id,{method:'DELETE'});S('Deleted');LC();}
async function EC(id,nm,rm,tr){var n=prompt('Name:',nm);if(n===null)return;var r=prompt('Remarks:',rm);if(r===null)return;var t=prompt('Traffic (GB):',tr);if(t===null)return;var f=new FormData();f.append('name',n);f.append('remarks',r);f.append('traffic_limit_gb',t);f.append('expire_days','0');var x=await fetch('/api/configs/'+id,{method:'PUT',body:f});var j=await x.json();if(j.success){S('Updated!');LC();}else{S('Error','err');}}
function cp(link){navigator.clipboard.writeText(link).then(function(){S('Copied!');}).catch(function(){prompt('Copy:',link);});}
async function LU(){if(!isAdmin)return;var r=await fetch('/api/users');var u=await r.json();var h=document.getElementById('ul');if(!u.length){h.innerHTML='<p style="color:#888;text-align:center;padding:20px;">No users.</p>';return;}h.innerHTML=u.map(function(x){return'<div class="it"><div class="ii"><strong>'+x.username+(x.is_admin?' <span style="color:#f39c12;">(Admin)</span>':'')+'</strong>'+(x.config_name?'<br><small>Config: '+x.config_name+' ('+(x.config_uuid||'').substring(0,8)+'...)</small>':'<br><small style="color:#888;">No config</small>')+'</div><div class="ia">'+(!x.is_admin?'<button class="bs bd" onclick="DU('+x.id+')">Del</button>':'')+'</div></div>';}).join('');}
async function DU(id){if(!confirm('Delete?'))return;await fetch('/api/users/'+id,{method:'DELETE'});S('Deleted');LU();}
async function LMC(){var r=await fetch('/api/my-config');var d=await r.json();var h=document.getElementById('mc');if(!d.has_config){h.innerHTML='<p style="color:#888;text-align:center;padding:20px;">No config assigned.</p>';return;}h.innerHTML='<p><strong>Name:</strong> '+(d.name||'Unnamed')+'</p>'+(d.remarks?'<p><strong>Remarks:</strong> '+d.remarks+'</p>':'')+'<p><strong>UUID:</strong> <code style="color:#7c5cfc;">'+d.uuid+'</code></p>'+(d.vless_link?'<p style="color:#2ecc71;margin-top:15px;">Link ready</p><button class="bt" onclick="cp(\''+esc(d.vless_link)+'\')">Copy VLESS Link</button>':'<p style="color:#e74c3c;">Domain not configured</p>');}
document.addEventListener('DOMContentLoaded',async function(){try{var r=await fetch('/api/me');if(!r.ok){window.location.href='/login';return;}var u=await r.json();isAdmin=u.is_admin;document.getElementById('ud').textContent=u.username+(u.is_admin?' (Admin)':'');var hr=await fetch('/health');var h=await hr.json();if(h.cf_domain&&h.cf_domain!=='not set'){document.getElementById('cd').innerHTML='<span class="bg bok">Domain OK</span>';}else{document.getElementById('cd').innerHTML='<span class="bg ber">No Domain</span>';}document.getElementById('cf').onsubmit=async function(e){e.preventDefault();var f=new FormData();f.append('name',document.getElementById('cn').value);f.append('remarks',document.getElementById('cr').value);f.append('traffic_limit_gb',document.getElementById('ct').value);f.append('expire_days',document.getElementById('ce').value);var x=await fetch('/api/configs',{method:'POST',body:f});var j=await x.json();if(j.success){S('Created!');document.getElementById('cn').value='';document.getElementById('cr').value='';document.getElementById('ct').value='0';document.getElementById('ce').value='0';LC();}else{S('Error','err');}};document.getElementById('uf').onsubmit=async function(e){e.preventDefault();var f=new FormData();f.append('username',document.getElementById('un').value);f.append('password',document.getElementById('up').value);var cid=document.getElementById('uc').value;if(cid)f.append('config_id',cid);var x=await fetch('/api/users',{method:'POST',body:f});var j=await x.json();if(j.success){S('User added!');document.getElementById('un').value='';document.getElementById('up').value='';document.getElementById('uc').value='';LU();}else{S(j.detail||'Error','err');}};if(isAdmin){LC();LU();}else{document.querySelectorAll('.tbb').forEach(function(b){if(b.dataset.tab!=='me')b.style.display='none';});LMC();}}catch(ex){window.location.href='/login';}});
</script>
</body>
</html>"""

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

@app.get("/", response_class=RedirectResponse)
async def root():
    return RedirectResponse("/login")

@app.get("/login", response_class=HTMLResponse)
async def login_page():
    return HTMLResponse(content=LOGIN_HTML)

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
    resp = JSONResponse({"success": True, "redirect": "/dashboard", "is_admin": bool(user["is_admin"]), "username": user["username"]})
    resp.set_cookie(key="session_id", value=session_id, httponly=True, samesite="lax", max_age=86400, path="/")
    return resp

@app.post("/api/logout")
async def api_logout(request: Request):
    session_id = request.cookies.get("session_id")
    if session_id and session_id in sessions:
        del sessions[session_id]
    resp = JSONResponse({"success": True})
    resp.delete_cookie("session_id", path="/")
    return resp

@app.get("/api/me")
async def api_me(request: Request):
    user = get_current_user(request)
    return {"username": user["username"], "is_admin": user["is_admin"], "config_id": user["config_id"]}

@app.get("/api/configs")
async def get_configs(request: Request):
    require_admin(request)
    conn = get_db()
    rows = conn.execute("SELECT * FROM configs ORDER BY created_at DESC").fetchall()
    conn.close()
    return [{"id": r["id"], "uuid": r["uuid"], "name": r["name"], "remarks": r["remarks"], "enabled": bool(r["enabled"]), "traffic_limit_gb": r["traffic_limit_gb"], "traffic_used_gb": r["traffic_used_gb"], "created_at": r["created_at"], "expire_at": r["expire_at"], "vless_link": generate_vless_link(r["uuid"], r["remarks"], r["name"]), "domain_set": bool(CF_DOMAIN)} for r in rows]

@app.post("/api/configs")
async def create_config(request: Request, name: str = Form(""), remarks: str = Form(""), traffic_limit_gb: float = Form(0), expire_days: int = Form(0)):
    require_admin(request)
    new_uuid = str(uuid.uuid4())
    expire_at = (datetime.now() + timedelta(days=expire_days)).strftime("%Y-%m-%d %H:%M:%S") if expire_days > 0 else None
    conn = get_db()
    conn.execute("INSERT INTO configs (uuid, name, remarks, traffic_limit_gb, expire_at) VALUES (?, ?, ?, ?, ?)", (new_uuid, name or "Unnamed", remarks, traffic_limit_gb, expire_at))
    conn.commit()
    conn.close()
    restart_xray()
    return {"success": True, "uuid": new_uuid, "link": generate_vless_link(new_uuid, remarks, name), "domain_set": bool(CF_DOMAIN)}

@app.put("/api/configs/{config_id}")
async def update_config(request: Request, config_id: int, name: str = Form(""), remarks: str = Form(""), traffic_limit_gb: float = Form(0), expire_days: int = Form(0)):
    require_admin(request)
    expire_at = (datetime.now() + timedelta(days=expire_days)).strftime("%Y-%m-%d %H:%M:%S") if expire_days > 0 else None
    conn = get_db()
    conn.execute("UPDATE configs SET name=?, remarks=?, traffic_limit_gb=?, expire_at=? WHERE id=?", (name, remarks, traffic_limit_gb, expire_at, config_id))
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
        conn.execute("UPDATE configs SET enabled = ? WHERE id = ?", (0 if row["enabled"] else 1, config_id))
        conn.commit()
        restart_xray()
    conn.close()
    return {"success": True}

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
        raise HTTPException(status_code=400, detail="Cannot delete admin")
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return {"success": True}

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
    return {"has_config": True, "id": row["id"], "uuid": row["uuid"], "name": row["name"], "remarks": row["remarks"], "vless_link": generate_vless_link(row["uuid"], row["remarks"], row["name"]), "domain_set": bool(CF_DOMAIN)}

@app.get("/health")
async def health():
    return {"status": "ok", "xray": "running" if (xray_process and xray_process.poll() is None) else "stopped", "cf_domain": CF_DOMAIN or "not set"}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=PORT)
