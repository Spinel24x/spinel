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

# ==================== CSS ====================
CSS = """
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',Tahoma,sans-serif;background:linear-gradient(135deg,#0d0d2b 0%,#1a1a4e 50%,#0d0d2b 100%);color:#e0e0e0;min-height:100vh;line-height:1.6}
.container{max-width:1100px;margin:0 auto;padding:20px}
.login-card{max-width:420px;margin:100px auto;background:rgba(255,255,255,0.05);backdrop-filter:blur(10px);border:1px solid rgba(255,255,255,0.1);border-radius:16px;padding:40px 30px}
.login-header{text-align:center;margin-bottom:30px}
.login-header h1{font-size:28px;color:#7c5cfc;margin-bottom:8px}
.login-header p{color:#888;font-size:14px}
.form-group{margin-bottom:20px}
.form-group label{display:block;margin-bottom:8px;color:#bbb;font-weight:500}
.form-group input{width:100%;padding:12px 15px;background:rgba(0,0,0,0.3);border:1px solid rgba(255,255,255,0.1);border-radius:10px;color:#fff;font-size:15px;transition:border-color 0.3s}
.form-group input:focus{outline:none;border-color:#7c5cfc}
.btn-login{width:100%;padding:14px;background:linear-gradient(135deg,#6c3ce0,#4a28c4);border:none;border-radius:10px;color:#fff;font-size:16px;font-weight:bold;cursor:pointer;margin-top:10px;transition:transform 0.2s}
.btn-login:hover{transform:translateY(-2px);box-shadow:0 8px 25px rgba(108,60,224,0.4)}
.error-message{display:none;padding:10px;background:rgba(255,50,50,0.2);border:1px solid rgba(255,50,50,0.4);border-radius:8px;color:#ff6b6b;font-size:14px;margin-bottom:15px;text-align:center}
.main-header{display:flex;justify-content:space-between;align-items:center;padding:20px;background:rgba(255,255,255,0.05);border-radius:16px;margin-bottom:25px;border:1px solid rgba(255,255,255,0.08);flex-wrap:wrap;gap:10px}
.main-header h1{font-size:24px;color:#7c5cfc}
.header-actions{display:flex;align-items:center;gap:15px;flex-wrap:wrap}
.header-actions span{color:#aaa;font-size:14px}
.btn-logout{padding:8px 20px;background:rgba(255,0,0,0.2);border:1px solid rgba(255,0,0,0.3);border-radius:8px;color:#ff6b6b;cursor:pointer;font-size:14px}
.btn-logout:hover{background:rgba(255,0,0,0.35)}
.tab-bar{display:flex;gap:5px;margin-bottom:20px;overflow-x:auto}
.tab-btn{padding:12px 25px;background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.08);border-radius:10px 10px 0 0;color:#aaa;cursor:pointer;font-size:15px;white-space:nowrap;transition:all 0.3s}
.tab-btn.active{background:rgba(124,92,252,0.2);border-color:#7c5cfc;color:#fff}
.tab-panel{display:none}
.tab-panel.active{display:block}
.card{background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:14px;padding:25px;margin-bottom:20px}
.card h3{color:#7c5cfc;margin-bottom:20px;font-size:18px}
.inline-form{display:flex;gap:10px;flex-wrap:wrap}
.inline-form input{flex:1;min-width:120px;padding:10px 15px;background:rgba(0,0,0,0.3);border:1px solid rgba(255,255,255,0.1);border-radius:8px;color:#fff;font-size:14px;transition:border-color 0.3s}
.inline-form input:focus{outline:none;border-color:#7c5cfc}
.btn-primary{padding:10px 25px;background:linear-gradient(135deg,#6c3ce0,#4a28c4);border:none;border-radius:8px;color:#fff;font-weight:bold;cursor:pointer;white-space:nowrap;transition:transform 0.2s}
.btn-primary:hover{transform:translateY(-1px)}
.btn-sm{padding:6px 14px;font-size:13px;border:none;border-radius:6px;cursor:pointer;transition:opacity 0.2s;margin:2px}
.btn-sm:hover{opacity:0.8}
.btn-copy{background:#27ae60;color:#fff}
.btn-toggle{background:#f39c12;color:#fff}
.btn-delete{background:#e74c3c;color:#fff}
.btn-edit{background:#3498db;color:#fff}
.config-item,.user-item{display:flex;justify-content:space-between;align-items:center;padding:15px;background:rgba(0,0,0,0.25);border-radius:10px;margin-bottom:10px;gap:15px;flex-wrap:wrap}
.config-item.disabled{opacity:0.5}
.config-info,.user-info-text{flex:1;min-width:200px}
.config-info strong,.user-info-text strong{display:block;color:#e0e0e0;margin-bottom:5px}
.config-info small,.user-info-text small{color:#888;font-size:12px}
.uuid-text{color:#7c5cfc;font-family:monospace;font-size:12px;word-break:break-all}
.config-actions,.user-actions{display:flex;gap:8px;flex-wrap:wrap}
.badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:12px;font-weight:bold}
.badge-active{background:rgba(39,174,96,0.2);color:#2ecc71;border:1px solid rgba(39,174,96,0.3)}
.badge-inactive{background:rgba(231,76,60,0.2);color:#e74c3c;border:1px solid rgba(231,76,60,0.3)}
.toast{position:fixed;bottom:30px;right:30px;padding:15px 25px;border-radius:10px;color:#fff;font-weight:bold;z-index:1000;display:none;animation:slideIn 0.3s ease}
.toast.success{background:#27ae60}
.toast.error{background:#e74c3c}
@keyframes slideIn{from{transform:translateX(100%);opacity:0}to{transform:translateX(0);opacity:1}}
@media(max-width:768px){.container{padding:10px}.main-header{flex-direction:column;text-align:center}.inline-form{flex-direction:column}.inline-form input{flex:unset}.config-item,.user-item{flex-direction:column;align-items:flex-start}.config-actions,.user-actions{width:100%;justify-content:flex-end}}
"""

# ==================== HTML Templates ====================
LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - VLESS Panel</title>
    <style>{css}</style>
</head>
<body>
    <div class="container">
        <div class="login-card">
            <div class="login-header">
                <h1>VLESS Panel</h1>
                <p>Cloudflare Worker + Railway</p>
            </div>
            <form id="loginForm">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" required autocomplete="username" placeholder="admin">
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required autocomplete="current-password">
                </div>
                <div class="error-message" id="errorBox"></div>
                <button type="submit" class="btn-login">Login</button>
            </form>
        </div>
    </div>
    <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {{
            e.preventDefault();
            const errorBox = document.getElementById('errorBox');
            errorBox.style.display = 'none';
            const formData = new FormData();
            formData.append('username', document.getElementById('username').value);
            formData.append('password', document.getElementById('password').value);
            try {{
                const res = await fetch('/api/login', {{ method: 'POST', body: formData }});
                const data = await res.json();
                if (res.ok && data.success) {{
                    window.location.href = data.redirect;
                }} else {{
                    errorBox.textContent = data.detail || 'Login failed';
                    errorBox.style.display = 'block';
                }}
            }} catch (err) {{
                errorBox.textContent = 'Connection error';
                errorBox.style.display = 'block';
            }}
        }});
    </script>
</body>
</html>
"""

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - VLESS Panel</title>
    <style>{css}</style>
</head>
<body>
    <div class="container">
        <header class="main-header">
            <h1>VLESS Panel</h1>
            <div class="header-actions">
                <span id="userDisplay"></span>
                <span id="cfStatus"></span>
                <button class="btn-logout" onclick="doLogout()">Logout</button>
            </div>
        </header>
        <div class="tab-bar">
            <button class="tab-btn active" data-tab="configs">Configs</button>
            <button class="tab-btn" data-tab="users">Users</button>
            <button class="tab-btn" data-tab="me">My Account</button>
        </div>
        <div class="tab-panel active" id="tab-configs">
            <div class="card">
                <h3>Create New Config</h3>
                <form id="addConfigForm" class="inline-form">
                    <input type="text" id="cfgName" placeholder="Config Name">
                    <input type="text" id="cfgRemarks" placeholder="Remarks (shown in VLESS link)">
                    <input type="number" id="cfgTraffic" placeholder="Traffic Limit (GB)" value="0" min="0">
                    <input type="number" id="cfgExpire" placeholder="Expire (Days)" value="0" min="0">
                    <button type="submit" class="btn-primary">Create</button>
                </form>
            </div>
            <div class="card">
                <h3>Configs List</h3>
                <div id="configsList">Loading...</div>
            </div>
        </div>
        <div class="tab-panel" id="tab-users">
            <div class="card">
                <h3>Add User</h3>
                <form id="addUserForm" class="inline-form">
                    <input type="text" id="newUsername" placeholder="Username" required>
                    <input type="password" id="newPassword" placeholder="Password" required>
                    <input type="number" id="assignConfigId" placeholder="Config ID (optional)">
                    <button type="submit" class="btn-primary">Add User</button>
                </form>
            </div>
            <div class="card">
                <h3>Users List</h3>
                <div id="usersList">Loading...</div>
            </div>
        </div>
        <div class="tab-panel" id="tab-me">
            <div class="card">
                <h3>My VLESS Config</h3>
                <div id="myConfig">Loading...</div>
            </div>
        </div>
    </div>
    <div class="toast" id="toast"></div>
    <script>
        let currentUser = null;
        function escapeStr(s) {{ return (s || '').replace(/\\\\/g, '\\\\\\\\').replace(/'/g, "\\\\'"); }}
        function showToast(m, t) {{
            t = t || 'success';
            const el = document.getElementById('toast');
            el.textContent = m;
            el.className = 'toast ' + t;
            el.style.display = 'block';
            setTimeout(function() {{ el.style.display = 'none'; }}, 3000);
        }}
        async function doLogout() {{
            await fetch('/api/logout', {{ method: 'POST' }});
            window.location.href = '/login';
        }}
        function setupTabs() {{
            document.querySelectorAll('.tab-btn').forEach(function(btn) {{
                btn.addEventListener('click', function() {{
                    document.querySelectorAll('.tab-btn').forEach(function(b) {{ b.classList.remove('active'); }});
                    document.querySelectorAll('.tab-panel').forEach(function(p) {{ p.classList.remove('active'); }});
                    btn.classList.add('active');
                    document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
                }});
            }});
        }}
        async function loadConfigs() {{
            if (!currentUser || !currentUser.is_admin) return;
            const res = await fetch('/api/configs');
            const configs = await res.json();
            const c = document.getElementById('configsList');
            if (!configs.length) {{
                c.innerHTML = '<p style="color:#888;text-align:center;padding:20px;">No configs yet.</p>';
                return;
            }}
            c.innerHTML = configs.map(function(cfg) {{
                return '<div class="config-item' + (cfg.enabled ? '' : ' disabled') + '">' +
                    '<div class="config-info">' +
                    '<strong>' + (cfg.name || 'Unnamed') + '</strong> ' +
                    '<span class="badge ' + (cfg.enabled ? 'badge-active' : 'badge-inactive') + '">' + (cfg.enabled ? 'Active' : 'Disabled') + '</span>' +
                    (cfg.remarks ? '<br><small>' + cfg.remarks + '</small>' : '') +
                    '<br><code class="uuid-text">' + cfg.uuid + '</code>' +
                    '<br><small>' + cfg.traffic_used_gb + '/' + (cfg.traffic_limit_gb || '∞') + ' GB</small>' +
                    '<br><small>' + (cfg.expire_at || 'No expiry') + '</small>' +
                    (cfg.domain_set ? '<br><small style="color:#2ecc71;">Link ready</small>' : '<br><small style="color:#e74c3c;">Set CF_DOMAIN</small>') +
                    '</div>' +
                    '<div class="config-actions">' +
                    (cfg.vless_link ? '<button class="btn-sm btn-copy" onclick="copyLink(\'' + escapeStr(cfg.vless_link) + '\')">Copy</button>' : '') +
                    '<button class="btn-sm btn-edit" onclick="editConfig(' + cfg.id + ',\'' + escapeStr(cfg.name) + '\',\'' + escapeStr(cfg.remarks) + '\',' + cfg.traffic_limit_gb + ')">Edit</button>' +
                    '<button class="btn-sm btn-toggle" onclick="toggleConfig(' + cfg.id + ')">' + (cfg.enabled ? 'Disable' : 'Enable') + '</button>' +
                    '<button class="btn-sm btn-delete" onclick="deleteConfig(' + cfg.id + ')">Delete</button>' +
                    '</div></div>';
            }}).join('');
        }}
        async function toggleConfig(id) {{
            await fetch('/api/configs/' + id + '/toggle', {{ method: 'PATCH' }});
            loadConfigs();
        }}
        async function deleteConfig(id) {{
            if (!confirm('Delete this config?')) return;
            await fetch('/api/configs/' + id, {{ method: 'DELETE' }});
            showToast('Config deleted');
            loadConfigs();
        }}
        async function editConfig(id, name, remarks, traffic) {{
            const n = prompt('Config name:', name) || '';
            const r = prompt('Remarks:', remarks) || '';
            const t = prompt('Traffic limit (GB):', traffic) || '0';
            const fd = new FormData();
            fd.append('name', n);
            fd.append('remarks', r);
            fd.append('traffic_limit_gb', t);
            fd.append('expire_days', '0');
            const res = await fetch('/api/configs/' + id, {{ method: 'PUT', body: fd }});
            const d = await res.json();
            if (d.success) {{ showToast('Config updated!'); loadConfigs(); }}
            else showToast('Error', 'error');
        }}
        function copyLink(link) {{
            navigator.clipboard.writeText(link).then(function() {{
                showToast('VLESS link copied!');
            }}).catch(function() {{
                prompt('Copy link:', link);
            }});
        }}
        async function loadUsers() {{
            if (!currentUser || !currentUser.is_admin) return;
            const res = await fetch('/api/users');
            const users = await res.json();
            const c = document.getElementById('usersList');
            if (!users.length) {{
                c.innerHTML = '<p style="color:#888;text-align:center;padding:20px;">No users.</p>';
                return;
            }}
            c.innerHTML = users.map(function(u) {{
                return '<div class="user-item">' +
                    '<div class="user-info-text">' +
                    '<strong>' + u.username + (u.is_admin ? ' <span style="color:#f39c12;">(Admin)</span>' : '') + '</strong>' +
                    (u.config_name ? '<br><small>Config: ' + u.config_name + ' (' + (u.config_uuid || '').substring(0,8) + '...)</small>' : '<br><small style="color:#888;">No config</small>') +
                    '</div>' +
                    '<div class="user-actions">' +
                    (!u.is_admin ? '<button class="btn-sm btn-delete" onclick="deleteUser(' + u.id + ')">Delete</button>' : '') +
                    '</div></div>';
            }}).join('');
        }}
        async function deleteUser(id) {{
            if (!confirm('Delete this user?')) return;
            await fetch('/api/users/' + id, {{ method: 'DELETE' }});
            showToast('User deleted');
            loadUsers();
        }}
        async function loadMyConfig() {{
            const res = await fetch('/api/my-config');
            const data = await res.json();
            const c = document.getElementById('myConfig');
            if (!data.has_config) {{
                c.innerHTML = '<p style="color:#888;text-align:center;padding:20px;">No config assigned. Contact admin.</p>';
                return;
            }}
            c.innerHTML = '<p><strong>Name:</strong> ' + (data.name || 'Unnamed') + '</p>' +
                (data.remarks ? '<p><strong>Remarks:</strong> ' + data.remarks + '</p>' : '') +
                '<p><strong>UUID:</strong> <code style="color:#7c5cfc;">' + data.uuid + '</code></p>' +
                (data.vless_link ? '<p style="color:#2ecc71;">Your VLESS link is ready</p><button class="btn-primary" onclick="copyLink(\'' + escapeStr(data.vless_link) + '\')">Copy VLESS Link</button>' : '<p style="color:#e74c3c;">Domain not configured</p>');
        }}
        document.addEventListener('DOMContentLoaded', async function() {{
            try {{
                const res = await fetch('/api/me');
                if (!res.ok) {{ window.location.href = '/login'; return; }}
                currentUser = await res.json();
                document.getElementById('userDisplay').textContent = currentUser.username + (currentUser.is_admin ? ' (Admin)' : '');
                const hr = await fetch('/health');
                const h = await hr.json();
                if (h.cf_domain && h.cf_domain !== 'not set') {{
                    document.getElementById('cfStatus').innerHTML = '<span class="badge badge-active">Domain OK</span>';
                }} else {{
                    document.getElementById('cfStatus').innerHTML = '<span class="badge badge-inactive">No Domain</span>';
                }}
                setupTabs();
                document.getElementById('addConfigForm').addEventListener('submit', async function(e) {{
                    e.preventDefault();
                    const fd = new FormData();
                    fd.append('name', document.getElementById('cfgName').value);
                    fd.append('remarks', document.getElementById('cfgRemarks').value);
                    fd.append('traffic_limit_gb', document.getElementById('cfgTraffic').value);
                    fd.append('expire_days', document.getElementById('cfgExpire').value);
                    const r = await fetch('/api/configs', {{ method: 'POST', body: fd }});
                    const d = await r.json();
                    if (d.success) {{
                        showToast('Config created!');
                        document.getElementById('cfgName').value = '';
                        document.getElementById('cfgRemarks').value = '';
                        document.getElementById('cfgTraffic').value = '0';
                        document.getElementById('cfgExpire').value = '0';
                        loadConfigs();
                    }} else showToast('Error', 'error');
                }});
                document.getElementById('addUserForm').addEventListener('submit', async function(e) {{
                    e.preventDefault();
                    const fd = new FormData();
                    fd.append('username', document.getElementById('newUsername').value);
                    fd.append('password', document.getElementById('newPassword').value);
                    const cid = document.getElementById('assignConfigId').value;
                    if (cid) fd.append('config_id', cid);
                    const r = await fetch('/api/users', {{ method: 'POST', body: fd }});
                    const d = await r.json();
                    if (d.success) {{
                        showToast('User added!');
                        document.getElementById('newUsername').value = '';
                        document.getElementById('newPassword').value = '';
                        document.getElementById('assignConfigId').value = '';
                        loadUsers();
                    }} else showToast(d.detail || 'Error', 'error');
                }});
                if (currentUser.is_admin) {{
                    loadConfigs();
                    loadUsers();
                }} else {{
                    document.querySelectorAll('.tab-btn').forEach(function(b) {{
                        if (b.dataset.tab !== 'me') b.style.display = 'none';
                    }});
                    loadMyConfig();
                }}
            }} catch (err) {{ window.location.href = '/login'; }}
        }});
    </script>
</body>
</html>
"""

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

# ==================== Pages ====================
@app.get("/", response_class=RedirectResponse)
async def root():
    return RedirectResponse("/login")

@app.get("/login", response_class=HTMLResponse)
async def login_page():
    return HTMLResponse(content=LOGIN_HTML.format(css=CSS))

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    try:
        get_current_user(request)
        return HTMLResponse(content=DASHBOARD_HTML.format(css=CSS))
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
    response.set_cookie(key="session_id", value=session_id, httponly=True, samesite="lax", max_age=86400)
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
    return {"username": user["username"], "is_admin": user["is_admin"], "config_id": user["config_id"]}

# ==================== Configs API ====================
@app.get("/api/configs")
async def get_configs(request: Request):
    require_admin(request)
    conn = get_db()
    rows = conn.execute("SELECT * FROM configs ORDER BY created_at DESC").fetchall()
    conn.close()
    return [{
        "id": r["id"], "uuid": r["uuid"], "name": r["name"], "remarks": r["remarks"],
        "enabled": bool(r["enabled"]), "traffic_limit_gb": r["traffic_limit_gb"],
        "traffic_used_gb": r["traffic_used_gb"], "created_at": r["created_at"],
        "expire_at": r["expire_at"],
        "vless_link": generate_vless_link(r["uuid"], r["remarks"], r["name"]),
        "domain_set": bool(CF_DOMAIN)
    } for r in rows]

@app.post("/api/configs")
async def create_config(
    request: Request, name: str = Form(""), remarks: str = Form(""),
    traffic_limit_gb: float = Form(0), expire_days: int = Form(0)
):
    require_admin(request)
    new_uuid = str(uuid.uuid4())
    expire_at = (datetime.now() + timedelta(days=expire_days)).strftime("%Y-%m-%d %H:%M:%S") if expire_days > 0 else None
    conn = get_db()
    conn.execute("INSERT INTO configs (uuid, name, remarks, traffic_limit_gb, expire_at) VALUES (?, ?, ?, ?, ?)",
                 (new_uuid, name or "Unnamed", remarks, traffic_limit_gb, expire_at))
    conn.commit()
    conn.close()
    restart_xray()
    return {"success": True, "uuid": new_uuid, "link": generate_vless_link(new_uuid, remarks, name), "domain_set": bool(CF_DOMAIN)}

@app.put("/api/configs/{config_id}")
async def update_config(
    request: Request, config_id: int, name: str = Form(""),
    remarks: str = Form(""), traffic_limit_gb: float = Form(0), expire_days: int = Form(0)
):
    require_admin(request)
    expire_at = (datetime.now() + timedelta(days=expire_days)).strftime("%Y-%m-%d %H:%M:%S") if expire_days > 0 else None
    conn = get_db()
    conn.execute("UPDATE configs SET name=?, remarks=?, traffic_limit_gb=?, expire_at=? WHERE id=?",
                 (name, remarks, traffic_limit_gb, expire_at, config_id))
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

# ==================== Users API ====================
@app.get("/api/users")
async def get_users(request: Request):
    require_admin(request)
    conn = get_db()
    rows = conn.execute("""
        SELECT u.id, u.username, u.is_admin, u.config_id, c.uuid as cuuid, c.name as cname
        FROM users u LEFT JOIN configs c ON u.config_id = c.id ORDER BY u.id DESC
    """).fetchall()
    conn.close()
    return [{"id": r["id"], "username": r["username"], "is_admin": bool(r["is_admin"]),
             "config_id": r["config_id"], "config_uuid": r["cuuid"], "config_name": r["cname"]} for r in rows]

@app.post("/api/users")
async def create_user(request: Request, username: str = Form(...), password: str = Form(...),
                      config_id: Optional[int] = Form(None)):
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
    return {"has_config": True, "id": row["id"], "uuid": row["uuid"], "name": row["name"],
            "remarks": row["remarks"], "vless_link": generate_vless_link(row["uuid"], row["remarks"], row["name"]),
            "domain_set": bool(CF_DOMAIN)}

@app.get("/health")
async def health():
    return {"status": "ok", "xray": "running" if (xray_process and xray_process.poll() is None) else "stopped",
            "cf_domain": CF_DOMAIN or "not set"}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=PORT)
