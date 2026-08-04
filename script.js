let currentUser = null;

// ==================== Init ====================
document.addEventListener('DOMContentLoaded', async () => {
    try {
        const res = await fetch('/api/me');
        if (!res.ok) { window.location.href = '/login'; return; }
        
        currentUser = await res.json();
        document.getElementById('userDisplay').textContent = 
            `👤 ${currentUser.username}${currentUser.is_admin ? ' (Admin)' : ''}`;

        // Check domain status
        const healthRes = await fetch('/health');
        const health = await healthRes.json();
        if (health.cf_domain && health.cf_domain !== 'not set') {
            document.getElementById('cfStatus').innerHTML = 
                '<span class="badge badge-active">🌐 Domain OK</span>';
        } else {
            document.getElementById('cfStatus').innerHTML = 
                '<span class="badge badge-inactive">⚠️ No Domain</span>';
        }

        // Setup UI
        setupTabs();
        setupForms();

        if (currentUser.is_admin) {
            loadConfigs();
            loadUsers();
            // Show all tabs
            document.querySelectorAll('.tab-btn').forEach(b => b.style.display = '');
        } else {
            // Only show "My Account" tab
            document.querySelectorAll('.tab-btn').forEach(b => {
                b.style.display = b.dataset.tab === 'me' ? '' : 'none';
            });
            loadMyConfig();
        }
    } catch (err) {
        window.location.href = '/login';
    }
});

// ==================== Tabs ====================
function setupTabs() {
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            document.getElementById(`tab-${btn.dataset.tab}`).classList.add('active');
        });
    });
}

// ==================== Toast ====================
function showToast(message, type = 'success') {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.className = `toast ${type}`;
    toast.style.display = 'block';
    setTimeout(() => { toast.style.display = 'none'; }, 3000);
}

// ==================== Forms ====================
function setupForms() {
    // Create Config
    document.getElementById('addConfigForm')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData();
        formData.append('name', document.getElementById('cfgName').value);
        formData.append('remarks', document.getElementById('cfgRemarks').value);
        formData.append('traffic_limit_gb', document.getElementById('cfgTraffic').value);
        formData.append('expire_days', document.getElementById('cfgExpire').value);

        const res = await fetch('/api/configs', { method: 'POST', body: formData });
        const data = await res.json();

        if (data.success) {
            showToast('✅ Config created successfully!');
            ['cfgName', 'cfgRemarks', 'cfgTraffic', 'cfgExpire'].forEach(id => {
                document.getElementById(id).value = '';
            });
            document.getElementById('cfgTraffic').value = '0';
            document.getElementById('cfgExpire').value = '0';
            loadConfigs();
        } else {
            showToast(data.detail || 'Error creating config', 'error');
        }
    });

    // Add User
    document.getElementById('addUserForm')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData();
        formData.append('username', document.getElementById('newUsername').value);
        formData.append('password', document.getElementById('newPassword').value);

        const configId = document.getElementById('assignConfigId').value;
        if (configId) formData.append('config_id', configId);

        const res = await fetch('/api/users', { method: 'POST', body: formData });
        const data = await res.json();

        if (data.success) {
            showToast('✅ User added!');
            ['newUsername', 'newPassword', 'assignConfigId'].forEach(id => {
                document.getElementById(id).value = '';
            });
            loadUsers();
        } else {
            showToast(data.detail || 'Error adding user', 'error');
        }
    });
}

// ==================== Logout ====================
async function doLogout() {
    await fetch('/api/logout', { method: 'POST' });
    window.location.href = '/login';
}

// ==================== Configs ====================
async function loadConfigs() {
    if (!currentUser?.is_admin) return;
    
    const res = await fetch('/api/configs');
    const configs = await res.json();
    const container = document.getElementById('configsList');

    if (!configs.length) {
        container.innerHTML = '<p style="color:#888;text-align:center;padding:20px;">No configs yet. Create one above.</p>';
        return;
    }

    container.innerHTML = configs.map(c => `
        <div class="config-item ${c.enabled ? '' : 'disabled'}">
            <div class="config-info">
                <strong>${c.name || 'Unnamed'}</strong>
                <span class="badge ${c.enabled ? 'badge-active' : 'badge-inactive'}">
                    ${c.enabled ? 'Active' : 'Disabled'}
                </span>
                ${c.remarks ? `<br><small>📝 ${c.remarks}</small>` : ''}
                <br><code class="uuid-text">${c.uuid}</code>
                <br><small>📊 ${c.traffic_used_gb}/${c.traffic_limit_gb || '∞'} GB</small>
                <br><small>📅 ${c.expire_at || 'No expiry'}</small>
                ${c.domain_set 
                    ? '<br><small style="color:#2ecc71;">✅ Link ready</small>' 
                    : '<br><small style="color:#e74c3c;">⚠️ Set CF_DOMAIN in Railway</small>'}
            </div>
            <div class="config-actions">
                ${c.vless_link ? `<button class="btn-sm btn-copy" onclick="copyLink('${escapeStr(c.vless_link)}')">📋 Copy</button>` : ''}
                <button class="btn-sm btn-edit" onclick="editConfig(${c.id}, '${escapeStr(c.name)}', '${escapeStr(c.remarks)}', ${c.traffic_limit_gb})">✏️</button>
                <button class="btn-sm btn-toggle" onclick="toggleConfig(${c.id})">
                    ${c.enabled ? '⏸' : '▶️'}
                </button>
                <button class="btn-sm btn-delete" onclick="deleteConfig(${c.id})">🗑</button>
            </div>
        </div>
    `).join('');
}

function escapeStr(str) {
    return (str || '').replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}

async function toggleConfig(id) {
    await fetch(`/api/configs/${id}/toggle`, { method: 'PATCH' });
    loadConfigs();
}

async function deleteConfig(id) {
    if (!confirm('Delete this config? All associated users will lose access.')) return;
    await fetch(`/api/configs/${id}`, { method: 'DELETE' });
    showToast('Config deleted');
    loadConfigs();
}

async function editConfig(id, currentName, currentRemarks, currentTraffic) {
    const name = prompt('Config name:', currentName) || '';
    const remarks = prompt('Remarks:', currentRemarks) || '';
    const traffic = prompt('Traffic limit (GB):', currentTraffic) || '0';
    
    const formData = new FormData();
    formData.append('name', name);
    formData.append('remarks', remarks);
    formData.append('traffic_limit_gb', traffic);
    formData.append('expire_days', '0');

    const res = await fetch(`/api/configs/${id}`, { method: 'PUT', body: formData });
    const data = await res.json();
    
    if (data.success) {
        showToast('✅ Config updated!');
        loadConfigs();
    } else {
        showToast('Error updating config', 'error');
    }
}

function copyLink(link) {
    navigator.clipboard.writeText(link).then(() => {
        showToast('📋 VLESS link copied to clipboard!');
    }).catch(() => {
        prompt('Copy this link:', link);
    });
}

// ==================== Users ====================
async function loadUsers() {
    if (!currentUser?.is_admin) return;
    
    const res = await fetch('/api/users');
    const users = await res.json();
    const container = document.getElementById('usersList');

    if (!users.length) {
        container.innerHTML = '<p style="color:#888;text-align:center;padding:20px;">No users yet.</p>';
        return;
    }

    container.innerHTML = users.map(u => `
        <div class="user-item">
            <div class="user-info-text">
                <strong>👤 ${u.username} ${u.is_admin ? '<span style="color:#f39c12;">(Admin)</span>' : ''}</strong>
                ${u.config_name 
                    ? `<br><small>Config: ${u.config_name} (${u.config_uuid?.substring(0, 8)}...)</small>` 
                    : '<br><small style="color:#888;">No config</small>'}
            </div>
            <div class="user-actions">
                ${!u.is_admin ? `<button class="btn-sm btn-delete" onclick="deleteUser(${u.id})">🗑</button>` : ''}
            </div>
        </div>
    `).join('');
}

async function deleteUser(id) {
    if (!confirm('Delete this user?')) return;
    await fetch(`/api/users/${id}`, { method: 'DELETE' });
    showToast('User deleted');
    loadUsers();
}

// ==================== My Config ====================
async function loadMyConfig() {
    const res = await fetch('/api/my-config');
    const data = await res.json();
    const container = document.getElementById('myConfig');

    if (!data.has_config) {
        container.innerHTML = `
            <div style="text-align:center;padding:20px;">
                <p style="color:#888;">No config assigned to your account.</p>
                <p style="color:#aaa;font-size:14px;">Contact the administrator to get a config.</p>
            </div>`;
        return;
    }

    container.innerHTML = `
        <div style="padding:10px;">
            <p><strong>Name:</strong> ${data.name || 'Unnamed'}</p>
            ${data.remarks ? `<p><strong>Remarks:</strong> ${data.remarks}</p>` : ''}
            <p><strong>UUID:</strong> <code style="color:#7c5cfc;">${data.uuid}</code></p>
            ${data.vless_link ? `
                <p style="color:#2ecc71;margin-top:15px;">✅ Your VLESS link is ready</p>
                <button class="btn-primary" onclick="copyLink('${escapeStr(data.vless_link)}')" style="margin-top:10px;">
                    📋 Copy VLESS Link
                </button>
            ` : `
                <p style="color:#e74c3c;margin-top:15px;">⚠️ Domain not configured yet.</p>
                <p style="color:#888;font-size:13px;">Administrator needs to set CF_DOMAIN in Railway.</p>
            `}
        </div>`;
}
