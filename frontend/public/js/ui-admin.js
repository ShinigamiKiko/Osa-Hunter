// ui-admin.js — Admin panel: create / delete users
// Rendered into #adminContent when navTo('admin') is called

function renderAdmin() {
  const el = document.getElementById('adminContent');
  if (!el) return;
  el.innerHTML = `
    <div style="padding:24px 32px">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:24px">
        <div>
          <div style="font-size:22px;font-weight:900;color:#fff">User Management</div>
          <div style="font-size:13px;color:#5a6478;margin-top:2px">Create and manage OSA Hunter accounts</div>
        </div>
        <button class="btn-primary" onclick="showCreateUser()" style="display:flex;align-items:center;gap:7px">
          + New User
        </button>
      </div>

      <!-- Create form (hidden by default) -->
      <div id="createUserForm" style="display:none;background:#0b0f18;border:1px solid #1a2030;
           border-radius:12px;padding:20px 24px;margin-bottom:20px">
        <div style="font-size:13px;font-weight:700;color:#8a9ab0;margin-bottom:16px;
                    text-transform:uppercase;letter-spacing:.05em">New Account</div>
        <div style="display:grid;grid-template-columns:1fr 1fr auto auto;gap:12px;align-items:end">
          <div>
            <div style="font-size:11px;font-weight:700;color:#5a6478;margin-bottom:5px;
                        text-transform:uppercase;letter-spacing:.04em">Username</div>
            <input id="newUsername" type="text" placeholder="john_doe"
                   style="width:100%;padding:9px 12px;background:#080b10;border:1px solid #1a2030;
                          border-radius:8px;color:#e5e7eb;font-size:13px;outline:none"/>
          </div>
          <div>
            <div style="font-size:11px;font-weight:700;color:#5a6478;margin-bottom:5px;
                        text-transform:uppercase;letter-spacing:.04em">Password</div>
            <input id="newPassword" type="password" placeholder="••••••••"
                   style="width:100%;padding:9px 12px;background:#080b10;border:1px solid #1a2030;
                          border-radius:8px;color:#e5e7eb;font-size:13px;outline:none"/>
          </div>
          <div>
            <div style="font-size:11px;font-weight:700;color:#5a6478;margin-bottom:5px;
                        text-transform:uppercase;letter-spacing:.04em">Role</div>
            <select id="newRole" style="padding:9px 12px;background:#080b10;border:1px solid #1a2030;
                                        border-radius:8px;color:#e5e7eb;font-size:13px;outline:none">
              <option value="user">User</option>
              <option value="admin">Admin</option>
            </select>
          </div>
          <div style="display:flex;gap:8px">
            <button class="btn-primary" onclick="createUser()" style="padding:9px 18px;font-size:13px">Create</button>
            <button class="btn-secondary" onclick="hideCreateUser()" style="padding:9px 14px;font-size:13px">Cancel</button>
          </div>
        </div>
        <div id="createErr" style="color:#ff6b6b;font-size:12px;margin-top:10px;display:none"></div>
      </div>

      <!-- Users table -->
      <div style="background:#0b0f18;border:1px solid #1a2030;border-radius:12px;overflow:hidden">
        <div id="usersTableWrap">
          <div style="text-align:center;padding:40px;color:#5a6478;font-size:13px">Loading…</div>
        </div>
      </div>

      <!-- API Keys section rendered here -->
      <div id="apiKeysSection"></div>
    </div>
  `;
  loadUsers();
  renderApiKeys();
}

function showCreateUser() {
  document.getElementById('createUserForm').style.display = 'block';
  document.getElementById('newUsername').focus();
}
function hideCreateUser() {
  document.getElementById('createUserForm').style.display = 'none';
  document.getElementById('newUsername').value = '';
  document.getElementById('newPassword').value = '';
  document.getElementById('createErr').style.display = 'none';
}

async function loadUsers() {
  const wrap = document.getElementById('usersTableWrap');
  if (!wrap) return;
  try {
    const r = await fetch('/api/auth/users', { credentials: 'same-origin' });
    const { users } = await r.json();
    if (!users.length) {
      wrap.innerHTML = '<div style="text-align:center;padding:40px;color:#5a6478;font-size:13px">No users yet</div>';
      return;
    }
    wrap.innerHTML = `
      <table style="width:100%;border-collapse:collapse">
        <thead>
          <tr style="background:#080b10">
            <th style="padding:10px 16px;font-size:10px;font-weight:700;letter-spacing:.05em;
                       text-transform:uppercase;color:#5a6478;text-align:left">Username</th>
            <th style="padding:10px 16px;font-size:10px;font-weight:700;letter-spacing:.05em;
                       text-transform:uppercase;color:#5a6478;text-align:left">Role</th>
            <th style="padding:10px 16px;font-size:10px;font-weight:700;letter-spacing:.05em;
                       text-transform:uppercase;color:#5a6478;text-align:left">Created</th>
            <th style="padding:10px 16px;width:80px"></th>
          </tr>
        </thead>
        <tbody>
          ${users.map(u => `
            <tr style="border-top:1px solid #111820" id="urow-${u.id}">
              <td style="padding:12px 16px">
                <div style="display:flex;align-items:center;gap:9px">
                  <span style="width:28px;height:28px;border-radius:50%;background:#5ef0c8;color:#07090f;
                               font-size:11px;font-weight:900;display:flex;align-items:center;justify-content:center;flex-shrink:0">
                    ${esc(u.username[0].toUpperCase())}
                  </span>
                  <span style="font-size:13px;font-weight:600;color:#e5e7eb">${esc(u.username)}</span>
                  ${u.id === window._authUser?.id ? '<span style="font-size:9px;color:#5a6478;margin-left:4px">(you)</span>' : ''}
                </div>
              </td>
              <td style="padding:12px 16px">
                <span style="font-size:10px;font-weight:800;padding:2px 9px;border-radius:4px;
                  ${u.role === 'admin'
                    ? 'background:#0a2018;border:1px solid #34d399;color:#34d399'
                    : 'background:#0d1219;border:1px solid #1a2030;color:#8a9ab0'}">
                  ${u.role.toUpperCase()}
                </span>
              </td>
              <td style="padding:12px 16px;font-size:12px;color:#5a6478">
                ${new Date(u.created_at).toLocaleDateString('en-US',{year:'numeric',month:'short',day:'2-digit'})}
              </td>
              <td style="padding:12px 16px">
                ${u.id !== window._authUser?.id ? `
                <button onclick="deleteUser(${u.id},'${esc(u.username)}')"
                  style="background:none;border:1px solid #1a2030;border-radius:6px;color:#5a6478;
                         cursor:pointer;padding:4px 10px;font-size:11px;transition:all .13s"
                  onmouseover="this.style.color='#ff6b6b';this.style.borderColor='#ff3b30'"
                  onmouseout="this.style.color='#5a6478';this.style.borderColor='#1a2030'">
                  Remove
                </button>` : ''}
              </td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `;
  } catch (e) {
    wrap.innerHTML = `<div style="text-align:center;padding:40px;color:#ff6b6b;font-size:13px">Failed to load users</div>`;
  }
}

async function createUser() {
  const username = document.getElementById('newUsername').value.trim();
  const password = document.getElementById('newPassword').value;
  const role     = document.getElementById('newRole').value;
  const errEl    = document.getElementById('createErr');
  errEl.style.display = 'none';
  if (!username || !password) { errEl.textContent = 'Username and password required'; errEl.style.display = 'block'; return; }
  try {
    const r = await fetch('/api/auth/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, role }),
      credentials: 'same-origin',
    });
    const data = await r.json();
    if (!r.ok) { errEl.textContent = data.error || 'Failed to create user'; errEl.style.display = 'block'; return; }
    hideCreateUser();
    loadUsers();
  } catch (e) {
    errEl.textContent = 'Connection error'; errEl.style.display = 'block';
  }
}

async function deleteUser(id, username) {
  if (!confirm(`Remove user "${username}"? This cannot be undone.`)) return;
  try {
    const r = await fetch(`/api/auth/users/${id}`, {
      method: 'DELETE',
      credentials: 'same-origin',
    });
    if (!r.ok) { const d = await r.json(); alert(d.error || 'Failed to delete'); return; }
    const row = document.getElementById(`urow-${id}`);
    if (row) row.remove();
  } catch (e) {
    alert('Connection error');
  }
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
}

// ── API Keys section ──────────────────────────────────────────
async function renderApiKeys() {
  const el = document.getElementById('apiKeysSection');
  if (!el) return;

  const r = await fetch('/api/auth/api-keys', { credentials: 'same-origin' });
  const { keys } = await r.json();

  el.innerHTML = `
    <div style="background:#0b0f18;border:1px solid #1a2030;border-radius:12px;overflow:hidden;margin-top:24px">
      <div style="padding:16px 20px;border-bottom:1px solid #111820;display:flex;align-items:center;justify-content:space-between">
        <div>
          <div style="font-size:14px;font-weight:700;color:#fff">API Keys</div>
          <div style="font-size:12px;color:#5a6478;margin-top:2px">Use <code style="background:#111827;padding:1px 6px;border-radius:4px;color:#5ef0c8">X-Api-Key: &lt;key&gt;</code> header to authenticate API requests</div>
        </div>
        <button class="btn-primary" onclick="showNewKeyForm()" style="font-size:12px;padding:7px 14px">+ New Key</button>
      </div>

      <!-- New key form -->
      <div id="newKeyForm" style="display:none;padding:16px 20px;border-bottom:1px solid #111820;background:#080b10">
        <div style="display:flex;gap:10px;align-items:flex-end">
          <div style="flex:1">
            <div style="font-size:11px;font-weight:700;color:#5a6478;margin-bottom:5px;text-transform:uppercase">Key Name</div>
            <input id="newKeyName" type="text" placeholder='e.g. "CI pipeline", "Local dev"'
                   style="width:100%;padding:9px 12px;background:#0b0f18;border:1px solid #1a2030;
                          border-radius:8px;color:#e5e7eb;font-size:13px;outline:none;box-sizing:border-box"/>
          </div>
          <button class="btn-primary" onclick="createApiKey()" style="font-size:13px;padding:9px 18px;flex-shrink:0">Generate</button>
          <button class="btn-secondary" onclick="hideNewKeyForm()" style="font-size:13px;padding:9px 14px;flex-shrink:0">Cancel</button>
        </div>
        <div id="newKeyErr" style="color:#ff6b6b;font-size:12px;margin-top:8px;display:none"></div>
      </div>

      <!-- Generated key banner -->
      <div id="generatedKey" style="display:none;padding:14px 20px;border-bottom:1px solid #111820;
           background:#051a0f;border-left:3px solid #34d399">
        <div style="font-size:11px;font-weight:700;color:#34d399;margin-bottom:6px;text-transform:uppercase">
          ✓ Key generated — copy it now, it won't be shown again
        </div>
        <div style="display:flex;align-items:center;gap:10px">
          <code id="generatedKeyVal" style="flex:1;background:#080b10;border:1px solid #1a2030;border-radius:6px;
                padding:8px 12px;color:#5ef0c8;font-size:13px;word-break:break-all;font-family:'DM Mono',monospace"></code>
          <button onclick="copyKey()" style="background:#0a2018;border:1px solid #34d399;color:#34d399;
                  border-radius:6px;padding:7px 12px;font-size:11px;cursor:pointer;font-weight:700;flex-shrink:0">Copy</button>
        </div>
      </div>

      <!-- Keys table -->
      ${!keys.length
        ? `<div style="padding:32px;text-align:center;color:#5a6478;font-size:13px">No API keys yet</div>`
        : `<table style="width:100%;border-collapse:collapse">
          <thead>
            <tr style="background:#080b10">
              <th style="padding:10px 16px;font-size:10px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:#5a6478;text-align:left">Name</th>
              <th style="padding:10px 16px;font-size:10px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:#5a6478;text-align:left">Key Prefix</th>
              ${window._authUser?.role === 'admin' ? '<th style="padding:10px 16px;font-size:10px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:#5a6478;text-align:left">Owner</th>' : ''}
              <th style="padding:10px 16px;font-size:10px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:#5a6478;text-align:left">Last Used</th>
              <th style="padding:10px 16px;width:80px"></th>
            </tr>
          </thead>
          <tbody>
            ${keys.map(k => `
              <tr style="border-top:1px solid #111820" id="krow-${k.id}">
                <td style="padding:12px 16px;font-size:13px;font-weight:600;color:#e5e7eb">${esc(k.name)}</td>
                <td style="padding:12px 16px">
                  <code style="background:#080b10;border:1px solid #1a2030;border-radius:5px;
                               padding:3px 8px;color:#5ef0c8;font-size:12px;font-family:'DM Mono',monospace">
                    ${esc(k.key_prefix)}…
                  </code>
                </td>
                ${window._authUser?.role === 'admin' ? `<td style="padding:12px 16px;font-size:12px;color:#8a9ab0">${esc(k.owner||'—')}</td>` : ''}
                <td style="padding:12px 16px;font-size:12px;color:#5a6478">
                  ${k.last_used ? new Date(k.last_used).toLocaleString('en-US',{month:'short',day:'2-digit',hour:'2-digit',minute:'2-digit'}) : 'Never'}
                </td>
                <td style="padding:12px 16px">
                  <button onclick="deleteApiKey(${k.id})"
                    style="background:none;border:1px solid #1a2030;border-radius:6px;color:#5a6478;
                           cursor:pointer;padding:4px 10px;font-size:11px;transition:all .13s"
                    onmouseover="this.style.color='#ff6b6b';this.style.borderColor='#ff3b30'"
                    onmouseout="this.style.color='#5a6478';this.style.borderColor='#1a2030'">
                    Revoke
                  </button>
                </td>
              </tr>`).join('')}
          </tbody>
        </table>`
      }
    </div>
  `;
}

function showNewKeyForm() {
  document.getElementById('newKeyForm').style.display = 'block';
  document.getElementById('generatedKey').style.display = 'none';
  document.getElementById('newKeyName').focus();
}
function hideNewKeyForm() {
  document.getElementById('newKeyForm').style.display = 'none';
  document.getElementById('newKeyName').value = '';
}

async function createApiKey() {
  const name  = document.getElementById('newKeyName').value.trim();
  const errEl = document.getElementById('newKeyErr');
  errEl.style.display = 'none';
  if (!name) { errEl.textContent = 'Name is required'; errEl.style.display = 'block'; return; }

  const r = await fetch('/api/auth/api-keys', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name }),
    credentials: 'same-origin',
  });
  const data = await r.json();
  if (!r.ok) { errEl.textContent = data.error || 'Failed'; errEl.style.display = 'block'; return; }

  hideNewKeyForm();
  showKeyModal(data.key, data.name);
  renderApiKeys();
}

function showKeyModal(key, name) {
  document.getElementById('keyModal')?.remove();

  const modal = document.createElement('div');
  modal.id = 'keyModal';
  modal.style.cssText = 'position:fixed;inset:0;z-index:99999;background:rgba(0,0,0,.72);backdrop-filter:blur(4px);display:flex;align-items:center;justify-content:center;padding:20px';

  const safeName = esc(name);
  const safeKey  = esc(key);

  modal.innerHTML = '<div style="background:#0b0f18;border:1px solid #34d399;border-radius:16px;padding:36px 40px;max-width:620px;width:100%;box-shadow:0 0 60px rgba(52,211,153,.12)">'
    + '<div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">'
    +   '<span style="font-size:20px">🔑</span>'
    +   '<span style="font-size:16px;font-weight:800;color:#fff">API Key Created</span>'
    + '</div>'
    + '<div style="font-size:13px;color:#5a6478;margin-bottom:24px">Key <b style="color:#e5e7eb">' + safeName + '</b> — copy it now, it will never be shown again.</div>'
    + '<div style="background:#060910;border:1px solid #1a2030;border-radius:10px;padding:16px 18px;margin-bottom:20px">'
    +   '<div style="font-size:10px;font-weight:700;color:#5a6478;text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px">Your API Key</div>'
    +   '<code id="modalKeyVal" style="display:block;color:#5ef0c8;font-size:14px;font-family:\'DM Mono\',monospace;word-break:break-all;line-height:1.6">' + safeKey + '</code>'
    + '</div>'
    + '<div style="background:#051a0f;border:1px solid #1a3020;border-radius:8px;padding:10px 14px;margin-bottom:24px;font-size:12px;color:#8a9ab0">'
    +   'Use as header: <code style="color:#a78bfa;font-family:\'DM Mono\',monospace">X-Api-Key: ' + safeKey + '</code>'
    + '</div>'
    + '<div style="display:flex;gap:10px">'
    +   '<button id="copyModalBtn" onclick="copyModalKey()" style="flex:1;padding:11px;background:#5ef0c8;border:none;border-radius:8px;color:#07090f;font-size:13px;font-weight:800;cursor:pointer">Copy Key</button>'
    +   '<button onclick="closeKeyModal()" style="padding:11px 20px;background:none;border:1px solid #1a2030;border-radius:8px;color:#8a9ab0;font-size:13px;font-weight:600;cursor:pointer">Done</button>'
    + '</div>'
    + '</div>';

  document.body.appendChild(modal);
  modal.addEventListener('click', e => { if (e.target === modal) closeKeyModal(); });
}

function copyModalKey() {
  const key = document.getElementById('modalKeyVal').textContent.trim();
  navigator.clipboard.writeText(key).then(() => {
    const btn = document.getElementById('copyModalBtn');
    btn.textContent = '✓ Copied!';
    btn.style.background = '#34d399';
    setTimeout(() => { btn.textContent = 'Copy Key'; btn.style.background = '#5ef0c8'; }, 2000);
  });
}

function closeKeyModal() {
  document.getElementById('keyModal')?.remove();
}

async function deleteApiKey(id) {
  if (!confirm('Revoke this API key? It will stop working immediately.')) return;
  const r = await fetch(`/api/auth/api-keys/${id}`, { method: 'DELETE', credentials: 'same-origin' });
  if (!r.ok) { alert('Failed to revoke'); return; }
  document.getElementById(`krow-${id}`)?.remove();
}

function copyKey() {
  const val = document.getElementById('generatedKeyVal').textContent;
  navigator.clipboard.writeText(val).then(() => {
    const btn = event.target;
    btn.textContent = 'Copied!'; btn.style.color = '#5ef0c8'; btn.style.borderColor = '#5ef0c8';
    setTimeout(() => { btn.textContent = 'Copy'; btn.style.color = '#34d399'; btn.style.borderColor = '#34d399'; }, 2000);
  });
}
