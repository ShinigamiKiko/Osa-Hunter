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
    </div>
  `;
  loadUsers();
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
