// ui-auth.js — session check + user chip top-right in topbar
(function () {
  fetch('/api/auth/me', { credentials: 'same-origin' })
    .then(r => r.ok ? r.json() : Promise.reject())
    .then(({ user }) => {
      window._authUser = user;
      injectUserChip(user);
      // Render the default page NOW — after auth is confirmed
      navTo('lib-list');
    })
    .catch(() => {
      window.location.replace('/login.html');
    });

  function injectUserChip(user) {
    const ta = document.getElementById('topbarActions');
    if (!ta) return;

    // Inject once — survives ta.innerHTML='' resets by re-injecting on MutationObserver
    function renderChip() {
      if (document.getElementById('authChip')) return; // already there

      const chip = document.createElement('div');
      chip.id = 'authChip';
      chip.style.cssText = 'position:relative;display:flex;align-items:center;margin-left:auto';
      chip.innerHTML = `
        <div style="display:flex;align-items:center;gap:6px;background:#0b0f18;border:1px solid #1a2030;
                    border-radius:999px;padding:5px 12px 5px 8px;cursor:pointer;user-select:none;
                    transition:border-color .15s"
             onmouseover="this.style.borderColor='#2a3450'"
             onmouseout="this.style.borderColor='#1a2030'"
             onclick="document.getElementById('authMenu').classList.toggle('open')">
          <span style="width:22px;height:22px;border-radius:50%;background:#5ef0c8;color:#07090f;
                       font-size:10px;font-weight:900;display:flex;align-items:center;justify-content:center;flex-shrink:0">
            ${escHtml(user.username[0].toUpperCase())}
          </span>
          <span style="font-size:12px;color:#e5e7eb;font-weight:600">${escHtml(user.username)}</span>
          ${user.role === 'admin' ? '<span style="font-size:9px;color:#5ef0c8;font-weight:800;letter-spacing:.04em">ADMIN</span>' : ''}
          <span style="font-size:9px;color:#5a6478;margin-left:2px">▼</span>
        </div>
        <div id="authMenu"
             style="display:none;position:absolute;top:calc(100% + 6px);right:0;
                    background:#0b0f18;border:1px solid #1a2030;border-radius:10px;
                    min-width:160px;overflow:hidden;box-shadow:0 8px 24px rgba(0,0,0,.5);z-index:9999">
          ${user.role === 'admin' ? `
          <div onclick="navTo('admin');document.getElementById('authMenu')?.classList.remove('open')"
               style="padding:10px 14px;font-size:12px;color:#8a9ab0;cursor:pointer;
                      display:flex;align-items:center;gap:8px"
               onmouseover="this.style.background='#111827'"
               onmouseout="this.style.background=''">
            👥 Manage Users
          </div>
          <div style="border-top:1px solid #1a2030"></div>
          ` : ''}
          <div onclick="doLogout()"
               style="padding:10px 14px;font-size:12px;color:#ff6b6b;cursor:pointer;
                      display:flex;align-items:center;gap:8px"
               onmouseover="this.style.background='#1a0808'"
               onmouseout="this.style.background=''">
            ⎋ Sign Out
          </div>
        </div>
      `;

      ta.appendChild(chip);

      document.addEventListener('click', e => {
        if (!document.getElementById('authChip')?.contains(e.target)) {
          document.getElementById('authMenu')?.classList.remove('open');
        }
      });
    }

    // Initial render
    renderChip();

    // Re-inject after any navTo clears topbarActions
    const observer = new MutationObserver(() => renderChip());
    observer.observe(ta, { childList: true });

    const style = document.createElement('style');
    style.textContent = '#authMenu.open{display:block!important}';
    document.head.appendChild(style);
  }

  window.doLogout = async function () {
    await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' });
    window.location.replace('/login.html');
  };

  function escHtml(s) {
    return String(s).replace(/[&<>"']/g, c =>
      ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c])
    );
  }
})();
