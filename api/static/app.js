// app.js — Alpine stores, HTMX hooks, clipboard helper, ⌘K shortcut.

// ── Sidebar toggle (vanilla, no Alpine dependency) ─────────────────────────
// Defined at module top so the button's onclick can call it the instant the
// script parses — independent of Alpine boot timing, x-store registration,
// or x-on:click directive binding. The Alpine.store('sidebar') below mirrors
// the same state so any future :class / x-show bindings stay in sync, but
// the click path no longer routes through Alpine.
window.aptToggleSidebar = function () {
  const root = document.documentElement;
  const next = root.dataset.sidebar === 'collapsed' ? 'expanded' : 'collapsed';
  root.dataset.sidebar = next;
  try { localStorage.setItem('sidebarCollapsed', next === 'collapsed' ? '1' : '0'); } catch (_) {}
  if (window.Alpine && Alpine.store('sidebar')) {
    Alpine.store('sidebar').collapsed = (next === 'collapsed');
  }
  // Lightweight diagnostic — kept because the previous Alpine-based path
  // failed silently and there's no other surface to confirm the click
  // landed in production.
  console.debug('[sidebar] toggled →', next);
};

// ── Topbar uptime pill (vanilla, no Alpine dependency) ────────────────────
// Same Alpine-binding failure mode as sidebar: x-data="uptimePill" + x-init
// silently never fired in production. Vanilla mount on DOMContentLoaded
// guarantees the pill updates regardless of Alpine state.
window.aptStartUptimePill = function () {
  const el = document.getElementById('uptime-pill-text');
  if (!el) return;
  let startedAt = 0;
  const refresh = async () => {
    try {
      const r = await fetch('/diag/uptime', { credentials: 'same-origin' });
      if (!r.ok) return;
      const j = await r.json();
      startedAt = j.started_at || 0;
      el.textContent = 'Up ' + (j.label || '…');
    } catch (_) { /* keep last visible value */ }
  };
  refresh();
  setInterval(refresh, 30_000);                // resync every 30 s
  setInterval(() => {                          // local 1-Hz tick between syncs
    if (!startedAt) return;
    el.textContent = 'Up ' + formatUptime((Date.now() / 1000) - startedAt);
  }, 1000);
};
document.addEventListener('DOMContentLoaded', () => {
  if (typeof aptStartUptimePill === 'function') aptStartUptimePill();
});

document.addEventListener('alpine:init', () => {
  Alpine.store('toast', {
    items: [],
    push(text, kind = 'ok', ttl = 4000) {
      const id = Math.random().toString(36).slice(2);
      this.items.push({ id, text, kind });
      setTimeout(() => this.dismiss(id), ttl);
    },
    dismiss(id) {
      this.items = this.items.filter(t => t.id !== id);
    },
  });

  Alpine.store('modal', {
    open: false,
    title: '',
    body: null,
    show(opts) {
      this.title = opts.title || '';
      this.body  = opts.body  || '';
      this.open  = true;
    },
    hide() { this.open = false; },
  });

  Alpine.store('palette', { open: false });

  Alpine.store('theme', {
    init() { this.value = window.AptTheme.currentTheme(); },
    value: 'auto',
    cycle() {
      const next = window.AptTheme.nextTheme(this.value);
      window.AptTheme.setTheme(next);
      this.value = next;
    },
    icon() { return window.AptTheme.iconFor(this.value); },
  });

  Alpine.store('sidebar', {
    collapsed: document.documentElement.dataset.sidebar === 'collapsed',
    toggle() {
      this.collapsed = !this.collapsed;
      localStorage.setItem('sidebarCollapsed', this.collapsed ? '1' : '0');
      document.documentElement.dataset.sidebar = this.collapsed ? 'collapsed' : 'expanded';
    },
  });

  // ── Notifications store ────────────────────────────────────────────────
  // Maintains the bell badge count + an in-memory recent list, and opens
  // an EventSource to /notifications/stream so a CRITICAL detection pops a
  // toast even if the operator isn't on the alerts page.
  Alpine.store('notifs', {
    items: [],
    unread: 0,
    connected: false,
    _src: null,

    async init() {
      try {
        const r = await fetch('/notifications?unread=1&limit=20',
                              { credentials: 'same-origin' });
        if (r.ok) {
          const d = await r.json();
          this.items = d.notifications || [];
          this.unread = d.unread || 0;
        }
      } catch (_) {}
      this._openStream();
    },

    _openStream() {
      try {
        const src = new EventSource('/notifications/stream',
                                     { withCredentials: true });
        this._src = src;
        src.addEventListener('hello',  () => { this.connected = true; });
        src.addEventListener('notification', (e) => {
          try {
            const n = JSON.parse(e.data);
            this.items.unshift({
              id: n.id, alert_id: n.alert_id, severity: n.severity,
              title: n.title, body: n.body, created_at: Date.now() / 1000,
              read_at: null,
            });
            if (this.items.length > 50) this.items.length = 50;
            this.unread += 1;
            const kind = (n.severity === 'critical') ? 'error'
                       : (n.severity === 'high') ? 'warn' : 'ok';
            Alpine.store('toast').push(n.title || 'New detection', kind, 6000);
          } catch (_) {}
        });
        src.onerror = () => {
          this.connected = false;
          // Don't aggressively reconnect — EventSource auto-retries.
        };
      } catch (e) {
        // EventSource not supported / blocked. Polling fallback below.
        this._startPolling();
      }
    },

    _startPolling() {
      const tick = async () => {
        try {
          const r = await fetch('/notifications?unread=1&limit=20',
                                { credentials: 'same-origin' });
          if (r.ok) {
            const d = await r.json();
            const newCount = d.unread || 0;
            if (newCount > this.unread) {
              const fresh = (d.notifications || [])[0];
              if (fresh) {
                Alpine.store('toast').push(fresh.title, 'warn', 5000);
              }
            }
            this.items = d.notifications || [];
            this.unread = newCount;
          }
        } catch (_) {}
        setTimeout(tick, 15000);
      };
      tick();
    },

    async markRead(nid) {
      try {
        await fetch('/notifications/' + nid + '/read',
                    { method: 'POST', credentials: 'same-origin' });
        this.items = this.items.map(n => n.id === nid ? { ...n, read_at: Date.now() / 1000 } : n);
        this.unread = Math.max(0, this.unread - 1);
      } catch (_) {}
    },

    async markAll() {
      try {
        await fetch('/notifications/read-all',
                    { method: 'POST', credentials: 'same-origin' });
        this.items = this.items.map(n => ({ ...n, read_at: Date.now() / 1000 }));
        this.unread = 0;
      } catch (_) {}
    },
  });

  // (Topbar uptime pill is mounted by aptStartUptimePill() above — vanilla.)
});

// Kick off the notifications store on every dashboard page load.
document.addEventListener('DOMContentLoaded', () => {
  if (!window.Alpine) return;
  // Wait for stores to be registered.
  setTimeout(() => {
    if (Alpine.store('notifs') && typeof Alpine.store('notifs').init === 'function') {
      Alpine.store('notifs').init();
    }
  }, 50);
});

// ── HTMX response toasts ────────────────────────────────────────────────────
document.addEventListener('htmx:afterRequest', (e) => {
  const xhr = e.detail.xhr;
  if (!xhr) return;
  // Server can opt in to its own toast text via HX-Trigger: {"showToast":"..."}
  const trig = xhr.getResponseHeader && xhr.getResponseHeader('HX-Trigger');
  if (trig) {
    try {
      const parsed = JSON.parse(trig);
      if (parsed.showToast) {
        Alpine.store('toast').push(parsed.showToast, parsed.toastKind || 'ok');
        return;
      }
    } catch (_) {
      // single-event trigger, ignore
    }
  }
  if (xhr.status >= 400) {
    const text = `Request failed (${xhr.status})`;
    Alpine.store('toast').push(text, 'error');
  }
});

document.addEventListener('htmx:responseError', (e) => {
  Alpine.store('toast').push('Network error — request did not complete.', 'error');
});

// ── Clipboard helper ────────────────────────────────────────────────────────
window.aptCopy = async function (text, label = 'Copied to clipboard') {
  const ok   = () => { if (window.Alpine) Alpine.store('toast').push(label, 'ok', 2200); };
  const fail = (e) => { if (window.Alpine) Alpine.store('toast').push('Copy failed: ' + ((e && e.message) || e), 'error'); };
  // Modern API only works in a secure context (HTTPS or http://localhost).
  if (navigator.clipboard && window.isSecureContext) {
    try { await navigator.clipboard.writeText(text); ok(); return; }
    catch (_) { /* fall through to the legacy path below */ }
  }
  // Legacy fallback: works over plain HTTP (deprecated execCommand, but reliable).
  try {
    const ta = document.createElement('textarea');
    ta.value = text == null ? '' : String(text);
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.top = '-1000px';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    ta.setSelectionRange(0, ta.value.length);
    const copied = document.execCommand('copy');
    document.body.removeChild(ta);
    copied ? ok() : fail(new Error('clipboard blocked by the browser — select + copy manually'));
  } catch (e) { fail(e); }
};

// ── ⌘K palette opener ───────────────────────────────────────────────────────
document.addEventListener('keydown', (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault();
    if (window.Alpine) Alpine.store('palette').open = !Alpine.store('palette').open;
  } else if (e.key === 'Escape') {
    if (window.Alpine) {
      Alpine.store('palette').open = false;
      Alpine.store('modal').hide();
    }
  }
});

// ── Lucide refresh on HTMX swaps ────────────────────────────────────────────
document.addEventListener('htmx:afterSettle', () => {
  if (window.lucide && typeof lucide.createIcons === 'function') {
    lucide.createIcons();
  }
});

// ── Uptime label formatter ──────────────────────────────────────────────────
// Shared by the vanilla aptStartUptimePill helper above.
function formatUptime(seconds) {
  const s = Math.max(0, Math.floor(seconds));
  if (s < 60)         return `${s}s`;
  if (s < 3600)       return `${Math.floor(s / 60)}m`;
  if (s < 86400) {
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
    return m ? `${h}h ${m}m` : `${h}h`;
  }
  if (s < 7 * 86400) {
    const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600);
    return h ? `${d}d ${h}h` : `${d}d`;
  }
  if (s < 30 * 86400) {
    const w = Math.floor(s / (7 * 86400)), d = Math.floor((s % (7 * 86400)) / 86400);
    return d ? `${w}w ${d}d` : `${w}w`;
  }
  const mo = Math.floor(s / (30 * 86400));
  const w  = Math.floor((s % (30 * 86400)) / (7 * 86400));
  return w ? `${mo}mo ${w}w` : `${mo}mo`;
}
