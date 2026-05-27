// app.js — Alpine stores, HTMX hooks, clipboard helper, ⌘K shortcut.
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

  // ── Topbar uptime pill ────────────────────────────────────────────────
  // Registered as Alpine.data() inside alpine:init so it's guaranteed to
  // exist before Alpine processes any x-data on the page. Use as:
  //   <span x-data="uptimePill" x-init="start()">…</span>
  Alpine.data('uptimePill', () => ({
    label: '',
    startedAt: 0,
    _pollTimer: null,
    _tickTimer: null,
    async refresh() {
      try {
        const r = await fetch('/diag/uptime', { credentials: 'same-origin' });
        if (!r.ok) return;
        const j = await r.json();
        this.startedAt = j.started_at || 0;
        this.label = j.label || '';
      } catch (_) { /* keep last value */ }
    },
    start() {
      console.log('[uptimePill] mounted');
      this.refresh();
      this._pollTimer = setInterval(() => this.refresh(), 30_000);
      this._tickTimer = setInterval(() => {
        if (!this.startedAt) return;
        this.label = formatUptime((Date.now() / 1000) - this.startedAt);
      }, 1000);
    },
    destroy() {
      if (this._pollTimer) clearInterval(this._pollTimer);
      if (this._tickTimer) clearInterval(this._tickTimer);
    },
  }));
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
  try {
    await navigator.clipboard.writeText(text);
    if (window.Alpine) Alpine.store('toast').push(label, 'ok', 2200);
  } catch (e) {
    if (window.Alpine) Alpine.store('toast').push('Copy failed: ' + e.message, 'error');
  }
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

// ── Topbar uptime pill — formatter ──────────────────────────────────────────
// The Alpine data factory is registered inside the alpine:init handler above.
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
