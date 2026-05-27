// theme.js — auto/light/dark cycle, persisted, live OS-switch on auto.
(function () {
  const KEY = 'theme';
  const root = document.documentElement;

  function setTheme(t) {
    root.dataset.theme = t;
    try { localStorage.setItem(KEY, t); } catch (e) {}
    // Tell anyone listening (charts re-skin via MutationObserver)
    window.dispatchEvent(new CustomEvent('themechange', { detail: { theme: t } }));
  }

  function currentTheme() {
    return root.dataset.theme || 'auto';
  }

  function nextTheme(t) {
    return t === 'auto' ? 'light' : t === 'light' ? 'dark' : 'auto';
  }

  function effectiveTheme() {
    const t = currentTheme();
    if (t !== 'auto') return t;
    return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  }

  function iconFor(t) {
    return t === 'light' ? 'sun' : t === 'dark' ? 'moon' : 'monitor';
  }

  window.AptTheme = { setTheme, currentTheme, nextTheme, effectiveTheme, iconFor };

  // Listen to system-preference changes while on auto
  window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', () => {
    if (currentTheme() === 'auto') {
      window.dispatchEvent(new CustomEvent('themechange', { detail: { theme: 'auto' } }));
    }
  });
})();
