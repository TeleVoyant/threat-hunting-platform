function Sidebar({ view, setView, criticalCount, openHunts }) {
  const items = [
    { id: 'dashboard', label: 'Dashboard', icon: 'layout-dashboard' },
    { id: 'hunts',     label: 'Hunts',     icon: 'crosshair',  count: openHunts },
    { id: 'alerts',    label: 'Alerts',    icon: 'bell',       badge: criticalCount },
    { id: 'lateral',   label: 'Lateral graph', icon: 'network' },
    { id: 'dns',       label: 'DNS exfil',  icon: 'globe' },
    { id: 'analytics', label: 'Analytics',  icon: 'bar-chart-3' },
  ];
  const footer = [
    { id: 'integrations', label: 'Integrations', icon: 'plug' },
    { id: 'settings',     label: 'Settings',     icon: 'settings' },
  ];

  return (
    <aside className="sidebar" style={{ display: 'flex', flexDirection: 'column' }}>
      <div style={{ padding: '14px 16px 18px', display: 'flex', alignItems: 'center', gap: 10 }}>
        <img src="../../assets/icon-dark.png" alt="" style={{ width: 30, height: 30, borderRadius: 7 }} />
        <div style={{ display: 'flex', flexDirection: 'column' }}>
          <span style={{ font: '700 13px Inter', color: 'var(--fg-1)', letterSpacing: '-0.01em' }}>APT THP</span>
          <span style={{ font: '500 10px Inter', color: 'var(--fg-3)', letterSpacing: '0.04em', textTransform: 'uppercase' }}>Threat hunting</span>
        </div>
      </div>

      <div className="eyebrow" style={{ padding: '0 16px 6px' }}>Operations</div>
      <nav style={{ padding: '0 8px', display: 'flex', flexDirection: 'column', gap: 1 }}>
        {items.map(it => <NavItem key={it.id} item={it} active={view === it.id} onClick={() => setView(it.id)} />)}
      </nav>

      <div style={{ flex: 1 }}></div>

      <div className="eyebrow" style={{ padding: '0 16px 6px' }}>Workspace</div>
      <nav style={{ padding: '0 8px 14px', display: 'flex', flexDirection: 'column', gap: 1 }}>
        {footer.map(it => <NavItem key={it.id} item={it} active={view === it.id} onClick={() => setView(it.id)} />)}
      </nav>

      <div style={{ margin: '0 12px 14px', padding: '10px 12px', background: 'var(--bg-2)', border: '1px solid var(--border-1)', borderRadius: 'var(--r-3)', display: 'flex', alignItems: 'center', gap: 8 }}>
        <span className="heartbeat" style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--apt-teal)', boxShadow: '0 0 8px var(--apt-teal)' }}></span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ font: '600 11px Inter', color: 'var(--fg-1)' }}>Detectors online</div>
          <div className="mono" style={{ font: '500 11px IBM Plex Mono', color: 'var(--fg-3)' }}>3 / 3 nodes · v2.1</div>
        </div>
      </div>
    </aside>
  );
}

function NavItem({ item, active, onClick }) {
  return (
    <button onClick={onClick} style={{
      all: 'unset',
      cursor: 'pointer',
      display: 'flex', alignItems: 'center', gap: 10,
      padding: '7px 10px',
      paddingLeft: active ? 8 : 10,
      borderRadius: 'var(--r-2)',
      borderLeft: active ? '2px solid var(--apt-teal)' : '2px solid transparent',
      background: active ? 'rgba(18,181,176,0.10)' : 'transparent',
      color: active ? 'var(--apt-teal-bright)' : 'var(--fg-2)',
      font: active ? '600 13px Inter' : '500 13px Inter',
      transition: 'background var(--dur-fast), color var(--dur-fast)',
    }}
    onMouseEnter={e => { if (!active) e.currentTarget.style.background = 'rgba(255,255,255,0.03)'; }}
    onMouseLeave={e => { if (!active) e.currentTarget.style.background = 'transparent'; }}
    >
      <Icon name={item.icon} size={16} />
      <span style={{ flex: 1 }}>{item.label}</span>
      {item.count != null && <span className="mono" style={{ font: '500 11px IBM Plex Mono', color: active ? 'var(--apt-teal-bright)' : 'var(--fg-3)' }}>{item.count}</span>}
      {item.badge != null && item.badge > 0 && (
        <span style={{ background: 'var(--critical)', color: '#fff', font: '700 10px Inter', padding: '1px 6px', borderRadius: '999px' }}>{item.badge}</span>
      )}
    </button>
  );
}

Object.assign(window, { Sidebar });
