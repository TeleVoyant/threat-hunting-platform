function Topbar({ onOpenPalette, criticalCount, onOpenInvestigation }) {
  return (
    <header className="topbar" style={{ display: 'flex', alignItems: 'center', gap: 14, padding: '0 20px', height: 'var(--topbar-h)' }}>
      {/* Tenant switcher */}
      <button style={{
        all: 'unset', cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: 8,
        padding: '5px 10px 5px 8px', borderRadius: 'var(--r-2)', border: '1px solid var(--border-2)',
        background: 'var(--bg-2)', color: 'var(--fg-1)', font: '500 13px Inter'
      }}>
        <span style={{ width: 18, height: 18, borderRadius: 4, background: 'var(--apt-teal)', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', font: '700 10px Inter', color: 'var(--fg-on-teal)' }}>NX</span>
        Nexus Bancorp
        <Icon name="chevrons-up-down" size={12} color="var(--fg-3)" />
      </button>

      <div style={{ flex: 1, maxWidth: 480, position: 'relative' }}>
        <button onClick={onOpenPalette} style={{
          all: 'unset', cursor: 'text', display: 'flex', alignItems: 'center', gap: 8,
          width: '100%', padding: '7px 12px 7px 36px', borderRadius: 'var(--r-2)',
          border: '1px solid var(--border-2)', background: 'var(--bg-2)', color: 'var(--fg-3)',
          font: '500 13px Inter'
        }}>
          Search hosts, IOCs, hunts…
          <span style={{ marginLeft: 'auto', font: '600 10px IBM Plex Mono', color: 'var(--fg-3)', border: '1px solid var(--border-1)', padding: '1px 6px', borderRadius: 4 }}>⌘K</span>
        </button>
        <Icon name="search" size={14} color="var(--fg-3)" style={{ position: 'absolute', left: 12, top: 11 }} />
      </div>

      <div className="spacer"></div>

      {/* Live mode indicator */}
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, font: '500 12px Inter', color: 'var(--fg-2)' }}>
        <span className="heartbeat" style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--apt-teal)', boxShadow: '0 0 6px var(--apt-teal)' }}></span>
        Live · last 24h
      </span>

      <button className="btn btn-ghost btn-icon" title="Notifications" style={{ position: 'relative' }} onClick={onOpenInvestigation}>
        <Icon name="bell" size={16} color="var(--fg-2)" />
        {criticalCount > 0 && (
          <span style={{ position: 'absolute', top: 4, right: 4, width: 8, height: 8, borderRadius: '50%', background: 'var(--critical)', boxShadow: '0 0 6px var(--critical)' }}></span>
        )}
      </button>
      <button className="btn btn-ghost btn-icon" title="Help">
        <Icon name="circle-help" size={16} color="var(--fg-2)" />
      </button>
      <div style={{ width: 30, height: 30, borderRadius: '50%', background: 'linear-gradient(135deg,#1f4a75,#12B5B0)', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', font: '700 11px Inter', color: 'var(--fg-1)' }}>MK</div>
    </header>
  );
}

Object.assign(window, { Topbar });
