function CommandPalette({ open, onClose, onAction }) {
  const [q, setQ] = React.useState('');
  React.useEffect(() => {
    if (!open) return;
    const onKey = (e) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open]);
  if (!open) return null;

  const ALL = [
    { id: 'new-hunt',     label: 'Start new hunt',                  hint: 'Hunts',     icon: 'crosshair' },
    { id: 'open-lateral', label: 'Open lateral-movement graph',     hint: 'Visualize', icon: 'network' },
    { id: 'open-dns',     label: 'Open DNS exfil view',             hint: 'Visualize', icon: 'globe' },
    { id: 'quarantine',   label: 'Quarantine host…',                hint: 'Action',    icon: 'shield-x' },
    { id: 'disable-user', label: 'Disable user account…',           hint: 'Action',    icon: 'user-x' },
    { id: 'open-settings',label: 'Settings · Detection models',     hint: 'Settings',  icon: 'settings' },
    { id: 'open-mitre',   label: 'MITRE ATT&CK coverage',           hint: 'Reference', icon: 'shield' },
    { id: 'open-docs',    label: 'Documentation · XGBoost detectors', hint: 'Reference', icon: 'book-open' },
  ];
  const filt = ALL.filter(a => a.label.toLowerCase().includes(q.toLowerCase()));

  return (
    <div className="scrim" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()} style={{ width: 580, maxHeight: 480, display: 'flex', flexDirection: 'column' }}>
        <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border-1)', display: 'flex', alignItems: 'center', gap: 10 }}>
          <Icon name="search" size={16} color="var(--fg-3)" />
          <input autoFocus value={q} onChange={e => setQ(e.target.value)} placeholder="Search hosts, IOCs, hunts, actions…"
            style={{ all: 'unset', flex: 1, font: '500 14px Inter', color: 'var(--fg-1)' }} />
          <span style={{ font: '600 10px IBM Plex Mono', color: 'var(--fg-3)', border: '1px solid var(--border-1)', padding: '1px 6px', borderRadius: 4 }}>ESC</span>
        </div>
        <div className="scroll" style={{ overflow: 'auto', padding: 6 }}>
          {filt.length === 0 && <div style={{ padding: 20, font: '500 12px Inter', color: 'var(--fg-3)' }}>No matches.</div>}
          {filt.map(a => (
            <button key={a.id} onClick={() => { onAction(a.id); onClose(); }} style={{
              all: 'unset', cursor: 'pointer', width: '100%',
              display: 'flex', alignItems: 'center', gap: 12,
              padding: '10px 12px', borderRadius: 'var(--r-2)',
              color: 'var(--fg-1)',
            }}
            onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-3)'}
            onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
            >
              <Icon name={a.icon} size={16} color="var(--fg-2)" />
              <span style={{ font: '500 13px Inter', flex: 1 }}>{a.label}</span>
              <span style={{ font: '500 11px Inter', color: 'var(--fg-3)' }}>{a.hint}</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

Object.assign(window, { CommandPalette });
