function HuntComposer({ open, onClose, onSave }) {
  const [query, setQuery] = React.useState('user:svc_* AND auth_count > 5 AND off_hours');
  const [model, setModel] = React.useState('lateral-credential');
  const [window_, setWindow] = React.useState('7d');
  const [name, setName] = React.useState('Off-hours service-account fan-out');

  if (!open) return null;

  return (
    <div className="scrim" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border-1)', display: 'flex', alignItems: 'center', gap: 10 }}>
          <Icon name="crosshair" size={18} color="var(--apt-teal)" />
          <h3 style={{ font: '600 16px Inter', color: 'var(--fg-1)', margin: 0 }}>New hunt</h3>
          <span className="spacer"></span>
          <button className="btn btn-ghost btn-icon" onClick={onClose}><Icon name="x" size={16} color="var(--fg-2)" /></button>
        </div>

        <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 14 }}>
          <Field label="Hunt name">
            <input className="input" value={name} onChange={e => setName(e.target.value)} style={{ width: '100%' }} />
          </Field>
          <Field label="Detection model">
            <div style={{ display: 'flex', gap: 6 }}>
              {[
                { id: 'lateral-credential', label: 'Lateral · credential' },
                { id: 'dns-exfil', label: 'DNS exfil' },
                { id: 'beacon', label: 'Beaconing' },
              ].map(m => (
                <button key={m.id} onClick={() => setModel(m.id)} className="btn" style={{
                  background: model === m.id ? 'rgba(18,181,176,0.14)' : 'var(--bg-1)',
                  color: model === m.id ? 'var(--apt-teal-bright)' : 'var(--fg-2)',
                  border: model === m.id ? '1px solid var(--apt-teal)' : '1px solid var(--border-2)',
                  font: '500 12px Inter'
                }}>{m.label}</button>
              ))}
            </div>
          </Field>
          <Field label="Query (KQL-like)">
            <textarea className="input mono" value={query} onChange={e => setQuery(e.target.value)} rows={3} style={{ width: '100%', fontFamily: 'IBM Plex Mono', resize: 'vertical' }} />
          </Field>
          <Field label="Time window">
            <div style={{ display: 'flex', gap: 6 }}>
              {['24h', '7d', '30d', '90d'].map(w => (
                <button key={w} onClick={() => setWindow(w)} className="btn" style={{
                  background: window_ === w ? 'rgba(18,181,176,0.14)' : 'var(--bg-1)',
                  color: window_ === w ? 'var(--apt-teal-bright)' : 'var(--fg-2)',
                  border: window_ === w ? '1px solid var(--apt-teal)' : '1px solid var(--border-2)',
                  font: '500 12px IBM Plex Mono', minWidth: 56, justifyContent: 'center'
                }}>{w}</button>
              ))}
            </div>
          </Field>
        </div>

        <div style={{ padding: '14px 20px', borderTop: '1px solid var(--border-1)', display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
          <button className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary" onClick={() => onSave({ name, model, query, window: window_ })}>
            <Icon name="play" size={13} /> Run hunt
          </button>
        </div>
      </div>
    </div>
  );
}

function Field({ label, children }) {
  return (
    <label style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      <span className="eyebrow">{label}</span>
      {children}
    </label>
  );
}

Object.assign(window, { HuntComposer });
