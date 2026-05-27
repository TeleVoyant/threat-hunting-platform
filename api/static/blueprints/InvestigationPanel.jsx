function InvestigationPanel({ detection, onClose, onQuarantine }) {
  if (!detection) return null;
  const s = SEVERITY[detection.severity];

  return (
    <div className="panel-right scroll" style={{ overflow: 'auto' }}>
      <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border-1)', display: 'flex', alignItems: 'center', gap: 10, background: 'var(--bg-2)' }}>
        <span className="eyebrow">Investigation</span>
        <span className="mono" style={{ font: '500 11px IBM Plex Mono', color: 'var(--fg-3)' }}>{detection.id}</span>
        <span className="spacer"></span>
        <button className="btn btn-ghost btn-icon" onClick={onClose} title="Close">
          <Icon name="x" size={16} color="var(--fg-2)" />
        </button>
      </div>

      <div style={{ padding: '20px 22px', display: 'flex', flexDirection: 'column', gap: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <SeverityBadge level={detection.severity} />
          <StatusPill status="triaging" />
          <span className="mono tabnum" style={{ font: '500 12px IBM Plex Mono', color: 'var(--apt-teal-bright)', marginLeft: 'auto' }}>conf {detection.confidence.toFixed(2)}</span>
        </div>
        <h2 className="apt-h2" style={{ font: '600 22px Inter', color: 'var(--fg-1)', margin: 0, letterSpacing: '-0.01em', lineHeight: '28px' }}>{detection.title}</h2>
        <p style={{ font: '500 13px Inter', color: 'var(--fg-2)', margin: 0, lineHeight: '20px' }}>{detection.summary}</p>

        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn btn-primary"><Icon name="search-code" size={14} /> Open in hunt</button>
          <button className="btn btn-secondary"><Icon name="user-x" size={14} /> Disable account</button>
          <button className="btn btn-danger" onClick={onQuarantine}><Icon name="shield-x" size={14} /> Quarantine host</button>
        </div>

        <Section title="Timeline">
          <Timeline items={detection.timeline} />
        </Section>

        <Section title="IOCs">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {detection.iocs.map((ioc, i) => (
              <div key={i} className="mono" style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 10px', background: 'var(--bg-2)', border: '1px solid var(--border-1)', borderRadius: 'var(--r-2)' }}>
                <span style={{ font: '500 10px Inter', color: 'var(--fg-3)', letterSpacing: '0.08em', textTransform: 'uppercase', minWidth: 38 }}>{ioc.kind}</span>
                <span style={{ font: '500 12px IBM Plex Mono', color: 'var(--fg-1)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ioc.value}</span>
                <button className="btn btn-ghost btn-icon" title="Copy"><Icon name="copy" size={13} color="var(--fg-3)" /></button>
              </div>
            ))}
          </div>
        </Section>

        <Section title="Model card">
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
            <Kv k="Detector" v={detection.model} />
            <Kv k="Algorithm" v="XGBoost · binary" />
            <Kv k="Features" v="148" />
            <Kv k="Recall (val)" v="0.91" />
          </div>
        </Section>

        <Section title="MITRE ATT&CK">
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {detection.mitre.map(m => (
              <span key={m} style={{ background: 'rgba(18,181,176,0.10)', border: '1px solid rgba(18,181,176,0.3)', color: 'var(--apt-teal-bright)', padding: '3px 8px', borderRadius: 4, font: '600 11px IBM Plex Mono' }}>{m}</span>
            ))}
          </div>
        </Section>
      </div>
    </div>
  );
}

function Section({ title, children }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      <div className="eyebrow">{title}</div>
      {children}
    </div>
  );
}
function Kv({ k, v }) {
  return (
    <div style={{ background: 'var(--bg-2)', border: '1px solid var(--border-1)', borderRadius: 'var(--r-2)', padding: '8px 10px' }}>
      <div className="eyebrow" style={{ fontSize: 9 }}>{k}</div>
      <div className="mono" style={{ font: '500 12px IBM Plex Mono', color: 'var(--fg-1)' }}>{v}</div>
    </div>
  );
}
function Timeline({ items }) {
  return (
    <div style={{ position: 'relative', paddingLeft: 18 }}>
      <span style={{ position: 'absolute', left: 5, top: 6, bottom: 6, width: 1, background: 'var(--border-2)' }}></span>
      {items.map((it, i) => (
        <div key={i} style={{ position: 'relative', paddingBottom: 12 }}>
          <span style={{ position: 'absolute', left: -16, top: 4, width: 9, height: 9, borderRadius: '50%', background: it.crit ? 'var(--critical)' : 'var(--apt-teal)', boxShadow: it.crit ? '0 0 6px var(--critical)' : 'none' }}></span>
          <div className="mono" style={{ font: '500 11px IBM Plex Mono', color: 'var(--fg-3)' }}>{it.t}</div>
          <div style={{ font: '500 13px Inter', color: 'var(--fg-1)' }}>{it.event}</div>
        </div>
      ))}
    </div>
  );
}

Object.assign(window, { InvestigationPanel });
