function DetectionTable({ detections, onSelect, selectedId }) {
  const cols = '60px 1fr 150px 90px 110px 90px';
  return (
    <div className="card" style={{ overflow: 'hidden' }}>
      <div style={{
        display: 'grid', gridTemplateColumns: cols,
        padding: '10px 16px', background: 'var(--bg-1)', borderBottom: '1px solid var(--border-1)',
        font: '600 10px Inter', letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--fg-3)'
      }}>
        <span>Sev</span><span>Detection</span><span>Host / actor</span><span>Conf</span><span>Model</span><span>Age</span>
      </div>
      {detections.map(d => {
        const s = SEVERITY[d.severity];
        const isSel = selectedId === d.id;
        return (
          <button key={d.id} onClick={() => onSelect(d)} style={{
            all: 'unset', cursor: 'pointer',
            display: 'grid', gridTemplateColumns: cols,
            padding: '10px 16px',
            borderBottom: '1px solid #122e4d',
            background: isSel ? 'var(--bg-4)' : 'transparent',
            borderLeft: isSel ? '2px solid var(--apt-teal)' : '2px solid transparent',
            paddingLeft: 14,
            alignItems: 'center',
            transition: 'background var(--dur-fast)',
          }}
          onMouseEnter={e => { if (!isSel) e.currentTarget.style.background = 'var(--bg-3)'; }}
          onMouseLeave={e => { if (!isSel) e.currentTarget.style.background = 'transparent'; }}
          >
            <span style={{ font: '700 10px Inter', letterSpacing: '0.08em', color: s.color }}>{s.label.slice(0, 4)}</span>
            <span style={{ font: '500 13px Inter', color: 'var(--fg-1)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{d.title}</span>
            <span className="mono" style={{ font: '500 12px IBM Plex Mono', color: 'var(--fg-2)' }}>{d.host}</span>
            <span className="mono tabnum" style={{ font: '500 12px IBM Plex Mono', color: d.confidence > 0.85 ? 'var(--apt-teal-bright)' : 'var(--fg-2)' }}>{d.confidence.toFixed(2)}</span>
            <span className="mono" style={{ font: '500 11px IBM Plex Mono', color: 'var(--fg-3)' }}>{d.model}</span>
            <span className="mono" style={{ font: '500 12px IBM Plex Mono', color: 'var(--fg-3)' }}>{d.age}</span>
          </button>
        );
      })}
    </div>
  );
}

function DetectionCard({ detection, onOpen }) {
  const s = SEVERITY[detection.severity];
  const isCrit = detection.severity === 'critical';
  return (
    <div className="card card-hover" onClick={() => onOpen(detection)} style={{
      padding: '14px 16px',
      cursor: 'pointer',
      borderLeft: `3px solid ${s.color}`,
      boxShadow: isCrit ? '0 0 0 1px rgba(231,76,60,0.18), 0 0 14px rgba(231,76,60,0.15)' : 'var(--shadow-1)',
      display: 'flex', flexDirection: 'column', gap: 10,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <SeverityBadge level={detection.severity} />
        <span className="mono" style={{ font: '500 11px IBM Plex Mono', color: 'var(--fg-3)' }}>{detection.id} · {detection.age} ago</span>
        <span className="spacer"></span>
        <span className="mono tabnum" style={{ font: '500 12px IBM Plex Mono', color: 'var(--apt-teal-bright)' }}>conf {detection.confidence.toFixed(2)}</span>
      </div>
      <div style={{ font: '600 15px Inter', color: 'var(--fg-1)', lineHeight: '22px' }}>{detection.title}</div>
      <div style={{ font: '500 12px Inter', color: 'var(--fg-2)', lineHeight: '18px' }}>{detection.summary}</div>
      <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
        {detection.tags.map(t => (
          <span key={t} className="mono" style={{ background: 'var(--bg-1)', border: '1px solid var(--border-1)', color: 'var(--fg-2)', padding: '2px 7px', borderRadius: 4, font: '500 11px IBM Plex Mono' }}>{t}</span>
        ))}
      </div>
    </div>
  );
}

Object.assign(window, { DetectionTable, DetectionCard });
