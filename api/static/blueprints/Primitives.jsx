/* ────── Pill primitives ────── */
const SEVERITY = {
  low:      { label: 'LOW',      color: '#2ECC71', bg: 'rgba(46,204,113,0.14)' },
  medium:   { label: 'MEDIUM',   color: '#F39C12', bg: 'rgba(243,156,18,0.16)' },
  high:     { label: 'HIGH',     color: '#FF7B3A', bg: 'rgba(255,123,58,0.16)' },
  critical: { label: 'CRITICAL', color: '#E74C3C', bg: 'rgba(231,76,60,0.18)' },
};

function SeverityBadge({ level }) {
  const s = SEVERITY[level] || SEVERITY.low;
  const isCrit = level === 'critical';
  return (
    <span className="pill" style={{ background: s.bg, color: s.color }}>
      <span className="pill-dot" style={{ background: s.color, boxShadow: isCrit ? `0 0 6px ${s.color}` : 'none' }}></span>
      {s.label}
    </span>
  );
}

const STATUS = {
  resolved:     { color: '#2ECC71', bg: 'rgba(46,204,113,0.14)', label: 'Resolved' },
  triaging:     { color: '#3498DB', bg: 'rgba(52,152,219,0.14)', label: 'Triaging' },
  review:       { color: '#F39C12', bg: 'rgba(243,156,18,0.16)', label: 'Needs review' },
  escalated:    { color: '#E74C3C', bg: 'rgba(231,76,60,0.18)', label: 'Escalated' },
  suppressed:   { color: '#A9BBD2', bg: '#0c2444',             label: 'Suppressed' },
  benign:       { color: '#6E84A0', bg: '#0c2444',             label: 'Benign' },
};

function StatusPill({ status }) {
  const s = STATUS[status] || STATUS.triaging;
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center',
      background: s.bg, color: s.color,
      padding: '3px 10px', borderRadius: '4px',
      font: '600 11px Inter',
      border: status === 'suppressed' || status === 'benign' ? '1px solid var(--border-1)' : 'none',
    }}>{s.label}</span>
  );
}

function Icon({ name, size = 16, color, style }) {
  const ref = React.useRef(null);
  React.useEffect(() => {
    if (window.lucide && ref.current) window.lucide.createIcons({ icons: window.lucide.icons, nameAttr: 'data-lucide' });
  }, [name]);
  return (
    <i ref={ref} data-lucide={name} style={{ width: size, height: size, color, display: 'inline-flex', ...style }} />
  );
}

Object.assign(window, { SEVERITY, STATUS, SeverityBadge, StatusPill, Icon });
