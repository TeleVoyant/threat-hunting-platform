function KpiCard({ label, value, unit, trend, accent, sub }) {
  const trendColor = trend?.dir === 'up'   ? 'var(--success)'
                   : trend?.dir === 'down' ? 'var(--success)'
                   : trend?.dir === 'crit' ? 'var(--critical)'
                   :                          'var(--fg-2)';
  return (
    <div className="card card-pad" style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      <div className="eyebrow">{label}</div>
      <div className="mono tabnum" style={{ font: '600 30px IBM Plex Mono', lineHeight: '36px', letterSpacing: '-0.02em', color: accent || 'var(--fg-1)' }}>
        {value}{unit && <span style={{ font: '600 16px IBM Plex Mono', color: 'var(--fg-3)', marginLeft: 2 }}>{unit}</span>}
      </div>
      {trend && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 5, font: '500 12px Inter', color: trendColor }}>
          <Icon name={trend.dir === 'down' ? 'trending-down' : 'trending-up'} size={12} />
          {trend.text}
        </div>
      )}
      {sub && !trend && <div style={{ font: '500 12px Inter', color: 'var(--fg-2)' }}>{sub}</div>}
    </div>
  );
}

function MiniChart({ points, anomalyIdx, color = '#12B5B0', height = 80 }) {
  const w = 100, h = 100;
  const xs = points.map((_, i) => (i / (points.length - 1)) * w);
  const max = Math.max(...points), min = Math.min(...points);
  const ys = points.map(v => h - ((v - min) / (max - min || 1)) * (h * 0.8) - h * 0.1);
  const path = xs.map((x, i) => `${i ? 'L' : 'M'} ${x.toFixed(1)} ${ys[i].toFixed(1)}`).join(' ');
  const area = `${path} L ${w} ${h} L 0 ${h} Z`;
  const gid = `g-${Math.random().toString(36).slice(2, 8)}`;
  return (
    <svg viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" style={{ width: '100%', height }}>
      <defs>
        <linearGradient id={gid} x1="0" x2="0" y1="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.35" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <path d={area} fill={`url(#${gid})`} />
      <path d={path} fill="none" stroke={color} strokeWidth="1.4" vectorEffect="non-scaling-stroke" />
      {anomalyIdx != null && (
        <circle cx={xs[anomalyIdx]} cy={ys[anomalyIdx]} r="2.2" fill="#E74C3C" stroke="#081B34" strokeWidth="0.8" vectorEffect="non-scaling-stroke" />
      )}
    </svg>
  );
}

Object.assign(window, { KpiCard, MiniChart });
