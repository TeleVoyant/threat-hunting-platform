function LateralGraph({ data, height = 380 }) {
  // Static positions for a deterministic, readable layout
  return (
    <svg viewBox="0 0 700 380" style={{ width: '100%', height, background: 'var(--bg-1)', borderRadius: 'var(--r-3)' }}>
      <defs>
        <marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
          <path d="M 0 0 L 10 5 L 0 10 z" fill="#1f4a75" />
        </marker>
        <marker id="arr-crit" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
          <path d="M 0 0 L 10 5 L 0 10 z" fill="#E74C3C" />
        </marker>
      </defs>

      {/* edges */}
      {data.edges.map((e, i) => {
        const a = data.nodes.find(n => n.id === e.from);
        const b = data.nodes.find(n => n.id === e.to);
        if (!a || !b) return null;
        const crit = e.severity === 'critical';
        return (
          <g key={i}>
            <line x1={a.x} y1={a.y} x2={b.x} y2={b.y}
              stroke={crit ? '#E74C3C' : '#1f4a75'}
              strokeWidth={crit ? 1.8 : 1.2}
              strokeDasharray={crit ? '0' : '4 4'}
              markerEnd={crit ? 'url(#arr-crit)' : 'url(#arr)'}
              opacity={crit ? 0.9 : 0.6}
            />
            {e.label && (
              <text x={(a.x + b.x) / 2} y={(a.y + b.y) / 2 - 6}
                fill={crit ? '#E74C3C' : '#6E84A0'}
                fontFamily="IBM Plex Mono" fontSize="9" textAnchor="middle">{e.label}</text>
            )}
          </g>
        );
      })}

      {/* nodes */}
      {data.nodes.map(n => {
        const accent = n.type === 'dc' ? '#E74C3C' : n.type === 'service' ? '#F39C12' : '#12B5B0';
        return (
          <g key={n.id}>
            <circle cx={n.x} cy={n.y} r="22" fill="#0c2444" stroke={accent} strokeWidth="1.5" />
            <text x={n.x} y={n.y + 4} fill="#E8F0FA" fontFamily="Inter" fontSize="10" fontWeight="600" textAnchor="middle">{n.short}</text>
            <text x={n.x} y={n.y + 38} fill="#A9BBD2" fontFamily="IBM Plex Mono" fontSize="9" textAnchor="middle">{n.label}</text>
          </g>
        );
      })}

      {/* legend */}
      <g transform="translate(16,16)">
        <rect width="170" height="62" fill="#050f22" stroke="#163659" rx="6" />
        <text x="10" y="14" fill="#6E84A0" fontFamily="Inter" fontSize="9" fontWeight="600" letterSpacing="0.06em">LEGEND</text>
        <circle cx="14" cy="30" r="4" fill="#0c2444" stroke="#E74C3C" />
        <text x="24" y="33" fill="#A9BBD2" fontFamily="Inter" fontSize="10">Domain controller</text>
        <circle cx="14" cy="46" r="4" fill="#0c2444" stroke="#12B5B0" />
        <text x="24" y="49" fill="#A9BBD2" fontFamily="Inter" fontSize="10">Workstation</text>
      </g>
    </svg>
  );
}

Object.assign(window, { LateralGraph });
