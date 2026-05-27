function App() {
  const [view, setView] = React.useState('dashboard');
  const [selected, setSelected] = React.useState(null);
  const [hunt, setHunt] = React.useState(false);
  const [palette, setPalette] = React.useState(false);
  const [toast, setToast] = React.useState(null);

  React.useEffect(() => {
    const onKey = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setPalette(true); }
      if (e.key === 'Escape') { setSelected(null); setHunt(false); }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  React.useEffect(() => {
    if (window.lucide) window.lucide.createIcons();
  });

  const critCount = DETECTIONS.filter(d => d.severity === 'critical').length;

  const showToast = (msg) => { setToast(msg); setTimeout(() => setToast(null), 3000); };

  return (
    <div className="app">
      <Sidebar view={view} setView={setView} criticalCount={critCount} openHunts={12} />
      <Topbar onOpenPalette={() => setPalette(true)} criticalCount={critCount} onOpenInvestigation={() => setSelected(DETECTIONS[0])} />
      <main className="main">
        <div className="main-inner">
          {view === 'dashboard' && <DashboardView onSelect={setSelected} onStartHunt={() => setHunt(true)} />}
          {view === 'hunts'     && <HuntsView onStartHunt={() => setHunt(true)} onSelect={setSelected} />}
          {view === 'alerts'    && <AlertsView onSelect={setSelected} />}
          {view === 'lateral'   && <LateralView onSelect={setSelected} />}
          {view === 'dns'       && <DnsView onSelect={setSelected} />}
          {view === 'analytics' && <AnalyticsView />}
          {view === 'settings'  && <SettingsView />}
          {view === 'integrations' && <SettingsView integrations />}
        </div>
      </main>

      {selected && (
        <InvestigationPanel
          detection={selected}
          onClose={() => setSelected(null)}
          onQuarantine={() => { setSelected(null); showToast(`Host ${selected.host} quarantined. Action ID Q-${Math.floor(Math.random()*9000+1000)}.`); }}
        />
      )}
      <HuntComposer
        open={hunt}
        onClose={() => setHunt(false)}
        onSave={(h) => { setHunt(false); showToast(`Hunt "${h.name}" running against last ${h.window} of telemetry.`); }}
      />
      <CommandPalette
        open={palette}
        onClose={() => setPalette(false)}
        onAction={(id) => {
          if (id === 'new-hunt') setHunt(true);
          else if (id === 'open-lateral') setView('lateral');
          else if (id === 'open-dns') setView('dns');
          else if (id === 'open-settings') setView('settings');
          else showToast(`Action: ${id}`);
        }}
      />
      {toast && (
        <div style={{
          position: 'fixed', bottom: 24, left: '50%', transform: 'translateX(-50%)',
          background: 'var(--bg-3)', border: '1px solid var(--apt-teal)',
          padding: '10px 16px', borderRadius: 'var(--r-2)', color: 'var(--fg-1)',
          font: '500 13px Inter', boxShadow: 'var(--shadow-2)', zIndex: 60,
          display: 'flex', alignItems: 'center', gap: 8,
        }}>
          <Icon name="check-circle-2" size={14} color="var(--apt-teal)" />
          {toast}
        </div>
      )}
    </div>
  );
}

/* ──────────────────────  VIEWS  ────────────────────── */

function PageHeader({ title, eyebrow, children }) {
  return (
    <div style={{ display: 'flex', alignItems: 'flex-end', gap: 16, marginBottom: 22, paddingBottom: 14, borderBottom: '1px solid var(--border-1)' }}>
      <div>
        <div className="eyebrow">{eyebrow}</div>
        <h1 style={{ font: '600 24px Inter', color: 'var(--fg-1)', letterSpacing: '-0.015em', margin: '4px 0 0' }}>{title}</h1>
      </div>
      <div className="spacer"></div>
      {children}
    </div>
  );
}

function DashboardView({ onSelect, onStartHunt }) {
  const top = DETECTIONS.filter(d => d.severity === 'critical' || d.severity === 'high').slice(0, 2);
  return (
    <>
      <PageHeader eyebrow="Nexus Bancorp · all detectors" title="Operations dashboard">
        <button className="btn btn-secondary"><Icon name="download" size={13} /> Export</button>
        <button className="btn btn-primary" onClick={onStartHunt}><Icon name="crosshair" size={13} /> Start hunt</button>
      </PageHeader>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14, marginBottom: 18 }}>
        <KpiCard label="Active hunts"     value="247" trend={{ dir: 'up', text: '+12 vs 24h' }} />
        <KpiCard label="Critical · open"  value="3"   accent="var(--critical)" sub="2 lateral · 1 exfil" />
        <KpiCard label="MTTD"             value="4.2" unit="m" trend={{ dir: 'down', text: '−38% WoW' }} />
        <KpiCard label="Models live"      value="11 / 12" sub="dns-tunneling retraining" />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 14, marginBottom: 18 }}>
        <div className="card card-pad">
          <div style={{ display: 'flex', alignItems: 'center', marginBottom: 10 }}>
            <div>
              <div className="eyebrow">Detections · last 24h</div>
              <div className="mono tabnum" style={{ font: '600 22px IBM Plex Mono', color: 'var(--fg-1)' }}>1,284</div>
            </div>
            <span className="spacer"></span>
            <span className="pill" style={{ background: 'rgba(231,76,60,0.18)', color: '#E74C3C' }}>
              <span className="pill-dot" style={{ background: '#E74C3C', boxShadow: '0 0 6px #E74C3C' }}></span>
              SPIKE · 20:00 UTC
            </span>
          </div>
          <MiniChart points={KPI_POINTS_24H} anomalyIdx={20} height={140} />
        </div>
        <div className="card card-pad">
          <div className="eyebrow" style={{ marginBottom: 10 }}>By model · last 24h</div>
          <ModelBars data={[
            { label: 'lateral-cred',   value: 612, color: '#12B5B0' },
            { label: 'dns-exfil',      value: 384, color: '#5B8DEF' },
            { label: 'beaconing',      value: 168, color: '#B284E6' },
            { label: 'geo-anomaly',    value: 88,  color: '#F39C12' },
            { label: 'stale-account',  value: 32,  color: '#6CCB9F' },
          ]} />
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
        <h2 style={{ font: '600 16px Inter', color: 'var(--fg-1)', margin: 0 }}>Top priority</h2>
        <span className="mono" style={{ font: '500 11px IBM Plex Mono', color: 'var(--fg-3)' }}>{top.length} surfaced</span>
        <span className="spacer"></span>
        <button className="btn btn-ghost"><Icon name="filter" size={13} /> Filters</button>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 22 }}>
        {top.map(d => <DetectionCard key={d.id} detection={d} onOpen={onSelect} />)}
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
        <h2 style={{ font: '600 16px Inter', color: 'var(--fg-1)', margin: 0 }}>All detections</h2>
        <span className="spacer"></span>
        <span className="mono" style={{ font: '500 11px IBM Plex Mono', color: 'var(--fg-3)' }}>severity · time · confidence</span>
      </div>
      <DetectionTable detections={DETECTIONS} onSelect={onSelect} />
    </>
  );
}

function ModelBars({ data }) {
  const max = Math.max(...data.map(d => d.value));
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 9 }}>
      {data.map(d => (
        <div key={d.label} style={{ display: 'grid', gridTemplateColumns: '110px 1fr 50px', alignItems: 'center', gap: 10 }}>
          <span className="mono" style={{ font: '500 11px IBM Plex Mono', color: 'var(--fg-2)' }}>{d.label}</span>
          <span style={{ height: 8, background: 'var(--bg-1)', borderRadius: 4, overflow: 'hidden' }}>
            <span style={{ display: 'block', width: `${(d.value / max) * 100}%`, height: '100%', background: d.color, borderRadius: 4 }}></span>
          </span>
          <span className="mono tabnum" style={{ font: '500 12px IBM Plex Mono', color: 'var(--fg-1)', textAlign: 'right' }}>{d.value}</span>
        </div>
      ))}
    </div>
  );
}

function HuntsView({ onStartHunt, onSelect }) {
  const hunts = [
    { name: 'Off-hours service-account fan-out', status: 'running', conf: '—', dets: 14, scope: 'AD · all OUs', age: 'started 2h ago' },
    { name: 'PowerShell + base64 + DNS TXT',     status: 'running', conf: '—', dets: 4,  scope: 'EDR · 1.2k hosts', age: 'started 45m ago' },
    { name: 'Stale account interactive login',   status: 'paused',  conf: '—', dets: 0,  scope: 'AD · service OU',  age: 'paused 1d ago' },
    { name: 'Kerberoasting · ticket request burst', status: 'completed', conf: '—', dets: 22, scope: '7d',          age: 'completed 6h ago' },
  ];
  return (
    <>
      <PageHeader eyebrow="Saved & live" title="Hunts">
        <button className="btn btn-secondary"><Icon name="library" size={13} /> Hunt library</button>
        <button className="btn btn-primary" onClick={onStartHunt}><Icon name="crosshair" size={13} /> New hunt</button>
      </PageHeader>
      <div className="card" style={{ overflow: 'hidden' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1.6fr 100px 80px 1fr 1fr 32px', padding: '10px 18px', background: 'var(--bg-1)', borderBottom: '1px solid var(--border-1)', font: '600 10px Inter', letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--fg-3)' }}>
          <span>Hunt</span><span>State</span><span>Hits</span><span>Scope</span><span>Updated</span><span></span>
        </div>
        {hunts.map((h, i) => {
          const st = h.status === 'running' ? '#12B5B0' : h.status === 'paused' ? '#F39C12' : '#A9BBD2';
          return (
            <div key={i} style={{ display: 'grid', gridTemplateColumns: '1.6fr 100px 80px 1fr 1fr 32px', padding: '12px 18px', borderBottom: '1px solid #122e4d', alignItems: 'center' }}>
              <span style={{ font: '500 13px Inter', color: 'var(--fg-1)' }}>{h.name}</span>
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, font: '500 12px Inter', color: st }}>
                <span style={{ width: 7, height: 7, borderRadius: '50%', background: st, boxShadow: h.status === 'running' ? `0 0 6px ${st}` : 'none' }}></span>
                {h.status}
              </span>
              <span className="mono tabnum" style={{ font: '500 12px IBM Plex Mono', color: 'var(--fg-1)' }}>{h.dets}</span>
              <span className="mono" style={{ font: '500 12px IBM Plex Mono', color: 'var(--fg-2)' }}>{h.scope}</span>
              <span className="mono" style={{ font: '500 12px IBM Plex Mono', color: 'var(--fg-3)' }}>{h.age}</span>
              <button className="btn btn-ghost btn-icon"><Icon name="more-horizontal" size={14} color="var(--fg-3)" /></button>
            </div>
          );
        })}
      </div>
    </>
  );
}

function AlertsView({ onSelect }) {
  return (
    <>
      <PageHeader eyebrow="Queue · open" title="Alerts" />
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {DETECTIONS.map(d => <DetectionCard key={d.id} detection={d} onOpen={onSelect} />)}
      </div>
    </>
  );
}

function LateralView({ onSelect }) {
  return (
    <>
      <PageHeader eyebrow="Credential-based" title="Lateral-movement graph">
        <button className="btn btn-secondary"><Icon name="clock" size={13} /> Last 24h</button>
        <button className="btn btn-secondary"><Icon name="download" size={13} /> Export</button>
      </PageHeader>
      <div className="card" style={{ padding: 14 }}>
        <LateralGraph data={LATERAL_DATA} />
      </div>
      <div style={{ marginTop: 18, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        {DETECTIONS.filter(d => d.tags.includes('RDP') || d.tags.includes('NTLM') || d.tags.includes('PtH')).map(d =>
          <DetectionCard key={d.id} detection={d} onOpen={onSelect} />
        )}
      </div>
    </>
  );
}

function DnsView({ onSelect }) {
  const exfil = DETECTIONS.find(d => d.id === 'DET-8418');
  return (
    <>
      <PageHeader eyebrow="Exfiltration channel" title="DNS exfil" />
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 14, marginBottom: 18 }}>
        <div className="card card-pad">
          <div style={{ display: 'flex', alignItems: 'center', marginBottom: 10 }}>
            <div>
              <div className="eyebrow">DNS query rate · last 24h</div>
              <div className="mono tabnum" style={{ font: '600 22px IBM Plex Mono', color: 'var(--fg-1)' }}>410<span style={{ font: '600 12px IBM Plex Mono', color: 'var(--fg-3)', marginLeft: 4 }}>peak q/s</span></div>
            </div>
          </div>
          <MiniChart points={DNS_POINTS_24H} anomalyIdx={13} color="#5B8DEF" height={160} />
        </div>
        <div className="card card-pad">
          <div className="eyebrow" style={{ marginBottom: 10 }}>Top suspicious TLDs</div>
          <ModelBars data={[
            { label: '*.tk', value: 2341, color: '#E74C3C' },
            { label: '*.ml', value: 1102, color: '#FF7B3A' },
            { label: '*.ga', value: 442,  color: '#F39C12' },
            { label: '*.cf', value: 188,  color: '#5B8DEF' },
          ]} />
        </div>
      </div>
      {exfil && <DetectionCard detection={exfil} onOpen={onSelect} />}
    </>
  );
}

function AnalyticsView() {
  return (
    <>
      <PageHeader eyebrow="Last 7 days" title="Analytics" />
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14, marginBottom: 18 }}>
        <KpiCard label="Detections / day" value="1,284" trend={{ dir: 'up', text: '+8% WoW' }} />
        <KpiCard label="Avg confidence"   value="0.78" sub="↑ from 0.71" />
        <KpiCard label="False-positive rate" value="3.1" unit="%" trend={{ dir: 'down', text: '−1.2pp' }} />
        <KpiCard label="Analyst MTTR"     value="9.4" unit="m" trend={{ dir: 'down', text: '−18% WoW' }} />
      </div>
      <div className="card card-pad">
        <div className="eyebrow" style={{ marginBottom: 10 }}>Model confidence distribution</div>
        <MiniChart points={[12,18,30,55,82,110,128,140,128,98,72,48,32,22,18,14,18,32,58,84,112,86,52,34,20]} anomalyIdx={20} height={180} />
      </div>
    </>
  );
}

function SettingsView({ integrations }) {
  return (
    <>
      <PageHeader eyebrow={integrations ? 'Connect data sources' : 'Workspace'} title={integrations ? 'Integrations' : 'Settings'} />
      <div className="card card-pad" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        <SettingRow label="Default detection window" value="Last 24 hours" />
        <SettingRow label="Severity floor (display)"  value="LOW · 0.30" />
        <SettingRow label="Auto-suppress benign"       value="On" toggle />
        <SettingRow label="Model auto-retraining"      value="Weekly · Sun 02:00 UTC" />
      </div>
    </>
  );
}
function SettingRow({ label, value, toggle }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 14, padding: '8px 0', borderBottom: '1px solid var(--border-1)' }}>
      <div style={{ flex: 1, font: '500 14px Inter', color: 'var(--fg-1)' }}>{label}</div>
      <div className="mono" style={{ font: '500 12px IBM Plex Mono', color: 'var(--fg-2)' }}>{value}</div>
      {toggle && (
        <span style={{ width: 32, height: 18, borderRadius: 999, background: 'var(--apt-teal)', position: 'relative' }}>
          <span style={{ position: 'absolute', right: 2, top: 2, width: 14, height: 14, borderRadius: '50%', background: 'var(--fg-on-teal)' }}></span>
        </span>
      )}
    </div>
  );
}

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<App />);
