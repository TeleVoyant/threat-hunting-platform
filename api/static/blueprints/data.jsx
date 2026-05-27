/* Sample analyst data for the demo dashboard */
const DETECTIONS = [
  {
    id: 'DET-8421', severity: 'critical', confidence: 0.94, age: '14m',
    title: 'Credential reuse · svc_backup → 7 hosts in 4m',
    summary: 'Service account svc_backup authenticated via RDP across 7 hosts during the 02:00–04:00 window. Pattern matches lateral-movement signature LM-23.',
    host: 'WIN-DC01', model: 'lateral-cred v2.1',
    tags: ['RDP', 'off-hours', 'T1078', 'xgb v2.1'],
    iocs: [
      { kind: 'user',  value: 'CORP\\svc_backup' },
      { kind: 'ip',    value: '10.0.4.21' },
      { kind: 'host',  value: 'WIN-DC01.corp.internal' },
      { kind: 'event', value: '4624 · logon type 10 (RDP)' },
    ],
    mitre: ['T1078.002', 'T1021.001', 'T1550.002'],
    timeline: [
      { t: '03:14:08 UTC', event: 'First anomalous logon — WIN-WS-04', crit: true },
      { t: '03:14:42 UTC', event: 'Fan-out to WIN-WS-12, WIN-WS-19' },
      { t: '03:16:01 UTC', event: 'Pivot to WIN-DC01 (privileged target)', crit: true },
      { t: '03:18:00 UTC', event: 'Model emitted detection · conf 0.94' },
    ],
  },
  {
    id: 'DET-8418', severity: 'high', confidence: 0.82, age: '38m',
    title: 'DNS exfil · burst tunneling to *.tk',
    summary: '2,341 unique TXT-record queries to short-lived .tk subdomains over a 9-minute window. Entropy + payload-size features triggered exfil detector.',
    host: 'FIN-WS-04', model: 'dns-exfil v1.6',
    tags: ['DNS', 'TXT', 'high-entropy', 'T1071.004'],
    iocs: [
      { kind: 'host',  value: 'FIN-WS-04.corp.internal' },
      { kind: 'fqdn',  value: 'a4f1b.h7k2.q.tk' },
      { kind: 'proc',  value: 'powershell.exe (PID 7421)' },
    ],
    mitre: ['T1071.004', 'T1048.003'],
    timeline: [
      { t: '02:38:12 UTC', event: 'Spike: 2,341 TXT queries to .tk', crit: true },
      { t: '02:41:55 UTC', event: 'Payload entropy 7.6 (>6.5 threshold)' },
      { t: '02:47:00 UTC', event: 'Model emitted detection · conf 0.82' },
    ],
  },
  {
    id: 'DET-8410', severity: 'medium', confidence: 0.61, age: '1h',
    title: 'Off-hours RDP from new geography',
    summary: 'User m.kovalenko@corp logged in via RDP from 185.245.x.x (Bucharest) at 03:42 local. First time geo for this user.',
    host: 'DEV-LX-12', model: 'geo-anomaly v0.9',
    tags: ['RDP', 'geo-new', 'T1078'],
    iocs: [
      { kind: 'user',  value: 'CORP\\m.kovalenko' },
      { kind: 'ip',    value: '185.245.91.12' },
      { kind: 'geo',   value: 'Bucharest, RO' },
    ],
    mitre: ['T1078'],
    timeline: [
      { t: '03:42:11 UTC', event: 'RDP from 185.245.91.12 (new geo)' },
      { t: '03:42:30 UTC', event: 'Model emitted detection · conf 0.61' },
    ],
  },
  {
    id: 'DET-8395', severity: 'low', confidence: 0.42, age: '2h',
    title: 'Stale service account · first interactive login in 90d',
    summary: 'svc_archive (last interactive: 2026-01-14) logged in interactively on a member server. Below confidence threshold but flagged for review.',
    host: 'WIN-WS-FS02', model: 'stale-account v0.4',
    tags: ['stale', 'interactive', 'T1078.002'],
    iocs: [{ kind: 'user', value: 'CORP\\svc_archive' }],
    mitre: ['T1078.002'],
    timeline: [{ t: '01:18:42 UTC', event: 'Interactive logon · 90d gap' }],
  },
  {
    id: 'DET-8382', severity: 'high', confidence: 0.79, age: '3h',
    title: 'Pass-the-hash signature on member server',
    summary: 'NTLM logon without corresponding Kerberos TGS — classic PtH indicator. Source process: lsass injected.',
    host: 'WIN-WS-19', model: 'lateral-cred v2.1',
    tags: ['NTLM', 'PtH', 'T1550.002'],
    iocs: [{ kind: 'user', value: 'CORP\\admin_jdoe' }, { kind: 'ip', value: '10.0.5.88' }],
    mitre: ['T1550.002', 'T1003.001'],
    timeline: [{ t: '00:14:00 UTC', event: 'NTLM logon · no Kerberos TGS', crit: true }],
  },
];

const KPI_POINTS_24H = [12, 14, 11, 13, 18, 22, 26, 24, 29, 28, 33, 41, 38, 36, 48, 52, 58, 62, 71, 88, 132, 84, 76, 62];
const DNS_POINTS_24H = [120, 130, 118, 124, 146, 159, 162, 188, 220, 245, 280, 305, 340, 410, 380, 360, 340, 320, 290, 260, 248, 230, 220, 215];

const LATERAL_DATA = {
  nodes: [
    { id: 'svc',  short: 'svc',   label: 'svc_backup',  x: 90,  y: 200, type: 'service' },
    { id: 'ws04', short: 'WS04',  label: 'WIN-WS-04',  x: 230, y: 90,  type: 'host' },
    { id: 'ws12', short: 'WS12',  label: 'WIN-WS-12',  x: 230, y: 200, type: 'host' },
    { id: 'ws19', short: 'WS19',  label: 'WIN-WS-19',  x: 230, y: 310, type: 'host' },
    { id: 'fs02', short: 'FS02',  label: 'WIN-FS02',   x: 400, y: 140, type: 'host' },
    { id: 'fs07', short: 'FS07',  label: 'WIN-FS07',   x: 400, y: 260, type: 'host' },
    { id: 'dc01', short: 'DC01',  label: 'WIN-DC01',   x: 580, y: 200, type: 'dc' },
  ],
  edges: [
    { from: 'svc', to: 'ws04', label: 'RDP' },
    { from: 'svc', to: 'ws12', label: 'RDP' },
    { from: 'svc', to: 'ws19', label: 'RDP' },
    { from: 'ws04', to: 'fs02', label: 'SMB' },
    { from: 'ws12', to: 'fs07', label: 'SMB' },
    { from: 'ws19', to: 'fs07', label: 'SMB' },
    { from: 'fs02', to: 'dc01', label: 'NTLM', severity: 'critical' },
    { from: 'fs07', to: 'dc01', label: 'RDP', severity: 'critical' },
  ],
};

Object.assign(window, { DETECTIONS, KPI_POINTS_24H, DNS_POINTS_24H, LATERAL_DATA });
