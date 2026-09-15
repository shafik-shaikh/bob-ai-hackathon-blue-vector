"""Benign background alerts for the synthetic corpus.

Real SOC feeds are overwhelmingly benign, and a correlation engine that is
only ever tested on planted attacks is untested. The templates here produce
the kind of activity that actually fills a queue: failed logons, patching,
scanner traffic, patrol flights, weekly threat summaries. Some of them look
alarming in isolation on purpose.

Each template returns a spec dict in the same shape as `scenarios.py`, so the
generator renders both through the same code path.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

WORKSTATIONS = [
    ("FIN-WS-042", "10.20.14.42", "CORP\\j.okafor"),
    ("FIN-WS-043", "10.20.14.43", "CORP\\p.singh"),
    ("RND-WS-117", "10.20.15.117", "CORP\\a.mehta"),
    ("RND-WS-118", "10.20.15.118", "CORP\\l.fischer"),
    ("HR-WS-023", "10.20.16.23", "CORP\\m.novak"),
    ("OPS-WS-008", "10.20.17.8", "CORP\\s.ahmed"),
    ("LOG-WS-031", "10.20.18.31", "CORP\\c.dubois"),
    ("ENG-WS-055", "10.20.15.55", "CORP\\t.berg"),
    ("ADM-WS-002", "10.20.10.2", "CORP\\r.tanaka"),
]
SERVERS = [
    ("DC01", "10.20.1.10"), ("DC02", "10.20.1.11"), ("DNS-01", "10.20.1.53"),
    ("FILE-SRV-01", "10.20.2.20"), ("FILE-SRV-02", "10.20.2.21"), ("MAIL-01", "10.20.2.25"),
    ("BACKUP-01", "10.20.2.30"), ("PRINT-SRV-01", "10.20.2.40"), ("VPN-GW-01", "10.20.0.5"),
    ("WEB-DMZ-01", "172.16.5.10"), ("WEB-DMZ-02", "172.16.5.11"),
]
ADMINS = ["CORP\\r.tanaka", "CORP\\k.olsen", "CORP\\svc_backup", "CORP\\svc_patch"]
INTERNET_NOISE_IPS = [
    "203.0.113.45", "198.51.100.23", "192.0.2.77", "203.0.113.199", "198.51.100.140",
    "192.0.2.15", "203.0.113.8", "198.51.100.201", "192.0.2.230", "203.0.113.120",
]
CDN_DOMAINS = ["cdn.office.net", "update.microsoft.com", "teams.microsoft.com", "static.corp-cdn.example", "avupdates.vendor.example"]
SITES = {
    "SITE-ALPHA": (64.1400, 21.9300),
    "SITE-BRAVO": (63.9800, 22.6100),
    "SITE-CHARLIE": (64.3100, 21.2200),
}


def _iso(t: datetime) -> str:
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _siem_noise(rng: random.Random, t: datetime) -> dict:
    ws, ws_ip, user = rng.choice(WORKSTATIONS)
    srv, srv_ip = rng.choice(SERVERS)
    kind = rng.choices(
        ["failed_logon", "av_update", "fw_deny", "ssh_bruteforce_dmz", "usb", "dropbox", "cert", "vpn_ok", "lockout", "defender_scan", "dns_nx", "software_install"],
        weights=[14, 8, 20, 8, 3, 4, 2, 10, 3, 6, 6, 4],
    )[0]
    if kind == "failed_logon":
        n = rng.randint(1, 4)
        return {"source": "siem", "at": _iso(t), "rule_id": "AD-3001", "rule": "Failed interactive logon", "severity": rng.choice(["low", "low", "informational"]),
                "category": "authentication", "host": ws, "user": user, "src_ip": ws_ip,
                "message": f"EventID 4625: {n} failed logon attempt(s) for {user} on {ws} (bad password). Followed by successful logon."}
    if kind == "av_update":
        return {"source": "siem", "at": _iso(t), "rule_id": "AV-0001", "rule": "Endpoint protection definitions updated", "severity": "informational",
                "category": "endpoint", "host": rng.choice([ws, srv]), "url": f"https://{rng.choice(CDN_DOMAINS)}/defs/", "message": "Signature package installed successfully."}
    if kind == "fw_deny":
        ip = rng.choice(INTERNET_NOISE_IPS)
        port = rng.choice([22, 23, 445, 3389, 8080, 1433, 5900, 25])
        return {"source": "siem", "at": _iso(t), "rule_id": "FW-0100", "rule": "Inbound connection denied at perimeter", "severity": "informational",
                "category": "firewall", "host": "VPN-GW-01", "src_ip": ip, "dst_ip": "203.0.113.10", "dst_port": port,
                "message": f"Denied TCP {ip} → 203.0.113.10:{port} (internet background radiation)."}
    if kind == "ssh_bruteforce_dmz":
        ip = rng.choice(INTERNET_NOISE_IPS)
        return {"source": "siem", "at": _iso(t), "rule_id": "IDS-1300", "rule": "ET SCAN Potential SSH brute force", "severity": rng.choice(["medium", "low"]),
                "category": "ids", "host": "WEB-DMZ-02", "src_ip": ip, "dst_ip": "172.16.5.11", "dst_port": 22,
                "message": f"{rng.randint(20, 80)} SSH connection attempts from {ip} to 172.16.5.11 in 5 minutes; all rejected (password auth disabled)."}
    if kind == "usb":
        return {"source": "siem", "at": _iso(t), "rule_id": "EDR-0200", "rule": "Removable media connected", "severity": "low",
                "category": "endpoint", "host": ws, "user": user, "message": f"USB mass storage device (vendor Kingston) connected on {ws}; policy: read-only."}
    if kind == "dropbox":
        return {"source": "siem", "at": _iso(t), "rule_id": "PRX-0100", "rule": "Access to cloud storage service", "severity": "low",
                "category": "proxy", "host": ws, "user": user, "src_ip": ws_ip, "url": "https://www.dropbox.com/",
                "message": f"{user} accessed dropbox.com; {rng.randint(1, 40)} MB transferred. Allowed by policy (personal use)."}
    if kind == "cert":
        return {"source": "siem", "at": _iso(t), "rule_id": "PKI-0010", "rule": "TLS certificate expiring within 14 days", "severity": "low",
                "category": "config", "host": srv, "message": f"Certificate CN={srv.lower()}.corp.example expires in {rng.randint(3, 14)} days."}
    if kind == "vpn_ok":
        return {"source": "siem", "at": _iso(t), "rule_id": "VPN-1001", "rule": "VPN logon", "severity": "informational",
                "category": "authentication", "host": "VPN-GW-01", "user": user, "src_ip": rng.choice(INTERNET_NOISE_IPS),
                "message": f"Successful VPN authentication for {user} (MFA ok). GeoIP: home country."}
    if kind == "lockout":
        return {"source": "siem", "at": _iso(t), "rule_id": "AD-3010", "rule": "Account lockout", "severity": "medium",
                "category": "authentication", "host": "DC01", "user": user, "src_ip": ws_ip,
                "message": f"EventID 4740: account {user} locked out after 5 bad passwords from {ws}. Helpdesk ticket auto-created."}
    if kind == "defender_scan":
        return {"source": "siem", "at": _iso(t), "rule_id": "AV-0005", "rule": "Scheduled antimalware scan completed", "severity": "informational",
                "category": "endpoint", "host": rng.choice([ws, srv]), "message": "Full scan completed; 0 threats found."}
    if kind == "dns_nx":
        return {"source": "siem", "at": _iso(t), "rule_id": "DNS-0400", "rule": "Elevated NXDOMAIN rate from client", "severity": "low",
                "category": "network", "host": ws, "src_ip": ws_ip, "dst_ip": "10.20.1.53",
                "message": f"{ws} generated {rng.randint(40, 120)} NXDOMAIN responses in 10 minutes (browser prefetch / mistyped hosts)."}
    return {"source": "siem", "at": _iso(t), "rule_id": "EDR-0300", "rule": "Software installation", "severity": "informational",
            "category": "endpoint", "host": ws, "user": rng.choice(ADMINS),
            "message": f"MSI package {rng.choice(['7-Zip 24.08', 'Microsoft Teams', 'Adobe Reader', 'Notepad++ 8.7'])} installed by SCCM on {ws}."}


def _syslog_noise(rng: random.Random, t: datetime) -> dict:
    srv, srv_ip = rng.choice(SERVERS)
    ws, ws_ip, user = rng.choice(WORKSTATIONS)
    kind = rng.choices(
        ["cron", "sshd_ok", "systemd", "dhcp", "sudo", "backup_ok", "disk", "ntp", "logon", "logoff", "proc_chrome", "proc_outlook", "gpo", "kernel"],
        weights=[10, 8, 6, 8, 6, 3, 3, 4, 12, 8, 8, 6, 4, 4],
    )[0]
    if kind == "cron":
        return {"source": "syslog", "at": _iso(t), "host": srv.lower(), "app": "CRON", "sev": "info",
                "msg": f"(root) CMD (/usr/lib/{rng.choice(['logrotate', 'sysstat/sa1', 'apt/apt.systemd.daily', 'certbot'])} )"}
    if kind == "sshd_ok":
        admin = rng.choice(ADMINS).split("\\")[1]
        return {"source": "syslog", "at": _iso(t), "host": rng.choice(["web-dmz-01", "web-dmz-02", "vpn-gw-01"]), "app": "sshd", "sev": "info",
                "msg": f"Accepted publickey for {admin} from 10.20.10.{rng.randint(2, 9)} port {rng.randint(40000, 60000)} ssh2: ED25519 SHA256:{''.join(rng.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(20))}"}
    if kind == "systemd":
        return {"source": "syslog", "at": _iso(t), "host": srv.lower(), "app": "systemd", "sev": "info",
                "msg": f"Started {rng.choice(['Daily apt download activities', 'Cleanup of Temporary Directories', 'Rotate log files', 'Session 4412 of user root'])}."}
    if kind == "dhcp":
        return {"source": "syslog", "at": _iso(t), "host": "dns-01", "app": "dhcpd", "sev": "info",
                "msg": f"DHCPACK on {ws_ip} to {':'.join(f'{rng.randint(0, 255):02x}' for _ in range(6))} ({ws.lower()}) via eth0"}
    if kind == "sudo":
        admin = rng.choice(ADMINS).split("\\")[1]
        return {"source": "syslog", "at": _iso(t), "host": rng.choice(["web-dmz-01", "web-dmz-02"]), "app": "sudo", "sev": "notice", "user": admin,
                "msg": f"{admin} : TTY=pts/0 ; PWD=/home/{admin} ; USER=root ; COMMAND=/usr/bin/{rng.choice(['apt update', 'systemctl restart confluence', 'journalctl -xe', 'tail -f /var/log/syslog'])}"}
    if kind == "backup_ok":
        return {"source": "syslog", "at": _iso(t), "host": "backup-01", "app": "VeeamBackup", "sev": "info", "user": "CORP\\svc_backup",
                "msg": f"Backup job '{rng.choice(['Nightly-FileServers', 'DC-System-State', 'Mail-Store'])}' completed successfully: {rng.randint(20, 900)} GB processed, 0 warnings."}
    if kind == "disk":
        return {"source": "syslog", "at": _iso(t), "host": srv.lower(), "app": "monit", "sev": "warning",
                "msg": f"filesystem / usage {rng.randint(81, 93)}% exceeds threshold 80%"}
    if kind == "ntp":
        return {"source": "syslog", "at": _iso(t), "host": srv.lower(), "app": "chronyd", "sev": "info",
                "msg": f"Selected source 10.20.1.10 (dc01), offset {rng.uniform(-0.01, 0.01):+.4f} s"}
    if kind == "logon":
        return {"source": "syslog", "at": _iso(t), "host": ws.lower(), "app": "Microsoft-Windows-Security-Auditing", "sev": "info", "user": user,
                "msg": f"EventID=4624 An account was successfully logged on. Subject={user} LogonType={rng.choice([2, 2, 2, 10, 7])} Workstation={ws} Source Network Address={ws_ip}"}
    if kind == "logoff":
        return {"source": "syslog", "at": _iso(t), "host": ws.lower(), "app": "Microsoft-Windows-Security-Auditing", "sev": "info", "user": user,
                "msg": f"EventID=4634 An account was logged off. Subject={user} LogonType=2"}
    if kind == "proc_chrome":
        return {"source": "syslog", "at": _iso(t), "host": ws.lower(), "app": "sysmon", "sev": "info", "user": user,
                "msg": f"EventID=1 ProcessCreate Image=C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe ParentImage=C:\\Windows\\explorer.exe User={user} CommandLine=\"chrome.exe --type=renderer\""}
    if kind == "proc_outlook":
        return {"source": "syslog", "at": _iso(t), "host": ws.lower(), "app": "sysmon", "sev": "info", "user": user,
                "msg": f"EventID=1 ProcessCreate Image=C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE ParentImage=C:\\Windows\\explorer.exe User={user}"}
    if kind == "gpo":
        return {"source": "syslog", "at": _iso(t), "host": ws.lower(), "app": "Microsoft-Windows-GroupPolicy", "sev": "info",
                "msg": "EventID=1502 The Group Policy settings for the computer were processed successfully. New settings from 3 Group Policy objects were detected and applied."}
    return {"source": "syslog", "at": _iso(t), "host": srv.lower(), "app": "kernel", "sev": "info",
            "msg": f"[{rng.randint(100000, 999999)}.{rng.randint(100000, 999999)}] eth0: link is up, 10 Gbps, full duplex"}


def _geo_noise(rng: random.Random, t: datetime) -> dict:
    site = rng.choice(list(SITES))
    lat, lon = SITES[site]
    kind = rng.choices(["patrol", "vessel", "civil_air", "wildlife", "weather", "vehicle"], weights=[8, 5, 10, 6, 3, 6])[0]
    jitter = lambda s: rng.uniform(-s, s)  # noqa: E731
    if kind == "patrol":
        return {"source": "geo", "at": _iso(t), "track_id": f"TRK-AIR-{rng.randint(1000, 9999)}", "sensor": "RADAR-N1", "site": site,
                "lat": lat + jitter(0.05), "lon": lon + jitter(0.08), "object_class": "rotary_wing", "alert_type": "scheduled_patrol",
                "confidence": round(rng.uniform(0.9, 0.99), 2), "priority": "P4", "speed": rng.randint(90, 130), "heading": rng.randint(0, 359),
                "notes": f"Friendly patrol flight callsign HAWK{rng.randint(10, 99)} on filed route; IFF valid"}
    if kind == "vessel":
        return {"source": "geo", "at": _iso(t), "track_id": f"TRK-SEA-{rng.randint(1000, 9999)}", "sensor": "AIS-COASTAL", "site": "SITE-BRAVO",
                "lat": 63.95 + jitter(0.03), "lon": 22.70 + jitter(0.05), "object_class": "vessel", "alert_type": "track_entered_zone",
                "confidence": round(rng.uniform(0.85, 0.99), 2), "priority": "P4", "speed": rng.randint(6, 14), "heading": rng.randint(0, 359),
                "notes": f"Fishing vessel MMSI 2{rng.randint(10000000, 99999999)} transiting coastal zone; AIS consistent with declared voyage"}
    if kind == "civil_air":
        return {"source": "geo", "at": _iso(t), "track_id": f"TRK-AIR-{rng.randint(1000, 9999)}", "sensor": "ADS-B-CHARLIE", "site": "SITE-CHARLIE",
                "lat": 64.31 + jitter(0.1), "lon": 21.22 + jitter(0.15), "object_class": "fixed_wing", "alert_type": "track_entered_zone",
                "confidence": round(rng.uniform(0.9, 0.99), 2), "priority": "P4", "speed": rng.randint(180, 420), "heading": rng.randint(0, 359),
                "notes": f"Civil flight {rng.choice(['SK', 'FI', 'DY'])}{rng.randint(100, 999)} at FL{rng.randint(80, 350)} on airway; ADS-B valid"}
    if kind == "wildlife":
        return {"source": "geo", "at": _iso(t), "track_id": f"TRK-UNK-{rng.randint(1000, 9999)}", "sensor": "RADAR-N2", "site": site,
                "lat": lat + jitter(0.02), "lon": lon + jitter(0.03), "object_class": "unknown_small", "alert_type": "low_confidence_track",
                "confidence": round(rng.uniform(0.2, 0.45), 2), "priority": "P4", "speed": rng.randint(5, 30), "heading": rng.randint(0, 359),
                "notes": "Erratic low-speed track, likely bird flock; dropped after 40 s"}
    if kind == "weather":
        return {"source": "geo", "at": _iso(t), "track_id": f"TRK-BAL-{rng.randint(100, 999)}", "sensor": "RADAR-N1", "site": site,
                "lat": lat + jitter(0.2), "lon": lon + jitter(0.3), "object_class": "balloon", "alert_type": "track_entered_zone",
                "confidence": round(rng.uniform(0.6, 0.8), 2), "priority": "P4", "speed": rng.randint(10, 40), "heading": rng.randint(0, 359),
                "notes": "Meteorological balloon on scheduled launch from met station"}
    return {"source": "geo", "at": _iso(t), "track_id": f"TRK-GND-{rng.randint(1000, 9999)}", "sensor": "PERIMETER-CAM", "site": site,
            "lat": lat + jitter(0.005), "lon": lon + jitter(0.008), "object_class": "vehicle", "alert_type": "vehicle_at_gate",
            "confidence": round(rng.uniform(0.85, 0.99), 2), "priority": "P3", "speed": 0, "heading": 0,
            "notes": f"Vehicle at main gate; plate matched authorised list ({rng.choice(['supplier delivery', 'shift change', 'contractor'])})"}


INTEL_NOISE = [
    {"origin": "Weekly threat summary", "priority": "LOW", "subject": "Weekly cyber threat summary - week 37",
     "body": "No significant change in the threat picture this week. Commodity malware volumes remain steady; phishing themes continue to favour parcel-delivery and payroll lures. Patch compliance across the enclave is 94% for critical updates. No new indicators of concern were received from partners. Analysts should continue routine monitoring."},
    {"origin": "Vendor advisory (relayed)", "priority": "MEDIUM", "subject": "Patch availability: CVE-2025-21001 in enterprise print spooler",
     "body": "The vendor has released fixes for CVE-2025-21001, a local privilege escalation in the print spooler service. No exploitation in the wild has been reported. Deployment to PRINT-SRV-01 and workstations is scheduled through the normal patch cycle. Reference: vendor bulletin 2025-09-A."},
    {"origin": "Security awareness team", "priority": "LOW", "subject": "Phishing simulation results and reminder",
     "body": "The September phishing simulation achieved a 6% click rate, down from 9%. Reminder to staff: report suspicious messages using the Outlook button rather than forwarding them. The simulation used the domain training-portal[.]example and no real infrastructure."},
    {"origin": "Regional assessment", "priority": "MEDIUM", "subject": "Regional situation assessment - northern sector",
     "body": "Routine maritime and air activity continues in the northern sector at seasonal norms. Fishing fleet density near SITE-BRAVO is elevated for the season. No hostile activity assessed. Scheduled patrol flights HAWK-series continue on the published rota; sensor operators should expect friendly tracks near all three sites."},
    {"origin": "Incident review board", "priority": "LOW", "subject": "Retrospective: August mail outage",
     "body": "The 22 August mail outage was caused by certificate expiry on MAIL-01, not by hostile action. Actions: certificate monitoring alerts now raised at 14 days (rule PKI-0010). No indicators of compromise were identified during the review."},
    {"origin": "Partner CTI exchange", "priority": "LOW", "subject": "Infrastructure takedown notice - commodity botnet",
     "body": "Partner law-enforcement action has sinkholed command-and-control domains for a commodity botnet. Organisations may see residual beaconing to sinkhole addresses in 192[.]0[.]2[.]0/24 from previously infected hosts; this is benign and the hosts should be cleaned through normal endpoint processes."},
]


def generate_noise(rng: random.Random, start: datetime, end: datetime, *, siem: int, syslog: int, geo: int) -> list[dict]:
    """Uniformly spread benign alerts across the window, with a daytime bias."""
    span = (end - start).total_seconds()

    def when() -> datetime:
        # Slight bias towards working hours so the feed feels like a real enclave.
        t = start + timedelta(seconds=rng.uniform(0, span))
        if rng.random() < 0.35:
            hour = rng.randint(7, 18)
            t = t.replace(hour=hour)
        return t

    specs = [_siem_noise(rng, when()) for _ in range(siem)]
    specs += [_syslog_noise(rng, when()) for _ in range(syslog)]
    specs += [_geo_noise(rng, when()) for _ in range(geo)]
    intel_times = [start + timedelta(hours=h) for h in (2, 9, 15, 26, 33, 41)]
    for report, t in zip(INTEL_NOISE, intel_times):
        specs.append({"source": "intel", "at": _iso(t), **report})
    return specs
