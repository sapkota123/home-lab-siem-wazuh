# 🛡️ SOC Home Lab — RDP Brute-Force Attack Detection

> **A hands-on cybersecurity home lab simulating a real-world RDP brute-force attack, detected and analyzed using a Wazuh SIEM. Built to demonstrate practical SOC analyst and penetration testing skills.**

---

## 📌 Project Overview

| Field | Details |
|---|---|
| **Project Type** | SOC Home Lab / Offensive & Defensive Security |
| **Duration** | Self-paced (ongoing) |
| **Goal** | Simulate real-world attacks and detect them using a SIEM |
| **Frameworks** | MITRE ATT&CK, Wazuh Detection Rules |
| **Certifications Targeted** | CompTIA Security+, CySA+ |

---

## 🏗️ Lab Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Home Network (Fritz!Box)              │
│                    192.168.178.0/24                      │
│                                                          │
│   ┌─────────────────────┐   ┌────────────────────────┐  │
│   │   Kali Linux VM     │   │  Windows 10 Victim VM  │  │
│   │   192.168.178.117   │   │  192.168.178.118       │  │
│   │                     │   │                        │  │
│   │  • Wazuh SIEM       │──▶│  • Wazuh Agent         │  │
│   │  • Nmap             │   │  • RDP Enabled         │  │
│   │  • Hydra            │   │  • Port 3389 Open      │  │
│   │  • xfreerdp         │   │                        │  │
│   └─────────────────────┘   └────────────────────────┘  │
│         Attacker                    Victim               │
└─────────────────────────────────────────────────────────┘
```

---

## 🛠️ Tools & Technologies

| Category | Tool | Purpose |
|---|---|---|
| **Hypervisor** | VirtualBox | Running both VMs on Windows host |
| **Attacker OS** | Kali Linux 2026.2 | Attack simulation platform |
| **Victim OS** | Windows 10 (Build 19041) | Target machine |
| **SIEM** | Wazuh 4.x (All-in-One) | Detection, alerting, MITRE mapping |
| **Reconnaissance** | Nmap 7.99 | Port scanning & service enumeration |
| **Exploitation** | Hydra v9.7 | RDP brute-force credential attack |
| **Access** | xfreerdp | RDP client to verify access |

---

## 🖥️ Lab Environment Setup

### Host Machine
- **OS:** Windows (Laptop)
- **CPU:** Intel i5-7300U (4 logical cores)
- **RAM:** ~15.7 GB

### VM Configuration

| VM | OS | RAM | CPUs | IP Address | Role |
|---|---|---|---|---|---|
| Kali Linux | Kali 2026.2 | 6144 MB | 2 | 192.168.178.117 | Attacker + SIEM |
| Windows 10 | Windows 10 v2004 | 3072 MB | 2 | 192.168.178.118 | Victim |

### Network Mode
Both VMs configured on **Bridged Adapter** — same home subnet, simulating a realistic internal network environment.

### Wazuh SIEM Deployment
- Wazuh all-in-one deployment (Indexer + Manager + Dashboard) on Kali Linux
- Windows 10 Wazuh agent installed, configured, and showing as **Active**
- Dashboard accessible at `https://192.168.178.117`

---

## ⚔️ Attack Simulation — Phase by Phase

### Phase 1: Reconnaissance

**Objective:** Discover the target and identify open services.

**Command:**
```bash
nmap -sn 192.168.178.0/24
```
*Host discovery sweep to identify live machines on the subnet.*

```bash
nmap -p 3389 --script rdp-enum-encryption,rdp-ntlm-info 192.168.178.118
```
*Targeted RDP enumeration to identify NLA status, encryption level, and OS build.*

**Findings:**

```
PORT      STATE  SERVICE
3389/tcp  open   ms-wbt-server

rdp-enum-encryption:
  Security layer:
    CredSSP (NLA): SUCCESS
    CredSSP with Early User Auth: SUCCESS
    RDSTLS: SUCCESS

rdp-ntlm-info:
  Target_Name: DESKTOP-12E7495
  Product_Version: 10.0.19041
  System_Time: 2026-09-04T13:44:14+00:00
```

**Analysis:**
- RDP is **open and accessible** on port 3389
- NLA (Network Level Authentication) is **enabled**
- Windows 10 Build **19041** — patched beyond BlueKeep vulnerability range
- **CVE-2019-0708 (BlueKeep) ruled out** — pivot to credential-based attack

**MITRE ATT&CK:** `T1595` — Active Scanning

---

### Phase 2: Credential-Based Attack (Brute Force)

**Objective:** Gain access using a dictionary-based password attack against RDP.

**Wordlist created:**
```
password
123456
admin123
Welcome1
victim
```

**Command:**
```bash
hydra -l victim -P ~/testpasswords.txt -t 1 rdp://192.168.178.118
```

**Result:**
```
[3389][rdp] host: 192.168.178.118   login: victim   password: victim
1 of 1 target successfully completed, 1 valid password found
```

**Analysis:**
- Hydra successfully identified valid credentials: `victim:victim`
- Weak password (username = password) was in wordlist → immediately found
- `-t 1` flag required — RDP doesn't support many parallel connections
- Attack completed in **~8 seconds** against a 5-entry wordlist
- Real-world equivalent: `rockyou.txt` (14M+ entries) would find this within minutes

**MITRE ATT&CK:** `T1110.001` — Brute Force: Password Guessing

---

### Phase 3: Access & Exploitation

**Objective:** Confirm access using discovered credentials via RDP.

**Command:**
```bash
xfreerdp /u:victim /p:victim /v:192.168.178.118
```

**Result:**
- ✅ Successfully authenticated to Windows 10 victim machine
- Full desktop access obtained from Kali Linux
- Attacker now has **complete control** of the victim machine

**Real-World Impact:**
- Can install malware or ransomware
- Can exfiltrate sensitive files
- Can create backdoor accounts
- Can move laterally to other network machines

**MITRE ATT&CK:** `T1021.001` — Remote Services: Remote Desktop Protocol

---

## 🔍 Detection & Analysis — Wazuh SIEM

### Alert Summary (Last 24 Hours)

| Severity | Count | Rule Level |
|---|---|---|
| Critical | 0 | Level 15+ |
| High | 0 | Level 12–14 |
| Medium | 7 | Level 7–11 |
| Low | 133 | Level 0–6 |
| **Total** | **140** | — |

### Threat Hunting Dashboard

| Metric | Value |
|---|---|
| Total Alerts | 140 |
| Authentication Failures | 10 |
| Authentication Successes | 13 |
| Level 12+ Alerts | 0 |

### Key Observations
- **10 authentication failures** followed by **13 successes** = classic brute-force-then-login pattern
- Alert **spike visible on timeline** at exactly the time the attack was executed (09:00–10:00)
- All events correctly attributed to the Windows 10 agent (DESKTOP-12E7495)

---

### MITRE ATT&CK — Detailed Technique IDs Detected by Wazuh

| Technique ID | Technique Name | Tactic | Rule Description | Rule Level |
|---|---|---|---|---|
| `T1531` | Account Access Removal | Impact | Logon Failure — Unknown user or bad password | 5 |
| `T1550.002` | Use Alternate Authentication Material: Pass the Hash | Defense Evasion, Lateral Movement | Successful Remote Logon Detected — User:\victim — NTLM authentication | 6 |
| `T1484` | Domain Policy Modification | Defense Evasion, Privilege Escalation | Special privileges assigned to new logon | 3 |

---

### 🔬 Attack Timeline Reconstructed from Wazuh Logs

This is the full attack story as seen by Wazuh — reading the logs like a real SOC analyst:

```
TIMESTAMP           TECHNIQUE    TACTIC              WAZUH RULE DESCRIPTION
─────────────────── ──────────── ─────────────────── ──────────────────────────────────────────────
10:01:46.276        T1531        Impact              Logon Failure — Unknown user or bad password
10:01:48.310        T1531        Impact              Logon Failure — Unknown user or bad password
10:01:50.354        T1531        Impact              Logon Failure — Unknown user or bad password
10:01:52.363        T1531        Impact              Logon Failure — Unknown user or bad password
                                                     ↑ Hydra trying: password, 123456, admin123, Welcome1
─────────────────── ──────────── ─────────────────── ──────────────────────────────────────────────
10:01:54.445        T1550.002    Defense Evasion,    Successful Remote Logon Detected
                                 Lateral Movement    User:\victim — NTLM authentication
                                                     ↑ Hydra found correct password: "victim"
─────────────────── ──────────── ─────────────────── ──────────────────────────────────────────────
10:01:54.412        T1484        Defense Evasion,    Special privileges assigned to new logon
10:01:54.414        T1484        Privilege Escalation Special privileges assigned to new logon
10:01:54.573        T1484        Defense Evasion,    Special privileges assigned to new logon
10:01:54.595        T1484        Privilege Escalation Special privileges assigned to new logon
                                                     ↑ Windows grants attacker full RDP session privileges
```

### What This Means (SOC Analyst Interpretation)

A real SOC analyst seeing this pattern would immediately recognize:

1. **Multiple rapid logon failures from same source** → brute-force attack in progress
2. **Sudden successful logon after failures** → brute-force succeeded, account compromised
3. **Immediate privilege assignment after logon** → attacker gained privileged access
4. **NTLM authentication flagged** → lateral movement technique detected (T1550.002)
5. **All within 8 seconds (10:01:46 → 10:01:54)** → automated tool used (Hydra), not manual

This is a textbook **brute-force → credential access → lateral movement** attack chain, fully visible in Wazuh logs.

---

## 🔐 Security Findings & Recommendations

| # | Finding | Severity | Recommendation |
|---|---|---|---|
| 1 | RDP exposed on network with no firewall restriction | High | Block port 3389 at firewall; allow only from trusted IPs/VPN |
| 2 | Weak credentials (username = password) | Critical | Enforce strong password policy; minimum 12 chars, complexity required |
| 3 | No account lockout policy configured | High | Set lockout after 5 failed attempts; 15-minute lockout duration |
| 4 | NLA enabled but not sufficient alone | Medium | Combine NLA with MFA for RDP access |
| 5 | RDP accessible without VPN | High | Require VPN before RDP access; never expose 3389 directly to internet |

---

## 📚 Key Learnings

1. **Open ports = attack surface** — RDP on 3389 was immediately discovered by Nmap and became the attack vector
2. **Weak passwords are trivially cracked** — `victim:victim` was found in under 10 seconds
3. **SIEMs detect behavioral patterns, not just signatures** — Wazuh flagged the brute-force via the pattern of failures followed by success, not a specific malware signature
4. **MITRE ATT&CK is a universal language** — every step of the attack maps to a documented technique, making it easy to communicate findings
5. **Defense in depth matters** — NLA alone wasn't enough; account lockout + strong passwords + firewall rules together would have prevented this attack

---

## 🗺️ Attack Chain Summary (Cyber Kill Chain)

```
Reconnaissance  →  Weaponization  →  Delivery  →  Exploitation  →  Installation  →  C2  →  Actions
   (Nmap)           (Hydra           (Network      (RDP Login       (Full desktop   N/A     (Full
  Port scan         wordlist)         access)       via weak         access via              control)
                                                    creds)           xfreerdp)
```

---

## 🚀 Next Steps (Lab Roadmap)

- [ ] Run Nmap scan and analyze Wazuh alerts for reconnaissance detection
- [ ] Deploy EICAR test file to trigger malware detection rules
- [ ] Set up Metasploit exploitation and analyze Wazuh response
- [ ] Write custom Wazuh detection rules for lab-specific scenarios
- [ ] Add a third VM (e.g., Ubuntu server) to simulate lateral movement
- [ ] Integrate threat intelligence feeds into Wazuh
- [ ] Practice log analysis and incident response documentation

---

## 📁 Repository Structure

```
soc-home-lab/
├── README.md                    ← This file
├── docs/
│   ├── lab-setup.md             ← Full VM and Wazuh setup guide
│   ├── attack-playbook.md       ← Step-by-step attack commands
│   └── wazuh-rules.md           ← Custom detection rules
├── screenshots/
│   ├── nmap-scan.png
│   ├── hydra-success.png
│   ├── rdp-access.png
│   └── wazuh-dashboard.png
└── reports/
    └── rdp-brute-force-report.md ← Full incident report
```

---

## 👤 About This Project

This lab was built as a hands-on learning environment to develop practical skills in:
- **Offensive security** — reconnaissance, enumeration, credential attacks
- **Defensive security** — SIEM configuration, alert analysis, threat detection
- **Security operations** — incident identification, MITRE ATT&CK mapping, reporting

> ⚠️ **Disclaimer:** This lab is conducted in a fully isolated, self-owned virtual environment for educational purposes only. All techniques demonstrated are performed against machines I own and control. Never attempt these techniques against systems you do not own or have explicit written permission to test.

---

*Built with 🔐 for learning | Tools: Kali Linux · Wazuh · Nmap · Hydra · VirtualBox*
