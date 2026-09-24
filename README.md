# 🛡️ SOC Home Lab — Wazuh SIEM

A hands-on cybersecurity home lab built with a **Wazuh SIEM**, simulating real-world attacks and detecting them from the defender's side. Built to demonstrate practical SOC analyst and detection-engineering skills, and to support my **CompTIA Security+ / CySA+** track.

**Environment:** VirtualBox — Kali Linux (Wazuh manager) + Windows 10 (victim, Wazuh agent + Sysmon), bridged on a home subnet. **Frameworks:** MITRE ATT&CK, custom Wazuh detection rules.

---

## 📂 Projects in this Repo

### [Project 1 — RDP Brute-Force Attack Detection](SOC_HomeLab_Portfolio.md)
Simulated an RDP brute-force attack (Nmap recon → Hydra credential attack → xfreerdp access) and detected the full chain in Wazuh: the pattern of failed logons followed by a success, mapped to MITRE ATT&CK. Covers reconnaissance detection, the HIDS vs. NIDS distinction, and a defense-in-depth finding.
**Tools:** Nmap · Hydra · xfreerdp · Wazuh
**MITRE:** T1595 · T1110.001 · T1021.001

### [Project 2 — Phishing Attack Detection with Sysmon + Wazuh](Phishing_Detection_HomeLab.md)
Built an end-to-end phishing **detection** lab: analyzed phishing email headers (SPF/DKIM/DMARC triage), simulated an LNK-attachment attack (benign payload), captured the execution with Sysmon, and wrote a **custom Wazuh rule** that fires a high-severity alert on the Explorer→PowerShell chain. Includes real detection-engineering troubleshooting.
**Tools:** Sysmon · Wazuh · custom detection rules
**MITRE:** T1566.001 · T1204.002 · T1059.001 · T1027

---

## 🗺️ Lab Roadmap
- ✅ Project 1 — RDP brute-force detection
- ✅ Project 2 — Phishing (LNK) detection with custom rules
- ⬜ Project 3 — Suricata / NIDS integration (close the HIDS gap from project 1)
- ⬜ Atomic Red Team — validate detections against MITRE techniques
- ⬜ Active response — auto-isolate on high-severity alerts

---

## 👤 About
Built as a hands-on environment to develop offensive skills (recon, credential attacks), defensive skills (SIEM configuration, alert analysis, detection engineering), and security-operations practice (MITRE ATT&CK mapping, incident documentation).

⚠️ **Disclaimer:** Conducted in a fully isolated, self-owned virtual environment for educational purposes only. All techniques are performed against machines I own and control.

*Built with 🔐 for learning · Kali Linux · Wazuh · Sysmon · Nmap · Hydra · VirtualBox*
