# 🛡️ Phase 2 Internship – Security Detection Use Cases

Welcome to my Phase 2 internship project, where I developed and tested multiple detection scenarios related to real-world adversarial techniques. These detections are mapped to the MITRE ATT&CK framework and validated using simulated attacker behaviors in a controlled lab environment.

📌 Project Overview

This repository documents key attack simulations and detection engineering activities carried out during Phase 2 of my cybersecurity internship. The focus was on simulating real-world adversarial behaviors mapped to the MITRE ATT&CK framework and building corresponding detection rules using Windows Event Logs and Splunk.

---

📁 Use Cases Overview

1. 🧍 Privilege Escalation

- MITRE ATT&CK IDs: [T1055 – Process Injection](https://attack.mitre.org/techniques/T1055/), [T1547 – Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)
- Summary: Simulates creation of a new local account and adds it to the Administrators group to gain elevated privileges.
- Detection Focus:
  - New user account creation (Event ID `4720`)
  - User added to privileged groups (Event ID `4732`)
  - Privileged logon detection (Event ID `4672`)



---

2. 🔄 Lateral Movement via PsExec

- MITRE ATT&CK ID: [T1021.002 – SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
- Summary: Simulates lateral movement using `psexec.py` from Impacket to execute commands remotely over SMB.
- Detection Focus:
  - Remote service creation (Event ID `7045`)
  - Remote logon via network (Event ID `4624`)
  - Access to ADMIN$ shares (Event ID `5140`)



---

3. 📥Suspicious File Download & Execution 

* MITRE ATT\&CK ID: [T1204.002 – User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002) 
* Summary: Simulated the download of a malicious ZIP file using PowerShell’s `Invoke-WebRequest` from a Python-hosted HTTP server. The file was saved to `C:\Users\Public\`, mimicking typical adversary behavior. 
* Detection Focus:

  * PowerShell script block logging (Event ID 4104)
  * Process creation with suspicious download commands (Event ID 4688 / Sysmon 1)
  * Monitoring for file creation in public or temp directories

---

Sure! Here’s the updated write-up including your simulation of User Account Control (UAC) activity:

---

4. 👤 Anomalous User Behavior

* MITRE ATT\&CK IDs: [T1087 – Account Discovery](https://attack.mitre.org/techniques/T1087/), [T1078 – Valid Accounts](https://attack.mitre.org/techniques/T1078/)
* Summary: Carried out simulations of anomalous user behaviors including successful logins at odd hours, multiple failed login attempts, unusual Network Management Console (NMC) access, and User Account Control (UAC) elevation prompts. Developed detection rules to identify deviations from normal login and privilege escalation patterns.
* Detection Focus:

  * Simulated logins outside normal business hours to test detection of after-hours access.
  * Generated failed login attempts to evaluate alerting on brute-force-like behavior.
  * Monitored unusual NMC logins to detect potential privilege escalation or lateral movement.
  * Simulated UAC elevation requests to detect unauthorized privilege escalations.


---

5. 📡 Beaconing Detection

- MITRE ATT&CK ID: [T1071 – Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)
- Summary: Identifies Command & Control (C2) traffic via beaconing patterns over HTTP/HTTPS.
- Detection Focus:
  - Repetitive low-volume connections
  - Consistent timing intervals
  - Anomalous DNS or endpoint behavior



---

#📊 Tools & Technologies

- 💻 Windows 11 (Target VM)
- 🐧 Kali Linux (Attacker VM)
- 🛠️ [Impacket Toolkit](https://github.com/fortra/impacket)
- 📈 Splunk Enterprise + Universal Forwarder
- 🔍 Sysmon + Windows Security Logs


---

> 📁 Folder Structure:
>
> - `/use-cases/` – Attack simulation reports  
> - `/splunk-detections/` – SPL queries  
> - `/screenshots/` – Visual evidence of detections  
> - `/ioc-samples/` – Sample logs and artifacts

---


🧪 Environment

- SIEM: Splunk Enterprise
- Forwarders: Splunk Universal Forwarder on Windows endpoints
- Attack Tools: PsExec (Impacket), PowerShell, Certutil, Custom Scripts
- Monitoring: Windows Event Logs, Sysmon



📂 Repository Structure

```

📁 use-cases/
│   ├── privilege-escalation/
│   ├── lateral-movement-psexec/
│   ├── suspicious-download-execution/
│   ├── anomalous-user-behavior/
│   └── beaconing-detection/
📁 screenshots/
📁 sample-logs/
📁 detection logics
📄 README.md

```



🧠 Goals & Learning Outcomes

- Simulate adversarial behavior mapped to MITRE ATT&CK
- Write effective detection rules in SPL (Splunk Processing Language)
- Validate detections using test data and generate alerts
- Document IOCs, analyst actions, and response recommendations


```



👤 Contact

Aishat Olayinka Yusuf – www.linkedin.com/in/aishat-olayinka-yusuf-3a16aa1b4

