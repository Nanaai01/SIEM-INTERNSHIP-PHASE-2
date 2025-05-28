```markdown
# 🛡️ Phase 2 Internship – Security Detection Use Cases

Welcome to my Phase 2 internship project, where I developed and tested multiple detection scenarios related to real-world adversarial techniques. These detections are mapped to the MITRE ATT&CK framework and validated using simulated attacker behaviors in a controlled lab environment.

📌 Project Overview

This repository contains detection logic, event samples, logs, and response recommendations for the following use cases:

🔐 1. Privilege Escalation
- MITRE IDs: T1055, T1547
- Simulates creation of a local account and privilege elevation by adding the user to the Administrators group.
- Detection includes monitoring for Event IDs 4720, 4732, and 4672.

🔄 2. Lateral Movement via PsExec
- **MITRE ID**: T1021.002
- Simulates lateral movement using `Impacket's psexec.py` to access remote Windows machines.
- Detects PsExec execution, new service creation, and remote logons.

📥 3. Suspicious File Download & Execution
- **MITRE ID**: T1204.002
- Simulates downloading executable files using PowerShell or `certutil.exe`.
- Detects use of LOLBins for payload retrieval and execution.

👤 4. Anomalous User Behavior
- **MITRE IDs**: T1087, T1078
- Monitors for behavior deviations such as logons outside business hours, rapid group changes, or failed login spikes.
- Uses UEBA-style rules to trigger alerts based on behavioral baselines.

📡 5. Beaconing Detection
- **MITRE ID**: T1071
- Identifies Command and Control (C2) beaconing based on repetitive, low-data outbound connections over HTTP/HTTPS.
- Highlights consistent timing intervals and anomalous DNS patterns.



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



✅ Status

- [x] Detection Logic Written  
- [x] Simulations Performed  
- [x] Alerts Tested  
- [ ] Ready for SOC Integration  



💡 Feel free to fork, test, or extend these detections in your own lab!

```




📞 Contact

Aishat Olayinka Yusuf – www.linkedin.com/in/aishat-olayinka-yusuf-3a16aa1b4

