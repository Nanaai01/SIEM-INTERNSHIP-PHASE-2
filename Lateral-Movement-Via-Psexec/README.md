# 🔄 Lateral Movement via PsExec – Detection Use Case

**MITRE ATT&CK Technique**: [T1021.002 – Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)

📖 Scenario Summary

This simulation demonstrates how an attacker with valid credentials can perform lateral movement using `psexec.py` from the Impacket toolkit to remotely execute a payload on a Windows machine. This technique is frequently used in real-world attacks to pivot across systems in an enterprise network.



⚙️ Environment Details

| Component         | Configuration                                   |
|------------------|--------------------------------------------------|
| **Attacker Host** | Kali Linux (Impacket installed)                 |
| **Target Host**   | Windows 11                  |
| **Log Collector** | Splunk Universal Forwarder → Splunk Enterprise  |
| **Tool Used**     | [`psexec.py`](https://github.com/fortra/impacket) (Impacket) |

---

🚨 Attack Steps

🛠 Command Used

```bash
python3 /usr/share/doc/python3-impacket/examples/psexec.py admin:Password123@192.168.1.111
````



🧾 Event IDs & Data Sources

| Source   | Event ID | Description                              |
| -------- | -------- | ---------------------------------------- |
| Security | 4624     | Successful logon (LogonType 3 - network) |
| Security | 5140     | Network share access (e.g., ADMIN\$)     |
| System   | 7045     | New service installed (`sBZc`)           |
| Sysmon   | 1        | Process creation (`GeShMsbN.exe`)        |

---

🔍 Detection Logic (Splunk SPL)

```spl
index=win_logs (EventCode=4624 OR EventCode=7045 OR EventCode=5140)
| search Account_Name="admin" OR Service_Name="PSEXESVC" OR Service_Name="sBZc"
| table _time, host, EventCode, Account_Name, Service_Name, IpAddress
```

---


---
🛡️ Recommendations

* Monitor for Event ID 7045 (new services).
* Correlate with Logon Type 3 from suspicious IPs.
* Disable or restrict usage of ADMIN\$ shares where possible.
* Alert on services created with random names or from non-domain IPs.
* Implement strict credential hygiene and admin segmentation.

