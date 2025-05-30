🛡️ Anomalous User Behavior Detection - Lab Report

---

Lab Architecture:
- Operating System: Windows 11 (Target)
- Monitoring Platform: Splunk Enterprise
- Log Collection: Windows Event Logs, Sysmon (enabled)
- Attack Platform: Kali Linux + Impacket `psexec.py`

---

🎯 Objective

Simulate and detect anomalous user behavior within a Windows environment using Splunk. The simulation includes:
- Successful but suspicious logins
- User logins during non-business hours
- Access to administrative tools (e.g., compmgmt.msc)
- UAC trigger events
- Privilege escalation using built-in tools

---

🧪 Simulated Behaviors

| # | Scenario                         | Description |
|--:|----------------------------------|-------------|
| 1 | Successful login             | A simulated user logs in using valid credentials |
| 2 | Odd-hours login             | Login event occurs outside standard business hours (e.g., 2:30 AM) |
| 3 | Administrative tool access   | Execution of `mmc.exe`, `compmgmt.msc`, or related admin tools |
| 4 | UAC prompt triggered         | Triggered via GUI or elevated PowerShell attempt |
| 5 | Privilege escalation         | Usage of `runas`, `psexec`, or similar to elevate user rights |

---

🔍 Detection Queries

✅ 1. Successful Logins

```spl
index=wineventlog EventCode=4624
| table _time, Account_Name, Logon_Type, Workstation_Name
````

* Filters for successful logon events (Event ID 4624)
* Can correlate Logon Type 2 (interactive), 10 (remote), or 3 (network)

---

### 🌙 2. Logins During Non-Business Hours

```spl
index=wineventlog EventCode=4624
| eval hour=strftime(_time, "%H")
| where hour < 6 OR hour > 20
| table _time, Account_Name, Workstation_Name, Logon_Type, hour
```

* Detects users logging in between **8:00 PM and 6:00 AM**
* Useful for catching suspicious or scheduled access patterns

---

⚙️ 3. Admin Tools Accessed

```spl
index=wineventlog EventCode=4688
| search (New_Process_Name="*mmc.exe" OR New_Process_Name="*compmgmt.msc")
| table _time, Account_Name, New_Process_Name, CommandLine, Parent_Process_Name
```

* Catches executions of system management consoles
* Useful for privilege abuse and lateral movement detection

---

🧱 4. UAC Prompt and Elevation

```spl
index=wineventlog EventCode=4688
| search (CommandLine="*runas*" OR CommandLine="*powershell* -verb runas*")
| table _time, Account_Name, CommandLine, Parent_Process_Name
```

* Detects manual privilege escalation attempts via `runas` or elevated PowerShell

---

🛡️ 5. Privileged Logons / Admin Sessions

```spl
index=wineventlog (EventCode=4672 OR EventCode=4648)
| table _time, EventCode, Account_Name, Logon_ID, Workstation_Name
```

* `4672`: Special privileges assigned (e.g., local admin, SeDebugPrivilege)
* `4648`: Use of explicit alternate credentials (e.g., impersonation)

---

📊 Sample Detection Results

| \_time             | EventCode | Account\_Name | Action                        |
| ------------------ | --------- | ------------- | ----------------------------- |
| 2025-05-29 02:32AM | 4624      | attacker      | Odd-hours login               |
| 2025-05-29 02:34AM | 4688      | attacker      | Admin tool launched (mmc.exe) |
| 2025-05-29 02:35AM | 4672      | attacker      | Privileged session initiated  |
| 2025-05-29 02:36AM | 4688      | attacker      | UAC triggered by `runas`      |

---

✅ Recommendations

| Recommendation                                             | Purpose                             |
| ---------------------------------------------------------- | ----------------------------------- |
| Deploy Sysmon with advanced config (e.g., SwiftOnSecurity) | Enhanced process visibility         |
| Enable PowerShell Module Logging and Script Block Logging  | Detect obfuscated/malicious scripts |
| Create alert for logins outside business hours             | Catch off-hour activities           |
| Monitor `mmc.exe`, `compmgmt.msc`, and `runas.exe` usage   | Detect admin tool abuse             |
| Use correlation searches for chained events                | (e.g., `4624` → `4672` → `4688`)    |

---

> 🧠 This report is part of adversary emulation efforts focused on detecting real-world post-exploitation behaviors using native Windows tools and logging.

