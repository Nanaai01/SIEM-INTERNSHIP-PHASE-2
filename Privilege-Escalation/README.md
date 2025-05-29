
🛡️ Privilege Escalation Detection 

📌 Scenario Overview
This scenario simulates a privilege escalation attack where an attacker creates a local user and adds it to the Administrators group, thereby gaining elevated privileges on the system.

🎯 Objective
Detect unauthorized privilege escalation attempts on Windows endpoints using Windows Security Event Logs and Splunk.

---

📖 MITRE Techniques
- T1055 – Process Injection (used as a placeholder to indicate privilege abuse via command execution)
- T1547 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder (indicates persistence through elevated privileges)

---

🔁 Attack Steps

⚙️ Simulated Commands

```powershell
net user backdoor Passw0rd! /add
net localgroup administrators backdoor /add
whoami
````

* `net user` creates a new local account.
* `net localgroup` adds the user to the Administrators group.
* `whoami` checks the user before and after escalation.

---

📊 Detection Logic

🔍 Windows Event IDs to Monitor

| Source   | Event ID | Description                                  |
| -------- | -------- | -------------------------------------------- |
| Security | 4720     | A user account was created                   |
| Security | 4732     | A member was added to a privileged group     |
| Security | 4672     | Special privileges assigned to new logon     |
| Sysmon   | 1        | Process creation (e.g., net.exe, whoami.exe) |

---

📥 Sample Splunk Query

```spl
index=win_logs (EventCode=4720 OR EventCode=4732 OR EventCode=4672)
| table _time, host, Account_Name, Target_Username, EventCode, Group_Name
```

This query identifies creation of user accounts and elevation to the Administrators group.

---

🧪 Logs & IOC Sample

```
EventCode: 4720
A user account was created:
    New Account Name: backdoor
    Account Domain:   WIN-HOST

EventCode: 4732
A member was added to a security-enabled local group:
    Member Name: backdoor
    Group Name: Administrators

EventCode: 4672
Special privileges assigned to new logon:
    Account Name: backdoor
```

---

✅ Recommendations

Detection Strategy

* Monitor for account creation and group membership changes in security logs.
* Use real-time alerts for EventCode 4720 + 4732 combinations.

Response Actions

* Disable suspicious accounts immediately.
* Investigate login history of the new account.
* Perform forensic analysis on associated host activity.

---


