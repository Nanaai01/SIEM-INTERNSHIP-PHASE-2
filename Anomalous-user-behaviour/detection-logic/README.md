🔍 Detection Logic: Full List

---

1. ✅ Successful Logins

```spl
index=wineventlog EventCode=4624
| table _time, Account_Name, Logon_Type, Workstation_Name
```

* Detects successful Windows logins.
* `Logon_Type` 

---

2. 🌙 Logins During Non-Business Hours

```spl
index=wineventlog EventCode=4624
| eval hour=strftime(_time, "%H")
| where hour < 6 OR hour > 20
| table _time, Account_Name, Workstation_Name, Logon_Type, hour
```

* Flags logins between 8:00 PM and 6:00 AM — an unusual time range for standard users.

---

3. ⚙️ Execution of Administrative Tools (MMC, compmgmt)

```spl
index=wineventlog EventCode=4688
| search (New_Process_Name="*mmc.exe" OR New_Process_Name="*compmgmt.msc")
| table _time, Account_Name, New_Process_Name, CommandLine, Parent_Process_Name
```

* Detects the use of admin tools like:

  * `mmc.exe` (Microsoft Management Console)
  * `compmgmt.msc` (Computer Management Snap-In)

---

4. 🚀 UAC Trigger via RunAs or Elevated PowerShell

```spl
index=wineventlog EventCode=4688
| search (CommandLine="*runas*" OR CommandLine="*powershell* -verb runas*")
| table _time, Account_Name, CommandLine, Parent_Process_Name
```

* Detects attempts to escalate privileges by:

  * Using `runas`
  * Running PowerShell with `-Verb RunAs` to prompt UAC

---

5. 🛡️ Special Privilege Assignments / Admin Session Start

```spl
index=wineventlog (EventCode=4672 OR EventCode=4648)
| table _time, EventCode, Account_Name, Logon_ID, Workstation_Name
```

* `4672`: Account assigned special privileges like `SeDebugPrivilege`, `SeTcbPrivilege`
* `4648`: Logon using explicit credentials (e.g., pass-the-hash, alternate tokens)

---

6. 🐚 Encoded PowerShell Execution (Optional for Detection)

```spl
index=sysmon EventCode=1
| search (CommandLine="*powershell*" AND CommandLine="*EncodedCommand*")
| table _time, user, CommandLine, ParentCommandLine
```

* Catches suspicious use of `-EncodedCommand` flag — often used in obfuscated attacks.

---

7. 🔎 Detection of MMC Launch from Sysmon

```spl
index=sysmon EventCode=1
| search CommandLine="*mmc*" OR Image="*compmgmt*"
| table _time, user, CommandLine, ParentCommandLine
```

