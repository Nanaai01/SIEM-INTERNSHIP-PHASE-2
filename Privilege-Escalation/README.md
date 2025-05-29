🔐 Use Case: Privilege Escalation Attempt (MITRE T1055 / T1547)



✅ Scenario Summary

Brief Description
This scenario simulates an attacker gaining elevated privileges on a Windows machine by creating a new local user and adding it to the Administrators group. The simulation aligns with MITRE ATT\&CK techniques:

* T1055 – Process Injection
* T1547 – Boot or Logon Autostart Execution

The goal is to emulate a post-compromise escalation method used to maintain control or persistence on the system.



🔧 Attack Steps

| Step | Description                                                            |
| ---- | ---------------------------------------------------------------------- |
| 1    | Attacker creates a new local user (`backdoor`).                        |
| 2    | Attacker adds the new user to the `Administrators` group.              |
| 3    | The newly privileged user logs in.                                     |
| 4    | Elevated privileges trigger special access logs (e.g., Event ID 4672). |


🛠 Commands Used

```cmd
net user backdoor Pass123! /add
net localgroup administrators backdoor /add
whoami
whoami /groups
```



📊 Event IDs & Data Sources

| Source               | Event ID | Description                                     |
| -------------------- | -------- | ----------------------------------------------- |
| Windows Security Log | 4720     | A user account was created                      |
| Windows Security Log | 4732     | A user was added to a local group               |
| Windows Security Log | 4672     | Special privileges assigned to new logon        |
| Sysmon               | 1        | Process creation (`cmd.exe`, `net.exe`)         |
| Sysmon               | 10       | Process access (if process injection simulated) |



🖼 Screenshot

> 📸 \[Available in the screenshot file]
> Include screenshots of:

* The alert in Splunk



📄 Logs / IOC Samples

Sample Windows Event 4732 – User Added to Local Group

```xml
A member was added to a security-enabled local group.

Subject:
    Security ID:         S-1-5-21-...
    Account Name:        ADMIN
    Logon ID:            0x1fd2e

Member:
    Security ID:         S-1-5-21-...-backdoor
    Account Name:        backdoor

Group:
    Security ID:         S-1-5-32-544
    Group Name:          Administrators
```

Sysmon Process Creation (ID 1)

```
Image: C:\Windows\System32\cmd.exe
CommandLine: cmd.exe /c net localgroup administrators backdoor /add
User: NT AUTHORITY\SYSTEM
```



✅ Recommendations

Detection Logic

* Monitor for `net.exe` and `cmd.exe` spawning with arguments like `add`, `user`, or `localgroup`.
* Alert on `Event ID 4732` where the target group is `Administrators`.
* Flag logon events (`4672`) where users unexpectedly receive `SeDebugPrivilege`, `SeTakeOwnershipPrivilege`, etc.

Analyst Response Steps

1. Identify the origin of the privilege change (who/what added the user).
2. Validate whether the user (`backdoor`) was authorized.
3. Review process creation logs for `cmd.exe`, `net.exe`.
4. Check other Event IDs (e.g., 4720, 4624) for full context.
5. Remove unauthorized accounts or group memberships.
6. Perform containment and initiate incident response if malicious activity is confirmed.



 Status

* [+] Detection Tested
* [+] Alert Triggered



📞 Contact

Aishat Olayinka Yusuf – www.linkedin.com/in/aishat-olayinka-yusuf-3a16aa1b4


