# SOC-Triage-Lab
SOC triage lab built with Splunk — log ingestion, detection rules, and incident investigation using the BOTS dataset..
## Finding #1: Nessus Vulnerability Scan Activity

- **What:** PowerShell command (Get-AppxPackage) executed and output piped to a temp file named with a "nessus" prefix
- **Where:** Windows Security logs, EventCode 4688 (Process Creation), host we8105desk
- **Why it matters:** Indicates a vulnerability scan ran against this host and enumerated installed applications. This is standard scanner behaviour, but it should be verified as authorized.
- **Verdict:** Likely benign (authorized scan), but would need confirmation
- **Recommended next step:** Confirm with IT/security whether the scan was scheduled and approved. If not, investigate as potential unauthorized reconnaissance.

- ## Finding #2: Ransomware Infection on WE8105DESK (user: bob.smith)

- **What:** A script dropper (20429.vbs) launched a payload that disguised itself
  as osk.exe in a GUID-named AppData folder. It deleted shadow copies and disabled
  Windows recovery (vssadmin, wmic, bcdedit), displayed a ransom note
  ("# DECRYPT MY FILES #"), then deleted itself.
- **Where:** Sysmon EventID 3 (network) and EventID 1 (process creation), host we8105desk
- **Evidence:** osk.exe running from AppData (legitimate path is System32); wscript.exe
  making external connections to 37[.]187[.]37[.]150 and 92[.]222[.]104[.]182
- **Timeline:** 17:43 dropper runs -> 17:49 recovery destroyed -> 18:15 ransom note shown -> self-delete
- **MITRE ATT&CK:** T1059.005 (VBScript), T1036 (Masquerading), T1490 (Inhibit System Recovery), T1070.004 (File Deletion)
- **Verdict:** True positive, high severity
- **Recommended actions:** Isolate the host, block the IPs above, reset bob.smith's credentials,
  restore from offline backup, and find the initial infection vector
