# Incident Report: Ransomware on WE8105DESK

**Environment:** Wayne Corp Inc (BOTS v1 dataset)
**Tools:** Splunk Enterprise, Sysmon and Windows Security logs
**Severity:** High
**Status:** True positive, containment recommended
**Analyst:** Yashwanth

## 1. Summary
On 2016-08-24, user bob.smith opened a malicious macro-enabled Word document
(Miranda_Tate_unveiled.dotm) on host WE8105DESK. The document launched a script
dropper, which installed a payload disguised as osk.exe. The malware deleted
Windows shadow copies, disabled recovery, displayed a ransom note
("# DECRYPT MY FILES #") and then deleted itself. The behaviour is consistent
with ransomware (the ransom note name is consistent with Cerber, unconfirmed
without a file hash).

## 2. Timeline (2016-08-24)
| Time | Event |
|------|-------|
| 17:43:12 | Word opens Miranda_Tate_unveiled.dotm from D:\ |
| 17:43:21 | WINWORD.EXE spawns cmd.exe, which writes and runs 20429.vbs |
| 17:48:21 | Script launches 121214.tmp from AppData |
| 17:48:41 | Payload starts as osk.exe from a GUID-named AppData folder |
| 17:49:23 | vssadmin and wmic delete shadow copies |
| 17:49:24 | bcdedit disables Windows recovery |
| 18:15:11 | Ransom note opened in Notepad, then a .vbs version runs |
| 18:15:29 | taskkill and del remove osk.exe (cleanup) |

## 3. How it was detected
Sysmon network logs showed osk.exe running from AppData and wscript.exe
connecting to external IPs. Process-creation logs then showed the parent/child
chain back to Word. A detection for Office apps spawning command shells
returns this event with no false positives.

## 4. Indicators of compromise
- Document: D:\Miranda_Tate_unveiled.dotm
- Files: AppData\Roaming\20429.vbs, AppData\Roaming\121214.tmp,
  AppData\Roaming\{35ACA89F-933F-6A5D-2776-A3589FB99832}\osk.exe
- IPs: 37[.]187[.]37[.]150, 92[.]222[.]104[.]182, 54[.]148[.]194[.]58
- Behaviour: WINWORD.EXE -> cmd.exe; vssadmin delete shadows /all /quiet

## 5. MITRE ATT&CK
T1204.002 User Execution: Malicious File, T1059.005 VBScript,
T1036 Masquerading, T1490 Inhibit System Recovery, T1070.004 File Deletion

## 6. Recommendations
**Immediate:** Isolate WE8105DESK, block the IPs above, reset bob.smith's
credentials, check other hosts for the same IOCs.
**Recovery:** Restore from offline backups (shadow copies are gone).
**Prevention:** Disable Office macros from untrusted sources, email and
removable-media filtering, user phishing awareness training, and keep the
Office-spawning-shell detection running as an alert.

## 7. Gaps and limitations
- Delivery method is unconfirmed (the file was on D:\, which could be USB or a share).
- No file hash or sandbox analysis, so family attribution is tentative.
- Based on a static lab dataset, not live monitoring.
