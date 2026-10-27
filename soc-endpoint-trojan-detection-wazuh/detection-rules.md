# Detection Reference — Endpoint Trojan Compromise

Wazuh rules observed during the incident, with the telemetry and MITRE technique each maps to.

| Wazuh rule | Level | Fires on | Telemetry | MITRE |
|---|---|---|---|---|
| 92213 | 15 | Executable dropped in a folder commonly used by malware | Sysmon 11 | T1105 |
| 100103 | 5 | Payload process execution | Sysmon 1 | T1204.002 |
| 100104 | 3 | Outbound C2 connection | Sysmon 3 | T1071 |
| 92055 / 92305 | 12 | `fodhelper.exe` UAC bypass | Sysmon 1 | T1548.002 |
| 62123 | 12 | Windows Defender detection | Defender Operational | — |
| 60109 | 8 | Local account created | Windows 4722 | T1136.001 |
| 60154 | 12 | Administrators group changed | Windows 4732 | T1484 |
| 100108 / 92041 | 8 / 10 | Registry Run-key persistence | Sysmon 13 | T1547.001 |

## Investigation pivots (Wazuh dashboard)

```
# 1. Start from critical alerts
rule.level:>=12

# 2. Privileged group change
rule.id:60154

# 3. Trace the account back to creation
rule.id:60109

# 4. Find the privilege escalation
rule.id:(92055 OR 92305)

# 5. Pivot on the payload to see process + network + registry
data.win.eventdata.image:*GHA6-Setup.exe*

# 6. Root cause — who wrote the file to disk
rule.description:"File created" and data.win.eventdata.targetFilename:*GHA6-Setup.exe*
```
