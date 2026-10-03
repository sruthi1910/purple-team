# Threat Intel Analysis: ClickFix + Matanbuchus 3.0 + AstarionRAT

**Source:** https://www.huntress.com/blog/clickfix-matanbuchus-astarionrat-analysis
**Date Ingested:** 2026-10-02
**Note:** Live /ingest-ti run was stopped by model safeguards (false positive, reported via /feedback). This TTP table is the instructor's /ingest-ti output from the course notes (Module 10.3).
**Campaign:** ClickFix social engineering delivering Matanbuchus loader and AstarionRAT
**Threat Actor:** "BelialDemon" (Matanbuchus MaaS operator, Russian-speaking forums)
**Assessed Objective:** Ransomware deployment or data exfiltration (disrupted before completion)

---

## Extracted TTPs

| Technique | ATT&CK ID | Confidence | Priority | Kill Chain Phase |
|-----------|-----------|------------|----------|------------------|
| User Execution via ClickFix | T1204.002 | High | Simulate | Initial Access |
| Msiexec Proxy Execution | T1218.007 | High | Simulate | Execution |
| DLL Side-Loading (Zillya + Java) | T1574.002 | High | Simulate | Defense Evasion |
| Scheduled Task Persistence | T1053.005 | High | Simulate | Persistence |
| Process Injection / Reflective Loading | T1055.001 | High | Simulate | Defense Evasion |
| Obfuscated Files (ChaCha20, XOR, RC4) | T1027 | High | Observe | Defense Evasion |
| Deobfuscate/Decode Files | T1140 | High | Observe | Defense Evasion |
| DLL Unhooking (KnownDlls) | T1562.001 | High | Simulate | Defense Evasion |
| System Information Discovery | T1082 | High | Simulate | Discovery |
| Domain Groups Discovery | T1069.002 | High | Simulate | Discovery |
| Create Account: Local | T1136.001 | High | Simulate | Persistence |
| Remote Services: RDP | T1021.001 | High | Simulate | Lateral Movement |
| Lateral Tool Transfer (PsExec) | T1570 | High | Simulate | Lateral Movement |
| Service Execution (PsExec) | T1569.002 | High | Simulate | Lateral Movement |
| Encrypted Channel (RSA C2) | T1573.002 | High | Observe | Command & Control |
| Masquerading: Match Legitimate Name | T1036.005 | High | Observe | Defense Evasion |
| Ingress Tool Transfer | T1105 | High | Simulate | Command & Control |
| Modify Registry / Defender Exclusion | T1562.001 | Medium | Simulate | Defense Evasion |
| Command and Scripting: Lua | T1059 | Medium | Observe | Execution |
| Heaven's Gate (WoW64 bypass) | T1106 | Medium | Observe | Defense Evasion |

## Exercise Scope (this run)

Techniques selected for simulation in 10.5, matching the course notes:
- T1082 - System Information Discovery
- T1069.002 - Domain Groups Discovery
- T1136.001 - Create Account: Local
