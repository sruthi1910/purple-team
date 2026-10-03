# Findings: 2026-10-02 Purple Team Exercise

**Scope:** T1082 System Information Discovery · T1069.002 Domain Groups · T1136.001 Create Local Account
**Tooling:** Hayabusa (via `hayabusa` MCP, `scan_evtx`, full output, no date filter)
**Data:** Pre-recorded EVTX-ATTACK-SAMPLES (no ConDef lab this run). Log timestamps are historical (2019–2020), not the exercise date.

## Scan Summary

| EVTX file | Host | Log timeframe | Detections |
|-----------|------|---------------|-----------:|
| `dicovery_4661_net_group_domain_admins_target.evtx` | WIN-77LTAPHIQ1R.example.corp (DC) | 2019-03-18 | 53 |
| `sysmon_local_account_creation_and_added_admingroup_12_13.evtx` | LAPTOP-JU4M3I0E | 2020-09-04 | 17 |
| `PanacheSysmon_vs_AtomicRedTeam01.evtx` | MSEDGEWIN10 | 2019-07-19 | 706 |
| **Total** | | | **776** |

## Results by Technique

| Technique | Telemetry present? | Detected? | Highest severity | Verdict |
|-----------|--------------------|-----------|------------------|---------|
| T1069.002 Domain Groups | Yes (DC Security 4661) | Yes | **High** | ✅ Detected |
| T1136.001 Local Account | Yes (Sysmon 12/13 only) | Partial | Medium | ⚠️ Detected via Sysmon config tags only, not Sigma |
| T1082 System Info Discovery | **No** | n/a | n/a | ❌ Not tested (no matching activity in samples) |

---

### T1069.002 – Domain Groups Discovery ✅

**Source:** `dicovery_4661_net_group_domain_admins_target.evtx` (DC-side view of `net group "domain admins" /domain`)

| Severity | Rule | Hits | Key details |
|----------|------|-----:|-------------|
| high | AD Privileged Users or Groups Reconnaissance | 6 | 2× `user01` → SAM_GROUP `...-512` (Domain Admins); 4× `administrator` → SAM_USER `...-500` |
| high | Reconnaissance Activity | 6 | Same events as above (both rules fire on 4661) |
| med | Password Policy Enumerated | 8 | `administrator`, SAM_DOMAIN `DC=example,DC=corp` / `CN=Builtin` |
| high | Log Cleared (1102) | 1 | `administrator` at 19:23:37 (likely sample prep, before activity) |
| info | Logon (Network) / NetShare Access / NTLM Auth / Net Conn | 32 | `user01` type-3 logon from **10.0.2.17**, IPC$ access (LID 0x15e1a7) |

**Attack chain (true positive):**
1. 19:23:52.491: `user01` network logon from 10.0.2.17 (4624, LID `0x15e1a7`)
2. 19:23:52.507: IPC$ share access (5140)
3. 19:23:52.522 / .538: 4661 SAM_GROUP RID **512 (Domain Admins)** opened by `user01`, which fires **2 high** rules

**Notes:**
- The `user01` 4661 hits on RID 512 are the real signal. The `administrator` hits on RID 500 (LID `0x4fd77`, an interactive session on the DC) look like the operator's own activity. Tune to reduce duplicates.
- Each event fires two high rules, so dedupe in the SIEM.
- Only the DC side is covered. There is no workstation process telemetry (Sysmon 1 / 4688 for `net.exe`/`net1.exe group ... /domain`) in the samples, so the command-line detection from the test plan was **not validated**.
- Needs `Audit SAM` / Directory Service Access auditing with a SACL on the SAM objects. Confirm this on the ConDef DC.

---

### T1136.001 – Create Account: Local Account ⚠️

**Source:** `sysmon_local_account_creation_and_added_admingroup_12_13.evtx`

| Severity | Rule | Hits | Sysmon RuleName |
|----------|------|-----:|-----------------|
| med | Reg Key Create/Delete (Sysmon Alert) (EID 12) | 8 | Valid Account - Local Account Created or Deleted |
| med | Reg Key Value Set (Sysmon Alert) (EID 13) | 9 | 5× Local Account Created or Deleted; 4× Account Added or Deleted from Local Administrators Group |

**Timeline (all writes by `lsass.exe` PID 900 to `HKLM\SAM\SAM\Domains\...`):**

| Time (2020-09-04, -04:00) | Activity |
|---------------------------|----------|
| 05:28:22 | `support` created |
| 05:28:42 | `support` deleted |
| 06:03:04 | `support` re-created |
| 06:33:31 | `sqlsvc` created |
| 06:45:30, 06:45:33 | Administrators alias (`Builtin\Aliases\00000220`) modified |
| 06:54:20 | `support` deleted + Administrators modified |
| 06:54:22 | `support` re-created |
| 07:00:13 / 07:00:24 | `support` deleted / re-created |
| 07:02:16 | Administrators modified |

**Notes:**
- These hits come from the **Sysmon config's RuleName tags**, which Hayabusa passes through as generic "Sysmon Alert" rules. **No Sigma account-creation rule fired.**
- The sample has no Security **4720** (user created) or **4732** (added to Administrators) events, and no `net user /add` process event. The test plan's main detection (4720 correlated with `net1.exe user * /add`) was **not validated**.
- The Administrators-group SAM write cannot be tied to a specific account from Sysmon alone. Pair it with 4732 in the lab.
- Account names to hunt for: `support`, `sqlsvc`.

---

### T1082 – System Information Discovery ❌

**Source checked:** all three files. `PanacheSysmon_vs_AtomicRedTeam01.evtx` is the only one with process-creation telemetry.

- **No** `systeminfo`, `hostname` or `wmic os/cpu/bios/computersystem` execution exists in any sample, so 0 T1082-tagged rules fired.
- Hayabusa does have rules ready: *Suspicious Execution of Systeminfo* (low), *Suspicious Execution of Hostname* (low), *System Information Discovery Via Wmic.EXE* (low), *Uncommon System Information Discovery Via Wmic.EXE* (med), *System Information Discovery via Registry Queries* (low).
- This is a **data gap, not a confirmed detection gap.** Re-test with real Atomic T1082 #1 / #7 / #27 runs.

**Related host recon in the Panache sample (not T1082):**

| Severity | Rule | Hits | Command |
|----------|------|-----:|---------|
| med | Potential Configuration And Service Reconnaissance Via Reg.EXE | 18 | `reg query HKLM\...\CurrentVersion\Run*`, `Winlogon\*`, etc. (T1012) |
| med | Potential Process Reconnaissance via Wmic.EXE | 2 | `wmic.exe process /FORMAT:list` (T1057) |
| low | Local Accounts Discovery | 1 | `whoami.exe /user` (T1033) |
| low | Net.EXE Execution / Share And Session Enumeration | 2 each | `net view`, `net view /domain` (T1135/T1018, not T1069.002) |

---

## Out-of-Scope Noise

The Panache file is a broad Atomic Red Team run, so most of its 706 hits fall outside this exercise's scope. They include 7 crit *Sticky Key Like Backdoor*, high hits for reg hive dumping, shadow copy deletion, bitsadmin downloads, regsvr32/SquiblyTwo and procdump LSASS, and 504 info *Proc Exec*. These are excluded from the verdicts above.

## Gaps & Next Steps

1. **T1082:** Run Atomic T1082 #1 (`systeminfo`), #7 (`hostname`) and #27 (wmic) in the lab, and confirm the low-severity rules fire. Consider raising severity when the parent is unusual (msiexec child, sideloaded binary), to match the Matanbuchus TTPs.
2. **T1069.002:** Capture the workstation side (Sysmon 1 for `net.exe` + `net1.exe`). Confirm it matches both `net group` and `net groups` (Atomic #3) and the PowerShell `Get-ADPrincipalGroupMembership` path via 4104 (Atomic #2).
3. **T1136.001:** Enable *Audit User Account Management* so 4720/4732 are produced. Validate Sigma rules on those IDs rather than relying on Sysmon RuleName tags.
4. Dedupe the paired high rules on 4661, and exclude expected admin RID-500 lookups on the DC.
