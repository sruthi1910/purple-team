---
date: 2026-10-02
type: siem-validation
exercise: "[[Exercise-2026-10-02]]"
techniques: [T1082, T1069.002, T1136.001]
siem: Splunk (local)
index: purple_team
tags: [purple-team, splunk, validation, hayabusa]
---

# Query Results: SIEM Validation of Hayabusa Findings (T1082 / T1069.002 / T1136.001)

Cross-checks [[findings]] (Hayabusa) against the same three EVTX samples ingested into Splunk `index=purple_team sourcetype=_json`. All searches were run with `/Applications/Splunk/bin/splunk search` and `earliest=0`.

## Verdict

| Technique | Hayabusa | Splunk | Agreement |
|-----------|----------|--------|-----------|
| [[T1069.002 - Domain Groups]] | ✅ High (4661 → RID 512) | ✅ Same 2 `user01` events, full session chain rebuilt | **Match** |
| [[T1136.001 - Local Account]] | ⚠️ Med (Sysmon RuleName tags only) | ⚠️ Same 17 events; still no 4720/4732 or `net user /add` | **Match** (same gap) |
| [[T1082 - System Information Discovery]] | ❌ No telemetry | ❌ 0 results | **Match** (data gap) |

The SIEM confirms Hayabusa's results with no extra or missing in-scope detections. It also showed **four Splunk ingestion problems** (see [[#Data Quality Issues]]). These come from this run's one-off EVTX→JSON conversion, not from a production log pipeline, and they affect only this exercise's `purple_team` index. They are tracked as exercise setup issues S1/S2 in [[gap-analysis]], not as coverage gaps.

---

## 0. Data Inventory

    index=purple_team sourcetype=_json earliest=0
    | stats count by source_file, Computer, Channel

| source_file | Computer | Channel | Events |
|-------------|----------|---------|-------:|
| PanacheSysmon_vs_AtomicRedTeam01.evtx | MSEDGEWIN10 | Sysmon | 565 |
| dicovery_4661_net_group_domain_admins_target.evtx | WIN-77LTAPHIQ1R.example.corp | Security | 63 |
| sysmon_local_account_creation_and_added_admingroup_12_13.evtx | LAPTOP-JU4M3I0E | Sysmon | 17 |

Event codes in the DC file: 5156 (28), **4661 (16)**, 5158 (5), 4624 (4), 4672 (3), 5145 (3), 5140 (2), 1102 (1), 4776 (1).

---

## 1. T1069.002 – Domain Groups Discovery ✅

### Query: SAM object access

    index=purple_team sourcetype=_json earliest=0 EventCode=4661
    | stats count by SubjectUserName ObjectType ObjectName

| SubjectUserName | ObjectType | ObjectName | Count |
|-----------------|------------|------------|------:|
| **user01** | **SAM_GROUP** | **S-1-5-21-…-512 (Domain Admins)** | **2** |
| user01 | SAM_DOMAIN | DC=example,DC=corp | 2 |
| administrator | SAM_USER | S-1-5-21-…-500 | 4 |
| administrator | SAM_DOMAIN | DC=example,DC=corp | 4 |
| administrator | SAM_DOMAIN | CN=Builtin,DC=example,DC=corp | 4 |

### Query: session correlation (user01, LogonId 0x15e1a7)

    index=purple_team sourcetype=_json earliest=0 source_file="dicovery_4661*"
        (TargetLogonId=0x15e1a7 OR SubjectLogonId=0x15e1a7)
    | table _time EventCode TargetUserName SubjectUserName IpAddress ShareName ObjectType ObjectName
    | sort _time

| Time (time of day only, see DQ-1) | EventCode | Event |
|-------------------------|-----------|-------|
| 19:23:52.507 | 4624 | `user01` network logon from **10.0.2.17** |
| 19:23:52.507 | 5140 | IPC$ share access |
| 19:23:52.522 / .538 | 5145 + 4661 | IPC$ (SAMR pipe) + SAM_DOMAIN open |
| 19:23:52.538 | 4661 | **SAM_GROUP RID 512 (Domain Admins)** |
| 19:23:57.397 | 4661 | **SAM_GROUP RID 512 (Domain Admins)** |

**Result:** The Splunk results agree with Hayabusa's 2 high hits on `user01`. Splunk adds the 5145 IPC$ events and the two `user01` SAM_DOMAIN opens, which complete the SAMR chain: remote logon → IPC$ → SAMR → Domain Admins lookup. This is what `net group "domain admins" /domain` from 10.0.2.17 looks like from the DC. The `administrator` RID-500 / SAM_DOMAIN activity is local to the DC (LogonId 0x4fd77) and is likely benign operator activity.

### Query: workstation process telemetry (`net group`)

    index=purple_team sourcetype=_json earliest=0 EventCode=1
        (Image="*\\net.exe" OR Image="*\\net1.exe")
    | table _time Computer Image CommandLine ParentImage

Only 3 results, all on MSEDGEWIN10 and none of them T1069.002: `net view /domain`, `net view`, `net use \\Target\C$ …`. **There is no `net group … /domain` process event in any sample**, so the source of 10.0.2.17 can't be seen.

### Proposed detection (DC-side)

    index=purple_team sourcetype=_json earliest=0 EventCode=4661
        ObjectType=SAM_GROUP ObjectName IN ("*-512","*-518","*-519","*-544")
        NOT SubjectUserName="*$"
    | stats count min(_time) as first values(ObjectName) as groups by SubjectUserName SubjectLogonId Computer

---

## 2. T1136.001 – Create Account: Local Account ⚠️

### Query: SAM registry writes (Sysmon 12/13)

    index=purple_team sourcetype=_json earliest=0 (EventCode=12 OR EventCode=13)
        TargetObject="HKLM\\SAM\\SAM\\Domains\\*"
    | spath output=evtype path=EventType
    | rex field=TargetObject "Users\\\\Names\\\\(?<account>[^\\\\]+)"
    | eval action=case(match(TargetObject,"Aliases\\\\00000220"),"Administrators modified",
                      evtype=="CreateKey","account created",
                      evtype=="DeleteKey","account deleted",
                      true(),"account value set")
    | stats count values(account) as accounts by action

| Action | Count | Accounts |
|--------|------:|----------|
| account created (EID 12 CreateKey) | 5 | `support`, `sqlsvc` |
| account deleted (EID 12 DeleteKey) | 3 | `support` |
| account value set (EID 13) | 5 | `support`, `sqlsvc` |
| Administrators modified (`Builtin\Aliases\00000220`) | 4 | (not attributable from Sysmon) |

All 17 events are from `lsass.exe` on LAPTOP-JU4M3I0E. The `UtcTime` values (2020-09-04 09:28:22 → 11:02:16 UTC) match Hayabusa's timeline exactly.

### Query: Security-log and command-line evidence

    index=purple_team sourcetype=_json earliest=0
        (EventCode=4720 OR EventCode=4732 OR EventCode=4728
         OR (EventCode=1 CommandLine="*user*/add*")
         OR (EventCode=1 CommandLine="*localgroup*"))
    | stats count by source_file EventCode

**0 results.** The SIEM shows the same gap as Hayabusa. Creation is only visible as SAM registry writes, so we can't see which process or user created the account or which account was added to Administrators.

---

## 3. T1082 – System Information Discovery ❌

### Query: system info discovery processes

    index=purple_team sourcetype=_json earliest=0 EventCode=1
        (Image="*\\systeminfo.exe" OR Image="*\\hostname.exe"
         OR (Image="*\\wmic.exe" (CommandLine="*os get*" OR CommandLine="*computersystem*"
             OR CommandLine="*cpu*" OR CommandLine="*bios*" OR CommandLine="*baseboard*"))
         OR CommandLine="*MachineGuid*" OR CommandLine="*SystemBiosVersion*")
    | table UtcTime Computer Image CommandLine

**0 results.** This confirms the T1082 data gap.

### Query: related recon (for context)

    index=purple_team sourcetype=_json earliest=0 EventCode=1
        (Image="*\\reg.exe" CommandLine="*query*") OR Image="*\\whoami.exe" OR Image="*\\WMIC.exe"
    | eval tool=lower(replace(Image,".*\\\\","")) | stats count values(CommandLine) by tool

| Tool | Count | Notes |
|------|------:|-------|
| reg.exe | 18 | `reg query` Run/RunOnce/Winlogon keys. This is [[T1012 - Query Registry]] / persistence hunting, not T1082 |
| wmic.exe | 2 | `process /FORMAT:list` and SquiblyTwo XSL ([[T1057]], [[T1220]]) |
| whoami.exe | 1 | `whoami /user` ([[T1033]]) |

These counts match Hayabusa exactly (18 / 2 / 1).

---

## Data Quality Issues

These are Splunk ingestion problems found during validation. **DQ-1 and DQ-2 need fixing before any time-based correlation search can be trusted.**

| ID | Issue | Evidence | Impact | Fix |
|----|-------|----------|--------|-----|
| **DQ-1** | `_time` has the wrong **date**. All events land on 2026-09-30 → 2026-10-02 instead of 2019/2020 | e.g. `net view /domain` `_time`=2026-10-01 10:51:22 EDT, `UtcTime`=2019-07-19 14:51:09 | Time-range searches and timecharts are wrong; `earliest=0` is the only reason anything is returned | In `props.conf` for this sourcetype: `TIME_PREFIX="timestamp":\s*"`, `TIME_FORMAT=%Y-%m-%dT%H:%M:%S.%7N`, `MAX_DAYS_AGO=10951`, then re-index |
| **DQ-2** | The JSON `timestamp` field isn't the event time. It drifts from `UtcTime` / Hayabusa by seconds to hours | Same event: `timestamp` 14:51:22Z vs `UtcTime` 14:51:09; sysmon_local file `timestamp` max 11:14:47Z vs last `UtcTime` 11:02:16 | Event order within a session can be wrong (Splunk puts one user01 RID-512 lookup at 19:23:57 where Hayabusa has 19:23:52.522) | Fix the EVTX→JSON converter to emit `System/TimeCreated/@SystemTime`; for Sysmon, use `UtcTime` |
| **DQ-3** | Null timestamps (`1601-01-01T00:00:00Z`) | 1× Panache EID 1, 1× DC EID 4624 | Events are dropped or misplaced in time | Same converter fix |
| **DQ-4** | Fields not flattened: `EventType` (Sysmon 12/13) needs `spath`; **1102 has no `SubjectUserName`** (UserData not exported) | `stats by EventType` returns empty; the 1102 `_raw` contains only timestamp/EventCode/Channel/Computer | Can't tell CreateKey from DeleteKey without `spath`; **can't attribute who cleared the Security log** (Hayabusa shows `administrator`) | Add `KV_MODE=json` / `INDEXED_EXTRACTIONS=json`; fix converter to flatten `UserData` |

---

## ATT&CK Mapping

- Technique: [[T1069.002 - Permission Groups Discovery - Domain Groups]] (validated, DC side only)
- Technique: [[T1136.001 - Create Account - Local Account]] (partially validated, Sysmon registry only)
- Technique: [[T1082 - System Information Discovery]] (not testable, no telemetry)
- Related: [[T1012 - Query Registry]], [[T1033 - System Owner User Discovery]], [[T1135 - Network Share Discovery]], [[T1070.001 - Clear Windows Event Logs]]
- Tactic: [[Discovery]] · [[Persistence]]

## Investigation Notes

Created: [[Investigation-2026-10-02-Purple-Team-SIEM-Validation]]
Related: [[findings]] · [[test-plan]] · [[threat-intel]] (ClickFix / Matanbuchus / AstarionRAT)

IOCs (from historical samples, not live):
- [[IOC-10.0.2.17]]: source host of the `user01` SAMR Domain Admins enumeration
- [[IOC-user01]]: account performing the domain group recon
- [[IOC-local-account-support]] and [[IOC-local-account-sqlsvc]]: local accounts created on LAPTOP-JU4M3I0E

## Follow-up Actions

- [ ] **Fix Splunk timestamping (DQ-1/2/3)** in `props.conf` and the EVTX→JSON converter, then re-index `purple_team`
- [ ] **Flatten `EventType` and `UserData` (DQ-4)** so 1102 log-clear attribution works in the SIEM
- [ ] Save the DC-side 4661 RID-512/518/519/544 search as a scheduled alert; exclude machine accounts and known admin sessions
- [ ] In the ConDef lab, capture Win11v Sysmon EID 1 for `net.exe`/`net1.exe group … /domain` (Atomic T1069.002 #1, #3) and 4104 for `Get-ADPrincipalGroupMembership` (#2)
- [ ] Enable *Audit User Account Management* and *Audit Security Group Management*, re-run Atomic T1136.001 #4 / #8, and validate 4720 + 4732 correlated with `net1.exe user * /add`
- [ ] Run Atomic T1082 #1 / #7 / #27 and validate the Splunk search in §3 returns hits
