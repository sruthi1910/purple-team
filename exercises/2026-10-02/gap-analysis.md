---
date: 2026-10-02
type: gap-analysis
exercise: "[[Exercise-2026-10-02]]"
techniques: [T1082, T1069.002, T1136.001]
tags: [purple-team, gap-analysis, coverage]
---

# Gap Analysis: 2026-10-02 (ClickFix / Matanbuchus 3.0 / AstarionRAT)

Inputs: [[threat-intel]] · [[test-plan]] · [[findings]] (Hayabusa) · [[siem-validation]] (Splunk)

> **Run caveat:** There was no ConDef lab this run. The planned Atomic tests were **not executed**. Pre-recorded EVTX-ATTACK-SAMPLES stood in for the Win11v and DC logs. The samples come from other hosts and other tools, so a "gap" below can mean the **sample lacks the telemetry** rather than that a **detection is missing**. Each row says which.

## 1. Coverage Summary

| Technique | Planned tests | Telemetry in samples | Hayabusa | Splunk | Outcome |
|-----------|---------------|----------------------|----------|--------|---------|
| T1069.002 Domain Groups | #1, #3, #2 | DC side only (4624 → 5140/5145 → 4661 RID 512) | ✅ **High** (2 rules) | ✅ Correlated session | **Detected** (DC side) |
| T1136.001 Local Account | #4, #8 | Sysmon 12/13 SAM registry only | ⚠️ Med (Sysmon RuleName pass-through) | ⚠️ Same 17 events | **Partially detected** |
| T1082 System Info | #1, #7, #27 | None | ❌ | ❌ | **Not tested** |

**Score:** 1 of 3 detected · 1 of 3 partial · 1 of 3 untestable with the current data.

## 2. Techniques Tested vs Detected

| Technique | Simulated? | Detected? | Gap type |
|-----------|-----------|-----------|----------|
| T1069.002 | Yes, by proxy (sample from a different domain, `user01` from 10.0.2.17) | Yes | Workstation command-line coverage unverified |
| T1136.001 | Yes, by proxy (accounts `support`, `sqlsvc` created on LAPTOP-JU4M3I0E) | Partial | No Sigma detection fired; it relies on a Sysmon config tag |
| T1082 | **No** | n/a | Data gap. Hayabusa rules exist but were never exercised |

## 3. Hayabusa vs SIEM

| Check | Hayabusa | Splunk | Match? |
|-------|----------|--------|--------|
| T1069.002 user01 → RID 512 events | 2 (×2 rules = 4 high hits) | 2 | ✅ |
| T1069.002 surrounding session | 4624, 5140, 4661 | + 5145 IPC$, + 2 user01 SAM_DOMAIN | ✅ Splunk adds context |
| T1136.001 SAM registry events | 17 | 17 (5 create / 3 delete / 5 set / 4 Admins) | ✅ |
| T1082 process events | 0 | 0 | ✅ |
| Related recon (reg query / wmic / whoami) | 18 / 2 / 1 | 18 / 2 / 1 | ✅ |
| Event timestamps | Correct (2019/2020) | **Wrong date (2026)**, `timestamp` field drifts from the real event time | ❌ DQ-1/2 |
| 1102 log clear attribution | `administrator` | **No username** | ❌ DQ-4 |
| Sysmon `EventType` | Parsed | Needs `spath` | ⚠️ DQ-4 |

**Conclusion:** The detection content agrees between the two tools. The ❌ timestamp and attribution rows come from this run's one-off EVTX→JSON conversion, not from a production log pipeline (see [[#Exercise setup issues]]). They still block time-windowed correlation searches *in this exercise's Splunk index*, for example "4720 within 60s of `net1.exe user /add`".

## 4. Expected vs Actual Telemetry

### T1082 (test plan §T1082)

| Expected | Actual |
|----------|--------|
| Sysmon 1 `systeminfo.exe` (parent cmd/powershell) | ❌ Absent |
| Sysmon 1 `reg.exe query *Services\Disk\Enum*` | ❌ Absent (only Run/Winlogon `reg query`, T1012) |
| Sysmon 1 `hostname.exe` | ❌ Absent |
| Sysmon 1 `wmic cpu/bios/os get …` | ❌ Absent (only `wmic process`) |
| Security 4688 equivalents | ❌ No Security log from a workstation in the samples |

### T1069.002 (test plan §T1069.002)

| Expected | Actual |
|----------|--------|
| Win11v Sysmon 1 `net.exe` + `net1.exe group "domain admins" /domain` | ❌ Absent (only `net view`, `net use`) |
| Win11v 4688 equivalents | ❌ Absent |
| Win11v 4799 (bonus) | ❌ Absent (expected for domain groups) |
| DC 4624 Type 3 from workstation | ✅ `user01` from 10.0.2.17 |
| DC 5145 IPC$ / samr | ✅ Present (3 events) |
| DC 4661 on Domain Admins (needs SACL) | ✅ Present (RID 512 ×2) |

### T1136.001 (test plan §T1136.001)

| Expected | Actual |
|----------|--------|
| 4720 user created | ❌ Absent |
| 4722 / 4724 / 4738 | ❌ Absent |
| 4732 added to Users / **Administrators** | ❌ Absent (Sysmon 13 on `Aliases\00000220` stands in, ×4) |
| 4726 / 4733 on cleanup | ❌ Absent (Sysmon 12 DeleteKey ×3 stands in) |
| Sysmon 1 / 4688 `net1.exe user * /add` | ❌ Absent |
| Sysmon 1 `net1.exe localgroup administrators * /add` | ❌ Absent |
| *(not planned)* Sysmon 12/13 `HKLM\SAM\…\Names\<user>` by lsass | ✅ 17 events, a useful fallback signal |

## 5. Gaps & Remediation (priority order)

| # | Gap | Type | Owner | Action |
|---|-----|------|-------|--------|
| G1 | T1136.001 has no Sigma hit; only a Sysmon config tag | **Detection** | Detection Eng | Enable User/Security Group Management auditing. Validate the 4720 + 4732 (S-1-5-32-544) rules. Add a Sigma/SPL rule for `lsass.exe` writes to `HKLM\SAM\SAM\Domains\Account\Users\Names\*` as a backup |
| G2 | T1069.002 workstation command-line detection unverified | **Data** | Red / Lab | Run Atomic T1069.002 #1, #3 (`net groups` plural), #2 (PowerShell/4104) on Win11v |
| G3 | T1082 completely untested | **Data** | Red / Lab | Run Atomic T1082 #1, #7, #27. Consider raising severity for an unusual parent (msiexec / sideloaded binary) to match Matanbuchus |
| G4 | 4661 duplicate high alerts; admin RID-500 noise | **Tuning** | SOC | Dedupe the paired rules. Exclude known admin sessions and machine accounts |
| G5 | No clustering of recon (systeminfo + hostname + net group in a short window) | **Detection** | Detection Eng | Build a correlation search; validate it on real lab data with correct timestamps (see S1) |

## Exercise setup issues

These are **not detection or production pipeline gaps**. They come from this run's one-off workaround: there was no ConDef lab, so pre-recorded EVTX samples were converted to JSON and loaded into a local Splunk. They affect only this exercise's `purple_team` index. They are kept out of the priority list and out of Vectr.

| # | Issue | Effect in this run | Fix (only if the workaround is reused) |
|---|-------|--------------------|----------------------------------------|
| S1 | Splunk `_time` has the wrong date (2026 instead of 2019/2020), the JSON `timestamp` drifts from the real event time, and 2 events have null `1601-01-01` timestamps (DQ-1/2/3) | Splunk event order and time windows are unreliable; searches need `earliest=0` | In the converter, emit `TimeCreated/@SystemTime` (or `UtcTime` for Sysmon). In `props.conf`, set `TIME_PREFIX`, `TIME_FORMAT` and `MAX_DAYS_AGO`. Re-index |
| S2 | 1102 `UserData` not exported and Sysmon `EventType` not auto-extracted (DQ-4) | Splunk can't attribute the log clear; create/delete needs `spath` | Flatten `UserData` in the converter; use `KV_MODE=json` |

In the ConDef lab, logs reach Splunk through the normal forwarder (test plan, Lab Prerequisites #6). Confirm S1/S2 don't recur there as part of the re-test.

## 6. Re-test Criteria (next lab run)

- [ ] T1136.001 #8 produces 4720 + 4732 (Administrators) and a **high** alert, correlated to `net1.exe … /add` by LogonId (G1)
- [ ] T1069.002 #1/#3 fire on both `net.exe` and `net1.exe` (G2); the DC 4661 alert fires once, deduped (G4)
- [ ] T1082 #1 fires *Suspicious Execution of Systeminfo* in both Hayabusa and Splunk (G3)
- [ ] Sanity check: forwarder-ingested Splunk `_time` matches the event's `UtcTime` / `SystemTime` (S1 doesn't recur)
