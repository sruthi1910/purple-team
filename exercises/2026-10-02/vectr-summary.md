# Vectr Entry: 2026-10-02 Purple Team Exercise

**Assessment:** ClickFix / Matanbuchus 3.0 / AstarionRAT
**Campaign:** 2026-10-02 Discovery + Persistence
**Source intel:** Huntress, https://www.huntress.com/blog/clickfix-matanbuchus-astarionrat-analysis
**Detection layers:** Hayabusa (Sigma) · Splunk
**Execution method:** Pre-recorded EVTX-ATTACK-SAMPLES (no ConDef lab; Atomic tests **not executed**). Tag every test case `sample-based` so it isn't counted as a live lab result.

## Open Gaps (record first)

| ID | Gap | Type | Technique | Next action |
|----|-----|------|-----------|-------------|
| G1 | Local account creation has no Sigma detection; only a Sysmon config tag fired. No 4720/4732 telemetry | Detection | T1136.001 | Enable User/Security Group Management auditing; validate 4720 + 4732 (Administrators) rules; add a SAM-registry backup rule |
| G2 | Workstation `net group … /domain` command-line detection unverified (DC side only) | Data | T1069.002 | Run Atomic T1069.002 #1, #3, #2 on Win11v |
| G3 | System info discovery never exercised | Data | T1082 | Run Atomic T1082 #1, #7, #27 |
| G4 | 4661 fires 2 high rules per event; admin RID-500 noise | Tuning | T1069.002 | Dedupe; exclude known admin and machine accounts |
| G5 | No recon clustering (systeminfo + hostname + net group) | Detection | T1082 / T1069.002 | Build a correlation search after the lab re-run |

## Test Cases

| Test case | Technique | Tactic | Outcome | Detecting layer | Severity | Notes |
|-----------|-----------|--------|---------|-----------------|----------|-------|
| Domain Admins group enumeration (net group /domain) | T1069.002 | Discovery | **Alerted** | Hayabusa: *AD Privileged Users or Groups Reconnaissance*, *Reconnaissance Activity* (4661 RID 512) · Splunk: logged, session correlated | High | DC side only; `user01` from 10.0.2.17. Workstation side not tested (G2) |
| Create local account (+ add to Administrators) | T1136.001 | Persistence | **Logged** | Hayabusa: *Reg Key Create/Delete* / *Reg Key Value Set (Sysmon Alert)* · Splunk: logged | Medium | Hayabusa surfaced Sysmon RuleName tags, not detection logic. Accounts `support`, `sqlsvc`. No 4720/4732 (G1) |
| System information discovery (systeminfo / hostname / wmic) | T1082 | Discovery | **Not tested** | — | — | No matching activity in samples. Rules exist (G3) |

## Coverage Snapshot

- 1 of 3 Alerted · 1 of 3 Logged · 1 of 3 Not tested
- Hayabusa and Splunk counts agree for every in-scope technique

## Notes (not tracked as gaps)

- Exercise setup issues S1/S2 (Splunk timestamps and field flattening) came from the one-off EVTX→JSON conversion. Details are in `gap-analysis.md`. Don't log them as coverage gaps.
- Re-run all three techniques in the ConDef lab and update these test cases with live results.
