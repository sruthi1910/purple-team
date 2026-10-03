# Atomic Red Team Test Plan: ClickFix / Matanbuchus 3.0 / AstarionRAT (Post-Compromise)

**Exercise:** 2026-10-02
**Source intel:** [threat-intel.md](./threat-intel.md) (Huntress: ClickFix -> Matanbuchus 3.0 -> AstarionRAT)
**Scope:** T1082, T1069.002, T1136.001 (Discovery + Persistence)
**Target host:** Win11v (domain-joined Windows 11, Sysmon installed). Domain queries resolve against DC.
**SIEM:** Splunk
**Platform filter:** Windows only

> **Verification note:** Test numbers, names, GUIDs, commands and cleanup commands below were checked against the
> Atomic Red Team `master` branch YAML files (`atomics/<TID>/<TID>.yaml`), commit `388942adbd96` (2026-09-05),
> retrieved 2026-10-02. Test numbers are positional and **can change** when upstream adds or removes tests. To guard
> against drift, each test also lists a `-TestGuids` command. Use the GUID form if your local `C:\AtomicRedTeam\atomics`
> checkout is older or newer than that commit. Run `-ShowDetailsBrief` first to confirm the numbers match.
>
> The **Expected Telemetry** sections are analyst expectations based on standard Windows and Sysmon behavior. They do not
> come from the atomic YAML. Confirm them against your audit policy and Sysmon config (see Lab Prerequisites).

---

## Observed Attacker Behavior -> Test Selection

| ATT&CK | Observed in campaign | Primary atomic | Secondary / optional |
|--------|----------------------|----------------|----------------------|
| T1082 | `systeminfo`-style host recon | #1 System Information Discovery (`systeminfo`) | #7 Hostname Discovery; #27 WMIC (optional, see caveat) |
| T1069.002 | `net group "domain admins" /domain` | #1 Basic Permission Groups Discovery Windows (Domain) | #3 Elevated group enumeration using net group; #2 PowerShell (needs RSAT) |
| T1136.001 | Local account created for persistence | #4 Create a new user in a command prompt (`net user /add`) | #8 Create a new Windows admin user (adds to Administrators) |

---

## Lab Prerequisites (one-time, on Win11v)

1. **Invoke-AtomicRedTeam + atomics** installed (elevated PowerShell):
   ```powershell
   IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
   Install-AtomicRedTeam -getAtomics -Force
   Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
   ```
   Microsoft Defender may quarantine parts of the atomics folder. Add a **lab-only** exclusion for `C:\AtomicRedTeam` if needed. None of the selected tests need downloaded payloads.
2. **Elevated PowerShell session** for the T1136.001 tests, which have `elevation_required: true`.
3. **Domain user context** for T1069.002. Run as a domain account on Win11v so `/domain` queries reach the DC.
4. **Audit policy** on Win11v, applied via GPO or `auditpol`:
   - Detailed Tracking > Process Creation: Success (**4688**)
   - GPO: *Include command line in process creation events* = Enabled (otherwise 4688 has no command line)
   - Account Management > User Account Management: Success (**4720, 4722, 4724, 4726, 4738**)
   - Account Management > Security Group Management: Success (**4732, 4733, 4799**)
   - PowerShell Script Block Logging enabled (**4104**)
5. **Sysmon** with process creation (Event 1) enabled and not filtering `net.exe`, `net1.exe`, `systeminfo.exe`, `reg.exe`, `hostname.exe`, `wmic.exe`.
6. **Splunk forwarding** of `Security`, `Microsoft-Windows-Sysmon/Operational`, and `Microsoft-Windows-PowerShell/Operational` from Win11v, plus `Security` from DC.
7. Start the **EVTX collection** window. Export logs to `exercises/2026-10-02/evtx/` after execution for Hayabusa analysis.

---

## Atomic Red Team Test Plan

### T1082 - System Information Discovery

#### Atomic Test #1 - System Information Discovery (PRIMARY)
- **GUID:** `66703791-c902-4560-8770-42b8a91f7667`
- **Executor:** `command_prompt` (no elevation required)
- **Why:** Matches the observed `systeminfo` host recon directly.
- **Commands executed:**
  ```cmd
  systeminfo
  reg query HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum
  ```
- **Prerequisites:** None (no dependencies defined).
- **Invoke-AtomicTest:**
  ```powershell
  Invoke-AtomicTest T1082 -TestNumbers 1 -ShowDetailsBrief
  Invoke-AtomicTest T1082 -TestNumbers 1 -CheckPrereqs
  Invoke-AtomicTest T1082 -TestNumbers 1
  Invoke-AtomicTest T1082 -TestNumbers 1 -Cleanup
  # GUID-pinned alternative:
  Invoke-AtomicTest T1082 -TestGuids 66703791-c902-4560-8770-42b8a91f7667
  ```
- **Cleanup:** None defined upstream (read-only test). Running `-Cleanup` is a harmless no-op.
- **Expected Telemetry:**
  - Sysmon Event 1: `Image=*\systeminfo.exe`, ParentImage `cmd.exe` (spawned by `powershell.exe` via Invoke-AtomicTest)
  - Sysmon Event 1: `Image=*\reg.exe`, `CommandLine=*query*Services\Disk\Enum*` (VM/disk fingerprinting)
  - Security 4688: same two processes with command line
  - Optional: `systeminfo.exe` loads WMI. Depending on Sysmon config you may see Event 7 (ImageLoad) for `wbemcomn.dll` / `fastprox.dll`
  - Detection idea: `systeminfo.exe` with a parent of `cmd.exe` / `powershell.exe` / an unusual parent (in the real campaign, a loader-spawned process such as msiexec child or sideloaded binary)

#### Atomic Test #7 - Hostname Discovery (Windows) (SECONDARY)
- **GUID:** `85cfbf23-4a1e-4342-8792-007e004b975f`
- **Executor:** `command_prompt` (no elevation)
- **Command:** `hostname`
- **Prerequisites:** None.
- **Invoke-AtomicTest:**
  ```powershell
  Invoke-AtomicTest T1082 -TestNumbers 7 -CheckPrereqs
  Invoke-AtomicTest T1082 -TestNumbers 7
  Invoke-AtomicTest T1082 -TestNumbers 7 -Cleanup   # no cleanup defined (no-op)
  ```
- **Expected Telemetry:**
  - Sysmon Event 1 / Security 4688: `Image=*\hostname.exe`
  - Value: low-fidelity on its own. Useful for **clustering**, e.g. systeminfo + hostname + net group within a short window from the same parent.

#### Atomic Test #27 - System Information Discovery with WMIC (OPTIONAL)
- **GUID:** `8851b73a-3624-4bf7-8704-aa312411565c`
- **Executor:** `command_prompt`
- **Commands:** a series of `wmic cpu get name`, `wmic bios get SMBIOSBIOSVersion`, `wmic OS get Caption,OSArchitecture,Version`, `wmic path win32_VideoController get name`, etc.
- **Caveats:**
  - `wmic.exe` is deprecated and is disabled by default (Feature on Demand) on recent Windows 11 builds. Check with `where wmic` first. If it is absent, skip this test or enable the WMIC FoD in the lab only.
  - The upstream command list ends with `Get-WmiObject win32_bios` under a `command_prompt` executor. That line fails in cmd ("not recognized"). This is expected and harmless.
- **Invoke-AtomicTest:**
  ```powershell
  Invoke-AtomicTest T1082 -TestNumbers 27 -CheckPrereqs
  Invoke-AtomicTest T1082 -TestNumbers 27
  Invoke-AtomicTest T1082 -TestNumbers 27 -Cleanup  # no cleanup defined (no-op)
  ```
- **Expected Telemetry:** Sysmon 1 / 4688 bursts of `wmic.exe` with `cpu`, `bios`, `baseboard`, `win32_VideoController` arguments. Also `WmiPrvSE.exe` activity.

---

### T1069.002 - Permission Groups Discovery: Domain Groups

#### Atomic Test #1 - Basic Permission Groups Discovery Windows (Domain) (PRIMARY)
- **GUID:** `dd66d77d-8998-48c0-8024-df263dc2ce5d`
- **Executor:** `command_prompt` (no elevation)
- **Why:** Contains the exact observed command `net group "domain admins" /domain`.
- **Commands executed:**
  ```cmd
  net localgroup
  net group /domain
  net group "enterprise admins" /domain
  net group "domain admins" /domain
  ```
- **Prerequisites:** Win11v must be domain-joined and able to reach DC, running as a domain user. On a non-domain host the test prints errors.
- **Invoke-AtomicTest:**
  ```powershell
  Invoke-AtomicTest T1069.002 -TestNumbers 1 -ShowDetailsBrief
  Invoke-AtomicTest T1069.002 -TestNumbers 1 -CheckPrereqs
  Invoke-AtomicTest T1069.002 -TestNumbers 1
  Invoke-AtomicTest T1069.002 -TestNumbers 1 -Cleanup
  # GUID-pinned alternative:
  Invoke-AtomicTest T1069.002 -TestGuids dd66d77d-8998-48c0-8024-df263dc2ce5d
  ```
- **Cleanup:** None defined upstream (read-only).
- **Expected Telemetry (Win11v):**
  - Sysmon Event 1: `Image=*\net.exe` with `CommandLine` containing `group` + `/domain` and `"domain admins"` / `"enterprise admins"`
  - Sysmon Event 1: child `Image=*\net1.exe` with the same arguments, ParentImage `net.exe`. Detections should cover **both** `net.exe` and `net1.exe`.
  - Security 4688: same process pairs with command line
  - Security **4799** (*A security-enabled local group membership was enumerated*) may appear for local-group queries. `net localgroup` without a group name often does **not** generate 4799, and domain global groups never generate 4799 on the workstation. Treat 4799 as bonus telemetry here.
- **Expected Telemetry (DC):**
  - Security 4624 Logon Type 3 / 4627 from Win11v for the querying user (SAMR over SMB)
  - Security 5145 (Detailed File Share) for `IPC$` / relative target `samr`, **only** if Detailed File Share auditing is enabled on DC
  - Security 4661 (handle to SAM object) for the Domain Admins group, **only** if a SACL is configured on the object
- **Detection idea:** `(Image IN (net.exe, net1.exe)) AND CommandLine="*group*" AND CommandLine="*/domain*" AND CommandLine IN ("*admins*", "*operators*")`.

#### Atomic Test #3 - Elevated group enumeration using net group (Domain) (SECONDARY)
- **GUID:** `0afb5163-8181-432e-9405-4322710c0c37`
- **Executor:** `command_prompt` (no elevation)
- **Why:** Tests detection resilience against alias and loose typing (`net groups` vs `net group`) across several high-value groups.
- **Commands executed:**
  ```cmd
  net groups "Account Operators" /domain
  net groups "Exchange Organization Management" /domain
  net group "BUILTIN\Backup Operators" /domain
  net group "Domain Admins" /domain
  ```
- **Prerequisites:** Same as #1. The Exchange group will not exist in ConDef, so an error for it is expected.
- **Invoke-AtomicTest:**
  ```powershell
  Invoke-AtomicTest T1069.002 -TestNumbers 3 -CheckPrereqs
  Invoke-AtomicTest T1069.002 -TestNumbers 3
  Invoke-AtomicTest T1069.002 -TestNumbers 3 -Cleanup   # no cleanup defined (no-op)
  # GUID-pinned:
  Invoke-AtomicTest T1069.002 -TestGuids 0afb5163-8181-432e-9405-4322710c0c37
  ```
- **Expected Telemetry:** As in #1. Verify the detection matches `net groups` (plural) and mixed-case group names.

#### Atomic Test #2 - Permission Groups Discovery PowerShell (Domain) (OPTIONAL)
- **GUID:** `6d5d8c96-3d2a-4da9-9d6d-9a9d341899a7`
- **Executor:** `powershell`
- **Command:** `get-ADPrincipalGroupMembership $env:USERNAME | select name` (input arg `user`, default `$env:USERNAME`)
- **Prerequisites:** The test defines **no** dependency, but it needs the ActiveDirectory PowerShell module (RSAT: AD DS tools) on Win11v. Without it the cmdlet is not recognized. Install it in the lab with `Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0` or skip this test.
- **Invoke-AtomicTest:**
  ```powershell
  Invoke-AtomicTest T1069.002 -TestNumbers 2 -CheckPrereqs
  Invoke-AtomicTest T1069.002 -TestNumbers 2
  Invoke-AtomicTest T1069.002 -TestNumbers 2 -Cleanup   # no cleanup defined (no-op)
  ```
- **Expected Telemetry:** PowerShell 4104 (Script Block) containing `Get-ADPrincipalGroupMembership`. There is **no** net.exe process, so this tests whether coverage depends only on command-line detections. On DC: LDAP/ADWS queries (port 9389) from Win11v. Sysmon 3 from `powershell.exe` to DC:9389 if network logging is enabled.

---

### T1136.001 - Create Account: Local Account

#### Atomic Test #4 - Create a new user in a command prompt (PRIMARY)
- **GUID:** `6657864e-0323-4206-9344-ac9cd7265a4f`
- **Executor:** `command_prompt`, **elevation required**
- **Why:** `net user /add` is the most common hands-on-keyboard local-account persistence pattern.
- **Command executed:**
  ```cmd
  net user /add "T1136.001_CMD" "T1136.001_CMD!"
  ```
  (input args: `username` default `T1136.001_CMD`, `password` default `T1136.001_CMD!`)
- **Prerequisites:** Elevated session. The password must meet the effective password policy. Domain-joined hosts apply the domain password policy to local accounts. The default meets standard complexity.
- **Invoke-AtomicTest:**
  ```powershell
  Invoke-AtomicTest T1136.001 -TestNumbers 4 -ShowDetailsBrief
  Invoke-AtomicTest T1136.001 -TestNumbers 4 -CheckPrereqs
  Invoke-AtomicTest T1136.001 -TestNumbers 4
  Invoke-AtomicTest T1136.001 -TestNumbers 4 -Cleanup
  # GUID-pinned:
  Invoke-AtomicTest T1136.001 -TestGuids 6657864e-0323-4206-9344-ac9cd7265a4f
  Invoke-AtomicTest T1136.001 -TestGuids 6657864e-0323-4206-9344-ac9cd7265a4f -Cleanup
  ```
- **Cleanup (upstream):** `net user /del "T1136.001_CMD" >nul 2>&1`
- **Expected Telemetry (Win11v Security log):**
  - **4720** A user account was created: TargetUserName `T1136.001_CMD`, SubjectUserName = operator
  - **4722** A user account was enabled
  - **4724** An attempt was made to reset an account's password (set during creation)
  - **4738** A user account was changed (one or more, during creation)
  - **4732** A member was added to a security-enabled local group: group `Users` (new local accounts join Users automatically)
  - On cleanup: **4726** A user account was deleted, **4733** member removed from local group
  - Sysmon Event 1 / Security 4688: `net.exe` and `net1.exe` with `CommandLine=*user*/add*`. **The plaintext password appears in the command line.** Note this for log-handling and redaction.
- **Detection idea:** 4720 on a workstation (should be rare), correlated with `net1.exe user * /add` from the same SubjectLogonId.

#### Atomic Test #8 - Create a new Windows admin user (SECONDARY)
- **GUID:** `fda74566-a604-4581-a4cc-fbbe21d66559`
- **Executor:** `command_prompt`, **elevation required**
- **Why:** Persistence accounts are often added to local Administrators. This tests the higher-severity variant. Run it if the scenario calls for admin-level persistence. The intel table does not say whether the account was privileged, so treat this as a coverage extension.
- **Commands executed:**
  ```cmd
  net user /add "T1136.001_Admin" "T1136_pass"
  net localgroup administrators "T1136.001_Admin" /add
  ```
- **Prerequisites:** Elevated session.
- **Invoke-AtomicTest:**
  ```powershell
  Invoke-AtomicTest T1136.001 -TestNumbers 8 -CheckPrereqs
  Invoke-AtomicTest T1136.001 -TestNumbers 8
  Invoke-AtomicTest T1136.001 -TestNumbers 8 -Cleanup
  # GUID-pinned:
  Invoke-AtomicTest T1136.001 -TestGuids fda74566-a604-4581-a4cc-fbbe21d66559
  Invoke-AtomicTest T1136.001 -TestGuids fda74566-a604-4581-a4cc-fbbe21d66559 -Cleanup
  ```
- **Cleanup (upstream):** `net user /del "T1136.001_Admin" >nul 2>&1`. Deleting the account also removes its group membership.
- **Expected Telemetry:**
  - 4720 / 4722 / 4724 / 4738 as in #4
  - **4732** member added to `Administrators` (S-1-5-32-544), the **high-severity** signal, plus 4732 for `Users`
  - Sysmon 1 / 4688: `net1.exe localgroup administrators * /add`
  - On cleanup: 4726, 4733

#### Not selected (FYI)
- #5 *Create a new user in PowerShell* (`bc8be0ac-475c-4fbf-9b1d-9fffd77afbde`, `New-LocalUser -NoPassword`, cleanup `Remove-LocalUser`). A good follow-up to test non-net.exe account creation (4720 + 4104, no net1.exe). It was left out because the campaign used CLI-style tradecraft.
- #9 *Create a new Windows admin user via .NET* (`2170d9b5-bacd-4819-a952-da76dae0815f`). Not reviewed in detail for this plan.

---

## Execution Order

Run from **one elevated PowerShell session on Win11v, logged in as a domain user who is a local admin**, so all activity shares a parent and logon session. That makes correlation easy.

| Step | Time (record) | Action |
|------|---------------|--------|
| 0 | | Confirm Splunk is receiving Win11v and DC logs. Note the start time (UTC). Run `-ShowDetailsBrief` for all three TIDs and confirm the numbers and GUIDs match this plan. |
| 1 | | `Invoke-AtomicTest T1082 -TestNumbers 1` |
| 2 | | `Invoke-AtomicTest T1082 -TestNumbers 7` *(optional #27 if wmic is present)* |
| 3 | | `Invoke-AtomicTest T1069.002 -TestNumbers 1` |
| 4 | | `Invoke-AtomicTest T1069.002 -TestNumbers 3` *(optional #2 if RSAT is installed)* |
| 5 | | `Invoke-AtomicTest T1136.001 -TestNumbers 4` |
| 6 | | *(optional)* `Invoke-AtomicTest T1136.001 -TestNumbers 8` |
| 7 | | Wait 2-5 min for ingestion, then validate in Splunk (checklist below) **before** cleanup, so the account is still present for live triage |
| 8 | | **Cleanup:** `Invoke-AtomicTest T1136.001 -TestNumbers 4 -Cleanup`, then `Invoke-AtomicTest T1136.001 -TestNumbers 8 -Cleanup` |
| 9 | | Verify removal: `net user` / `Get-LocalUser \| ? Name -like 'T1136*'` returns nothing |
| 10 | | Export EVTX (Security, Sysmon, PowerShell/Operational) from Win11v and DC to `exercises/2026-10-02/evtx/`. Run the Hayabusa scan. Record results in `findings.md` |

Optional convenience (attack chain in one go, discovery first):
```powershell
$tests = @{ 'T1082' = @(1,7); 'T1069.002' = @(1,3); 'T1136.001' = @(4) }
foreach ($t in $tests.Keys | Sort-Object) { Invoke-AtomicTest $t -TestNumbers $tests[$t] }
```
Hashtable key order is not guaranteed, and `Sort-Object` happens to give T1069.002 -> T1082 -> T1136.001. That order still puts persistence last. Run the steps individually if exact ordering matters.

---

## Safety Notes

- **Lab only.** Run only on ConDef Win11v. Never on production or any domain-connected host outside the lab.
- **Account cleanup is mandatory.** T1136.001 #4 and #8 create real local accounts with known passwords (`T1136.001_CMD` / `T1136.001_CMD!`, `T1136.001_Admin` / `T1136_pass`). #8 creates a **local administrator**. Run `-Cleanup` and verify with `net user`. Do not leave the accounts overnight.
- If you override `-InputArgs` for username or password, pass the **same** `-InputArgs` to `-Cleanup`. Otherwise cleanup deletes the default name and leaves your account behind.
- Plaintext passwords will be stored in 4688 / Sysmon 1 command lines in Splunk and in the EVTX exports. This is acceptable for lab dummy credentials only. Never substitute real credentials.
- Discovery tests (T1082, T1069.002) are read-only and have no cleanup. They generate SAMR/LDAP traffic to DC, which is harmless.
- Any Defender exclusion added for `C:\AtomicRedTeam` should be removed after the exercise.
- Snapshot Win11v before execution if possible.

---

## Validation Checklist (Splunk)

Adjust `index=` / `sourcetype=` to the ConDef Splunk configuration. The examples assume `XmlWinEventLog` sourcetypes from the Splunk Add-on for Microsoft Windows and `host=Win11v`.

**T1082 - System Information Discovery**
- [ ] Sysmon 1 for `systeminfo.exe` on Win11v
  `index=* host=Win11v sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*\\systeminfo.exe"`
- [ ] Sysmon 1 / 4688 for `reg.exe query ...Services\Disk\Enum`
- [ ] Sysmon 1 for `hostname.exe`
- [ ] Parent-child chain visible: `powershell.exe -> cmd.exe -> systeminfo.exe`
- [ ] Existing detection or alert fired? (Y/N, rule name): ________

**T1069.002 - Domain Groups Discovery**
- [ ] Sysmon 1 / 4688 for `net.exe` **and** `net1.exe` with `/domain` and `domain admins`
  `index=* host=Win11v (EventCode=1 OR EventCode=4688) (Image="*\\net.exe" OR Image="*\\net1.exe" OR NewProcessName="*\\net*.exe") CommandLine="*/domain*" CommandLine="*admins*"`
- [ ] `net groups` (plural) variant from test #3 also matched
- [ ] DC: 4624 Type 3 from Win11v around execution time (5145 `samr` if file-share auditing is on)
- [ ] (Optional #2) 4104 containing `Get-ADPrincipalGroupMembership`
- [ ] Existing detection or alert fired? (Y/N, rule name): ________

**T1136.001 - Create Local Account**
- [ ] 4720 for `T1136.001_CMD` (and `T1136.001_Admin` if #8 was run)
  `index=* host=Win11v sourcetype="XmlWinEventLog:Security" EventCode IN (4720,4722,4724,4738,4726) TargetUserName="T1136.001*"`
- [ ] 4722 account enabled
- [ ] 4732 added to `Users`; 4732 added to `Administrators` (#8). For local accounts, 4732 `MemberName` is usually `-`, so match on `MemberSid` = the `TargetSid` from the 4720 event:
  `index=* host=Win11v sourcetype="XmlWinEventLog:Security" EventCode IN (4732,4733) MemberSid="<TargetSid from 4720>"`
- [ ] Sysmon 1 / 4688 for `net1.exe user ... /add`
- [ ] After cleanup: 4726 deleted + 4733 removed from group
- [ ] Account confirmed absent on Win11v (`net user`)
- [ ] Existing detection or alert fired? (Y/N, rule name): ________

**Correlation / Wrap-up**
- [ ] All three techniques visible in one timeline from the same parent PID / logon ID
- [ ] EVTX exported to `evtx/`, Hayabusa scan run, hits recorded in `findings.md`
- [ ] Gaps (no alert fired) logged as detection engineering backlog items in `findings.md`

---

## Reference
- Atomic Red Team: https://github.com/redcanaryco/atomic-red-team
  - [T1082.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.yaml)
  - [T1069.002.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1069.002/T1069.002.yaml)
  - [T1136.001.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136.001/T1136.001.yaml)
- Invoke-AtomicRedTeam: https://github.com/redcanaryco/invoke-atomicredteam
- Test index: https://atomicredteam.io/
- Campaign: https://www.huntress.com/blog/clickfix-matanbuchus-astarionrat-analysis
