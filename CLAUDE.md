# Purple Team Workflow

End-to-end purple team loop: threat intel → simulation → detection → validation → reporting.

## Commands

- `/ingest-ti <url>` - Process threat intelligence, extract TTPs
- `/query <search>` - Run SIEM query, generate Obsidian notes  
- `/purple-loop` - Full guided workflow

## Agents

- `atomic-mapper` - Map techniques to Atomic Red Team tests

## MCP Servers

- `hayabusa` - EVTX analysis and threat hunting

## Exercise Structure

Exercises stored in `exercises/YYYY-MM-DD/`:
- `evtx/` - Collected event logs
- `findings.md` - Detection results
- `report.md` - Exercise summary

## Lab Environment

ConDef lab:
- DC (Domain Controller)
- Win11v (Workstation with Sysmon)
- Splunk for SIEM validation

## Actual Environment (this run)

No ConDef lab. Running on macOS. Test execution (10.5) is replaced with
pre-recorded EVTX-ATTACK-SAMPLES files copied into exercises/YYYY-MM-DD/evtx/.
Log timestamps are historical, not the exercise date.
