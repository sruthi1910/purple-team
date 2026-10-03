# purple-team

Module 10 (Purple Team Loop): threat intel -> Atomic Red Team mapping -> execution -> Hayabusa detection -> SIEM validation -> gap analysis -> Vectr summary, with `/ingest-ti`, `/query`, `/purple-loop` and an `atomic-mapper` subagent. The 2026-10-02 exercise is in `exercises/2026-10-02/`.

## Notes for course readers

**The Hayabusa MCP server is configured in `.mcp.json`.**
Claude Code reads project MCP servers from `.mcp.json` at the project root, not from `.claude/settings.json`, and that format has no `cwd` field. *If you're following the course:* use `.mcp.json`, and point `PYTHONPATH` and `HAYABUSA_BIN` at your own Module 3 server. Approve the server when Claude Code first asks.

**Listing commands and agents.**
`/commands` and `/agents` aren't available in current Claude Code. Type `/` to see commands, and use `/context` to confirm custom agents are loaded.

**`threat-intel.md` contains the course's example TTP table.**
The live `/ingest-ti` run on the Huntress report was stopped by the model's safety safeguards (a false positive on defensive work), so the course's own output was used, and the file says so. The exercise is scoped to T1082, T1069.002 and T1136.001, the three techniques the course executes. *If you're following the course:* run `/ingest-ti` as written. If it's blocked, use the course's table the same way.

**No lab execution: pre-recorded EVTX samples stand in for the exported logs.**
There was no Windows lab to run Atomic Red Team in, so files from [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) were used. They are not committed here. Every result is tagged `sample-based`, and the gap analysis separates "not tested" from "not detected". *If you have a lab:* run the commands in `test-plan.md` and export the logs with `wevtutil epl`. To reproduce this run instead, copy these three files into `exercises/2026-10-02/evtx/`:
- `Discovery/dicovery_4661_net_group_domain_admins_target.evtx`
- `Persistence/sysmon_local_account_creation_and_added_admingroup_12_13.evtx`
- `AutomatedTestingTools/PanacheSysmon_vs_AtomicRedTeam01.evtx`

**SIEM validation used a local Splunk, loaded from converted samples.**
Splunk on macOS can't read EVTX, so `scripts/evtx_to_json.py` converts them to JSON, which is then uploaded with `splunk add oneshot <file> -index purple_team -sourcetype _json`. Search with `earliest=0`, because the samples are from 2019–2020. Splunk ignores timestamps older than `MAX_DAYS_AGO` (about 2000 days by default) and substitutes the upload time; raise it for the sourcetype if event times matter. The original run used an earlier version of the converter with a timestamp bug, recorded as setup issues S1/S2 in `gap-analysis.md`. *If you're following the course:* use your SIEM's normal forwarding, and none of this applies.

**`/purple-loop` was resumed from step 6.**
Steps 1–5 had been run individually, so the loop was pointed at the existing exercise to do the gap analysis and the Vectr summary. Step 7 (documents) was skipped, since that's covered in Module 9. `vectr-summary.md` is ready to enter into Vectr; no Vectr instance was used.

**Working-directory pitfall.**
If Claude's file writes fail with a bare "Error writing file" after a subagent has run shell commands, the session's working directory has probably moved. Start a fresh session in the project folder, or ask for absolute paths.
