# Demo script — five minutes, one continuous run

Record with the console at 1440×900 and IBM Bob open in a second window. No slides inside the video.
Everything below is reproducible from `python scripts/demo.py`; the incident IDs are stable because the
corpus is deterministic.

## 0:00 — The problem, viscerally (Raw feeds view)

Open <http://localhost:8000/#/feeds>. Four panes: SIEM JSON, syslog, geo CSV, intel prose.
Say: "This is what the analyst starts the shift with. 521 alerts in four formats with four severity
scales. The SIEM says *critical*, the sensor says *err*, the geo feed says *P2*, and the report says
*HIGH*. None of them know about each other."

## 0:40 — Run the pipeline (terminal)

```
python -m src.pipeline.run
```

Read the stage lines aloud as they appear: 521 alerts → 491 ATT&CK mappings → 148 evidential edges →
456 incidents, 24 of them multi-alert. "Several hundred alerts collapse into two dozen things worth a
human's attention, in three seconds."

## 1:10 — The queue (Triage queue view)

Reload <http://localhost:8000/#/queue>. Point at the score bars: "Four factors, kept separate.
Correlation confidence, asset criticality, kill-chain depth, and the red segment — false-positive
likelihood. Vendor severity is on the far right, preserved, and deliberately not part of the score."

Point at #2: "A radar track, an RF emitter, a rogue access point, a NAC event and a Modbus write on a
PLC — five alerts from three feeds that no single console could have joined."

## 1:50 — Open INC-014 (Incident view)

Click #1. Walk the kill-chain strip: Initial Access → Execution → Persistence → Credential Access →
Lateral Movement → C2 → Exfiltration. "Ten alerts, three sources, one intrusion."

Hover the edge between **SIEM-0146** and **SYS-0161** in the graph. Read the tooltip: 42 minutes apart,
same asset FIN-WS-042, execution → credential-access is a curated progression. "That is the evidence
trail. Every edge carries the reason it exists."

Scroll to the BLUF panel. Read the BOTTOM LINE and the GAPS. "A commander gets the bottom line, the
confidence and its driver, the recommended actions for the next 30 minutes — and what we do not know."

## 3:00 — Switch to IBM Bob

Ask, in order:

1. **"What should I look at first this shift?"** — Bob calls `get_priority_queue` and relays the same
   order as the console.
2. **"Why are SIEM-0146 and SYS-0161 part of the same incident?"** — `explain_correlation`; Bob reads the
   three signals and their weights.
3. **"Give me the BLUF for INC-017."** — `get_bluf`; the SITE-ALPHA physical/cyber convergence brief.

## 4:10 — The closer

Ask Bob: **"The SIEM marked SIEM-0121 critical. Why is it ranked so low?"**

Bob calls `why_deprioritised` and answers: position 136 of 456, rule `KNOWN_SCANNER_RANGE`, 12 of 12
alerts from 10.50.1.10 inside the authorised scanner range, Monday 06:00 matching the standing
schedule, and what would change its mind — a different source, a different account, a technique
beyond scanning.

Say: "That single answer used ingestion, ATT&CK mapping, correlation, scoring, the suppression
evidence and the Bob integration in one breath. And it is the question a sceptical analyst actually
asks."

## 4:50 — Close

Show the evaluation table from the terminal: six intrusions in the top six, both look-alike benign
scenarios below every one of them, zero noise in any planted incident. "Measured against ground truth,
not asserted."

---

Record it more than once. The first take is always too slow.
