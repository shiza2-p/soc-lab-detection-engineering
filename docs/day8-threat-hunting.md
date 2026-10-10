# Day 8: Threat Hunting - Hunt #1 and the sourcetype labeling fix

## Objective
Move beyond alert-driven detection into proactive threat hunting:
start from a hypothesis about what an attacker might have done, then
search existing Splunk data directly for evidence, rather than relying
solely on a signature firing.

---

## Sourcetype labeling issue found and fixed

Before the hunt itself could work, had to resolve a data-visibility
problem: searches using `sourcetype=suricata*` consistently returned
zero results, despite Suricata data genuinely flowing into Splunk
since Day 5.

**Diagnosis:**
```
| metadata type=sourcetypes index=*
```
This showed only two sourcetypes actually present: `fgt_log` (304
events, as expected) and an unexpected `json-2` with **20,954
events**. The Universal Forwarder configured on Day 5 was never given
an explicit `-sourcetype suricata` flag when the eve.json monitor was
added — Splunk auto-detected it as generic JSON and labeled it
`json-2` instead of anything Suricata-specific.

**Impact:** No data was lost — all 20,954 events were real and
present — but every search written against an assumed `suricata`
sourcetype silently failed, since that sourcetype simply didn't exist
in the index.

**Fix applied:**
```bash
sudo /opt/splunkforwarder/bin/splunk remove monitor /var/log/suricata/eve.json -auth admin:<password>
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/suricata/eve.json -sourcetype suricata -auth admin:<password>
sudo /opt/splunkforwarder/bin/splunk restart
```
This does not retroactively relabel the existing 20,954 `json-2`
events (they remain under that sourcetype permanently) but ensures all
new data going forward is cleanly tagged `sourcetype=suricata`.

**Lesson:** Always specify `-sourcetype` explicitly when adding a
forwarder monitor for a structured log format like Suricata's
eve.json, rather than relying on Splunk's auto-detection — the
auto-generated name is not obviously wrong at a glance and can cause
searches to silently return nothing rather than an explicit error,
making the root cause harder to spot.

---

## Hunt #1: "Did any burst of SSH activity match a brute-force pattern?"

**Hypothesis:** Rather than only trusting the dedicated SID 1000002
alert to catch brute-force behavior, hunt directly for the underlying
*pattern* — repeated SSH-related events from a single source in a
short window — to confirm the detection logic and demonstrate the
ability to find this behavior even without a purpose-built signature.

### Search
```
sourcetype=json-2 event_type=alert dest_ip=10.10.20.10 dest_port=22
| transaction src_ip maxspan=2m
| where eventcount > 4
```
(Used the actual `json-2` sourcetype present at hunt time, per the
labeling issue above; future hunts will use the corrected `suricata`
sourcetype.)

### Result
One transaction matched: source `10.10.10.10`, destination
`10.10.20.10:22`, five individual alert events grouped together,
spanning `2026-08-15T20:06:59` to `2026-08-15T20:08:58` — correctly
identifying the Hydra brute-force test run on Day 7 purely through
behavioral pattern matching (burst of same-source, same-destination
authentication-related alerts within a 2-minute window), independent
of the fact that SID 1000002 had already flagged this activity
directly.

### Why this matters
This is the actual point of threat hunting: the search doesn't rely on
signature ID 1000002 at all — it would surface a similarly-shaped burst
of activity even from a source or pattern that hadn't tripped an
existing rule. It validates the underlying detection logic from a
second, independent angle and demonstrates a repeatable hunting query
that generalizes beyond this one custom rule.

---

## Hunt #2: "Did reconnaissance activity lead to an actual accepted connection?"

**Hypothesis:** A real attacker doesn't scan purely for its own sake —
scanning is typically followed by an attempt to connect to whatever
was discovered open. This hunt cross-references Suricata's port-scan
alert data (SID 1000003) against FortiGate's independently-logged
accepted sessions, to check whether any of the 342 scan probes from
Day 6/7 correlated with an actual accepted connection during the same
window.

### Step 1: Establish the scan's time window
```
(sourcetype=suricata OR sourcetype="json-2") event_type=alert alert.signature_id=1000003
| stats earliest(_time) as scan_start latest(_time) as scan_end
```
Result: scan activity spanned epoch `1786816013.477796` to
`1786869768.874661` (covering the original Day 6 test plus later
re-verification runs sharing the same signature).

Note: initial attempts at this query used `spath` to extract the
nested `alert.signature_id` field, which returned zero results.
Confirmed via raw event inspection that Splunk's automatic JSON field
extraction already exposes nested fields via dot notation directly
(`alert.signature_id`) without needing `spath` at all — the manual
extraction attempt was unnecessary and actually broke the match.

### Step 2: Cross-reference FortiGate's accepted-session log for the same window
```
sourcetype=fgt_log dstip=10.10.20.10 action=accept
| where _time >= 1786816013 AND _time <= 1786869768
| stats count by service, proto
```

### Result
Exactly **one** accepted session in the entire scan window: a single
ICMP ping (`service=PING`, `proto=1`, `count=1`). No TCP-based service
connections were accepted during this period.

### Interpretation
This is a genuine, defensible negative finding: reconnaissance
activity (342 scan-related alerts) occurred, but the independently
sourced FortiGate accept log shows no corresponding follow-on TCP
connection during that window — only a single baseline connectivity
check (ping). In a real investigation this supports the conclusion
that scanning occurred without evidence of a successful or attempted
follow-on access during the observed window, which is itself a useful,
citable result rather than an inconclusive one. It also demonstrates
genuine two-source correlation (Suricata + FortiGate) rather than
relying on a single log source's view of events.

---

## Verification checkpoints reached
- Diagnosed and fixed a real data-labeling gap that was silently
  preventing all Suricata-sourced Splunk searches from returning
  results, despite the underlying data being present and correct the
  entire time.
- Successfully ran a hypothesis-driven hunt query independent of any
  specific alert signature, and correctly identified known brute-force
  activity purely through behavioral pattern matching.
- Corrected the forwarder configuration so all future Suricata data
  lands under a properly labeled `sourcetype=suricata`.
- Successfully correlated two independent log sources (Suricata alert
  data and FortiGate accepted-session data) to answer a real
  investigative question, producing a defensible negative finding
  rather than an inconclusive one.
