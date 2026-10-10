# Day 11: MTTD Metrics — Closing the Advanced Roadmap

## Objective
Calculate Mean Time to Detect (MTTD) for each of the lab's three
custom Suricata detections, using real data already captured across
prior sessions — the final layer of the advanced project roadmap.

---

## Approach

MTTD is measured here as the gap between a flow's actual start time
(`flow.start`, captured by Suricata at the packet level) and the
moment Suricata generated the corresponding alert (`_time`). This
measures true detection latency within the IDS itself — a legitimate,
citable MTTD metric, distinct from (and narrower than) an
end-to-end "attack launched to analyst notified" metric, which would
require additional tooling (e.g., alerting/paging integration) outside
this lab's scope.

### Base query
```
(sourcetype=suricata OR sourcetype="json-2") event_type=alert
| eval flow_start_epoch=strptime('flow.start', "%Y-%m-%dT%H:%M:%S.%6N%z")
| eval detect_latency_sec = _time - flow_start_epoch
| stats avg(detect_latency_sec) as mttd_sec, min(detect_latency_sec) as fastest_sec, max(detect_latency_sec) as slowest_sec, count as total_alerts by alert.signature, alert.signature_id
| eval mttd_sec=round(mttd_sec,3), fastest_sec=round(fastest_sec,3), slowest_sec=round(slowest_sec,3)
```

Both sourcetypes (`suricata` and the legacy `json-2` label from before
the Day 8 sourcetype fix) were included via `OR` to capture the full
historical dataset rather than only data logged after the labeling fix.

---

## Data quality check: one signature didn't belong

Initial results included a fourth signature, SID `2221036`, with only
a single alert. Rather than including it uncritically, checked it
directly:
```
sourcetype=suricata OR sourcetype="json-2"
event_type=alert alert.signature_id=2221036
| head 1
```
The raw event showed traffic flowing from Metasploitable2
(`src_ip: 10.10.20.10`) to Kali (`dest_ip: 10.10.10.10`) on the
response side of an HTTP transaction — this matches the incidental
"SURICATA HTTP Response excessive header repetition" alert first
observed back on Day 3, fired by Suricata's built-in Emerging Threats
Open ruleset rather than one of this lab's custom rules. SID
`2221036` falls well outside the `100000x` range deliberately chosen
for custom rules on Day 3 specifically to avoid collision with the
built-in ruleset — confirming this was a legitimate signal to exclude,
not a data error.

**Final query, filtered to the three intentional custom detections:**
```
(sourcetype=suricata OR sourcetype="json-2") event_type=alert
(alert.signature_id=1000001 OR alert.signature_id=1000002 OR alert.signature_id=1000003)
| eval flow_start_epoch=strptime('flow.start', "%Y-%m-%dT%H:%M:%S.%6N%z")
| eval detect_latency_sec = _time - flow_start_epoch
| stats avg(detect_latency_sec) as mttd_sec, min(detect_latency_sec) as fastest_sec, max(detect_latency_sec) as slowest_sec, count as total_alerts by alert.signature, alert.signature_id
| eval mttd_sec=round(mttd_sec,3), fastest_sec=round(fastest_sec,3), slowest_sec=round(slowest_sec,3)
```

---

## Results

| Rule | SID | MTTD (avg) | Fastest | Slowest | Alert Count |
|---|---|---|---|---|---|
| CUSTOM SQLi - UNION SELECT Attempt Detected | 1000001 | 0.089s | 0.089s | 0.089s | 1 |
| CUSTOM SSH Brute Force - Repeated Connection Attempts | 1000002 | 0.007s | 0.000s | 2.045s | 1,079 |
| CUSTOM Port Scan - Multiple Ports Contacted by Single Source | 1000003 | 0.511s | 0.000s | 2.087s | 674 |

### Interpretation, with honest caveats

- **SID 1000001 (SQLi)** has only a single alert on record — its
  min/max/avg are identical by mathematical necessity with n=1, and
  this figure should not be presented as a statistically meaningful
  average. It reflects one confirmed detection event (the Day 3 test),
  not a measured trend. Running additional SQLi test traffic would be
  needed to produce a genuine average.
- **SID 1000002 (SSH Brute Force)** has the largest sample (1,079
  alerts) and the fastest average detection latency (7ms) — consistent
  with it being a simple, low-overhead signature match on TCP SYN
  packets to port 22, requiring no deep packet inspection.
- **SID 1000003 (Port Scan)** shows a higher average latency (0.511s)
  than SID 1000002 despite a similarly large sample (674 alerts) —
  plausibly explained by its threshold-based logic (15 attempts within
  10 seconds) inherently requiring more elapsed time to accumulate
  enough matching packets before firing, compared to 1000002's
  simpler 5-in-60-second threshold.
- All three rules show sub-second average detection latency, which is
  expected and appropriate for signature-based network IDS detection —
  this is a fundamentally different (and much faster) measurement than
  a full SOC "time to detect and respond" metric, which would also
  include analyst triage time, alert routing, and any manual
  investigation steps not modeled in this lab.

---

## Verification checkpoints reached
- Built a working MTTD calculation directly from real Suricata flow
  and alert timestamps, without needing additional tooling.
- Caught and excluded a data-quality issue (an incidental built-in ET
  rule alert) that would have misrepresented the custom-rule metrics
  if included uncritically, verified by inspecting the raw event
  rather than assuming based on signature ID pattern alone.
- Produced a final, correctly-labeled, three-rule MTTD table suitable
  for direct inclusion in the project's public documentation and
  LinkedIn material.

---

## Advanced roadmap: complete

This closes the sixth and final layer of the original advanced project
scope. Full layer status:

| Layer | Status |
|---|---|
| Core Lab Foundation | Complete |
| Detection-as-Code (Git) | Complete |
| Adversary Emulation (Atomic Red Team) | Complete |
| Threat Hunting | Complete (2 documented hunts) |
| Deception (Cowrie Honeypot) | Complete |
| SOAR Automated Response | Complete |
| MTTD Metrics | Complete |
