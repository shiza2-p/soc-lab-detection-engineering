# Day 7: Completing Structured Test Coverage Across All Three Detections

## Objective
Round out Atomic Red Team / MITRE ATT&CK-mapped testing so all three
custom Suricata rules have documented, technique-cited coverage — not
just the port scan rule from Day 6.

---

## T1110.001 (Brute Force: Password Guessing) — library gap found

Attempted to find a network-based SSH brute-force test under
T1110.001 to properly exercise SID 1000002 (SSH Brute Force rule)
through the Atomic Red Team framework, consistent with how T1046 was
tested on Day 6.

**Finding:** Atomic Red Team's public library does not currently
include a network-based SSH brute-force test under T1110.001. The only
tests available under this specific sub-technique are:
- Test #3 — Azure AD credential brute force (cloud-specific, not
  applicable to this lab)
- Test #5 — SUDO Brute Force (Debian) — a *local* privilege escalation
  test that creates a local user and brute-forces `sudo` password
  locally via a downloaded script; generates no network traffic at all
- Test #7 — SUDO Brute Force (FreeBSD) — same pattern as #5, different
  OS, also local-only

None of these touch port 22 or generate the kind of network-based
authentication traffic SID 1000002 is built to detect.

**Resolution:** Rather than force-fitting an inapplicable test just to
have an Atomic Red Team citation, used Hydra directly as the test tool
while still correctly citing the MITRE ATT&CK technique it maps to.
This reflects standard real-world detection engineering practice —
ATT&CK is a taxonomy of adversary behavior, not a requirement that
every technique must originate from one specific test library. Not
every technique has (or needs) a pre-built Atomic test to be
legitimately cited and validated against.

### Test execution
```bash
hydra -l msfadmin -P /usr/share/wordlists/rockyou.txt -t 4 ssh://10.10.20.10
```
Run for approximately 10-15 seconds (sufficient to exceed the rule's
5-attempts-in-60-seconds threshold), then stopped manually.

### Detection result
```bash
grep "1000002" /var/log/suricata/fast.log | grep "08/16" | wc -l
```
**6 confirmed alerts** — consistent with expectations: the rule fires
once the threshold (5 attempts/60s) is crossed, and continued firing
as Hydra kept generating attempts briefly past that point before being
stopped.

---

## Complete detection coverage summary

All three custom Suricata rules are correctly categorized under a
MITRE ATT&CK technique, with test evidence for each — but the
relationship to Atomic Red Team's library differs meaningfully across
all three, and that distinction is documented honestly below rather
than presented as uniform coverage:

| SID | Detection | Technique Cited | Atomic Red Team Library Status | Test Method | Result |
|-----|-----------|-----------------|--------------------------------|-------------|--------|
| 1000001 | SQL Injection (UNION SELECT) | T1190 - Exploit Public-Facing Application | No atomics exist for this technique at all (`T1190.yaml` not present in the library) | Manual crafted curl payload | Confirmed firing (Day 3) |
| 1000002 | SSH Brute Force | T1110.001 - Password Guessing | Atomics exist but none are applicable (Azure AD and local-sudo tests only; no network SSH test) | Hydra | 6 alerts confirmed |
| 1000003 | Port Scan | T1046 - Network Service Discovery | Applicable atomic test exists and was used directly | Atomic Red Team Test #12 (GUID 0d5a2b03-3a26-45e4-96ae-89485b4d1f97) | 342 alerts confirmed (Day 6) |

**Why this distinction matters:** T1046 represents genuine, direct use
of the Atomic Red Team framework as intended. T1110.001 represents a
case where the framework has tests, but none fit this specific
scenario (network-based SSH auth), so an equivalent manual test was
substituted with the technique still correctly cited. T1190 represents
a technique with *no* atomics at all — a known, broader limitation of
Atomic Red Team's library, not specific to this lab. Presenting all
three as equivalent "Atomic Red Team-tested" would have been
misleading; the table above reflects what was actually verified at
each level.

Also documented: a genuine coverage *gap* was found and recorded on
Day 6 — SID 1000003 does not trigger on single-port/low-volume
reconnaissance (Atomic Red Team T1046 Test #2), since its threshold is
tuned specifically for multi-port scanning behavior. This remains an
open, known limitation rather than something silently glossed over.

---

## Why this matters for the project as a whole

Every detection built in this lab now has a citable, MITRE
ATT&CK-mapped test behind it, with an honest accounting of where a
standard test-library approach worked cleanly (T1046) versus where it
didn't apply and a documented alternative was used instead (T1110.001).
This is a more complete and more credible picture than simply claiming
full Atomic Red Team coverage without qualification — it shows the
actual boundaries of the tooling as well as the lab's detections.

## Verification checkpoints reached
- Confirmed, via direct inspection of Atomic Red Team's test library,
  that no applicable network-based SSH brute-force test exists under
  T1110.001.
- Documented the gap and the reasoning for using an alternative test
  method while retaining accurate ATT&CK technique citation.
- Confirmed SID 1000002 fires correctly and proportionally to
  brute-force attempt volume.
- All three custom Suricata detections now have complete, documented,
  technique-cited test coverage.
