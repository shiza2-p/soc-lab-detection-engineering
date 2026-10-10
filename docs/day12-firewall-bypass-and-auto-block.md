# Day 12: Firewall Bypass, Enforceable Auto-Block, and Cross-Source Correlation

## Objective
Review the lab against its own claims and close the gaps: confirm that
attack traffic really crosses FortiGate, make the SOAR block actually
enforce, correlate firewall and IDS data in Splunk, and verify what
Atomic Red Team can and cannot cover.

---

## 1. Firewall bypass found and fixed

Cowrie's log showed the Kali test session with source `10.10.20.5`
(the Windows host's VMnet3 adapter) instead of `10.10.10.10`.
`ip route get 10.10.20.50` on Kali returned `via 192.168.75.2 dev eth1`:
Kali's second adapter (VMware NAT) was carrying the traffic around
FortiGate. Full detail and the routing fix are in
`day9-cowrie-honeypot.md`.

Verification after the fix: `tracepath -n 10.10.20.50` from Kali showed
`10.10.10.1` (FortiGate) as hop 1, and FortiGate's Forward Traffic log
recorded the sessions with source `10.10.10.10`.

---

## 2. Making the auto-block actually block

### What was wrong
The Shuffle playbook creates an address object on FortiGate
(`cowrie-block-<ip>`), but:
- the object's reference count was `0`, meaning no policy used it, and
- the only firewall policy was `Attacker-to-Victim` (accept all).

An address object on its own blocks nothing.

### Fix
1. Created a deny policy `Block-Cowrie-Blocklist`: `port2` to `port3`,
   destination `all`, service `ALL`, action deny, violation logging
   enabled, placed **above** `Attacker-to-Victim` (policies match top to
   bottom). For the test its source was the individual object
   `cowrie-block-10.10.10.10`.
2. Afterwards, created an address group `cowrie-blocklist` and changed
   the policy's source to the group, so further blocked addresses can be
   added to the group without editing the policy.

### Test
| Step | Result |
|---|---|
| Before: `ping -c 4 10.10.20.50` from Kali | 4 of 4 replies, 0% loss, `ttl=63` |
| Shuffle run, input `{"src_ip":"10.10.10.10"}` | GET returned 404, POST returned 200 (object created) |
| Deny policy referencing `cowrie-block-10.10.10.10` in place (manual step) | n/a |
| After: same ping | 4 sent, 0 received, 100% loss |
| FortiGate Forward Traffic, filtered on the honeypot | four deny entries from `10.10.10.10` |
| Shuffle run again, same input | GET returned 200, POST **skipped** ("Minimum of one branch's conditions must be correct to continue. Total: 0 of 1") |

The second run confirms the playbook is idempotent: no duplicate object
and no error.

After the test, the policy source was switched to the `cowrie-blocklist`
group and Kali's object was removed from the group, so lab traffic
could resume.

### Limitations
- The run was triggered manually with a test payload, not by a live
  Cowrie event.
- The playbook only creates the address object. Referencing it in the
  deny policy (directly, or through the address group) is manual; it
  needs a third workflow step calling the FortiGate API.

---

## 3. Cross-source correlation in Splunk

Search saved as `splunk-searches/correlate-firewall-ids-by-attacker.spl`.
It combines FortiGate syslog (`fgt_log`) and Suricata alerts by attacker
and victim address.

Result over all time:

| Source | Destination | Firewall events | IDS alerts | Notes |
|---|---|---|---|---|
| `10.10.10.10` | `10.10.20.10` | 126 | 1,398 | all three custom signatures; policy `Attacker-to-Victim` |
| `10.10.10.10` | `10.10.20.50` | 29 | 0 | includes `deny` under `Block-Cowrie-Blocklist` |

The counts are cumulative across all testing. The join is on address,
not time, so it shows the same attacker seen by both sources, not
event ordering.

---

## 4. Atomic Red Team coverage check

```powershell
Import-Module /home/kali/AtomicRedTeam/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 -Force
Invoke-AtomicTest T1190 -ShowDetailsBrief -PathToAtomicsFolder /home/kali/AtomicRedTeam/atomics
Invoke-AtomicTest T1110.001 -ShowDetailsBrief -PathToAtomicsFolder /home/kali/AtomicRedTeam/atomics
```

- **T1190** (public-facing application exploit): `T1190.yaml does not
  exist`. There is no Atomic test, so the SQLi rule was validated with a
  manual payload.
- **T1110.001** (password guessing): the library lists an Azure AD test
  and three local `sudo` brute-force tests (Debian, Red Hat, FreeBSD).
  None is a network SSH brute force, so the SSH rule was validated with
  Hydra, not Atomic Red Team.

---

## 5. Suricata rules, revision 2, and re-test

Revision 1 had three weaknesses: raw payload matching for SQLi, alerts on
every packet after the threshold (1,079 alerts from one run), and
messages that overstated what was measured. Revision 2 (files in
`suricata-rules/`):
- SQLi matches the decoded HTTP URI (SID 1000001) and, in a new rule,
  the request body (SID 1000004).
- SSH and scan rules use `threshold:type both`, so they alert once per
  interval, and their messages now say "connection attempts" and
  "SYN scan".

Validated with `suricata -T` (4 rules loaded, 0 failed) before the live
swap, then tested from Kali through FortiGate:

| Test | Result |
|---|---|
| `nmap -sS -p 1-1000` against the victim | 1 alert, SID 1000003 rev 2 |
| 10 connections to port 22 | 1 alert, SID 1000002 rev 2 |
| URL-encoded `%55NION ALL %53ELECT` in the URI | alert, SID 1000001 rev 2 |
| `UNION SELECT` in a POST body | alert, SID 1000004 rev 1 |
| Benign traffic (2 HTTP requests, 3 pings, nmap of 3 ports) | no new alerts (count unchanged) |

Notes:
- The SSH test used a connection burst. Hydra on current Kali cannot
  negotiate Metasploitable's legacy SSH MAC algorithms, and the rule
  counts connections, not password guesses.
- The benign-traffic check was small and from one source; it is not a
  false-positive study.
- Distinct-port counting needs the Splunk search
  `splunk-searches/distinct-ports-scan-detection.spl`, which has not been
  validated yet.

---

## Lessons
- A control that is configured but not referenced does nothing:
  verify enforcement end to end, not just object creation.
- Dual-homed lab VMs can silently route around the control being
  tested. Check the path (`ip route get`, `tracepath`) before trusting
  the logs.
- Routes added at the command line disappear on reboot; make them
  persistent before relying on them.
