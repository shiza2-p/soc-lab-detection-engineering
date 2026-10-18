# Day 4: SSH Brute Force and Port Scan Detection Rules

> **Update:** this page documents the original (revision 1) SSH and port-scan rules. Revision 2 changed both to alert once per interval and renamed their messages (SID 1000002 and SID 1000003, rev 2). The current rules are in `suricata-rules/`, and the re-test is in [Day 12](day12-firewall-bypass-and-auto-block.md).

## Objective
Extend Suricata's custom detection coverage beyond the initial SQLi rule
with two more attack patterns: SSH brute force and network port
scanning. Both use threshold-based detection (pattern over time) rather
than single-packet content matching, which is a different detection
technique than the SQLi rule used.

---

## Rules added

### SID 1000002 — SSH Brute Force
```
alert tcp any any -> $HOME_NET 22 (msg:"CUSTOM SSH Brute Force - Repeated Connection Attempts"; flow:to_server; flags:S; threshold:type threshold, track by_src, count 5, seconds 60; classtype:attempted-recon; sid:1000002; rev:1;)
```

Logic: watches TCP SYN packets (new connection attempts, not full
sessions) directed at port 22. Uses Suricata's `threshold` keyword to
only alert once a single source IP generates 5 or more connection
attempts within a 60-second window — this is what makes it a
brute-force detector rather than a single-attempt alert. SSH itself is
encrypted, so this rule can't inspect login content; it detects the
*behavioral pattern* of repeated rapid connections instead.

### SID 1000003 — Port Scan Detection
```
alert tcp any any -> $HOME_NET any (msg:"CUSTOM Port Scan - Multiple Ports Contacted by Single Source"; flags:S; threshold:type threshold, track by_src, count 15, seconds 10; classtype:network-scan; sid:1000003; rev:1;)
```

Logic: same SYN-based approach, but with no destination port
restriction (a scan by definition touches many different ports) and a
tighter threshold — 15 connection attempts within 10 seconds from one
source. Tuned to match typical Nmap default scan timing.

---

## Testing

### SSH brute force test
Initial attempt used Hydra:
```
hydra -l msfadmin -P /usr/share/wordlists/rockyou.txt -t 4 ssh://10.10.20.10
```
This failed with a key exchange/MAC algorithm mismatch — Metasploitable2
runs legacy SSH algorithms (circa 2010) that modern Kali's SSH client
has deprecated for security reasons. This is a known, common
compatibility issue when pairing current Kali against Metasploitable2,
not a lab misconfiguration.

Fixed by editing `/etc/ssh/ssh_config` to re-permit legacy MACs and key
exchange algorithms for this lab environment:
```
Host *
    MACs +hmac-md5,hmac-sha1,hmac-ripemd160
    KexAlgorithms +diffie-hellman-group1-sha1
```
After this, Hydra connected and began generating real login attempts,
which was enough to cross the rule's threshold.

### Port scan test
```
nmap -sS -T4 10.10.20.10
```
Generated SYN packets across Metasploitable2's many open ports well in
excess of the 15-in-10-seconds threshold.

---

## Bug found and fixed: stale rule persisted after edit

**Symptom:** After correcting a mistake in the SID 1000002 rule
definition, fast.log continued showing SSH Brute Force alerts firing
against destination ports other than 22 (e.g., 4006, 8000, 9944) —
despite the rule explicitly restricting to port 22 only. This happened
across two separate test runs, including one after the file had
supposedly already been corrected.

**Diagnosis process:**
1. Compared raw fast.log timestamps against when the correction was
   made — alerts on incorrect ports continued appearing even after the
   edit.
2. Verified the actual rule file contents directly with `cat`, rather
   than assuming the edit had been saved correctly.
3. Checked `systemctl status suricata` for the service's "Active
   since" timestamp — confirmed Suricata was still running on rules
   loaded before the correction. Editing `local.rules` on disk does
   not change what the running Suricata process is using in memory
   until it's explicitly restarted or reloaded.

**Fix:** `sudo systemctl restart suricata` — forced a full reload of
the corrected rule set.

**Verification:** Cleared and re-triggered both tests. Re-checked
fast.log — every SID 1000002 alert now correctly shows destination
port 22 exclusively; SID 1000003 correctly continues to show varied
destination ports, as expected for a scan detector.

**Lesson:** A rule file edit is not live until the service is
restarted. This is an easy mistake to repeat once more rule files are
in play (Splunk searches, SOAR playbooks) — worth keeping in mind for
future config changes generally, not just Suricata.

---

## Verification checkpoints reached
- Three custom rules now active and confirmed correctly firing on
  distinct attack types: SQLi (1000001), SSH brute force (1000002),
  port scan (1000003).
- Confirmed via clean fast.log output that SID 1000002 correctly
  scopes to port 22 only, and SID 1000003 correctly spans multiple
  ports — no cross-contamination between rule logic.
- Diagnosed and fixed a real stale-config bug independently, using
  timestamp comparison and direct file inspection rather than assuming
  the fix had worked.

## Artifacts saved
- `suricata-rules/ssh-bruteforce-and-portscan.rules` — SID 1000002 and
  1000003, corrected and verified.
