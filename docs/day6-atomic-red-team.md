# Day 6: Atomic Red Team - Structured Adversary Emulation

## Objective
Replace ad-hoc manual attack tools with Atomic Red Team's structured,
MITRE ATT&CK-mapped test framework, and use it to validate (and find
the real boundaries of) the Suricata detections built in prior days.

---

## Setup

### Installing Atomic Red Team on Kali
Atomic Red Team's primary tooling (`Invoke-AtomicRedTeam`) is
PowerShell-based, including on Linux, via PowerShell Core.

```bash
sudo apt install -y powershell
pwsh
```
Inside PowerShell:
```powershell
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
```

### Networking bug found and fixed before install could even reach the internet
Kali's `apt update` failed with "Network is unreachable," despite a NAT
adapter being added for internet access. `ip route` revealed the same
class of bug already fixed once before on Splunk-SIEM: a static
default route on the VMnet2 (lab) interface had a lower/preferred
metric (100) than the NAT interface's DHCP-assigned default route
(101), so Linux was routing all traffic — including internet-bound —
through the isolated lab segment with no real path out. Fixed by
explicitly marking the VMnet2 connection as never eligible to be a
default route:
```bash
sudo nmcli con mod "Wired connection 1" ipv4.never-default yes
sudo nmcli con up "Wired connection 1"
```
Confirmed only one default route remained afterward, via the NAT
interface, and internet access worked immediately.

**Lesson repeated:** any interface on an isolated host-only segment
should be explicitly excluded from default-route eligibility at setup
time, not left to metric ordering — this is now the second time this
exact bug appeared (Splunk-SIEM, then Kali), so it's worth checking
proactively on any future VM added to this lab.

---

## Test 1: T1046 (Network Service Discovery) — Test #2, "Port Scan Nmap"

**GUID:** 515942b0-a09f-4163-a7bb-22fefb6f185f

### Execution problems encountered
- Running interactively inside `pwsh` caused a PSReadLine terminal
  crash (a known PowerShell-on-Linux terminal rendering bug, unrelated
  to the lab itself). Worked around by writing commands to a `.ps1`
  script file and executing that non-interactively
  (`pwsh /path/to/script.ps1`) instead of typing live in the terminal.
- The test's default target (`192.168.1.0/24`) doesn't exist in this
  lab; overrode with `-InputArgs` to target the real Victim segment.
- First real run against the full `/24` network timed out after 120+
  seconds. Diagnosed by running the equivalent raw `nmap` command
  directly: confirmed nmap itself was fine (successfully found
  Metasploitable2's port 80 open among ~254 scanned addresses), but a
  full-subnet scan legitimately takes longer than the wrapper's
  default timeout when most addresses report as "filtered" rather than
  cleanly closed or open.
- Narrowed the target to a single host (`/32`) to rule out scan size as
  the cause — still timed out. Root cause turned out to be different:
  this specific atomic test's command chain includes `telnet`, which
  connects successfully and then hangs indefinitely waiting for
  interactive keyboard input, since there is no interactive session in
  a scripted run. This happened regardless of scan scope.
- Along the way, discovered multiple earlier attempts had left orphaned
  background processes (`sh -c sudo nmap ...`) still running/stopped
  from previous timeouts, competing for resources. Cleared with
  `sudo pkill -9` against nmap/telnet/nc before retrying.

### Resolution
Ran the test's exact command sequence manually, outside the Atomic Red
Team wrapper, adding `timeout` to the interactive steps so they
couldn't hang:
```bash
sudo nmap -sS 10.10.20.10 -p 80
echo "" | timeout 3 telnet 10.10.20.10 80
timeout 3 nc -nv 10.10.20.10 80
```
Completed cleanly: nmap confirmed port 80 open, telnet connected and
was force-closed after 3 seconds, netcat confirmed the open port
independently.

### Detection result: no alert fired (expected, and instructive)
Checked SID 1000003 (port scan rule) in fast.log — no new entries
matching this test's timestamp. Verified this was not a bug: the rule
requires 15 SYN packets within 10 seconds from one source
(`threshold:type threshold, track by_src, count 15, seconds 10`). A
single-host, single-port check generates exactly one SYN packet, which
never comes close to that threshold.

**Finding, documented honestly:** SID 1000003 is tuned for genuine
multi-port/multi-host scanning behavior and does not catch low-volume,
targeted single-port reconnaissance. This is a real, known coverage
gap rather than a rule malfunction — single-port probes are a
meaningfully different attacker behavior pattern than a scan, and this
rule was never built to catch them. Worth addressing with a
lower-threshold or content-based rule in a future iteration if
single-port recon detection becomes a priority.

---

## Test 2: T1046 — Test #12, "Port Scan using nmap (Port range)"

**GUID:** 0d5a2b03-3a26-45e4-96ae-89485b4d1f97

Chosen specifically because it uses only `nmap`, with no `telnet`
step — avoiding the interactive-hang problem from Test #2 entirely and
allowing a clean run through the actual Atomic Red Team wrapper rather
than a manual bypass.

### Execution
```powershell
Invoke-AtomicTest T1046 -TestNumbers 12 -InputArgs @{"port_range"="1-1000"; "host"="10.10.20.10"} -TimeoutSeconds 90
```
Targeted Metasploitable2 across ports 1-1000 with service-version
detection (`-sV`).

The wrapper again reported "Process Timed out after 90 seconds" — but
this time the nmap scan itself had already completed successfully
underneath ("Starting Nmap... Exit code: / Done executing test" all
printed). The timeout in this case was the wrapper's output-capture
step timing out while waiting to format nmap's full verbose results,
not a failure of the scan itself — `-sV` is slow, since it actively
probes each open port to identify the running service rather than
just checking if it's open.

### Detection result: confirmed working, at real volume
```bash
grep "1000003" /var/log/suricata/fast.log | grep "08/16" | wc -l
```
**342 SID 1000003 alerts** generated by this single test run, all
correctly timestamped to match the test's execution window and
correctly attributing source (Kali) and destination (Metasploitable2).

---

## Summary — what this day actually demonstrates

Running the exact same technique (T1046, port scanning) two different
ways against the same rule produced two different, both-correct
outcomes: a low-volume single-port check that legitimately shouldn't
trigger a scan-detection rule, and a genuine multi-port scan that
triggered it 342 times. Documenting both — not just the clean success —
is the more accurate and more useful record: it shows the detection
logic's actual behavior and boundaries, not just a single passing
test.

## Verification checkpoints reached
- Atomic Red Team fully installed and operational on Kali, with a
  reusable script-file execution pattern to avoid the PSReadLine
  terminal crash going forward.
- Two structured, MITRE ATT&CK-cited tests executed (T1046 Test #2 and
  Test #12), with GUIDs recorded for exact reproducibility.
- Confirmed and documented a real detection coverage gap
  (single-port recon vs. SID 1000003's volume threshold).
- Confirmed strong, high-volume detection accuracy against genuine
  multi-port scanning (342 correctly attributed alerts from one test).
- Identified and fixed a second instance of the same default-route
  metric bug first found on Splunk-SIEM, now flagged as a standard
  check for any future VM added to the lab.
