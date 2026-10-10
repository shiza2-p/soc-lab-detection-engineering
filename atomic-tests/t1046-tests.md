\# Atomic Red Team Tests Executed



\## T1046 — Network Service Discovery



\### Test #2 — "Port Scan Nmap"

\- GUID: 515942b0-a09f-4163-a7bb-22fefb6f185f

\- Default command chain: nmap -sS, telnet, nc

\- Issue: telnet hangs indefinitely waiting for interactive input in a

&#x20; non-interactive test run, causing the Atomic Red Team wrapper to

&#x20; time out regardless of scan scope.

\- Resolution: executed the test's exact command sequence manually,

&#x20; outside the wrapper, with `timeout` added to the interactive steps.

&#x20; Full details in docs/day6-atomic-red-team.md.

\- Detection result: did NOT trigger SID 1000003 (port scan rule) —

&#x20; single-port check generates only one SYN packet, well under the

&#x20; rule's 15-in-10-seconds threshold. Documented as a known, expected

&#x20; coverage gap, not a bug.



\### Test #12 — "Port Scan using nmap (Port range)"

\- GUID: 0d5a2b03-3a26-45e4-96ae-89485b4d1f97

\- Executed successfully through the Atomic Red Team wrapper (no

&#x20; telnet dependency, so no hang issue).

\- Command: nmap -Pn -sV -p 1-1000 against Metasploitable2 (10.10.20.10)

\- Detection result: triggered SID 1000003 a total of 342 times,

&#x20; confirmed via fast.log. Full details in docs/day6-atomic-red-team.md.



\## T1110.001 — Brute Force: Password Guessing



\- Checked the full Atomic Red Team library for this sub-technique.

&#x20; Only three tests exist: Azure AD credential brute force (cloud,

&#x20; not applicable), and two OS-specific local sudo brute-force tests

&#x20; (Debian, FreeBSD) — neither generates network traffic or touches

&#x20; SSH at all.

\- No applicable network-based SSH brute-force test exists in the

&#x20; Atomic Red Team library for this technique.

\- Substitute method used: Hydra, run directly against Metasploitable2

&#x20; (10.10.20.10:22), correctly cited against T1110.001 despite not

&#x20; originating from the Atomic Red Team test library itself.

\- Detection result: triggered SID 1000002 (SSH Brute Force rule), 6

&#x20; confirmed alerts. Full details in docs/day7-complete-atomic-coverage.md.



\## T1190 — Exploit Public-Facing Application



\- Checked directly: no atomics exist for this technique at all

&#x20; (`T1190.yaml` not present in the Atomic Red Team library) — a

&#x20; known, broader limitation of the framework, not specific to this

&#x20; lab.

\- SID 1000001 (SQLi rule) was tested via a manually crafted curl

&#x20; payload instead, correctly categorized under T1190 even without a

&#x20; library test to cite. Full details in docs/day3-suricata-first-detection.md

&#x20; and docs/day7-complete-atomic-coverage.md.

