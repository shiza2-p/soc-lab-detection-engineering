# SOC Lab: Detection Engineering and Purple Team Laboratory

A self-built detection-to-response lab: a FortiGate firewall, a Suricata
IDS with custom rules, Splunk as the SIEM, a Cowrie honeypot, and a
Shuffle SOAR playbook that creates firewall blocks through the FortiGate
REST API. Attacks are generated from Kali, including MITRE ATT&CK-mapped
Atomic Red Team tests, and each detection is checked in Splunk.

Every claim below is backed by a doc in this repo. Where something is
partial or manual, it says so (see **Limitations**).

## Architecture

| Segment | Network | Hosts |
|---|---|---|
| Attacker | `10.10.10.0/24` (FortiGate `port2`) | Kali (`10.10.10.10`) |
| Victim | `10.10.20.0/24` (FortiGate `port3`) | Metasploitable2 (`10.10.20.10`), Cowrie (`10.10.20.50`), Suricata sensor |
| Management / telemetry | `10.10.30.0/24` | Splunk (`10.10.30.10`), Shuffle |
| WAN / NAT | `port1`, VMware NAT | package installs, admin access |

FortiGate-VM 7.4.12 (evaluation license) routes attacker-to-victim
traffic under one logging policy. It has no inspection profile enabled,
so Suricata does the detecting; FortiGate provides routing, policy
enforcement and traffic logs. Kali and the Cowrie VM also have NAT
adapters, which created a side path around the firewall that was found
and fixed (see Day 9 and Day 12).

## What was built and verified

- **Custom Suricata rules** (revision 2) for UNION-based SQL injection
  (URI and request body), SSH connection bursts and high-rate SYN
  scanning, all re-tested on live traffic through the firewall
  (`suricata-rules/`).
- **Splunk** ingesting FortiGate syslog, Suricata `eve.json` and Cowrie
  logs, with a cross-source search joining firewall and IDS events by
  attacker and victim address (`splunk-searches/`).
- **Atomic Red Team** T1046 (network service discovery) executed, with
  the library gaps for T1190 and T1110.001 documented.
- **Cowrie honeypot** capturing SSH sessions and every command typed,
  with source address preserved through the firewall after the routing
  fix.
- **Shuffle playbook**: webhook, existence check against the FortiGate
  API, conditional create. Verified on both paths: first run creates the
  address object, second run skips it.
- **Blocking verified**: once a FortiGate deny policy referenced the
  object the playbook created, pings from Kali to the honeypot went from
  0% to 100% packet loss, with deny entries in the firewall log. The
  policy now references an address group, so new objects can be added
  without editing it.
- **Detection latency** (flow start to Suricata alert) calculated per rule.

## Detection coverage

| Rule (SID) | Technique | Test used | Atomic Red Team |
|---|---|---|---|
| 1000001 / 1000004 SQLi UNION SELECT (URI / body) | T1190 Exploit Public-Facing Application | manual `curl` payload | no test exists for T1190 |
| 1000002 SSH connection burst | T1110.001 Password Guessing | Hydra | tests exist but none is a network SSH test |
| 1000003 High-rate SYN scan | T1046 Network Service Discovery | Atomic T1046 and Nmap | yes |

## Detection latency

Measured as Suricata's alert time minus the flow start time. This is
sensor alert latency, not end-to-end MTTD: it excludes analyst response.
Threshold rules cannot fire before their count is reached, so the
figures partly reflect rule design. The SQLi figure is a single alert.
These figures were measured with the revision 1 rules, before the
alert-volume tuning in Day 12.

| SID | Average | Alerts |
|---|---|---|
| 1000001 | 0.089 s | 1 |
| 1000002 | 0.007 s | 1,079 |
| 1000003 | 0.511 s | 674 |

## Limitations

- The Shuffle playbook was triggered manually with a test payload, not
  by a live Cowrie event. The playbook only creates the address object;
  referencing it in the deny policy or address group is a manual step.
- The SQLi rules are keyword-based on decoded HTTP buffers; heavier
  obfuscation or non-HTTP transports can still evade them.
- The scan and brute-force rules count TCP SYN packets, not distinct
  ports or authentication attempts, and were checked against only a
  small amount of benign traffic.
- Revision 1 produced over a thousand alerts from one run; revision 2
  alerts once per interval, but has not been tuned on realistic traffic.
- The correlation search joins on source and destination address and
  does not prove event ordering.
- Linux routes added for the firewall path are not persistent, and
  Cowrie does not start by itself after a reboot.
- The REST API account has a broad admin profile; a scoped profile would
  be better practice.
- FortiGate runs on an evaluation license with no signature updates.

## Repository layout

- `docs/`: day-by-day build and debugging notes (Day 1 to Day 12)
- `suricata-rules/`: custom detection rules
- `splunk-searches/`: reusable SPL (MTTD, threat hunts, correlation)
- `atomic-tests/`: Atomic Red Team test reference

## Notes

All addresses and credentials in this repo are lab-only; passwords are
shown as `<password>` placeholders.
