# Day 3: Suricata Sensor Deployment and First Live Detection

## Objective
Deploy Suricata as a passive sensor (promiscuous mode) on the Victim segment (VMnet3),
confirm it can see live traffic, write a custom detection rule, and
prove it fires correctly against real attack traffic generated from Kali.

---

## What I built

### 1. Suricata sensor VM
- Deployed a fresh Ubuntu Server 26.04 LTS ("Resolute Raccoon") VM in
  VMware Workstation — chose 26.04 over 22.04 since it's the current
  LTS release with a longer support runway (until April 2031).
- Specs: 1 vCPU, 1GB RAM, 20GB disk (plain partitioning, no LVM, no
  encryption — unnecessary complexity for a disposable lab sensor).
- During install: enabled OpenSSH server with password auth, skipped
  Ubuntu Pro, skipped optional server snaps.
- Named host `suricata-sensor`.

### 2. Network configuration
- Primary adapter attached to VMnet3 (Victim segment) — this is the
  interface that needs to observe attacker-to-victim traffic.
- Hit an issue immediately: this interface has no internet access by
  design (VMnet3 is an isolated host-only segment), which blocked
  `apt update`. Fixed by adding a second, temporary network adapter set
  to NAT (VMnet8), giving the VM a second interface purely for package
  installation. The VMnet3 interface itself intentionally has no IP
  address — it doesn't need one to passively monitor traffic.
- After adding the second adapter, interface names shifted: the VMnet3
  monitoring interface became `ens37`, the NAT interface became `ens38`.

### 3. Suricata installation
- Installed via apt: `sudo apt install -y suricata`
- Pulled the Emerging Threats Open ruleset: `sudo suricata-update`
  (loaded 52,309 community rules on top of custom rules later)
- Enabled the service to start on boot: `sudo systemctl enable suricata`
- Confirmed version: Suricata 8.0.3 RELEASE

### 4. Interface binding
- Put the monitoring interface into promiscuous mode so it reads every
  packet on the wire, not just traffic addressed to it:
  `sudo ip link set ens37 promisc on`
- Edited `/etc/suricata/suricata.yaml`, set the `af-packet` interface
  to `ens37`.
- Restarted Suricata, confirmed `active (running)` via systemctl.

### 5. Verified passive visibility (before writing any custom rules)
- Ran a plain ping test from Kali (10.10.10.10) to Metasploitable2
  (10.10.20.10).
- Filtered `eve.json` for the traffic and confirmed a matching
  `event_type: flow` entry with correct source/dest IPs and ICMP type —
  proof Suricata was passively observing traffic on the segment
  correctly before any detection logic was added.

### 6. Custom detection rule — SID 1000001
Location: `/var/lib/suricata/rules/local.rules` (this build's actual
`default-rule-path`, confirmed via
`grep -A2 "default-rule-path" suricata.yaml` — differs from the more
commonly documented `/etc/suricata/rules/`, which is only where
`suricata-update` stages its own downloaded rules by default).

```
alert http any any -> $HOME_NET any (msg:"CUSTOM SQLi - UNION SELECT Attempt Detected"; flow:to_server; content:"UNION"; nocase; content:"SELECT"; nocase; distance:0; classtype:web-application-attack; sid:1000001; rev:1;)
```

Rule logic: inspects all HTTP traffic heading toward the protected
network; flags any request containing "UNION" followed anywhere after
by "SELECT" (case-insensitive), classifying it as a web application
attack. This targets classic UNION-based SQL injection syntax.

- Validated syntax before deploying: `sudo suricata -T -c
  /etc/suricata/suricata.yaml -v` → confirmed "Configuration provided
  was successfully loaded" and "0 rules failed" out of 52,309 total.
- Restarted Suricata to load the new rule live.

### 7. Live detection test
From Kali, sent a crafted UNION-based SQLi payload at Metasploitable2's
DVWA endpoint using curl with proper URL encoding (`-G` +
`--data-urlencode`, needed after an initial attempt failed due to
unescaped quotes/spaces in the raw URL):

```bash
curl -G "http://10.10.20.10/dvwa/vulnerabilities/sqli/" \
  --data-urlencode "id=1' UNION SELECT user,password FROM users-- -" \
  --data-urlencode "Submit=Submit"
```

Checked `/var/log/suricata/fast.log` immediately after — the rule
fired:

```
08/15/2026-16:40:18.013006 [**] [1:1000001:1] CUSTOM SQLi - UNION 
SELECT Attempt Detected [**] [Classification: Web Application Attack] 
[Priority: 1] {TCP} 10.10.10.10:45910 -> 10.10.20.10:80
```

Confirms: signature ID 1000001, revision 1 (my custom rule) matched
correctly, correctly classified, correct source (Kali) and destination
(Metasploitable2, port 80) logged.

A second, unrelated alert also appeared immediately after from the
Emerging Threats community ruleset (`SURICATA HTTP Response excessive
header repetition`) — confirms the full 52k+ rule set is actively
inspecting traffic as well, not just the one custom rule.

---

## What broke, and how it was diagnosed and fixed

**Issue 1 — No internet access on the monitoring VM.**
Root cause: VMnet3 is intentionally isolated with no NAT/internet path,
since it's meant to be a passive monitoring segment. Fixed by adding a
second, temporary NAT-connected network adapter purely for package
installation.

**Issue 2 — Interface names changed after adding the second adapter.**
`ens33` from the initial single-NIC boot became `ens37` (VMnet3) and
`ens38` (NAT) once the second adapter was added — Linux renames/
reorders interfaces based on detected hardware at each boot when
adapters change. Confirmed the correct current names via `ip a` before
editing any config, rather than assuming the original name still
applied.

**Issue 3 — Custom rules file expected in a different directory than
initially assumed.**
Initially wrote `local.rules` to `/etc/suricata/rules/`, the commonly
documented path — but this build's actual `default-rule-path` (checked
directly in `suricata.yaml`) was `/var/lib/suricata/rules/`. Verified
directly from config rather than assuming a default, and placed the
rule file in the correct location.

**Issue 4 — curl "Malformed input to a URL" error.**
Raw SQLi payload contained unescaped spaces, quotes, and dashes that
curl's URL parser rejected outright. Fixed by using curl's `-G` flag
with `--data-urlencode`, which properly URL-encodes special characters
before constructing the request.

---

## Verification checkpoints reached
- Suricata service confirmed `active (running)`, zero rule load
  failures across 52,309 total rules (52,308 community + 1 custom).
- Passive traffic visibility confirmed via plain ICMP flow logging
  before any alerting logic was tested.
- Custom rule (SID 1000001) confirmed firing correctly on a real,
  crafted SQL injection payload sent from the dedicated lab Kali
  instance, with accurate classification, source, and destination
  logged to both `fast.log` and `eve.json`.

## Artifacts saved
- `suricata-rules/sqli-union-select.rules` — custom detection rule,
  SID 1000001.
