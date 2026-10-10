# Day 5: Splunk Deployment, Victim Segment Completion, and Full Log Ingestion

## Objective
Add OWASP Broken Web Apps as a second victim machine, deploy Splunk as
the SIEM, and get both FortiGate and Suricata forwarding real log data
into it — completing the Core Lab Foundation layer end to end.

---

## Part 1: OWASP Broken Web Apps deployment

- Attached the existing OWASP BWA VM to VMnet3 (Victim segment),
  alongside Metasploitable2.
- Logged in via console (root/owaspbwa), declined the VMware Tools
  update prompt (unnecessary for this old, intentionally vulnerable
  appliance and not worth risking stability for).
- Confirmed the VM uses legacy `ifconfig`-based networking, no DHCP on
  VMnet3 as expected. Set a permanent static IP via
  `/etc/network/interfaces`:
  ```
  auto eth0
  iface eth0 inet static
      address 10.10.20.20
      netmask 255.255.255.0
      gateway 10.10.20.1
  ```
- Verified end-to-end: ping from Kali (10.10.10.10) to OWASP BWA
  (10.10.20.20) succeeded with 0% packet loss. Confirmed the same
  "Attacker-to-Victim" FortiGate policy handled it correctly with no
  changes needed, since the policy was originally scoped to
  `srcaddr all / dstaddr all` rather than specific IPs — validating
  that early design decision.
- Confirmed the traffic was correctly logged in FortiGate's Forward
  Traffic view once the log table's time window was widened (initial
  confusion was just an aged-out 5-minute default view, not a real
  routing problem).

---

## Part 2: Splunk-SIEM deployment

### VM build
- Ubuntu Server 26.04 LTS, 2 vCPU, 2-3GB RAM, 40GB disk.
- Network adapter on VMnet4 (Management segment), static IP
  `10.10.30.10/24` via netplan.
- Hit the same isolated-segment problem as Suricata: VMnet4 has no
  internet path by design, so a temporary second NAT adapter was added
  for package installation and the Splunk download.

### Netplan default-route bug (found and fixed)
Initial static netplan config included a `routes:` block pointing
VMnet4's gateway (10.10.30.1, the Windows host) as the *default* route.
Since this static route had a lower (better) metric than the NAT
adapter's DHCP-assigned default route, Linux preferred the dead-end
VMnet4 path for all outbound traffic, including internet-bound
requests — causing every `apt` and `wget` call to fail with "Network
is unreachable," misleadingly appearing to be an IPv6 problem at
first glance. Fixed by removing the `routes:` block from the VMnet4
interface entirely; a host-only segment should never claim to be a
default gateway.

### Splunk Enterprise installation — extended troubleshooting

This was the longest single debugging effort of the whole build so
far. Documenting the actual sequence in full, since each dead end
taught something and the final fix isn't the obvious first guess.

**Symptom:** After installing Splunk Enterprise via `.deb` package and
running `splunk start --accept-license --answer-yes --no-prompt
--run-as-root`, the web UI consistently showed "No users exist. Please
set up a user," and `/opt/splunk/etc/passwd` never got created,
regardless of login attempts.

**Attempt 1 — user-seed.conf:** Created
`/opt/splunk/etc/system/local/user-seed.conf` with `USERNAME=admin` /
`PASSWORD=...` and restarted. Did not work. Assumed Splunk had already
considered itself "initialized" from an earlier attempt and was
permanently skipping seed application.

**Attempt 2 — ownership mismatch theory:** Startup logs showed a flood
of "Permission denied" errors across `/opt/splunk/etc/apps/*` and
`/opt/splunk/var/run/*`. Traced this to inconsistently mixing `sudo`
(root) and `sudo -u splunk` across different start attempts, leaving
files owned by different users. Fixed with
`sudo chown -R splunk:splunk /opt/splunk` and committed to running
every subsequent command consistently as the `splunk` user. This
cleared the permission errors but did not fix the missing account.

**Attempt 3 — full clean reinstall:** Removed `/opt/splunk` entirely
and reinstalled from the `.deb`, to rule out any lingering corrupted
state. Recreated the seed file immediately as the `splunk` user this
time (avoiding any future ownership drift) before the first start.
Still no `passwd` file, still no admin account.

**Root cause, found via `find`:** Ran
`find /opt/splunk -iname "*seed*"` and discovered a second, leftover
copy of `user-seed.conf` at
`/opt/splunk/var/run/splunk/confsnapshot/baseline_local/system/local/user-seed.conf`
— Splunk's internal config-snapshot/baseline mechanism had captured an
earlier (broken) seed attempt and was silently treating that cached
baseline as authoritative, overriding the real seed file every time,
regardless of how many times the real file was corrected or the whole
install was wiped and rebuilt (the confsnapshot directory itself
apparently isn't always cleared by a plain `rm -rf` if timing/caching
allows it to regenerate from stale data).

**Interactive start attempt:** Tried starting without `--answer-yes`/
`--no-prompt` to force Splunk's normal first-run interactive prompt
for username/password. It did not prompt at all — further confirming
Splunk believed a user already existed somewhere in its state, even
though the visible `passwd` file said otherwise.

**`resetpw` attempt:** Tried Splunk's dedicated password-reset command
(`splunk resetpw`), expecting it to output a temporary password
directly. This command does not exist in this Splunk version/edition
("Did you mean the 'set' command?") — a dead end specific to this
release, not a mistake in the approach itself.

**Actual fix — `--seed-passwd` flag:** After a final full wipe and
reinstall (with the leftover confsnapshot seed file also deleted this
time), started Splunk with the password supplied directly as a start
argument rather than via any file:
```
sudo -u splunk /opt/splunk/bin/splunk start --accept-license \
  --answer-yes --no-prompt --seed-passwd <password>
```
This bypasses the file-based seed mechanism entirely — the password is
passed straight into the startup command itself. This worked
immediately; `passwd` was created correctly and the web UI login
succeeded on the first try afterward.

**Lesson:** For scripted/non-interactive Splunk installs, `--seed-passwd`
on the start command is more reliable than `user-seed.conf`, since the
file-based method can be silently overridden by Splunk's own internal
config-snapshot caching in ways that are difficult to detect from the
outside (the seed file looks correct, permissions look correct, and
there's still no visible error — it just quietly doesn't apply).

---

## Part 3: Log ingestion — Suricata to Splunk

- Installed a Splunk Universal Forwarder on Suricata-Sensor (separate
  lightweight package from full Splunk Enterprise).
- Same `--seed-passwd` approach used to avoid repeating the seed-file
  issue.
- Configured the forwarder to target Splunk-SIEM:
  ```
  splunk add forward-server 10.10.30.10:9997 -auth admin:<password>
  ```
- Configured it to monitor Suricata's alert log directly:
  ```
  splunk add monitor /var/log/suricata/eve.json -auth admin:<password>
  ```
- On Splunk-SIEM, enabled the receiving port:
  ```
  splunk enable listen 9997 -auth admin:<password>
  ```
- Verified the forward-server connection showed as Active (not just
  configured) once the receiving port was open and Splunk restarted.

---

## Part 4: Log ingestion — FortiGate to Splunk

**Port 514 conflict:** Attempted to set Splunk to listen on the
standard syslog port 514 via
`splunk add udp 514 -sourcetype fgt_log`. Failed with "UDP port 514 is
not available." Diagnosed with `netstat`/`systemctl status rsyslog` —
Ubuntu Server's built-in `rsyslog` service was already bound to that
port for local system logging. Rather than disabling a core system
service, moved Splunk's FortiGate listener to port 5140 instead —
avoids the conflict entirely without touching Ubuntu's own logging.

**FortiGate-side syslog configuration:**
- The GUI's Log Settings page (`Log & Report > Log Settings`) only
  exposes a single IP/FQDN text field for the syslog target, with no
  separate port field visible in this FortiOS 7.4.12 build. Attempting
  `10.10.30.10:5140` in that field returned "Invalid hostname" — the
  field strictly validates as an IP/FQDN only, not an address:port
  combination.
- Also discovered that "Local traffic logging" has its own separate
  "Log allowed traffic" toggle, independent from the per-policy
  `logtraffic all` setting configured back on Day 1. The per-policy
  setting controls what FortiGate stores/displays locally; this
  separate global toggle controls what actually gets forwarded via
  syslog. Both needed to be enabled for FortiGate's Accept-logged
  sessions to reach Splunk.
- Switched to the CLI to set the port explicitly, since the GUI
  couldn't:
  ```
  config log syslogd setting
      set status enable
      set server "10.10.30.10"
      set port 5140
      set mode udp
  end
  ```
  FortiGate prompted a confirmation since 5140 differs from the
  standard 514 — confirmed intentionally.

**Verification:** Generated fresh ping traffic from Kali, searched
Splunk for `sourcetype=fgt_log`, and confirmed 25 real events landing
correctly — fully parsed fields including `srcip`, `dstip`, `action`,
`policyid`, `service`, `duration`, and byte counts, sourced from
`udp:5140` as expected.

---

## Verification checkpoints reached
- OWASP BWA live on Victim segment, reachable, logged by FortiGate,
  visible to Suricata — same as Metasploitable2, no policy changes
  required.
- Splunk Enterprise running with a working, verified admin account.
- Suricata Universal Forwarder actively shipping eve.json data to
  Splunk (index/sourcetype=suricata).
- FortiGate actively shipping traffic logs to Splunk via syslog on a
  non-conflicting port (sourcetype=fgt_log), confirmed with 25 real,
  fully-parsed events from live test traffic.
- **Core Lab Foundation is now fully complete**: FortiGate + Suricata +
  Splunk all deployed, integrated, and confirmed correlatable in one
  place — the actual goal of the whole foundation layer.

## Artifacts saved
- Splunk deployment notes and the `--seed-passwd` fix (this document)
  as a reusable reference for any future Splunk redeployment.
