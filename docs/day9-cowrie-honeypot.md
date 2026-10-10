# Day 9: Cowrie Honeypot Deployment

## Objective
Deploy Cowrie as a deception layer on the Victim segment — a fake SSH
service that anything touching is malicious by definition, adding a
third, independent, high-confidence detection source alongside
FortiGate and Suricata.

---

## VM build
- Ubuntu Server 26.04 LTS, 1 vCPU, 1GB RAM, 20GB disk.
- Network adapter on VMnet3 (Victim segment), static IP
  `10.10.20.50/24` via netplan — no `routes:` block included this
  time, applying the lesson learned from repeated default-route
  metric bugs on earlier VMs.
- First netplan attempt failed with a YAML indentation error, caused
  by the auto-generated config's existing `match`/`macaddress` block
  conflicting with a manually inserted `dhcp4: no` line at the wrong
  indent level. Resolved by rewriting the file cleanly from scratch
  rather than patching the auto-generated structure.
- Added a temporary NAT adapter for package installation, same pattern
  as Suricata-Sensor and Splunk-SIEM.

---

## Cowrie installation

```bash
sudo apt install -y git python3-venv python3-dev libssl-dev libffi-dev \
  build-essential libpython3-dev python3-minimal authbind virtualenv
sudo adduser --disabled-password cowrie
sudo su - cowrie
git clone http://github.com/cowrie/cowrie
cd cowrie
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install --upgrade pip
pip install --upgrade -r requirements.txt
```

Installed as a dedicated non-root `cowrie` user, following standard
honeypot security practice — a honeypot process should never run with
elevated privileges, since it's specifically designed to be attacked.

### Entry-point troubleshooting

The commonly documented startup command, `bin/cowrie start`, failed
with "No such file or directory" — the `bin/` folder only contained
unrelated helper scripts (`build-fs-pickle.sh`,
`createdynamicprocess`, `regen-dropin.cache`), no `cowrie` executable
at all. This indicated the installed version's structure has changed
from what most tutorials assume.

Searched the full repository directly rather than continuing to guess:
```bash
find . -iname "*cowrie*" -type f 2>/dev/null | grep -v ".git"
```
This revealed the real entry point at
`src/cowrie/scripts/cowrie.py`, which docstring-documented itself as
"Cowrie service management script."

Running it directly by file path
(`python3 src/cowrie/scripts/cowrie.py start`) failed differently:
```
ModuleNotFoundError: No module named 'cowrie.core'; 'cowrie' is not a package
```
This happens because invoking a script by direct file path doesn't
resolve Python's package import structure the same way a proper
installed entry point does, even when the code itself is correct.

**Fix:** installed the package in editable mode so Python's import
system could resolve it correctly:
```bash
pip install --editable .
```
This also registered a real, dedicated `cowrie` command on the PATH
(`which cowrie` → `/home/cowrie/cowrie/cowrie-env/bin/cowrie`).
Running `cowrie start` (the proper installed command, not the raw
script path) succeeded immediately.

**Lesson:** for any Python project structured as an installable
package, use its proper entry-point command once installed
(`pip install --editable .` + the resulting command), rather than
invoking internal script files directly by path — even when a file
technically exists at a path a script tries to import from, direct
invocation bypasses the package resolution that makes cross-module
imports work.

---

## Exposing Cowrie as the "real" SSH port

Cowrie listens on port 2222 by default (avoiding port 22 deliberately,
since binding under 1024 requires root, which Cowrie's process
intentionally avoids running as). To make it convincingly look like a
normal SSH server to an attacker scanning port 22, set up a redirect.

### Step 1: Disable the genuine OpenSSH server on this VM
```bash
sudo systemctl stop ssh
sudo systemctl disable ssh
```
This VM's sole purpose is to be a honeypot; real SSH management access
is intentionally sacrificed in favor of the VMware console going
forward, consistent with standard honeypot deployment practice.

### Step 2: Redirect port 22 to Cowrie's real listener

**Misconfiguration found and corrected:** the redirect was initially
set to `--to-port 22222` based on a terminal misread of Cowrie's
actual listening port — `ss -tlnp` output showing `:2222` was
misread as `:22222` in a wrapped terminal line. This meant traffic to
port 22 was being redirected to a port nothing was actually listening
on, while Cowrie's genuine port (2222) remained un-redirected and
directly exposed instead — confirmed via `nmap -p 22,2222,22222` from
Kali, which showed port 22 as `filtered` (redirected nowhere useful)
and 2222 as `open` (Cowrie's real, un-redirected port).

Corrected:
```bash
sudo iptables -t nat -F PREROUTING
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
sudo netfilter-persistent save
```

**Diagnostic approach used:** rather than continuing to guess,
verified the actual bound process and port directly with
`sudo ss -tlnp | grep :2222` (confirming `twistd`, Cowrie's underlying
process, genuinely listening there) before rewriting the redirect
rule — this caught the exact mismatch rather than applying another
guess.

---

## Verification: attack traffic captured (and a path bug found)

### First test sessions

The first interactive session (`ls`, `whoami`, `cd bin`) was run on the
honeypot itself and appears in Cowrie's JSON log with source
`127.0.0.1` — a local self-test, not network traffic. Later sessions,
including the commands typed from Kali (`whoami`, `ls`, `cat /etc/passwd`,
`uname -a`, `id`, `ls -la /root`), were logged with source
`10.10.20.5`, which is the Windows host's own VMnet3 adapter — not
Kali's `10.10.10.10`.

### Finding: the Kali test bypassed the firewall

Kali has a second adapter on the VMware NAT network (`eth1`,
`192.168.75.136`). `ip route get 10.10.20.50` on Kali returned
`via 192.168.75.2 dev eth1`, so the SSH session left through the NAT
gateway instead of crossing FortiGate on `eth0`. FortiGate therefore had
no record of it, and the honeypot saw the host's address as the source.
Cowrie's VM has the same dual-homed layout (`ens33` on the victim
segment, `ens37` on NAT) with its default route on the NAT side.

**Fix:** pinned the path through the firewall on both ends:
```bash
# Kali
sudo ip route replace 10.10.20.0/24 via 10.10.10.1 dev eth0
# Cowrie-Honeypot (return path)
sudo ip route add 10.10.10.0/24 via 10.10.20.1 dev ens33
```
Without the return route the connection timed out, because Cowrie
replied out of its NAT interface. `tracepath -n 10.10.20.50` from Kali
then showed `10.10.10.1` (FortiGate) as hop 1 and the honeypot as hop 2.

### Re-test through FortiGate

SSH from Kali to `10.10.20.50`, then `whoami`, `ls`, `cat /etc/passwd`,
`uname -a`, `id`, `ls -la /rot` (a typo, logged as typed),
`ls -la /root`, `exit`. Cowrie's log now records every command with
`src_ip: 10.10.10.10`, and FortiGate's Forward Traffic log shows the
same source unchanged (NAT is disabled on the policy).

**Limitations noted:**
- The `ip route` entries are not persistent and are lost on reboot.
- Cowrie does not start automatically after a VM restart; it was
  started manually as the `cowrie` user (`cowrie start`).

---

## Splunk integration

Installed a Universal Forwarder on Cowrie-Honeypot, following the same
pattern as Suricata-Sensor, with the sourcetype set explicitly from
the start this time (`-sourcetype cowrie`) to avoid repeating the
`json-2` auto-labeling issue found on Day 8.

```bash
sudo dpkg -i splunkforwarder.deb
sudo /opt/splunkforwarder/bin/splunk start --accept-license --answer-yes --no-prompt --seed-passwd <password>
sudo /opt/splunkforwarder/bin/splunk add forward-server 10.10.30.10:9997 -auth admin:<password>
sudo /opt/splunkforwarder/bin/splunk add monitor /home/cowrie/cowrie/var/log/cowrie/cowrie.json -sourcetype cowrie -auth admin:<password>
```

One install hiccup: the initial `dpkg -i` attempt was run while still
in the `cowrie` user's shell context (from the earlier `sudo -u cowrie
-i` session switch), which correctly failed with a sudo permission
denial — `cowrie` is intentionally a low-privilege account with no
sudo rights, by design. Exiting back to the regular admin account
resolved this immediately; not a bug, just a reminder to track which
user context is active across a multi-VM, multi-account session.

Verified in Splunk with `sourcetype=cowrie`. The first ingestion
delivered the log as a single multi-line event stamped with its arrival
time, because Splunk had no line-breaking or timestamp rules for the
sourcetype. Fixed on the indexer with a `[cowrie]` stanza in
`props.conf` (`SHOULD_LINEMERGE = false`, `KV_MODE = json`, and
`TIME_PREFIX`/`TIME_FORMAT` pointing at Cowrie's own `timestamp` field).
After a Splunk restart, each command is its own event with the real
timestamp and `src_ip`:

```
sourcetype=cowrie eventid=cowrie.command.input | table _time src_ip input
```

## Verification checkpoints reached
- Cowrie deployed as a dedicated, non-root honeypot service on the
  Victim segment.
- Diagnosed and resolved a Python packaging/entry-point issue (editable
  install) instead of following outdated documentation.
- Diagnosed and corrected a port-redirect misconfiguration using direct
  process verification (`ss -tlnp`).
- Found that the first Kali test took a side path around FortiGate
  (dual-homed Kali, NAT default route), fixed the routing on both VMs,
  and re-ran the test so it crossed the firewall with source
  `10.10.10.10` preserved.
- Fixed Cowrie log ingestion in Splunk (event breaking and timestamp
  extraction), so commands are individually searchable.
- Cowrie is a third detection source alongside FortiGate and Suricata,
  centralized in one SIEM.
