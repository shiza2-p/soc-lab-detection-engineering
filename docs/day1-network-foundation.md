# Day 1–2: Core Network Foundation Build

## Objective
Deploy FortiGate-VM as the routing/firewall backbone for a 3-segment
detection engineering lab (Attacker / Victim / Management), and prove
attacker-to-victim traffic is correctly routed, logged, and inspectable.

---

## What I built

### 1. Host environment prep
- Confirmed VMware Workstation Pro (free personal-use license) already
  installed and working.
- Investigated a Windows Hyper-V / Memory Integrity conflict flagged by
  `systeminfo`. Rather than assuming it was a blocker, tested directly —
  since VMware had already run FortiGate-VM successfully for a prior
  classroom lab on this same machine, concluded no change was needed.
  Left Memory Integrity as-is.

### 2. FortiGate-VM deployment
- Downloaded FortiGate-VM 7.4.12 (GA, build 2902) from the Fortinet
  support portal, VMware ESXi platform package (compatible with
  Workstation Pro).
- Selected the plain `FortiGate-VM64.ovf` variant over the hw13/15/17,
  nsxt, and vApp variants, since those target ESXi hardware-version
  compatibility and orchestration scenarios not relevant here.
- Imported into VMware Workstation. Default OVF shipped with 10 network
  adapters, all set to Bridged — removed adapters 4–10 (unused) and
  reassigned the first 3:
  - Network Adapter 1 → VMnet8 (NAT) → port1 / WAN
  - Network Adapter 2 → VMnet2 (custom host-only) → port2 / Attacker
  - Network Adapter 3 → VMnet3 (custom host-only) → port3 / Victim
- Powered on, logged in via console (`admin` / blank password), set a
  new admin password on first login.

### 3. Licensing
- Confirmed FortiOS 7.4.12 booted correctly (`get system status`),
  License Status initially `Invalid`.
- Activated the free permanent evaluation license via CLI:
  `execute vm-license-options account-id <email>`
  `execute vm-license-options account-password <password>`
  `execute vm-license` (this is the command that actually triggers
  activation — the account-id/account-password commands only stage
  the values silently).
- Confirmed reboot, re-verified `get system status` → License Status
  now `Valid`. Eval license limits: 1 vCPU, 2GB RAM, max 3 interfaces,
  low-encryption only — acceptable for lab use.

### 4. First-login configuration choices
- Declined automatic patch upgrades (disabled) — deliberate choice to
  keep FortiOS version pinned at a known build for consistent
  documentation and to avoid unexpected reboots mid-lab-session.
- Selected "Comprehensive" dashboard/FortiView set over "Optimal" —
  wanted full monitor visibility for both teaching use and portfolio
  screenshots later.

### 5. Interface and policy configuration
- Set port2 static: `10.10.10.1/24`, allowaccess ping/https/ssh.
- Set port3 static: `10.10.20.1/24`, allowaccess ping/https/ssh.
- Created firewall policy #1 "Attacker-to-Victim": srcintf port2 →
  dstintf port3, srcaddr/dstaddr all, action accept, service ALL,
  logtraffic all (critical — this is what feeds Splunk later).
- Enabled disk logging (`config log disk setting` → `set status
  enable`) — required for logs to persist across VM power cycles;
  default/memory-only logging does not survive a reboot.

### 6. Victim and attacker machines
- Attached existing Metasploitable2-Linux VM to VMnet3, set static IP
  10.10.20.10 via `/etc/network/interfaces` (legacy Debian-style
  networking, since Metasploitable2 predates netplan).
- Deliberately did NOT reuse personal daily-driver Kali VM for the lab
  — imported a separate, dedicated Kali instance from a fresh
  pre-built image instead, to avoid any risk to the personal Kali's
  existing tool configuration. Renamed `Kali-SOC-Lab`, attached to
  VMnet2, static IP 10.10.10.10 via `nmcli`.

---

## What broke, and how it was diagnosed and fixed

**Issue 1 — VMnet2/3/4 not visible in Virtual Network Editor despite
VM-to-VM traffic working.**
Root cause: VMware lets VMs communicate over a custom vmnet the moment
it's selected in a VM's adapter dropdown, without that network being
formally registered via "Add Network." This let Kali-to-Metasploitable
traffic succeed, but meant no host-side virtual adapter existed, so the
Windows host itself couldn't reach `10.10.10.1`. Also traced this to
initially viewing the Network Editor without admin elevation, which
silently restricted the view. Fixed by reopening VMware Workstation as
Administrator and explicitly adding VMnet2/3/4 with "Connect a host
virtual adapter to this network" checked.

**Issue 2 — Host's VMnet2/VMnet3 adapters auto-assigned `.1`
addresses, conflicting with FortiGate's own port2 (`10.10.10.1`) and
port3 (`10.10.20.1`).**
Two devices with the same IP on the same segment caused the host
browser to time out reaching the FortiGate GUI (`ERR_CONNECTION_
TIMED_OUT`). Fixed by manually setting the host's VMnet2 adapter to
`10.10.10.5` and VMnet3 adapter to `10.10.20.5` via Windows adapter
properties.

**Issue 3 — "Destination Host Unreachable" errors from FortiGate
after a fresh reboot.**
Not a config regression — Metasploitable2 (and separately, later,
FortiGate itself) were simply powered off. FortiGate correctly reported
unreachability rather than a false success. Resolved by powering the
relevant VM back on. Reinforced the need for a consistent
power-on checklist across sessions once more VMs (Suricata, Splunk)
join the topology.

**Issue 4 — Forward Traffic log showed no results after Day 2
restart.**
Not a bug — disk-logged traffic history only contains what's actually
occurred since logging was enabled; a full overnight power-off with no
traffic naturally shows nothing until new traffic is generated. Fixed
by simply re-running a test ping from Kali after powering everything
back on, which appeared in the logs as expected.

---

## Verification checkpoints reached

- `get system interface physical` confirms port1 (DHCP, WAN),
  port2 (static, 10.10.10.1/24), port3 (static, 10.10.20.1/24) — all
  status up.
- `show firewall policy` confirms policy 1 saved exactly as configured.
- End-to-end ping test (Kali 10.10.10.10 → Metasploitable2 10.10.20.10)
  succeeded with 0% packet loss, ttl=63 (one hop, confirming routing
  through FortiGate).
- FortiGate GUI Forward Traffic log confirmed the same ping sessions,
  logged to disk, with accurate timestamps and byte counts — validating
  that `logtraffic all` is working and this data source is ready for
  Splunk ingestion in a later phase.
- Re-verified full chain after a complete power-cycle on Day 2 with no
  configuration loss.

---

## Artifacts saved
- `fortigate-configs/FGVMEVAETPZ-TJEB_7-4_2902_202608150646.conf` —
  full FortiOS configuration backup.
