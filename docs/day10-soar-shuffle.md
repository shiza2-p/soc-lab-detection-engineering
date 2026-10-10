# Day 10: SOAR Automated Response with Shuffle

## Objective
Deploy Shuffle as a SOAR platform and build a real, idempotent
automated-response playbook: detect a Cowrie honeypot connection,
check whether the source IP is already blocked, and if not,
automatically create a block on FortiGate via its REST API.

---

## Part 1: Deployment planning and a real resource constraint

Before building, ran into a genuine storage constraint: only ~13GB
free on the primary lab drive (E:), while Shuffle's officially
documented minimum is 4 CPU / 8GB RAM / 30GB disk (primarily driven by
OpenSearch, Shuffle's backend database).

Considered and rejected two options before settling on the right one:
- **USB drive**: initially considered, but rejected after discussion —
  OpenSearch does continuous, heavy random-write I/O, and most
  consumer USB drives lack power-loss protection, risking database
  corruption from something as simple as a loose connection. This is
  the same class of risk flagged and avoided back on Day 1 for live
  VM storage generally.
- **Deleting an old unused personal Kali VM** (22GB, confirmed separate
  from the dedicated lab Kali) to free space on E: — a reasonable
  option, but ultimately unnecessary once a second internal drive
  (D:) with adequate free space was identified.

**Final decision:** deployed Shuffle-SOAR on D: (a genuine internal
drive), avoiding both the USB reliability risk and the need to delete
anything from E:.

---

## Part 2: VM build and networking

- Ubuntu Server 26.04 LTS, 2 vCPU, 4GB RAM initially (later increased —
  see OOM section below), 30GB disk, stored on D:.
- Static IP `10.10.30.20/24` on VMnet4 (Management segment), no
  `routes:` block (lesson from repeated default-route bugs applied
  consistently).
- Temporary NAT adapter added for Docker installation, same pattern as
  every prior VM.

---

## Part 3: Docker and Shuffle installation

Installed Docker CE via the official repository, then deployed Shuffle
via its documented `docker compose` setup (cloned repo, prepared the
`shuffle-database` directory with correct ownership, set
`vm.max_map_count=262144` for OpenSearch as required).

### OOM crash loop (major issue, resolved by adding RAM)

On first `docker compose up -d`, the OpenSearch container repeatedly
crashed and restarted — `dmesg`/container logs showed continuous
`Out of memory: Killed process (java)` entries. `docker compose ps`
showed OpenSearch's uptime resetting to a low number (e.g., "Up 29
seconds") while other containers stayed stable at several minutes,
confirming a crash-restart loop rather than a one-time failure.

**Root cause:** 4GB RAM was genuinely insufficient for OpenSearch's
default JVM heap requirements running alongside three other
containers (frontend, backend, orborus) plus normal OS overhead.

**Fix:** increased the VM's RAM allocation to 8GB and restarted.
OpenSearch's logs then showed a clean, healthy startup (heap size
auto-calculated at 3GB, plugins loaded successfully, cluster formed) —
no further OOM kills observed afterward. This was chosen over
aggressively capping OpenSearch's heap via `OPENSEARCH_JAVA_OPTS`,
since a heap capped too small risked its own instability; addressing
the actual resource shortfall directly was the more durable fix.

### Corrupted database volume (second major issue)

After the OOM crash-loop, a new symptom appeared: canvas changes
(added nodes) stopped persisting across page reloads, and a specific
app ("HTTP") failed to activate entirely with:
```
[ERROR] Failed auto-download. Applength: 0
{"success": false, "reason": "App doesn't exist"}
```
Verified via `curl -v` directly against `shuffler.io` that internet
connectivity and TLS were fine — the request reached Shuffle's cloud
registry successfully and got a clean 401/"App doesn't exist"
response. This ruled out a networking problem and pointed to a
corrupted or inconsistent local reference — most likely a stale app ID
cached in Shuffle's database during one of the OOM crash cycles.

**Fix:** stopped the stack, removed the persistent database volume
entirely, and rebuilt from scratch:
```bash
sudo docker compose down
sudo docker volume rm shuffle_shuffle-database
sudo docker compose up -d
```
This required recreating the admin account and the (still-empty)
workflow, but resolved both the persistence issue and the HTTP app
activation failure immediately on a clean database.

**Lesson:** a crash-looping container can leave a platform's own
backing database in an inconsistent state even after the immediate
crash is fixed (more RAM) — verifying the underlying data layer is
genuinely healthy, not just checking whether containers are "up," was
necessary here.

---

## Part 4: FortiGate REST API access

Created a dedicated REST API administrator account on FortiGate
(`shuffle-soar-api`), scoped with Trusted Hosts restricted to the
specific IPs Shuffle-SOAR would call from (`10.10.30.20/32`, later
`10.10.10.20/32` once network routing required a second interface —
see Part 5). Left the PKI Group option disabled, since
certificate-based authentication was not in use — confirmed via
research that this field is specifically for client-certificate auth
and does not need to be enabled for standard token-based API access.

Verified the API token worked correctly by testing directly with
`curl` before attempting to configure it inside Shuffle — this
isolated "does the API access itself work" from "is Shuffle configured
correctly," which proved useful for diagnosing later issues
independently.

---

## Part 5: Network path — no direct route from Shuffle to FortiGate

Discovered that Shuffle-SOAR (on VMnet4/Management) had no network
path to FortiGate at all, since FortiGate only has interfaces on
VMnet2 (Attacker), VMnet3 (Victim), and WAN — never VMnet4.

Considered adding a fourth FortiGate interface directly, but this was
skipped due to a known constraint: FortiGate-VM's free evaluation
license explicitly limits deployments to a maximum of three
interfaces, firewall policies, and routes each (confirmed back on Day
1 during initial licensing) — adding a fourth interface would very
likely be rejected outright.

**Fix:** added a second network adapter to Shuffle-SOAR on VMnet2,
with a static IP (`10.10.10.20/24`), giving it direct reachability to
FortiGate's port2 (`10.10.10.1`) without needing any change to
FortiGate's interface count. Verified with a successful ping before
proceeding.

---

## Part 6: Building the workflow

### Trigger and initial HTTP action
Added a Webhook trigger and a single HTTP POST action to create a
FortiGate address object for a given source IP, using Shuffle's
runtime variable syntax `$exec.src_ip` to reference the value from
the incoming webhook payload (confirmed via Shuffle's "Details" panel,
which showed the real resolved execution data:
`"$exec": {"src_ip": "1.2.3.4"}`).

**Bug found and fixed:** the Body field initially still referenced the
incorrect, unprefixed `$src_ip` (a leftover from before the correct
syntax was confirmed) — Shuffle's own inline UI warning
("$src_ip, $src_ip are not accessible in this action") flagged this
directly. Corrected to:
```json
{"name":"cowrie-block-$exec.src_ip","subnet":"$exec.src_ip 255.255.255.255"}
```
After the fix, the first test run succeeded (`status: 200`), confirmed
by checking Policy & Objects → Addresses on FortiGate directly for the
newly created object.

### Duplicate-object bug on re-run
Re-running the identical test payload without deleting the
previously-created object failed with `status: 500`, FortiGate error
code `-8`... actually corrected on inspection to **error `-5`**
("entry already exists") on the second attempt — read directly from
the response body's `error` field, since the accompanying `cli_error`
array was empty this time (the error code alone was sufficient to
diagnose it as a duplicate-key conflict, cross-checked against the
create-flow's earlier `-8`/"invalid ip address" error to confirm they
were two genuinely distinct failure modes, not the same bug repeating).

This was treated as a real design gap rather than dismissed — a
production SOAR playbook needs to handle "this IP is already blocked"
gracefully rather than fail.

### Building idempotent check-then-create logic
Restructured the workflow:
```
Webhook → Check Exists (GET) → [condition: status == 404] → Create Block (POST)
```
- **Check Exists**: a GET request to
  `https://10.10.10.1/api/v2/cmdb/firewall/address/cowrie-block-$exec.src_ip`
  — FortiGate's API allows querying a specific object directly by
  appending its name to the URL path, returning 404 if it doesn't
  exist or 200 with its data if it does.

**Wrong tool first — "Filter list" action:** initially attempted to
gate execution using Shuffle's "Filter list" action (found under
Shuffle Tools), configuring it with the Check Exists status, an
"Equals" comparison, and value `404`. This produced no error but
silently failed to actually gate anything — the Create Block step ran
regardless of the check's result. Investigating the Filter node's own
execution output revealed why:
```json
{"success": false, "reason": "Error: input isnt a list. Please use conditions instead if using JSON."}
```
Shuffle's own error message directly pointed to the correct
tool — "Filter list" is designed for filtering items within an array,
not branching on a single JSON value, and Shuffle explicitly
recommends using **Conditions** for this case instead.

**Correct approach — condition on the connection line:** removed the
Filter node, reconnected Check Exists directly to Create Block, then
configured a condition directly on that connecting line (clicking the
line itself, rather than adding a separate node, exposes Shuffle's
branch/condition configuration):
- Value: `$http_1.status` (the exact node name confirmed by clicking
  into the Check Exists node itself, since more than one HTTP action
  existed in the workflow and node names needed to be disambiguated
  directly rather than assumed)
- Condition: Equals
- Compare to: `404`

### Verification — both branches confirmed
- **Run 1** (object deleted beforehand): Check Exists returned 404 →
  condition passed → Create Block executed → 200. Confirmed via
  FortiGate GUI that the object was genuinely created.
- **Run 2** (same payload, object already existing from Run 1): Check
  Exists returned 200 (found) → condition correctly evaluated false →
  execution stopped. Confirmed in the execution log that Create
  Block's action did not run a second time at all — no duplicate
  attempt, no error, clean idempotent behavior.

---

## Verification checkpoints reached
- Shuffle deployed successfully after resolving a genuine OOM crash
  loop (fixed via RAM increase) and a resulting corrupted database
  volume (fixed via volume removal and clean rebuild).
- FortiGate REST API access configured, tested independently via curl
  before integration, and confirmed working from Shuffle.
- Resolved a real network-reachability gap (Shuffle had no path to
  FortiGate) without violating the FortiGate-VM license's 3-interface
  limit, by adding a second NIC to Shuffle-SOAR instead.
- Diagnosed and fixed two distinct FortiGate API error codes
  encountered during development (`-8` invalid-IP on the create call,
  `-5` duplicate-entry on a naive re-run).
- Identified that Shuffle's "Filter list" action was the wrong tool
  for single-value conditional branching (confirmed via the tool's own
  error message) and correctly used connection-line Conditions
  instead.
- Built and verified a genuinely idempotent detection-to-response
  playbook: Webhook trigger → existence check → conditional branch →
  FortiGate block creation, confirmed correct on both the
  first-time-block and already-blocked paths.

## Artifacts saved
- Shuffle workflow: `Cowrie-to-FortiGate-AutoBlock` (exported/screenshot
  reference, given Shuffle workflows are stored in its own database
  rather than flat files suitable for direct Git storage).
