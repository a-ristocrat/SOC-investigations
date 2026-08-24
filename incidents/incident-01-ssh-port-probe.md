# Incident #1 — SSH Port Probe on Production EC2

**Dataset:** Splunk BOTS v3 · **SIEM:** Splunk · **Role:** Tier 1 triage

---

## The alert

A single AWS GuardDuty finding surfaced in a stream of ~2M events:

```
Recon:EC2/PortProbeUnprotectedPort   severity: 2 (Low)
```

GuardDuty fires rarely on normal activity, so a lone finding among millions
of events is exactly the kind of low-frequency signal worth looking at first.
**Rare source = high priority to review**, regardless of the severity label.

---

## Investigation

### 1. Validate — read the full alert

Opening the raw GuardDuty event (not just type + severity) gave the core facts:

- **Type:** `Recon:EC2/PortProbeUnprotectedPort`, `blocked: false`
- **Target:** port 22 / SSH on instance `i-0cc93bade2b3cba63`
- **Source IP:** `122.112.243.11`, flagged as a **known scanner** on the
  ProofPoint threat list
- **Geo:** Beijing, China — China Telecom, ASN 4812
- **Asset context:** tag `WebServers`, security group
  `production-FrothlyWebPubSecGroup` → this is a **production** host

Reading the whole event mattered: the threat-intel flag and the production
tag both change how serious this is, and neither is visible from the
severity number alone.

```spl
index=botsv3 sourcetype="aws:cloudwatch:guardduty"
```

### 2. Scope — pivot on the source IP

The key question: did this IP do anything beyond the probe? Pivoted the
single indicator across all data.

```spl
index=botsv3 "122.112.243.11"
```

It appeared in three sources:

- **VPC Flow** — traffic to port 22 logged as `ACCEPT`. The SSH port is
  reachable from the internet at the network level (confirms GuardDuty's
  "unprotected port").
- **netstat (host)** — connection from the IP to `:22` stuck in `SYN-RECV`.
  The TCP handshake never completed → no session established.
- **stream:tcp** — a small flow (6 packets, `app: unknown`), consistent with
  a probe rather than a data-carrying session.

### 3. Confirm — did the attacker get in?

Checked host authentication logs for any trace of the source IP.

```spl
index=botsv3 host="gacrux.i-0cc93bade2b3cba63" sourcetype=linux_secure "122.112.243.11"
```

**Zero results.** No authentication records from the attacker IP → no login
attempt reached the server.

> Trap avoided: `linux_secure` on this host showed many `useradd` events
> (apache, memcached, streamfwd) around 13:33. In isolation these look like
> an attacker creating accounts — but they occur in one short burst, run as
> root, and include a Splunk-forwarder install. That is server
> **provisioning**, not compromise. Context, not keywords, decides.

### 4. Was it a targeted probe or a wide scan?

```spl
index=botsv3 "122.112.243.11" sourcetype=stream:tcp
| stats count by dest_port
```

Only port 22, once. This was a **targeted probe of SSH specifically**, not a
broad port sweep — which fits the "check if this service is open" behaviour
of reconnaissance.

---

## Ticket

```
INCIDENT #1 — SSH Port Probe on Production EC2

SUMMARY:
External IP 122.112.243.11 (known scanner) probed SSH port 22 on
production web server i-0cc93bade2b3cba63. Port confirmed open and
reachable, but no connection was established and no login occurred.
Assessed as reconnaissance, likely preceding a future attack.

SEVERITY: Medium
The recon attempt itself failed (no access gained), which alone would
be Low. Raised to Medium because it exposed a genuinely misconfigured
SSH port open to the internet on a PRODUCTION server, probed by an IP
already listed as malicious in threat intel.

TIMELINE (UTC):
- 13:50:05  GuardDuty first observed the probe (eventFirstSeen)
- 13:51:04  Probe activity ended (eventLastSeen)
- 14:01:29  GuardDuty finding generated
- Connection seen on host in SYN-RECV state — handshake never completed
- No corresponding authentication events in host logs

EVIDENCE:
- GuardDuty: Recon:EC2/PortProbeUnprotectedPort, severity 2.
  Source IP flagged as known scanner (ProofPoint threat list).
  Geolocated to Beijing, China (China Telecom, ASN 4812).
  Probe not blocked (blocked: false). Target port 22 / SSH.
- VPC Flow: traffic to port 22 logged as ACCEPT — confirms the SSH
  port is reachable from the internet at the network level.
- netstat (host): connection from 122.112.243.11 to :22 stuck in
  SYN-RECV — TCP handshake never completed, no session established.
- linux_secure (host): zero authentication records from the source
  IP — confirms no login attempt reached the server.

ATT&CK: T1046 — Network Service Discovery
(Targeted probe of a specific service/port to determine if it is open.)

ASSESSMENT: True Positive — attempted reconnaissance, unsuccessful.
The scan was real and originated from a known-malicious IP, but no
access was gained. The fact that the source is already in a threat
feed raises the likelihood it will return with a follow-up attempt.

RECOMMENDATION:
1. Restrict SSH (port 22) at the security group level to internal /
   whitelisted IPs only; block inbound from the internet.
2. Confirm key-based authentication is enforced (disable password auth).
3. Consider blocking/monitoring 122.112.243.11 given its threat-feed
   listing.
4. Review whether other production instances share the same exposed
   security group (production-FrothlyWebPubSecGroup).
```

---

## What this case demonstrates

- Severity of a single alert ≠ priority of the incident. A Low GuardDuty
  finding, after pivoting, exposed a real production misconfiguration.
- Pivoting on one indicator (source IP) across GuardDuty, VPC Flow, netstat,
  stream, and host auth logs to build a complete picture.
- Distinguishing malicious activity from benign provisioning noise in
  `linux_secure` — the difference between a useful analyst and one who
  escalates everything.
- Tying every conclusion to specific evidence and writing a recommendation
  a next-tier analyst can act on directly.
