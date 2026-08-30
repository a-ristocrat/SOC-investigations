# SOC Investigations — Incident Triage Portfolio

A series of security incident investigations worked end-to-end in Splunk,
using the [Splunk BOTS v3](https://github.com/splunk/botsv3) public dataset.

Each case documents a real triage workflow: taking a raw alert, validating
it, pivoting across data sources to scope the activity, and reaching a
documented verdict with a recommendation — the same process a Tier 1 SOC
analyst follows on shift.

## Approach

Every incident follows one repeatable framework:

**VALIDATE → SCOPE → DOCUMENT → ESCALATE**

1. **Validate** — Is the alert real, or a false positive? What does the raw log say?
2. **Scope** — One host or many? One user? What time window? Pivot on indicators.
3. **Document** — Timeline, evidence per source, IOCs, ATT&CK mapping.
4. **Escalate** — Verdict and a recommendation for the next tier.

Each write-up separates **what was observed** from **what it indicates** —
conclusions are tied to specific evidence, not assumed.

## A note on data

This repository contains **analysis only** — no raw event data. The
underlying logs belong to Splunk's BOTS v3 dataset, which is publicly
available at the link above. All queries, findings, and conclusions here
are my own work.

## Incidents

| # | Title | ATT&CK | Verdict |
|---|-------|--------|---------|
| 1 | [SSH Port Probe on Production EC2](incidents/incident-01-ssh-port-probe.md) | T1046 | True Positive — attempted recon, unsuccessful |
| 2 | [SSH Brute Force / Username Enumeration](incidents/incident-02-ssh-brute-force.md) | T1110.001 | Attempted — brute force failed, no access gained |
| 3 | [Web Application Reconnaissance](incidents/incident-03-web-recon.md) | T1595 | True Positive — automated recon, no exploitation |
| 4 | _(in progress — phpMyAdmin / webshell scanner)_ | | |
| 5 | _(planned)_ | | |

## Tools & data sources used

Splunk (SPL) · AWS GuardDuty · VPC Flow Logs · linux_secure · netstat ·
stream:tcp · MITRE ATT&CK framework · threat-intel enrichment

---

*Built as hands-on preparation for a SOC analyst role. Learning in public —
feedback welcome.*
