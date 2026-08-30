# Incident #2 — SSH Brute Force / Username Enumeration on Linux Host

**Dataset:** Splunk BOTS v3 · **SIEM:** Splunk · **Role:** Tier 1 triage

---

## The lead

No alert pointed here directly. Starting from a hypothesis — "is there
password brute force in this environment?" — the first queries for
Windows `4625` and Linux `"Failed password"` both came back nearly empty.

Rather than stop there, I looked at how authentication events were
distributed across hosts:

```spl
index=botsv3 sourcetype=linux_secure
| stats count by host
```

One host stood out: `mars.i-08e52f8b5a034012d` had **222** secure events
against ~20–67 on every other host. An outlier relative to the baseline is
the thing to look at — so I did.

---

## Investigation

### 1. Read the raw logs

The host's events weren't auto-parsed into `user` / `src_ip` fields, so
`stats` returned nothing. Reading the raw events by hand revealed the
pattern:

```
sshd[...]: Invalid user admin from 167.114.13.150 port ... [preauth]
sshd[...]: Invalid user pi from 199.192.19.19 ... [preauth]
reverse mapping checking getaddrinfo ... POSSIBLE BREAK-IN ATTEMPT!
```

This is why the earlier query missed it: for non-existent users the system
logs `Invalid user`, **not** `Failed password`. The attackers were guessing
**usernames** (admin, pi, ubnt, support, test, usuario…), not passwords on a
known account.

### 2. Extract the attacker IPs with rex

Since the fields weren't parsed, I extracted them from the raw text:

```spl
index=botsv3 sourcetype=linux_secure host="mars.i-08e52f8b5a034012d" "Invalid user"
| rex "from (?<attacker_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by attacker_ip
| sort - count
```

Result: **76 attempts from 25 distinct IPs**, top attacker
`167.114.13.150` with 11 tries. Pivoting into that IP showed a classic
dictionary run — admin, test, ubnt, user, usuario, support, pi — the default
logins bots try everywhere.

Every event carried `[preauth]` — the connection dropped before
authentication completed. No logins from the brute force.

### 3. A successful login appears — investigate it

Checking for any success surfaced something that needed its own look:

```spl
index=botsv3 sourcetype=linux_secure host="mars.i-08e52f8b5a034012d" "Accepted"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
```

**4 `Accepted publickey` logins for `ec2-user`** from 3 IPs, all using the
same key fingerprint. Different IPs on one admin account is worth a second
look — could be a stolen key.

Enriching the 3 IPs and building a timeline:

| Time (UTC) | IP | Location | Provider |
|---|---|---|---|
| 02:29:09 | 157.97.121.132 | New York | VPN Consumer Network |
| 07:03:47 | 91.207.175.249 | Los Angeles | M247 (VPN/hosting) |
| 07:11:42 | 166.170.40.8 | Concord, CA | AT&T |
| 07:18:34 | 166.170.40.8 | Concord, CA | AT&T |

VPN endpoints raised suspicion — but a hypothesis has to be tested, not
assumed. I checked what the account actually did after logging in:

```spl
index=botsv3 host="mars.i-08e52f8b5a034012d" sourcetype=bash_history
```

```
ls / pwd / cd AWS_ENVIRONMENT/ / cd AWS_SCENARIOS
sudo pip install boto3
python /home/ec2-user/tools/s3-upload.py --bucket frothlywebcode \
  --file frothly_web_memcached.tar.gz
```

These are the company's own resources (`frothlywebcode` bucket, a
pre-installed `s3-upload.py` tool). No recon, no account creation, no log
tampering — this is routine DevOps work, not an intruder. The VPN
geolocation looked alarming, but the evidence says legitimate.

### 4. Prove the brute force never succeeded

Two independent confirmations:

```spl
index=botsv3 sourcetype=linux_secure host="mars.i-08e52f8b5a034012d" "Accepted password"
```

Empty — zero password logins ever. And the 3 publickey IPs do **not** overlap
with the 25 attacking IPs. Two separate groups: the ones who hammered the
host never got in; the one who got in never hammered it.

---

## Ticket

```
INCIDENT #2 — SSH Brute Force / Username Enumeration on Linux Host

SUMMARY:
Username enumeration in linux_secure on host mars.i-08e52f8b5a034012d —
76 "Invalid user" attempts from 25 different IPs. Top attacker
167.114.13.150 (11 attempts). None of these IPs gained access to the
system. A dictionary of default usernames was used.

SEVERITY: Medium
SSH is open to the internet and attracts continuous attack traffic. The
brute force itself failed, but the exposed service is a standing risk.

TIMELINE (UTC):
- August 20, 2018, 14:35–14:54 — brute force activity window

EVIDENCE:
- linux_secure: 76 "Invalid user" attempts from 25 IPs, top attacker
  167.114.13.150 (11 attempts) — mass username enumeration.
- linux_secure: all events were [preauth], terminated before
  authentication; no login occurred.
- linux_secure: "POSSIBLE BREAK-IN ATTEMPT" indicates non-legitimate
  sources.
- No "Accepted password" events exist, and the 3 successful publickey
  IPs do not overlap with the 25 attacking IPs (detailed in Note below)
  — double confirmation that the brute force never succeeded.
- geo-enrichment + bash_history on the publickey logins — separate
  track, assessed as legitimate admin activity.

ATT&CK: T1110.001 — Brute Force: Password Guessing
(Automated guessing of usernames via a dictionary of common defaults.)

ASSESSMENT: Attempted
A dictionary attack was used to guess usernames; none succeeded.

RECOMMENDATION:
1. Restrict SSH access at the security group level to whitelisted
   internal IPs; block inbound from the internet.
2. Disable password authentication (key-based only). All attacks used
   password guessing; legitimate logins already use keys — this closes
   the vector entirely.
3. Add / consider fail2ban to block an IP after N failed attempts.
4. Monitor the most active attacking IPs.

NOTE (secondary finding):
During the investigation I found 4 "Accepted publickey" logins for
ec2-user, all with the same key fingerprint
(SHA256:Z1RO5UMCuK3+NOcX0XWO1atA1+fhYXeYomgkTarWrmQ):
  02:29:09 — 157.97.121.132 — New York — VPN Consumer Network
  07:03:47 — 91.207.175.249 — Los Angeles — M247 (VPN/hosting)
  07:11:42 — 166.170.40.8 — Concord, CA — AT&T
  07:18:34 — 166.170.40.8 — Concord, CA — AT&T
Subsequent shell activity shows legitimate admin work with Frothly
resources. Conclusion: legitimate administrative activity, but
accessing production through a consumer VPN is poor security practice
and should be confirmed with the key owner.
```

---

## What this case demonstrates

- Turning a hunch into proof. "I think there's more here" became a number:
  76 attempts, 25 IPs — verified with a query, not left as a feeling.
- Reading raw logs when auto-parsing fails, and using `rex` to extract
  fields (attacker IP) that Splunk didn't index.
- Understanding *why* the obvious query missed — `Invalid user` vs
  `Failed password` — instead of concluding "nothing's here."
- Investigating a suspicious signal (publickey logins from VPN IPs),
  forming a compromise hypothesis, testing it against evidence, and
  **discarding it honestly** when the data showed legitimate activity.
- Proving a negative two independent ways (no `Accepted password`;
  attacker and success IPs disjoint) rather than asserting it.
