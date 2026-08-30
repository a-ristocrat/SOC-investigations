# Incident #3 — Web Application Reconnaissance

**Dataset:** Splunk BOTS v3 · **SIEM:** Splunk · **Role:** Tier 1 triage

---

## The lead

No alert — this started as a hunt through web traffic (`stream:http`).
Ranking source IPs by request volume was a dead end: the top talkers were
all legitimate (Windows weather/update traffic, health-checkers). Volume
alone doesn't find web attacks.

The better angle was the **User-Agent** field. Filtering out the browsers
and known Microsoft/AWS background agents left a handful of non-browser
clients — `python-requests`, `curl`, a bare `Mozilla/5.0`, and one that
stood out: **`__main__/0.2`**, a homemade script identifier.

---

## Investigation

### 1. Pivot into the suspicious User-Agent

```spl
index=botsv3 sourcetype=stream:http http_user_agent="__main__/0.2"
| stats count by src_ip, uri_path
```

All traffic came from a single IP, `35.182.246.222`, hitting the forum
`brewertalk.com`. Looking at what it requested on `/member.php`:

```spl
index=botsv3 sourcetype=stream:http src_ip="35.182.246.222" uri_path="/member.php"
| stats count by uri_query
```

```
action=login     11
action=lostpw    11
action=register  11
action=profile&uid=40   9
action=profile&uid=27   8
action=profile&uid=31   1
```

Not a human. Equal counts across login / lostpw / register is a script
walking through each function methodically.

### 2. Scope the full sweep

```spl
index=botsv3 sourcetype=stream:http src_ip="35.182.246.222"
| stats count by uri_path
```

**197 requests across 10 pages** — member, forumdisplay, showthread,
calendar, index, memberlist, misc, portal, search, and root. Most pages
hit exactly 11 times. The IP mapped the entire application surface.

### 3. Confirm automation

```spl
index=botsv3 sourcetype=stream:http src_ip="35.182.246.222"
| timechart span=1m count
```

A steady stream of requests every single minute for ~20 minutes — no
human browsing rhythm. Machine-driven.

### 4. Enrich the source

`35.182.246.222` → AWS EC2, ca-central-1 (Montréal), Amazon Data Services
Canada, hosting instance, 0 hosted domains. A rented cloud box with no
legitimate service on it — classic disposable infrastructure for scanning.

### 5. Check the outcome

Every request returned HTTP 200 — the server answered everything, with no
rate-limiting or blocking. The recon succeeded in the sense that it got a
full picture of the app; no exploitation was attempted in this traffic.

> Due diligence: I also checked the other non-browser User-Agents.
> `python-requests` was internal app-to-app traffic (benign). `curl` was
> EC2 instances querying their own AWS metadata service (benign, though
> worth watching for SSRF). The bare `Mozilla/5.0` from `45.7.231.174`
> was a **separate** phpMyAdmin/webshell scanner — tracked as its own
> incident (#4), not merged here.

---

## Ticket

```
INCIDENT #3 — Web Application Reconnaissance

SUMMARY:
Automated web application crawling from a rented AWS EC2 instance. The
__main__/0.2 script systematically probed all functions of the
brewertalk.com forum, including entry points and user profiles. Source
is a cloud instance with no legitimate purpose. All responses returned
HTTP 200, indicating the application had no effective protection in place.

SEVERITY: Medium
Systematic reconnaissance of the application's attack surface from an
anonymous cloud host. 3 user profiles were accessed during the sweep,
and the application applied no rate-limiting or blocking. No exploitation
yet, but this is typical pre-attack behavior.

TIMELINE (UTC):
August 20, 2018, approximately 06:04–06:23 — a continuous stream of
requests providing evidence of automated activity.

EVIDENCE:
- stream:http: 197 requests from 35.182.246.222 across 10 different
  pages, user-agent "__main__/0.2" (non-browser) — automated crawling,
  not human traffic.
- stream:http: exactly 11 systematic requests to most functions (login,
  register, lostpw, calendar, memberlist, misc, portal, search).
- timechart: continuous requests every minute for ~20 minutes — confirms
  automation.
- IP enrichment: 35.182.246.222 = AWS EC2 hosting instance — rented
  cloud infra with no legitimate purpose.
- All responses returned HTTP 200 — the server answered every request
  with no rate-limiting or blocking.

ATT&CK: T1595 — Active Scanning

ASSESSMENT: True Positive
Confirmed automated reconnaissance. A rented cloud host systematically
mapped the forum's functions. No exploitation was observed, but
reconnaissance of this kind commonly precedes a targeted attack.

RECOMMENDATION:
1. Alert on repetitive, monotonic request patterns (steady per-minute
   request rate from one source).
2. Add rate-limiting / WAF — the server answered every request with no
   throttling.
3. Block and monitor 35.182.246.222; report to the AWS abuse contact
   (trustandsafety@support.aws.com) since it originates from EC2.
4. Review whether user profiles should be accessible without auth.
```

---

## What this case demonstrates

- Finding a web attack by User-Agent analysis when volume-ranking failed —
  choosing the right pivot instead of the obvious one.
- Recognizing scripted behavior from the shape of the traffic (equal
  request counts, per-minute cadence) rather than a signature.
- Enrichment turning an IP into context: a rented EC2 host with no hosted
  domains reframes "some crawler" as "disposable attack infrastructure."
- Scoping discipline: checked three other suspicious User-Agents, correctly
  separated benign automation from a second real attack, and kept that
  second attack as its own incident instead of muddying this ticket.
