# Wazuh SIEM Monitoring & Detection Homelab

A self-built security-monitoring lab: a **Wazuh** manager on Ubuntu with a Windows
endpoint agent, centralised log collection, real-time alerting and a file-integrity
monitoring (FIM) policy, used to practise the alert-triage and case-documentation
workflow that security operations teams run daily.

> 📌 This repository is the **write-up plus the runnable configuration**:
> architecture, decisions, the detection rules, the ingest scripts and what the
> exercise taught me. It intentionally contains no copy-paste dumps of my
> environment's configs or keys.
>
> Live demo of the workflow (and everything else I build):
> **[darshan2209.github.io/darshangiri-goswami](https://darshan2209.github.io/darshangiri-goswami/)**

## Where this went next

I started this in July as a Wazuh manager and one Windows agent, which is where the
sections below stop. In August I rebuilt the collection layer underneath it, and that
work lives in this same repository:

- **A Zeek sensor on a mirror port**, so the lab sees network telemetry and not only
  endpoint logs. Config in [`zeek/local.zeek`](zeek/local.zeek).
- **Apache Kafka between Zeek and the indexer.** Without a broker, a slow or restarting
  indexer silently drops events. With one, Zeek keeps producing and the consumer catches
  up from its committed offset. I can stop the consumer for ten minutes, replay traffic,
  restart it, and lose nothing. Consumer in
  [`scripts/kafka_to_opensearch.py`](scripts/kafka_to_opensearch.py).
- **12 detection rules I wrote and tuned**, in
  [`detection-rules/local_rules.xml`](detection-rules/local_rules.xml). Every rule carries
  a comment saying why its threshold is what it is, because a rule you cannot explain is a
  rule you downloaded.
- **MISP threat intelligence**, pulled over the REST API and validated before anything
  touches a file, so new indicators enrich alerts with no manual re-entry.
  See [`scripts/misp_ingest.py`](scripts/misp_ingest.py).

Full build steps for that stage are in [`SETUP.md`](SETUP.md). The tuning is the part
worth reading: two thresholds moved because of it. The long-DNS rule went from 40
characters to 52, because at 40 it flagged legitimate CDN and cloud-provider hostnames.
The query-volume rule went from 50 per minute to 120, because Windows telemetry on its
own cleared 60.

```bash
pip install -r requirements-dev.txt
pytest    # 46 tests: the MISP validator and the Kafka index namer
```

The two things those tests actually guard are worth naming: the MISP validator rejects
private and loopback addresses, malformed domains and hashes, and any value carrying a
control character, and the index namer sanitises the attacker-influenced `_path` field so
no path traversal or separator reaches an index name. Both take input from outside, so
both get tested.

## Architecture

```
┌──────────────────────┐        agent (TLS 1514/1515)        ┌──────────────────────┐
│  Windows 11 endpoint │ ───────────────────────────────────▶ │  Ubuntu 22.04 server │
│  · Wazuh agent       │                                      │  · Wazuh manager     │
│  · Sysmon-style logs │                                      │  · Indexer + dashboard│
│  · FIM watched paths │ ◀─────────────────────────────────── │  · Rules + decoders  │
└──────────────────────┘        policy push / upgrades        └──────────────────────┘
```

- **Manager**: Wazuh all-in-one (manager, indexer, dashboard) on Ubuntu.
- **Endpoint**: Windows host onboarded with the Wazuh agent; log collection for
  security, system and application channels.
- **FIM**: `syscheck` policy watching high-value paths (system32 drivers/hosts,
  startup locations, a honeytoken directory) with real-time mode on the
  most sensitive paths.

## What I actually did

1. **Deployment.** Installed and hardened the manager, enrolled the Windows
   agent over an authenticated channel, verified event flow end to end.
2. **File-integrity monitoring.** Tuned a `syscheck` policy, then generated
   controlled unauthorized changes; the lab surfaced **100+ FIM alerts**, each
   worked from the dashboard.
3. **Alert triage practice.** For every alert: classify (expected change /
   suspicious / noise), document the decision, and track follow-up to closure,
   the same checks-and-assessments loop used in SOC and GRC monitoring work.
4. **Tuning.** Suppressed the noisiest rule matches (temp-file churn) to keep
   the signal reviewable; documented every suppression with a reason, because
   an undocumented exclusion is a future blind spot.

## What it taught me

- **Detection is a documentation discipline.** An alert without a recorded
  triage decision is just noise with a timestamp.
- **FIM policies age.** Watched paths need review as software changes, the
  same lifecycle logic as access reviews, applied to controls.
- **Tuning is risk management.** Every suppression trades alert fatigue against
  blind spots; writing down the "why" is what makes it defensible in an audit.

## Mapped controls

| Practice in this lab | ISO/IEC 27001:2022 |
|---|---|
| Centralised logging | A.8.15 |
| Monitoring & alert review | A.8.16 |
| File-integrity monitoring / change detection | A.8.9, A.8.32 |
| Case documentation & follow-up | A.5.25 |

---

**Darshangiri Goswami** · SecOps · Detection Engineering · Cloud Security ·
[Portfolio](https://darshan2209.github.io/darshangiri-goswami/) ·
[LinkedIn](https://linkedin.com/in/darshangiri-goswami-033283213)
