# Wazuh SIEM Monitoring & Detection Homelab

A self-built security-monitoring lab: a **Wazuh** manager on Ubuntu with a Windows
endpoint agent, centralised log collection, real-time alerting and a file-integrity
monitoring (FIM) policy — used to practise the alert-triage and case-documentation
workflow that security operations teams run daily.

> 📌 This repository is the **write-up** of the lab: architecture, configuration
> decisions, and what the exercise taught me. It intentionally contains no
> copy-paste dumps of my environment's configs or keys.
>
> Live demo of the workflow (and everything else I build):
> **[darshan2209.github.io/darshangiri-goswami](https://darshan2209.github.io/darshangiri-goswami/)**

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

1. **Deployment** — installed and hardened the manager, enrolled the Windows
   agent over an authenticated channel, verified event flow end to end.
2. **File-integrity monitoring** — tuned a `syscheck` policy, then generated
   controlled unauthorized changes; the lab surfaced **100+ FIM alerts**, each
   worked from the dashboard.
3. **Alert triage practice** — for every alert: classify (expected change /
   suspicious / noise), document the decision, and track follow-up to closure —
   the same checks-and-assessments loop used in SOC and GRC monitoring work.
4. **Tuning** — suppressed the noisiest rule matches (temp-file churn) to keep
   the signal reviewable; documented every suppression with a reason, because
   an undocumented exclusion is a future blind spot.

## What it taught me

- **Detection is a documentation discipline.** An alert without a recorded
  triage decision is just noise with a timestamp.
- **FIM policies age.** Watched paths need review as software changes — the
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

**Darshangiri Goswami** — GRC · SecOps · IAM · AI Security ·
[Portfolio](https://darshan2209.github.io/darshangiri-goswami/) ·
[LinkedIn](https://linkedin.com/in/darshangiri-goswami-033283213)
