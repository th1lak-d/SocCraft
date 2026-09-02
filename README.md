# SocCraft

**An AI-augmented, open-source SOC framework with SOAR capabilities — built to take incident response from detection to remediation in under 15 seconds.**

![SocCraft Demo](https://github.com/th1lak-d/SocCraft/raw/main/assets/github1.gif)

---

## Why I built this

Manual SOC triage doesn't scale. An analyst manually investigating a suspicious file drop typically has to correlate logs across multiple tools, pivot into threat intel lookups, and decide on a remediation action — a process that can take anywhere from several minutes to hours depending on queue depth and alert fatigue.

I built SocCraft to answer a specific question: **how much of that pipeline can be automated end-to-end, without losing the judgment calls that matter?** The goal wasn't to remove the analyst — it's to compress the mechanical parts of the workflow (detection → enrichment → risk scoring → proportionate response) so a human only steps in where it counts.

This project is my hands-on lab for building the kind of detection and response tooling used in real SOC/MSSP environments — end to end, on infrastructure I stood up and configured myself.

---

## 🚀 Key Features

- **End-to-End Automation** — a fully automated pipeline from initial file detection to final remediation in under 15 seconds.
- **AI-Gated, Risk-Based Response** — autonomously executes proportionate actions (**Monitor**, **Quarantine**, or **Delete**) based on AI-determined risk level, rather than one-size-fits-all blocking.
- **Resilient Hash-Based Detection** — relies on immutable file hashes, effective against simple evasion techniques like renaming malware.
- **Hybrid AI Model** — a local LLM (Ollama/Llama3) handles privacy-sensitive analysis on-box; Amazon Bedrock handles heavier-weight risk assessment in the cloud.
- **Proactive Anomaly Detection** — unsupervised ML (Random Cut Forest) surfaces "unknown unknowns" that signature-based tools miss.

---

## 🏗️ Architecture

SocCraft integrates a layered stack of best-in-class open-source security tooling, connected through a custom SOAR automation layer.

![SOCCraft System Architecture](https://github.com/th1lak-d/SocCraft/raw/main/docs/images/soccraft.png)

**Pipeline, at a glance:**
`Detection (Wazuh / Suricata / Velociraptor) → Enrichment (MISP / VirusTotal) → Risk Scoring (RCF + AI) → Automated Response (Shuffle SOAR)`

---

## 🛠️ Technology Stack

| Layer | Tools |
|---|---|
| SIEM / EDR | Wazuh, OpenSearch, Velociraptor |
| SOAR & Automation | Shuffle, custom Python |
| AI & ML | Amazon Bedrock, Ollama (Llama3), Random Cut Forest |
| Network Security | Suricata |
| Threat Intelligence | MISP, VirusTotal |
| Deployment | Docker, NGINX, QEMU/KVM |

---

## 📊 Performance Results

Each scenario below was run against a controlled lab environment and validated against MITRE ATT&CK techniques, measuring end-to-end time from first detection event to final automated remediation action.

| Threat Scenario | MITRE ATT&CK Technique | Total Time (s) |
|---|---|---|
| SSH Brute Force Attack | T1110 – Brute Force | 2.700 |
| Malicious File Drop (Critical) | T1204 – User Execution | 11.996 |
| Webshell Deployment | T1505.003 – Web Shell | 10.221 |
| **Average Total Time** | | **12.489** |

*Baseline for comparison: manual SOC triage of an equivalent alert — correlating logs, checking threat intel, and deciding on remediation — commonly takes 15–30+ minutes depending on analyst workload. This isn't a controlled A/B benchmark against a live SOC team; it's a comparison against typical documented manual triage timelines, and I'd treat it as directional rather than a guaranteed multiplier in every environment.*

---

## 🧠 What I learned building this

- **Correlation is harder than detection.** Getting Wazuh, Suricata, and Velociraptor to agree on "this is one incident, not three separate alerts" required more tuning than the initial detection rules themselves.
- **AI risk-scoring needs guardrails, not just a model.** Early versions of the risk-gating logic over-escalated benign anomalies; adding confidence thresholds and a human-review path for medium-risk cases fixed most false positives.
- **SOAR automation is a workflow design problem before it's a coding problem.** The hardest part wasn't writing the Shuffle workflows — it was deciding *which* actions were safe to fully automate versus which needed a human in the loop.

---

## 🎬 Demo

See SocCraft detect, investigate, and remediate a live threat scenario end-to-end:

[![SOCCraft Demo](https://github.com/th1lak-d/SocCraft/raw/main/assets/github1.gif)](https://github.com/th1lak-d/SocCraft/blob/main/assets/github1.gif)

---

## Roadmap

- [ ] Expand MITRE ATT&CK scenario coverage beyond the current three
- [ ] Add a lightweight analyst-facing dashboard for medium-risk review queue
- [ ] Document lab setup steps for others to reproduce the environment

---

## License

MIT
