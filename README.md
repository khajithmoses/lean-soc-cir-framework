# Lean SOC CIR Framework

> A lightweight, data-driven Cybersecurity Incident Response framework for lean Security Operations Centres — without the enterprise price tag.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![NIST SP 800-61](https://img.shields.io/badge/Aligned-NIST%20SP%20800--61-green)](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
[![ISO 27035](https://img.shields.io/badge/Aligned-ISO%2027035-green)](https://www.iso.org/standard/60803.html)
[![Dataset on Kaggle](https://img.shields.io/badge/Dataset-Kaggle-blue)](https://www.kaggle.com/datasets/khajithmoses/ireland-cyber-incident-dataset)

---

## The Problem

Enterprise SOAR platforms (Splunk Phantom, Palo Alto Cortex XSOAR, IBM QRadar) cost €50,000–€200,000+ per year. Small hospitals, SMEs, universities, local government bodies, and public sector organisations cannot afford them — so they end up with no structured incident response process at all.

When an attack hits, they have no clear way to decide what to deal with first, who to call, or how to document what happened. Detection is slow. Response is chaotic. Lessons are never captured.

**This framework is built for them.**

---

## What It Does

The Lean SOC CIR Framework gives resource-constrained security teams a structured, transparent, and customisable incident response system:

- **Weighted Severity Classification** — Scores incidents based on asset value, data sensitivity, user role, and alert timing (SEV1/SEV2/SEV3)
- **YAML-Driven SLA Escalation** — Configurable acknowledgment and escalation timelines per severity level, adaptable to any organisation type
- **AI-Hybrid Queue Prioritisation** — Blends rule-based severity scoring with IsolationForest anomaly detection to surface unusual incidents that rules alone might miss
- **Compliance-Ready Documentation Templates** — Pre-structured incident logs aligned to ISO 27035 and NIST SP 800-61, reducing analyst workload
- **KPI Benchmarking** — Tracks MTTD, MTTR, Documentation Rate, and PIR Completion to measure and improve SOC performance over time

---

## Why This Instead of a SOAR?

| Feature | Enterprise SOAR | This Framework |
|---|---|---|
| Cost | €50k–€200k/year | Free, open source |
| Setup time | Weeks with vendor support | Under 30 minutes |
| Customisation | Vendor-locked | Edit a YAML file |
| Transparency | Black box automation | Human-readable rules |
| Compliance audit | Complex | YAML rules are directly auditable |
| Works without SIEM | No | Yes |
| Team size needed | 5–10 analysts | 1–2 analysts |

---

## Quick Start

```bash
# Clone the repo
git clone https://github.com/khajithmoses/lean-soc-cir-framework.git
cd lean-soc-cir-framework

# Install dependencies
pip install -r requirements.txt

# Run the AI hybrid prioritisation pipeline
python src/ai_hybrid_pipeline.py
```

Outputs will be saved to the `outputs/` folder:
- `queue_before.csv` — incident queue using rule-based ranking only
- `queue_after.csv` — incident queue after AI-hybrid re-prioritisation
- `kpi_summary.csv` — before/after KPI comparison

---

## Customise for Your Organisation

Open the relevant YAML config file in `config/` and adjust the SLA thresholds to match your team's requirements:

```yaml
# config/sla_sme.yaml
SEV1:
  InitialResponder: SOC Tier 1 Analyst
  AckSLA: 15 min
  EscalationSLA: 30 min
  FinalEscalation: SOC Manager

SEV2:
  InitialResponder: SOC Tier 1 Analyst
  AckSLA: 30 min
  EscalationSLA: 1 hr
  FinalEscalation: SOC Manager

SEV3:
  InitialResponder: SOC Tier 1 Analyst
  AckSLA: 1 hr
  EscalationSLA: 4 hrs
  FinalEscalation: IT Support Lead
```

Three pre-built configs are included: `sla_sme.yaml`, `sla_hospital.yaml`, `sla_university.yaml`. No coding required to customise them.

---

## Project Structure

```
lean-soc-cir-framework/
├── src/
│   └── ai_hybrid_pipeline.py     # AI-hybrid incident prioritisation engine
├── config/
│   ├── sla_sme.yaml              # SLA config for small/medium enterprises
│   ├── sla_hospital.yaml         # SLA config for healthcare organisations
│   └── sla_university.yaml       # SLA config for universities / education
├── templates/
│   └── incident_response_template.md  # Compliance-ready IR documentation template
├── data/
│   └── README.md                 # Dataset info + Kaggle link
├── outputs/                      # Generated CSV outputs (git-ignored)
├── requirements.txt
└── README.md
```

---

## The Dataset

This framework was developed and validated using the **Ireland Cyber Incident Dataset** — 30 annotated cybersecurity incidents relevant to Irish SMEs and public sector organisations, aligned to MITRE ATT&CK, NIST SP 800-61, and ISO 27035.

[View and download the dataset on Kaggle](https://www.kaggle.com/datasets/khajithmoses/ireland-cyber-incident-dataset)

---

## KPI Results (Simulation Study)

The framework was validated through a simulation study using the Ireland Cyber Incident Dataset. Results compared a baseline (manual/unstructured process) against the optimised framework:

| Metric | Baseline | With Framework | Improvement |
|---|---|---|---|
| Mean Time to Detect (MTTD) | 20.14 hrs | 15.18 hrs | ↓ 24.65% |
| Mean Time to Respond (MTTR) | 6.0 hrs | 4.0 hrs | ↓ 33.33% |
| Documentation Rate | 60% | 76.67% | ↑ 27.78% |
| PIR Completion | 30% | 46.67% | ↑ 55.57% |

> **Note:** These results are from a simulation study using synthetic data, not a live SOC deployment. They represent projected improvements based on the framework's structured workflow. Real-world validation is ongoing.

---

## Standards Alignment

- **NIST SP 800-61 Rev. 2** — Computer Security Incident Handling Guide
- **ISO/IEC 27035** — Information Security Incident Management
- **GDPR** — Documentation templates support breach reporting requirements
- **MITRE ATT&CK** — Dataset incidents mapped to ATT&CK techniques

---

## Research Background

This framework was developed as part of an MSc in Software Design with Cybersecurity at the Technological University of the Shannon (TUS), Athlone, Ireland. A companion paper formatted for IEEE conference submission is in preparation.

**Research areas:** Lean SOC optimisation · Cybersecurity Incident Response · MTTD/MTTR improvement · YAML-driven escalation · AI-assisted triage

---

## Roadmap

- [ ] Wazuh alert ingestion integration
- [ ] Real-time YAML SLA violation alerts
- [ ] Web-based dashboard for KPI tracking
- [ ] Expanded dataset (50–100 incidents)
- [ ] SIEM connector (Elastic/Splunk)
- [ ] Peer-reviewed publication

---

## Contributing

Contributions are welcome, especially from SOC practitioners and researchers working in lean environments. If you work in a small SOC and want to share feedback, open an issue — that input directly improves the framework.

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes
4. Open a pull request

---

## License

MIT License — free to use, modify, and distribute. See [LICENSE](LICENSE) for details.

---

## Author

**Khajith Moses Alikana**
MSc Software Design with Cybersecurity — Technological University of the Shannon, Ireland
[LinkedIn](https://www.linkedin.com/in/khajithmoses) · [Kaggle Dataset](https://www.kaggle.com/datasets/khajithmoses/ireland-cyber-incident-dataset) · [GitHub](https://github.com/khajithmoses)
