# Incident Response Log
> Aligned to NIST SP 800-61 Rev. 2 and ISO/IEC 27035
> Complete all fields during or immediately after the incident. PIR section to be completed within the deadline set by your SLA config.

---

## 1. Incident Identification

| Field | Value |
|---|---|
| **Incident ID** | IR-[YYYY]-[NNN] (e.g. IR-2025-001) |
| **Date/Time Detected** | YYYY-MM-DD HH:MM |
| **Date/Time Reported** | YYYY-MM-DD HH:MM |
| **Detected By** | Analyst name / SIEM alert / Automated tool |
| **Reported By** | Name and role |
| **Assigned Analyst** | |
| **Incident Status** | Open / In Progress / Contained / Closed |

---

## 2. Incident Classification

| Field | Value |
|---|---|
| **Incident Type** | Phishing / Ransomware / Insider Threat / DDoS / Misconfiguration / Other |
| **Severity** | SEV1 (Critical) / SEV2 (High) / SEV3 (Medium) |
| **Severity Score** | [Calculated from weighted matrix — see config/] |
| **Asset Affected** | System / application / data store name |
| **Asset Value** | High / Medium / Low |
| **Data Sensitivity** | High (PII/PHI) / Medium / Low |
| **User Role Involved** | Admin / Standard User / External |
| **MITRE ATT&CK Technique** | e.g. T1566 (Phishing) |

---

## 3. Incident Description

**Summary** *(What happened, in plain language)*

> [Write a 2–4 sentence description here]

**Detection Source** *(How was this detected?)*

> [SIEM alert / User report / External notification / Automated scan]

**Initial Indicators of Compromise (IOCs)**

| Indicator | Type | Value |
|---|---|---|
| | IP Address | |
| | File Hash | |
| | Domain/URL | |
| | Email Address | |

---

## 4. Timeline

| Time | Action | By Whom |
|---|---|---|
| HH:MM | Incident detected | |
| HH:MM | Incident acknowledged | |
| HH:MM | Initial triage completed | |
| HH:MM | Escalated to [role] | |
| HH:MM | Containment action taken | |
| HH:MM | Eradication completed | |
| HH:MM | Recovery completed | |
| HH:MM | Incident closed | |

---

## 5. Response Actions

**Containment Actions** *(What did you do to stop the spread?)*

- [ ]
- [ ]
- [ ]

**Eradication Actions** *(What did you do to remove the threat?)*

- [ ]
- [ ]
- [ ]

**Recovery Actions** *(How were systems restored?)*

- [ ]
- [ ]
- [ ]

---

## 6. Impact Assessment

| Field | Value |
|---|---|
| **Systems Affected** | |
| **Users Affected** | Number / Names if relevant |
| **Data Compromised?** | Yes / No / Unknown |
| **Data Types Compromised** | PII / Financial / Health / IP / None |
| **Estimated Downtime** | |
| **Estimated Financial Impact** | |
| **GDPR Breach?** | Yes / No / Under Assessment |
| **DPC Notification Required?** | Yes (within 72 hrs) / No |

---

## 7. SLA Compliance Check

| SLA Metric | Target (from config) | Actual | Met? |
|---|---|---|---|
| Acknowledgement Time | | | Yes / No |
| Escalation Time | | | Yes / No |
| Containment Time | | | Yes / No |
| Documentation Deadline | | | Yes / No |

---

## 8. Root Cause Analysis

**Root Cause** *(Why did this happen?)*

> [e.g. Unpatched vulnerability in VPN client / User clicked phishing link / Misconfigured S3 bucket permissions]

**Contributing Factors**

> [e.g. Lack of MFA / No phishing awareness training / Delayed patching cycle]

---

## 9. Post-Incident Review (PIR)

> Complete this section within the deadline specified in your SLA config. Required for all SEV1 and SEV2 incidents.

**PIR Completed By:** _______________
**PIR Date:** _______________

**What went well?**

>

**What could have been done better?**

>

**Lessons Learned**

>

**Action Items to Prevent Recurrence**

| Action | Owner | Deadline | Status |
|---|---|---|---|
| | | | |
| | | | |

---

## 10. Sign-Off

| Role | Name | Signature | Date |
|---|---|---|---|
| Lead Analyst | | | |
| SOC Manager / IT Lead | | | |
| DPO (if data breach) | | | |

---

*Template version 1.0 — Lean SOC CIR Framework | github.com/khajithmoses/lean-soc-cir-framework*
