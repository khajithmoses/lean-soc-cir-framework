# ai_hybrid_pipeline.py
# Hybrid AI prioritisation for incident response:
# - Computes anomaly scores (IsolationForest) on post-optimised times
# - Blends SEV weight with AI score to produce a Hybrid Priority
# - Reorders queue and simulates realistic time savings on the surfaced outliers
# - Recomputes KPI before/after and prints report-ready tables
#
# Outputs:
#   outputs/queue_before.csv
#   outputs/queue_after.csv
#   outputs/kpi_summary.csv
#
# Requirements: pip install pandas numpy scikit-learn

from __future__ import annotations
import os
import math
from dataclasses import dataclass
from typing import List, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

# ---------------------------
# CONFIG (tweak as needed)
# ---------------------------
SEV_WEIGHTS = {"SEV 1": 3.0, "SEV 2": 2.0, "SEV 3": 1.0}
RULE_WEIGHT = 0.80         # weight for rule-based severity
AI_WEIGHT = 0.20           # weight for AI anomaly score
AI_CONTAMINATION = 0.15    # % anomalies IsolationForest expects
TOP_N_STRONG = 6           # top-N anomalies get stronger improvement
TOP_N_MEDIUM = 6           # next-N anomalies get medium improvement
# Improvement assumptions when outliers are handled earlier by hybrid triage:
IMPROVE = {
    "strong": {"mttd": 0.15, "mttr": 0.10, "escalation": 0.15, "response": 0.10},  # 15% MTTD, 10% MTTR etc.
    "medium": {"mttd": 0.08, "mttr": 0.06, "escalation": 0.08, "response": 0.06},
}

# SLA thresholds by severity
SLA = {
    1: {"escalation_min": 10,  "response_h": 1},
    2: {"escalation_min": 30,  "response_h": 4},
    3: {"escalation_min": 240, "response_h": 24},
}

# ---------------------------
# INPUT DATA (30 incidents)
# Post-optimised times from your dataset + SLA times used earlier in Phase 3.5
# ---------------------------
ROWS = [
    # ID, SEV, New_MTTD_h, New_MTTR_h, Escalation_Minutes, Response_Hours
    (1,  "SEV 2",  8.0,  3.0,   25, 3.0),
    (2,  "SEV 1",  5.0,  0.8,    8, 0.8),
    (3,  "SEV 2", 14.0,  3.5,   20, 3.5),
    (4,  "SEV 3",  4.0, 20.0,   60, 20.0),
    (5,  "SEV 1",  1.0,  0.9,    9, 0.9),
    (6,  "SEV 2", 20.0,  4.5,   35, 4.5),
    (7,  "SEV 1",  2.0,  2.0,   15, 2.0),
    (8,  "SEV 2",  6.0,  3.2,   18, 3.2),
    (9,  "SEV 2",  4.0,  3.0,   22, 3.0),
    (10, "SEV 1",  0.5,  0.9,    7, 0.9),
    (11, "SEV 3",  2.5, 23.0,  180, 23.0),
    (12, "SEV 2",  9.0,  3.8,   28, 3.8),
    (13, "SEV 1",  7.5,  0.8,   11, 0.8),
    (14, "SEV 3",  1.2, 25.0,  150, 25.0),
    (15, "SEV 3",  0.4, 20.0,  200, 20.0),
    (16, "SEV 2", 10.5,  4.2,   40, 4.2),
    (17, "SEV 1",  1.6,  1.5,    8, 1.5),
    (18, "SEV 2",  5.0,  3.5,   15, 3.5),
    (19, "SEV 2", 16.0,  3.9,   28, 3.9),
    (20, "SEV 1",  0.8,  0.7,    5, 0.7),
    (21, "SEV 2",  3.5,  3.7,   20, 3.7),
    (22, "SEV 1",  1.2,  0.6,    6, 0.6),
    (23, "SEV 3",  3.0, 26.0,  360, 26.0),
    (24, "SEV 1",  0.9,  0.9,    9, 0.9),
    (25, "SEV 2",  2.0,  3.5,   25, 3.5),
    (26, "SEV 1",  1.2,  1.2,   12, 1.2),
    (27, "SEV 3",  0.8, 22.0,  100, 22.0),
    (28, "SEV 2",  6.5,  3.3,   18, 3.3),
    (29, "SEV 1",  0.8,  0.8,    7, 0.8),
    (30, "SEV 2",  9.5,  3.6,   26, 3.6),
]

# ---------------------------
# DATASTRUCTURES & HELPERS
# ---------------------------
@dataclass
class KPI:
    avg_mttd_h: float
    avg_mttr_h: float
    esc_breaches: int
    resp_breaches: int
    esc_compliance_pct: float
    resp_compliance_pct: float

def compute_kpis(df: pd.DataFrame) -> KPI:
    """Compute avg MTTD, MTTR and SLA compliance metrics."""
    avg_mttd = df["New_MTTD_h"].mean()
    avg_mttr = df["New_MTTR_h"].mean()

    # SLA checks
    def esc_met(row):
        sev_num = int(row["Severity"].split()[-1])
        return row["Escalation_Minutes"] <= SLA[sev_num]["escalation_min"]

    def resp_met(row):
        sev_num = int(row["Severity"].split()[-1])
        return row["Response_Hours"] <= SLA[sev_num]["response_h"]

    esc_ok = df.apply(esc_met, axis=1)
    resp_ok = df.apply(resp_met, axis=1)

    esc_breaches = int((~esc_ok).sum())
    resp_breaches = int((~resp_ok).sum())
    n = len(df)

    return KPI(
        avg_mttd_h=avg_mttd,
        avg_mttr_h=avg_mttr,
        esc_breaches=esc_breaches,
        resp_breaches=resp_breaches,
        esc_compliance_pct=100.0 * (n - esc_breaches) / n,
        resp_compliance_pct=100.0 * (n - resp_breaches) / n,
    )

def normalise_0_1(arr: np.ndarray) -> np.ndarray:
    a_min, a_max = float(arr.min()), float(arr.max())
    if math.isclose(a_min, a_max):
        return np.zeros_like(arr)
    return (arr - a_min) / (a_max - a_min)

# ---------------------------
# 1) Build baseline DataFrame
# ---------------------------
df = pd.DataFrame(ROWS, columns=[
    "ID","Severity","New_MTTD_h","New_MTTR_h","Escalation_Minutes","Response_Hours"
])
df["Base_Severity_Weight"] = df["Severity"].map(SEV_WEIGHTS)

# ---------------------------
# 2) AI anomaly score (unsupervised)
# ---------------------------
X = df[["New_MTTD_h","New_MTTR_h"]].values
iso = IsolationForest(random_state=42, contamination=AI_CONTAMINATION)
iso.fit(X)
raw_scores = -iso.score_samples(X)             # higher => more anomalous
df["AI_Anomaly_Score"] = np.round(normalise_0_1(raw_scores), 3)

# ---------------------------
# 3) Hybrid Priority & Ranking
# ---------------------------
df["Hybrid_Priority"] = np.round(
    RULE_WEIGHT * df["Base_Severity_Weight"] + AI_WEIGHT * df["AI_Anomaly_Score"],
    3
)
# Rule-only priority rank (by severity weight)
df_rule = df.sort_values(["Base_Severity_Weight","ID"], ascending=[False, True]).copy()
df_rule["Rule_Rank"] = np.arange(1, len(df_rule) + 1)

# Hybrid rank (by hybrid priority, then anomaly score)
df_hybrid = df.sort_values(["Hybrid_Priority","AI_Anomaly_Score","ID"],
                           ascending=[False, False, True]).copy()
df_hybrid["Hybrid_Rank"] = np.arange(1, len(df_hybrid) + 1)

# Merge ranks
df_merge = pd.merge(
    df_rule[["ID","Rule_Rank"]],
    df_hybrid[["ID","Hybrid_Rank"]],
    on="ID",
    how="inner"
)
df = pd.merge(df, df_merge, on="ID", how="inner")
df["Rank_Change"] = df["Rule_Rank"] - df["Hybrid_Rank"]  # positive = moved up

# ---------------------------
# 4) BEFORE KPIs (rule-only handling)
# ---------------------------
kpi_before = compute_kpis(df)

# ---------------------------
# 5) Simulate AFTER handling: earlier action on top anomalies
#    - Identify top anomalies by AI score (independent of SEV), apply improvements
# ---------------------------
df_after = df.copy()
top_by_ai = df_after.sort_values("AI_Anomaly_Score", ascending=False).index.tolist()

strong_idx = top_by_ai[:TOP_N_STRONG]
med_idx    = top_by_ai[TOP_N_STRONG:TOP_N_STRONG+TOP_N_MEDIUM]

def apply_improve(row, kind):
    row = row.copy()
    m = IMPROVE[kind]
    # Reduce MTTD / MTTR
    row["New_MTTD_h"]       = row["New_MTTD_h"] * (1.0 - m["mttd"])
    row["New_MTTR_h"]       = row["New_MTTR_h"] * (1.0 - m["mttr"])
    # Reduce escalation / response times proportionally
    row["Escalation_Minutes"] = max(0.0, row["Escalation_Minutes"] * (1.0 - m["escalation"]))
    row["Response_Hours"]     = max(0.0, row["Response_Hours"] * (1.0 - m["response"]))
    return row

df_after.loc[strong_idx] = df_after.loc[strong_idx].apply(lambda r: apply_improve(r, "strong"), axis=1)
df_after.loc[med_idx]    = df_after.loc[med_idx].apply(lambda r: apply_improve(r, "medium"), axis=1)

# ---------------------------
# 6) AFTER KPIs (AI-hybrid handling)
# ---------------------------
kpi_after = compute_kpis(df_after)

# ---------------------------
# 7) PRINT REPORT-READY OUTPUTS
# ---------------------------
def fmt_pct(x: float) -> str:
    return f"{x:.2f}%"

def fmt_h(x: float) -> str:
    return f"{x:.2f} h"

print("\n=== AI‑Hybrid Priority Module (Report View) ===\n")

print("## Before/After KPI Summary (30 incidents)")
print(f"- Average MTTD: Before {fmt_h(kpi_before.avg_mttd_h)}  |  After {fmt_h(kpi_after.avg_mttd_h)}"
      f"  |  Change {(100*(kpi_after.avg_mttd_h/kpi_before.avg_mttd_h - 1)):.1f}%")
print(f"- Average MTTR: Before {fmt_h(kpi_before.avg_mttr_h)}  |  After {fmt_h(kpi_after.avg_mttr_h)}"
      f"  |  Change {(100*(kpi_after.avg_mttr_h/kpi_before.avg_mttr_h - 1)):.1f}%")
print(f"- Escalation SLA Met: Before {fmt_pct(kpi_before.esc_compliance_pct)} "
      f"(breaches={kpi_before.esc_breaches})  |  After {fmt_pct(kpi_after.esc_compliance_pct)} "
      f"(breaches={kpi_after.esc_breaches})")
print(f"- Response   SLA Met: Before {fmt_pct(kpi_before.resp_compliance_pct)} "
      f"(breaches={kpi_before.resp_breaches})  |  After {fmt_pct(kpi_after.resp_compliance_pct)} "
      f"(breaches={kpi_after.resp_breaches})")

# Top-10 reordering table
cols_for_table = ["Rule_Rank","ID","Severity","New_MTTD_h","New_MTTR_h",
                  "AI_Anomaly_Score","Hybrid_Priority","Hybrid_Rank","Rank_Change"]
top10 = df.sort_values("Hybrid_Rank").head(10)[cols_for_table].copy()
# nice rounding
top10["New_MTTD_h"] = top10["New_MTTD_h"].round(2)
top10["New_MTTR_h"] = top10["New_MTTR_h"].round(2)

print("\n## Queue Re‑Ordering (Top‑10)")
print(top10.to_string(index=False))

# Which SLA breaches were “saved”
def identify_breaches(frame: pd.DataFrame) -> set[int]:
    ids = set()
    for _, row in frame.iterrows():
        sev_num = int(row["Severity"].split()[-1])
        esc_ok = row["Escalation_Minutes"] <= SLA[sev_num]["escalation_min"]
        resp_ok = row["Response_Hours"]     <= SLA[sev_num]["response_h"]
        if not esc_ok or not resp_ok:
            ids.add(int(row["ID"]))
    return ids

breach_before = identify_breaches(df)
breach_after  = identify_breaches(df_after)
saved = sorted(list(breach_before - breach_after))

if saved:
    print("\n## SLA Breaches Resolved by AI‑Hybrid")
    print("Incident IDs resolved:", saved)
else:
    print("\n## SLA Breaches Resolved by AI‑Hybrid")
    print("No previously breaching incidents were fully resolved.")

# ---------------------------
# 8) EXPORT CSVs
# ---------------------------
os.makedirs("outputs", exist_ok=True)
df_rule_sorted = df.sort_values("Rule_Rank")
df_hybrid_sorted = df.sort_values("Hybrid_Rank")

df_rule_sorted.to_csv("outputs/queue_before.csv", index=False)
df_hybrid_sorted.to_csv("outputs/queue_after.csv", index=False)

kpi_df = pd.DataFrame([{
    "Avg_MTTD_Before_h": round(kpi_before.avg_mttd_h, 4),
    "Avg_MTTD_After_h":  round(kpi_after.avg_mttd_h, 4),
    "Avg_MTTR_Before_h": round(kpi_before.avg_mttr_h, 4),
    "Avg_MTTR_After_h":  round(kpi_after.avg_mttr_h, 4),
    "Esc_SLA_Before_pct": round(kpi_before.esc_compliance_pct, 2),
    "Esc_SLA_After_pct":  round(kpi_after.esc_compliance_pct, 2),
    "Resp_SLA_Before_pct":round(kpi_before.resp_compliance_pct, 2),
    "Resp_SLA_After_pct": round(kpi_after.resp_compliance_pct, 2),
    "Esc_Breaches_Before": kpi_before.esc_breaches,
    "Esc_Breaches_After":  kpi_after.esc_breaches,
    "Resp_Breaches_Before":kpi_before.resp_breaches,
    "Resp_Breaches_After": kpi_after.resp_breaches,
}])
kpi_df.to_csv("outputs/kpi_summary.csv", index=False)

print("\nCSV files written to ./outputs:")
print(" - outputs/queue_before.csv")
print(" - outputs/queue_after.csv")
print(" - outputs/kpi_summary.csv")
