"""
AI-based SOC alert triage demo.

1. Trains an Isolation Forest (unsupervised anomaly detection) on SOC logs.
2. Scores every log entry for "anomaly likelihood".
3. Flags top anomalies as alerts.
4. Generates a plain-English triage summary + severity rating for each alert
   (rule-based summarizer here, but designed as a drop-in slot for an LLM call).
"""
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder, StandardScaler

df = pd.read_csv("soc_logs.csv")

# ---- Feature engineering ----
features = df.copy()
le_proc = LabelEncoder()
features["process_enc"] = le_proc.fit_transform(features["process_name"])

le_dst = LabelEncoder()
features["dst_ip_enc"] = le_dst.fit_transform(features["dst_ip"])

feature_cols = [
    "dst_port", "bytes_sent", "bytes_received",
    "login_attempts", "duration_sec", "process_enc", "dst_ip_enc"
]

X = features[feature_cols]
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# ---- Train Isolation Forest ----
model = IsolationForest(
    n_estimators=200,
    contamination=0.04,   # expect ~4% anomalies
    random_state=42
)
model.fit(X_scaled)

# anomaly_score: lower = more anomalous. We convert to 0-100 "risk score"
raw_scores = model.decision_function(X_scaled)
df["anomaly_score_raw"] = raw_scores
df["risk_score"] = (
    (raw_scores.max() - raw_scores) / (raw_scores.max() - raw_scores.min()) * 100
).round(1)
df["predicted_anomaly"] = model.predict(X_scaled)  # -1 = anomaly, 1 = normal

alerts = df[df["predicted_anomaly"] == -1].sort_values("risk_score", ascending=False)

# ---- Rule-based "LLM-style" triage summary generator ----
def triage_summary(row):
    reasons = []
    if row["login_attempts"] > 10:
        reasons.append(f"{int(row['login_attempts'])} login attempts in a short window — possible brute force")
    if row["bytes_sent"] > 100000:
        reasons.append(f"unusually large outbound transfer ({int(row['bytes_sent']):,} bytes) to {row['dst_ip']} — possible data exfiltration")
    if row["process_name"] in ["nmap.exe"]:
        reasons.append("scanning tool detected (nmap.exe) — possible reconnaissance/port scan")
    if row["dst_port"] not in [80,443,53,22,3389] and row["bytes_received"] < 5:
        reasons.append(f"connection to unusual port {int(row['dst_port'])} with minimal response — possible scan probe")
    if row["process_name"] in ["powershell.exe","cmd.exe","rundll32.exe"] and row["bytes_sent"] > 50000:
        reasons.append(f"{row['process_name']} initiating large data transfer — suspicious script-based exfil")

    if not reasons:
        reasons.append("statistical outlier in traffic pattern — manual review recommended")

    if row["risk_score"] > 90:
        severity = "Critical"
    elif row["risk_score"] > 75:
        severity = "High"
    elif row["risk_score"] > 60:
        severity = "Medium"
    else:
        severity = "Low"

    return severity, "; ".join(reasons)

alerts[["severity","triage_reason"]] = alerts.apply(
    lambda r: pd.Series(triage_summary(r)), axis=1
)

# ---- Output ----
print(f"Total logs analyzed: {len(df)}")
print(f"Flagged anomalies: {len(alerts)}\n")

print("=== TOP 10 AI-PRIORITIZED ALERTS ===\n")
display_cols = ["risk_score","severity","src_ip","dst_ip","dst_port",
                 "process_name","login_attempts","bytes_sent","triage_reason","label"]
top10 = alerts[display_cols].head(10)
for i, row in top10.iterrows():
    print(f"[Risk: {row['risk_score']:>5.1f}] [{row['severity']:>8}] "
          f"{row['src_ip']} -> {row['dst_ip']}:{int(row['dst_port'])} | proc={row['process_name']}")
    print(f"   Reason: {row['triage_reason']}")
    print(f"   (Ground truth label: {row['label']})\n")

# Detection accuracy vs ground truth
true_malicious = df["label"] != "normal"
detected = df["predicted_anomaly"] == -1
tp = (true_malicious & detected).sum()
fn = (true_malicious & ~detected).sum()
fp = (~true_malicious & detected).sum()
print("=== DETECTION PERFORMANCE vs GROUND TRUTH ===")
print(f"True Positives (malicious correctly flagged): {tp}")
print(f"False Negatives (malicious missed): {fn}")
print(f"False Positives (normal flagged as anomaly): {fp}")
print(f"Detection rate on malicious events: {tp/(tp+fn)*100:.1f}%")

alerts.to_csv("ai_alerts_output.csv", index=False)
print("\nFull alert list saved to ai_alerts_output.csv")

# ---- Export JSON for the dashboard ----
import json

alerts_sorted = alerts.sort_values("risk_score", ascending=False)
alerts_records = alerts_sorted[
    ["src_ip","dst_ip","dst_port","bytes_sent","bytes_received","login_attempts",
     "process_name","duration_sec","label","risk_score","severity","triage_reason"]
].to_dict("records")

summary = {
    "total": int(len(df)),
    "flagged": int(len(alerts)),
    "by_severity": alerts["severity"].value_counts().to_dict(),
    "by_label": df["label"].value_counts().to_dict(),
    "avg_risk": float(alerts["risk_score"].mean()),
    "detection_rate": round(tp/(tp+fn)*100, 1) if (tp+fn) > 0 else 0
}

with open("alerts.json", "w", encoding="utf-8") as f:
    json.dump(alerts_records, f)

with open("summary.json", "w", encoding="utf-8") as f:
    json.dump(summary, f)

print("Dashboard data exported to alerts.json and summary.json")
print("Open soc_dashboard.html in your browser to view results.")
