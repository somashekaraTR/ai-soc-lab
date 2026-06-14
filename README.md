# AI SOC Lab — AI-Based Security Operations Center Triage Dashboard

A lightweight, fully local project that demonstrates how AI/ML can be used to automatically detect and triage security alerts in a Security Operations Center (SOC) environment.

## Overview

This project simulates a SOC log pipeline:

1. **Synthetic log generation** — creates realistic network/process logs with normal traffic plus injected attack patterns (brute force, port scans, data exfiltration).
2. **AI-based anomaly detection** — an Isolation Forest model (unsupervised ML) scores every log entry for anomaly likelihood and assigns a 0–100 risk score.
3. **Automated triage** — a rule-based summarizer generates a plain-English explanation and severity rating (Critical / High / Medium / Low) for each flagged alert.
4. **Interactive dashboard** — a self-contained HTML wallboard visualizes KPIs, a live threat feed, detection breakdown by attack class, severity distribution, and a filterable/sortable alert table.

## Tech Stack

- Python 3.10+
- pandas
- scikit-learn (Isolation Forest)
- HTML / CSS / JavaScript (no frameworks, fully self-contained dashboard)

## Project Structure

```
soc_lab_project/
├── generate_logs.py        # Generates synthetic SOC logs (soc_logs.csv)
├── ai_triage.py             # Runs anomaly detection + triage, exports alerts.json/summary.json
├── build_dashboard.py       # Embeds latest data into the dashboard HTML
├── dashboard_template.html  # Dashboard template (used by build_dashboard.py)
├── soc_dashboard.html       # Generated dashboard (open this in a browser)
├── run_soc_lab.bat           # One-click Windows launcher (runs full pipeline + opens dashboard)
└── README.md
```

## How to Run

### 1. Install requirements
```bash
pip install pandas scikit-learn
```

### 2. Run the pipeline
```bash
python generate_logs.py
python ai_triage.py
python build_dashboard.py
```

### 3. View results
Open `soc_dashboard.html` in any browser.

**Windows shortcut:** double-click `run_soc_lab.bat` to run all steps and open the dashboard automatically.

## Sample Results

On a typical run:
- ~2,000+ synthetic log entries analyzed
- ~84 anomalies flagged
- **~98.8% detection rate** on injected malicious events
- 0 false positives on normal traffic

## Detected Attack Patterns

| Attack Type      | Detection Signal                                  |
|-------------------|---------------------------------------------------|
| Brute Force       | High login attempt count in short duration         |
| Port Scan         | Scanning tool process (nmap), many unusual ports   |
| Data Exfiltration | Abnormally large outbound transfer to external IP  |

## Notes

- All data is **synthetic** — generated for educational/demo purposes only.
- The dashboard is a static snapshot; re-run the pipeline to refresh with new random data.
- Designed as a portfolio project for cybersecurity / SOC analyst / AI security roles.

## License

MIT




author by
Somashekara T R
