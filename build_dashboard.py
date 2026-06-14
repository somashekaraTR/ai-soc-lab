"""
Rebuilds soc_dashboard.html by embedding the latest alerts.json + summary.json
into the dashboard template (dashboard_template.html).

Run this AFTER ai_triage.py to refresh the dashboard with new data.
"""
import json

with open("alerts.json", encoding="utf-8") as f:
    alerts = json.load(f)
with open("summary.json", encoding="utf-8") as f:
    summary = json.load(f)

with open("dashboard_template.html", encoding="utf-8") as f:
    html = f.read()

data_js = f"const ALERTS = {json.dumps(alerts)};\nconst SUMMARY = {json.dumps(summary)};\n"

html = html.replace('<script src="data.js"></script>', f'<script>\n{data_js}</script>')

with open("soc_dashboard.html", "w", encoding="utf-8") as f:
    f.write(html)

print(f"soc_dashboard.html updated with {len(alerts)} alerts.")
print("Open soc_dashboard.html in your browser.")
