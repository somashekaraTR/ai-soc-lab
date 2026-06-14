"""
Generates a synthetic SOC log dataset simulating process/network events.
Includes normal baseline activity and injected malicious patterns
(e.g., brute force, port scans, suspicious process spawns, data exfil).
"""
import pandas as pd
import numpy as np

np.random.seed(42)

def generate_normal(n):
    return pd.DataFrame({
        "src_ip": [f"10.0.0.{np.random.randint(2,50)}" for _ in range(n)],
        "dst_ip": [f"10.0.0.{np.random.randint(50,60)}" for _ in range(n)],
        "dst_port": np.random.choice([80, 443, 53, 22, 3389], n, p=[0.4,0.4,0.1,0.05,0.05]),
        "bytes_sent": np.random.normal(2000, 500, n).clip(100, None),
        "bytes_received": np.random.normal(5000, 1000, n).clip(100, None),
        "login_attempts": np.random.choice([1,1,1,2], n),
        "process_name": np.random.choice(
            ["chrome.exe","explorer.exe","outlook.exe","svchost.exe","teams.exe"], n
        ),
        "duration_sec": np.random.normal(30, 10, n).clip(1, None),
        "label": "normal"
    })

def generate_brute_force(n):
    return pd.DataFrame({
        "src_ip": ["203.0.113.55"]*n,
        "dst_ip": ["10.0.0.10"]*n,
        "dst_port": [3389]*n,
        "bytes_sent": np.random.normal(150, 20, n).clip(50, None),
        "bytes_received": np.random.normal(100, 10, n).clip(50, None),
        "login_attempts": np.random.randint(15, 50, n),
        "process_name": ["svchost.exe"]*n,
        "duration_sec": np.random.normal(2, 0.5, n).clip(0.5, None),
        "label": "brute_force"
    })

def generate_port_scan(n):
    return pd.DataFrame({
        "src_ip": ["198.51.100.23"]*n,
        "dst_ip": [f"10.0.0.{i%60+1}" for i in range(n)],
        "dst_port": np.random.randint(1, 65535, n),
        "bytes_sent": np.random.normal(60, 10, n).clip(40, None),
        "bytes_received": np.random.normal(0, 5, n).clip(0, None),
        "login_attempts": [0]*n,
        "process_name": ["nmap.exe"]*n,
        "duration_sec": np.random.normal(0.2, 0.05, n).clip(0.05, None),
        "label": "port_scan"
    })

def generate_exfil(n):
    return pd.DataFrame({
        "src_ip": [f"10.0.0.{np.random.randint(2,50)}" for _ in range(n)],
        "dst_ip": ["185.220.101.7"]*n,  # suspicious external IP
        "dst_port": [443]*n,
        "bytes_sent": np.random.normal(500000, 100000, n).clip(100000, None),
        "bytes_received": np.random.normal(2000, 500, n).clip(100, None),
        "login_attempts": [1]*n,
        "process_name": np.random.choice(["powershell.exe","cmd.exe","rundll32.exe"], n),
        "duration_sec": np.random.normal(120, 30, n).clip(10, None),
        "label": "data_exfil"
    })

normal = generate_normal(2000)
brute = generate_brute_force(40)
scan = generate_port_scan(30)
exfil = generate_exfil(15)

df = pd.concat([normal, brute, scan, exfil], ignore_index=True)
df = df.sample(frac=1, random_state=42).reset_index(drop=True)  # shuffle

df.to_csv("soc_logs.csv", index=False)
print(f"Generated {len(df)} log entries.")
print(df["label"].value_counts())
