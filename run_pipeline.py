"""End-to-end: generate (or load) DNS logs -> features -> detect -> evaluate.

Usage:
    python run_pipeline.py                        # synthetic data
    python run_pipeline.py --input my_dns.csv     # your own logs
    python run_pipeline.py --no-allowlist         # see the false-positive impact

Required columns: timestamp, client, qname, qtype, rcode, response_size
(optional: label, is_anomaly -> enables evaluation)
"""
import argparse
import os

import pandas as pd

from src.detect import run_detection
from src.evaluate import report
from src.features import build_features
from src.generate_data import generate


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", help="CSV of DNS events (default: generate synthetic)")
    ap.add_argument("--contamination", type=float, default=0.03)
    ap.add_argument("--no-allowlist", action="store_true")
    a = ap.parse_args()

    os.makedirs("data", exist_ok=True); os.makedirs("outputs", exist_ok=True)
    df = pd.read_csv(a.input) if a.input else generate()
    feats = build_features(df)
    res = run_detection(feats, a.contamination, use_allowlist=not a.no_allowlist)

    alerts = res[res["alert"] == 1].sort_values("ml_score", ascending=False)
    alerts.to_csv("outputs/alerts.csv", index=False)
    print(f"[+] {len(alerts):,} alerts saved -> outputs/alerts.csv\n")
    if "truth" in res:
        report(res)


if __name__ == "__main__":
    main()
