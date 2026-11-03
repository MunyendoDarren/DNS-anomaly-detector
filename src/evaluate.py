"""Metrics + plots."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.metrics import precision_recall_fscore_support, roc_auc_score


def report(res: pd.DataFrame, outdir="outputs"):
    lines = []
    for name, col in [("Rules", "rule_flag"), ("Isolation Forest", "ml_flag"), ("Hybrid", "alert")]:
        p, r, f, _ = precision_recall_fscore_support(res["truth"], res[col], average="binary", zero_division=0)
        lines.append(f"{name:<18} precision={p:.3f} recall={r:.3f} f1={f:.3f}")
    lines.append(f"Isolation Forest ROC-AUC = {roc_auc_score(res['truth'], res['ml_score']):.3f}")

    lines.append("\nRecall per threat type (hybrid):")
    for lbl, g in res[res["truth"] == 1].groupby("label"):
        lines.append(f"  {lbl:<12} {g['alert'].mean():.2%}  ({len(g)} events)")
    fp = res[(res.truth == 0) & (res.alert == 1)]
    lines.append(f"\nFalse positives (hybrid): {len(fp)} of {(res.truth == 0).sum():,} benign events")

    text = "\n".join(lines)
    print(text)
    with open(f"{outdir}/report.txt", "w") as fh:
        fh.write(text)

    plt.figure(figsize=(8, 4))
    plt.hist(res.loc[res.truth == 0, "ml_score"], bins=60, alpha=.6, label="benign", density=True)
    plt.hist(res.loc[res.truth == 1, "ml_score"], bins=60, alpha=.6, label="malicious", density=True)
    plt.xlabel("Isolation Forest anomaly score"); plt.ylabel("density"); plt.legend()
    plt.title("Anomaly score distribution"); plt.tight_layout()
    plt.savefig(f"{outdir}/score_distribution.png", dpi=150); plt.close()

    top = res[res.alert == 1].groupby("client").size().sort_values(ascending=False).head(10)
    top.plot(kind="bar", figsize=(9, 4), title="Top 10 clients by alert count")
    plt.ylabel("alerts"); plt.tight_layout()
    plt.savefig(f"{outdir}/top_clients.png", dpi=150); plt.close()
