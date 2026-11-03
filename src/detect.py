"""Hybrid detector: explainable DNS rules + Isolation Forest."""
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from .features import FEATURE_COLS

# Domains known to be legitimately periodic / high-entropy. Extend for your network.
ALLOWLIST_SLD = {"ntp-sync", "fastedge-cdn", "assetsbucket", "imgcache"}


def rule_based(df: pd.DataFrame, use_allowlist=True) -> pd.DataFrame:
    allowed = df["sld"].isin(ALLOWLIST_SLD) if use_allowlist else pd.Series(False, index=df.index)
    r = pd.DataFrame(index=df.index)

    # DGA: random-looking SLD that fails to resolve, or a client spraying NXDOMAINs
    dga_lex = (df["sld_entropy"] >= 3.2) & (df["sld_len"] >= 11) & (df["nx"] == 1)
    dga_beh = (df["client_nx_5m"] >= 15) & (df["client_unique_sld_5m"] >= 15)
    r["dga"] = np.where((dga_lex | dga_beh) & ~allowed, "dga", "")

    # Tunneling: very long labels + many unique FQDNs under one parent domain
    r["tunneling"] = np.where(
        (df["longest_label"] >= 25) & (df["fqdn_per_sld_5m"] >= 10) & ~allowed, "tunneling", "")

    # Beaconing: highly regular intervals to the same domain
    r["beaconing"] = np.where(
        (df["pair_count"] >= 20) & (df["beacon_cv"] < 0.05) & ~allowed, "beaconing", "")

    out = df[["timestamp", "client", "qname", "qtype", "rcode"]].copy()
    out["rule_reason"] = r.apply(lambda x: ",".join(v for v in x if v), axis=1)
    out["rule_flag"] = (out["rule_reason"] != "").astype(int)
    return out


def ml_scores(df: pd.DataFrame, contamination=0.03, seed=42):
    X = StandardScaler().fit_transform(df[FEATURE_COLS])
    model = IsolationForest(n_estimators=300, contamination=contamination,
                            random_state=seed, n_jobs=-1).fit(X)
    return -model.score_samples(X), (model.predict(X) == -1).astype(int)


def run_detection(df, contamination=0.03, use_allowlist=True):
    res = rule_based(df, use_allowlist)
    res["ml_score"], res["ml_flag"] = ml_scores(df, contamination)
    res["alert"] = ((res["rule_flag"] == 1) | (res["ml_flag"] == 1)).astype(int)
    if "is_anomaly" in df:
        res["truth"] = df["is_anomaly"].values
        res["label"] = df["label"].values
    return res
