"""Feature engineering: lexical (per-domain) + behavioural (per-client) features."""
import math
from collections import Counter

import numpy as np
import pandas as pd

WINDOW = 300  # seconds (5 min)
VOWELS = set("aeiou")


def entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in Counter(s).values())


def max_consonant_run(s: str) -> int:
    best = cur = 0
    for ch in s:
        cur = cur + 1 if (ch.isalpha() and ch not in VOWELS) else 0
        best = max(best, cur)
    return best


def split_name(qname: str):
    """Naive split: SLD = second-to-last label. (Use `tldextract` for co.uk etc.)"""
    labels = qname.lower().rstrip(".").split(".")
    if len(labels) < 2:
        return labels[0], "", []
    return labels[-2], labels[-1], labels[:-2]


def _windowed_sum(times, values):
    """Sum of values over (t - WINDOW, t] for each event; times must be sorted."""
    cum = np.cumsum(values)
    left = np.searchsorted(times, times - WINDOW, side="right")
    prior = np.where(left > 0, cum[np.maximum(left - 1, 0)], 0)
    return cum - prior


def _window_distinct(times, keys):
    """Number of distinct keys inside the trailing window, per event."""
    lo, counts, out = 0, {}, []
    for i in range(len(times)):
        counts[keys[i]] = counts.get(keys[i], 0) + 1
        while times[i] - times[lo] >= WINDOW:
            k = keys[lo]
            counts[k] -= 1
            if counts[k] == 0:
                del counts[k]
            lo += 1
        out.append(len(counts))
    return out


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp").reset_index(drop=True)
    ts = (df["timestamp"] - pd.Timestamp("1970-01-01")).dt.total_seconds().values

    # ---- lexical features ----
    parts = df["qname"].map(split_name)
    df["sld"] = parts.map(lambda p: p[0])
    df["tld"] = parts.map(lambda p: p[1])
    subs = parts.map(lambda p: p[2])
    sub_str = subs.map("".join)

    df["qname_len"] = df["qname"].str.len()
    df["n_labels"] = df["qname"].str.count(r"\.") + 1
    df["longest_label"] = df["qname"].map(lambda q: max(len(x) for x in q.split(".")))
    df["sld_len"] = df["sld"].str.len()
    df["sld_entropy"] = df["sld"].map(entropy)
    df["sld_digit_ratio"] = df["sld"].map(lambda s: sum(c.isdigit() for c in s) / max(len(s), 1))
    df["sld_vowel_ratio"] = df["sld"].map(lambda s: sum(c in VOWELS for c in s) / max(len(s), 1))
    df["max_cons_run"] = df["sld"].map(max_consonant_run)
    df["sub_entropy"] = sub_str.map(entropy)
    df["is_txt_null"] = df["qtype"].isin(["TXT", "NULL"]).astype(int)
    df["nx"] = (df["rcode"] == "NXDOMAIN").astype(int)

    # ---- behavioural: per client, trailing 5-minute window ----
    n = len(df)
    q_5m, nx_5m, sld_5m = np.zeros(n), np.zeros(n), np.zeros(n)
    for idx in df.groupby("client").indices.values():
        t = ts[idx]
        q_5m[idx] = _windowed_sum(t, np.ones(len(idx)))
        nx_5m[idx] = _windowed_sum(t, df["nx"].values[idx])
        sld_5m[idx] = _window_distinct(t, df["sld"].values[idx])
    df["client_q_5m"], df["client_nx_5m"], df["client_unique_sld_5m"] = q_5m, nx_5m, sld_5m

    # ---- behavioural: distinct FQDNs per (client, SLD) in window (tunneling) ----
    fq = np.zeros(n)
    beacon_cv = np.full(n, 3.0)   # default = "irregular"
    group_n = np.zeros(n)
    for idx in df.groupby(["client", "sld"]).indices.values():
        fq[idx] = _window_distinct(ts[idx], df["qname"].values[idx])
        group_n[idx] = len(idx)
        if len(idx) >= 20:                      # enough samples to judge regularity
            d = np.diff(ts[idx])
            if d.mean() > 0:
                beacon_cv[idx] = d.std() / d.mean()
    df["fqdn_per_sld_5m"], df["beacon_cv"], df["pair_count"] = fq, beacon_cv, group_n
    return df


FEATURE_COLS = [
    "qname_len", "n_labels", "longest_label", "sld_len", "sld_entropy", "sld_digit_ratio",
    "sld_vowel_ratio", "max_cons_run", "sub_entropy", "is_txt_null", "nx", "response_size",
    "client_q_5m", "client_nx_5m", "client_unique_sld_5m", "fqdn_per_sld_5m", "beacon_cv",
]
