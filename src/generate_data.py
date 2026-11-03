"""Generate synthetic DNS query logs with labelled threats.

Benign: Zipf-popular domains, some CDN hash subdomains, typo NXDOMAINs,
        and a legitimately periodic NTP-style domain (a false-positive trap).
Threats: DGA bursts, DNS tunneling (exfiltration), C2 beaconing.
"""
import string

import numpy as np
import pandas as pd

WORDS = ("cloud mail shop zone data news tech sky blue green fast safe smart web net "
         "media music video game book travel food health bank pay secure open mobile "
         "photo social learn code dev work home market trade star sun moon river").split()
TLDS = ["com", "org", "net", "io"]
SUBS = ["", "", "", "www", "mail", "api", "cdn", "static"]
START = pd.Timestamp("2026-01-01")


def _rand_str(rng, n, alphabet=string.ascii_lowercase):
    return "".join(rng.choice(list(alphabet), n))


def generate(n_clients=100, days=3, out="data/dns_logs.csv", seed=42):
    rng = np.random.default_rng(seed)
    clients = [f"10.0.{i // 250}.{i % 250 + 1}" for i in range(n_clients)]
    rows = []

    def add(ts, client, qname, qtype, rcode, size, label):
        rows.append((ts, client, qname, qtype, rcode, int(size), label))

    # ---------- benign ----------
    domains = list({f"{rng.choice(WORDS)}{rng.choice(WORDS)}.{rng.choice(TLDS)}" for _ in range(400)})
    pop = 1 / np.arange(1, len(domains) + 1); pop /= pop.sum()
    cdn_domains = ["fastedge-cdn.net", "assetsbucket.io", "imgcache.org"]

    for c in clients:
        for d in range(days):
            n = int(rng.integers(150, 350))
            hours = np.clip(rng.normal(13, 3.5, n), 0, 23.99)
            for h in hours:
                ts = START + pd.Timedelta(days=d, hours=float(h))
                if rng.random() < 0.03:                     # CDN hash subdomain
                    q = f"{_rand_str(rng, 16, '0123456789abcdef')}.{rng.choice(cdn_domains)}"
                else:
                    q = f"{rng.choice(SUBS)}.{rng.choice(domains, p=pop)}".lstrip(".")
                nx = rng.random() < 0.02
                add(ts, c, q, str(rng.choice(["A", "AAAA"], p=[.7, .3])),
                    "NXDOMAIN" if nx else "NOERROR", rng.integers(60, 180), "benign")

    # legit periodic traffic (NTP-like), every 30 min from 20 clients
    for c in clients[:20]:
        t = START + pd.Timedelta(seconds=float(rng.integers(0, 1800)))
        while t < START + pd.Timedelta(days=days):
            add(t, c, "time.ntp-sync.org", "A", "NOERROR", 90, "benign")
            t += pd.Timedelta(seconds=1800 + float(rng.normal(0, 3)))

    # ---------- threat 1: DGA bursts ----------
    for c in rng.choice(clients[20:], 6, replace=False):
        for _ in range(int(rng.integers(3, 6))):
            t0 = START + pd.Timedelta(days=int(rng.integers(0, days)), hours=float(rng.uniform(0, 23)))
            for k in range(int(rng.integers(30, 80))):
                q = f"{_rand_str(rng, int(rng.integers(12, 22)))}.{rng.choice(['com', 'net', 'biz', 'xyz'])}"
                nx = rng.random() < 0.95
                add(t0 + pd.Timedelta(seconds=float(k * rng.uniform(0.5, 3))), c, q, "A",
                    "NXDOMAIN" if nx else "NOERROR", 100, "dga")

    # ---------- threat 2: DNS tunneling ----------
    for c in rng.choice(clients[20:], 3, replace=False):
        t0 = START + pd.Timedelta(days=int(rng.integers(0, days)), hours=float(rng.uniform(0, 22)))
        for k in range(int(rng.integers(150, 300))):
            payload = f"{_rand_str(rng, 30, string.ascii_lowercase + '234567')}." \
                      f"{_rand_str(rng, 28, string.ascii_lowercase + '234567')}"
            add(t0 + pd.Timedelta(seconds=float(k * rng.uniform(1, 3))), c,
                f"{payload}.t.exfil-dns.xyz", str(rng.choice(["TXT", "NULL"])),
                "NOERROR", rng.integers(250, 500), "tunneling")

    # ---------- threat 3: C2 beaconing (fixed 60 s interval, tiny jitter) ----------
    for c in rng.choice(clients[20:], 3, replace=False):
        t = START + pd.Timedelta(days=int(rng.integers(0, days)), hours=float(rng.uniform(0, 12)))
        for _ in range(360):
            add(t, c, "update-check-svc.top", "A", "NOERROR", 64, "beaconing")
            t += pd.Timedelta(seconds=60 + float(rng.normal(0, 0.4)))

    df = pd.DataFrame(rows, columns=["timestamp", "client", "qname", "qtype",
                                     "rcode", "response_size", "label"])
    df = df.sort_values("timestamp").reset_index(drop=True)
    df["is_anomaly"] = (df["label"] != "benign").astype(int)
    df.to_csv(out, index=False)
    print(f"[+] Wrote {len(df):,} DNS events ({df.is_anomaly.sum():,} malicious) -> {out}")
    return df


if __name__ == "__main__":
    generate()
