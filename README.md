# 🌐 DNS Anomaly Detector

Detects malicious DNS activity from query logs using **explainable rules + an Isolation Forest**.
DNS is a favourite channel for attackers because it is almost never blocked — so it is a
high-value place to hunt.

## Threats detected

| Threat | What it looks like in DNS | Signals used |
|---|---|---|
| **DGA** (domain generation algorithms) | Bursts of random-looking domains that mostly return NXDOMAIN | SLD entropy, length, NXDOMAIN rate per client, distinct SLDs per client |
| **DNS tunneling / exfiltration** | Very long encoded subdomains under one parent domain, TXT/NULL queries, large responses | Longest label, distinct FQDNs per parent domain in 5 min, record type, response size |
| **C2 beaconing** | The same domain queried at near-perfectly regular intervals | Coefficient of variation (std/mean) of inter-query gaps per client+domain |

## Pipeline

```
dns_logs.csv ─► features.py ─► detect.py ─► evaluate.py
                (lexical +      (rules +       (precision/recall,
                 behavioural     Isolation      per-threat recall,
                 features)       Forest)        plots, alerts.csv)
```

**Lexical features:** query length, label count, longest label, Shannon entropy, digit/vowel ratio,
longest consonant run.
**Behavioural features (5-min trailing window per client):** query volume, NXDOMAIN count,
distinct SLDs, distinct FQDNs per SLD, beacon regularity.

## Quick start

```bash
git clone https://github.com/<your-username>/dns-anomaly-detector.git
cd dns-anomaly-detector
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python run_pipeline.py
```

Outputs go to `outputs/`: `alerts.csv`, `report.txt`, `score_distribution.png`, `top_clients.png`.

### Use your own logs

```bash
python run_pipeline.py --input my_dns.csv
```

Required columns: `timestamp, client, qname, qtype, rcode, response_size`.
You can export these from Zeek `dns.log`, Pi-hole, BIND query logs or Windows DNS debug logs.
Add `label` and `is_anomaly` columns to get evaluation metrics.

## Sample results (synthetic: 80,686 events, 3,298 malicious)

```
Rules              precision=0.983 recall=0.973 f1=0.978
Isolation Forest   precision=0.970 recall=0.712 f1=0.821
Hybrid             precision=0.969 recall=0.997 f1=0.983

beaconing 100.00% | dga 99.37% | tunneling 100.00%
```

### The false-positive lesson

The dataset includes a **legitimate periodic domain** (NTP-style, every 30 min) and **CDN hash subdomains**
that look like beacons/DGA. Run with and without the allowlist:

```bash
python run_pipeline.py                  # hybrid precision ≈ 0.97
python run_pipeline.py --no-allowlist   # hybrid precision ≈ 0.52 (~3,000 false positives)
```

Recall barely changes but precision collapses — a real-world reminder that **allowlisting and tuning
matter as much as detection logic**. Edit `ALLOWLIST_SLD` in `src/detect.py`.

## Limitations (be honest about these in interviews)

- Data is **synthetic**; real traffic is messier. Validate on real logs (e.g. CTU-13, Zeek captures).
- SLD extraction is naive (second-to-last label). Use `tldextract` to handle `co.uk`-style suffixes.
- Beacon detection needs ≥20 queries per client+domain, so slow or jittered beacons may evade it.
- Attackers adapt (dictionary-based DGAs defeat entropy checks; low-and-slow tunneling defeats volume checks).

## Ideas to extend

- Supervised DGA classifier (Random Forest / character-level LSTM) on a public DGA dataset
- Add threat-intel enrichment (domain age via WHOIS, VirusTotal lookups)
- Use passive-DNS signals: TTL anomalies, fast-flux IP churn
- Streamlit dashboard or alert forwarding to Slack/SIEM
- Unit tests for the feature functions (`pytest`)

## Structure

```
├── run_pipeline.py
├── requirements.txt
├── src/
│   ├── generate_data.py   # synthetic DNS logs with labelled threats
│   ├── features.py        # lexical + behavioural features
│   ├── detect.py          # rules, allowlist, Isolation Forest
│   └── evaluate.py        # metrics and plots
├── data/
└── outputs/
```

## License
MIT
