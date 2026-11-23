from pathlib import Path
from collections import defaultdict
import pandas as pd

ROOT = Path(r"E:\iot_dataset")
FEATURES = ROOT / "07_features"
OUT_DIR = ROOT / "08_reports"
OUT_DIR.mkdir(parents=True, exist_ok=True)

PACKETS = FEATURES / "packets_anonymized.tsv"
OUT = OUT_DIR / "contacted_domains.csv"

CHUNK_SIZE = 500_000

usecols = [
    "pcap_file",
    "frame_time_epoch",
    "ip_src",
    "dns_query",
    "http_host",
    "tls_sni"
]

domains = defaultdict(lambda: {
    "count": 0,
    "dns_count": 0,
    "http_count": 0,
    "tls_sni_count": 0,
    "first_seen": None,
    "last_seen": None,
    "source_ips": set(),
    "pcap_files": set()
})

def clean_domain(value):
    if pd.isna(value):
        return ""

    value = str(value).strip().lower().replace('"', "")

    if value == "" or value == "nan":
        return ""

    # If tshark joined multiple values, keep each separately later.
    value = value.strip(".")
    return value

def update_domain(domain, source_type, ts, src_ip, pcap_file):
    if not domain:
        return

    d = domains[domain]

    d["count"] += 1

    if source_type == "dns":
        d["dns_count"] += 1
    elif source_type == "http":
        d["http_count"] += 1
    elif source_type == "tls_sni":
        d["tls_sni_count"] += 1

    if ts is not None:
        if d["first_seen"] is None or ts < d["first_seen"]:
            d["first_seen"] = ts
        if d["last_seen"] is None or ts > d["last_seen"]:
            d["last_seen"] = ts

    if src_ip:
        d["source_ips"].add(src_ip)

    if pcap_file:
        d["pcap_files"].add(pcap_file)

print("Extracting contacted domains...")

reader = pd.read_csv(
    PACKETS,
    sep="\t",
    dtype=str,
    chunksize=CHUNK_SIZE,
    usecols=lambda c: c in usecols,
    low_memory=True
)

for i, chunk in enumerate(reader, start=1):
    print(f"Processing chunk {i}...")

    for col in usecols:
        if col not in chunk.columns:
            chunk[col] = ""

    chunk = chunk.fillna("")

    chunk["frame_time_epoch"] = pd.to_numeric(chunk["frame_time_epoch"], errors="coerce")
    chunk["timestamp"] = pd.to_datetime(chunk["frame_time_epoch"], unit="s", errors="coerce")

    for _, row in chunk.iterrows():
        ts = row["timestamp"]
        src_ip = str(row["ip_src"]).split(",")[0]
        pcap_file = row["pcap_file"]

        # DNS queries
        dns_values = str(row["dns_query"]).split(",")
        for value in dns_values:
            domain = clean_domain(value)
            update_domain(domain, "dns", ts, src_ip, pcap_file)

        # HTTP host
        http_values = str(row["http_host"]).split(",")
        for value in http_values:
            domain = clean_domain(value)
            update_domain(domain, "http", ts, src_ip, pcap_file)

        # TLS SNI
        tls_values = str(row["tls_sni"]).split(",")
        for value in tls_values:
            domain = clean_domain(value)
            update_domain(domain, "tls_sni", ts, src_ip, pcap_file)

rows = []

for domain, d in domains.items():
    rows.append({
        "domain": domain,
        "total_observations": d["count"],
        "dns_count": d["dns_count"],
        "http_count": d["http_count"],
        "tls_sni_count": d["tls_sni_count"],
        "first_seen": d["first_seen"],
        "last_seen": d["last_seen"],
        "unique_source_devices": len(d["source_ips"]),
        "source_devices": ";".join(sorted(d["source_ips"])),
        "pcap_files": ";".join(sorted(d["pcap_files"]))
    })

df = pd.DataFrame(rows)

if len(df) > 0:
    df = df.sort_values("total_observations", ascending=False)

df.to_csv(OUT, index=False, encoding="utf-8")

print("Done.")
print(f"Extracted domains: {len(df)}")
print(f"Wrote: {OUT}")