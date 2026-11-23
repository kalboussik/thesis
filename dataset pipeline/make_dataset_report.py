from pathlib import Path
import pandas as pd

ROOT = Path(r"E:\iot_dataset")
FEATURES = ROOT / "07_features"
OUT = ROOT / "08_reports"
OUT.mkdir(parents=True, exist_ok=True)

summary_file = FEATURES / "summary_statistics.txt"
protocol_file = FEATURES / "protocol_distribution.csv"
device_file = FEATURES / "device_stats.csv"
ports_file = FEATURES / "top_ports.csv"
ts_1h_file = FEATURES / "timeseries_1h.csv"

report_file = OUT / "dataset_report.md"

summary_text = summary_file.read_text(encoding="utf-8")

protocols = pd.read_csv(protocol_file)
devices = pd.read_csv(device_file)
ports = pd.read_csv(ports_file)
ts = pd.read_csv(ts_1h_file)

# Clean / sort
protocols = protocols.sort_values("packets", ascending=False)
devices = devices.sort_values("total_bytes", ascending=False)
ports = ports.sort_values("packets", ascending=False)

# Extra traffic statistics
ts["timestamp"] = pd.to_datetime(ts["timestamp"], errors="coerce")
peak_bytes_hour = ts.loc[ts["bytes"].idxmax()] if len(ts) else None
peak_packets_hour = ts.loc[ts["packets"].idxmax()] if len(ts) else None

total_packets = devices["total_packets"].sum()
total_bytes = devices["total_bytes"].sum()

# Derived device ratios
devices["upload_download_ratio"] = devices["bytes_sent"] / devices["bytes_received"].replace(0, pd.NA)
devices["traffic_share_percent"] = devices["total_bytes"] / devices["total_bytes"].sum() * 100

top_devices = devices.head(10).copy()
top_protocols = protocols.head(10).copy()
top_ports = ports.head(20).copy()

# Save top tables separately
top_protocols.to_csv(OUT / "table_top_protocols.csv", index=False)
top_devices.to_csv(OUT / "table_top_devices.csv", index=False)
top_ports.to_csv(OUT / "table_top_ports.csv", index=False)

with open(report_file, "w", encoding="utf-8") as f:
    f.write("# IoT Dataset Preliminary Report\n\n")

    f.write("## 1. Global Summary\n\n")
    f.write("```text\n")
    f.write(summary_text)
    f.write("\n```\n\n")

    f.write("## 2. Protocol Distribution\n\n")
    f.write(top_protocols.to_markdown(index=False))
    f.write("\n\n")

    f.write("## 3. Top Devices by Traffic Volume\n\n")
    f.write(top_devices[[
        "device_ip",
        "packets_sent",
        "packets_received",
        "bytes_sent",
        "bytes_received",
        "total_packets",
        "total_bytes",
        "unique_destinations_contacted",
        "traffic_share_percent",
        "upload_download_ratio"
    ]].to_markdown(index=False))
    f.write("\n\n")

    f.write("## 4. Top Destination Ports\n\n")
    f.write(top_ports.to_markdown(index=False))
    f.write("\n\n")

    f.write("## 5. Hourly Traffic Peaks\n\n")
    if peak_bytes_hour is not None:
        f.write(f"- Peak byte-volume hour: {peak_bytes_hour['timestamp']}\n")
        f.write(f"- Bytes in peak hour: {int(peak_bytes_hour['bytes'])}\n")
        f.write(f"- Packets in peak byte-volume hour: {int(peak_bytes_hour['packets'])}\n\n")

    if peak_packets_hour is not None:
        f.write(f"- Peak packet-volume hour: {peak_packets_hour['timestamp']}\n")
        f.write(f"- Packets in peak hour: {int(peak_packets_hour['packets'])}\n")
        f.write(f"- Bytes in peak packet-volume hour: {int(peak_packets_hour['bytes'])}\n\n")

    f.write("## 6. Initial Interpretation\n\n")
    f.write(
        "The dataset represents real-world smart-home IoT traffic captured over approximately "
        "twelve days. The traffic volume and packet count are sufficient for baseline behavioral "
        "profiling, device-level traffic characterization, and future comparison against attack scenarios. "
        "The anonymized device identifiers preserve per-device behavior while protecting the original home network addresses.\n\n"
    )

    f.write("## 7. Notes for Publication\n\n")
    f.write("- Raw PCAP files should not be published.\n")
    f.write("- The private anonymization mapping file must not be published.\n")
    f.write("- Public release should use anonymized and payload-stripped PCAPs.\n")
    f.write("- CSV feature tables can be released after removing DNS names, HTTP hosts, and TLS SNI if necessary.\n")
    f.write("- The same processing pipeline should be reused for future cyberattack captures.\n")

print(f"Wrote report: {report_file}")
print(f"Wrote table: {OUT / 'table_top_protocols.csv'}")
print(f"Wrote table: {OUT / 'table_top_devices.csv'}")
print(f"Wrote table: {OUT / 'table_top_ports.csv'}")