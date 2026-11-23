from pathlib import Path
import pandas as pd
import numpy as np

ROOT = Path(r"E:\iot_dataset")
FEATURES = ROOT / "07_features"

PACKETS = FEATURES / "packets_anonymized.tsv"

OUT_SUMMARY = FEATURES / "summary_statistics.txt"
OUT_PROTOCOLS = FEATURES / "protocol_distribution.csv"
OUT_DEVICES = FEATURES / "device_stats.csv"
OUT_PORTS = FEATURES / "top_ports.csv"
OUT_TIMESERIES_1MIN = FEATURES / "timeseries_1min.csv"
OUT_TIMESERIES_5MIN = FEATURES / "timeseries_5min.csv"
OUT_TIMESERIES_1H = FEATURES / "timeseries_1h.csv"
OUT_FLOWS = FEATURES / "flows_5tuple.csv"

df = pd.read_csv(PACKETS, sep="\t", dtype=str)

# Clean numeric fields
df["frame_len"] = pd.to_numeric(df["frame_len"], errors="coerce").fillna(0)
df["frame_time_epoch"] = pd.to_numeric(df["frame_time_epoch"], errors="coerce")
df = df.dropna(subset=["frame_time_epoch"])
df["timestamp"] = pd.to_datetime(df["frame_time_epoch"], unit="s", errors="coerce")

# Normalize empty values
for col in df.columns:
    df[col] = df[col].fillna("")

# Protocol names
proto_map = {
    "1": "ICMP",
    "2": "IGMP",
    "6": "TCP",
    "17": "UDP",
    "58": "ICMPv6"
}
df["protocol_name"] = df["ip_proto"].map(proto_map).fillna(df["ip_proto"])
df.loc[df["ip_proto"] == "", "protocol_name"] = "NON_IP"

# Internal anonymized devices
# Based on previous anonymization: internal devices are 10.10.0.x
def is_internal(ip):
    return isinstance(ip, str) and ip.startswith("10.10.0.")

df["src_internal"] = df["ip_src"].apply(is_internal)
df["dst_internal"] = df["ip_dst"].apply(is_internal)

# ======================
# Summary statistics
# ======================
total_packets = len(df)
total_bytes = int(df["frame_len"].sum())
start_time = df["timestamp"].min()
end_time = df["timestamp"].max()
duration_seconds = (end_time - start_time).total_seconds() if pd.notna(start_time) and pd.notna(end_time) else 0

avg_packets_per_second = total_packets / duration_seconds if duration_seconds > 0 else 0
avg_bytes_per_second = total_bytes / duration_seconds if duration_seconds > 0 else 0

unique_src_ips = df["ip_src"][df["ip_src"] != ""].nunique()
unique_dst_ips = df["ip_dst"][df["ip_dst"] != ""].nunique()
unique_eth_src = df["eth_src"][df["eth_src"] != ""].nunique()
unique_eth_dst = df["eth_dst"][df["eth_dst"] != ""].nunique()
internal_devices = sorted(set(df.loc[df["src_internal"], "ip_src"]) | set(df.loc[df["dst_internal"], "ip_dst"]))

with open(OUT_SUMMARY, "w", encoding="utf-8") as f:
    f.write("IoT Traffic Dataset Summary\n")
    f.write("===========================\n\n")
    f.write(f"Total packets: {total_packets}\n")
    f.write(f"Total bytes: {total_bytes}\n")
    f.write(f"Start time: {start_time}\n")
    f.write(f"End time: {end_time}\n")
    f.write(f"Duration seconds: {duration_seconds:.2f}\n")
    f.write(f"Duration days: {duration_seconds / 86400:.2f}\n")
    f.write(f"Average packets/second: {avg_packets_per_second:.4f}\n")
    f.write(f"Average bytes/second: {avg_bytes_per_second:.4f}\n")
    f.write(f"Average bitrate bps: {avg_bytes_per_second * 8:.4f}\n")
    f.write(f"Unique source IPs: {unique_src_ips}\n")
    f.write(f"Unique destination IPs: {unique_dst_ips}\n")
    f.write(f"Unique source MACs: {unique_eth_src}\n")
    f.write(f"Unique destination MACs: {unique_eth_dst}\n")
    f.write(f"Detected internal anonymized devices: {len(internal_devices)}\n")
    f.write("\nInternal anonymized devices:\n")
    for dev in internal_devices:
        f.write(f"- {dev}\n")

# ======================
# Protocol distribution
# ======================
protocols = (
    df.groupby("protocol_name")
    .agg(
        packets=("frame_len", "count"),
        bytes=("frame_len", "sum")
    )
    .reset_index()
    .sort_values("packets", ascending=False)
)

protocols["packet_percentage"] = protocols["packets"] / total_packets * 100
protocols["byte_percentage"] = protocols["bytes"] / total_bytes * 100 if total_bytes > 0 else 0
protocols.to_csv(OUT_PROTOCOLS, index=False)

# ======================
# Device-level statistics
# ======================
device_rows = []

for dev in internal_devices:
    sent = df[df["ip_src"] == dev]
    received = df[df["ip_dst"] == dev]

    tcp_sent = sent[sent["protocol_name"] == "TCP"]
    udp_sent = sent[sent["protocol_name"] == "UDP"]

    device_rows.append({
        "device_ip": dev,
        "packets_sent": len(sent),
        "packets_received": len(received),
        "bytes_sent": int(sent["frame_len"].sum()),
        "bytes_received": int(received["frame_len"].sum()),
        "total_packets": len(sent) + len(received),
        "total_bytes": int(sent["frame_len"].sum() + received["frame_len"].sum()),
        "unique_destinations_contacted": sent["ip_dst"][sent["ip_dst"] != ""].nunique(),
        "unique_sources_contacting_device": received["ip_src"][received["ip_src"] != ""].nunique(),
        "tcp_packets_sent": len(tcp_sent),
        "udp_packets_sent": len(udp_sent),
        "unique_tcp_dst_ports": tcp_sent["tcp_dstport"][tcp_sent["tcp_dstport"] != ""].nunique(),
        "unique_udp_dst_ports": udp_sent["udp_dstport"][udp_sent["udp_dstport"] != ""].nunique(),
        "first_seen": min(sent["timestamp"].min(), received["timestamp"].min()),
        "last_seen": max(sent["timestamp"].max(), received["timestamp"].max()),
    })

device_stats = pd.DataFrame(device_rows)
device_stats = device_stats.sort_values("total_bytes", ascending=False)
device_stats.to_csv(OUT_DEVICES, index=False)

# ======================
# Top ports
# ======================
tcp_ports = df[df["tcp_dstport"] != ""].groupby("tcp_dstport").agg(
    packets=("frame_len", "count"),
    bytes=("frame_len", "sum")
).reset_index()
tcp_ports["transport"] = "TCP"
tcp_ports = tcp_ports.rename(columns={"tcp_dstport": "dst_port"})

udp_ports = df[df["udp_dstport"] != ""].groupby("udp_dstport").agg(
    packets=("frame_len", "count"),
    bytes=("frame_len", "sum")
).reset_index()
udp_ports["transport"] = "UDP"
udp_ports = udp_ports.rename(columns={"udp_dstport": "dst_port"})

ports = pd.concat([tcp_ports, udp_ports], ignore_index=True)
ports = ports.sort_values("packets", ascending=False)
ports.to_csv(OUT_PORTS, index=False)

# ======================
# Time-series statistics
# ======================
ts = df.set_index("timestamp")

for interval, out_file in [
    ("1min", OUT_TIMESERIES_1MIN),
    ("5min", OUT_TIMESERIES_5MIN),
    ("1h", OUT_TIMESERIES_1H),
]:
    g = ts.resample(interval).agg(
        packets=("frame_len", "count"),
        bytes=("frame_len", "sum"),
        active_src_ips=("ip_src", lambda x: x[x != ""].nunique()),
        active_dst_ips=("ip_dst", lambda x: x[x != ""].nunique()),
        tcp_packets=("protocol_name", lambda x: (x == "TCP").sum()),
        udp_packets=("protocol_name", lambda x: (x == "UDP").sum()),
        non_ip_packets=("protocol_name", lambda x: (x == "NON_IP").sum()),
    ).reset_index()

    g["bytes_per_second"] = g["bytes"] / pd.to_timedelta(interval).total_seconds()
    g["packets_per_second"] = g["packets"] / pd.to_timedelta(interval).total_seconds()

    g.to_csv(out_file, index=False)

# ======================
# Simple 5-tuple flow-like statistics
# ======================
df["src_port"] = np.where(df["tcp_srcport"] != "", df["tcp_srcport"], df["udp_srcport"])
df["dst_port"] = np.where(df["tcp_dstport"] != "", df["tcp_dstport"], df["udp_dstport"])

flow_cols = ["ip_src", "ip_dst", "protocol_name", "src_port", "dst_port"]

flows = (
    df[(df["ip_src"] != "") & (df["ip_dst"] != "")]
    .groupby(flow_cols)
    .agg(
        first_seen=("timestamp", "min"),
        last_seen=("timestamp", "max"),
        packets=("frame_len", "count"),
        bytes=("frame_len", "sum"),
        mean_packet_size=("frame_len", "mean"),
        min_packet_size=("frame_len", "min"),
        max_packet_size=("frame_len", "max"),
    )
    .reset_index()
)

flows["duration_seconds"] = (flows["last_seen"] - flows["first_seen"]).dt.total_seconds()
flows["packets_per_second"] = flows["packets"] / flows["duration_seconds"].replace(0, np.nan)
flows["bytes_per_second"] = flows["bytes"] / flows["duration_seconds"].replace(0, np.nan)

flows = flows.sort_values("bytes", ascending=False)
flows.to_csv(OUT_FLOWS, index=False)

print("Done.")
print(f"Wrote: {OUT_SUMMARY}")
print(f"Wrote: {OUT_PROTOCOLS}")
print(f"Wrote: {OUT_DEVICES}")
print(f"Wrote: {OUT_PORTS}")
print(f"Wrote: {OUT_TIMESERIES_1MIN}")
print(f"Wrote: {OUT_TIMESERIES_5MIN}")
print(f"Wrote: {OUT_TIMESERIES_1H}")
print(f"Wrote: {OUT_FLOWS}")