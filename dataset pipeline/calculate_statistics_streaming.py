from pathlib import Path
from collections import defaultdict
import pandas as pd
import numpy as np

ROOT = Path(r"E:\iot_dataset")
FEATURES = ROOT / "07_features"
PACKETS = FEATURES / "packets_anonymized.tsv"

OUT_SUMMARY = FEATURES / "summary_statistics.txt"
OUT_PROTOCOLS = FEATURES / "protocol_distribution.csv"
OUT_DEVICES = FEATURES / "device_stats.csv"
OUT_PORTS = FEATURES / "top_ports.csv"
OUT_TS_1MIN = FEATURES / "timeseries_1min.csv"
OUT_TS_5MIN = FEATURES / "timeseries_5min.csv"
OUT_TS_1H = FEATURES / "timeseries_1h.csv"

CHUNK_SIZE = 500_000

proto_map = {
    "1": "ICMP",
    "2": "IGMP",
    "6": "TCP",
    "17": "UDP",
    "58": "ICMPv6"
}

def is_internal(ip):
    return isinstance(ip, str) and ip.startswith("10.10.0.")

def update_counter_dict(counter, key, packets, bytes_):
    if key not in counter:
        counter[key] = {"packets": 0, "bytes": 0}
    counter[key]["packets"] += int(packets)
    counter[key]["bytes"] += int(bytes_)

total_packets = 0
total_bytes = 0
start_time = None
end_time = None

protocol_counter = {}
port_counter = {}
device_counter = {}

unique_src_ips = set()
unique_dst_ips = set()
unique_eth_src = set()
unique_eth_dst = set()
internal_devices = set()

timeseries_1min = defaultdict(lambda: {"packets": 0, "bytes": 0, "tcp_packets": 0, "udp_packets": 0, "non_ip_packets": 0})
timeseries_5min = defaultdict(lambda: {"packets": 0, "bytes": 0, "tcp_packets": 0, "udp_packets": 0, "non_ip_packets": 0})
timeseries_1h = defaultdict(lambda: {"packets": 0, "bytes": 0, "tcp_packets": 0, "udp_packets": 0, "non_ip_packets": 0})

usecols = [
    "pcap_file",
    "frame_time_epoch",
    "frame_len",
    "eth_src",
    "eth_dst",
    "ip_src",
    "ip_dst",
    "ip_proto",
    "tcp_srcport",
    "tcp_dstport",
    "udp_srcport",
    "udp_dstport"
]

print("Starting streaming statistics...")
print(f"Input: {PACKETS}")

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

    # Some tshark fields may still contain multiple values joined by commas.
    # Keep only the first value for statistical counting.
    for col in ["eth_src", "eth_dst", "ip_src", "ip_dst", "ip_proto",
                "tcp_srcport", "tcp_dstport", "udp_srcport", "udp_dstport"]:
        if col in chunk.columns:
            chunk[col] = chunk[col].astype(str).str.split(",").str[0]

    chunk["frame_len_num"] = pd.to_numeric(chunk["frame_len"], errors="coerce").fillna(0).astype("int64")
    chunk["frame_time_num"] = pd.to_numeric(chunk["frame_time_epoch"], errors="coerce")
    chunk = chunk.dropna(subset=["frame_time_num"])

    chunk["timestamp"] = pd.to_datetime(chunk["frame_time_num"], unit="s", errors="coerce")
    chunk = chunk.dropna(subset=["timestamp"])

    chunk["protocol_name"] = chunk["ip_proto"].map(proto_map).fillna(chunk["ip_proto"])
    chunk.loc[chunk["ip_proto"] == "", "protocol_name"] = "NON_IP"

    total_packets += len(chunk)
    total_bytes += int(chunk["frame_len_num"].sum())

    c_start = chunk["timestamp"].min()
    c_end = chunk["timestamp"].max()

    if start_time is None or c_start < start_time:
        start_time = c_start
    if end_time is None or c_end > end_time:
        end_time = c_end

    unique_src_ips.update(chunk.loc[chunk["ip_src"] != "", "ip_src"].unique())
    unique_dst_ips.update(chunk.loc[chunk["ip_dst"] != "", "ip_dst"].unique())
    unique_eth_src.update(chunk.loc[chunk["eth_src"] != "", "eth_src"].unique())
    unique_eth_dst.update(chunk.loc[chunk["eth_dst"] != "", "eth_dst"].unique())

    internal_devices.update([x for x in chunk["ip_src"].unique() if is_internal(x)])
    internal_devices.update([x for x in chunk["ip_dst"].unique() if is_internal(x)])

    # Protocol distribution
    proto_group = chunk.groupby("protocol_name")["frame_len_num"].agg(["count", "sum"]).reset_index()
    for _, row in proto_group.iterrows():
        update_counter_dict(protocol_counter, row["protocol_name"], row["count"], row["sum"])

    # Ports
    tcp_ports = chunk.loc[chunk["tcp_dstport"] != ""].groupby("tcp_dstport")["frame_len_num"].agg(["count", "sum"]).reset_index()
    for _, row in tcp_ports.iterrows():
        update_counter_dict(port_counter, ("TCP", row["tcp_dstport"]), row["count"], row["sum"])

    udp_ports = chunk.loc[chunk["udp_dstport"] != ""].groupby("udp_dstport")["frame_len_num"].agg(["count", "sum"]).reset_index()
    for _, row in udp_ports.iterrows():
        update_counter_dict(port_counter, ("UDP", row["udp_dstport"]), row["count"], row["sum"])

    # Device stats
    chunk["src_internal"] = chunk["ip_src"].apply(is_internal)
    chunk["dst_internal"] = chunk["ip_dst"].apply(is_internal)

    for dev in set(chunk.loc[chunk["src_internal"], "ip_src"]) | set(chunk.loc[chunk["dst_internal"], "ip_dst"]):
        if dev not in device_counter:
            device_counter[dev] = {
                "packets_sent": 0,
                "packets_received": 0,
                "bytes_sent": 0,
                "bytes_received": 0,
                "tcp_packets_sent": 0,
                "udp_packets_sent": 0,
                "unique_destinations_contacted": set(),
                "unique_sources_contacting_device": set(),
                "tcp_dst_ports": set(),
                "udp_dst_ports": set(),
                "first_seen": None,
                "last_seen": None
            }

        sent = chunk[chunk["ip_src"] == dev]
        received = chunk[chunk["ip_dst"] == dev]

        device_counter[dev]["packets_sent"] += len(sent)
        device_counter[dev]["packets_received"] += len(received)
        device_counter[dev]["bytes_sent"] += int(sent["frame_len_num"].sum())
        device_counter[dev]["bytes_received"] += int(received["frame_len_num"].sum())

        device_counter[dev]["tcp_packets_sent"] += int((sent["protocol_name"] == "TCP").sum())
        device_counter[dev]["udp_packets_sent"] += int((sent["protocol_name"] == "UDP").sum())

        device_counter[dev]["unique_destinations_contacted"].update(sent.loc[sent["ip_dst"] != "", "ip_dst"].unique())
        device_counter[dev]["unique_sources_contacting_device"].update(received.loc[received["ip_src"] != "", "ip_src"].unique())

        device_counter[dev]["tcp_dst_ports"].update(sent.loc[sent["tcp_dstport"] != "", "tcp_dstport"].unique())
        device_counter[dev]["udp_dst_ports"].update(sent.loc[sent["udp_dstport"] != "", "udp_dstport"].unique())

        d_start = chunk.loc[(chunk["ip_src"] == dev) | (chunk["ip_dst"] == dev), "timestamp"].min()
        d_end = chunk.loc[(chunk["ip_src"] == dev) | (chunk["ip_dst"] == dev), "timestamp"].max()

        if device_counter[dev]["first_seen"] is None or d_start < device_counter[dev]["first_seen"]:
            device_counter[dev]["first_seen"] = d_start
        if device_counter[dev]["last_seen"] is None or d_end > device_counter[dev]["last_seen"]:
            device_counter[dev]["last_seen"] = d_end

    # Time series
    for interval, store in [
        ("1min", timeseries_1min),
        ("5min", timeseries_5min),
        ("1h", timeseries_1h),
    ]:
        temp = chunk.copy()
        temp["bucket"] = temp["timestamp"].dt.floor(interval)

        grouped = temp.groupby("bucket").agg(
            packets=("frame_len_num", "count"),
            bytes=("frame_len_num", "sum"),
            tcp_packets=("protocol_name", lambda x: int((x == "TCP").sum())),
            udp_packets=("protocol_name", lambda x: int((x == "UDP").sum())),
            non_ip_packets=("protocol_name", lambda x: int((x == "NON_IP").sum()))
        ).reset_index()

        for _, row in grouped.iterrows():
            bucket = row["bucket"]
            store[bucket]["packets"] += int(row["packets"])
            store[bucket]["bytes"] += int(row["bytes"])
            store[bucket]["tcp_packets"] += int(row["tcp_packets"])
            store[bucket]["udp_packets"] += int(row["udp_packets"])
            store[bucket]["non_ip_packets"] += int(row["non_ip_packets"])

print("Writing output files...")

# Summary
duration_seconds = (end_time - start_time).total_seconds() if start_time is not None and end_time is not None else 0
avg_pps = total_packets / duration_seconds if duration_seconds > 0 else 0
avg_bps = total_bytes / duration_seconds if duration_seconds > 0 else 0

with open(OUT_SUMMARY, "w", encoding="utf-8") as f:
    f.write("IoT Traffic Dataset Summary\n")
    f.write("===========================\n\n")
    f.write(f"Total packets: {total_packets}\n")
    f.write(f"Total bytes: {total_bytes}\n")
    f.write(f"Start time: {start_time}\n")
    f.write(f"End time: {end_time}\n")
    f.write(f"Duration seconds: {duration_seconds:.2f}\n")
    f.write(f"Duration days: {duration_seconds / 86400:.2f}\n")
    f.write(f"Average packets/second: {avg_pps:.4f}\n")
    f.write(f"Average bytes/second: {avg_bps:.4f}\n")
    f.write(f"Average bitrate bps: {avg_bps * 8:.4f}\n")
    f.write(f"Unique source IPs: {len(unique_src_ips)}\n")
    f.write(f"Unique destination IPs: {len(unique_dst_ips)}\n")
    f.write(f"Unique source MACs: {len(unique_eth_src)}\n")
    f.write(f"Unique destination MACs: {len(unique_eth_dst)}\n")
    f.write(f"Detected internal anonymized devices: {len(internal_devices)}\n")
    f.write("\nInternal anonymized devices:\n")
    for dev in sorted(internal_devices):
        f.write(f"- {dev}\n")

# Protocols
protocol_rows = []
for proto, values in protocol_counter.items():
    protocol_rows.append({
        "protocol": proto,
        "packets": values["packets"],
        "bytes": values["bytes"],
        "packet_percentage": values["packets"] / total_packets * 100 if total_packets else 0,
        "byte_percentage": values["bytes"] / total_bytes * 100 if total_bytes else 0
    })

pd.DataFrame(protocol_rows).sort_values("packets", ascending=False).to_csv(OUT_PROTOCOLS, index=False)

# Ports
port_rows = []
for (transport, port), values in port_counter.items():
    port_rows.append({
        "transport": transport,
        "dst_port": port,
        "packets": values["packets"],
        "bytes": values["bytes"]
    })

pd.DataFrame(port_rows).sort_values("packets", ascending=False).to_csv(OUT_PORTS, index=False)

# Devices
device_rows = []
for dev, values in device_counter.items():
    device_rows.append({
        "device_ip": dev,
        "packets_sent": values["packets_sent"],
        "packets_received": values["packets_received"],
        "bytes_sent": values["bytes_sent"],
        "bytes_received": values["bytes_received"],
        "total_packets": values["packets_sent"] + values["packets_received"],
        "total_bytes": values["bytes_sent"] + values["bytes_received"],
        "unique_destinations_contacted": len(values["unique_destinations_contacted"]),
        "unique_sources_contacting_device": len(values["unique_sources_contacting_device"]),
        "tcp_packets_sent": values["tcp_packets_sent"],
        "udp_packets_sent": values["udp_packets_sent"],
        "unique_tcp_dst_ports": len(values["tcp_dst_ports"]),
        "unique_udp_dst_ports": len(values["udp_dst_ports"]),
        "first_seen": values["first_seen"],
        "last_seen": values["last_seen"]
    })

pd.DataFrame(device_rows).sort_values("total_bytes", ascending=False).to_csv(OUT_DEVICES, index=False)

def write_timeseries(store, out_file, seconds):
    rows = []
    for bucket, values in store.items():
        rows.append({
            "timestamp": bucket,
            "packets": values["packets"],
            "bytes": values["bytes"],
            "tcp_packets": values["tcp_packets"],
            "udp_packets": values["udp_packets"],
            "non_ip_packets": values["non_ip_packets"],
            "packets_per_second": values["packets"] / seconds,
            "bytes_per_second": values["bytes"] / seconds
        })

    pd.DataFrame(rows).sort_values("timestamp").to_csv(out_file, index=False)

write_timeseries(timeseries_1min, OUT_TS_1MIN, 60)
write_timeseries(timeseries_5min, OUT_TS_5MIN, 300)
write_timeseries(timeseries_1h, OUT_TS_1H, 3600)

print("Done.")
print(f"Wrote: {OUT_SUMMARY}")
print(f"Wrote: {OUT_PROTOCOLS}")
print(f"Wrote: {OUT_DEVICES}")
print(f"Wrote: {OUT_PORTS}")
print(f"Wrote: {OUT_TS_1MIN}")
print(f"Wrote: {OUT_TS_5MIN}")
print(f"Wrote: {OUT_TS_1H}")