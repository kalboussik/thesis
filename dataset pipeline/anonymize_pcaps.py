from pathlib import Path
import json
import ipaddress
from scapy.all import PcapReader, PcapWriter, Ether, IP, IPv6, TCP, UDP, ARP

ROOT = Path(r"E:\iot_dataset")

IN_DIR = ROOT / "00_raw_pcaps"
OUT_DIR = ROOT / "05_anonymized_pcaps"
OUT_DIR.mkdir(parents=True, exist_ok=True)

PRIVATE_MAP_FILE = OUT_DIR / "private_mapping_DO_NOT_PUBLISH.json"

ip4_map = {}
ip6_map = {}
mac_map = {}

internal_ipv4_counter = 1
external_ipv4_counter = 1
internal_ipv6_counter = 1
external_ipv6_counter = 1
mac_counter = 1

def is_rfc1918(ip):
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version != 4:
            return False
        return (
            addr in ipaddress.ip_network("10.0.0.0/8") or
            addr in ipaddress.ip_network("172.16.0.0/12") or
            addr in ipaddress.ip_network("192.168.0.0/16")
        )
    except Exception:
        return False

def anonymize_ipv4(ip):
    global internal_ipv4_counter, external_ipv4_counter

    if not ip:
        return ip

    try:
        addr = ipaddress.ip_address(ip)
    except Exception:
        return ip

    # Keep multicast, broadcast, loopback, link-local as they are.
    if addr.is_multicast or addr.is_loopback or addr.is_link_local or ip == "255.255.255.255":
        return ip

    if ip in ip4_map:
        return ip4_map[ip]

    if is_rfc1918(ip):
        # Internal IoT/home addresses
        new_ip = str(ipaddress.ip_address("10.10.0.0") + internal_ipv4_counter)
        internal_ipv4_counter += 1
    else:
        # External Internet addresses
        new_ip = str(ipaddress.ip_address("10.200.0.0") + external_ipv4_counter)
        external_ipv4_counter += 1

    ip4_map[ip] = new_ip
    return new_ip

def anonymize_ipv6(ip):
    global internal_ipv6_counter, external_ipv6_counter

    if not ip:
        return ip

    try:
        addr = ipaddress.ip_address(ip)
    except Exception:
        return ip

    # Keep multicast and loopback.
    if addr.is_multicast or addr.is_loopback:
        return ip

    if ip in ip6_map:
        return ip6_map[ip]

    if addr.is_private or addr.is_link_local:
        new_ip = str(ipaddress.ip_address("fd00:10::") + internal_ipv6_counter)
        internal_ipv6_counter += 1
    else:
        new_ip = str(ipaddress.ip_address("fd00:200::") + external_ipv6_counter)
        external_ipv6_counter += 1

    ip6_map[ip] = new_ip
    return new_ip

def anonymize_mac(mac):
    global mac_counter

    if not mac:
        return mac

    mac = mac.lower()

    # Keep broadcast and common multicast prefixes.
    if mac == "ff:ff:ff:ff:ff:ff":
        return mac

    if mac.startswith("01:00:5e") or mac.startswith("33:33"):
        return mac

    if mac in mac_map:
        return mac_map[mac]

    value = mac_counter
    mac_counter += 1

    new_mac = "02:00:%02x:%02x:%02x:%02x" % (
        (value >> 24) & 0xff,
        (value >> 16) & 0xff,
        (value >> 8) & 0xff,
        value & 0xff
    )

    mac_map[mac] = new_mac
    return new_mac

def fix_checksums(pkt):
    if IP in pkt:
        if hasattr(pkt[IP], "len"):
            try:
                del pkt[IP].len
            except Exception:
                pass
        if hasattr(pkt[IP], "chksum"):
            try:
                del pkt[IP].chksum
            except Exception:
                pass

    if IPv6 in pkt:
        if hasattr(pkt[IPv6], "plen"):
            try:
                del pkt[IPv6].plen
            except Exception:
                pass

    if TCP in pkt:
        try:
            del pkt[TCP].chksum
        except Exception:
            pass

    if UDP in pkt:
        try:
            del pkt[UDP].len
        except Exception:
            pass
        try:
            del pkt[UDP].chksum
        except Exception:
            pass

    return pkt

def anonymize_packet(pkt):
    if Ether in pkt:
        pkt[Ether].src = anonymize_mac(pkt[Ether].src)
        pkt[Ether].dst = anonymize_mac(pkt[Ether].dst)

    if IP in pkt:
        pkt[IP].src = anonymize_ipv4(pkt[IP].src)
        pkt[IP].dst = anonymize_ipv4(pkt[IP].dst)

    if IPv6 in pkt:
        pkt[IPv6].src = anonymize_ipv6(pkt[IPv6].src)
        pkt[IPv6].dst = anonymize_ipv6(pkt[IPv6].dst)

    if ARP in pkt:
        pkt[ARP].hwsrc = anonymize_mac(pkt[ARP].hwsrc)
        pkt[ARP].hwdst = anonymize_mac(pkt[ARP].hwdst)
        pkt[ARP].psrc = anonymize_ipv4(pkt[ARP].psrc)
        pkt[ARP].pdst = anonymize_ipv4(pkt[ARP].pdst)

    return fix_checksums(pkt)

for pcap in IN_DIR.glob("*.pcap*"):
    out_file = OUT_DIR / f"{pcap.stem}_anon.pcap"

    print(f"Anonymizing: {pcap.name} -> {out_file.name}")

    reader = PcapReader(str(pcap))
    writer = PcapWriter(str(out_file), sync=True)

    count = 0

    for pkt in reader:
        pkt = anonymize_packet(pkt)
        writer.write(pkt)
        count += 1

    reader.close()
    writer.close()

    print(f"  packets written: {count}")

mapping = {
    "ipv4_mapping": ip4_map,
    "ipv6_mapping": ip6_map,
    "mac_mapping": mac_map,
    "important_warning": "Do not publish this file. It links real addresses to anonymized addresses."
}

with open(PRIVATE_MAP_FILE, "w", encoding="utf-8") as f:
    json.dump(mapping, f, indent=2)

print(f"Private mapping written to: {PRIVATE_MAP_FILE}")
print("DO NOT PUBLISH the private mapping file.")