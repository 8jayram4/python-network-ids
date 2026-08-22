from scapy.all import sniff, IP, TCP
from collections import defaultdict, deque
import time
import csv
import os
import sys
from datetime import datetime


# ==========================================
# DETECTION SETTINGS
# ==========================================

PORT_SCAN_THRESHOLD = 10
SYN_FLOOD_THRESHOLD = 50
TIME_WINDOW = 5


# ==========================================
# STORAGE
# ==========================================

# Stores recent SYN packets for port-scan detection
port_scan_connections = defaultdict(deque)

# Stores recent SYN packets for SYN-flood detection
syn_flood_connections = defaultdict(deque)


# ==========================================
# CREATE CSV FILE
# ==========================================

if not os.path.exists("alerts.csv"):

    with open("alerts.csv", "w", newline="") as file:

        writer = csv.writer(file)

        writer.writerow([
            "Timestamp",
            "Alert Type",
            "Source IP",
            "Destination IP",
            "Details"
        ])


# ==========================================
# SAVE ALERT TO CSV
# ==========================================

def save_alert(alert_type, source_ip, destination_ip, details):

    with open("alerts.csv", "a", newline="") as file:

        writer = csv.writer(file)

        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            alert_type,
            source_ip,
            destination_ip,
            details
        ])


# ==========================================
# PROCESS EACH PACKET
# ==========================================

def show_packet(packet):

    # We only analyze IPv4 TCP packets
    if IP not in packet or TCP not in packet:
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst

    source_port = packet[TCP].sport
    destination_port = packet[TCP].dport

    flags = packet[TCP].flags

    # ------------------------------------------
    # Check for SYN without ACK
    # ------------------------------------------

    syn_packet = (
        bool(flags & 0x02)
        and not bool(flags & 0x10)
    )

    # Ignore packets that aren't initial SYN packets
    if not syn_packet:
        return

    current_time = time.time()


    # ==========================================
    # PORT SCAN DETECTION
    # ==========================================

    connection_key = (
        source_ip,
        destination_ip
    )

    # Store timestamp + destination port
    port_scan_connections[connection_key].append(
        (current_time, destination_port)
    )


    # Remove entries older than TIME_WINDOW
    while port_scan_connections[connection_key]:

        oldest_time = (
            port_scan_connections[connection_key][0][0]
        )

        if current_time - oldest_time > TIME_WINDOW:

            port_scan_connections[connection_key].popleft()

        else:

            break


    # Get unique destination ports
    recent_ports = {
        port
        for timestamp, port
        in port_scan_connections[connection_key]
    }


    # ==========================================
    # SYN FLOOD DETECTION
    # ==========================================

    syn_flood_connections[destination_ip].append(
        current_time
    )


    # Remove old SYN packets
    while syn_flood_connections[destination_ip]:

        oldest_time = (
            syn_flood_connections[destination_ip][0]
        )

        if current_time - oldest_time > TIME_WINDOW:

            syn_flood_connections[destination_ip].popleft()

        else:

            break


    # Number of recent SYN packets
    syn_count = len(
        syn_flood_connections[destination_ip]
    )


    # ==========================================
    # DISPLAY PACKET
    # ==========================================

    print(
        f"[SYN] "
        f"{source_ip}:{source_port} "
        f"-> "
        f"{destination_ip}:{destination_port} "
        f"| Ports in window: {len(recent_ports)} "
        f"| SYNs to destination: {syn_count}"
    )


# ==========================================
# START IDS
# ==========================================

print("==========================================")
print("          PYTHON NETWORK IDS")
print("==========================================")

print(
    f"Port scan threshold : "
    f"{PORT_SCAN_THRESHOLD}"
)

print(
    f"SYN flood threshold : "
    f"{SYN_FLOOD_THRESHOLD}"
)

print(
    f"Time window         : "
    f"{TIME_WINDOW} seconds"
)


# ==========================================
# CAPTURE MODE
# ==========================================

try:

    # --------------------------------------
    # PCAP MODE
    # --------------------------------------

    if len(sys.argv) > 1:

        pcap_file = sys.argv[1]

        print("\n==========================================")
        print("              PCAP MODE")
        print("==========================================")

        print(
            f"Reading PCAP file:\n"
            f"{pcap_file}"
        )

        if not os.path.exists(pcap_file):

            print("\nERROR: PCAP file not found!")

            sys.exit(1)


        sniff(
            offline=pcap_file,
            prn=show_packet,
            store=False
        )


    # --------------------------------------
    # LIVE CAPTURE MODE
    # --------------------------------------

    else:

        print("\n==========================================")
        print("          LIVE CAPTURE MODE")
        print("==========================================")

        print("\nStarting live packet capture...")
        print("Press Ctrl+C to stop.\n")


        sniff(
            prn=show_packet,
            store=False
        )


except KeyboardInterrupt:

    print("\n\nCapture stopped by user.")


# ==========================================
# FINAL ANALYSIS
# ==========================================

print("\n==========================================")
print("              FINAL ANALYSIS")
print("==========================================")


# ==========================================
# PORT SCAN ANALYSIS
# ==========================================

print("\n--- PORT SCAN ANALYSIS ---")


for connection, entries in port_scan_connections.items():

    source_ip, destination_ip = connection


    # Get unique ports
    ports = {
        port
        for timestamp, port
        in entries
    }


    print(
        f"\nSource      : "
        f"{source_ip}"
    )

    print(
        f"Destination : "
        f"{destination_ip}"
    )

    print(
        f"Unique ports: "
        f"{len(ports)}"
    )

    print(
        f"Ports       : "
        f"{sorted(ports)}"
    )


    # --------------------------------------
    # Port scan alert
    # --------------------------------------

    if len(ports) >= PORT_SCAN_THRESHOLD:

        print(
            "⚠️ SUSPICIOUS: "
            "Possible port scan"
        )


        save_alert(
            "Possible Port Scan",
            source_ip,
            destination_ip,
            f"{len(ports)} unique ports detected"
        )


    else:

        print(
            "Status      : Normal"
        )


# ==========================================
# SYN FLOOD ANALYSIS
# ==========================================

print("\n--- SYN FLOOD ANALYSIS ---")


for destination_ip, timestamps in syn_flood_connections.items():

    syn_count = len(timestamps)


    print(
        f"\nDestination : "
        f"{destination_ip}"
    )

    print(
        f"SYN packets : "
        f"{syn_count}"
    )


    # --------------------------------------
    # SYN flood alert
    # --------------------------------------

    if syn_count >= SYN_FLOOD_THRESHOLD:

        print(
            "⚠️ SUSPICIOUS: "
            "Possible SYN flood"
        )


        save_alert(
            "Possible SYN Flood",
            "Multiple/Unknown",
            destination_ip,
            f"{syn_count} SYN packets detected"
        )


    else:

        print(
            "Status      : Normal"
        )


# ==========================================
# PROGRAM FINISHED
# ==========================================

print("\n==========================================")
print("           IDS ANALYSIS COMPLETE")
print("==========================================")

print("\nResults have been processed.")

print(
    "Check alerts.csv for any "
    "detected suspicious activity."
)
