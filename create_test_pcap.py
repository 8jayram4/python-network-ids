from scapy.all import IP, TCP, wrpcap
import os


# =====================================
# CREATE PCAP FOLDER
# =====================================

os.makedirs("pcaps", exist_ok=True)


packets = []


# =====================================
# 1. NORMAL HTTPS TRAFFIC
# =====================================

normal_packet = (
    IP(src="192.168.1.10", dst="10.0.0.10")
    /
    TCP(sport=50000, dport=443, flags="S")
)

packets.append(normal_packet)


# =====================================
# 2. SIMULATED PORT SCAN
# =====================================

print("Creating simulated port scan...")

for port in range(20, 35):

    packet = (
        IP(
            src="192.168.1.100",
            dst="10.0.0.20"
        )
        /
        TCP(
            sport=40000 + port,
            dport=port,
            flags="S"
        )
    )

    packets.append(packet)


# =====================================
# 3. SIMULATED SYN FLOOD
# =====================================

print("Creating simulated SYN flood...")

for i in range(60):

    packet = (
        IP(
            src=f"192.168.1.{100 + (i % 10)}",
            dst="10.0.0.30"
        )
        /
        TCP(
            sport=30000 + i,
            dport=80,
            flags="S"
        )
    )

    packets.append(packet)


# =====================================
# SAVE PCAP
# =====================================

output_file = "pcaps/test_security_traffic.pcap"

wrpcap(output_file, packets)


print("\n======================================")
print("Test PCAP created successfully!")
print("======================================")

print(f"File: {output_file}")
print(f"Total packets: {len(packets)}")