# Python Network IDS

A lightweight Python-based Network Intrusion Detection System (IDS) that captures and analyzes TCP traffic using Scapy. The system identifies suspicious port-scanning and SYN-flood patterns using threshold-based and time-window analysis.

## Features

- Live network packet capture
- Offline PCAP analysis
- TCP SYN packet identification
- Port-scan detection
- SYN-flood detection
- Configurable detection thresholds
- Time-window based analysis
- Automatic security-alert logging to CSV
- Controlled security-traffic testing

## Architecture

```text
Network Traffic / PCAP
          |
          v
       Scapy
          |
          v
    Packet Capture
          |
          v
     TCP SYN Filter
          |
          v
   +------+------+
   |             |
   v             v
Port Analysis  SYN Analysis
   |             |
   v             v
Port Scan      SYN Flood
Detection      Detection
   |             |
   +------+------+
          |
          v
     Alert Logging
          |
          v
      alerts.csv
## Technologies Used

- Python 3
- Scapy
- TCP/IP networking
- Packet analysis
- CSV-based security alert logging

## Installation

Clone the repository:

```bash
git clone https://github.com/8jayram4/python-network-ids.git
cd python-network-ids
