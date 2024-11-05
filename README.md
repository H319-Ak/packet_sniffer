# Packet Sniffer in Python

A lightweight Python packet sniffer that captures and displays real-time network traffic. It parses Ethernet, IPv4, TCP, UDP, and ICMP protocols, showing key details like IP addresses, ports, and flags. Requires Python 3.x and root privileges.

## Features
- Real-time capture for Ethernet, IPv4, TCP, UDP, and ICMP protocols.
- Displays IP addresses, ports, and protocol flags with hex output for payloads.

## Requirements
- Python 3.x
- Root privileges (for raw socket access)

## Usage
Run the script with root privileges:
```bash
sudo python3 packet_sniffer.py
