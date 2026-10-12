# Packet Sniffer

A Python-based HTTP traffic inspection tool built with Scapy. It captures HTTP requests on a selected network interface and displays request URLs and source information for authorized network analysis.

## Features

- Capture HTTP traffic on a specified network interface.
- Extract hostnames and paths from HTTP requests.
- Display request URLs and available source information.
- Configure the number of packets to capture.
- Use BPF filtering to focus on TCP port 80 traffic.
- Handle permission errors and graceful user interruption.

## Requirements

- Python 3
- Scapy
- Appropriate permissions to capture network traffic

Install the dependency:

```bash
pip install scapy
```

## Usage

Start capturing HTTP traffic using the default interface:

```bash
sudo python3 packet_sniffer.py
```

Specify a network interface:

```bash
sudo python3 packet_sniffer.py -i eth0
```

Capture a limited number of packets:

```bash
sudo python3 packet_sniffer.py -i eth0 -c 50
```

Display available options:

```bash
python3 packet_sniffer.py -h
```

Replace `eth0` with the correct interface name for your environment.

## How It Works

The tool uses Scapy to capture packets matching the TCP port 80 filter. It inspects packets containing HTTP request layers and extracts the requested host and path when available.

## Limitations

- Designed to inspect HTTP traffic, not decrypt HTTPS.
- Encrypted HTTPS application data cannot generally be inspected as readable HTTP using this script alone.
- Packet visibility depends on the network interface, permissions, and network topology.
- HTTP request parsing and source-address extraction may require adjustments for different packet structures.
- Network traffic that does not match the capture filter will not be processed.

## Security and Responsible Use

Use this tool only on networks and devices you own or have explicit authorization to monitor.

Do not collect, expose, or publish passwords, session tokens, or other sensitive information. For public demonstrations, use synthetic traffic and redact sensitive payloads.

**Note:** The current script searches raw HTTP payloads for keywords associated with possible credentials and prints matching payload content. Before using it outside an isolated lab, remove raw credential-payload logging and retain only the minimum non-sensitive metadata needed for analysis.

## Author

SENSI0X
