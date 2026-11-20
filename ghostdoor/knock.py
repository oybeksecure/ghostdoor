#!/usr/bin/env python3
"""Send a signed UDP knock. The server never answers - success is seen by
connecting to the vault port afterwards."""
import argparse
import socket

from common import DEFAULT_KNOCK_PORT, DEFAULT_SECRET, build_knock


def send_knock(host, port, secret, src=None, packet=None):
    packet = packet or build_knock(secret)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if src:
        s.bind((src, 0))
    s.sendto(packet, (host, port))
    s.close()
    return packet


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=DEFAULT_KNOCK_PORT)
    p.add_argument("--secret", default=DEFAULT_SECRET)
    p.add_argument("--src", help="source IP to bind (e.g. 127.0.0.2 for lab demos)")
    p.add_argument("--print-hex", action="store_true", help="print the packet (what a sniffer would capture)")
    a = p.parse_args()
    pkt = send_knock(a.host, a.port, a.secret, a.src)
    print(f"knock sent ({len(pkt)} bytes), no reply expected")
    if a.print_hex:
        print(pkt.hex())
