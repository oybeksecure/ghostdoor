#!/usr/bin/env python3
"""Tiny TCP connect scanner (your 'attacker' tool) + banner grabber.
Use ONLY against your own machine/lab.

It shows what the attacker sees: the real vault port looks closed, the
decoy port looks open - and grabbing its banner gets you stuck."""
import argparse
import socket
import time


def scan(host, ports, src=None, timeout=1.0):
    results = {}
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if src:
            s.bind((src, 0))
        try:
            s.connect((host, port))
            results[port] = "open"
        except ConnectionRefusedError:
            results[port] = "closed"
        except socket.timeout:
            results[port] = "filtered"
        finally:
            s.close()
    return results


def grab_banner(host, port, src=None, patience=5.0):
    """Wait for a banner line. A tarpit never finishes the line in time."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0)
    if src:
        s.bind((src, 0))
    s.connect((host, port))
    start, got = time.time(), b""
    try:
        while time.time() - start < patience:
            try:
                chunk = s.recv(64)
            except socket.timeout:
                continue
            if not chunk:
                break
            got += chunk
    finally:
        s.close()
    return got, time.time() - start


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--ports", default="8000-9100")
    p.add_argument("--src")
    p.add_argument("--grab", action="store_true", help="grab banners from open ports (you will get trapped)")
    a = p.parse_args()
    lo, _, hi = a.ports.partition("-")
    ports = range(int(lo), int(hi or lo) + 1)
    res = scan(a.host, ports, a.src, 0.3)
    opened = [p for p, st in res.items() if st == "open"]
    print(f"scanned {len(res)} ports -> open: {opened or 'none'}")
    if a.grab:
        for port in opened:
            data, secs = grab_banner(a.host, port, a.src, 8)
            print(f"port {port}: stuck for {secs:.1f}s, received junk: {data[:40]!r}")
