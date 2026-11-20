#!/usr/bin/env python3
"""Interactive client for the hidden TCP vault (knock first!)."""
import argparse
import socket
import sys

from common import DEFAULT_VAULT_PORT


def connect(host, port, src=None, timeout=3):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    if src:
        s.bind((src, 0))
    s.connect((host, port))
    return s


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=DEFAULT_VAULT_PORT)
    p.add_argument("--src")
    a = p.parse_args()
    try:
        s = connect(a.host, a.port, a.src)
    except ConnectionRefusedError:
        sys.exit("connection refused - the door is closed. Send a knock first.")
    try:
        banner = s.recv(1024).decode()
    except (ConnectionResetError, socket.timeout, OSError):
        sys.exit("connection reset by server - no valid knock for this IP (or the window ended).")
    print(banner, end="")
    try:
        while True:
            cmd = input("vault> ")
            s.sendall((cmd + "\n").encode())
            print(s.recv(1024).decode(), end="")
            if cmd.strip().upper() == "QUIT":
                break
    except (EOFError, KeyboardInterrupt, OSError):
        pass