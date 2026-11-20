#!/usr/bin/env python3
"""Ghost Door server.

 UDP  9999  silent knock listener (never replies)
 TCP  9000  real vault service - port is CLOSED (kernel sends RST) until a
            valid knock opens it for the knocking IP for --window seconds
 TCP  9001  decoy service - always open, a tarpit that wastes scanners' time
 HTTP 8080  live dashboard

Run on your OWN machine / lab only.
"""
import argparse
import json
import os
import random
import socket
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from common import (DEFAULT_DECOY_PORT, DEFAULT_KNOCK_PORT, DEFAULT_SECRET,
                    DEFAULT_VAULT_PORT, DEFAULT_WEB_PORT, verify_knock)

SECRETS = {
    "wifi": "ghost-lab-5G / correct-horse-battery",
    "api_key": "sk-demo-1234-not-a-real-key",
    "flag": "FLAG{udp_knock_opens_the_tcp_door}",
}


class State:
    def __init__(self, logfile):
        self.lock = threading.Lock()
        self.allowed = {}          # ip -> expiry (epoch)
        self.seen_nonces = {}      # nonce -> ts (replay protection)
        self.events = deque(maxlen=300)
        self.counters = {k: 0 for k in (
            "knock_ok", "knock_replay", "knock_badsig", "knock_stale",
            "knock_malformed", "vault_sessions", "intruders_refused",
            "decoy_hits", "tarpit_seconds")}
        self.tarpit_active = 0
        self.logfile = logfile

    def log(self, kind, ip, detail=""):
        ev = {"t": time.strftime("%H:%M:%S"), "kind": kind, "ip": ip, "detail": detail}
        with self.lock:
            self.events.append(ev)
            if kind in self.counters:
                self.counters[kind] += 1
        print(f"[{ev['t']}] {kind:<16} {ip:<15} {detail}", flush=True)
        if self.logfile:
            with open(self.logfile, "a") as f:
                f.write(json.dumps(ev) + "\n")

    def is_allowed(self, ip):
        with self.lock:
            return self.allowed.get(ip, 0) > time.time()

    def snapshot(self):
        now = time.time()
        with self.lock:
            allowed = [{"ip": ip, "remaining": round(exp - now, 1)}
                       for ip, exp in self.allowed.items() if exp > now]
            return {"allowed": allowed, "counters": dict(self.counters),
                    "tarpit_active": self.tarpit_active,
                    "door_open": bool(allowed),
                    "events": list(self.events)[-60:][::-1]}


class Door:
    """The real TCP listener. It only exists while at least one IP is allowed."""

    def __init__(self, state, port, window):
        self.state, self.port, self.window = state, port, window
        self.lsock = None
        self.mutex = threading.Lock()

    def open_for(self, ip):
        with self.state.lock:
            self.state.allowed[ip] = time.time() + self.window
        with self.mutex:
            if self.lsock is None:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("0.0.0.0", self.port))
                s.listen(16)
                s.settimeout(0.5)
                self.lsock = s
                threading.Thread(target=self._accept_loop, args=(s,), daemon=True).start()
                self.state.log("door_open", "-", f"TCP {self.port} now listening")

    def reaper(self):
        while True:
            time.sleep(0.25)
            now = time.time()
            with self.state.lock:
                expired = [i for i, e in self.state.allowed.items() if e <= now]
                for ip in expired:
                    del self.state.allowed[ip]
                none_left = not self.state.allowed
            for ip in expired:
                self.state.log("access_expired", ip, "window ended")
            with self.mutex:
                if none_left and self.lsock is not None:
                    self.lsock.close()
                    self.lsock = None
                    self.state.log("door_closed", "-", f"TCP {self.port} closed (RST for everyone)")

    def _accept_loop(self, sock):
        while True:
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                if self.lsock is not sock:
                    return
                continue
            except OSError:
                return
            ip = addr[0]
            if self.state.is_allowed(ip):
                threading.Thread(target=self._vault, args=(conn, ip), daemon=True).start()
            else:
                self.state.log("intruders_refused", ip, "connected during open window, no valid knock -> RST")
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
                conn.close()

    def _vault(self, conn, ip):
        self.state.log("vault_sessions", ip, "authenticated session started")
        conn.settimeout(1.0)
        buf = b""
        try:
            conn.sendall(b"GHOST-VAULT ready. commands: LIST | GET <name> | QUIT\n")
            while True:
                if not self.state.is_allowed(ip):
                    conn.sendall(b"SESSION EXPIRED - knock again\n")
                    return
                try:
                    data = conn.recv(1024)
                except socket.timeout:
                    continue
                if not data:
                    return
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    parts = line.decode(errors="replace").strip().split()
                    if not parts:
                        continue
                    cmd = parts[0].upper()
                    if cmd == "LIST":
                        conn.sendall((", ".join(SECRETS) + "\n").encode())
                    elif cmd == "GET" and len(parts) > 1:
                        conn.sendall((SECRETS.get(parts[1], "no such secret") + "\n").encode())
                    elif cmd == "QUIT":
                        conn.sendall(b"bye\n")
                        return
                    else:
                        conn.sendall(b"unknown command\n")
        except OSError:
            pass
        finally:
            conn.close()


def knock_listener(state, door, secret, port, skew):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    state.log("info", "-", f"UDP knock listener on {port} (never replies)")
    while True:
        data, addr = sock.recvfrom(2048)
        ip = addr[0]
        status, nonce = verify_knock(secret, data, skew)
        if status == "ok":
            with state.lock:
                now = time.time()
                for n in [n for n, t in state.seen_nonces.items() if now - t > skew * 2]:
                    del state.seen_nonces[n]
                replay = nonce in state.seen_nonces
                state.seen_nonces[nonce] = now
            if replay:
                state.log("knock_replay", ip, f"nonce {nonce:016x} already used -> ignored")
                continue
            state.log("knock_ok", ip, f"valid knock -> door open for {door.window}s")
            door.open_for(ip)
        else:
            state.log(f"knock_{status}", ip, f"{len(data)} bytes -> ignored silently")
        # NOTE: no sendto() anywhere - the server is silent by design.


def tarpit(conn, ip, state, interval, max_seconds):
    """Endlessh-style: accept, then drip one junk line every `interval`s."""
    start = time.time()
    with state.lock:
        state.tarpit_active += 1
    state.log("decoy_hits", ip, "connected to decoy service - trapping")
    try:
        conn.settimeout(interval)
        while time.time() - start < max_seconds:
            try:
                conn.sendall(f"{random.getrandbits(32):x}\r\n".encode())
            except OSError:
                break
            try:                      # also notice when the client leaves
                if conn.recv(1024) == b"":
                    break
            except socket.timeout:
                pass
            except OSError:
                break
    finally:
        wasted = time.time() - start
        with state.lock:
            state.tarpit_active -= 1
            state.counters["tarpit_seconds"] += int(wasted)
        state.log("tarpit_end", ip, f"held attacker for {wasted:.1f}s")
        conn.close()


def decoy_listener(state, port, interval, max_seconds, max_conns):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(64)
    state.log("info", "-", f"TCP decoy tarpit on {port}")
    while True:
        conn, addr = sock.accept()
        if state.tarpit_active >= max_conns:
            conn.close()
            continue
        threading.Thread(target=tarpit, args=(conn, addr[0], state, interval, max_seconds),
                         daemon=True).start()


PAGE = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard.html")).read()


def make_handler(state):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path.startswith("/api/state"):
                body, ctype = json.dumps(state.snapshot()).encode(), "application/json"
            else:
                body, ctype = PAGE.encode(), "text/html; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    return H


def main():
    p = argparse.ArgumentParser(description="Ghost Door stealth server")
    p.add_argument("--secret", default=os.environ.get("GHOST_SECRET", DEFAULT_SECRET))
    p.add_argument("--knock-port", type=int, default=DEFAULT_KNOCK_PORT)
    p.add_argument("--vault-port", type=int, default=DEFAULT_VAULT_PORT)
    p.add_argument("--decoy-port", type=int, default=DEFAULT_DECOY_PORT)
    p.add_argument("--web-port", type=int, default=DEFAULT_WEB_PORT)
    p.add_argument("--window", type=float, default=30, help="seconds the door stays open per knock")
    p.add_argument("--skew", type=float, default=10, help="max clock skew accepted on knocks (s)")
    p.add_argument("--tarpit-interval", type=float, default=2.0)
    p.add_argument("--tarpit-max", type=float, default=300)
    p.add_argument("--tarpit-conns", type=int, default=100)
    p.add_argument("--log", default="events.jsonl")
    a = p.parse_args()

    state = State(a.log)
    door = Door(state, a.vault_port, a.window)
    threading.Thread(target=door.reaper, daemon=True).start()
    threading.Thread(target=knock_listener, args=(state, door, a.secret, a.knock_port, a.skew), daemon=True).start()
    threading.Thread(target=decoy_listener, args=(state, a.decoy_port, a.tarpit_interval, a.tarpit_max, a.tarpit_conns), daemon=True).start()
    web = ThreadingHTTPServer(("0.0.0.0", a.web_port), make_handler(state))
    state.log("info", "-", f"dashboard on http://localhost:{a.web_port}")
    try:
        web.serve_forever()
    except KeyboardInterrupt:
        print("bye")


if __name__ == "__main__":
    main()
