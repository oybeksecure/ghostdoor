#!/usr/bin/env python3
"""Ghost Door - one-command narrated demo.

    python3 run_all.py            # opens the dashboard, runs everything with pauses
    python3 run_all.py --fast     # no pauses (quick check)
    python3 run_all.py --keep     # keep the server running at the end (Ctrl+C to stop)

It starts server.py, then runs the same commands you would type by hand:
scanner -> tarpit -> vault refused -> knock -> vault session -> replay attack
-> forged knock -> wait for the door to close.
"""
import argparse
import os
import socket
import subprocess
import sys
import time
import webbrowser

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable
GOOD, BAD, H = "127.0.0.2", "127.0.0.3", "127.0.0.1"

ap = argparse.ArgumentParser()
ap.add_argument("--fast", action="store_true", help="no pauses between steps")
ap.add_argument("--keep", action="store_true", help="leave the server running at the end")
ap.add_argument("--window", type=float, default=40, help="seconds the door stays open")
ap.add_argument("--no-browser", action="store_true")
args = ap.parse_args()


def pause(sec):
    if not args.fast:
        time.sleep(sec)


def step(title):
    print(f"\n{'=' * 64}\n{title}\n{'=' * 64}", flush=True)
    pause(1.5)


def run(*cmd):
    """Run one of our scripts exactly like you would in a terminal."""
    print("$ python3 " + " ".join(os.path.basename(c) if c.endswith(".py") else c for c in cmd), flush=True)
    out = subprocess.run([PY, *[os.path.join(HERE, c) if c.endswith(".py") else c for c in cmd]],
                         cwd=HERE, capture_output=True, text=True)
    text = (out.stdout + out.stderr).strip()
    if text:
        print(text, flush=True)
    return out.stdout


# --- pre-flight: extra loopback IPs (needed on macOS) -----------------------
for ip in (GOOD, BAD):
    s = socket.socket()
    try:
        s.bind((ip, 0))
    except OSError:
        sys.exit(f"Cannot use {ip}. On macOS run once:\n"
                 f"  sudo ifconfig lo0 alias {GOOD} up\n  sudo ifconfig lo0 alias {BAD} up")
    finally:
        s.close()

# --- start the server --------------------------------------------------------
step("Starting server.py  (UDP knock 9999 | TCP vault 9000 | TCP decoy 9001 | web 8080)")
srv = subprocess.Popen([PY, os.path.join(HERE, "server.py"), "--window", str(args.window),
                        "--log", os.path.join(HERE, "events.jsonl")], cwd=HERE,
                       stdout=subprocess.DEVNULL)
time.sleep(1.0)
if srv.poll() is not None:
    sys.exit("Server failed to start - is another server.py still running? (pkill -f server.py)")

try:
    if not args.no_browser:
        webbrowser.open("http://localhost:8080")
        print("Dashboard: http://localhost:8080  (keep it visible while this runs)")
    pause(4)

    step("1) ATTACKER scans the host: the real vault port 9000 should look closed")
    run("scanner.py", "--ports", "8995-9005", "--src", BAD)
    pause(3)

    step("2) ATTACKER grabs the banner of the only open port (9001) -> trapped in the tarpit")
    run("scanner.py", "--ports", "9001", "--src", BAD, "--grab")
    pause(3)

    step("3) ATTACKER tries the vault directly -> refused")
    run("vault_client.py", "--src", BAD)
    pause(3)

    step("4) DEFENDER sends a signed UDP knock (no reply is ever sent)")
    out = run("knock.py", "--src", GOOD, "--print-hex")
    captured = out.strip().splitlines()[-1]      # the packet a sniffer would capture
    pause(3)

    step("5) DEFENDER connects to the now-open TCP vault")
    from vault_client import connect
    s = connect(H, 9000, GOOD)
    print(s.recv(200).decode().strip())
    for cmd in ("LIST", "GET flag"):
        print(f"vault> {cmd}")
        s.sendall((cmd + "\n").encode())
        print(s.recv(200).decode().strip())
        pause(1.5)
    s.sendall(b"QUIT\n")
    s.close()
    pause(3)

    step("6) ATTACKER replays the sniffed knock from his own IP -> rejected (nonce already used)")
    run("replay_attack.py", "replay", "--hex", captured, "--src", BAD)
    pause(2)
    run("vault_client.py", "--src", BAD)
    pause(3)

    step("7) ATTACKER forges a knock with a guessed secret -> rejected (bad HMAC)")
    run("replay_attack.py", "forge", "--src", BAD)
    pause(3)

    step(f"8) Waiting for the {args.window:.0f}s window to end -> the door closes again")
    time.sleep(args.window + 1.5)   # real time, even in --fast mode (+margin for the door to close)
    run("vault_client.py", "--src", GOOD)

    print("\nDone. Full log: events.jsonl")
    if args.keep:
        print("Server still running - Ctrl+C to stop.")
        srv.wait()
except KeyboardInterrupt:
    print("\nstopped")
finally:
    if srv.poll() is None:
        srv.terminate()
