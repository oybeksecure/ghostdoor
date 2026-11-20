# Ghost Door — a UDP-knock stealth server with a TCP tarpit

**Computer Networks – Assignment 4.** A small defensive security tool that
uses **UDP and TCP for what each is best at**, plus the attacker tools to
test it.

## The idea

| Port | Proto | Behaviour |
|------|-------|-----------|
| 9999 | UDP | Silent knock listener. Never replies, so a scanner can't tell it exists. |
| 9000 | TCP | The real service (a secret vault). **Closed** (kernel RST) until a valid knock arrives. |
| 9001 | TCP | Decoy "service" that is always open: an *endlessh-style tarpit* that drips junk bytes and wastes the attacker's time. |
| 8080 | HTTP | Live dashboard of every event. |

**Why UDP for the knock?** It is connectionless: no handshake, no reply, no
state — nothing for a scanner to detect or SYN-flood. **Why TCP for the vault?**
It needs a reliable, ordered, stateful stream — and the 3-way handshake is
exactly what lets the server decide, per source IP, who gets in.

### Knock packet (51 bytes)
`MAGIC(3) | timestamp_ms(8) | nonce(8) | HMAC-SHA256(32)`
- HMAC with a shared secret → forged knocks are rejected.
- Timestamp window (10 s) → old packets are rejected.
- Server remembers nonces → a captured packet can't be **replayed**.
- A valid knock opens the door only for the **source IP of the knock**, for
  `--window` seconds (default 30), then the listener closes again.

## Run it (Python 3.10+, standard library only)

```bash
# terminal 1 – server (+ dashboard at http://localhost:8080)
python3 server.py

# terminal 2 – attacker view (use --src 127.0.0.3 to be a different "machine")
python3 scanner.py --ports 8990-9010 --src 127.0.0.3    # 9000 closed, 9001 open
python3 scanner.py --ports 9001 --src 127.0.0.3 --grab  # gets stuck in the tarpit
python3 vault_client.py --src 127.0.0.2                 # refused: door closed

# terminal 3 – defender
python3 knock.py --src 127.0.0.2 --print-hex
python3 vault_client.py --src 127.0.0.2                 # LIST / GET flag / QUIT

# attacker tries to beat the knock
python3 replay_attack.py replay --hex <hex from above> --src 127.0.0.3
python3 replay_attack.py forge --src 127.0.0.3
```

Automated test of the whole story: `python3 run_demo.py` → prints PASS/FAIL
for 10 checks (scan, tarpit, knock, replay, forgery, silence, expiry).

> **Ethics:** only run scanners/attacks against your own machine or lab.
> `127.0.0.2/3` are extra loopback addresses on Linux/macOS, so one computer
> can play defender and attacker. For two real machines, drop `--src` and set
> `--host` to the server's IP.

## Limitations (honest ones)
- While the door is open for one IP, the TCP port completes handshakes for
  everyone; other IPs are reset right after (logged as `intruders_refused`).
  A production version would do the per-IP filtering in the firewall (iptables / nftables).
- The shared secret is static; real systems would use per-user keys or asymmetric signatures.
- An attacker who can *spoof* the source IP of a valid knock needs the secret first, but
  on-path observers could race the legit client — this is a teaching tool.
- Sessions are cut when the window ends (re-knock to continue).

## Agentic AI log (fill in with your own words)
- Used an AI coding agent to scaffold the protocol, server, tools and tests.
- First test run: 2 of 10 checks failed. Cause: my test assumed the port is
  refused for the attacker, but during an open window the handshake succeeds
  and the server resets afterwards. Fixed the test, documented the behaviour.
- Next: ask the agent to red-team the design (replay, spoofing, resource
  exhaustion of the tarpit → capped by `--tarpit-conns`) and record what it finds.

## Files
`server.py` server + dashboard · `common.py` knock format · `knock.py` client ·
`vault_client.py` · `scanner.py` + `replay_attack.py` attacker tools ·
`run_demo.py` automated test · `dashboard.html`
