# tcp-rs

A userspace TCP/IP stack implemented in Rust, running over a TUN interface in Linux/WSL2.

## Overview

`tcp-rs` implements a functional TCP stack from scratch in userspace, handling the full connection lifecycle including the three-way handshake, data transfer, and connection teardown. Packets are exchanged via a TUN interface, bypassing the kernel's TCP implementation entirely.

## Features

- Three-way handshake (SYN, SYN-ACK, ACK)
- Reliable data transfer with piggybacked ACKs
- Connection teardown (FIN/FIN-ACK exchange)
- TCP timestamp option (RFC 1323) — correct TSval/TSecr echo
- Sequence and acknowledgment number validation with wraparound support
- Per-connection state machine (LISTEN → SYN_RCVD → ESTAB → CLOSE_WAIT → LAST_ACK → CLOSED)
- Connection demultiplexing via 4-tuple HashMap
- Window size tracking
- MSS, SACK_PERM, and window scale negotiation in SYN

## Architecture

```
┌─────────────────────────────────────┐
│            Application              │
└────────────────┬────────────────────┘
                 │
┌────────────────▼────────────────────┐
│         TUN Interface               │  tun_tap crate
└────────────────┬────────────────────┘
                 │ raw IP packets
┌────────────────▼────────────────────┐
│         IPv4 Parser                 │  src/ipv4.rs
└────────────────┬────────────────────┘
                 │
┌────────────────▼────────────────────┐
│         TCP Header Parser           │  src/tcp_header.rs
└────────────────┬────────────────────┘
                 │
┌────────────────▼────────────────────┐
│   Connection State Machine          │  src/tcp.rs
│                                     │
│  HashMap<4-tuple, Connection>       │
│  ├─ handle_packet_synchronized()    │
│  ├─ handle_packet_unsynchronized()  │
│  ├─ send_syn_ack()                  │
│  ├─ echo_with_ack()                 │
│  └─ send_fin()                      │
└─────────────────────────────────────┘
```

## Getting Started

### Prerequisites

- Rust (stable)
- Linux or WSL2
- `sudo` access (required for TUN device creation)

### Setup

Create and configure the TUN interface:

```bash
sudo ip tuntap add dev tun0 mode tun
sudo ip addr add 192.168.0.2/24 dev tun0
sudo ip link set tun0 up
```

### Build and Run

```bash
cargo build --release
sudo ./target/release/tcp-rs
```

### Testing

With `nc`:
```bash
echo "hello" | nc 192.168.0.2 7878
```

## State Machine

```
LISTEN ──SYN──► SYN_RCVD ──ACK──► ESTAB
                                     │
                                  FIN recv
                                     │
                               CLOSE_WAIT ──FIN──► LAST_ACK ──ACK──► CLOSED
```

## What's Not Implemented (Yet)

- Congestion control (slow start, AIMD, fast retransmit)
- Retransmission timer and reliable delivery
- Out-of-order segment buffering
- SACK processing
- Nagle's algorithm
- TIME_WAIT state

## Resources

- [RFC 793 — Transmission Control Protocol](https://www.rfc-editor.org/rfc/rfc793)
- [RFC 1323 — TCP Extensions for High Performance](https://www.rfc-editor.org/rfc/rfc1323)
- [RFC 7323 — TCP Extensions for High Performance (updated)](https://www.rfc-editor.org/rfc/rfc7323)
- [Jon Gjengset's live-coded TCP in Rust](https://www.youtube.com/watch?v=bzja9fQWzdA) — inspiration for this project
