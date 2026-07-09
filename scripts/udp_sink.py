#!/usr/bin/env python3

import socket
import select
import time
import argparse


def parse_ports(spec):
    """Accetta '8888,8889' oppure '8888-8899' oppure combinazioni con virgole."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ports", required=True,
                        help="Porte UDP da ascoltare, es. '8888-8899,9980-9999'")
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--duration", type=float, default=0,
                        help="Secondi di ascolto (0 = per sempre finche' non ucciso)")
    args = parser.parse_args()

    ports = parse_ports(args.ports)
    socks = []
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # buffer di ricezione ampio: assorbe i burst senza perdere pacchetti
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        except OSError:
            pass
        try:
            s.bind((args.bind, p))
            s.setblocking(False)
            socks.append(s)
        except OSError as e:
            print(f"[udp_sink] impossibile bindare la porta {p}: {e}", flush=True)

    if not socks:
        print("[udp_sink] nessuna porta aperta, esco.", flush=True)
        return

    print(f"[udp_sink] in ascolto su {len(socks)} porte UDP: {ports[0]}..{ports[-1]}", flush=True)
    end = time.time() + args.duration if args.duration > 0 else None

    while True:
        if end is not None and time.time() >= end:
            break
        readable, _, _ = select.select(socks, [], [], 1.0)
        for s in readable:
            try:
                # svuota tutto il backlog della porta senza bloccare
                while True:
                    s.recv(65535)
            except (BlockingIOError, OSError):
                pass

    for s in socks:
        s.close()
    print("[udp_sink] terminato.", flush=True)


if __name__ == "__main__":
    main()
