#!/usr/bin/env python3
import os, socket, struct, sys
from dnslib import DNSRecord

LISTEN_ADDR = os.getenv("LISTEN_ADDR", "127.0.0.1")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "5355"))

def udp_query(q: bytes, addr: str, port: int, timeout: float = 1.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.sendto(q, (addr, port))
    data, _ = s.recvfrom(4096)
    s.close()
    return data

def main():
    try:
        q = DNSRecord.question(".")
        resp = udp_query(q.pack(), LISTEN_ADDR, LISTEN_PORT)
        # Basic sanity: parseable & QR=1
        r = DNSRecord.parse(resp)
        if r.header.qr != 1:
            sys.exit(2)
        sys.exit(0)
    except Exception:
        sys.exit(1)

if __name__ == "__main__":
    main()
