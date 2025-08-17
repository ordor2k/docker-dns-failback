#!/usr/bin/env python3
import os
import socket
import socketserver
import struct
import threading
import time
import logging
import signal
import sys
from typing import List, Tuple, Optional

from dnslib import DNSRecord, DNSHeader, DNSQuestion, DNSError

def _env(name: str, default: str) -> str:
    v = os.getenv(name)
    return v if v not in (None, "") else default

def _parse_hostport(item: str, default_port: int) -> Tuple[str, int]:
    item = item.strip()
    if not item:
        raise ValueError("empty host")
    if ":" in item:
        host, port_s = item.rsplit(":", 1)
        return host.strip(), int(port_s)
    return item, default_port

def _parse_upstreams(csv: str, default_port: int) -> List[Tuple[str,int]]:
    out: List[Tuple[str,int]] = []
    for part in csv.split(","):
        part = part.strip()
        if part:
            out.append(_parse_hostport(part, default_port))
    return out

# -------------------------
# Configuration (via env)
# -------------------------
LISTEN_ADDR = _env("LISTEN_ADDR", "0.0.0.0")
LISTEN_PORT = int(_env("LISTEN_PORT", "5355"))

# Unbound default often 127.0.0.1:5335 (Pi-hole setup)
PRIMARY_DNS = _parse_hostport(_env("PRIMARY_DNS", "127.0.0.1:5335"), 53)

# Fallback list (CSV of host[:port])
FALLBACK_DNS = _parse_upstreams(
    _env("FALLBACK_DNS", "1.1.1.1,8.8.8.8,9.9.9.9,1.0.0.1"),
    53
)

UDP_TIMEOUT = float(_env("UDP_TIMEOUT", "1.0"))
TCP_TIMEOUT = float(_env("TCP_TIMEOUT", "2.0"))
RETRIES_PER_UPSTREAM = int(_env("RETRIES_PER_UPSTREAM", "1"))

LOG_LEVEL = _env("LOG_LEVEL", "INFO").upper()
LOG_FORMAT = "[%(asctime)s] %(levelname)s %(message)s"
# -------------------------

logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO), format=LOG_FORMAT)
logger = logging.getLogger("dns-failover-proxy")
_shutdown = threading.Event()

def _udp_query(upstream: Tuple[str, int], payload: bytes, timeout: float) -> Optional[bytes]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(payload, upstream)
            data, _ = s.recvfrom(4096)
            return data
    except (socket.timeout, OSError) as e:
        logger.debug(f"UDP query to {upstream} failed: {e}")
        return None

def _tcp_query(upstream: Tuple[str, int], payload: bytes, timeout: float) -> Optional[bytes]:
    try:
        with socket.create_connection(upstream, timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(struct.pack("!H", len(payload)) + payload)
            hdr = s.recv(2)
            if len(hdr) < 2:
                return None
            (length,) = struct.unpack("!H", hdr)
            buf = b""
            while len(buf) < length:
                chunk = s.recv(length - len(buf))
                if not chunk:
                    return None
                buf += chunk
            return buf
    except (socket.timeout, OSError) as e:
        logger.debug(f"TCP query to {upstream} failed: {e}")
        return None

def _try_upstream(upstream: Tuple[str, int], query: bytes) -> Optional[bytes]:
    udp_resp = _udp_query(upstream, query, UDP_TIMEOUT)
    if udp_resp is None:
        return None
    try:
        dns = DNSRecord.parse(udp_resp)
        if dns.header.tc:
            logger.debug(f"Truncated UDP response from {upstream}; retrying via TCP")
            tcp_resp = _tcp_query(upstream, query, TCP_TIMEOUT)
            return tcp_resp or udp_resp
        return udp_resp
    except DNSError:
        logger.debug(f"Failed to parse UDP response from {upstream}; trying TCP")
        tcp_resp = _tcp_query(upstream, query, TCP_TIMEOUT)
        return tcp_resp

def resolve_with_failover(query: bytes) -> Optional[bytes]:
    upstreams = [PRIMARY_DNS] + FALLBACK_DNS
    for upstream in upstreams:
        for attempt in range(1 + RETRIES_PER_UPSTREAM):
            resp = _try_upstream(upstream, query)
            if resp:
                logger.debug(f"Answered via {upstream} (attempt {attempt+1})")
                return resp
            logger.debug(f"No response from {upstream} (attempt {attempt+1})")
        logger.info(f"Upstream failed: {upstream}")
    return None

class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        client = self.client_address
        try:
            q = DNSRecord.parse(data)
            qname = str(q.q.qname) if q.q else "<?>"
            logger.debug(f"UDP query from {client}: {qname}")
            resp = resolve_with_failover(data)
            if resp:
                sock.sendto(resp, client)
            else:
                try:
                    rq = DNSRecord.parse(data)
                    r = DNSRecord(
                        DNSHeader(id=rq.header.id, qr=1, aa=0, ra=1, rcode=2),
                        q=rq.q if rq.q else DNSQuestion("invalid.")
                    )
                    sock.sendto(r.pack(), client)
                except DNSError:
                    pass
        except DNSError:
            logger.debug(f"Malformed UDP DNS from {client}; ignoring")

class TCPHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        client = self.client_address
        try:
            hdr = self.rfile.read(2)
            if len(hdr) < 2:
                return
            (length,) = struct.unpack("!H", hdr)
            payload = self.rfile.read(length)
            if len(payload) < length:
                return
            q = DNSRecord.parse(payload)
            qname = str(q.q.qname) if q.q else "<?>"
            logger.debug(f"TCP query from {client}: {qname}")

            resp = resolve_with_failover(payload)
            if resp is None:
                try:
                    rq = DNSRecord.parse(payload)
                    r = DNSRecord(
                        DNSHeader(id=rq.header.id, qr=1, aa=0, ra=1, rcode=2),
                        q=rq.q if rq.q else DNSQuestion("invalid.")
                    ).pack()
                    self.wfile.write(struct.pack("!H", len(r)) + r)
                except DNSError:
                    return
                return
            self.wfile.write(struct.pack("!H", len(resp)) + resp)
        except DNSError:
            logger.debug(f"Malformed TCP DNS from {client}; ignoring")
        except (ConnectionResetError, BrokenPipeError):
            pass

class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    daemon_threads = True
    allow_reuse_address = True

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

def _health_logger():
    while not _shutdown.is_set():
        try:
            q = DNSRecord.question(".")
            resp = _try_upstream(PRIMARY_DNS, q.pack())
            if resp:
                logger.debug("Health: PRIMARY reachable")
            else:
                logger.info("Health: PRIMARY appears down/unreachable")
        except Exception as e:
            logger.debug(f"Health check error: {e}")
        _shutdown.wait(30)

def main():
    logger.info(f"DNS failover proxy listening on {LISTEN_ADDR}:{LISTEN_PORT} "
                f"(primary {PRIMARY_DNS}, fallbacks {FALLBACK_DNS})")
    udp_server = ThreadedUDPServer((LISTEN_ADDR, LISTEN_PORT), UDPHandler)
    tcp_server = ThreadedTCPServer((LISTEN_ADDR, LISTEN_PORT), TCPHandler)

    t_udp = threading.Thread(target=udp_server.serve_forever, name="UDPServer", daemon=True)
    t_tcp = threading.Thread(target=tcp_server.serve_forever, name="TCPServer", daemon=True)
    t_hlt = threading.Thread(target=_health_logger, name="Health", daemon=True)

    t_udp.start()
    t_tcp.start()
    t_hlt.start()

    def stop(*_):
        logger.info("Shutting down...")
        _shutdown.set()
        udp_server.shutdown()
        tcp_server.shutdown()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    try:
        while not _shutdown.is_set():
            time.sleep(0.2)
    finally:
        udp_server.server_close()
        tcp_server.server_close()
        logger.info("Bye.")

if __name__ == "__main__":
    try:
        import dnslib  # noqa: F401
    except ImportError:
        sys.stderr.write("Missing dependency 'dnslib'. Install with: pip install dnslib\n")
        sys.exit(1)
    main()
