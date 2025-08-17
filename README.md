# docker-dns-failback

A lightweight DNS failover proxy in Python, designed to sit between Pi-hole and Unbound.

- **Primary resolver**: Local Unbound (e.g. `127.0.0.1:5335`)
- **Fallbacks**: Public DNS (Cloudflare, Google, Quad9, etc.)
- **Containerized**: Runs in Docker with healthcheck + logging

## Usage

```bash
git clone https://github.com/ordor2k/docker-dns-failback.git
cd docker-dns-failback
docker compose up -d
