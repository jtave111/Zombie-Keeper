# Network Session

Blue team domain — tools for active network discovery, fingerprinting, and intelligence gathering.
Each tool feeds data into the `NetworkSession → Node → Port → Vulnerability` model in the C2 API.

## Structure

| Directory | Description |
|-----------|-------------|
| `scanners/` | Active scanning tools (full subnet fingerprint, port scan, service probe) |
| `discovery/` | Host discovery (ICMP sweep, ARP scan, DNS enumeration) |
| `osint/` | External/passive reconnaissance (subdomain, Shodan, SSL analysis) |

> Shared libraries (e.g. `ping`) live in `libs/` at the Arsenal root and are available to all domains.

## Tools

### Scanners
- [local-fingerprint](scanners/local-fingerprint/README.md) — Full subnet fingerprint: ICMP sweep + TCP port scan + service enumeration. Sends results to `/api/recon`.

## Build

```bash
# From Arsenal root
make network-session

# Or via cmake directly
cmake --build build --target LocalFingerPrint
```
