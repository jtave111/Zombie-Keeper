# LocalFingerPrint

Full local network fingerprinting tool. Performs ICMP host discovery + TCP port scanning via raw sockets, builds a complete `NetworkSession` model, and sends results to the C2 API via HTTP POST.

**Requires:** root or `CAP_NET_RAW` capability, `libcurl`

**Dependencies:** `ping` (shared lib at `libs/cpp/ping/`), `CURL::libcurl`

## Implementations

| Language | Directory | Status |
|----------|-----------|--------|
| C++17 | `cpp/` | Done |
| Python | `python/` | Helper scripts |
| Go | `go/` | Planned |

## Build

```bash
# From Arsenal root (recommended)
cmake --build build --target LocalFingerPrint

# Or build everything
make
```

## Apply Network Capabilities

Raw sockets require elevated privileges. After building, apply `CAP_NET_RAW`:

```bash
sudo cmake --build build --target setcap
```

Must be reapplied every time the binary is recompiled.

## Usage

```bash
./LocalFingerPrint <interface> <subnet_cidr> <c2_url>

# Example
./LocalFingerPrint eth0 192.168.1.0/24 http://localhost:8080
```

## API Integration

Posts results to `POST /api/recon` — feeds `NetworkSession → Node → Port → Vulnerability`.
