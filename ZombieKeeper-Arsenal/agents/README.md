# Agents

Red team domain — C2 implants, exploits, post-exploitation modules, and attack tools.
Each implant registers itself against the `Agent` model in the C2 API.

## Structure

| Directory | Description |
|-----------|-------------|
| `implants/` | C2 beacons and stagers, organized by platform (linux, windows, cross-platform) |
| `exploits/` | Exploitation modules by platform (linux, windows, web) |
| `post-exploitation/` | Post-access modules: persistence, privesc, credential harvesting |
| `attacks/` | Active attack modules by vector (network, web, credentials) |
| `payloads/` | Shellcodes and ROP chains by architecture (x86_64, arm64) |
| `evasion/` | AV/EDR bypass and anti-forensics techniques |
| `hardware/` | Hardware-based attacks (BadUSB, SDR, RFID) |

> Shared libraries (e.g. `ping`) live in `libs/` at the Arsenal root — use `target_link_libraries(<target> PRIVATE ping)` directly, no extra config needed.

## Platform Targets

| Platform | Implants | Status |
|----------|----------|--------|
| Linux | `implants/linux/` | Planned |
| Windows | `implants/windows/` | Planned |
| Cross-platform | `implants/cross-platform/` | Planned |

## Activating the Domain

To enable CMake build for this domain:

1. Create `agents/CMakeLists.txt` with `add_subdirectory` entries for each tool
2. Uncomment `add_subdirectory(agents)` in the Arsenal root `CMakeLists.txt`
3. Update `scripts/build-agents.sh` with the correct target names
4. Run `cmake -B build` to reconfigure
