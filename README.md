# ⚡ Warp Migration Engine — LuaJIT 2.1 + FFI Edition

**High-Performance Layer 3 Kernel Handshake Migration Engine for Cloudflare WARP**  
Zero-compilation, zero-allocation hot-path QUIC / MASQUE engine written in **LuaJIT 2.1 + FFI**, enhanced with **Official Cloudflare WARP Auto-Configuration**, **Event-Driven Bidirectional `1-RTT` Migration**, and a **Dual-Perspective Self-Learning AI Brain**.

---

## 🌟 Why LuaJIT 2.1 + FFI? (Comparison with the Rust Edition)

| Feature | Rust Edition (`warp-migration-engine`) | LuaJIT 2.1 + FFI Edition (This Repo) |
| :--- | :--- | :--- |
| **Focus & Architecture** | Dual-mode (23 `.rs` files, ~3,849 lines) | **Streamlined 100% QUIC / MASQUE Engine** (4 `.lua` core modules) |
| **Compile Time** | Cargo release build required | **0 seconds** (Instant execution + JIT machine code) |
| **External Dependencies** | Tokio, WinDivert-rs, Clap, Serde, Socket2 | **Zero** (Standalone `luajit.exe` / `luajit`) |
| **Hot-Path Memory** | Heap-managed `Vec<u8>` buffers | **Zero-Allocation** preallocated `ffi.new` buffers |
| **Official WARP Integration** | Manual CLI setup required | **One-Time Auto-Config & Saved Profile** (`mode warp` / `MASQUE h3-only` / Relay Split-Tunnel WFP Exclude) |
| **MASQUE Migration Logic** | Static count triggers | **Event-Driven BiDi `1-RTT`** (`30rx + 45tx >= 6.5s` + Aux Health-Check Guard) |
| **Runtime Intelligence** | Static logs | **Dual-Perspective AI Brain** (Welford + Discounted UCB1 + `evolved_policy.lua` + 200-pkt Ring Buffer + Unified Logs) |
| **Protocol Compatibility** | 17 Camouflage Masks | **100% Identical Wire Format** (Interoperable with Rust relay/client) |

---

## 🚀 Key Features

### 1. Native Official Cloudflare WARP Client Support (`warp-cli` Auto-Setup)
Works directly alongside the **Official Cloudflare WARP Windows Client** in both **Full Tunnel (`mode warp`)** and **Local Proxy (`mode proxy`)**:
- One-time setup wizard lets you save your **Relay Server (`IP:PORT`)**, customize your **Cloudflare WARP Endpoint (`IP:PORT`, default `162.159.198.2:8095`)**, and configure `warp-cli.exe` automatically:
  - Sets `mode warp` (Full Tunnel) or `mode proxy`
  - Configures `MASQUE` + `h3-only` + target endpoint (`warp-cli tunnel endpoint set`)
  - Disables strict connectivity probes (`debug connectivity-check disable`) and enables `debug high-timeouts enable`
  - **Automatically excludes `<RELAY_IP>` from WARP Split Tunnel** (`warp-cli tunnel ip add`) so WARP's internal Windows WFP (`catch-all Deny`) firewall never blocks outbound handshake packets to your relay.
- Saves everything in `config.json` — on all future runs it skips repetitive setup questions and asks **only** which Camouflage Protocol (`0..17`, or `r` to reconfigure) to use!
- Optionally auto-runs `warp-cli connect` immediately after WinDivert opens so zero initial packets are missed.

### 2. All 17 Named Layer-4 Camouflage Protocols (`common.lua`)
Full named selection menu (`0..17`) using raw `uint8_t` FFI buffers and `bit.*` operations:

| ID | Key | Description |
| :--- | :--- | :--- |
| `0` | `auto` | AI Smart Auto-Rotation (Discounted UCB1 Tier-1 Masks) |
| `1` | `junk` | Classic Random Junk (AmneziaWG) |
| `2` | `quic_v1` | QUIC v1 / HTTP/3 Short Header (`0x43`) |
| `3` | `quic_v2` | QUIC v2 / RFC 9369 Initial Header (`0xD0`) |
| `4` | `webrtc` | WebRTC / SRTP Audio Video Stream (`RTP v2`) *(Tier-1)* |
| `5` | `dtls` | DTLS 1.2 Application Data Record *(Tier-1)* |
| `6` | `dns` | DNS Query (Standard RFC 1035) |
| `7` | `esp` | IPsec NAT-T ESP (Enterprise Tunnel) *(Tier-1, Default Mode 2)* |
| `8` | `utp` | uTP BitTorrent (State Data Packet) |
| `9` | `raknet` | RakNet Gaming (Minecraft Bedrock) |
| `10` | `stun` | STUN / ICE Binding Request (RFC 5389) *(Tier-1)* |
| `11` | `turn` | TURN ChannelData (Relayed Media) |
| `12` | `steam` | Steam / Valve Source Query (CS:GO) |
| `13` | `sdr` | Steam Datagram Relay (CS2 SDR Transport) |
| `14` | `riot` | Riot Games (Valorant / LoL Media) |
| `15` | `zoom` | Zoom Media Stream (RTP Video / Voice) |
| `16` | `rdp` | Microsoft RDP over UDP (MS-RDPEUDP) |
| `17` | `discord` | Discord Voice & Media (Opus Audio) |

### 3. Event-Driven Bidirectional `1-RTT` Migration & Aux Session Guard (`client.lua`)
- **RFC 9000 Coalesced QUIC Dissection:** Parses Varint + Long Header frames (`Initial`, `Retry`, `Handshake`, `0-RTT`, `1-RTT`).
- **BiDi Event-Driven Migration:** Confirms `2nd Server Handshake`, waits for bidirectional `1-RTT` proof (`>= 30` server `1-RTT` RX frames + `>= 45` client `1-RTT` TX frames + `>= 6.5s` settle time, or an `8.5s / 180-pkt` fallback cap) so WARP finishes HTTP/3 `CONNECT-IP`, `wintun` creation, and PMTU setup before switching to Direct Wire-Speed (`11.0s` initial Path-Validation grace).
- **Auxiliary Session Protection (`AUX SESSION`):** Prevents WARP periodic health-check `Initial` packets from triggering `Network: unstable` disconnects once the primary relay is locked.

### 4. Ultra-Lightweight Linux Epoll Relay (`server.lua`)
- Direct `ffi.C` bindings to Linux `socket`, `bind`, `recvfrom`, `sendto`, and `epoll` (`__attribute__((packed))`).
- Dual-stack IPv4 + lazy-allocated IPv6 upstream sockets (saves 50% FDs on IPv4 traffic), 60-second inactivity auto-purge, and zero user-IP disk logging.

### 5. Dual-Perspective Self-Learning AI Brain & Unified Logging (`telemetry.lua`)
- **Unified Pipeline:** Every lifecycle phase, WARP auto-config action, handshake, migration, 15s throughput heartbeat, and AI RCA summary writes cohesively to **Console**, **`wme_session.log`**, and **`ai_report.json`**.
- **Internal Code Brain:** `jit.attach` trace profiler, memory monitor, 5×5 phase transition matrix, and `autonomous_upgrade_blueprint`.
- **External Network Brain:** Welford online baseline, `Discounted UCB1` ($\gamma = 0.90$) with circadian buckets & 15% hysteresis, `Endpoint Guard` (60s), `Port Guard` (120s), 200-packet Ring Buffer, and contract-verified `evolved_policy.lua` (`<1ms` auto-rollback).

---

## 📦 Quick Start (Windows Client)

1. Ensure `luajit.exe`, `lua51.dll`, `WinDivert.dll`, and `WinDivert64.sys` are in the project directory.
2. Double-click **`run_test.bat`** (auto-elevates to Administrator).
3. On first run, choose a Camouflage Protocol (`0..17`), enter your **Relay IP:PORT** and **WARP Endpoint IP:PORT**, and allow **Official Cloudflare WARP Auto-Setup**. On all subsequent runs, only select your Protocol (`0..17`, or `r` to reconfigure).
4. Runtime controls:
   - `[Enter]` — Re-Arm relay manually
   - `[S]` — Save live diagnostic snapshot to `ai_report.json` + `wme_session.log`
   - `[Ctrl+C]` — Flush unified telemetry & exit cleanly

---

## 🖥️ Server Deployment (Linux VPS)

Upload `server.lua`, `common.lua`, and `deploy_server.sh` to your Linux VPS (Ubuntu/Debian/Alpine):

```bash
chmod +x deploy_server.sh
./deploy_server.sh 4678
```

Or run directly with LuaJIT:

```bash
luajit server.lua 4678
```

---

## 🧪 Running Unit Tests

```bat
luajit.exe test_suite.lua
```

Verifies `WINDIVERT_ADDRESS` x64 ABI (64 bytes), RFC 9000 Varint & coalesced QUIC parsing, all 17 camouflage protocols, Cloudflare IPv4 ranges, ports & endpoint parsing, IPv4/UDP checksums, Welford/UCB1 math, Digital Twin contract validation, sandbox security, auto-rollback, and unified logging.

---

## 📄 License

MIT License
