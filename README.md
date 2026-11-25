# ⚡ Warp Migration Engine — LuaJIT 2.1 + FFI Edition

**High-Performance Layer 3 Kernel Network Engine for Cloudflare WARP**  
Zero-compilation, zero-allocation hot-path port of `warp-migration-engine` written in **LuaJIT 2.1 + FFI**, enhanced with a **Dual-Perspective Self-Learning AI Brain**.

---

## 🌟 Why LuaJIT 2.1 + FFI? (Comparison with the Rust Edition)

| Feature | Rust Edition (`warp-migration-engine`) | LuaJIT 2.1 + FFI Edition (This Repo) |
| :--- | :--- | :--- |
| **Codebase Size** | 23 `.rs` files (~3,849 lines) | **4 `.lua` core modules** (~1,900 lines) |
| **Compile Time** | Cargo release build required | **0 seconds** (Instant execution + JIT machine code) |
| **External Dependencies** | Tokio, WinDivert-rs, Clap, Serde, Socket2 | **Zero** (Standalone `luajit.exe` / `luajit`) |
| **Hot-Path Memory** | Heap-managed `Vec<u8>` buffers | **Zero-Allocation** preallocated `ffi.new` buffers |
| **Runtime Intelligence** | Static logs | **Dual-Perspective AI Brain** (Welford + Discounted UCB1 + `evolved_policy.lua` + 200-pkt Ring Buffer) |
| **Protocol Compatibility** | 17 Camouflage Masks, Mode 1 & Mode 2 | **100% Identical Wire Format** (Interoperable with Rust relay/client) |

---

## 🚀 Key Features

1. **17 Pluggable Layer-4 Camouflage Protocols (`common.lua`)**
   - Preserves all 17 protocol masks (`AUTO`, `WebRTC`, `DTLS 1.2`, `IPsec ESP`, `STUN`, `DNS`, `Steam SDR`, `Discord`, `Zoom`, `RakNet`, etc.) using raw `uint8_t` FFI buffers and `bit.*` operations.
2. **RFC 9000 Coalesced QUIC Dissection & Dual-Trigger**
   - Full Varint & Long Header length parser to dissect coalesced `Initial`, `Retry`, `Handshake`, and `1-RTT` frames.
   - Primary Trigger on 2nd `Server Handshake` + Backup 20-packet `1-RTT` safety cushion.
3. **Dual Engine Modes (`client.lua`)**
   - **Mode 1 (WireGuard Direct):** `Stateful CPS Pinhole` (I1/I2 Lead-In + Dual Trail at +60ms/+180ms) + `Inverted Rekeying / Role Swap` + `VERDICT_DROP` on duplicate retries.
   - **Mode 2 (QUIC / MASQUE):** Asymmetric Handshake Migration via lightweight UDP relay -> `2x Lead-In` -> Permanent Direct `1-RTT` Wire-Speed (`RELAY LOCKED` + `[Enter]` Re-Arm + Smart Auto-Heal).
4. **Ultra-Lightweight Linux Epoll Relay (`server.lua`)**
   - Direct `ffi.C` bindings to Linux `socket`, `bind`, `recvfrom`, `sendto`, and `epoll` (`__attribute__((packed))`), dual-stack IPv4/IPv6, 60-second inactivity auto-purge, and zero user-IP disk logging.
5. **Dual-Perspective Self-Learning AI Brain (`telemetry.lua`)**
   - **Internal Code Brain:** `jit.attach` trace profiler, `collectgarbage("count")` memory monitor, 5×5 phase transition matrix, and `autonomous_upgrade_blueprint`.
   - **External Network Brain:** Welford online statistical baseline (zero fixed thresholds), `Discounted UCB1` ($\gamma = 0.90$) with circadian time buckets & 15% hysteresis, `Endpoint Guard` (60s cooldown), `Port Guard` (120s cooldown), and a 200-packet circular Ring-Buffer Flight Recorder.
   - **Contract-Verified Policy Synthesizer:** Generates `evolved_policy.lua` inside an isolated `setfenv` sandbox, validates against the client-server Digital Twin contract (`E2E_SYSTEM_MODEL`), and auto-rolls back in `<1ms` on regression.

---

## 📦 Quick Start (Windows Client)

1. Ensure `luajit.exe`, `lua51.dll`, `WinDivert.dll`, and `WinDivert64.sys` are in the project directory.
2. Copy `config.example.json` to `config.json` (or enter your relay `IP:PORT` on first run).
3. Double-click **`run_test.bat`** (auto-elevates to Administrator).
4. Controls during runtime:
   - `[Enter]` — Re-Arm relay manually
   - `[S]` — Save live diagnostic snapshot to `ai_report.json`
   - `[Ctrl+C]` — Flush telemetry & exit cleanly

---

## 🖥️ Server Deployment (Linux VPS)

Upload `server.lua`, `common.lua`, and `deploy_server.sh` to your Linux VPS (Ubuntu/Debian/Alpine):

```bash
chmod +x deploy_server.sh
./deploy_server.sh 2632
```

Or run directly with LuaJIT:

```bash
luajit server.lua 2632
```

---

## 🧪 Running Unit Tests

```bat
luajit.exe test_suite.lua
```

Verifies `WINDIVERT_ADDRESS` x64 ABI (64 bytes), RFC 9000 Varint & coalesced QUIC parsing, all 17 camouflage protocols, Cloudflare IPv4 ranges & ports, IPv4/UDP checksums, Welford/UCB1 math, Digital Twin contract validation, sandbox security, and auto-rollback.

---

## 📄 License

MIT License
