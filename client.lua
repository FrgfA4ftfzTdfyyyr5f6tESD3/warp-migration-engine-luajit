-- client.lua: Windows Layer 3 Kernel Network Engine via WinDivert 2.2.2 FFI
-- Supports Mode 1 (WireGuard Direct Desync + Reverse Rekey) & Mode 2 (QUIC/MASQUE Handshake Migration).
-- Standalone execution: luajit.exe client.lua (next to WinDivert.dll and WinDivert64.sys, Run as Admin).

local ffi = require("ffi")
local bit = require("bit")
local C = require("common")
local T = require("telemetry")

local band, bor = bit.band, bit.bor

ffi.cdef[[
    typedef struct {
        int64_t  Timestamp;
        uint32_t Layer:8;
        uint32_t Event:8;
        uint32_t Sniffed:1;
        uint32_t Outbound:1;
        uint32_t Loopback:1;
        uint32_t Impostor:1;
        uint32_t IPv6:1;
        uint32_t IPChecksum:1;
        uint32_t TCPChecksum:1;
        uint32_t UDPChecksum:1;
        uint32_t Reserved1:8;
        uint32_t Reserved2;
        uint8_t  Reserved3[48];
    } WINDIVERT_ADDRESS;

    typedef struct {
        uintptr_t Internal;
        uintptr_t InternalHigh;
        uint32_t  Offset;
        uint32_t  OffsetHigh;
        void     *hEvent;
    } WME_OVERLAPPED;

    typedef struct {
        uint16_t EventType;
        uint16_t _pad;
        union {
            struct {
                int32_t  bKeyDown;
                uint16_t wRepeatCount;
                uint16_t wVirtualKeyCode;
                uint16_t wVirtualScanCode;
                uint16_t UnicodeChar;
                uint32_t dwControlKeyState;
            } KeyEvent;
            uint8_t Raw[16];
        } Event;
    } WME_INPUT_RECORD;

    void*    WinDivertOpen(const char *filter, int layer, int16_t priority, uint64_t flags);
    int      WinDivertRecv(void *handle, void *pPacket, uint32_t packetLen, uint32_t *pRecvLen, WINDIVERT_ADDRESS *pAddr);
    int      WinDivertRecvEx(void *handle, void *pPacket, uint32_t packetLen, uint32_t *pRecvLen, uint64_t flags, WINDIVERT_ADDRESS *pAddr, uint32_t *pAddrLen, WME_OVERLAPPED *lpOverlapped);
    int      WinDivertSend(void *handle, const void *pPacket, uint32_t packetLen, uint32_t *pSendLen, const WINDIVERT_ADDRESS *pAddr);
    int      WinDivertShutdown(void *handle, int how);
    int      WinDivertClose(void *handle);
    int      WinDivertHelperCalcChecksums(void *pPacket, uint32_t packetLen, WINDIVERT_ADDRESS *pAddr, uint64_t flags);

    void*    GetStdHandle(uint32_t nStdHandle);
    void*    CreateEventA(void *lpEventAttributes, int bManualReset, int bInitialState, const char *lpName);
    int      ResetEvent(void *hEvent);
    uint32_t WaitForMultipleObjects(uint32_t nCount, void **lpHandles, int bWaitAll, uint32_t dwMilliseconds);
    int      GetOverlappedResult(void *hFile, WME_OVERLAPPED *lpOverlapped, uint32_t *lpNumberOfBytesTransferred, int bWait);
    int      PeekConsoleInputA(void *hConsoleInput, WME_INPUT_RECORD *lpBuffer, uint32_t nLength, uint32_t *lpNumberOfEventsRead);
    int      ReadConsoleInputA(void *hConsoleInput, WME_INPUT_RECORD *lpBuffer, uint32_t nLength, uint32_t *lpNumberOfEventsRead);
    int      GetConsoleMode(void *hConsoleHandle, uint32_t *lpMode);
    int      SetConsoleMode(void *hConsoleHandle, uint32_t dwMode);
    int      CancelIo(void *hFile);
    uint32_t GetLastError(void);
    void     Sleep(uint32_t dwMilliseconds);
]]

local wd = ffi.load("WinDivert")
local INVALID_HANDLE = ffi.cast("void*", ffi.cast("intptr_t", -1))
local STD_INPUT_HANDLE = 0xFFFFFFF6 -- (DWORD)-10
local ERROR_IO_PENDING = 997
local WAIT_OBJECT_0 = 0
local WAIT_TIMEOUT = 258
local INFINITE = 0xFFFFFFFF

local function ts_prefix()
    return os.date("[%H:%M:%S]")
end

-- Minimal config.json persistence
local CONFIG_FILE = "config.json"
local function load_config()
    local f = io.open(CONFIG_FILE, "r")
    if not f then return {} end
    local s = f:read("*a"); f:close()
    local ip = s:match('"relay_ip"%s*:%s*"([^"]+)"')
    local port = tonumber(s:match('"relay_port"%s*:%s*(%d+)'))
    return { relay_ip = ip, relay_port = port }
end

local function save_config(ip, port)
    local f = io.open(CONFIG_FILE, "w")
    if not f then return end
    f:write(string.format('{\n  "relay_ip": "%s",\n  "relay_port": %d\n}\n', ip, port))
    f:close()
end

-- Preallocated Zero-Allocation Hot-Path Buffers
local pkt_buf   = ffi.new("uint8_t[65535]")
local mod_buf   = ffi.new("uint8_t[65535]")
local lead_buf  = ffi.new("uint8_t[1500]")
local raw_buf   = ffi.new("uint8_t[1600]")
local camo_hdr  = ffi.new("uint8_t[8]")
local addr_in   = ffi.new("WINDIVERT_ADDRESS")
local addr_tmp  = ffi.new("WINDIVERT_ADDRESS")
local recv_len  = ffi.new("uint32_t[1]")
local send_len  = ffi.new("uint32_t[1]")
local addr_len  = ffi.new("uint32_t[1]")
local ov        = ffi.new("WME_OVERLAPPED")
local xfer_len  = ffi.new("uint32_t[1]")
local quic_kinds = ffi.new("uint8_t[16]")
local quic_bytes = ffi.new("uint8_t[16]")
local con_rec   = ffi.new("WME_INPUT_RECORD[8]")
local con_read  = ffi.new("uint32_t[1]")

local function build_masque_filter(target_ip_str, target_port, relay_ip_str, relay_port)
    local ip_dst = string.format(
        "((ip.DstAddr >= 162.159.192.0 and ip.DstAddr <= 162.159.203.255) or (ip.DstAddr >= 188.114.96.0 and ip.DstAddr <= 188.114.99.255) or ip.DstAddr == %s)",
        target_ip_str
    )
    local ip_src = string.format(
        "((ip.SrcAddr >= 162.159.192.0 and ip.SrcAddr <= 162.159.203.255) or (ip.SrcAddr >= 188.114.96.0 and ip.SrcAddr <= 188.114.99.255) or ip.SrcAddr == %s)",
        target_ip_str
    )
    local p_dst = string.format(
        "(udp.DstPort == 8095 or udp.DstPort == 8595 or udp.DstPort == 8642 or udp.DstPort == 8742 or " ..
        "udp.DstPort == 8854 or udp.DstPort == 8886 or udp.DstPort == 8943 or udp.DstPort == 443 or " ..
        "udp.DstPort == 2408 or udp.DstPort == 500 or udp.DstPort == 1701 or udp.DstPort == 4443 or " ..
        "udp.DstPort == 4500 or udp.DstPort == 8443 or (udp.DstPort >= 5200 and udp.DstPort <= 5205) or " ..
        "udp.DstPort == 7152 or udp.DstPort == 7156 or udp.DstPort == 7284 or udp.DstPort == 7559 or " ..
        "udp.DstPort == 7815 or udp.DstPort == 9034 or udp.DstPort == 9088 or udp.DstPort == 9389 or " ..
        "udp.DstPort == 9408 or udp.DstPort == 9555 or udp.DstPort == %d)", target_port
    )
    local p_src = p_dst:gsub("udp%.DstPort", "udp.SrcPort")
    return string.format(
        "(outbound and ip and udp and %s and %s) or (inbound and ip and udp and ((ip.SrcAddr == %s and udp.SrcPort == %d) or (%s and %s)))",
        ip_dst, p_dst, relay_ip_str, relay_port, ip_src, p_src
    )
end

-- Poll console input non-blockingly for [Enter] (re-arm), [S] (snapshot), or Ctrl+C
local function check_console_key(hStdin)
    if ffi.C.PeekConsoleInputA(hStdin, con_rec, 8, con_read) == 0 then return nil end
    local n = con_read[0]
    if n == 0 then return nil end
    ffi.C.ReadConsoleInputA(hStdin, con_rec, n, con_read)
    for i = 0, n - 1 do
        if con_rec[i].EventType == 1 and con_rec[i].Event.KeyEvent.bKeyDown ~= 0 then
            local vk = con_rec[i].Event.KeyEvent.wVirtualKeyCode
            local ch = con_rec[i].Event.KeyEvent.UnicodeChar
            if ch == 3 or (vk == 67 and band(con_rec[i].Event.KeyEvent.dwControlKeyState, 0x000C) ~= 0) then
                return "ctrl_c"
            elseif vk == 0x0D then
                return "enter"
            elseif vk == 0x53 then -- 'S'
                return "snapshot"
            end
        end
    end
    return nil
end

-- =========================================================================
-- MODE 2: QUIC / MASQUE HANDSHAKE MIGRATION ENGINE
-- =========================================================================
local function run_masque_engine(cfg)
    local target_ip_bytes = ffi.new("uint8_t[4]")
    local relay_ip_bytes  = ffi.new("uint8_t[4]")
    if not C.parse_ipv4_str(cfg.target_ip, target_ip_bytes) then
        C.parse_ipv4_str("162.159.198.2", target_ip_bytes)
    end
    if not C.parse_ipv4_str(cfg.relay_ip, relay_ip_bytes) then
        print("[ERROR] Invalid relay IP: " .. tostring(cfg.relay_ip))
        return
    end

    local filter = build_masque_filter(cfg.target_ip, cfg.target_port, cfg.relay_ip, cfg.relay_port)
    print("=========================================================================")
    print("  WinDivert QUIC / MASQUE Engine (LuaJIT 2.1 + FFI Zero-Alloc)")
    print("=========================================================================")
    print(string.format("  Relay Server   : %s:%d", cfg.relay_ip, cfg.relay_port))
    print(string.format("  Default Target : %s:%d", cfg.target_ip, cfg.target_port))
    print(string.format("  Initial Mask   : %s", cfg.proto_id == 0 and "AUTO (Tier-1: ESP, STUN, WebRTC, DTLS)" or C.get_protocol_by_id(cfg.proto_id).name))
    print("  Route Mode     : 1st Migration Instant Lock + Direct Wire-Speed")
    print("  Controls       : [ENTER] Re-Arm Relay | [S] Save AI Report | [Ctrl+C] Exit")
    print("=========================================================================\n")

    local handle = wd.WinDivertOpen(filter, 0, 0, 0)
    if handle == INVALID_HANDLE then
        print(string.format("[ERROR] WinDivertOpen failed (err=%d). Run as Administrator with WinDivert.dll/sys.", ffi.C.GetLastError()))
        return
    end
    print("[*] WinDivert handle active. Waiting for WARP QUIC packets...")

    T.load_mask_memory()
    T.load_evolved_policy()
    local hStdin = ffi.C.GetStdHandle(STD_INPUT_HANDLE)
    local old_mode = ffi.new("uint32_t[1]")
    ffi.C.GetConsoleMode(hStdin, old_mode)
    ffi.C.SetConsoleMode(hStdin, band(old_mode[0], bit.bnot(0x0018))) -- Disable mouse/window events
    local sessions = {} -- src_port -> { target_ip, target_port, proto_id, migrated, short_1rtt, srv_hs, warmup_done, start_ms }
    local relay_locked = false
    local active_proto_id = cfg.proto_id
    local last_auto_id = nil
    local out_seq = 1
    local out_count, in_count = 0, 0
    local stall_tx_since_rx = 0
    local stall_tx_start_ms = 0
    local lock_time_ms = 0
    local last_direct_rx_ms = 0
    local rx_at_lock = 0
    local active_port = 0
    local loop_tick = 0
    local consecutive_stalls = 0
    local hb_last_ms = T.now_ms()
    local hb_last_tx_b, hb_last_rx_b = 0, 0

    local function reset_unmigrated_timers(new_proto_id)
        local now_r = T.now_ms()
        for _, s in pairs(sessions) do
            if not s.migrated then
                s.start_ms = now_r
                if new_proto_id then s.proto_id = new_proto_id end
            end
        end
    end

    local function handle_stall_heal(port, proto_id, reason)
        local ep = T.live.active_endpoint
        if ep ~= "" then
            local port_cooled = T.ep_mark_stalled(ep, 60000, active_port)
            print(string.format("%s [AI ENDPOINT GUARD] Cooling down stalled %s for 60s", ts_prefix(), ep))
            if port_cooled then
                print(string.format("%s [AI PORT GUARD] Port %d stalled >=2x -> Cooling down for 120s", ts_prefix(), active_port))
            end
        end
        T.enter_phase(T.PHASE_AUTO_REARM)
        T.stat_stall(proto_id)
        if T.on_policy_stall() then
            print(string.format("%s [AUTO-ROLLBACK] Evolved policy reverted (<1ms)", ts_prefix()))
        end
        local attr, domain, pat = T.attribute_and_discover()
        local is_regime = T.check_regime_change()
        if is_regime then
            print(string.format("%s [AI REGIME CHANGE] Multi-path degradation in <30s (%s | %s)", ts_prefix(), domain, attr))
            local ok_syn = T.synthesize_policy_from_features()
            if ok_syn then
                print(string.format("%s [AI POLICY SYNTH] Generated & contract-verified evolved_policy.lua", ts_prefix()))
            end
        end
        T.record("stall_detected", port, proto_id, reason .. " | " .. domain .. " | " .. attr .. (pat and (" | " .. pat) or ""))
        T.flush_json("ai_report.json")
        relay_locked = false
        stall_tx_since_rx = 0
        consecutive_stalls = consecutive_stalls + 1
        local switched_id = nil
        if cfg.proto_id == 0 then
            active_proto_id = T.pick_smart_mask(C.MASQUE_TIER1_PROTO_IDS, proto_id)
            last_auto_id = active_proto_id
            switched_id = active_proto_id
            print(string.format("%s [AI SMART MASK] Rotating to Mask %d (%s)", ts_prefix(), active_proto_id, C.get_protocol_by_id(active_proto_id).key))
        elseif consecutive_stalls >= 2 then
            active_proto_id = T.pick_smart_mask(C.MASQUE_TIER1_PROTO_IDS, proto_id)
            consecutive_stalls = 0
            switched_id = active_proto_id
            print(string.format("%s [AI AUTO-ESCALATE] Mask %d stalled 2x -> Switching to Mask %d (%s)",
                ts_prefix(), proto_id, active_proto_id, C.get_protocol_by_id(active_proto_id).key))
        end
        reset_unmigrated_timers(switched_id)
    end

    local function send_relay_warmup(src_ip_ptr, src_port, proto_id, base_addr)
        local pinfo = C.get_protocol_by_id(proto_id)
        print(string.format("%s [WARMUP] Client :%d -> 2x 48B Lead-In to Relay [%s]", ts_prefix(), src_port, pinfo.key))
        T.record("warmup_sent", src_port, proto_id, pinfo.key)
        local zero_ip = ffi.new("uint8_t[4]")
        for i = 1, 2 do
            C.build_outbound_camo(proto_id, i, camo_hdr, 0)
            ffi.copy(lead_buf, camo_hdr, 8)
            ffi.copy(lead_buf + 8, zero_ip, 4)
            C.put_be16(lead_buf, 12, 0)
            lead_buf[14] = proto_id; lead_buf[15] = C.ADDR_TYPE_IPV4
            C.fill_bytes(lead_buf, 16, 32)
            local total = C.build_ipv4_udp_packet(raw_buf, src_ip_ptr, relay_ip_bytes, src_port, cfg.relay_port, lead_buf, 48)
            ffi.copy(addr_tmp, base_addr, ffi.sizeof("WINDIVERT_ADDRESS"))
            wd.WinDivertHelperCalcChecksums(raw_buf, total, addr_tmp, 0)
            wd.WinDivertSend(handle, raw_buf, total, send_len, addr_tmp)
            ffi.C.Sleep(10)
        end
    end

    local function send_direct_lead_in(src_ip_ptr, src_port, dst_ip_ptr, dst_port, proto_id, base_addr)
        local lead_proto = (proto_id == 2 or proto_id == 3) and 7 or proto_id
        local pinfo = C.get_protocol_by_id(lead_proto)
        print(string.format("%s [LEAD-IN] Client :%d -> 2x Non-QUIC (48B/96B) [%s] -> Direct %s:%d",
            ts_prefix(), src_port, pinfo.key, C.format_ipv4(dst_ip_ptr), dst_port))
        T.record("lead_in_sent", src_port, lead_proto, string.format("%s:%d", C.format_ipv4(dst_ip_ptr), dst_port))
        local ts_now = os.time()
        local sizes = { 48, 96 }
        for idx = 1, 2 do
            local sz = sizes[idx]
            C.build_lead_payload(lead_proto, sz, idx, ts_now, ts_now, lead_buf)
            local total = C.build_ipv4_udp_packet(raw_buf, src_ip_ptr, dst_ip_ptr, src_port, dst_port, lead_buf, sz)
            ffi.copy(addr_tmp, base_addr, ffi.sizeof("WINDIVERT_ADDRESS"))
            addr_tmp.Outbound = 1
            wd.WinDivertHelperCalcChecksums(raw_buf, total, addr_tmp, 0)
            wd.WinDivertSend(handle, raw_buf, total, send_len, addr_tmp)
            ffi.C.Sleep(10)
        end
    end

    local running = true
    while running do
        local key = check_console_key(hStdin)
        if key == "enter" then
            if relay_locked then
                relay_locked = false
                stall_tx_since_rx = 0
                reset_unmigrated_timers()
                print(string.format("\n%s [RELAY ARMED] Ready for next handshake migration...\n", ts_prefix()))
                T.record("relay_rearmed", 0, 0, "User pressed Enter")
            else
                print(string.format("\n%s [RELAY ALREADY ARMED] Ready for handshake migration.\n", ts_prefix()))
            end
        elseif key == "snapshot" then
            T.flush_json("ai_report.json")
            T.print_diagnostic_summary()
            print(string.format("%s [SNAPSHOT] Saved AI RCA bundle to ai_report.json", ts_prefix()))
        end

        local ok = wd.WinDivertRecv(handle, pkt_buf, 65535, recv_len, addr_in)
        if ok == 0 then
            local err = ffi.C.GetLastError()
            print(string.format("[WARN] WinDivertRecv failed (err=%d)", err))
            T.record("error", 0, 0, "WinDivertRecv err=" .. err)
            break
        end
        local nbytes = recv_len[0]
        if nbytes < 28 or band(pkt_buf[0], 0xF0) ~= 0x40 then
            wd.WinDivertSend(handle, pkt_buf, nbytes, send_len, addr_in)
            goto continue_loop
        end

        local ihl = band(pkt_buf[0], 0x0F) * 4
        if ihl < 20 or pkt_buf[9] ~= 17 or nbytes < ihl + 8 then
            wd.WinDivertSend(handle, pkt_buf, nbytes, send_len, addr_in)
            goto continue_loop
        end

        local udp_off = ihl
        local src_port = C.get_be16(pkt_buf, udp_off)
        local dst_port = C.get_be16(pkt_buf, udp_off + 2)
        local udp_len  = C.get_be16(pkt_buf, udp_off + 4)
        local pay_off  = udp_off + 8
        local pay_len  = udp_len - 8
        if udp_len < 8 or nbytes < udp_off + udp_len then
            wd.WinDivertSend(handle, pkt_buf, nbytes, send_len, addr_in)
            goto continue_loop
        end

        if addr_in.Outbound == 1 then
            local dst_ip_ptr = pkt_buf + 16
            local is_cf = C.is_cloudflare_ip_v4(dst_ip_ptr[0], dst_ip_ptr[1], dst_ip_ptr[2])
                or (dst_ip_ptr[0] == target_ip_bytes[0] and dst_ip_ptr[1] == target_ip_bytes[1]
                    and dst_ip_ptr[2] == target_ip_bytes[2] and dst_ip_ptr[3] == target_ip_bytes[3])
            local port_ok = C.is_cloudflare_port(dst_port) or dst_port == cfg.target_port

            if is_cf and port_ok then
                local sess = sessions[src_port]
                -- Fast-path: already migrated and Short 1-RTT header (MSB == 0)
                if sess and sess.migrated and pay_len > 0 and band(pkt_buf[pay_off], 0x80) == 0 then
                    T.live.direct_tx_pkts  = T.live.direct_tx_pkts + 1
                    T.live.direct_tx_bytes = T.live.direct_tx_bytes + pay_len
                    T.observe_tx_pkt(pay_len)
                    T.ring_push(3, src_port, pay_len, C.QUIC_SHORT_1RTT, 1)
                    if stall_tx_since_rx == 0 then
                        stall_tx_start_ms = T.now_ms()
                    end
                    stall_tx_since_rx = stall_tx_since_rx + 1
                    local dyn_stall = T.get_dynamic_stall_ms()
                    if relay_locked and stall_tx_since_rx >= 6 and (T.now_ms() - stall_tx_start_ms) >= dyn_stall then
                        print(string.format("%s [STALL DETECTED] No RX for %.1fs (%d TX pkts). Auto Re-Arming...", ts_prefix(), dyn_stall / 1000.0, stall_tx_since_rx))
                        handle_stall_heal(src_port, sess.proto_id, "Dynamic RX stall -> Auto Re-Arm")
                    end
                    -- Live 15s Throughput Heartbeat + 15s Evolved Policy Check
                    local hb_now = T.now_ms()
                    if hb_now - hb_last_ms >= 15000 and T.live.direct_rx_pkts > 0 then
                        local dt_s = (hb_now - hb_last_ms) / 1000.0
                        local tx_kbs = (T.live.direct_tx_bytes - hb_last_tx_b) / 1024.0 / dt_s
                        local rx_kbs = (T.live.direct_rx_bytes - hb_last_rx_b) / 1024.0 / dt_s
                        hb_last_ms = hb_now
                        hb_last_tx_b = T.live.direct_tx_bytes
                        hb_last_rx_b = T.live.direct_rx_bytes
                        print(string.format("%s [LIVE AI] %s | TX: %.1f KB/s | RX: %.1f KB/s | Pkts: %d/%d",
                            ts_prefix(), T.live.active_endpoint, tx_kbs, rx_kbs, T.live.direct_tx_pkts, T.live.direct_rx_pkts))
                        local pol_act = T.eval_evolved_policy()
                        if pol_act and pol_act.action == "DIVERSE_SWITCH" then
                            print(string.format("%s [EVOLVED POLICY] Pre-emptive diverse switch triggered!", ts_prefix()))
                            handle_stall_heal(src_port, sess.proto_id, "Evolved policy pre-emptive switch")
                        end
                    end
                    wd.WinDivertHelperCalcChecksums(pkt_buf, nbytes, addr_in, 0)
                    wd.WinDivertSend(handle, pkt_buf, nbytes, send_len, addr_in)
                    goto continue_loop
                end

                C.inspect_all_quic_packets(pkt_buf, pay_off, pay_len, quic_kinds, quic_bytes)
                local qkind = quic_kinds[1]

                if not sess then
                    local chosen = active_proto_id
                    if chosen == 0 then
                        chosen = T.pick_smart_mask(C.MASQUE_TIER1_PROTO_IDS, last_auto_id)
                        last_auto_id = chosen
                    end
                    local ep_str = string.format("%s:%d", C.format_ipv4(dst_ip_ptr), dst_port)
                    sess = {
                        target_ip = ffi.new("uint8_t[4]"),
                        target_port = dst_port,
                        ep_str = ep_str,
                        proto_id = chosen,
                        migrated = false,
                        short_1rtt = 0,
                        srv_hs = 0,
                        warmup_done = false,
                        start_ms = T.now_ms(),
                    }
                    ffi.copy(sess.target_ip, dst_ip_ptr, 4)
                    sessions[src_port] = sess
                    T.stat_attempt(chosen)
                else
                    ffi.copy(sess.target_ip, dst_ip_ptr, 4)
                    sess.target_port = dst_port
                end

                local needs_warmup = (qkind == C.QUIC_LONG_INITIAL and not sess.warmup_done)
                if needs_warmup then sess.warmup_done = true end

                -- State machine
                local action = "relay"
                if qkind == C.QUIC_LONG_INITIAL then
                    if sess.migrated then
                        -- Genuine reconnect on a reused port: reset session state
                        sess.migrated = false; sess.short_1rtt = 0; sess.srv_hs = 0
                        sess.start_ms = T.now_ms()
                    end
                    action = "relay"
                elseif sess.migrated then
                    action = "direct"
                elseif qkind == C.QUIC_SHORT_1RTT then
                    sess.short_1rtt = sess.short_1rtt + 1
                    if sess.short_1rtt >= 20 then
                        sess.migrated = true
                        action = "trigger_migration"
                    end
                end

                if action == "relay" and relay_locked then
                    local now_t = T.now_ms()
                    local lock_age = now_t - lock_time_ms
                    local no_rx_since_lock = (T.live.direct_rx_pkts == rx_at_lock) and (lock_age >= 2800)
                    local rx_timed_out     = (lock_age >= 2800) and (last_direct_rx_ms > 0) and ((now_t - last_direct_rx_ms) >= 3500)
                    if qkind == C.QUIC_LONG_INITIAL and (no_rx_since_lock or rx_timed_out) then
                        print(string.format("\n%s [AUTO RE-ARM] Previous tunnel inactive. Re-arming for Client :%d...", ts_prefix(), src_port))
                        handle_stall_heal(src_port, sess.proto_id, "WARP reconnect + dead direct path -> Auto Re-Arm")
                    else
                        T.ring_push(5, src_port, pay_len, qkind, 2)
                        T.record("verdict_drop", src_port, sess.proto_id, "Relay locked, dropped unmigrated pkt")
                        T.stat_drop(sess.proto_id)
                        goto continue_loop -- VERDICT_DROP
                    end
                elseif action == "relay" and T.ep_is_cooled_down(sess.ep_str, dst_port) then
                    -- Endpoint & Port Guard: drop stalled Cloudflare IP/port during handshake race
                    T.ring_push(5, src_port, pay_len, qkind, 3)
                    T.stat_drop(sess.proto_id)
                    goto continue_loop
                end

                if needs_warmup and not relay_locked then
                    T.enter_phase(T.PHASE_WARMUP)
                    send_relay_warmup(pkt_buf + 12, src_port, sess.proto_id, addr_in)
                    T.enter_phase(T.PHASE_HANDSHAKE)
                end

                if action == "trigger_migration" then
                    T.enter_phase(T.PHASE_MIGRATION)
                    send_direct_lead_in(pkt_buf + 12, src_port, dst_ip_ptr, dst_port, sess.proto_id, addr_in)
                    local dt = T.now_ms() - sess.start_ms
                    T.stat_migrated(sess.proto_id, dt, false)
                    T.record("migration_triggered", src_port, sess.proto_id, "Backup 20x 1-RTT cushion", dt)
                    print(string.format("%s [MIGRATED -> DIRECT] Client :%d -> %s:%d (Backup 20 Pkts, %.1fms)",
                        ts_prefix(), src_port, C.format_ipv4(dst_ip_ptr), dst_port, dt))
                    if not relay_locked then
                        relay_locked = true
                        lock_time_ms = T.now_ms()
                        rx_at_lock   = T.live.direct_rx_pkts
                        stall_tx_since_rx = 0
                        active_port = rest_port
                        T.live.active_endpoint = sess.ep_str
                        T.ep_mark_migrated(sess.ep_str)
                        print(string.format("%s [RELAY LOCKED] 1st session migrated. Press [ENTER] to re-arm...", ts_prefix()))
                        T.record("relay_locked", src_port, sess.proto_id, "Backup trigger")
                        T.flush_json("ai_report.json")
                        T.print_diagnostic_summary()
                    end
                    wd.WinDivertHelperCalcChecksums(pkt_buf, nbytes, addr_in, 0)
                    wd.WinDivertSend(handle, pkt_buf, nbytes, send_len, addr_in)
                elseif action == "direct" then
                    wd.WinDivertHelperCalcChecksums(pkt_buf, nbytes, addr_in, 0)
                    wd.WinDivertSend(handle, pkt_buf, nbytes, send_len, addr_in)
                else
                    -- Prepend 16B envelope into mod_buf (zero allocation)
                    local new_pay_len = pay_len + 16
                    local new_total   = nbytes + 16
                    ffi.copy(mod_buf, pkt_buf, pay_off)
                    ffi.copy(mod_buf + pay_off + 16, pkt_buf + pay_off, pay_len)
                    C.build_outbound_camo(sess.proto_id, out_seq, camo_hdr, 0)
                    out_seq = out_seq + 1
                    ffi.copy(mod_buf + pay_off, camo_hdr, 8)
                    ffi.copy(mod_buf + pay_off + 8, dst_ip_ptr, 4)
                    C.put_be16(mod_buf, pay_off + 12, dst_port)
                    mod_buf[pay_off + 14] = sess.proto_id
                    mod_buf[pay_off + 15] = C.ADDR_TYPE_IPV4

                    C.put_be16(mod_buf, 2, ihl + 8 + new_pay_len)
                    ffi.copy(mod_buf + 16, relay_ip_bytes, 4)
                    C.put_be16(mod_buf, udp_off + 2, cfg.relay_port)
                    C.put_be16(mod_buf, udp_off + 4, 8 + new_pay_len)

                    out_count = out_count + 1
                    T.ring_push(1, src_port, pay_len, qkind, 0)
                    local pspec = C.get_protocol_by_id(sess.proto_id)
                    if qkind == C.QUIC_LONG_INITIAL and (out_count <= 2 or out_count % 10 == 0) then
                        print(string.format("%s [HANDSHAKE] Client :%d -> Initial (%dB) [%s] -> Relay", ts_prefix(), src_port, pay_len, pspec.key))
                        T.record("handshake_pkt", src_port, sess.proto_id, string.format("OUT Initial %dB", pay_len))
                    elseif qkind == C.QUIC_LONG_HANDSHAKE then
                        print(string.format("%s [HANDSHAKE] Client :%d -> Handshake (%dB) [%s] -> Relay", ts_prefix(), src_port, pay_len, pspec.key))
                        T.record("handshake_pkt", src_port, sess.proto_id, string.format("OUT Handshake %dB", pay_len))
                    elseif qkind == C.QUIC_SHORT_1RTT and (sess.short_1rtt == 1 or sess.short_1rtt == 10 or sess.short_1rtt == 19) then
                        print(string.format("%s [1-RTT TRANSIT] Client :%d -> Packet %d/20 via Relay", ts_prefix(), src_port, sess.short_1rtt))
                        T.record("handshake_pkt", src_port, sess.proto_id, string.format("OUT 1-RTT %d/20", sess.short_1rtt))
                    end

                    wd.WinDivertHelperCalcChecksums(mod_buf, new_total, addr_in, 0)
                    wd.WinDivertSend(handle, mod_buf, new_total, send_len, addr_in)
                end
                goto continue_loop
            end
        else
            -- INBOUND
            local src_ip_ptr = pkt_buf + 12
            local from_relay = (src_ip_ptr[0] == relay_ip_bytes[0] and src_ip_ptr[1] == relay_ip_bytes[1]
                and src_ip_ptr[2] == relay_ip_bytes[2] and src_ip_ptr[3] == relay_ip_bytes[3]
                and src_port == cfg.relay_port)

            if from_relay and pay_len >= 8 then
                in_count = in_count + 1
                local sess = sessions[dst_port]
                -- Silently drop leftover relay packets for losing parallel ports after RELAY LOCKED
                if relay_locked and (not sess or not sess.migrated) then
                    T.stat_drop(sess and sess.proto_id or active_proto_id)
                    goto continue_loop
                end
                local rest_ip = sess and sess.target_ip or target_ip_bytes
                local rest_port = sess and sess.target_port or cfg.target_port
                local locked_proto = sess and sess.proto_id or cfg.proto_id

                local new_pay_len = pay_len - 8
                local new_total   = nbytes - 8
                ffi.copy(mod_buf, pkt_buf, pay_off)
                ffi.copy(mod_buf + pay_off, pkt_buf + pay_off + 8, new_pay_len)

                C.put_be16(mod_buf, 2, ihl + 8 + new_pay_len)
                ffi.copy(mod_buf + 12, rest_ip, 4)
                C.put_be16(mod_buf, udp_off, rest_port)
                C.put_be16(mod_buf, udp_off + 4, 8 + new_pay_len)

                local qcount = C.inspect_all_quic_packets(mod_buf, pay_off, new_pay_len, quic_kinds, quic_bytes)
                T.ring_push(2, dst_port, new_pay_len, quic_kinds[1], 0)
                local hs_count = 0
                for qi = 1, qcount do
                    local k = quic_kinds[qi]
                    local kname = C.QUIC_KIND_NAMES[k] or "QUIC"
                    if k == C.QUIC_LONG_INITIAL or k == C.QUIC_LONG_RETRY or k == C.QUIC_LONG_HANDSHAKE then
                        print(string.format("%s [HANDSHAKE] Relay -> Stripped [%s (0x%02x)] -> Client :%d", ts_prefix(), kname, quic_bytes[qi], dst_port))
                        T.record("quic_coalesced", dst_port, locked_proto, string.format("IN %s (0x%02x)", kname, quic_bytes[qi]))
                    end
                    if k == C.QUIC_LONG_HANDSHAKE then hs_count = hs_count + 1 end
                end

                if hs_count > 0 and not relay_locked and sess and not sess.migrated then
                    sess.srv_hs = sess.srv_hs + hs_count
                    if sess.srv_hs >= 2 then
                        sess.migrated = true
                        T.enter_phase(T.PHASE_MIGRATION)
                        send_direct_lead_in(pkt_buf + 16, dst_port, rest_ip, rest_port, locked_proto, addr_in)
                        local dt = T.now_ms() - sess.start_ms
                        T.stat_migrated(locked_proto, dt, true)
                        T.record("migration_triggered", dst_port, locked_proto, "Primary 2nd Server Handshake", dt)
                        print(string.format("%s [MIGRATED -> DIRECT] Client :%d -> %s:%d (2nd Server Handshake, %.1fms)",
                            ts_prefix(), dst_port, C.format_ipv4(rest_ip), rest_port, dt))
                        relay_locked = true
                        lock_time_ms = T.now_ms()
                        rx_at_lock   = T.live.direct_rx_pkts
                        stall_tx_since_rx = 0
                        active_port = rest_port
                        T.live.active_endpoint = sess.ep_str
                        T.ep_mark_migrated(sess.ep_str)
                        print(string.format("%s [RELAY LOCKED] 1st session migrated. Press [ENTER] to re-arm...", ts_prefix()))
                        T.record("relay_locked", dst_port, locked_proto, "Primary trigger")
                        T.flush_json("ai_report.json")
                        T.print_diagnostic_summary()
                    end
                end

                wd.WinDivertHelperCalcChecksums(mod_buf, new_total, addr_in, 0)
                if cfg.zero_csum then mod_buf[udp_off + 6] = 0; mod_buf[udp_off + 7] = 0 end
                wd.WinDivertSend(handle, mod_buf, new_total, send_len, addr_in)
                goto continue_loop
            elseif C.is_cloudflare_ip_v4(src_ip_ptr[0], src_ip_ptr[1], src_ip_ptr[2]) and (C.is_cloudflare_port(src_port) or src_port == cfg.target_port) then
                -- Direct 1-RTT inbound from Cloudflare
                T.enter_phase(T.PHASE_DIRECT_1RTT)
                T.live.direct_rx_pkts  = T.live.direct_rx_pkts + 1
                T.live.direct_rx_bytes = T.live.direct_rx_bytes + pay_len
                T.observe_rx_pkt(pay_len)
                last_direct_rx_ms = T.now_ms()
                stall_tx_since_rx = 0
                consecutive_stalls = 0
                if T.live.active_endpoint ~= "" then T.ep_mark_rx(T.live.active_endpoint, src_port) end
                T.ring_push(4, dst_port, pay_len, C.QUIC_SHORT_1RTT, 1)
                wd.WinDivertSend(handle, pkt_buf, nbytes, send_len, addr_in)
                goto continue_loop
            end
        end

        wd.WinDivertSend(handle, pkt_buf, nbytes, send_len, addr_in)
        ::continue_loop::
    end

    ffi.C.SetConsoleMode(hStdin, old_mode[0])
    wd.WinDivertShutdown(handle, 3)
    wd.WinDivertClose(handle)
    T.flush_json("ai_report.json")
    print("[*] AI RCA bundle saved to ai_report.json. MASQUE engine shut down cleanly.")
end

-- =========================================================================
-- MODE 1: DIRECT RELAYLESS WIREGUARD ENGINE (Stateful CPS + Role Swap)
-- =========================================================================
local function run_wireguard_engine(cfg)
    local filter = "(udp.PayloadLength == 148 and udp.Payload32[0] == 0x01000000) or (udp.PayloadLength == 92 and udp.Payload32[0] == 0x02000000)"
    print("=========================================================================")
    print("  WireGuard / UDP Direct Desync Engine (LuaJIT 2.1 + FFI)")
    print("=========================================================================")
    print(string.format("  Reverse Rekey : %s", cfg.reverse_rekey and "ENABLED (Noise_IK Role Swap)" or "DISABLED"))
    print(string.format("  Initial Mode  : %s", cfg.proto_id == 0 and "AUTO (Tier-1)" or C.get_protocol_by_id(cfg.proto_id).name))
    print("  Controls      : [Ctrl+C] Flush Telemetry & Exit")
    print("=========================================================================\n")

    local handle = wd.WinDivertOpen(filter, 0, 0, 0)
    if handle == INVALID_HANDLE then
        print(string.format("[ERROR] WinDivertOpen failed (err=%d). Run as Administrator.", ffi.C.GetLastError()))
        return
    end

    local hStdin = ffi.C.GetStdHandle(STD_INPUT_HANDLE)
    local old_mode = ffi.new("uint32_t[1]")
    ffi.C.GetConsoleMode(hStdin, old_mode)
    ffi.C.SetConsoleMode(hStdin, band(old_mode[0], bit.bnot(0x0019)))
    ov.hEvent = ffi.C.CreateEventA(nil, 1, 0, nil)
    local wait_handles = ffi.new("void*[2]", { ov.hEvent, hStdin })
    local wg_pending = false

    local flows = {} -- flow_key -> { state="tried"|"est", last_ms, est_ms, rev_status, rev_sup_ms, rev_sup_cnt }
    local trails = {} -- non-blocking scheduled trail packets { due_ms, addr, pkt_copy, len, label }
    local last_auto_id = nil
    local hs_counter = 0

    local running = true
    while running do
        -- Dispatch any due trail packets
        local now = T.now_ms()
        local i = 1
        while i <= #trails do
            if now >= trails[i].due_ms then
                local tr = table.remove(trails, i)
                wd.WinDivertHelperCalcChecksums(tr.pkt, tr.len, tr.addr, 0)
                wd.WinDivertSend(handle, tr.pkt, tr.len, send_len, tr.addr)
                print(string.format("    [%s] -> Size: %4d B [SENT]", tr.label, tr.len))
            else
                i = i + 1
            end
        end

        local timeout_ms = INFINITE
        if #trails > 0 then
            local min_due = trails[1].due_ms
            for j = 2, #trails do if trails[j].due_ms < min_due then min_due = trails[j].due_ms end end
            local diff = math.floor(min_due - T.now_ms())
            timeout_ms = diff > 0 and diff or 0
        end

        local nbytes = 0
        if not wg_pending then
            ffi.C.ResetEvent(ov.hEvent)
            ov.Internal = 0; ov.InternalHigh = 0; ov.Offset = 0; ov.OffsetHigh = 0
            addr_len[0] = ffi.sizeof("WINDIVERT_ADDRESS")
            local ok = wd.WinDivertRecvEx(handle, pkt_buf, 65535, recv_len, 0, addr_in, addr_len, ov)
            if ok ~= 0 then
                nbytes = recv_len[0]
            else
                if ffi.C.GetLastError() ~= ERROR_IO_PENDING then break end
                wg_pending = true
            end
        end
        if wg_pending then
            local w = ffi.C.WaitForMultipleObjects(2, wait_handles, 0, timeout_ms)
            if w == WAIT_OBJECT_0 then
                wg_pending = false
                if ffi.C.GetOverlappedResult(handle, ov, xfer_len, 1) ~= 0 then nbytes = xfer_len[0] end
            elseif w == WAIT_TIMEOUT then
                nbytes = 0
            elseif w == WAIT_OBJECT_0 + 1 then
                if check_console_key(hStdin) == "ctrl_c" then running = false end
                nbytes = 0
            end
        end

        if not running then break end
        if nbytes == 0 then goto wg_continue end

        local ver = bit.rshift(pkt_buf[0], 4)
        local ihl = (ver == 4) and (band(pkt_buf[0], 0x0F) * 4) or 40
        local proto = (ver == 4) and pkt_buf[9] or pkt_buf[6]
        if proto ~= 17 or nbytes < ihl + 8 then
            wd.WinDivertSend(handle, pkt_buf, nbytes, send_len, addr_in)
            goto wg_continue
        end

        local src_port = C.get_be16(pkt_buf, ihl)
        local dst_port = C.get_be16(pkt_buf, ihl + 2)
        local udp_len  = C.get_be16(pkt_buf, ihl + 4)
        local pay_off  = ihl + 8
        local pay_len  = udp_len - 8
        if udp_len < 8 or nbytes < ihl + udp_len then
            wd.WinDivertSend(handle, pkt_buf, nbytes, send_len, addr_in)
            goto wg_continue
        end
        local fkey = (addr_in.Outbound == 1)
            and string.format("%d->%d", src_port, dst_port)
            or  string.format("%d->%d", dst_port, src_port)

        local is_type1 = (pay_len == 148 and pkt_buf[pay_off] == 1 and pkt_buf[pay_off+1] == 0 and pkt_buf[pay_off+2] == 0 and pkt_buf[pay_off+3] == 0)
        local is_type2 = (pay_len == 92  and pkt_buf[pay_off] == 2 and pkt_buf[pay_off+1] == 0 and pkt_buf[pay_off+2] == 0 and pkt_buf[pay_off+3] == 0)

        if addr_in.Outbound == 0 then
            if is_type2 then
                local ent = flows[fkey] or {}
                ent.state = "est"; ent.est_ms = T.now_ms(); ent.last_ms = ent.est_ms
                ent.rev_status = ent.rev_status or "init"
                flows[fkey] = ent
                print(string.format("%s [WG ESTABLISHED] Flow %s Type 2 (92B) received!", ts_prefix(), fkey))
                T.record("wg_established", src_port, 0, fkey)
            elseif is_type1 and cfg.reverse_rekey then
                local ent = flows[fkey]
                if ent and ent.rev_status ~= "done" then
                    ent.rev_status = "srv_init"
                    print(string.format("%s [REVERSE REKEY] Server Type 1 (148B) received on %s!", ts_prefix(), fkey))
                    T.record("wg_reverse_rekey_swap", src_port, 0, fkey)
                end
            end
            wd.WinDivertSend(handle, pkt_buf, nbytes, send_len, addr_in)
            goto wg_continue
        end

        -- Outbound
        if is_type2 and cfg.reverse_rekey then
            local ent = flows[fkey]
            if ent and ent.rev_status == "srv_init" then
                ent.rev_status = "done"
                print(string.format("%s [REVERSE REKEY] Role Swap LOCKED on %s!", ts_prefix(), fkey))
            end
            wd.WinDivertSend(handle, pkt_buf, nbytes, send_len, addr_in)
            goto wg_continue
        end

        if is_type1 then
            local ent = flows[fkey]
            if ent and ent.state == "est" then
                if cfg.reverse_rekey and ent.rev_status ~= "done" and ent.rev_status ~= "fallback" then
                    local age_s = (T.now_ms() - ent.est_ms) / 1000.0
                    if ent.rev_status == "init" then
                        ent.rev_status = "suppressing"; ent.rev_sup_ms = T.now_ms(); ent.rev_sup_cnt = 1
                        print(string.format("%s [REVERSE REKEY] Client Rekey Suppressed (age=%.1fs)", ts_prefix(), age_s))
                        T.record("wg_reverse_rekey_suppress", src_port, 0, fkey)
                        goto wg_continue -- Drop
                    elseif ent.rev_status == "suppressing" then
                        local sup_s = (T.now_ms() - ent.rev_sup_ms) / 1000.0
                        if age_s > 220.0 or sup_s > 95.0 then
                            ent.rev_status = "fallback"
                            print(string.format("%s [REVERSE REKEY] Safety Fallback -> Passing Rekey", ts_prefix()))
                            T.record("wg_reverse_rekey_fallback", src_port, 0, fkey)
                        else
                            ent.rev_sup_cnt = ent.rev_sup_cnt + 1
                            goto wg_continue -- Drop
                        end
                    end
                end
                wd.WinDivertSend(handle, pkt_buf, nbytes, send_len, addr_in)
                goto wg_continue
            elseif ent and ent.state == "tried" then
                print(string.format("%s [DUPLICATE DROPPED] Flow %s -> forcing port rotation", ts_prefix(), fkey))
                T.record("wg_duplicate_drop", src_port, 0, fkey)
                goto wg_continue -- VERDICT_DROP
            end

            -- Fresh flow
            hs_counter = hs_counter + 1
            flows[fkey] = { state = "tried", last_ms = T.now_ms(), rev_status = "init" }
            local pid = cfg.proto_id
            if pid == 0 then pid = C.get_next_auto_proto(last_auto_id); last_auto_id = pid end
            local spec = C.get_protocol_by_id(pid)
            local jc = spec.c_min + (C.next_u32() % (spec.c_max - spec.c_min + 1))
            local iv_ms = math.floor((1800 + (C.next_u32() % 600)) / jc)
            print(string.format("%s [WG HANDSHAKE #%d] Flow %s | Mask: %s | Lead-In x%d", ts_prefix(), hs_counter, fkey, spec.key, jc))
            T.record("wg_handshake", src_port, pid, fkey)

            local ts_now = os.time()
            for i = 1, jc do
                local sz = spec.s_min + (C.next_u32() % (spec.s_max - spec.s_min + 1))
                C.build_lead_payload(pid, sz, i, ts_now, ts_now, lead_buf)
                local total = (ver == 4)
                    and C.build_ipv4_udp_packet(raw_buf, pkt_buf+12, pkt_buf+16, src_port, dst_port, lead_buf, sz)
                    or  C.build_ipv6_udp_packet(raw_buf, pkt_buf+8,  pkt_buf+24, src_port, dst_port, lead_buf, sz)
                wd.WinDivertHelperCalcChecksums(raw_buf, total, addr_in, 0)
                wd.WinDivertSend(handle, raw_buf, total, send_len, addr_in)
                ffi.C.Sleep(iv_ms)
            end

            -- Release 148B Type 1
            wd.WinDivertSend(handle, pkt_buf, nbytes, send_len, addr_in)
            print("    [HANDSHAKE] -> Size: 148 B [PASSED]")

            -- Schedule Dual Trail (+60ms, +180ms)
            local base_t = T.now_ms()
            for t_idx, delay in ipairs({ 60, 180 }) do
                local sz = spec.s_min + (C.next_u32() % (spec.s_max - spec.s_min + 1))
                C.build_lead_payload(pid, sz, jc + t_idx, os.time(), os.time(), lead_buf)
                local tbuf = ffi.new("uint8_t[1600]")
                local tlen = (ver == 4)
                    and C.build_ipv4_udp_packet(tbuf, pkt_buf+12, pkt_buf+16, src_port, dst_port, lead_buf, sz)
                    or  C.build_ipv6_udp_packet(tbuf, pkt_buf+8,  pkt_buf+24, src_port, dst_port, lead_buf, sz)
                local taddr = ffi.new("WINDIVERT_ADDRESS")
                ffi.copy(taddr, addr_in, ffi.sizeof("WINDIVERT_ADDRESS"))
                trails[#trails + 1] = { due_ms = base_t + delay, pkt = tbuf, len = tlen, addr = taddr, label = "TRAIL " .. t_idx .. "/2" }
            end
            goto wg_continue
        end

        wd.WinDivertSend(handle, pkt_buf, nbytes, send_len, addr_in)
        ::wg_continue::
    end

    ffi.C.SetConsoleMode(hStdin, old_mode[0])
    ffi.C.SetConsoleMode(hStdin, old_mode[0])
    wd.WinDivertShutdown(handle, 3)
    wd.WinDivertClose(handle)
    T.flush_json("telemetry.json")
    print("[*] Telemetry saved to telemetry.json. WireGuard engine shut down cleanly.")
end

-- =========================================================================
-- CLI ENTRYPOINT
-- =========================================================================
local function prompt(msg)
    io.write(msg); io.flush()
    return (io.read("*l") or ""):match("^%s*(.-)%s*$")
end

local function main()
    print("=========================================================================")
    print("  Warp Migration Engine - LuaJIT 2.1 + FFI Edition")
    print("=========================================================================")
    print("  [1] WireGuard / UDP Direct Desync Engine (Zero-NAT + Reverse Rekey)")
    print("  [2] QUIC / MASQUE Handshake Migration Engine (Relay + 1-RTT Direct)")
    local m = prompt("Select Engine Mode [1 or 2, Default 2]: ")
    local mode = (m == "1") and 1 or 2

    print("\n  Camouflage Protocols [0=AUTO, 4=WebRTC, 5=DTLS, 7=IPsec ESP, 10=STUN, 1..17]:")
    local def_p = (mode == 1) and 0 or 7
    local p_str = prompt(string.format("Select Protocol [Enter for %d]: ", def_p))
    local proto_id = tonumber(p_str) or def_p

    if mode == 1 then
        local rev = prompt("Enable Beta Reverse-Handshake (Role Swap)? [y/N]: "):lower()
        run_wireguard_engine({ proto_id = proto_id, reverse_rekey = (rev == "y" or rev == "yes") })
    else
        local saved = load_config()
        local relay_ip, relay_port = saved.relay_ip, saved.relay_port or 2632
        local ans
        if relay_ip then
            ans = prompt(string.format("Use saved relay [%s:%d]? (Enter to keep, or IP:PORT): ", relay_ip, relay_port))
        else
            ans = prompt("Enter Relay Server [IP:PORT, e.g. 198.51.100.1:2632]: ")
        end
        if ans ~= "" then
            local ip, p = ans:match("^([^:]+):(%d+)$")
            if ip then relay_ip = ip; relay_port = tonumber(p) else relay_ip = ans end
        end
        if not relay_ip or relay_ip == "" then print("[!] Relay IP required."); return end
        save_config(relay_ip, relay_port)
        run_masque_engine({
            proto_id    = proto_id,
            target_ip   = "162.159.198.2",
            target_port = 8095,
            relay_ip    = relay_ip,
            relay_port  = relay_port,
            zero_csum   = false,
        })
    end
end

main()
