-- client.lua: Windows Layer 3 Kernel Network Engine via WinDivert 2.2.2 FFI
-- Dedicated QUIC / MASQUE Handshake Migration Engine for Cloudflare WARP (Official Client + Direct 1-RTT).
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
    int      WinDivertSend(void *handle, const void *pPacket, uint32_t packetLen, uint32_t *pSendLen, const WINDIVERT_ADDRESS *pAddr);
    int      WinDivertShutdown(void *handle, int how);
    int      WinDivertClose(void *handle);
    int      WinDivertHelperCalcChecksums(void *pPacket, uint32_t packetLen, WINDIVERT_ADDRESS *pAddr, uint64_t flags);

    void*    GetStdHandle(uint32_t nStdHandle);
    int      PeekConsoleInputA(void *hConsoleInput, WME_INPUT_RECORD *lpBuffer, uint32_t nLength, uint32_t *lpNumberOfEventsRead);
    int      ReadConsoleInputA(void *hConsoleInput, WME_INPUT_RECORD *lpBuffer, uint32_t nLength, uint32_t *lpNumberOfEventsRead);
    int      GetConsoleMode(void *hConsoleHandle, uint32_t *lpMode);
    int      SetConsoleMode(void *hConsoleHandle, uint32_t dwMode);
    int      FlushConsoleInputBuffer(void *hConsoleInput);
    uint32_t GetLastError(void);
    void     Sleep(uint32_t dwMilliseconds);
]]

local wd = ffi.load("WinDivert")
local INVALID_HANDLE = ffi.cast("void*", ffi.cast("intptr_t", -1))
local STD_INPUT_HANDLE = 0xFFFFFFF6 -- (DWORD)-10

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
    local t_ip = s:match('"target_ip"%s*:%s*"([^"]+)"')
    local t_port = tonumber(s:match('"target_port"%s*:%s*(%d+)'))
    local proto = tonumber(s:match('"proto_id"%s*:%s*(%d+)'))
    local w_mode = s:match('"warp_mode"%s*:%s*"([^"]+)"')
    local w_cfg = s:match('"warp_configured"%s*:%s*(true|false)')
    local w_ac  = s:match('"warp_auto_connect"%s*:%s*(true|false)')
    return {
        relay_ip = ip,
        relay_port = port,
        target_ip = t_ip,
        target_port = t_port,
        proto_id = proto,
        warp_mode = w_mode,
        warp_configured = (w_cfg == "true"),
        warp_auto_connect = (w_ac == "true"),
    }
end

local function save_config(c)
    local f = io.open(CONFIG_FILE, "w")
    if not f then return end
    f:write(string.format(
        '{\n  "relay_ip": "%s",\n  "relay_port": %d,\n  "target_ip": "%s",\n  "target_port": %d,\n  "proto_id": %d,\n  "warp_mode": "%s",\n  "warp_configured": %s,\n  "warp_auto_connect": %s\n}\n',
        c.relay_ip, c.relay_port, c.target_ip or "162.159.198.2", c.target_port or 8095,
        c.proto_id or 7, c.warp_mode or "manual",
        tostring(c.warp_configured == true), tostring(c.warp_auto_connect == true)
    ))
    f:close()
end

local function log_msg(fmt, ...)
    local msg = select("#", ...) > 0 and string.format(fmt, ...) or fmt
    T.log_line(msg)
end

-- Preallocated Zero-Allocation Hot-Path Buffers
local pkt_buf   = ffi.new("uint8_t[65535]")
local mod_buf   = ffi.new("uint8_t[65535]")
local lead_buf  = ffi.new("uint8_t[1500]")
local raw_buf   = ffi.new("uint8_t[1600]")
local camo_hdr  = ffi.new("uint8_t[8]")
local zero_ip   = ffi.new("uint8_t[4]")
local addr_in   = ffi.new("WINDIVERT_ADDRESS")
local addr_tmp  = ffi.new("WINDIVERT_ADDRESS")
local recv_len  = ffi.new("uint32_t[1]")
local send_len  = ffi.new("uint32_t[1]")
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
        "udp.DstPort == 500 or udp.DstPort == 1701 or udp.DstPort == 4443 or " ..
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
    T.init_session_log("wme_session.log")
    T.session_meta.engine_mode     = "masque"
    T.session_meta.relay_endpoint  = string.format("%s:%d", cfg.relay_ip, cfg.relay_port)
    T.session_meta.target_endpoint = string.format("%s:%d", cfg.target_ip, cfg.target_port)
    T.session_meta.warp_auto_setup = cfg.warp_auto_setup == true
    T.session_meta.warp_mode       = cfg.warp_mode or "manual"
    T.session_meta.migration_rule  = "BiDi-1RTT (30rx+45tx >=6.5s) / 8.5s Cap"

    log_msg("=========================================================================")
    log_msg("  WinDivert QUIC / MASQUE Engine (LuaJIT 2.1 + FFI Zero-Alloc)")
    log_msg("=========================================================================")
    log_msg("  Relay Server   : %s:%d", cfg.relay_ip, cfg.relay_port)
    log_msg("  WARP Target    : %s:%d", cfg.target_ip, cfg.target_port)
    log_msg("  WARP Mode      : %s%s", cfg.warp_mode or "manual", cfg.warp_auto_setup and " (Auto-Configured)" or "")
    log_msg("  Initial Mask   : %s", C.format_protocol_label(cfg.proto_id))
    log_msg("  Route Mode     : BiDi Event-Driven 1-RTT Migration + Aux Session Guard")
    log_msg("  Unified Logs   : Console + wme_session.log + ai_report.json")
    log_msg("  Controls       : [ENTER] Re-Arm Relay | [S] Save AI Report | [Ctrl+C] Exit")
    log_msg("=========================================================================\n")

    local handle = wd.WinDivertOpen(filter, 0, 0, 0)
    if handle == INVALID_HANDLE then
        log_msg("[ERROR] WinDivertOpen failed (err=%d). Run as Administrator with WinDivert.dll/sys.", ffi.C.GetLastError())
        T.close_session_log()
        return
    end
    log_msg("[*] WinDivert handle active. Waiting for WARP QUIC packets...")
    if cfg.warp_auto_connect and cfg.warp_cli_bin then
        log_msg("[*] Auto-connecting Official Cloudflare WARP client...")
        os.execute(string.format('start "" /B "%s" connect >nul 2>&1', cfg.warp_cli_bin))
    end

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
    local hs_no_reply_cnt = 0
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

    local primary_ep = string.format("%s:%d", cfg.target_ip, cfg.target_port)

    local function handle_stall_heal(port, proto_id, reason)
        local ep = T.live.active_endpoint
        if ep ~= "" and ep ~= primary_ep then
            local port_cooled = T.ep_mark_stalled(ep, 60000, active_port)
            log_msg("%s [AI ENDPOINT GUARD] Cooling down stalled %s for 60s", ts_prefix(), ep)
            if port_cooled then
                log_msg("%s [AI PORT GUARD] Port %d stalled >=2x -> Cooling down for 120s", ts_prefix(), active_port)
            end
        end
        T.enter_phase(T.PHASE_AUTO_REARM)
        T.stat_stall(proto_id)
        if T.on_policy_stall() then
            log_msg("%s [AUTO-ROLLBACK] Evolved policy reverted (<1ms)", ts_prefix())
        end
        local attr, domain, pat = T.attribute_and_discover()
        local is_regime = T.check_regime_change()
        if is_regime then
            log_msg("%s [AI REGIME CHANGE] Multi-path degradation in <30s (%s | %s)", ts_prefix(), domain, attr)
            local ok_syn = T.synthesize_policy_from_features()
            if ok_syn then
                log_msg("%s [AI POLICY SYNTH] Generated & contract-verified evolved_policy.lua", ts_prefix())
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
            log_msg("%s [AI SMART MASK] Rotating to Mask %s", ts_prefix(), C.format_protocol_label(active_proto_id))
        elseif consecutive_stalls >= 2 then
            active_proto_id = T.pick_smart_mask(C.MASQUE_TIER1_PROTO_IDS, proto_id)
            consecutive_stalls = 0
            switched_id = active_proto_id
            log_msg("%s [AI AUTO-ESCALATE] Mask %d stalled 2x -> Switching to Mask %s",
                ts_prefix(), proto_id, C.format_protocol_label(active_proto_id))
        end
        reset_unmigrated_timers(switched_id)
    end

    local function send_relay_warmup(src_ip_ptr, src_port, proto_id, base_addr)
        local pinfo = C.get_protocol_by_id(proto_id)
        log_msg("%s [WARMUP] Client :%d -> 2x 48B Lead-In to Relay [%d:%s]", ts_prefix(), src_port, pinfo.id, pinfo.key)
        T.record("warmup_sent", src_port, proto_id, pinfo.key)
        for i = 1, 2 do
            C.build_outbound_camo(proto_id, i, camo_hdr, 0)
            C.pack_relay_env_v4(lead_buf, 0, camo_hdr, zero_ip, 0, proto_id)
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
        log_msg("%s [LEAD-IN] Client :%d -> 2x Non-QUIC (48B/96B) [%d:%s] -> Direct %s:%d",
            ts_prefix(), src_port, pinfo.id, pinfo.key, C.format_ipv4(dst_ip_ptr), dst_port)
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

    ffi.C.FlushConsoleInputBuffer(hStdin)
    local running = true
    while running do
        loop_tick = loop_tick + 1
        if band(loop_tick, 15) == 1 then
            local key = check_console_key(hStdin)
            if key == "enter" then
                if relay_locked then
                    relay_locked = false
                    stall_tx_since_rx = 0
                    reset_unmigrated_timers()
                    log_msg("\n%s [RELAY ARMED] Ready for next handshake migration...\n", ts_prefix())
                    T.record("relay_rearmed", 0, 0, "User pressed Enter")
                else
                    log_msg("\n%s [RELAY ALREADY ARMED] Ready for handshake migration.\n", ts_prefix())
                end
            elseif key == "snapshot" then
                T.flush_json("ai_report.json")
                T.print_diagnostic_summary()
                log_msg("%s [SNAPSHOT] Saved unified AI RCA bundle to ai_report.json + wme_session.log", ts_prefix())
            end
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
                    local now_s = T.now_ms()
                    local dyn_stall = T.get_dynamic_stall_ms()
                    local eff_stall = (now_s - lock_time_ms < 14000) and math.max(dyn_stall, 11000) or dyn_stall
                    if relay_locked and stall_tx_since_rx >= 3 and (now_s - stall_tx_start_ms) >= eff_stall then
                        log_msg("%s [STALL DETECTED] No RX for %.1fs (%d TX pkts). Auto Re-Arming...", ts_prefix(), eff_stall / 1000.0, stall_tx_since_rx)
                        handle_stall_heal(src_port, sess.proto_id, "Dynamic RX stall -> Auto Re-Arm")
                    end
                    -- Live 15s Throughput Heartbeat + 15s Evolved Policy Check + Idle Session GC
                    local hb_now = T.now_ms()
                    if hb_now - hb_last_ms >= 15000 and T.live.direct_rx_pkts > 0 then
                        local dt_s = (hb_now - hb_last_ms) / 1000.0
                        local tx_kbs = (T.live.direct_tx_bytes - hb_last_tx_b) / 1024.0 / dt_s
                        local rx_kbs = (T.live.direct_rx_bytes - hb_last_rx_b) / 1024.0 / dt_s
                        hb_last_ms = hb_now
                        hb_last_tx_b = T.live.direct_tx_bytes
                        hb_last_rx_b = T.live.direct_rx_bytes
                        log_msg("%s [LIVE AI] %s | TX: %.1f KB/s | RX: %.1f KB/s | Pkts: %d/%d",
                            ts_prefix(), T.live.active_endpoint, tx_kbs, rx_kbs, T.live.direct_tx_pkts, T.live.direct_rx_pkts)
                        for kp, sp in pairs(sessions) do
                            if not sp.migrated and (hb_now - sp.start_ms) > 180000 then sessions[kp] = nil end
                        end
                        local pol_act = T.eval_evolved_policy()
                        if pol_act and pol_act.action == "DIVERSE_SWITCH" then
                            log_msg("%s [EVOLVED POLICY] Pre-emptive diverse switch triggered!", ts_prefix())
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
                        aux_allowed = false,
                        hs_confirmed = false,
                        hs_confirmed_ms = 0,
                        post_hs_1rtt = 0,
                        srv_1rtt = 0,
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

                -- State machine (BiDi Event-Driven 1-RTT Migration + Safety Cap)
                local action = "relay"
                local is_primary_mig = false
                local mig_reason = nil
                if qkind == C.QUIC_LONG_INITIAL then
                    if sess.migrated then
                        -- Genuine reconnect on a reused port: reset session state cleanly
                        sess.migrated = false; sess.hs_confirmed = false; sess.hs_confirmed_ms = 0
                        sess.post_hs_1rtt = 0; sess.srv_1rtt = 0
                        sess.short_1rtt = 0; sess.srv_hs = 0
                        sess.warmup_done = true
                        needs_warmup = true
                        sess.start_ms = T.now_ms()
                    end
                    action = "relay"
                elseif sess.migrated then
                    action = "direct"
                elseif qkind == C.QUIC_SHORT_1RTT then
                    if sess.hs_confirmed then
                        sess.post_hs_1rtt = sess.post_hs_1rtt + 1
                        local elapsed_hs = T.now_ms() - sess.hs_confirmed_ms
                        local bidi_ready = (sess.srv_1rtt >= 30 and sess.post_hs_1rtt >= 45 and elapsed_hs >= 6500)
                        local cap_ready  = (sess.post_hs_1rtt >= 60 and elapsed_hs >= 8500) or (elapsed_hs >= 6500 and sess.post_hs_1rtt >= 180)
                        if bidi_ready or cap_ready then
                            sess.migrated = true
                            is_primary_mig = true
                            action = "trigger_migration"
                            mig_reason = bidi_ready and string.format("BiDi 1-RTT (%dtx/%drx)", sess.post_hs_1rtt, sess.srv_1rtt) or "8.5s/180p Cap"
                        end
                    else
                        sess.short_1rtt = sess.short_1rtt + 1
                        if sess.short_1rtt >= 20 then
                            sess.migrated = true
                            action = "trigger_migration"
                            mig_reason = "Backup 20 Pkts"
                        end
                    end
                end

                if action == "relay" and relay_locked then
                    local now_t = T.now_ms()
                    local lock_age = now_t - lock_time_ms
                    local no_rx_since_lock = (T.live.direct_rx_pkts == rx_at_lock) and (lock_age >= 2800)
                    local rx_timed_out     = (lock_age >= 2800) and (last_direct_rx_ms > 0) and ((now_t - last_direct_rx_ms) >= 3500)
                    if qkind == C.QUIC_LONG_INITIAL and (no_rx_since_lock or rx_timed_out) then
                        log_msg("\n%s [AUTO RE-ARM] Previous tunnel inactive. Re-arming for Client :%d...", ts_prefix(), src_port)
                        handle_stall_heal(src_port, sess.proto_id, "WARP reconnect + dead direct path -> Auto Re-Arm")
                    elseif qkind == C.QUIC_LONG_INITIAL and lock_age >= 2000 then
                        if not sess.aux_allowed then
                            sess.aux_allowed = true
                            if not sess.warmup_done then sess.warmup_done = true; needs_warmup = true end
                            log_msg("%s [AUX SESSION] Client :%d -> New Initial while tunnel active; routing via Relay", ts_prefix(), src_port)
                        end
                    elseif sess.aux_allowed then
                        -- Auxiliary session in handshake/grace window: allow via Relay
                    else
                        T.ring_push(5, src_port, pay_len, qkind, 2)
                        T.record("verdict_drop", src_port, sess.proto_id, "Relay locked, dropped unmigrated pkt")
                        T.stat_drop(sess.proto_id)
                        goto continue_loop -- VERDICT_DROP
                    end
                elseif action == "relay" and sess.ep_str ~= primary_ep and T.ep_is_cooled_down(sess.ep_str, dst_port) then
                    -- Endpoint & Port Guard: drop stalled alternate Cloudflare IP/port (never blackhole the primary configured endpoint)
                    T.ring_push(5, src_port, pay_len, qkind, 3)
                    T.stat_drop(sess.proto_id)
                    goto continue_loop
                end

                if needs_warmup and (not relay_locked or sess.aux_allowed) then
                    hs_no_reply_cnt = hs_no_reply_cnt + 1
                    if hs_no_reply_cnt >= 4 then
                        hs_no_reply_cnt = 0
                        active_proto_id = T.pick_smart_mask(C.MASQUE_TIER1_PROTO_IDS, sess.proto_id)
                        sess.proto_id = active_proto_id
                        log_msg("%s [AI HANDSHAKE ESCALATE] 4x no-reply -> Switching to Mask %s",
                            ts_prefix(), C.format_protocol_label(active_proto_id))
                    end
                    T.enter_phase(T.PHASE_WARMUP)
                    send_relay_warmup(pkt_buf + 12, src_port, sess.proto_id, addr_in)
                    T.enter_phase(T.PHASE_HANDSHAKE)
                end

                if action == "trigger_migration" then
                    T.enter_phase(T.PHASE_MIGRATION)
                    send_direct_lead_in(pkt_buf + 12, src_port, dst_ip_ptr, dst_port, sess.proto_id, addr_in)
                    local dt = T.now_ms() - sess.start_ms
                    T.stat_migrated(sess.proto_id, dt, is_primary_mig)
                    local trig_lbl = mig_reason or (is_primary_mig and "2nd Server Handshake + BiDi 1-RTT" or "Backup 20 Pkts")
                    T.record("migration_triggered", src_port, sess.proto_id, trig_lbl, dt)
                    log_msg("%s [MIGRATED -> DIRECT] Client :%d -> %s:%d (%s, %.1fms)",
                        ts_prefix(), src_port, C.format_ipv4(dst_ip_ptr), dst_port, trig_lbl, dt)
                    if not relay_locked then
                        relay_locked = true
                        lock_time_ms = T.now_ms()
                        rx_at_lock   = T.live.direct_rx_pkts
                        stall_tx_since_rx = 0
                        active_port = dst_port
                        T.live.active_endpoint = sess.ep_str
                        T.ep_mark_migrated(sess.ep_str)
                        log_msg("%s [RELAY LOCKED] 1st session migrated. Press [ENTER] to re-arm...", ts_prefix())
                        T.record("relay_locked", src_port, sess.proto_id, trig_lbl)
                        T.flush_json("ai_report.json")
                        T.print_diagnostic_summary()
                    end
                    wd.WinDivertHelperCalcChecksums(pkt_buf, nbytes, addr_in, 0)
                    wd.WinDivertSend(handle, pkt_buf, nbytes, send_len, addr_in)
                elseif action == "direct" then
                    wd.WinDivertHelperCalcChecksums(pkt_buf, nbytes, addr_in, 0)
                    wd.WinDivertSend(handle, pkt_buf, nbytes, send_len, addr_in)
                else
                    -- Prepend 16B envelope into mod_buf via shared common.lua helper (zero allocation)
                    local new_pay_len = pay_len + C.OUTBOUND_PREPEND_LEN_V4
                    local new_total   = nbytes + C.OUTBOUND_PREPEND_LEN_V4
                    ffi.copy(mod_buf, pkt_buf, pay_off)
                    ffi.copy(mod_buf + pay_off + C.OUTBOUND_PREPEND_LEN_V4, pkt_buf + pay_off, pay_len)
                    C.build_outbound_camo(sess.proto_id, out_seq, camo_hdr, 0)
                    out_seq = out_seq + 1
                    C.pack_relay_env_v4(mod_buf, pay_off, camo_hdr, dst_ip_ptr, dst_port, sess.proto_id)

                    C.put_be16(mod_buf, 2, ihl + 8 + new_pay_len)
                    ffi.copy(mod_buf + 16, relay_ip_bytes, 4)
                    C.put_be16(mod_buf, udp_off + 2, cfg.relay_port)
                    C.put_be16(mod_buf, udp_off + 4, 8 + new_pay_len)

                    out_count = out_count + 1
                    T.ring_push(1, src_port, pay_len, qkind, 0)
                    local pspec = C.get_protocol_by_id(sess.proto_id)
                    if qkind == C.QUIC_LONG_INITIAL and (out_count <= 2 or out_count % 10 == 0) then
                        log_msg("%s [HANDSHAKE] Client :%d -> Initial (%dB) [%d:%s] -> Relay", ts_prefix(), src_port, pay_len, pspec.id, pspec.key)
                        T.record("handshake_pkt", src_port, sess.proto_id, string.format("OUT Initial %dB", pay_len))
                    elseif qkind == C.QUIC_LONG_HANDSHAKE then
                        log_msg("%s [HANDSHAKE] Client :%d -> Handshake (%dB) [%d:%s] -> Relay", ts_prefix(), src_port, pay_len, pspec.id, pspec.key)
                        T.record("handshake_pkt", src_port, sess.proto_id, string.format("OUT Handshake %dB", pay_len))
                    elseif qkind == C.QUIC_SHORT_1RTT and (sess.short_1rtt == 1 or sess.short_1rtt == 10 or sess.short_1rtt == 19) then
                        log_msg("%s [1-RTT TRANSIT] Client :%d -> Packet %d/20 via Relay", ts_prefix(), src_port, sess.short_1rtt)
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
                hs_no_reply_cnt = 0
                in_count = in_count + 1
                local sess = sessions[dst_port]
                -- Silently drop leftover relay packets for losing parallel ports after RELAY LOCKED
                if relay_locked and (not sess or (not sess.migrated and not sess.aux_allowed)) then
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
                local rtt1_count = 0
                for qi = 1, qcount do
                    local k = quic_kinds[qi]
                    local kname = C.QUIC_KIND_NAMES[k] or "QUIC"
                    if k == C.QUIC_LONG_INITIAL or k == C.QUIC_LONG_RETRY or k == C.QUIC_LONG_HANDSHAKE then
                        log_msg("%s [HANDSHAKE] Relay -> Stripped [%s (0x%02x)] -> Client :%d", ts_prefix(), kname, quic_bytes[qi], dst_port)
                        T.record("quic_coalesced", dst_port, locked_proto, string.format("IN %s (0x%02x)", kname, quic_bytes[qi]))
                    end
                    if k == C.QUIC_LONG_HANDSHAKE then hs_count = hs_count + 1 end
                    if k == C.QUIC_SHORT_1RTT then rtt1_count = rtt1_count + 1 end
                end

                if sess and hs_count > 0 and (not relay_locked or sess.aux_allowed) and not sess.migrated and not sess.hs_confirmed then
                    sess.srv_hs = sess.srv_hs + hs_count
                    if sess.srv_hs >= 2 then
                        sess.hs_confirmed = true
                        sess.hs_confirmed_ms = T.now_ms()
                        sess.post_hs_1rtt = 0
                        sess.srv_1rtt = 0
                        log_msg("%s [HS CONFIRMED] Client :%d -> 2nd Server Handshake (BiDi 1-RTT event-driven grace)", ts_prefix(), dst_port)
                    end
                elseif rtt1_count > 0 and sess and sess.hs_confirmed and not sess.migrated then
                    sess.srv_1rtt = sess.srv_1rtt + rtt1_count
                end

                wd.WinDivertHelperCalcChecksums(mod_buf, new_total, addr_in, 0)
                if cfg.zero_csum then mod_buf[udp_off + 6] = 0; mod_buf[udp_off + 7] = 0 end
                wd.WinDivertSend(handle, mod_buf, new_total, send_len, addr_in)
                goto continue_loop
            elseif (C.is_cloudflare_ip_v4(src_ip_ptr[0], src_ip_ptr[1], src_ip_ptr[2])
                or (src_ip_ptr[0] == target_ip_bytes[0] and src_ip_ptr[1] == target_ip_bytes[1]
                    and src_ip_ptr[2] == target_ip_bytes[2] and src_ip_ptr[3] == target_ip_bytes[3]))
                and (C.is_cloudflare_port(src_port) or src_port == cfg.target_port) then
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
    log_msg("[*] Unified AI RCA saved to ai_report.json + wme_session.log. MASQUE engine shut down cleanly.")
    T.close_session_log()
end

-- =========================================================================
-- CLI ENTRYPOINT & OFFICIAL CLOUDFLARE WARP AUTO-CONFIG
-- =========================================================================
local function prompt(msg)
    io.write(msg); io.flush()
    return (io.read("*l") or ""):match("^%s*(.-)%s*$")
end

local function print_all_protocols()
    print("\n  Camouflage Protocols (17 L4 Masks + AI Auto):")
    print("    [ 0] auto     - AI Smart Auto-Rotation (Discounted UCB1 Tier-1 Masks)")
    for id = 1, 17 do
        local p = C.PROTOCOLS[id]
        local tag = (id == 7 or id == 10 or id == 4 or id == 5) and " *Tier-1*" or ""
        print(string.format("    [%2d] %-8s - %s%s", p.id, p.key, p.name, tag))
    end
end

local function find_warp_cli()
    local std_path = [[C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe]]
    local f = io.open(std_path, "rb")
    if f then f:close(); return std_path end
    local p = io.popen("where warp-cli 2>nul")
    if p then
        local out = (p:read("*l") or ""):match("^%s*(.-)%s*$")
        p:close()
        if out ~= "" then return out end
    end
    return nil
end

local function exec_warp_cli(warp_bin, args)
    local cmd = string.format('""%s" %s 2>&1"', warp_bin, args)
    local p = io.popen(cmd)
    if not p then return false, "popen_failed" end
    local out = (p:read("*a") or ""):match("^%s*(.-)%s*$")
    local ok = p:close()
    return ok == true or ok == 0, out
end

local function configure_official_warp(relay_ip, target_ip, target_port, warp_mode)
    local warp_bin = find_warp_cli()
    if not warp_bin then
        print("[WARN] warp-cli.exe not found in C:\\Program Files\\Cloudflare\\Cloudflare WARP\\ or PATH.")
        return false, nil
    end

    print(string.format("\n[*] Configuring Official Cloudflare WARP (%s)...", warp_bin))
    local steps = {
        { args = "disconnect",                                           label = "Disconnect active session" },
        { args = "mode " .. warp_mode,                                   label = "Set WARP mode -> " .. warp_mode },
        { args = "tunnel protocol set MASQUE",                           label = "Set tunnel protocol -> MASQUE" },
        { args = "tunnel masque-options set h3-only",                    label = "Set MASQUE HTTP/3 -> h3-only" },
        { args = string.format("tunnel endpoint set %s:%d", target_ip, target_port), label = string.format("Set endpoint -> %s:%d", target_ip, target_port) },
        { args = "debug connectivity-check disable",                     label = "Disable connectivity-check" },
        { args = "debug high-timeouts enable",                           label = "Enable high-timeouts profile" },
    }

    for _, st in ipairs(steps) do
        local ok, out = exec_warp_cli(warp_bin, st.args)
        local status = ok and "OK" or "WARN"
        print(string.format("  [%s] %s%s", status, st.label, (not ok and out ~= "") and (" (" .. out .. ")") or ""))
        T.record("warp_cli_step", 0, 0, st.label .. " -> " .. status)
    end

    -- Critical for Full Tunnel (mode warp): WARP's WFP catch-all Deny firewall blocks the Relay IP unless excluded!
    local _, ip_list = exec_warp_cli(warp_bin, "tunnel ip list")
    if ip_list and (ip_list:find(relay_ip .. "/32", 1, true) or ip_list:find(relay_ip, 1, true)) then
        print(string.format("  [OK] Relay IP %s already in WARP Split Tunnel Exclude list", relay_ip))
        T.record("warp_cli_exclude", 0, 0, relay_ip .. " already excluded")
    else
        local ok_add, out_add = exec_warp_cli(warp_bin, "tunnel ip add " .. relay_ip)
        print(string.format("  [%s] Exclude Relay IP %s from WARP WFP firewall (warp-cli tunnel ip add)%s",
            ok_add and "OK" or "WARN", relay_ip, (not ok_add and out_add ~= "") and (" (" .. out_add .. ")") or ""))
        T.record("warp_cli_exclude", 0, 0, relay_ip .. " add -> " .. (ok_add and "OK" or out_add))
    end

    return true, warp_bin
end

local function main()
    print("=========================================================================")
    print("  Warp Migration Engine - QUIC / MASQUE Edition (LuaJIT 2.1 + FFI)")
    print("=========================================================================")

    local saved = load_config()
    local is_saved = (saved.relay_ip ~= nil and saved.warp_configured == true)

    if is_saved then
        print(string.format("  Saved Profile  : Relay %s:%d | Target %s:%d | WARP: %s",
            saved.relay_ip, saved.relay_port or 2632,
            saved.target_ip or "162.159.198.2", saved.target_port or 8095,
            saved.warp_mode or "warp"))
    end

    print_all_protocols()
    local def_p = saved.proto_id or 7
    local p_prompt = is_saved
        and string.format("\nSelect Protocol [0..17, r=Reconfigure, Enter for %d (%s)]: ", def_p, def_p == 0 and "auto" or C.get_protocol_by_id(def_p).key)
        or  string.format("\nSelect Protocol [0..17, Enter for %d (%s)]: ", def_p, def_p == 0 and "auto" or C.get_protocol_by_id(def_p).key)
    local raw_p = prompt(p_prompt)

    local force_reconfig = (raw_p:lower() == "r")
    local proto_id = tonumber(raw_p)
    if not proto_id or proto_id < 0 or proto_id > 17 then proto_id = def_p end

    if is_saved and not force_reconfig then
        if proto_id ~= saved.proto_id then
            saved.proto_id = proto_id
            save_config({
                relay_ip          = saved.relay_ip,
                relay_port        = saved.relay_port or 2632,
                target_ip         = saved.target_ip or "162.159.198.2",
                target_port       = saved.target_port or 8095,
                proto_id          = proto_id,
                warp_mode         = saved.warp_mode or "warp",
                warp_configured   = true,
                warp_auto_connect = saved.warp_auto_connect,
            })
        end
        run_masque_engine({
            proto_id          = proto_id,
            target_ip         = saved.target_ip or "162.159.198.2",
            target_port       = saved.target_port or 8095,
            relay_ip          = saved.relay_ip,
            relay_port        = saved.relay_port or 2632,
            warp_auto_setup   = true,
            warp_mode         = saved.warp_mode or "warp",
            warp_cli_bin      = find_warp_cli(),
            warp_auto_connect = saved.warp_auto_connect,
            zero_csum         = false,
        })
        return
    end

    if force_reconfig then
        print_all_protocols()
        local p2 = prompt(string.format("\nSelect Protocol [0..17, Enter for %d (%s)]: ", def_p, def_p == 0 and "auto" or C.get_protocol_by_id(def_p).key))
        local p2_num = tonumber(p2)
        if p2_num and p2_num >= 0 and p2_num <= 17 then proto_id = p2_num end
    end

    local relay_ip, relay_port = saved.relay_ip, saved.relay_port or 2632
    local ans
    if relay_ip then
        ans = prompt(string.format("\nUse saved Relay Server [%s:%d]? (Enter to keep, or IP:PORT): ", relay_ip, relay_port))
    else
        ans = prompt("\nEnter Relay Server [IP:PORT, e.g. 198.51.100.1:4678]: ")
    end
    if ans ~= "" then
        local ip, p = C.parse_endpoint_str(ans, relay_port)
        if ip then relay_ip = ip; relay_port = p else print("[!] Invalid Relay IP:PORT."); return end
    end
    if not relay_ip or relay_ip == "" then print("[!] Relay IP required."); return end

    local def_t_ip   = saved.target_ip or "162.159.198.2"
    local def_t_port = saved.target_port or 8095
    local t_ans = prompt(string.format("WARP Target Endpoint [%s:%d]? (Enter to keep, or IP:PORT): ", def_t_ip, def_t_port))
    local target_ip, target_port = def_t_ip, def_t_port
    if t_ans ~= "" then
        local tip, tp = C.parse_endpoint_str(t_ans, def_t_port)
        if tip then target_ip = tip; target_port = tp else print("[!] Invalid Target IP:PORT, keeping default.") end
    end

    local warp_auto = false
    local warp_mode = "manual"
    local warp_bin = nil
    local warp_auto_connect = false

    local use_official = prompt("\nUsing Official Cloudflare WARP client? Auto-configure it now? [Y/n]: "):lower()
    if use_official == "" or use_official == "y" or use_official == "yes" then
        print("  [1] Full Tunnel (warp) [Recommended — routes all Windows traffic]")
        print("  [2] Local SOCKS5 Proxy (proxy on 127.0.0.1:40000)")
        local wm = prompt("Select Official WARP Mode [1 or 2, Default 1]: ")
        warp_mode = (wm == "2") and "proxy" or "warp"
        warp_auto, warp_bin = configure_official_warp(relay_ip, target_ip, target_port, warp_mode)
        if warp_auto then
            local ac = prompt("Auto-connect Cloudflare WARP right after engine starts? [Y/n]: "):lower()
            warp_auto_connect = (ac == "" or ac == "y" or ac == "yes")
        end
    end

    save_config({
        relay_ip          = relay_ip,
        relay_port        = relay_port,
        target_ip         = target_ip,
        target_port       = target_port,
        proto_id          = proto_id,
        warp_mode         = warp_mode,
        warp_configured   = warp_auto,
        warp_auto_connect = warp_auto_connect,
    })

    run_masque_engine({
        proto_id          = proto_id,
        target_ip         = target_ip,
        target_port       = target_port,
        relay_ip          = relay_ip,
        relay_port        = relay_port,
        warp_auto_setup   = warp_auto,
        warp_mode         = warp_mode,
        warp_cli_bin      = warp_bin,
        warp_auto_connect = warp_auto_connect,
        zero_csum         = false,
    })
end

main()
