-- test_suite.lua: Automated verification of Common, RFC 9000, Checksums, Telemetry & WinDivert ABI
local ffi = require("ffi")
local C = require("common")
local T = require("telemetry")

-- 1. Verify WinDivert 2.2.2 WINDIVERT_ADDRESS size (must be 64 bytes on x64)
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
    } TEST_WINDIVERT_ADDRESS;
]]
assert(ffi.sizeof("TEST_WINDIVERT_ADDRESS") == 64, "WINDIVERT_ADDRESS must be 64 bytes")
print("[PASS] WINDIVERT_ADDRESS sizeof == 64 bytes")

-- 2. Verify RFC 9000 Varint parsing
local b = ffi.new("uint8_t[8]")
b[0] = 25
local v1, c1 = C.parse_quic_varint(b, 0, 1)
assert(v1 == 25 and c1 == 1, "1-byte varint failed")

b[0] = 0x40; b[1] = 0x16
local v2, c2 = C.parse_quic_varint(b, 0, 2)
assert(v2 == 22 and c2 == 2, "2-byte varint failed")

b[0] = 0x80; b[1] = 0x00; b[2] = 0x01; b[3] = 0x00
local v3, c3 = C.parse_quic_varint(b, 0, 4)
assert(v3 == 256 and c3 == 4, "4-byte varint failed")
print("[PASS] RFC 9000 Varint (1B, 2B, 4B)")

-- 3. Verify Coalesced QUIC Packet Dissection (40B Initial + 30B Handshake = 70B)
local qbuf = ffi.new("uint8_t[70]")
qbuf[0] = 0xc0; qbuf[4] = 1; qbuf[5] = 8; qbuf[14] = 8; qbuf[23] = 0; qbuf[24] = 15
qbuf[40] = 0xe0; qbuf[44] = 1; qbuf[45] = 8; qbuf[54] = 8; qbuf[63] = 6
local kinds = ffi.new("uint8_t[8]")
local fbytes = ffi.new("uint8_t[8]")
local qcnt = C.inspect_all_quic_packets(qbuf, 0, 70, kinds, fbytes)
assert(qcnt == 2 and kinds[1] == C.QUIC_LONG_INITIAL and kinds[2] == C.QUIC_LONG_HANDSHAKE, "Coalesced QUIC failed")
print("[PASS] Coalesced QUIC Dissection (Initial + Handshake)")

-- 4. Verify all 17 Camouflage Protocols (Outbound, Inbound, Lead-In)
local hdr = ffi.new("uint8_t[8]")
local lbuf = ffi.new("uint8_t[1500]")
for pid = 1, 17 do
    C.build_outbound_camo(pid, 1, hdr, 0)
    C.build_inbound_camo(pid, 1, hdr, 0)
    local sz = C.build_lead_payload(pid, 96, 2, 1700000000, 1700000000, lbuf)
    assert(sz == 96, "Lead payload size mismatch for proto " .. pid)
end
print("[PASS] All 17 Camouflage Protocols (Outbound, Inbound, Lead-In)")

-- 5. Verify Cloudflare WARP IPv4 ranges & Ports
assert(C.is_cloudflare_ip_v4(162, 159, 198) == true)
assert(C.is_cloudflare_ip_v4(188, 114, 97) == true)
assert(C.is_cloudflare_ip_v4(8, 8, 8) == false)
assert(C.is_cloudflare_port(8095) == true)
assert(C.is_cloudflare_port(5203) == true)
assert(C.is_cloudflare_port(2408) == false)
assert(C.is_cloudflare_port(80) == false)
local env_buf = ffi.new("uint8_t[16]")
local dst_ip_t = ffi.new("uint8_t[4]", {162, 159, 198, 2})
C.build_outbound_camo(7, 1, hdr, 0)
C.pack_relay_env_v4(env_buf, 0, hdr, dst_ip_t, 8095, 7)
assert(env_buf[8] == 162 and env_buf[11] == 2 and C.get_be16(env_buf, 12) == 8095 and env_buf[14] == 7 and env_buf[15] == C.ADDR_TYPE_IPV4, "pack_relay_env_v4 failed")
assert(T.E2E_SYSTEM_MODEL.server_contract.session_ttl_s == C.RELAY_SESSION_TTL_S, "E2E contract TTL sync failed")
local ep_ip, ep_port = C.parse_endpoint_str("162.159.198.2:8095", 8095)
assert(ep_ip == "162.159.198.2" and ep_port == 8095, "parse_endpoint_str failed")
local ep_ip2, ep_port2 = C.parse_endpoint_str("167.17.67.90", 4678)
assert(ep_ip2 == "167.17.67.90" and ep_port2 == 4678, "parse_endpoint_str default port failed")
assert(C.format_protocol_label(7):find("esp", 1, true) ~= nil, "format_protocol_label failed")
print("[PASS] Cloudflare WARP IPv4 Ranges, Ports & Endpoint Parser")

-- 6. Verify IPv4 + UDP Checksum & Packet Builder
local src_ip = ffi.new("uint8_t[4]", {192, 168, 1, 10})
local dst_ip = ffi.new("uint8_t[4]", {162, 159, 198, 2})
local pkt = ffi.new("uint8_t[256]")
local tlen = C.build_ipv4_udp_packet(pkt, src_ip, dst_ip, 50000, 8095, lbuf, 48)
assert(tlen == 20 + 8 + 48, "Packet length mismatch")
assert(C.calc_ipv4_checksum(pkt, 20) == C.get_be16(pkt, 10), "IPv4 checksum mismatch")
print("[PASS] IPv4/UDP Checksum & Packet Builder")

-- 7. Verify Telemetry, Welford Online Baseline & UCB1 Bandit
local w = T.welford_new()
T.welford_update(w, 100); T.welford_update(w, 110); T.welford_update(w, 90); T.welford_update(w, 100)
assert(math.abs(w.mean - 100) < 0.01, "Welford mean failed")
assert(T.welford_zscore(w, 160) > 2.5, "Welford z-score failed")

T.bandit_reward(7, 0.9)
T.bandit_reward(10, 0.2)
local picked = T.pick_smart_mask({7, 10, 4, 5}, nil)
assert(picked == 4 or picked == 5, "UCB1 should explore untried arms first")

T.enter_phase(T.PHASE_HANDSHAKE)
T.enter_phase(T.PHASE_MIGRATION)
T.enter_phase(T.PHASE_DIRECT_1RTT)
local cause, domain = T.attribute_and_discover()
assert(type(cause) == "string" and type(domain) == "string", "Attribution failed")

-- 8. Verify Digital Twin, Sandbox Security, Server Contract Rejection & Auto-Rollback
assert(T.E2E_SYSTEM_MODEL.server_contract.outbound_env_v4 == 16, "E2E contract mismatch")
local ok_bad1, err1 = T.activate_evolved_policy("return function(ctx) os.execute('calc') end", false)
assert(not ok_bad1 and err1:match("forbidden"), "Sandbox must reject os.execute")
local ok_bad2, err2 = T.activate_evolved_policy("return function(ctx) return { action = 'DIVERSE_SWITCH', stall_ms = 100 } end", false)
assert(not ok_bad2 and err2 == "contract_stall_bounds", "Digital Twin must reject unsafe stall_ms")
local ok_good = T.synthesize_policy_from_features()
assert(ok_good == true, "Valid synthesized policy failed")
assert(T.on_policy_stall() == false, "1st stall should not rollback yet")
assert(T.on_policy_stall() == true, "2nd stall must trigger Auto-Rollback")
local has_pol, rollbacks = T.get_policy_stats()
assert(has_pol == false and rollbacks >= 1, "Rollback state mismatch")
os.remove("evolved_policy.lua")
print("[PASS] Digital Twin, Sandbox Security & Auto-Rollback")

T.stat_attempt(7)
T.record("migration_triggered", 50000, 7, "Test OK", 42.5)
T.stat_migrated(7, 42.5, true)
T.init_session_log("test_session.log")
T.session_meta.engine_mode = "masque"
T.session_meta.warp_auto_setup = true
T.log_line("[TEST] Unified logger verification")
assert(T.flush_json("test_telemetry.json", true) == true)
T.close_session_log()
os.remove("test_telemetry.json")
os.remove("test_session.log")
print("[PASS] Self-Learning Brain (Welford + UCB1 + Flight Recorder)")
print("\nALL 7 SUITE CHECKS PASSED!")
