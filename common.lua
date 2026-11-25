-- common.lua: Protocols, 17 Camouflage Masks, RFC 9000 QUIC Parser, Envelope & Checksums
-- Zero-allocation hot path using LuaJIT 2.1 FFI + bit library.

local ffi = require("ffi")
local bit = require("bit")

local band, bor, bxor = bit.band, bit.bor, bit.bxor
local lshift, rshift = bit.lshift, bit.rshift
local bnot = bit.bnot

local M = {}

M.OUTBOUND_PREPEND_LEN_V4 = 16
M.OUTBOUND_PREPEND_LEN_V6 = 28
M.INBOUND_STRIP_LEN       = 8
M.ADDR_TYPE_IPV4          = 0x04
M.ADDR_TYPE_IPV6          = 0x06

-- QUIC Packet Kinds
M.QUIC_LONG_INITIAL   = 1
M.QUIC_LONG_0RTT      = 2
M.QUIC_LONG_HANDSHAKE = 3
M.QUIC_LONG_RETRY     = 4
M.QUIC_LONG_OTHER     = 5
M.QUIC_SHORT_1RTT     = 6
M.QUIC_UNKNOWN        = 7

M.QUIC_KIND_NAMES = {
    [1] = "QUIC Initial",
    [2] = "QUIC 0-RTT",
    [3] = "QUIC Handshake",
    [4] = "QUIC Retry",
    [5] = "QUIC Long",
    [6] = "QUIC 1-RTT",
    [7] = "UDP Non-QUIC",
}

-- 17 Layer-4 Camouflage Protocol Specs
M.PROTOCOLS = {
    [1]  = { id = 1,  key = "junk",    name = "Classic Random Junk (AmneziaWG)",          c_min = 4, c_max = 8, s_min = 100,  s_max = 950  },
    [2]  = { id = 2,  key = "quic_v1", name = "QUIC v1 / HTTP/3 Short Header (0x43)",      c_min = 4, c_max = 8, s_min = 1200, s_max = 1250 },
    [3]  = { id = 3,  key = "quic_v2", name = "QUIC v2 / RFC 9369 Initial Header (0xD0)", c_min = 4, c_max = 8, s_min = 1200, s_max = 1250 },
    [4]  = { id = 4,  key = "webrtc",  name = "WebRTC / SRTP Audio Video Stream (RTP v2)", c_min = 4, c_max = 8, s_min = 64,   s_max = 220  },
    [5]  = { id = 5,  key = "dtls",    name = "DTLS 1.2 Application Data Record",         c_min = 4, c_max = 8, s_min = 180,  s_max = 350  },
    [6]  = { id = 6,  key = "dns",     name = "DNS Query (Standard RFC 1035)",             c_min = 4, c_max = 8, s_min = 42,   s_max = 68   },
    [7]  = { id = 7,  key = "esp",     name = "IPsec NAT-T ESP (Enterprise Tunnel)",       c_min = 4, c_max = 8, s_min = 100,  s_max = 850  },
    [8]  = { id = 8,  key = "utp",     name = "uTP BitTorrent (State Data Packet)",       c_min = 4, c_max = 8, s_min = 60,   s_max = 400  },
    [9]  = { id = 9,  key = "raknet",  name = "RakNet Gaming (Minecraft Bedrock)",        c_min = 4, c_max = 8, s_min = 100,  s_max = 500  },
    [10] = { id = 10, key = "stun",    name = "STUN / ICE Binding Request (RFC 5389)",     c_min = 4, c_max = 8, s_min = 48,   s_max = 120  },
    [11] = { id = 11, key = "turn",    name = "TURN ChannelData (Relayed Media)",         c_min = 4, c_max = 8, s_min = 48,   s_max = 100  },
    [12] = { id = 12, key = "steam",   name = "Steam / Valve Source Query (CS:GO)",       c_min = 4, c_max = 8, s_min = 40,   s_max = 120  },
    [13] = { id = 13, key = "sdr",     name = "Steam Datagram Relay (CS2 SDR Transport)", c_min = 4, c_max = 8, s_min = 60,   s_max = 150  },
    [14] = { id = 14, key = "riot",    name = "Riot Games (Valorant / LoL Media)",        c_min = 4, c_max = 8, s_min = 50,   s_max = 120  },
    [15] = { id = 15, key = "zoom",    name = "Zoom Media Stream (RTP Video / Voice)",    c_min = 4, c_max = 8, s_min = 80,   s_max = 240  },
    [16] = { id = 16, key = "rdp",     name = "Microsoft RDP over UDP (MS-RDPEUDP)",      c_min = 4, c_max = 8, s_min = 70,   s_max = 200  },
    [17] = { id = 17, key = "discord", name = "Discord Voice & Media (Opus Audio)",       c_min = 4, c_max = 8, s_min = 60,   s_max = 160  },
}

M.TIER1_PROTO_IDS        = { 2, 3, 4, 5, 7, 10 }
M.MASQUE_TIER1_PROTO_IDS = { 7, 10, 4, 5 }

function M.get_protocol_by_id(id)
    return M.PROTOCOLS[id] or M.PROTOCOLS[7]
end

-- Fast xorshift32 PRNG (pure 32-bit bit ops, zero heap allocation)
local rng_state = bxor(os.time(), 0x517cc1b7)
if rng_state == 0 then rng_state = 0x517cc1b7 end

function M.seed_rng(seed)
    rng_state = band(seed, 0xFFFFFFFF)
    if rng_state == 0 then rng_state = 0x517cc1b7 end
end

function M.next_u32()
    local x = rng_state
    x = bxor(x, lshift(x, 13))
    x = bxor(x, rshift(x, 17))
    x = bxor(x, lshift(x, 5))
    rng_state = x
    if x < 0 then return x + 4294967296 end
    return x
end

function M.fill_bytes(buf, offset, count)
    local i = 0
    while i < count do
        local r = M.next_u32()
        local rem = count - i
        if rem >= 4 then
            buf[offset + i]     = band(r, 0xFF)
            buf[offset + i + 1] = band(rshift(r, 8), 0xFF)
            buf[offset + i + 2] = band(rshift(r, 16), 0xFF)
            buf[offset + i + 3] = band(rshift(r, 24), 0xFF)
            i = i + 4
        else
            for j = 0, rem - 1 do
                buf[offset + i + j] = band(rshift(r, j * 8), 0xFF)
            end
            i = i + rem
        end
    end
end

local function pick_non_repeating(pool, last_id)
    local n = #pool
    if n == 0 then return 7 end
    if last_id and n > 1 then
        local idx = (M.next_u32() % (n - 1)) + 1
        local c = 0
        for i = 1, n do
            if pool[i] ~= last_id then
                c = c + 1
                if c == idx then return pool[i] end
            end
        end
    end
    return pool[(M.next_u32() % n) + 1]
end

function M.get_next_auto_proto(last_id)
    return pick_non_repeating(M.TIER1_PROTO_IDS, last_id)
end

function M.get_next_masque_auto_proto(last_id)
    return pick_non_repeating(M.MASQUE_TIER1_PROTO_IDS, last_id)
end

-- Helper to write big-endian u16 / u32 into uint8_t* buffer
local function put_be16(buf, off, val)
    buf[off]     = band(rshift(val, 8), 0xFF)
    buf[off + 1] = band(val, 0xFF)
end

local function put_be32(buf, off, val)
    buf[off]     = band(rshift(val, 24), 0xFF)
    buf[off + 1] = band(rshift(val, 16), 0xFF)
    buf[off + 2] = band(rshift(val, 8), 0xFF)
    buf[off + 3] = band(val, 0xFF)
end

local function get_be16(buf, off)
    return bor(lshift(buf[off], 8), buf[off + 1])
end

M.put_be16 = put_be16
M.put_be32 = put_be32
M.get_be16 = get_be16

-- Build 8-byte outbound camouflage header directly into `hdr` (uint8_t*) at `off`
function M.build_outbound_camo(proto_id, seq, hdr, off)
    off = off or 0
    if proto_id == 1 then
        put_be32(hdr, off, M.next_u32())
        put_be32(hdr, off + 4, seq)
    elseif proto_id == 2 then
        hdr[off] = 0x43; hdr[off+1] = 0xAA; hdr[off+2] = 0xBB; hdr[off+3] = 0xCC
        put_be32(hdr, off + 4, seq)
    elseif proto_id == 3 then
        hdr[off] = 0xD0; hdr[off+1] = 0x6B; hdr[off+2] = 0x33; hdr[off+3] = 0x43
        hdr[off+4] = 0xCF; hdr[off+5] = 0x08
        put_be16(hdr, off + 6, seq)
    elseif proto_id == 4 then
        hdr[off] = 0x80; hdr[off+1] = 0x60
        put_be16(hdr, off + 2, seq)
        put_be32(hdr, off + 4, seq * 160)
    elseif proto_id == 5 then
        hdr[off] = 0x17; hdr[off+1] = 0xFE; hdr[off+2] = 0xFD
        hdr[off+3] = 0x00; hdr[off+4] = 0x01; hdr[off+5] = 0x00
        put_be16(hdr, off + 6, seq)
    elseif proto_id == 6 then
        put_be16(hdr, off, bxor(seq, 0xA5A5))
        hdr[off+2] = 0x01; hdr[off+3] = 0x00
        hdr[off+4] = 0x00; hdr[off+5] = 0x01
        hdr[off+6] = 0x00; hdr[off+7] = 0x00
    elseif proto_id == 7 then
        hdr[off] = 0x19; hdr[off+1] = 0x84; hdr[off+2] = 0x07; hdr[off+3] = 0x10
        put_be32(hdr, off + 4, seq)
    elseif proto_id == 8 then
        hdr[off] = 0x21; hdr[off+1] = 0x00; hdr[off+2] = 0x04; hdr[off+3] = 0xD2
        put_be16(hdr, off + 4, seq)
        put_be16(hdr, off + 6, seq > 0 and (seq - 1) or 0)
    elseif proto_id == 9 then
        hdr[off]   = 0x84
        hdr[off+1] = band(seq, 0xFF)
        hdr[off+2] = band(rshift(seq, 8), 0xFF)
        hdr[off+3] = band(rshift(seq, 16), 0xFF)
        hdr[off+4] = 0x40; hdr[off+5] = 0x00; hdr[off+6] = 0x04; hdr[off+7] = 0x00
    elseif proto_id == 10 then
        hdr[off] = 0x00; hdr[off+1] = 0x01; hdr[off+2] = 0x00; hdr[off+3] = 0x00
        hdr[off+4] = 0x21; hdr[off+5] = 0x12; hdr[off+6] = 0xA4; hdr[off+7] = 0x42
    elseif proto_id == 11 then
        hdr[off] = 0x40; hdr[off+1] = 0x00
        put_be16(hdr, off + 2, seq)
        hdr[off+4] = 0x11; hdr[off+5] = 0x22; hdr[off+6] = 0x33; hdr[off+7] = 0x44
    elseif proto_id == 12 then
        hdr[off] = 0xFF; hdr[off+1] = 0xFF; hdr[off+2] = 0xFF; hdr[off+3] = 0xFF
        hdr[off+4] = 0x54; hdr[off+5] = 0x53; hdr[off+6] = 0x6F; hdr[off+7] = 0x75
    elseif proto_id == 13 then
        hdr[off] = 0x01; hdr[off+1] = 0x00; hdr[off+2] = 0x01; hdr[off+3] = 0x00
        put_be32(hdr, off + 4, seq)
    elseif proto_id == 14 then
        hdr[off] = 0x00; hdr[off+1] = 0x01; hdr[off+2] = 0x02; hdr[off+3] = band(seq, 0xFF)
        put_be32(hdr, off + 4, seq)
    elseif proto_id == 15 then
        hdr[off] = 0x80; hdr[off+1] = 0x62
        put_be16(hdr, off + 2, seq)
        put_be32(hdr, off + 4, seq * 3000)
    elseif proto_id == 16 then
        hdr[off] = 0xD0; hdr[off+1] = 0x00; hdr[off+2] = 0x00; hdr[off+3] = 0x01
        put_be32(hdr, off + 4, seq)
    elseif proto_id == 17 then
        hdr[off] = 0x80; hdr[off+1] = 0x78
        put_be16(hdr, off + 2, seq)
        put_be32(hdr, off + 4, seq * 960)
    else
        hdr[off] = 0x19; hdr[off+1] = 0x84; hdr[off+2] = 0x07; hdr[off+3] = 0x10
        put_be32(hdr, off + 4, seq)
    end
end

-- Build 8-byte inbound camouflage response header directly into `hdr` (uint8_t*) at `off`
function M.build_inbound_camo(proto_id, seq, hdr, off)
    off = off or 0
    if proto_id == 10 then
        hdr[off] = 0x01; hdr[off+1] = 0x01; hdr[off+2] = 0x00; hdr[off+3] = 0x00
        hdr[off+4] = 0x21; hdr[off+5] = 0x12; hdr[off+6] = 0xA4; hdr[off+7] = 0x42
    elseif proto_id == 6 then
        put_be16(hdr, off, bxor(seq, 0xA5A5))
        hdr[off+2] = 0x81; hdr[off+3] = 0x80
        hdr[off+4] = 0x00; hdr[off+5] = 0x01
        hdr[off+6] = 0x00; hdr[off+7] = 0x01
    elseif proto_id == 5 then
        hdr[off] = 0x17; hdr[off+1] = 0xFE; hdr[off+2] = 0xFD
        hdr[off+3] = 0x00; hdr[off+4] = 0x01; hdr[off+5] = 0x00
        put_be16(hdr, off + 6, seq)
    elseif proto_id == 4 or proto_id == 15 or proto_id == 17 then
        hdr[off] = 0x80; hdr[off+1] = 0x60
        put_be16(hdr, off + 2, seq)
        put_be32(hdr, off + 4, seq * 160)
    else
        hdr[off] = 0x19; hdr[off+1] = 0x84; hdr[off+2] = 0x07; hdr[off+3] = 0x10
        put_be32(hdr, off + 4, seq)
    end
end

-- Build full lead-in packet payload (Stateful CPS Chain: I1 / I2) into `buf` (uint8_t*)
local STEAM_QUERY = "Source Engine Query\0"
function M.build_lead_payload(proto_id, size, seq, ts_now, ts_us, buf)
    local pos = 0
    if proto_id == 1 then
        if seq > 1 and size >= 8 then
            put_be32(buf, 0, ts_now); put_be32(buf, 4, seq); pos = 8
        end
    elseif proto_id == 2 then
        buf[0] = 0x43
        M.fill_bytes(buf, 1, 8)
        put_be16(buf, 9, seq)
        buf[11] = 0x00; buf[12] = 0x00
        M.fill_bytes(buf, 13, 7)
        pos = 20
    elseif proto_id == 3 then
        buf[0]=0xD0; buf[1]=0x6B; buf[2]=0x33; buf[3]=0x43; buf[4]=0xCF; buf[5]=0x08
        M.fill_bytes(buf, 6, 8)
        buf[14]=0x00; buf[15]=0x00; buf[16]=0x44; buf[17]=0x50; buf[18]=seq % 256
        pos = 19
    elseif proto_id == 4 then
        buf[0]=0x80; buf[1]=0x60; put_be16(buf, 2, seq); put_be32(buf, 4, seq * 160)
        buf[8]=0x11; buf[9]=0x22; buf[10]=0x33; buf[11]=0x44; buf[12]=0x00; buf[13]=0x00
        M.fill_bytes(buf, 14, 6); pos = 20
    elseif proto_id == 5 then
        local frag_len = size >= 13 and (size - 13) or 0
        buf[0]=0x17; buf[1]=0xFE; buf[2]=0xFD; buf[3]=0x00; buf[4]=0x01
        buf[5]=0x00; buf[6]=0x00; buf[7]=0x00; buf[8]=0x00
        put_be16(buf, 9, seq); put_be16(buf, 11, frag_len)
        buf[13]=0x00; buf[14]=0x00; M.fill_bytes(buf, 15, 5); pos = 20
    elseif proto_id == 6 then
        put_be16(buf, 0, bxor(band(M.next_u32(), 0xFFFF), band(seq, 0xFFFF)))
        buf[2]=0x01; buf[3]=0x00; buf[4]=0x00; buf[5]=0x01
        buf[6]=0x00; buf[7]=0x00; buf[8]=0x00; buf[9]=0x00
        M.fill_bytes(buf, 10, 8); buf[18]=0x00; buf[19]=0x01; pos = 20
    elseif proto_id == 7 then
        buf[0]=0x19; buf[1]=0x84; buf[2]=0x07; buf[3]=0x10
        put_be32(buf, 4, seq); buf[8]=0x00; buf[9]=0x00
        M.fill_bytes(buf, 10, 8); buf[18]=0x00; buf[19]=0x00; pos = 20
    elseif proto_id == 8 then
        buf[0]=0x21; buf[1]=0x00; buf[2]=0x04; buf[3]=0xD2
        put_be32(buf, 4, ts_us or ts_now)
        buf[8]=0; buf[9]=0; buf[10]=0; buf[11]=0; buf[12]=0; buf[13]=0x10; buf[14]=0; buf[15]=0
        put_be16(buf, 16, seq)
        put_be16(buf, 18, seq > 0 and (seq - 1) or 0); pos = 20
    elseif proto_id == 9 then
        local body_bytes = size >= 7 and (size - 7) or 0
        local bit_len = (body_bytes * 8) % 65536
        buf[0]=0x84; buf[1]=band(seq,0xFF); buf[2]=band(rshift(seq,8),0xFF); buf[3]=0
        buf[4]=0x40; put_be16(buf, 5, bit_len)
        buf[7]=band(seq,0xFF); buf[8]=band(rshift(seq,8),0xFF); buf[9]=0
        buf[10]=0; buf[11]=0; buf[12]=0; buf[13]=0
        M.fill_bytes(buf, 14, 6); pos = 20
    elseif proto_id == 10 then
        local msg_len = size >= 20 and (math.floor((size - 20) / 4) * 4) or 0
        buf[0]=0x00; buf[1]=0x01; put_be16(buf, 2, msg_len)
        buf[4]=0x21; buf[5]=0x12; buf[6]=0xA4; buf[7]=0x42
        M.fill_bytes(buf, 8, 12); pos = 20
    elseif proto_id == 11 then
        local data_len = size >= 4 and (size - 4) or 0
        buf[0]=0x40; buf[1]=0x00; put_be16(buf, 2, data_len)
        buf[4]=0; buf[5]=0; buf[6]=0; buf[7]=0
        M.fill_bytes(buf, 8, 12); pos = 20
    elseif proto_id == 12 then
        buf[0]=0xFF; buf[1]=0xFF; buf[2]=0xFF; buf[3]=0xFF; buf[4]=0x54
        ffi.copy(buf + 5, STEAM_QUERY, #STEAM_QUERY)
        pos = 5 + #STEAM_QUERY
    elseif proto_id == 13 then
        buf[0]=0x01; buf[1]=0x00; buf[2]=0x01; buf[3]=0x00; buf[4]=0x00
        put_be32(buf, 5, seq); buf[9]=0; buf[10]=0
        M.fill_bytes(buf, 11, 9); pos = 20
    elseif proto_id == 14 then
        buf[0]=0x00; buf[1]=0x01; buf[2]=0x02; put_be32(buf, 3, seq)
        buf[7]=0; buf[8]=0; M.fill_bytes(buf, 9, 11); pos = 20
    elseif proto_id == 15 then
        buf[0]=0x80; buf[1]=0x62; put_be16(buf, 2, seq); put_be32(buf, 4, seq * 3000)
        buf[8]=0x4A; buf[9]=0x53; buf[10]=0x54; buf[11]=0x55; buf[12]=0; buf[13]=0
        M.fill_bytes(buf, 14, 6); pos = 20
    elseif proto_id == 16 then
        buf[0]=0xD0; buf[1]=0x00; buf[2]=0x00; buf[3]=0x01
        put_be32(buf, 4, seq); buf[8]=0; buf[9]=0
        M.fill_bytes(buf, 10, 8); buf[18]=0; buf[19]=0; pos = 20
    elseif proto_id == 17 then
        buf[0]=0x80; buf[1]=0x78; put_be16(buf, 2, seq); put_be32(buf, 4, seq * 960)
        buf[8]=0xDE; buf[9]=0xAD; buf[10]=0xBE; buf[11]=0xEF; buf[12]=0; buf[13]=0
        M.fill_bytes(buf, 14, 6); pos = 20
    else
        buf[0]=0x19; buf[1]=0x84; buf[2]=0x07; buf[3]=0x10; put_be32(buf, 4, seq); pos = 8
    end

    if pos < size then
        local pad_len = size - pos
        if seq > 1 and pad_len >= 8 and proto_id ~= 1 then
            put_be32(buf, pos, ts_now)
            put_be32(buf, pos + 4, seq)
            if pad_len > 8 then
                M.fill_bytes(buf, pos + 8, pad_len - 8)
            end
        else
            M.fill_bytes(buf, pos, pad_len)
        end
    end
    return size
end

-- RFC 9000 Varint Parser: returns (value, bytes_consumed) or nil
function M.parse_quic_varint(buf, pos, total_len)
    if pos >= total_len then return nil end
    local first = buf[pos]
    local prefix = rshift(first, 6)
    if prefix == 0 then
        return band(first, 0x3F), 1
    elseif prefix == 1 then
        if pos + 2 > total_len then return nil end
        local v = bor(lshift(band(first, 0x3F), 8), buf[pos + 1])
        return v, 2
    elseif prefix == 2 then
        if pos + 4 > total_len then return nil end
        local v = bor(
            lshift(band(first, 0x3F), 24),
            lshift(buf[pos + 1], 16),
            lshift(buf[pos + 2], 8),
            buf[pos + 3]
        )
        if v < 0 then v = v + 4294967296 end
        return v, 4
    else
        if pos + 8 > total_len then return nil end
        local hi = bor(
            lshift(band(first, 0x3F), 24),
            lshift(buf[pos + 1], 16),
            lshift(buf[pos + 2], 8),
            buf[pos + 3]
        )
        if hi < 0 then hi = hi + 4294967296 end
        local lo = bor(
            lshift(buf[pos + 4], 24),
            lshift(buf[pos + 5], 16),
            lshift(buf[pos + 6], 8),
            buf[pos + 7]
        )
        if lo < 0 then lo = lo + 4294967296 end
        return hi * 4294967296 + lo, 8
    end
end

local function parse_long_header_len(buf, base, len, packet_type)
    if len < 7 then return nil end
    local dcil = buf[base + 5]
    local scil_offset = 6 + dcil
    if len <= scil_offset then return nil end
    local scil = buf[base + scil_offset]
    local pos = scil_offset + 1 + scil
    if len < pos then return nil end

    if packet_type == 0x00 then
        local tok_len, tok_vlen = M.parse_quic_varint(buf, base + pos, base + len)
        if not tok_len then return nil end
        pos = pos + tok_vlen + tok_len
        if len < pos then return nil end
        local rem_len, rem_vlen = M.parse_quic_varint(buf, base + pos, base + len)
        if not rem_len then return nil end
        return pos + rem_vlen + rem_len
    elseif packet_type == 0x01 or packet_type == 0x02 then
        local rem_len, rem_vlen = M.parse_quic_varint(buf, base + pos, base + len)
        if not rem_len then return nil end
        return pos + rem_vlen + rem_len
    else
        return len
    end
end

-- Zero-allocation coalesced QUIC packet inspector.
-- Writes QuicPacketKind ints into `out_kinds` (1-based) and first_byte into `out_bytes`, returns count.
function M.inspect_all_quic_packets(buf, offset, len, out_kinds, out_bytes)
    local count = 0
    local pos = offset
    local rem = len

    while rem > 0 do
        local first_byte = buf[pos]
        if band(first_byte, 0x80) == 0 then
            count = count + 1
            if band(first_byte, 0x40) ~= 0 then
                out_kinds[count] = M.QUIC_SHORT_1RTT
            else
                out_kinds[count] = M.QUIC_UNKNOWN
            end
            if out_bytes then out_bytes[count] = first_byte end
            break
        end

        local pkt_type = rshift(band(first_byte, 0x30), 4)
        local kind
        if     pkt_type == 0x00 then kind = M.QUIC_LONG_INITIAL
        elseif pkt_type == 0x01 then kind = M.QUIC_LONG_0RTT
        elseif pkt_type == 0x02 then kind = M.QUIC_LONG_HANDSHAKE
        elseif pkt_type == 0x03 then kind = M.QUIC_LONG_RETRY
        else                         kind = M.QUIC_LONG_OTHER
        end

        count = count + 1
        out_kinds[count] = kind
        if out_bytes then out_bytes[count] = first_byte end

        local pkt_len = parse_long_header_len(buf, pos, rem, pkt_type)
        if pkt_len and pkt_len > 0 and pkt_len < rem then
            pos = pos + pkt_len
            rem = rem - pkt_len
        else
            break
        end
    end

    if count == 0 then
        count = 1
        out_kinds[1] = M.QUIC_UNKNOWN
        if out_bytes then out_bytes[1] = 0 end
    end
    return count
end

-- Cloudflare WARP IPv4 ranges (AS13335):
-- 162.159.192.0 - 162.159.203.255 & 188.114.96.0 - 188.114.99.255
function M.is_cloudflare_ip_v4(b0, b1, b2)
    if b0 == 162 and b1 == 159 and b2 >= 192 and b2 <= 203 then return true end
    if b0 == 188 and b1 == 114 and b2 >= 96  and b2 <= 99  then return true end
    return false
end

local CF_PORTS = {
    [8095]=true, [8595]=true, [8642]=true, [8742]=true, [8854]=true, [8886]=true, [8943]=true,
    [443]=true,  [500]=true,  [1701]=true, [2408]=true, [4443]=true, [4500]=true, [8443]=true,
    [5200]=true, [5201]=true, [5202]=true, [5203]=true, [5204]=true, [5205]=true,
    [7152]=true, [7156]=true, [7284]=true, [7559]=true, [7815]=true,
    [9034]=true, [9088]=true, [9389]=true, [9408]=true, [9555]=true,
}

function M.is_cloudflare_port(port)
    return CF_PORTS[port] == true
end

-- IPv4 / UDP Checksum helpers (operating on uint8_t*)
function M.calc_ipv4_checksum(buf, ihl)
    local sum = 0
    local i = 0
    while i < ihl do
        if i ~= 10 then
            local hi = buf[i]
            local lo = (i + 1 < ihl) and buf[i + 1] or 0
            sum = sum + bor(lshift(hi, 8), lo)
        end
        i = i + 2
    end
    while rshift(sum, 16) ~= 0 do
        sum = band(sum, 0xFFFF) + rshift(sum, 16)
    end
    return band(bnot(sum), 0xFFFF)
end

function M.calc_udp_checksum_v4(buf, src_off, dst_off, udp_off, udp_len)
    local sum = 0
    sum = sum + bor(lshift(buf[src_off], 8), buf[src_off + 1])
    sum = sum + bor(lshift(buf[src_off + 2], 8), buf[src_off + 3])
    sum = sum + bor(lshift(buf[dst_off], 8), buf[dst_off + 1])
    sum = sum + bor(lshift(buf[dst_off + 2], 8), buf[dst_off + 3])
    sum = sum + 17 + udp_len

    local i = 0
    while i < udp_len do
        if i ~= 6 then
            local hi = buf[udp_off + i]
            local lo = (i + 1 < udp_len) and buf[udp_off + i + 1] or 0
            sum = sum + bor(lshift(hi, 8), lo)
        end
        i = i + 2
    end
    while rshift(sum, 16) ~= 0 do
        sum = band(sum, 0xFFFF) + rshift(sum, 16)
    end
    local res = band(bnot(sum), 0xFFFF)
    return res == 0 and 0xFFFF or res
end

function M.calc_udp_checksum_v6(buf, src_off, dst_off, udp_off, udp_len)
    local sum = 0
    for i = 0, 14, 2 do
        sum = sum + bor(lshift(buf[src_off + i], 8), buf[src_off + i + 1])
        sum = sum + bor(lshift(buf[dst_off + i], 8), buf[dst_off + i + 1])
    end
    sum = sum + rshift(udp_len, 16) + band(udp_len, 0xFFFF) + 17

    local i = 0
    while i < udp_len do
        if i ~= 6 then
            local hi = buf[udp_off + i]
            local lo = (i + 1 < udp_len) and buf[udp_off + i + 1] or 0
            sum = sum + bor(lshift(hi, 8), lo)
        end
        i = i + 2
    end
    while rshift(sum, 16) ~= 0 do
        sum = band(sum, 0xFFFF) + rshift(sum, 16)
    end
    local res = band(bnot(sum), 0xFFFF)
    return res == 0 and 0xFFFF or res
end

-- Build raw IPv4/UDP packet into preallocated `out_buf` (uint8_t*), returns total_len
function M.build_ipv4_udp_packet(out_buf, src_ip, dst_ip, src_port, dst_port, payload, payload_len)
    local ihl = 20
    local udp_len = 8 + payload_len
    local total_len = ihl + udp_len
    out_buf[0] = 0x45; out_buf[1] = 0x00
    put_be16(out_buf, 2, total_len)
    out_buf[4] = 0x12; out_buf[5] = 0x34
    out_buf[6] = 0x40; out_buf[7] = 0x00
    out_buf[8] = 64;   out_buf[9] = 17
    out_buf[10] = 0;   out_buf[11] = 0
    ffi.copy(out_buf + 12, src_ip, 4)
    ffi.copy(out_buf + 16, dst_ip, 4)
    put_be16(out_buf, 10, M.calc_ipv4_checksum(out_buf, ihl))

    put_be16(out_buf, 20, src_port)
    put_be16(out_buf, 22, dst_port)
    put_be16(out_buf, 24, udp_len)
    out_buf[26] = 0; out_buf[27] = 0
    if payload_len > 0 then
        ffi.copy(out_buf + 28, payload, payload_len)
    end
    put_be16(out_buf, 26, M.calc_udp_checksum_v4(out_buf, 12, 16, 20, udp_len))
    return total_len
end

function M.build_ipv6_udp_packet(out_buf, src_ip, dst_ip, src_port, dst_port, payload, payload_len)
    local udp_len = 8 + payload_len
    local total_len = 40 + udp_len
    out_buf[0] = 0x60; out_buf[1] = 0; out_buf[2] = 0; out_buf[3] = 0
    put_be16(out_buf, 4, udp_len)
    out_buf[6] = 17; out_buf[7] = 64
    ffi.copy(out_buf + 8, src_ip, 16)
    ffi.copy(out_buf + 24, dst_ip, 16)

    put_be16(out_buf, 40, src_port)
    put_be16(out_buf, 42, dst_port)
    put_be16(out_buf, 44, udp_len)
    out_buf[46] = 0; out_buf[47] = 0
    if payload_len > 0 then
        ffi.copy(out_buf + 48, payload, payload_len)
    end
    put_be16(out_buf, 46, M.calc_udp_checksum_v6(out_buf, 8, 24, 40, udp_len))
    return total_len
end

-- Parse IPv4/IPv6 + IP string helpers
function M.parse_ipv4_str(s, out_bytes)
    local a, b, c, d = s:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return false end
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    if a > 255 or b > 255 or c > 255 or d > 255 then return false end
    out_bytes[0] = a; out_bytes[1] = b; out_bytes[2] = c; out_bytes[3] = d
    return true
end

function M.format_ipv4(b)
    return string.format("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
end

return M
