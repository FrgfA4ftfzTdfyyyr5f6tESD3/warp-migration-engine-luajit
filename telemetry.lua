-- telemetry.lua: Dual-Perspective Prior-Informed Self-Learning Brain (Code + Network)
-- 1. Domain Priors (LuaJIT Phase Topology + QUIC/Network Priors)
-- 2. Internal Code Learner (5x5 Phase Transition Matrix + Phase Welford + debug.getinfo)
-- 3. External Network Learner (Non-Stationary Welford + Discounted UCB1 Bandit gamma=0.90 + Pre-Stall Warning)
-- 4. Unsupervised Pattern Discovery (DISCOVERED_PATTERN_#) & Code x Network Cross-Correlation

local ffi = require("ffi")
local C = require("common")

local M = {}

local is_win = (ffi.os == "Windows")
local qpc_freq = 0
local qpc_val = ffi.new("int64_t[1]")
local ts_val

if is_win then
    pcall(ffi.cdef, [[
        int QueryPerformanceCounter(int64_t *lpPerformanceCount);
        int QueryPerformanceFrequency(int64_t *lpFrequency);
    ]])
    local f = ffi.new("int64_t[1]")
    if ffi.C.QueryPerformanceFrequency(f) ~= 0 then
        qpc_freq = tonumber(f[0])
    end
else
    pcall(ffi.cdef, [[
        typedef struct { long tv_sec; long tv_nsec; } wme_timespec_t;
        int clock_gettime(int clk_id, wme_timespec_t *tp);
    ]])
    ts_val = ffi.new("wme_timespec_t")
end

function M.now_ms()
    if is_win and qpc_freq > 0 then
        ffi.C.QueryPerformanceCounter(qpc_val)
        return (tonumber(qpc_val[0]) * 1000.0) / qpc_freq
    elseif not is_win and ts_val then
        ffi.C.clock_gettime(1, ts_val)
        return tonumber(ts_val.tv_sec) * 1000.0 + tonumber(ts_val.tv_nsec) / 1e6
    end
    return os.clock() * 1000.0
end

local start_ms = M.now_ms()

-- =========================================================================
-- 1. Domain Priors (Code Topology + Network Priors)
-- =========================================================================
M.PHASE_WARMUP      = 1
M.PHASE_HANDSHAKE   = 2
M.PHASE_MIGRATION   = 3
M.PHASE_DIRECT_1RTT = 4
M.PHASE_AUTO_REARM  = 5

M.PHASE_NAMES = {
    [1] = "WARMUP",
    [2] = "HANDSHAKE",
    [3] = "MIGRATION",
    [4] = "DIRECT_1RTT",
    [5] = "AUTO_REARM",
}

-- Protocol Structural Families (17 fixed protocols preserved untouched)
local PROTO_FAMILY = {
    [1]="junk", [2]="quic", [3]="quic", [4]="rtp", [5]="dtls",
    [6]="dns", [7]="esp", [8]="utp", [9]="raknet", [10]="stun",
    [11]="stun", [12]="steam", [13]="esp", [14]="esp", [15]="rtp",
    [16]="esp", [17]="rtp",
}

-- Boot Self-Anatomy & End-to-End Digital Twin (Synced with common.lua + server.lua Contract)
M.E2E_SYSTEM_MODEL = {
    client_pipeline    = { "WinDivert_FFI", "QUIC_Dissector", "Mask(1..17)", "BiDi_1RTT_Grace", "AuxGuard" },
    server_contract    = {
        outbound_env_v4 = C.OUTBOUND_PREPEND_LEN_V4,
        outbound_env_v6 = C.OUTBOUND_PREPEND_LEN_V6,
        inbound_camo    = C.INBOUND_STRIP_LEN,
        session_ttl_s   = C.RELAY_SESSION_TTL_S,
        min_proto_id    = 1,
        max_proto_id    = #C.PROTOCOLS,
        safe_stall_min  = 2200,
        safe_stall_max  = 6000,
        safe_pacing_max = 50,
    },
}

M.self_identity = {
    mission      = "Maximize Direct MASQUE 1-RTT RX | Zero Stall | Preserve 17 Fixed Protocols",
    jit_version  = jit and jit.version or "Lua",
    jit_enabled  = jit and jit.status and (jit.status() == true) or false,
    boot_mem_kb  = collectgarbage("count"),
    modules      = { "common.lua", "client.lua", "telemetry.lua", "server.lua" },
    fixed_protos = #C.PROTOCOLS,
}

-- Circadian Time Bucket (0=night, 1=morning, 2=afternoon, 3=evening)
function M.get_time_bucket()
    local h = tonumber(os.date("%H")) or 12
    if h < 6 then return "night"
    elseif h < 12 then return "morning"
    elseif h < 18 then return "afternoon"
    else return "evening"
    end
end

-- =========================================================================
-- 2. Welford Online Statistical Baseline (O(1) memory, Zero-Alloc)
-- =========================================================================
local function welford_new()
    return { n = 0, mean = 0.0, m2 = 0.0 }
end

local function welford_update(w, x)
    w.n = w.n + 1
    local delta = x - w.mean
    w.mean = w.mean + delta / w.n
    local delta2 = x - w.mean
    w.m2 = w.m2 + delta * delta2
end

local function welford_std(w)
    if w.n < 2 then return 0.0 end
    local v = w.m2 / (w.n - 1)
    return v > 0 and math.sqrt(v) or 0.0
end

local function welford_zscore(w, x)
    if w.n < 3 then return 0.0 end
    local s = welford_std(w)
    if s < 1e-6 then return 0.0 end
    return (x - w.mean) / s
end

M.welford_new    = welford_new
M.welford_update = welford_update
M.welford_zscore = welford_zscore

local w_mig_ms      = welford_new()
local w_rx_tx_ratio = welford_new()
local w_large_ratio = welford_new()
local w_jitter_ms   = welford_new()

-- =========================================================================
-- 3. Internal Code Learner (5x5 Transition Matrix + Loop & JIT Introspection)
-- =========================================================================
local trans_matrix = {}
for i = 1, 5 do
    trans_matrix[i] = { 0, 0, 0, 0, 0 }
end
local current_phase = M.PHASE_WARMUP
local mig_to_rearm_loops = 0
local pre_stall_streak = 0

function M.enter_phase(next_phase)
    if next_phase ~= current_phase then
        trans_matrix[current_phase][next_phase] = trans_matrix[current_phase][next_phase] + 1
        if current_phase == M.PHASE_MIGRATION and next_phase == M.PHASE_AUTO_REARM then
            mig_to_rearm_loops = mig_to_rearm_loops + 1
        elseif next_phase == M.PHASE_DIRECT_1RTT then
            mig_to_rearm_loops = 0
        end
        current_phase = next_phase
    end
end

local function get_lua_loc()
    local info = debug and debug.getinfo and debug.getinfo(3, "nSl")
    if not info then return "unknown" end
    return string.format("%s:%d", info.name or "loop", info.currentline or 0)
end

-- =========================================================================
-- 4. 1-Second Feature Window & Pre-Stall Early Warning (Zero-Alloc)
-- =========================================================================
local win_start_ms   = start_ms
local win_tx_pkts    = 0
local win_rx_pkts    = 0
local win_tx_bytes   = 0
local win_rx_bytes   = 0
local win_large_ok   = 0
local win_large_tot  = 0
local win_jitter_sum = 0
local win_jitter_cnt = 0
local last_rx_pkt_ms = 0
local last_features  = { rx_tx = 1.0, large_ratio = 1.0, jitter = 0.0, tx_kbps = 0.0, rx_kbps = 0.0 }

function M.observe_tx_pkt(size)
    win_tx_pkts  = win_tx_pkts + 1
    win_tx_bytes = win_tx_bytes + size
    if size >= 1000 then win_large_tot = win_large_tot + 1 end
end

function M.observe_rx_pkt(size)
    local now = M.now_ms()
    win_rx_pkts  = win_rx_pkts + 1
    win_rx_bytes = win_rx_bytes + size
    if size >= 1000 then win_large_ok = win_large_ok + 1 end
    if last_rx_pkt_ms > 0 then
        local dt = now - last_rx_pkt_ms
        if dt < 2000 then
            win_jitter_sum = win_jitter_sum + dt
            win_jitter_cnt = win_jitter_cnt + 1
        end
    end
    last_rx_pkt_ms = now

    if now - win_start_ms >= 1000 then
        local dt_s = (now - win_start_ms) / 1000.0
        local rx_tx = win_tx_pkts > 0 and (win_rx_pkts / win_tx_pkts) or 1.0
        local l_rat = win_large_tot > 0 and math.min(1.0, win_large_ok / win_large_tot) or 1.0
        local jit   = win_jitter_cnt > 0 and (win_jitter_sum / win_jitter_cnt) or 0.0

        local z_drop = welford_zscore(w_rx_tx_ratio, rx_tx)
        if z_drop < -2.2 and win_tx_pkts >= 5 then
            pre_stall_streak = pre_stall_streak + 1
            if pre_stall_streak == 2 then
                M.record("pre_stall_warning", 0, 0, string.format("PRE_STALL_WARNING z_rxtx=%.2f", z_drop))
            end
        else
            pre_stall_streak = 0
        end

        welford_update(w_rx_tx_ratio, rx_tx)
        welford_update(w_large_ratio, l_rat)
        if win_jitter_cnt > 0 then welford_update(w_jitter_ms, jit) end

        last_features.rx_tx       = rx_tx
        last_features.large_ratio = l_rat
        last_features.jitter      = jit
        last_features.tx_kbps     = win_tx_bytes / 1024.0 / dt_s
        last_features.rx_kbps     = win_rx_bytes / 1024.0 / dt_s

        win_start_ms = now
        win_tx_pkts = 0; win_rx_pkts = 0; win_tx_bytes = 0; win_rx_bytes = 0
        win_large_ok = 0; win_large_tot = 0; win_jitter_sum = 0; win_jitter_cnt = 0
    end
end

function M.get_dynamic_stall_ms()
    if w_jitter_ms.n < 5 then return 3000 end
    local dyn = w_jitter_ms.mean * 12.0 + 2000.0
    if dyn < 2200 then return 2200 end
    if dyn > 5500 then return 5500 end
    return dyn
end

-- =========================================================================
-- 5. Unsupervised Pattern Discovery & Code x Network Cross-Correlation
-- =========================================================================
local discovered_patterns = {} -- { id, z_rxtx, z_large, z_jit, hits, domain, phase }

function M.attribute_and_discover()
    local z_rxtx  = welford_zscore(w_rx_tx_ratio, last_features.rx_tx)
    local z_large = welford_zscore(w_large_ratio, last_features.large_ratio)
    local z_jit   = welford_zscore(w_jitter_ms, last_features.jitter)

    local cause = "GENERAL_STALL"
    local max_abs = 1.5
    if z_large < -max_abs and math.abs(z_large) >= math.abs(z_rxtx) then
        cause = string.format("SIZE_THROTTLING(z=%.2f)", z_large)
    elseif z_rxtx < -max_abs then
        cause = string.format("RX_BLACKHOLE(z=%.2f)", z_rxtx)
    elseif z_jit > max_abs then
        cause = string.format("JITTER_SPIKE(z=%.2f)", z_jit)
    end

    local net_dev = math.sqrt(z_rxtx * z_rxtx + z_large * z_large + z_jit * z_jit)
    local domain = "NETWORK_ANOMALY"
    if mig_to_rearm_loops >= 3 and net_dev < 1.5 then
        domain = string.format("CODE_LOGIC_ANOMALY(phase=%s, loc=%s)", M.PHASE_NAMES[current_phase] or "?", get_lua_loc())
    end

    -- Discover new multivariate pattern if z-vector deviates > 2.2
    local pat_tag = nil
    if net_dev >= 2.2 then
        local matched = false
        for i = 1, #discovered_patterns do
            local p = discovered_patterns[i]
            local d = math.sqrt((p.z_rxtx - z_rxtx)^2 + (p.z_large - z_large)^2 + (p.z_jit - z_jit)^2)
            if d < 1.2 then
                p.hits = p.hits + 1
                pat_tag = p.id
                matched = true
                break
            end
        end
        if not matched and #discovered_patterns < 32 then
            local id = string.format("DISCOVERED_PATTERN_%02d", #discovered_patterns + 1)
            discovered_patterns[#discovered_patterns + 1] = {
                id = id, z_rxtx = z_rxtx, z_large = z_large, z_jit = z_jit,
                hits = 1, domain = domain, phase = M.PHASE_NAMES[current_phase] or "?",
            }
            pat_tag = id
        end
    end

    return cause, domain, pat_tag
end

-- =========================================================================
-- 6. 200-Packet Ring-Buffer & LuaJIT Trace Profiler
-- =========================================================================
local RING_CAP = 200
local ring = {}
for i = 1, RING_CAP do
    ring[i] = { t_ms = 0, dir = 0, port = 0, size = 0, qkind = 0, state = 0 }
end
local ring_head = 0
local ring_total = 0

function M.ring_push(dir, port, size, qkind, state)
    ring_head = (ring_head % RING_CAP) + 1
    ring_total = ring_total + 1
    local slot = ring[ring_head]
    slot.t_ms  = M.now_ms() - start_ms
    slot.dir   = dir
    slot.port  = port
    slot.size  = size
    slot.qkind = qkind
    slot.state = state
end

M.jit_stats = { traces_compiled = 0, traces_aborted = 0, last_abort_why = "" }

if jit and jit.attach then
    pcall(jit.attach, function(what, tr, func, pc, otr, oex)
        if what == "stop" then
            M.jit_stats.traces_compiled = M.jit_stats.traces_compiled + 1
        elseif what == "abort" then
            M.jit_stats.traces_aborted = M.jit_stats.traces_aborted + 1
            M.jit_stats.last_abort_why = tostring(oex or "unknown")
        end
    end, "trace")
end

-- =========================================================================
-- 7. Per-Endpoint Reputation & Regime Change Detector
-- =========================================================================
local endpoint_stats = {}
local port_cooldowns = {} -- dst_port -> { stalls, cooldown_until }
local stall_ring = { 0, 0, 0, 0 }
local stall_ring_idx = 0
local regime_changes = 0

local function ensure_ep(ep)
    if not endpoint_stats[ep] then
        endpoint_stats[ep] = { migrations = 0, stalls = 0, rx_pkts = 0, cooldown_until = 0 }
    end
    return endpoint_stats[ep]
end

function M.ep_mark_migrated(ep)
    if ep and ep ~= "" then ensure_ep(ep).migrations = ensure_ep(ep).migrations + 1 end
end

function M.ep_mark_rx(ep, port)
    if ep and ep ~= "" then
        local e = ensure_ep(ep)
        e.rx_pkts = e.rx_pkts + 1
        e.cooldown_until = 0
    end
    if port and port_cooldowns[port] then
        port_cooldowns[port].cooldown_until = 0
        port_cooldowns[port].stalls = 0
    end
end

function M.ep_mark_stalled(ep, cooldown_ms, port)
    local now = M.now_ms()
    if ep and ep ~= "" then
        local e = ensure_ep(ep)
        e.stalls = e.stalls + 1
        e.cooldown_until = now + (cooldown_ms or 60000)
    end
    if port and port > 0 then
        local p = port_cooldowns[port]
        if not p then p = { stalls = 0, cooldown_until = 0 }; port_cooldowns[port] = p end
        p.stalls = p.stalls + 1
        if p.stalls >= 2 then
            p.cooldown_until = now + 120000
            return true
        end
    end
    return false
end

function M.ep_is_cooled_down(ep, port)
    local now = M.now_ms()
    local e = endpoint_stats[ep]
    if e and e.cooldown_until > 0 then
        if now >= e.cooldown_until then e.cooldown_until = 0 else return true end
    end
    if port then
        local p = port_cooldowns[port]
        if p and p.cooldown_until > 0 then
            if now >= p.cooldown_until then p.cooldown_until = 0; p.stalls = 0 else return true end
        end
    end
    return false
end

function M.check_regime_change()
    local now = M.now_ms()
    stall_ring_idx = (stall_ring_idx % 4) + 1
    stall_ring[stall_ring_idx] = now
    local recent = 0
    for i = 1, 4 do
        if stall_ring[i] > 0 and (now - stall_ring[i]) <= 30000 then
            recent = recent + 1
        end
    end
    if recent >= 2 then
        regime_changes = regime_changes + 1
        return true
    end
    return false
end

-- =========================================================================
-- 8. Discounted Contextual Bandit (gamma = 0.90) & Persistent Brain State
-- =========================================================================
local GAMMA = 0.90
local MAX_EVENTS = 512
local events = {}
local event_count = 0
local proto_stats = {}
local anomalies = {}
local total_bandit_pulls = 0.0

M.live = {
    direct_tx_pkts  = 0,
    direct_rx_pkts  = 0,
    direct_tx_bytes = 0,
    direct_rx_bytes = 0,
    stall_count     = 0,
    active_endpoint = "",
}

M.session_meta = {
    engine_mode     = "masque",
    relay_endpoint  = "",
    target_endpoint = "",
    warp_auto_setup = false,
    warp_mode       = "manual",
    migration_rule  = "BiDi-1RTT (4rx+10tx >=1.2s) / 3.5s Cap",
}

local log_file = nil

function M.init_session_log(filepath)
    filepath = filepath or "wme_session.log"
    if log_file then pcall(function() log_file:close() end) end
    log_file = io.open(filepath, "w")
    if log_file then
        log_file:write(string.format("=== Warp Migration Engine Session Log (%s) ===\n", os.date("%Y-%m-%d %H:%M:%S")))
        log_file:flush()
    end
    return log_file ~= nil
end

function M.log_line(line)
    print(line)
    io.flush()
    if log_file then
        log_file:write(line .. "\n")
        log_file:flush()
    end
end

function M.close_session_log()
    if log_file then
        pcall(function()
            log_file:write(string.format("=== Session Closed (%s) ===\n", os.date("%Y-%m-%d %H:%M:%S")))
            log_file:close()
        end)
        log_file = nil
    end
end

local function ensure_proto(pid)
    if not proto_stats[pid] then
        proto_stats[pid] = {
            attempts = 0, migrated = 0, primary_trig = 0, backup_trig = 0,
            drops = 0, stalls = 0, sum_ms = 0, inbound_pkts = 0,
            pulls = 0.0, reward_sum = 0.0,
        }
    end
    return proto_stats[pid]
end

local BRAIN_FILE = "brain_state.json"

function M.load_mask_memory()
    local f = io.open(BRAIN_FILE, "r")
    if not f then return end
    local content = f:read("*a"); f:close()
    for pid_s, mig_s, sum_s, st_s, pul_s, rew_s in content:gmatch(
        '"(%d+)"%s*:%s*{[^}]*"migrated"%s*:%s*(%d+)[^}]*"sum_ms"%s*:%s*([%d%.]+)[^}]*"stalls"%s*:%s*(%d+)[^}]*"pulls"%s*:%s*([%d%.]+)[^}]*"reward_sum"%s*:%s*([%d%.]+)'
    ) do
        local pid = tonumber(pid_s)
        local s = ensure_proto(pid)
        s.migrated   = tonumber(mig_s) or 0
        s.sum_ms     = tonumber(sum_s) or 0
        s.stalls     = tonumber(st_s) or 0
        s.pulls      = tonumber(pul_s) or 0.0
        s.reward_sum = tonumber(rew_s) or 0.0
        s.attempts   = s.migrated
        total_bandit_pulls = total_bandit_pulls + s.pulls
    end
end

function M.save_mask_memory()
    local f = io.open(BRAIN_FILE, "w")
    if not f then return end
    f:write("{\n")
    local first = true
    for pid, s in pairs(proto_stats) do
        if not first then f:write(",\n") end
        first = false
        f:write(string.format(
            '  "%d": {"migrated": %d, "sum_ms": %.2f, "stalls": %d, "pulls": %.3f, "reward_sum": %.4f}',
            pid, s.migrated, s.sum_ms, s.stalls, s.pulls, s.reward_sum
        ))
    end
    f:write("\n}\n")
    f:close()
end

-- Discounted Bandit Reward (gamma = 0.90 forgets stale DPI rules in 2-3 cycles)
local ctx_rewards = {} -- "bucket:pid" -> { pulls, reward_sum }

function M.bandit_reward(pid, reward_val)
    local s = ensure_proto(pid)
    local r = math.max(0.0, math.min(1.0, reward_val))
    s.pulls      = s.pulls * GAMMA + 1.0
    s.reward_sum = s.reward_sum * GAMMA + r
    total_bandit_pulls = total_bandit_pulls * GAMMA + 1.0

    local ck = M.get_time_bucket() .. ":" .. pid
    if not ctx_rewards[ck] then ctx_rewards[ck] = { pulls = 0.0, reward_sum = 0.0 } end
    ctx_rewards[ck].pulls      = ctx_rewards[ck].pulls * GAMMA + 1.0
    ctx_rewards[ck].reward_sum = ctx_rewards[ck].reward_sum * GAMMA + r
end

-- Hysteresis + Circadian Context UCB1 Selection (15% switching cost guard)
function M.pick_smart_mask(pool, exclude_id, current_healthy_id)
    local best_id, best_ucb = nil, -1
    local ln_total = math.log(math.max(1.0, total_bandit_pulls) + 1.0)
    local ex_fam = exclude_id and PROTO_FAMILY[exclude_id] or nil
    local bucket = M.get_time_bucket()
    local cur_ucb = -1

    for i = 1, #pool do
        local pid = pool[i]
        if pid ~= exclude_id then
            local s = proto_stats[pid]
            local c = ctx_rewards[bucket .. ":" .. pid]
            local ucb
            if not s or s.pulls < 0.5 then
                ucb = 2.0
            else
                local avg_r = s.reward_sum / s.pulls
                if c and c.pulls >= 1.0 then
                    avg_r = 0.6 * (c.reward_sum / c.pulls) + 0.4 * avg_r
                end
                ucb = avg_r + 0.45 * math.sqrt(ln_total / s.pulls)
            end
            if ex_fam and PROTO_FAMILY[pid] ~= ex_fam then
                ucb = ucb + 0.35
            end
            if pid == current_healthy_id then cur_ucb = ucb end
            if ucb > best_ucb then
                best_ucb = ucb
                best_id = pid
            end
        end
    end
    -- Hysteresis: keep current_healthy_id unless challenger beats it by >= 15%
    if current_healthy_id and current_healthy_id ~= exclude_id and cur_ucb > 0 and best_ucb < cur_ucb * 1.15 then
        return current_healthy_id
    end
    return best_id or pool[1] or 7
end

-- =========================================================================
-- 9. Contract-Verified LuaJIT Policy Synthesizer (evolved_policy.lua)
-- =========================================================================
local EVOLVED_FILE = "evolved_policy.lua"
local SAFE_ENV = {} -- Strictly isolated sandbox: no os, io, ffi, debug, loadstring
local active_policy_fn = nil
local prev_policy_fn   = nil
local active_policy_src = nil
local prev_policy_src   = nil
local policy_stalls     = 0
local policy_rollbacks  = 0

local VALID_ACTIONS = { DIVERSE_SWITCH = true, HOLD = true, REARM_SESSION = true }

function M.validate_policy_code(code_str)
    if type(code_str) ~= "string" or #code_str > 1024 then
        return nil, "invalid_length"
    end
    -- Forbid OS/IO/FFI/loops/metatable escapes
    local lower = code_str:lower()
    for _, bad in ipairs({ "os%.", "io%.", "ffi", "debug", "loadstring", "while%s", "repeat%s", "for%s", "require" }) do
        if lower:match(bad) then
            return nil, "forbidden_token:" .. bad
        end
    end
    local fn, err = loadstring(code_str, "evolved_policy")
    if not fn then return nil, "syntax:" .. tostring(err) end
    setfenv(fn, SAFE_ENV)
    local ok, policy = pcall(fn)
    if not ok or type(policy) ~= "function" then
        return nil, "init_failed"
    end
    setfenv(policy, SAFE_ENV)

    -- Pre-Flight Digital Twin Simulation against Server Contract
    local sc = M.E2E_SYSTEM_MODEL.server_contract
    local test_cases = {
        { jitter_ms = 20,  rx_tx_ratio = 1.0, large_pkt_ratio = 0.9, stall_ms = 3000 },
        { jitter_ms = 250, rx_tx_ratio = 0.2, large_pkt_ratio = 0.1, stall_ms = 3000 },
    }
    for _, tc in ipairs(test_cases) do
        local pok, res = pcall(policy, tc)
        if not pok then return nil, "runtime_err" end
        if res ~= nil then
            if type(res) ~= "table" then return nil, "bad_return_type" end
            if res.action and not VALID_ACTIONS[res.action] then return nil, "invalid_action" end
            if res.stall_ms and (res.stall_ms < sc.safe_stall_min or res.stall_ms > sc.safe_stall_max) then
                return nil, "contract_stall_bounds"
            end
            if res.pacing_ms and (res.pacing_ms < 0 or res.pacing_ms > sc.safe_pacing_max) then
                return nil, "contract_pacing_bounds"
            end
        end
    end
    return policy, nil
end

function M.activate_evolved_policy(code_str, save_disk)
    local policy, err = M.validate_policy_code(code_str)
    if not policy then
        M.record("policy_rejected", 0, 0, tostring(err))
        return false, err
    end
    prev_policy_fn  = active_policy_fn
    prev_policy_src = active_policy_src
    active_policy_fn  = policy
    active_policy_src = code_str
    policy_stalls = 0
    if save_disk then
        local f = io.open(EVOLVED_FILE, "w")
        if f then f:write(code_str); f:close() end
    end
    M.record("policy_activated", 0, 0, "Contract-verified LuaJIT policy hot-swapped")
    return true, nil
end

function M.load_evolved_policy()
    local f = io.open(EVOLVED_FILE, "r")
    if not f then return false end
    local s = f:read("*a"); f:close()
    return M.activate_evolved_policy(s, false)
end

function M.rollback_evolved_policy()
    if not active_policy_fn then return false end
    active_policy_fn  = prev_policy_fn
    active_policy_src = prev_policy_src
    prev_policy_fn    = nil
    prev_policy_src   = nil
    policy_rollbacks  = policy_rollbacks + 1
    policy_stalls     = 0
    os.remove(EVOLVED_FILE)
    M.record("policy_rollback", 0, 0, "Auto-Rollback triggered (<1ms)")
    return true
end

function M.synthesize_policy_from_features()
    if active_policy_fn then return false, "already_active" end
    local jit_thr = math.max(80, math.floor((w_jitter_ms.mean > 0 and w_jitter_ms.mean or 80) * 1.8))
    local dyn_st  = math.max(2200, math.min(5500, math.floor(M.get_dynamic_stall_ms() * 0.85)))
    local code = string.format(
        "return function(ctx)\n" ..
        "  if ctx.jitter_ms > %d and ctx.large_pkt_ratio < 0.35 then\n" ..
        "    return { action = 'DIVERSE_SWITCH', stall_ms = %d }\n" ..
        "  end\n" ..
        "  return nil\n" ..
        "end\n", jit_thr, dyn_st
    )
    return M.activate_evolved_policy(code, true)
end

local eval_ctx = { jitter_ms = 0, rx_tx_ratio = 1, large_pkt_ratio = 1, stall_ms = 3000 }
function M.eval_evolved_policy()
    if not active_policy_fn then return nil end
    eval_ctx.jitter_ms       = last_features.jitter
    eval_ctx.rx_tx_ratio     = last_features.rx_tx
    eval_ctx.large_pkt_ratio = last_features.large_ratio
    eval_ctx.stall_ms        = M.get_dynamic_stall_ms()
    local ok, res = pcall(active_policy_fn, eval_ctx)
    if not ok then
        M.rollback_evolved_policy()
        return nil
    end
    return res
end

function M.on_policy_stall()
    if active_policy_fn then
        policy_stalls = policy_stalls + 1
        if policy_stalls >= 2 then
            return M.rollback_evolved_policy()
        end
    end
    return false
end

function M.get_policy_stats()
    return active_policy_fn ~= nil, policy_rollbacks
end

function M.record(kind, port, proto_id, detail, extra_ms)
    if event_count >= MAX_EVENTS then
        table.remove(events, 1)
    else
        event_count = event_count + 1
    end
    local t_ms = M.now_ms() - start_ms
    events[event_count] = {
        t_ms     = math.floor(t_ms * 100 + 0.5) / 100,
        kind     = kind,
        port     = port or 0,
        proto_id = proto_id or 0,
        detail   = detail or "",
        delta_ms = extra_ms and (math.floor(extra_ms * 100 + 0.5) / 100) or nil,
    }
    if kind == "quic_coalesced" and proto_id and proto_id > 0 then
        ensure_proto(proto_id).inbound_pkts = ensure_proto(proto_id).inbound_pkts + 1
    end
end

function M.stat_attempt(proto_id)
    ensure_proto(proto_id).attempts = ensure_proto(proto_id).attempts + 1
end

function M.stat_migrated(proto_id, elapsed_ms, is_primary)
    local s = ensure_proto(proto_id)
    s.migrated = s.migrated + 1
    if is_primary then s.primary_trig = s.primary_trig + 1 else s.backup_trig = s.backup_trig + 1 end
    if elapsed_ms then
        s.sum_ms = s.sum_ms + elapsed_ms
        local z_mig = welford_zscore(w_mig_ms, elapsed_ms)
        welford_update(w_mig_ms, elapsed_ms)
        if z_mig > 2.5 then
            M.record("zscore_latency", 0, proto_id, string.format("LATENCY_DRIFT z=%.2f (%.1fms vs mean %.1fms)", z_mig, elapsed_ms, w_mig_ms.mean))
        end
        local speed_r = math.max(0.1, math.min(1.0, 1.0 - (elapsed_ms / 5000.0)))
        M.bandit_reward(proto_id, speed_r * (is_primary and 1.0 or 0.7))
    end
end

function M.stat_drop(proto_id)
    ensure_proto(proto_id).drops = ensure_proto(proto_id).drops + 1
end

function M.stat_stall(proto_id)
    M.live.stall_count = M.live.stall_count + 1
    if proto_id and proto_id > 0 then
        ensure_proto(proto_id).stalls = ensure_proto(proto_id).stalls + 1
        M.bandit_reward(proto_id, 0.0)
    end
end

function M.generate_upgrade_blueprint()
    local bp = {}
    if M.jit_stats.traces_aborted > 15 then
        bp[#bp + 1] = {
            target_file     = "client.lua",
            target_func     = "run_masque_engine",
            observed_cause  = string.format("LuaJIT aborted %d traces (last: %s)", M.jit_stats.traces_aborted, M.jit_stats.last_abort_why),
            proposed_change = "Isolate cold string formatting from hot packet loop to reduce trace aborts.",
        }
    end
    if mig_to_rearm_loops >= 2 then
        bp[#bp + 1] = {
            target_file     = "client.lua",
            target_func     = "handle_stall_heal",
            observed_cause  = string.format("%d consecutive MIGRATION->AUTO_REARM loops without 1-RTT RX", mig_to_rearm_loops),
            proposed_change = "Increase Lead-In spacing or rotate to a different Cloudflare port/subnet.",
        }
    end
    local total_back = 0
    for _, s in pairs(proto_stats) do total_back = total_back + s.backup_trig end
    if total_back > 0 then
        bp[#bp + 1] = {
            target_file     = "client.lua",
            target_func     = "run_masque_engine (inbound)",
            observed_cause  = string.format("Backup 20-packet trigger fired %dx instead of Primary 2nd Handshake", total_back),
            proposed_change = "Inspect coalesced Server Handshake frames in ring_buffer to tune primary trigger.",
        }
    end
    if #discovered_patterns > 0 then
        bp[#bp + 1] = {
            target_file     = "telemetry.lua",
            target_func     = "attribute_and_discover",
            observed_cause  = string.format("Discovered %d novel multivariate anomaly signature(s)", #discovered_patterns),
            proposed_change = "Review discovered_patterns in ai_report.json and add targeted pre-stall mitigation.",
        }
    end
    if #bp == 0 then
        bp[#bp + 1] = {
            target_file     = "none",
            target_func     = "all",
            observed_cause  = "Zero code bottlenecks, zero loops, optimal JIT compilation",
            proposed_change = "No code changes required; current strategy is operating at peak efficiency.",
        }
    end
    return bp
end

function M.analyze_anomalies()
    anomalies = {}
    local total_mig, total_prim, total_back, total_drops = 0, 0, 0, 0
    local sum_ms = 0
    local best_id, best_score = nil, -1

    for pid, s in pairs(proto_stats) do
        total_mig   = total_mig + s.migrated
        total_prim  = total_prim + s.primary_trig
        total_back  = total_back + s.backup_trig
        total_drops = total_drops + s.drops
        sum_ms      = sum_ms + s.sum_ms

        local avg_r = s.pulls > 0 and (s.reward_sum / s.pulls) or 0
        if s.migrated > 0 and avg_r > best_score then
            best_score = avg_r
            best_id = pid
        end

        local pkey = C.get_protocol_by_id(pid).key
        if s.attempts > 0 and s.inbound_pkts == 0 and s.migrated == 0 then
            anomalies[#anomalies + 1] = string.format("[DPI_ALERT] Proto %d (%s) had 0 server responses.", pid, pkey)
        end
        if s.backup_trig > 0 then
            anomalies[#anomalies + 1] = string.format("[BOTTLENECK] Proto %d (%s) used Backup 20-Pkt trigger %dx.", pid, pkey, s.backup_trig)
        end
        if s.stalls > 0 then
            local cause, domain, pat = M.attribute_and_discover()
            local extra = pat and (" | " .. pat) or ""
            anomalies[#anomalies + 1] = string.format("[%s] Proto %d (%s) stalled %dx (%s%s).", domain, pid, pkey, s.stalls, cause, extra)
        end
    end

    if regime_changes > 0 then
        anomalies[#anomalies + 1] = string.format("[REGIME_CHANGE] Detected %d multi-path degradation burst(s) in <30s.", regime_changes)
    end

    local overall_avg = total_mig > 0 and (sum_ms / total_mig) or 0
    local health_score = 100
    if total_mig > 0 then
        local prim_rate = total_prim / total_mig
        local stall_pen = math.min(25, M.live.stall_count * 8)
        local lat_pts   = math.max(0, 25 - (overall_avg / 150))
        local rx_bonus  = (M.live.direct_rx_pkts >= 50) and math.min(25, math.floor(M.live.direct_rx_pkts / 40)) or 0
        health_score = math.max(0, math.min(100, math.floor(50 + prim_rate * 25 + lat_pts - stall_pen + rx_bonus)))
    end

    return {
        health_score     = health_score,
        recommended_mask = best_id or 7,
        avg_migration_ms = math.floor(overall_avg * 100 + 0.5) / 100,
        primary_triggers = total_prim,
        backup_triggers  = total_back,
        total_drops      = total_drops,
        anomalies        = anomalies,
    }
end

function M.print_diagnostic_summary()
    local a = M.analyze_anomalies()
    local mem_kb = collectgarbage("count")
    local lines = {
        "\n---------------- DUAL-PERSPECTIVE AI BRAIN SUMMARY -------------",
        string.format("  Health Score     : %d / 100 | Avg Mig: %.1f ms (Welford: %.1f ms)",
            a.health_score, a.avg_migration_ms, w_mig_ms.mean),
        string.format("  Code Phases      : Current=%s | Mig->ReArm Loops=%d",
            M.PHASE_NAMES[current_phase] or "?", mig_to_rearm_loops),
        string.format("  Triggers         : Primary=%d | Backup=%d | Stalls=%d | Drops=%d",
            a.primary_triggers, a.backup_triggers, M.live.stall_count, a.total_drops),
        string.format("  Direct 1-RTT     : TX=%d pkts (%.1f KB) | RX=%d pkts (%.1f KB)",
            M.live.direct_tx_pkts, M.live.direct_tx_bytes / 1024,
            M.live.direct_rx_pkts, M.live.direct_rx_bytes / 1024),
        string.format("  Welford Baseline : RX/TX=%.2f | LargePkt=%.2f | Jitter=%.1fms | DynStall=%.0fms",
            w_rx_tx_ratio.mean, w_large_ratio.mean, w_jitter_ms.mean, M.get_dynamic_stall_ms()),
        string.format("  LuaJIT Engine    : Mem=%.1f KB | Traces=%d Compiled / %d Aborted",
            mem_kb, M.jit_stats.traces_compiled, M.jit_stats.traces_aborted),
        string.format("  Discovered Pats  : %d | UCB1 Best Mask: %d (%s) | Endpoint: %s",
            #discovered_patterns, a.recommended_mask, PROTO_FAMILY[a.recommended_mask] or "esp",
            M.live.active_endpoint ~= "" and M.live.active_endpoint or "N/A"),
    }
    if #a.anomalies == 0 then
        lines[#lines + 1] = "  Anomalies        : None detected (Optimal baseline)"
    else
        for i = 1, #a.anomalies do
            lines[#lines + 1] = "  ! " .. a.anomalies[i]
        end
    end
    local bp = M.generate_upgrade_blueprint()
    if bp[1] and bp[1].target_file ~= "none" then
        lines[#lines + 1] = string.format("  Upgrade Hint     : [%s:%s] %s", bp[1].target_file, bp[1].target_func, bp[1].proposed_change)
    end
    lines[#lines + 1] = "----------------------------------------------------------------"
    local block = table.concat(lines, "\n")
    M.log_line(block)
end

local function json_escape(str)
    return (str:gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n'):gsub('\r', '\\r'))
end

function M.flush_json(filepath)
    filepath = filepath or "ai_report.json"
    local f = io.open(filepath, "w")
    if not f then return false end

    local audit = M.analyze_anomalies()
    local mem_kb = collectgarbage("count")
    M.save_mask_memory()

    f:write("{\n")
    f:write(string.format('  "uptime_ms": %.2f,\n', M.now_ms() - start_ms))
    f:write(string.format('  "event_count": %d,\n', event_count))

    f:write('  "session_meta": {\n')
    f:write(string.format(
        '    "engine_mode": "%s", "relay_endpoint": "%s", "target_endpoint": "%s", "warp_auto_setup": %s, "warp_mode": "%s", "migration_rule": "%s"\n',
        json_escape(M.session_meta.engine_mode), json_escape(M.session_meta.relay_endpoint),
        json_escape(M.session_meta.target_endpoint), tostring(M.session_meta.warp_auto_setup),
        json_escape(M.session_meta.warp_mode), json_escape(M.session_meta.migration_rule)
    ))
    f:write("  },\n")

    f:write('  "self_identity": {\n')
    f:write(string.format('    "mission": "%s", "jit_version": "%s", "jit_enabled": %s, "boot_mem_kb": %.2f, "fixed_protos": %d\n',
        json_escape(M.self_identity.mission), json_escape(M.self_identity.jit_version),
        tostring(M.self_identity.jit_enabled), M.self_identity.boot_mem_kb, M.self_identity.fixed_protos))
    f:write("  },\n")

    f:write('  "autonomous_upgrade_blueprint": [\n')
    local bp = M.generate_upgrade_blueprint()
    for i = 1, #bp do
        local item = bp[i]
        f:write(string.format(
            '    {"target_file": "%s", "target_func": "%s", "observed_cause": "%s", "proposed_change": "%s"}%s\n',
            json_escape(item.target_file), json_escape(item.target_func),
            json_escape(item.observed_cause), json_escape(item.proposed_change),
            i < #bp and "," or ""
        ))
    end
    f:write("  ],\n")

    f:write('  "welford_baseline": {\n')
    f:write(string.format('    "mig_mean_ms": %.2f, "mig_std_ms": %.2f,\n', w_mig_ms.mean, welford_std(w_mig_ms)))
    f:write(string.format('    "rx_tx_mean": %.3f, "large_pkt_ratio": %.3f, "jitter_mean_ms": %.2f,\n', w_rx_tx_ratio.mean, w_large_ratio.mean, w_jitter_ms.mean))
    f:write(string.format('    "dynamic_stall_ms": %.0f, "regime_changes": %d\n', M.get_dynamic_stall_ms(), regime_changes))
    f:write("  },\n")

    f:write('  "code_health": {\n')
    f:write(string.format('    "current_phase": "%s", "mig_to_rearm_loops": %d,\n', M.PHASE_NAMES[current_phase] or "?", mig_to_rearm_loops))
    f:write(string.format('    "lua_mem_kb": %.2f, "traces_compiled": %d, "traces_aborted": %d, "last_abort": "%s",\n',
        mem_kb, M.jit_stats.traces_compiled, M.jit_stats.traces_aborted, json_escape(M.jit_stats.last_abort_why)))
    f:write('    "transition_matrix": [')
    for i = 1, 5 do
        f:write(string.format("[%d,%d,%d,%d,%d]%s", trans_matrix[i][1], trans_matrix[i][2], trans_matrix[i][3], trans_matrix[i][4], trans_matrix[i][5], i < 5 and ", " or ""))
    end
    f:write("]\n  },\n")

    f:write('  "discovered_patterns": [\n')
    for i = 1, #discovered_patterns do
        local p = discovered_patterns[i]
        f:write(string.format(
            '    {"id": "%s", "hits": %d, "domain": "%s", "phase": "%s", "z_rxtx": %.2f, "z_large": %.2f, "z_jit": %.2f}%s\n',
            p.id, p.hits, json_escape(p.domain), p.phase, p.z_rxtx, p.z_large, p.z_jit, i < #discovered_patterns and "," or ""
        ))
    end
    f:write("  ],\n")

    f:write('  "ai_audit_summary": {\n')
    f:write(string.format('    "health_score": %d, "recommended_mask_id": %d, "active_endpoint": "%s",\n',
        audit.health_score, audit.recommended_mask, json_escape(M.live.active_endpoint)))
    f:write(string.format('    "avg_migration_ms": %.2f, "primary_triggers": %d, "backup_triggers": %d, "stall_count": %d,\n',
        audit.avg_migration_ms, audit.primary_triggers, audit.backup_triggers, M.live.stall_count))
    f:write(string.format('    "direct_tx_pkts": %d, "direct_rx_pkts": %d, "direct_tx_bytes": %d, "direct_rx_bytes": %d,\n',
        M.live.direct_tx_pkts, M.live.direct_rx_pkts, M.live.direct_tx_bytes, M.live.direct_rx_bytes))
    f:write('    "anomalies": [')
    for i = 1, #audit.anomalies do
        f:write(string.format('"%s"%s', json_escape(audit.anomalies[i]), i < #audit.anomalies and ", " or ""))
    end
    f:write("]\n  },\n")

    f:write('  "proto_stats": {\n')
    local first_p = true
    for pid, s in pairs(proto_stats) do
        if not first_p then f:write(",\n") end
        first_p = false
        local avg_ms = s.migrated > 0 and (s.sum_ms / s.migrated) or 0
        local avg_r  = s.pulls > 0 and (s.reward_sum / s.pulls) or 0
        f:write(string.format(
            '    "%d": {"migrated": %d, "stalls": %d, "pulls": %.2f, "avg_reward": %.3f, "avg_ms": %.2f}',
            pid, s.migrated, s.stalls, s.pulls, avg_r, avg_ms
        ))
    end
    f:write("\n  },\n")

    f:write('  "ring_buffer": [\n')
    local count = math.min(ring_total, RING_CAP)
    local start_idx = (ring_total <= RING_CAP) and 1 or ((ring_head % RING_CAP) + 1)
    for k = 0, count - 1 do
        local idx = ((start_idx - 1 + k) % RING_CAP) + 1
        local r = ring[idx]
        local comma = (k < count - 1) and "," or ""
        f:write(string.format(
            '    {"t_ms": %.2f, "dir": %d, "port": %d, "size": %d, "qkind": %d, "state": %d}%s\n',
            r.t_ms, r.dir, r.port, r.size, r.qkind, r.state, comma
        ))
    end
    f:write("  ],\n")

    f:write('  "events": [\n')
    for i = 1, event_count do
        local e = events[i]
        local delta = e.delta_ms and string.format(', "delta_ms": %.2f', e.delta_ms) or ""
        local comma = (i < event_count) and "," or ""
        f:write(string.format(
            '    {"t_ms": %.2f, "kind": "%s", "port": %d, "proto": %d, "detail": "%s"%s}%s\n',
            e.t_ms, json_escape(e.kind), e.port, e.proto_id, json_escape(e.detail), delta, comma
        ))
    end
    f:write("  ]\n}\n")
    f:close()
    return true
end

return M
