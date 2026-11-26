-- server.lua: Ultra-lightweight Linux UDP Relay via LuaJIT 2.1 FFI + epoll
-- Zero external dependencies, zero-allocation hot path, 60s ephemeral session TTL, zero disk logging.
-- Usage: luajit server.lua [port]  (default: 2632)

local ffi = require("ffi")
local bit = require("bit")
local C = require("common")

local band, bor, lshift, rshift = bit.band, bit.bor, bit.lshift, bit.rshift

ffi.cdef[[
    typedef uint32_t socklen_t;
    typedef uint16_t sa_family_t;

    struct in_addr  { uint32_t s_addr; };
    struct in6_addr { uint8_t s6_addr[16]; };

    struct sockaddr {
        sa_family_t sa_family;
        char        sa_data[14];
    };

    struct sockaddr_in {
        sa_family_t    sin_family;
        uint16_t       sin_port;
        struct in_addr sin_addr;
        char           sin_zero[8];
    };

    struct sockaddr_in6 {
        sa_family_t     sin6_family;
        uint16_t        sin6_port;
        uint32_t        sin6_flowinfo;
        struct in6_addr sin6_addr;
        uint32_t        sin6_scope_id;
    };

    typedef union epoll_data {
        void    *ptr;
        int      fd;
        uint32_t u32;
        uint64_t u64;
    } epoll_data_t;

    struct __attribute__((packed)) epoll_event {
        uint32_t     events;
        epoll_data_t data;
    };

    int     socket(int domain, int type, int protocol);
    int     bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    int     setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
    int     fcntl(int fd, int cmd, ...);
    ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
    ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
    int     close(int fd);
    int     epoll_create1(int flags);
    int     epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
    int     epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
    char   *strerror(int errnum);
]]

local AF_INET       = 2
local AF_INET6      = 10
local SOCK_DGRAM    = 2
local SOL_SOCKET    = 1
local SO_REUSEADDR  = 2
local SO_SNDBUF     = 7
local SO_RCVBUF     = 8
local IPPROTO_IPV6  = 41
local IPV6_V6ONLY   = 26
local F_SETFL       = 4
local O_NONBLOCK    = 2048
local EPOLLIN       = 1
local EPOLL_CTL_ADD = 1
local EPOLL_CTL_DEL = 2

local SESSION_TIMEOUT_SECS = C.RELAY_SESSION_TTL_S
local MAX_SESSIONS = 4096

local function htons(v)
    return bor(lshift(band(v, 0xFF), 8), band(rshift(v, 8), 0xFF))
end

local function create_udp_socket(is_v6, port)
    local domain = is_v6 and AF_INET6 or AF_INET
    local fd = ffi.C.socket(domain, SOCK_DGRAM, 0)
    if fd < 0 then return -1 end

    local one = ffi.new("int[1]", 1)
    ffi.C.setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, one, 4)
    local buf_sz = ffi.new("int[1]", 4194304)
    ffi.C.setsockopt(fd, SOL_SOCKET, SO_RCVBUF, buf_sz, 4)
    ffi.C.setsockopt(fd, SOL_SOCKET, SO_SNDBUF, buf_sz, 4)
    if is_v6 then
        ffi.C.setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, one, 4)
    end
    ffi.C.fcntl(fd, F_SETFL, ffi.cast("int", O_NONBLOCK))

    local res
    if is_v6 then
        local addr = ffi.new("struct sockaddr_in6")
        addr.sin6_family = AF_INET6
        addr.sin6_port   = htons(port)
        res = ffi.C.bind(fd, ffi.cast("const struct sockaddr*", addr), ffi.sizeof("struct sockaddr_in6"))
    else
        local addr = ffi.new("struct sockaddr_in")
        addr.sin_family = AF_INET
        addr.sin_port   = htons(port)
        res = ffi.C.bind(fd, ffi.cast("const struct sockaddr*", addr), ffi.sizeof("struct sockaddr_in"))
    end
    if res < 0 then ffi.C.close(fd); return -1 end
    return fd
end

local function main()
    local port = tonumber(arg[1]) or 2632
    print("=========================================================================")
    print("  masque-relay (LuaJIT 2.1 + FFI Epoll Dual-Stack Relay)")
    print("=========================================================================")
    print(string.format("  Listen Port  : %d (IPv4 + IPv6 Dual-Stack)", port))
    print(string.format("  Session TTL  : %d seconds inactivity auto-purge", SESSION_TIMEOUT_SECS))
    print("  Privacy      : Zero disk logging, zero payload inspection")
    print("=========================================================================")

    local listen_v4 = create_udp_socket(false, port)
    if listen_v4 < 0 then
        io.stderr:write(string.format("[ERROR] Failed to bind IPv4 0.0.0.0:%d\n", port))
        os.exit(1)
    end
    print(string.format("  [IPv4] Listening on 0.0.0.0:%d", port))

    local listen_v6 = create_udp_socket(true, port)
    if listen_v6 >= 0 then
        print(string.format("  [IPv6] Listening on [::]:%d", port))
    else
        print("  [IPv6 WARN] IPv6 unavailable (IPv4 only)")
    end

    local epfd = ffi.C.epoll_create1(0)
    if epfd < 0 then
        io.stderr:write("[ERROR] epoll_create1 failed\n")
        os.exit(1)
    end
    local ev = ffi.new("struct epoll_event")
    ev.events = EPOLLIN; ev.data.fd = listen_v4
    ffi.C.epoll_ctl(epfd, EPOLL_CTL_ADD, listen_v4, ev)
    if listen_v6 >= 0 then
        ev.data.fd = listen_v6
        ffi.C.epoll_ctl(epfd, EPOLL_CTL_ADD, listen_v6, ev)
    end

    -- Preallocated Zero-Allocation Hot-Path Buffers
    local rx_buf      = ffi.new("uint8_t[65535]")
    local resp_buf    = ffi.new("uint8_t[65535]")
    local camo_hdr    = ffi.new("uint8_t[8]")
    local events      = ffi.new("struct epoll_event[64]")
    local src_storage = ffi.new("struct sockaddr_in6") -- big enough for both v4 & v6
    local src_len     = ffi.new("socklen_t[1]")
    local target_v4   = ffi.new("struct sockaddr_in")
    local target_v6   = ffi.new("struct sockaddr_in6")
    target_v4.sin_family  = AF_INET
    target_v6.sin6_family = AF_INET6

    local sessions = {} -- client_key -> session
    local session_count = 0
    local fd_to_sess = {} -- upstream_fd -> session
    local pkt_count = 0
    local last_gc = os.time()

    local function register_session(client_key, addr_ptr, addr_sz, is_v6, proto_id)
        if session_count >= MAX_SESSIONS then return nil end
        local up_v4 = create_udp_socket(false, 0)
        if up_v4 < 0 then return nil end

        local client_addr_copy = ffi.new("uint8_t[?]", addr_sz)
        ffi.copy(client_addr_copy, addr_ptr, addr_sz)

        local sess = {
            key = client_key,
            client_addr = ffi.cast("const struct sockaddr*", client_addr_copy),
            client_addr_len = addr_sz,
            listen_fd = is_v6 and listen_v6 or listen_v4,
            up_v4 = up_v4,
            up_v6 = -1, -- lazy-created on demand for IPv6 upstream targets
            proto_id = proto_id,
            in_count = 0,
            last_seen = os.time(),
        }
        sessions[client_key] = sess
        session_count = session_count + 1
        fd_to_sess[up_v4] = sess
        ev.events = EPOLLIN; ev.data.fd = up_v4
        ffi.C.epoll_ctl(epfd, EPOLL_CTL_ADD, up_v4, ev)
        return sess
    end

    local function ensure_up_v6(sess)
        if sess.up_v6 >= 0 then return true end
        local fd6 = create_udp_socket(true, 0)
        if fd6 < 0 then return false end
        sess.up_v6 = fd6
        fd_to_sess[fd6] = sess
        ev.events = EPOLLIN; ev.data.fd = fd6
        ffi.C.epoll_ctl(epfd, EPOLL_CTL_ADD, fd6, ev)
        return true
    end

    local function purge_expired(now)
        for k, s in pairs(sessions) do
            if now - s.last_seen >= SESSION_TIMEOUT_SECS then
                ffi.C.epoll_ctl(epfd, EPOLL_CTL_DEL, s.up_v4, nil)
                ffi.C.close(s.up_v4)
                fd_to_sess[s.up_v4] = nil
                if s.up_v6 >= 0 then
                    ffi.C.epoll_ctl(epfd, EPOLL_CTL_DEL, s.up_v6, nil)
                    ffi.C.close(s.up_v6)
                    fd_to_sess[s.up_v6] = nil
                end
                sessions[k] = nil
                session_count = session_count - 1
            end
        end
    end

    while true do
        local nfds = ffi.C.epoll_wait(epfd, events, 64, 5000)
        local now = os.time()

        for i = 0, nfds - 1 do
            local fd = events[i].data.fd
            if fd == listen_v4 or fd == listen_v6 then
                while true do
                    src_len[0] = ffi.sizeof("struct sockaddr_in6")
                    local n = tonumber(ffi.C.recvfrom(fd, rx_buf, 65535, 0, ffi.cast("struct sockaddr*", src_storage), src_len))
                    if n <= 0 then break end

                    if n >= C.OUTBOUND_PREPEND_LEN_V4 then
                        local is_t6 = (n >= C.OUTBOUND_PREPEND_LEN_V6 and rx_buf[27] == C.ADDR_TYPE_IPV6)
                        local env_len = is_t6 and C.OUTBOUND_PREPEND_LEN_V6 or C.OUTBOUND_PREPEND_LEN_V4
                        if n > env_len then
                            local proto_id = is_t6 and rx_buf[26] or rx_buf[14]
                            local t_port = is_t6 and C.get_be16(rx_buf, 24) or C.get_be16(rx_buf, 12)
                            local valid_target = (t_port ~= 0)
                            if valid_target and not is_t6 then
                                valid_target = not (rx_buf[8]==0 and rx_buf[9]==0 and rx_buf[10]==0 and rx_buf[11]==0)
                            end

                            if valid_target then
                                local ckey = ffi.string(src_storage, src_len[0])
                                local sess = sessions[ckey]
                                if not sess then
                                    sess = register_session(ckey, src_storage, src_len[0], (fd == listen_v6), proto_id)
                                end
                                if sess then
                                    sess.proto_id = proto_id
                                    sess.last_seen = now
                                    local pay_ptr = rx_buf + env_len
                                    local pay_len = n - env_len
                                    if is_t6 and ensure_up_v6(sess) then
                                        ffi.copy(target_v6.sin6_addr.s6_addr, rx_buf + 8, 16)
                                        target_v6.sin6_port = htons(t_port)
                                        ffi.C.sendto(sess.up_v6, pay_ptr, pay_len, 0, ffi.cast("const struct sockaddr*", target_v6), ffi.sizeof("struct sockaddr_in6"))
                                    elseif not is_t6 then
                                        ffi.copy(target_v4.sin_addr, rx_buf + 8, 4)
                                        target_v4.sin_port = htons(t_port)
                                        ffi.C.sendto(sess.up_v4, pay_ptr, pay_len, 0, ffi.cast("const struct sockaddr*", target_v4), ffi.sizeof("struct sockaddr_in"))
                                    end
                                    pkt_count = pkt_count + 1
                                    if pkt_count <= 5 or pkt_count % 250 == 0 then
                                        local pinfo = C.get_protocol_by_id(proto_id)
                                        print(string.format("[RELAY] Out #%d | Active=%d | Proto [%d:%s] -> %dB", pkt_count, session_count, pinfo.id, pinfo.key, pay_len))
                                        io.flush()
                                    end
                                end
                            end
                        end
                    end
                end
            else
                -- Upstream response -> prepend 8B inbound camo -> send back to client
                local sess = fd_to_sess[fd]
                if sess then
                    while true do
                        local n = tonumber(ffi.C.recvfrom(fd, resp_buf + 8, 65527, 0, nil, nil))
                        if n <= 0 then break end
                        sess.in_count = sess.in_count + 1
                        sess.last_seen = now
                        C.build_inbound_camo(sess.proto_id, sess.in_count, camo_hdr, 0)
                        ffi.copy(resp_buf, camo_hdr, 8)
                        ffi.C.sendto(sess.listen_fd, resp_buf, n + 8, 0, sess.client_addr, sess.client_addr_len)
                    end
                end
            end
        end

        if now - last_gc >= 10 then
            purge_expired(now)
            last_gc = now
        end
    end
end

main()
