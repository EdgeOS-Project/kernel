#include "block/device_mapper.h"
#include "block/loop.h"
#include "kernel/input_device.h"
#include "kernel/linux_input.h"
#include "kernel/linux_fiemap.h"

static int x86_alsa_copy_from_user(
    void *context, void *destination, uint64_t source, uint32_t length) {
    (void)context;
    return copy_from_user(destination, source, length);
}

static int x86_alsa_copy_to_user(
    void *context, uint64_t destination, const void *source,
    uint32_t length) {
    (void)context;
    return copy_to_user(destination, source, length);
}

static int x86_loop_copy_from_user(
    void *context, void *destination, uint64_t source, uint64_t length) {
    (void)context;
    return copy_from_user(destination, source, length);
}

static int x86_loop_copy_to_user(
    void *context, uint64_t destination, const void *source,
    uint64_t length) {
    (void)context;
    return copy_to_user(destination, source, length);
}

/*
 * Prepare every user page touched by a socket iovec before taking a socket
 * queue spinlock.  A first access to a file-backed user page can perform VFS
 * I/O and yield.  Suspending a task while it owns an IRQ-safe queue lock leaves
 * every peer spinning with interrupts masked, so queue critical sections must
 * contain only non-faulting copies.
 */
static int socket_iovec_user_access_prepare(
    const kernel_socket_iovec_source_t *source, uint32_t count,
    uint64_t byte_limit, int write) {
    uint64_t remaining = byte_limit;

    if (!source) return -EINVAL;
    for (uint32_t index = 0; index < count && remaining; ++index) {
        struct edge_linux_iovec iov;
        uint64_t length;
        int status = kernel_socket_iovec_source_read(source, index, &iov);

        if (status < 0) return status;
        length = iov.iov_len < remaining ? iov.iov_len : remaining;
        if (length && !user_access_ok(iov.iov_base, length, write))
            return -EFAULT;
        remaining -= length;
    }
    return 0;
}

static int x86_loop_resolve_backing(
    void *context, int32_t descriptor, edge_loop_backing_file_t *backing) {
    task_t *task = (task_t *)context;
    edge_fd_proc_t *process;
    edge_fd_t *entry;

    if (!task || task != process_current_task() || !backing)
        return -ESRCH;
    process = fd_proc_for_pid(
        task->fd_owner_pid > 0 ? task->fd_owner_pid : task->pid, 0);
    entry = fd_get(process, descriptor);
    if (!entry) return -EBADF;
    if (entry->kind != FD_VFS || !entry->sb ||
        (entry->inode.mode & 0xf000u) != VFS_INODE_FILE)
        return -EINVAL;
    memset(backing, 0, sizeof(*backing));
    backing->superblock = entry->sb;
    backing->inode = entry->inode;
    backing->device_number = 1u;
    backing->status_flags = (uint32_t)entry->flags;
    strncpy(backing->path, entry->path, sizeof(backing->path) - 1u);
    backing->path[sizeof(backing->path) - 1u] = 0;
    return 0;
}

static int g_x11_sock_trace_budget = EDGE_GUI_DEEP_TRACE ? 512 : 160;
static int x11_sockio_trace_task(const task_t *t) {
    if (!t || !t->name[0]) return 0;
#if EDGE_X11_TRACE
    return strcmp(t->name, "Xorg") == 0 ||
           strcmp(t->name, "InputThread") == 0 ||
           strcmp(t->name, "xrdb") == 0 ||
           strcmp(t->name, "xsetroot") == 0 ||
           strcmp(t->name, "twm") == 0 ||
           strcmp(t->name, "xterm") == 0 ||
           strcmp(t->name, "xclock") == 0 ||
           strcmp(t->name, "xfce4-session") == 0 ||
           strcmp(t->name, "xfce4-terminal") == 0 ||
           strcmp(t->name, "xfwm4") == 0 ||
           strcmp(t->name, "xfce4-panel") == 0 ||
           strcmp(t->name, "xfdesktop") == 0 ||
           strcmp(t->name, "xfsettingsd") == 0 ||
           strcmp(t->name, "dbus-launch") == 0 ||
           strcmp(t->name, "dbus-daemon") == 0 ||
           strcmp(t->name, "xwininfo") == 0 ||
           strcmp(t->name, "xdpyinfo") == 0 ||
           strcmp(t->name, "xdotool") == 0;
#elif EDGE_X11_BOOT_TRACE
    return strcmp(t->name, "xrdb") == 0;
#else
    return 0;
#endif
}

static int xfce_x11_peer_trace_task(const task_t *cur, const edge_socket_t *s) {
    const task_t *peer;
    if (!cur || !cur->name[0]) return 0;
    if (strcmp(cur->name, "xfce4-session") == 0 ||
        strcmp(cur->name, "xrdb") == 0 ||
        strcmp(cur->name, "xfwm4") == 0 ||
        strcmp(cur->name, "xfce4-panel") == 0 ||
        strcmp(cur->name, "xfdesktop") == 0 ||
        strcmp(cur->name, "xfsettingsd") == 0 ||
        strcmp(cur->name, "xfconfd") == 0 ||
        strcmp(cur->name, "dbus-daemon") == 0 ||
        strcmp(cur->name, "gdbus") == 0 ||
        strcmp(cur->name, "gmain") == 0) {
        return 1;
    }
    if (!s || strcmp(cur->name, "Xorg") != 0 || s->peer_cred_pid <= 0) return 0;
    peer = process_get_task(s->peer_cred_pid);
    if (!peer || !peer->name[0]) return 0;
    return strcmp(peer->name, "xrdb") == 0 ||
           strcmp(peer->name, "xfce4-session") == 0 ||
           strcmp(peer->name, "xfwm4") == 0 ||
           strcmp(peer->name, "xfce4-panel") == 0 ||
           strcmp(peer->name, "xfdesktop") == 0 ||
           strcmp(peer->name, "xfsettingsd") == 0;
}

static int gui_accept_trace_task(const task_t *t) {
    if (!t || !t->name[0]) return 0;
    return strcmp(t->name, "Xorg") == 0 ||
           strcmp(t->name, "xfce4-session") == 0 ||
           strcmp(t->name, "xfwm4") == 0 ||
           strcmp(t->name, "xfdesktop") == 0 ||
           strcmp(t->name, "xfce4-panel") == 0 ||
           strcmp(t->name, "xfsettingsd") == 0 ||
           strcmp(t->name, "xfconfd") == 0 ||
           strcmp(t->name, "dbus-daemon") == 0 ||
           strcmp(t->name, "gdbus") == 0 ||
           strcmp(t->name, "gmain") == 0;
}

static void gui_accept_trace(const char *where, const task_t *cur, int fd,
                             const edge_socket_t *listener, int rc) {
    static int budget = 96;
    int sid = listener ? socket_id_from_ptr((edge_socket_t *)listener) : -1;

    if (budget <= 0 || !gui_accept_trace_task(cur)) return;
    /*
     * X11, ICE, D-Bus, and GLib all depend on Linux AF_UNIX accept semantics.
     * Keep this errno-level trace generic to desktop socket servers: repeated
     * userland "accept() failed" messages are otherwise ambiguous between
     * EAGAIN, stale queued children, fd exhaustion, and listen state bugs.
     */
    printf("[accept-abi] %s pid=%d cmd=%s fd=%d sid=%d rc=%d used=%d listen=%d pending=%d backlog=%d refs=%d nonblock=%d closed=%d rxclosed=%d budget=%d\n",
           where ? where : "?",
           cur ? cur->pid : -1,
           cur && cur->name[0] ? cur->name : "?",
           fd, sid, rc,
           listener ? listener->used : -1,
           listener ? listener->listening : -1,
           listener ? socket_pending_count(listener) : -1,
           listener ? listener->backlog : -1,
           listener ? listener->refs : -1,
           listener ? listener->nonblock : -1,
           listener ? listener->closed : -1,
           listener ? listener->rx_closed : -1,
           budget - 1);
    budget--;
}

static void gui_connect_backlog_trace(const char *where, const task_t *cur,
                                      int fd, const edge_socket_t *listener,
                                      int rc) {
    static int budget = 64;
    int sid = listener ? socket_id_from_ptr((edge_socket_t *)listener) : -1;

    if (budget <= 0 || !gui_accept_trace_task(cur)) return;
    printf("[connect-backlog] %s pid=%d cmd=%s fd=%d listener=%d rc=%d pending=%d backlog=%d refs=%d budget=%d\n",
           where ? where : "?",
           cur ? cur->pid : -1,
           cur && cur->name[0] ? cur->name : "?",
           fd, sid, rc,
           listener ? socket_pending_count(listener) : -1,
           listener ? listener->backlog : -1,
           listener ? listener->refs : -1,
           budget - 1);
    budget--;
}

static uint64_t fbdev_ioctl_cmap(uint32_t cmd, uint64_t arg_u) {
    struct edge_fb_cmap cmap;
    static int fb_cmap_log_budget = 0;

    if (!arg_u) return (uint64_t)-EINVAL;
    if (copy_from_user(&cmap, arg_u, sizeof(cmap)) < 0) return (uint64_t)-EFAULT;
    if (cmap.len > 65536u) return (uint64_t)-EINVAL;
    if (cmap.len != 0 &&
        (!cmap.red || !cmap.green || !cmap.blue)) {
        return (uint64_t)-EFAULT;
    }

    /*
     * Linux fbdev exposes a real nested-pointer ABI for struct fb_cmap even on
     * true-color framebuffers where palette programming does not change
     * hardware state.  Xorg saves/restores and programs the cmap during fbdev
     * setup; returning success without touching the caller's arrays is a fake
     * success path that leaves userspace observing uninitialized data.
     *
     * EdgeOS has no programmable palette for the virtio-gpu true-color fbdev,
     * so FBIOPUTCMAP validates/copies the supplied arrays and discards them.
     * FBIOGETCMAP returns deterministic identity ramps.  Keep this generic to
     * fbdev; do not key it on Xorg/XFCE or a rootfs package.
     */
    if (cmd == LINUX_FBIOGETCMAP) {
        for (uint32_t i = 0; i < cmap.len; ++i) {
            uint32_t idx = cmap.start + i;
            uint16_t v;
            uint16_t a = 0xffffu;
            if (idx > 255u) v = 0xffffu;
            else v = (uint16_t)(idx * 257u);
            if (copy_to_user(cmap.red + (uint64_t)i * sizeof(v), &v, sizeof(v)) < 0 ||
                copy_to_user(cmap.green + (uint64_t)i * sizeof(v), &v, sizeof(v)) < 0 ||
                copy_to_user(cmap.blue + (uint64_t)i * sizeof(v), &v, sizeof(v)) < 0 ||
                (cmap.transp &&
                 copy_to_user(cmap.transp + (uint64_t)i * sizeof(a), &a, sizeof(a)) < 0)) {
                return (uint64_t)-EFAULT;
            }
        }
    } else if (cmd == LINUX_FBIOPUTCMAP) {
        for (uint32_t i = 0; i < cmap.len; ++i) {
            uint16_t v;
            if (copy_from_user(&v, cmap.red + (uint64_t)i * sizeof(v), sizeof(v)) < 0 ||
                copy_from_user(&v, cmap.green + (uint64_t)i * sizeof(v), sizeof(v)) < 0 ||
                copy_from_user(&v, cmap.blue + (uint64_t)i * sizeof(v), sizeof(v)) < 0 ||
                (cmap.transp &&
                 copy_from_user(&v, cmap.transp + (uint64_t)i * sizeof(v), sizeof(v)) < 0)) {
                return (uint64_t)-EFAULT;
            }
        }
    } else {
        return (uint64_t)-ENOTTY;
    }
    if (fb_cmap_log_budget > 0) {
        task_t *cur = process_current_task();
        printf("[fb-cmap] pid=%d task=%s cmd=0x%x start=%u len=%u rc=0 budget=%d\n",
               cur ? cur->pid : -1, cur && cur->name[0] ? cur->name : "?",
               cmd, cmap.start, cmap.len, fb_cmap_log_budget - 1);
        fb_cmap_log_budget--;
    }
    return 0;
}

int edge_procfs_socket_snapshot(int pid, int fd, int *sock_id_out, int *domain_out,
                                int *type_out, int *peer_out, uint32_t *rx_len_out,
                                int *closed_out, int *rx_closed_out, int *listening_out,
                                int *pending_out, int *nonblock_out, int *passcred_out,
                                int *refs_out, int *rights_count_out,
                                uint32_t *rights_start_out,
                                int *rights_fds_out,
                                uint32_t *packet_count_out) {
    const task_t *t = process_get_task(pid);
    edge_fd_proc_t *p;
    edge_fd_t *e;
    edge_socket_t *s;
    kernel_socket_rights_record_info_t rights_info;
    int have_rights = 0;
    int owner_pid = pid;

    if (fd < 0 || fd >= EDGE_MAX_FD) return -1;
    if (!t || t->state == TASK_UNUSED) return -1;
    if (t->fd_owner_pid > 0) owner_pid = t->fd_owner_pid;
    p = fd_proc_for_pid(owner_pid, 0);
    e = fd_get(p, fd);
    if (!e || e->kind != FD_SOCKET ||
        e->pipe_id < 0 || e->pipe_id >= EDGE_MAX_SOCKETS) {
        return -1;
    }
    s = &g_sockets[e->pipe_id];
    if (!s->used) return -1;
    memset(&rights_info, 0, sizeof(rights_info));
    if (socket_rights_peek_at(s, 0, &rights_info) == 0)
        have_rights = 1;

    if (sock_id_out) *sock_id_out = e->pipe_id;
    if (domain_out) *domain_out = s->domain;
    if (type_out) *type_out = s->type;
    if (peer_out) *peer_out = s->unix_peer_id;
    if (rx_len_out) *rx_len_out = s->rx_len;
    if (closed_out) *closed_out = s->closed;
    if (rx_closed_out) *rx_closed_out = s->rx_closed;
    if (listening_out) *listening_out = s->listening;
    if (pending_out) *pending_out = socket_pending_count(s);
    if (nonblock_out) *nonblock_out = s->nonblock || (e->flags & LINUX_O_NONBLOCK) ? 1 : 0;
    if (passcred_out)
        *passcred_out = s->option_state.pass_credentials;
    if (refs_out) *refs_out = s->refs;
    if (rights_count_out) {
        *rights_count_out =
            (int)kernel_socket_rights_queue_count(&s->rights);
    }
    if (rights_start_out) {
        uint64_t head_sequence =
            rights_info.association_kind ==
                    KERNEL_SOCKET_RIGHTS_ASSOCIATION_PACKET ?
                s->unix_packet_head_sequence :
                s->unix_stream_head_sequence;
        uint64_t relative = have_rights &&
                rights_info.association_sequence > head_sequence ?
            rights_info.association_sequence - head_sequence : 0;
        *rights_start_out =
            relative > UINT32_MAX ? UINT32_MAX : (uint32_t)relative;
    }
    if (rights_fds_out) {
        *rights_fds_out =
            have_rights ? (int)rights_info.descriptor_count : 0;
    }
    if (packet_count_out) *packet_count_out = s->packet_count;
    return 0;
}

static void x11_sockio_trace_bytes(const char *op, const task_t *cur, int fd,
                                   int sid, int peer_id, uint32_t len,
                                   uint32_t queued, const uint8_t *buf,
                                   uint32_t buf_len) {
    uint32_t b0 = 0, b1 = 0, b2 = 0, b3 = 0;
    if (!x11_sockio_trace_task(cur) || g_x11_sock_trace_budget-- <= 0) return;
    if (buf && buf_len > 0) b0 = buf[0];
    if (buf && buf_len > 1) b1 = buf[1];
    if (buf && buf_len > 2) b2 = buf[2];
    if (buf && buf_len > 3) b3 = buf[3];
    printf("[x11io] %s pid=%d cmd=%s fd=%d sid=%d peer=%d len=%u queued=%u b=%x,%x,%x,%x\n",
           op, cur ? cur->pid : -1, cur ? cur->name : "?",
           fd, sid, peer_id, len, queued, b0, b1, b2, b3);
}

static void xfce_sock_trace_bytes(const char *op, const task_t *cur, const edge_socket_t *s,
                                  int fd, int sid, int peer_id, uint32_t len,
                                  uint32_t queued, const uint8_t *buf,
                                  uint32_t buf_len) {
#if EDGE_XFCE_BOOT_TRACE
    static int budget = 192;
    uint32_t b0 = 0, b1 = 0, b2 = 0, b3 = 0;
    uint64_t read_sequence = 0;
    uint64_t write_sequence = 0;
    const task_t *peer = 0;
    if (budget <= 0 || !xfce_x11_peer_trace_task(cur, s)) return;
    if (s && s->peer_cred_pid > 0) peer = process_get_task(s->peer_cred_pid);
    if (buf && buf_len > 0) b0 = buf[0];
    if (buf && buf_len > 1) b1 = buf[1];
    if (buf && buf_len > 2) b2 = buf[2];
    if (buf && buf_len > 3) b3 = buf[3];
    if (s)
        kernel_socket_readiness_snapshot(
            &s->readiness, &read_sequence, &write_sequence);
    printf("[xfce-x11io] %s pid=%d cmd=%s fd=%d sid=%d peer=%d peerpid=%d peercmd=%s len=%u queued=%u rx=%u closed=%d rxclosed=%d rseq=%llu wseq=%llu b=%x,%x,%x,%x budget=%d\n",
           op, cur ? cur->pid : -1, cur ? cur->name : "?",
           fd, sid, peer_id, s ? s->peer_cred_pid : -1,
           peer ? peer->name : "-",
           len, queued, s ? s->rx_len : 0,
           s ? s->closed : -1, s ? s->rx_closed : -1,
           (unsigned long long)read_sequence,
           (unsigned long long)write_sequence,
           b0, b1, b2, b3, budget - 1);
    budget--;
#else
    (void)op;
    (void)cur;
    (void)s;
    (void)fd;
    (void)sid;
    (void)peer_id;
    (void)len;
    (void)queued;
    (void)buf;
    (void)buf_len;
#endif
}

static int socket_ipv4_is_loopback_be(uint32_t addr_be) {
    return (edge_bswap32(addr_be) & 0xFF000000u) == 0x7F000000u;
}

static int socket_ipv4_is_local_be(uint32_t addr_be) {
    return socket_ipv4_is_loopback_be(addr_be) ||
           edge_linux_rtnetlink_ipv4_is_local(addr_be);
}

static int socket_ipv6_address_is_any(const uint8_t address[16]) {
    for (uint32_t index = 0; index < 16u; ++index) {
        if (address[index]) return 0;
    }
    return 1;
}

static int socket_ipv6_address_is_mapped_ipv4(
    const uint8_t address[16], uint32_t ipv4) {
    static const uint8_t prefix[12] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff
    };

    return memcmp(address, prefix, sizeof(prefix)) == 0 &&
           memcmp(address + sizeof(prefix), &ipv4, sizeof(ipv4)) == 0;
}

static void socket_ipv6_address_from_ipv4(
    uint8_t address[16], uint32_t ipv4) {
    memset(address, 0, 16u);
    address[10] = 0xffu;
    address[11] = 0xffu;
    memcpy(address + 12u, &ipv4, sizeof(ipv4));
}

static void socket_apply_ip_pcb_options(edge_socket_t *s) {
    if (!s || !s->lwip_pcb) return;
    lwip_stack_core_enter();
    if ((s->domain == LINUX_AF_INET || s->domain == LINUX_AF_INET6) &&
        s->type == LINUX_SOCK_DGRAM &&
        (s->protocol == 0 || s->protocol == LINUX_IPPROTO_UDP)) {
        struct udp_pcb *up = (struct udp_pcb *)s->lwip_pcb;
        up->ttl = s->ip_ttl ? s->ip_ttl : 64;
        up->tos = s->ip_tos;
        up->mcast_ttl = s->domain == LINUX_AF_INET6 ?
            (uint8_t)s->option_state.ipv6_multicast_hops :
            s->option_state.ip_multicast_ttl;
        udp_set_multicast_netif_index(
            up, (uint8_t)(s->domain == LINUX_AF_INET6 ?
                s->option_state.ipv6_multicast_interface_index :
                s->option_state.ip_multicast_interface_index));
        if (s->domain == LINUX_AF_INET) {
            ip4_addr_t multicast_address;

            multicast_address.addr =
                s->option_state.ip_multicast_interface_address;
            udp_set_multicast_netif_addr(up, &multicast_address);
        }
        if ((s->domain == LINUX_AF_INET6 ?
             s->option_state.ipv6_multicast_loop :
             s->option_state.ip_multicast_loop))
            up->flags |= UDP_FLAGS_MULTICAST_LOOP;
        else
            up->flags &= (uint8_t)~UDP_FLAGS_MULTICAST_LOOP;
        if (s->option_state.reuse_address)
            ip_set_option(up, SOF_REUSEADDR);
        else
            ip_reset_option(up, SOF_REUSEADDR);
    } else if ((s->domain == LINUX_AF_INET || s->domain == LINUX_AF_INET6) &&
               s->type == LINUX_SOCK_STREAM &&
               (s->protocol == 0 || s->protocol == LINUX_IPPROTO_TCP)) {
        struct tcp_pcb *tp = (struct tcp_pcb *)s->lwip_pcb;
        tp->ttl = s->ip_ttl ? s->ip_ttl : 64;
        tp->tos = s->ip_tos;
        if (s->option_state.reuse_address)
            ip_set_option(tp, SOF_REUSEADDR);
        else
            ip_reset_option(tp, SOF_REUSEADDR);
        if (s->tcp_keepalive) ip_set_option(tp, SOF_KEEPALIVE);
        else ip_reset_option(tp, SOF_KEEPALIVE);
        if (s->option_state.tcp_nodelay)
            tcp_nagle_disable(tp);
        else
            tcp_nagle_enable(tp);
#if LWIP_TCP_KEEPALIVE
        tp->keep_idle = (u32_t)((s->tcp_keepidle_sec > 0 ? s->tcp_keepidle_sec : 7200) * 1000u);
        tp->keep_intvl = (u32_t)((s->tcp_keepintvl_sec > 0 ? s->tcp_keepintvl_sec : 75) * 1000u);
        tp->keep_cnt = (u32_t)(s->tcp_keepcnt > 0 ? s->tcp_keepcnt : 9);
#endif
    }
    lwip_stack_core_exit();
}

static void socket_sync_option_state(edge_socket_t *socket) {
    const kernel_socket_option_state_t *state;
    if (!socket) return;
    state = &socket->option_state;
    socket->recv_timeout_us = state->receive_timeout_us;
    socket->ip_ttl = state->ip_ttl ? state->ip_ttl : 64;
    socket->ip_tos = state->ip_tos;
    socket->ip_pktinfo = state->ip_packet_info;
    socket->ip_recverr = state->ip_receive_error;
    socket->ip_recvttl = state->ip_receive_ttl;
    socket->ip_freebind = state->ip_freebind;
    socket->ip_mtu_discover = state->ip_mtu_discover;
    socket->ipv6_v6only = state->ipv6_only;
    socket->ipv6_recverr = state->ipv6_receive_error;
    socket->ipv6_recvpktinfo = state->ipv6_receive_packet_info;
    socket->ipv6_recvhoplimit = state->ipv6_receive_hop_limit;
    socket->ipv6_recvtclass = state->ipv6_receive_traffic_class;
    socket->tcp_keepalive = state->keepalive;
    socket->tcp_keepidle_sec = state->tcp_keep_idle;
    socket->tcp_keepintvl_sec = state->tcp_keep_interval;
    socket->tcp_keepcnt = state->tcp_keep_count;
}

static void socket_copy_ip_options(edge_socket_t *dst, const edge_socket_t *src) {
    if (!dst || !src) return;
    dst->option_state = src->option_state;
    socket_sync_option_state(dst);
    socket_apply_ip_pcb_options(dst);
}

static int socket_ipv4_listener_matches(
    const edge_socket_t *client, edge_socket_t *listener,
    uint32_t dst_addr_be, uint16_t port_be) {
    struct edge_sockaddr_in lsin;
    struct edge_sockaddr_in6 lsin6;
    uint32_t destination_namespace;

    if (!client || !listener || !listener->used || !listener->listening)
        return 0;
    if (listener->type != LINUX_SOCK_STREAM) return 0;
    if (listener->local_port_be != port_be) return 0;
    if (socket_ipv4_is_loopback_be(dst_addr_be) &&
        listener->network_namespace != client->network_namespace)
        return 0;
    if (!socket_ipv4_is_loopback_be(dst_addr_be) &&
        edge_linux_rtnetlink_ipv4_owner(
            dst_addr_be, &destination_namespace) == 0 &&
        listener->network_namespace != destination_namespace)
        return 0;
    if (listener->domain == LINUX_AF_INET) {
        if (listener->bind_len < sizeof(lsin)) return 0;
        if (sockaddr_in_from_buf(
                listener->bind_addr, listener->bind_len, &lsin) < 0)
            return 0;
        if (lsin.sin_addr == 0) return 1;
        return lsin.sin_addr == dst_addr_be;
    }
    if (listener->domain != LINUX_AF_INET6 || listener->ipv6_v6only ||
        listener->bind_len < sizeof(lsin6))
        return 0;
    if (sockaddr_in6_from_buf(
            listener->bind_addr, listener->bind_len, &lsin6) < 0)
        return 0;
    /*
     * An IPv6 wildcard listener accepts IPv4 connections unless IPV6_V6ONLY
     * is enabled.  An explicitly mapped IPv4 address accepts only that
     * address, matching Linux dual-stack listener selection.
     */
    return socket_ipv6_address_is_any(lsin6.sin6_addr) ||
           socket_ipv6_address_is_mapped_ipv4(
               lsin6.sin6_addr, dst_addr_be);
}

static int socket_find_ipv4_loopback_listener(
    const edge_socket_t *client, uint32_t dst_addr_be, uint16_t port_be) {
    if (!socket_ipv4_is_local_be(dst_addr_be)) return -1;
    for (int sid = 0; sid < EDGE_MAX_SOCKETS; ++sid) {
        if (socket_ipv4_listener_matches(
                client, &g_sockets[sid], dst_addr_be, port_be))
            return sid;
    }
    return -1;
}

static uint64_t socket_buffered_stream_send(edge_socket_t *s, edge_fd_t *fde, task_t *cur,
                                            int fd, uint64_t buf_u, uint32_t len,
                                            int call_dontwait) {
    uint8_t chunkbuf[1024];
    uint32_t off = 0;
    while (off < len) {
        edge_socket_t *peer;
        uint32_t room;
        uint32_t n;
        int peer_was_empty;
        if (s->unix_peer_id < 0 || s->unix_peer_id >= EDGE_MAX_SOCKETS) {
            if (s->domain == LINUX_AF_UNIX && x11_sockio_trace_task(cur) && g_x11_sock_trace_budget-- > 0) {
                printf("[x11dbg] unix-send epipe pid=%d cmd=%s fd=%d sid=%d peer=%d len=%u off=%u\n",
                       cur->pid, cur->name, fd, fde ? fde->pipe_id : -1, s->unix_peer_id, len, off);
            }
            return (uint64_t)-EPIPE;
        }
        peer = &g_sockets[s->unix_peer_id];
        if (!peer->used || peer->shutdown_read) {
            if (s->domain == LINUX_AF_UNIX && x11_sockio_trace_task(cur) && g_x11_sock_trace_budget-- > 0) {
                printf("[x11dbg] unix-send deadpeer pid=%d cmd=%s fd=%d sid=%d peer=%d len=%u off=%u\n",
                       cur->pid, cur->name, fd, fde ? fde->pipe_id : -1, s->unix_peer_id, len, off);
            }
            return (uint64_t)-EPIPE;
        }
        if (s->shutdown_write) return (uint64_t)-EPIPE;
        room = (peer->rx_len < socket_rx_capacity(peer)) ?
               (uint32_t)(socket_rx_capacity(peer) - peer->rx_len) : 0;
        if (room == 0) {
            /*
             * If this stream write already queued bytes, return the partial
             * count instead of sleeping inside the same syscall waiting for
             * more peer receive space.  Linux may block a fully blocking
             * write until the whole request is copied, but it is also allowed
             * to return a short successful write.  That matters for desktop
             * workloads: Xorg, DBus, and GLib exchange large bursts over
             * local streams, and EdgeOS does not yet have exact per-socket
             * wait queues.  Sleeping here after making partial progress can
             * leave the peer runnable but not scheduled promptly, which looks
             * like frozen X11 windows and unresponsive mouse clicks.  Return
             * the queued byte count so userland's normal write retry path
             * drives the remaining data after the peer drains the buffer.
             */
            if (off > 0) {
                fd_wake_socket_waiters_events(s->unix_peer_id, LINUX_POLLIN | LINUX_POLLPRI);
                return off;
            }
            if (call_dontwait || (fde && (fde->flags & LINUX_O_NONBLOCK)) || s->nonblock) {
                return (uint64_t)-EAGAIN;
            }
            if (signal_pending_interrupt()) return tty_interrupt_current_ret();
            lwip_stack_poll();
            wait_blocking_step();
            continue;
        }
        n = len - off;
        if (n > room) n = room;
        peer_was_empty = (peer->rx_len == 0);
        {
            uint32_t done = 0;
            while (done < n) {
                uint32_t chunk = n - done;
                if (chunk > sizeof(chunkbuf)) chunk = sizeof(chunkbuf);
                if (copy_from_user(chunkbuf, buf_u + off + done, chunk) < 0) return (uint64_t)-EFAULT;
                memcpy(peer->rx_buf + peer->rx_len + done, chunkbuf, chunk);
                done += chunk;
            }
        }
        peer->rx_len += n;
        off += n;
        if (s->domain == LINUX_AF_UNIX && off == n) {
            x11_sockio_trace_bytes("send", cur, fd, fde ? fde->pipe_id : -1,
                                   s->unix_peer_id, len, peer->rx_len,
                                   chunkbuf, n);
            xfce_sock_trace_bytes("send", cur, s, fd, fde ? fde->pipe_id : -1,
                                  s->unix_peer_id, len, peer->rx_len,
                                  chunkbuf, n);
        }
        /*
         * A fresh AF_UNIX stream append is a fresh wakeup opportunity even
         * when the peer already had unread bytes.  X11, GTK, D-Bus, and window
         * managers often use EPOLLET-style loops around local stream sockets;
         * if EdgeOS only advances the read generation on empty->non-empty
         * transitions, later protocol records can remain queued behind older
         * unread bytes without waking the consumer again.  Keep this in sync
         * with the AF_UNIX send-buffer path.
         *
         * Red flag: do not turn this into a process-name, DISPLAY, or rootfs
         * special case.  The Linux ABI contract is AF_UNIX stream readiness.
         */
        (void)peer_was_empty;
        fd_wake_socket_waiters_events(s->unix_peer_id, LINUX_POLLIN | LINUX_POLLPRI);
        fd_wake_unix_listener_for_pending_child(s->unix_peer_id);
    }
    if (s->domain == LINUX_AF_UNIX && x11_sockio_trace_task(cur) && g_x11_sock_trace_budget-- > 0) {
        printf("[x11dbg] unix-send ok pid=%d cmd=%s fd=%d sid=%d peer=%d len=%u queued=%u\n",
               cur->pid, cur->name, fd, fde ? fde->pipe_id : -1, s->unix_peer_id, len,
               (s->unix_peer_id >= 0 && s->unix_peer_id < EDGE_MAX_SOCKETS) ? g_sockets[s->unix_peer_id].rx_len : 0);
    }
    return off;
}

static int64_t socket_buffered_stream_send_kernel(
    edge_socket_t *socket, edge_fd_t *descriptor, task_t *task,
    const uint8_t *buffer, uint32_t length) {
    uint32_t completed = 0;

    while (completed < length) {
        edge_socket_t *peer;
        uint32_t available;
        uint32_t count;
        if (!socket || socket->unix_peer_id < 0 ||
            socket->unix_peer_id >= EDGE_MAX_SOCKETS)
            return completed ? (int64_t)completed : -EPIPE;
        peer = &g_sockets[socket->unix_peer_id];
        if (!peer->used || peer->shutdown_read || socket->shutdown_write)
            return completed ? (int64_t)completed : -EPIPE;
        available = peer->rx_len < socket_rx_capacity(peer) ?
            socket_rx_capacity(peer) - peer->rx_len : 0;
        if (!available) {
            if (completed) return (int64_t)completed;
            if ((descriptor && (descriptor->flags & LINUX_O_NONBLOCK)) ||
                socket->nonblock)
                return -EAGAIN;
            if (signal_pending_interrupt())
                return (int64_t)tty_interrupt_current_ret();
            if (descriptor && task)
                socket_waiter_add(descriptor->pipe_id, task->pid,
                                  LINUX_POLLOUT | LINUX_POLLWRNORM);
            available = peer->rx_len < socket_rx_capacity(peer) ?
                socket_rx_capacity(peer) - peer->rx_len : 0;
            if (available) {
                if (task) waiter_remove_pid(task->pid);
                continue;
            }
            socket_blocking_wait_step(0);
            continue;
        }
        count = length - completed;
        if (count > available) count = available;
        memcpy(peer->rx_buf + peer->rx_len, buffer + completed, count);
        peer->rx_len += count;
        completed += count;
        fd_wake_socket_waiters_events(socket->unix_peer_id,
                                      LINUX_POLLIN | LINUX_POLLPRI);
        fd_wake_unix_listener_for_pending_child(socket->unix_peer_id);
    }
    return (int64_t)completed;
}

static int64_t socket_stream_send_kernel(edge_socket_t *socket,
                                         edge_fd_t *descriptor,
                                         const uint8_t *buffer,
                                         uint32_t length) {
    task_t *task = process_current_task();
    uint32_t completed = 0;

    if (!socket || socket->type != LINUX_SOCK_STREAM) return -EINVAL;
    if (!length) return 0;
    if (socket->shutdown_write) return -EPIPE;
    if (socket->domain == LINUX_AF_UNIX ||
        ((socket->domain == LINUX_AF_INET ||
          socket->domain == LINUX_AF_INET6) &&
         !socket->lwip_pcb && socket->unix_peer_id >= 0))
        return socket_buffered_stream_send_kernel(
            socket, descriptor, task, buffer, length);
    if ((socket->domain != LINUX_AF_INET &&
         socket->domain != LINUX_AF_INET6) || !socket->lwip_pcb)
        return -EINVAL;
    if (!socket->connected) return -ENOTCONN;

    while (completed < length) {
        struct tcp_pcb *tcp;
        uint16_t count = (uint16_t)(length - completed > 0xffffu ?
                                   0xffffu : length - completed);
        err_t error;
        lwip_stack_core_enter();
        tcp = (struct tcp_pcb *)socket->lwip_pcb;
        if (!tcp) {
            lwip_stack_core_exit();
            return completed ? (int64_t)completed : -EPIPE;
        }
        if (count > tcp_sndbuf(tcp)) count = tcp_sndbuf(tcp);
        if (!count) {
            lwip_stack_core_exit();
            if (completed) return (int64_t)completed;
            if ((descriptor && (descriptor->flags & LINUX_O_NONBLOCK)) ||
                socket->nonblock)
                return -EAGAIN;
            if (signal_pending_interrupt())
                return (int64_t)tty_interrupt_current_ret();
            if (descriptor && task)
                socket_waiter_add(descriptor->pipe_id, task->pid,
                                  LINUX_POLLOUT | LINUX_POLLWRNORM);
            lwip_stack_poll();
            lwip_stack_core_enter();
            tcp = (struct tcp_pcb *)socket->lwip_pcb;
            if (tcp && tcp_sndbuf(tcp)) {
                lwip_stack_core_exit();
                if (task) waiter_remove_pid(task->pid);
                continue;
            }
            lwip_stack_core_exit();
            if (!tcp)
                return completed ? (int64_t)completed : -EPIPE;
            socket_blocking_wait_step(0);
            continue;
        }
        error = tcp_write(tcp, buffer + completed, count,
                          TCP_WRITE_FLAG_COPY);
        if (error == ERR_MEM) {
            lwip_stack_core_exit();
            continue;
        }
        if (error != ERR_OK) {
            lwip_stack_core_exit();
            return completed ? (int64_t)completed :
                -lwip_err_to_linux_errno((int)error);
        }
        completed += count;
        error = tcp_output(tcp);
        lwip_stack_core_exit();
        if (error != ERR_OK)
            return completed ? (int64_t)completed :
                -lwip_err_to_linux_errno((int)error);
    }
    return (int64_t)completed;
}

int64_t arch_socket_create_descriptor(uint32_t domain_u, uint32_t type_u,
                                      uint32_t protocol_u,
                                      uint32_t flags) {
    int domain = (int)domain_u;
    int type = (int)type_u;
    int protocol = (int)protocol_u;
    int cloexec = flags & LINUX_SOCK_CLOEXEC;
    int nonblock = flags & LINUX_SOCK_NONBLOCK;

    edge_fd_proc_t *p = fd_proc_with_stdio();
    if (!p) return (uint64_t)-ENOMEM;
    int fd = fd_alloc(p, 0);
    if (fd < 0) return -EMFILE;
    int sid = socket_alloc();
    if (sid < 0) {
        fd_abort_reserved(p, fd);
        return (uint64_t)-ENOMEM;
    }

    edge_socket_t *s = &g_sockets[sid];
    if (lwip_stack_is_ready() &&
        (domain == LINUX_AF_INET || domain == LINUX_AF_INET6) &&
        type == LINUX_SOCK_DGRAM &&
        (protocol == 0 || protocol == LINUX_IPPROTO_UDP)) {
        struct udp_pcb *up;

        lwip_stack_core_enter();
        up = udp_new_ip_type(
            domain == LINUX_AF_INET6 ? IPADDR_TYPE_V6 : IPADDR_TYPE_V4);
        if (!up) {
            lwip_stack_core_exit();
            fd_abort_reserved(p, fd);
            memset(s, 0, sizeof(*s));
            return (uint64_t)((domain == LINUX_AF_INET6) ? -EAFNOSUPPORT : -ENOMEM);
        }
        udp_recv(up, edge_udp_recv_cb, s);
        s->lwip_pcb = up;
        lwip_stack_core_exit();
    } else if (lwip_stack_is_ready() &&
               (domain == LINUX_AF_INET || domain == LINUX_AF_INET6) &&
               type == LINUX_SOCK_STREAM &&
               (protocol == 0 || protocol == LINUX_IPPROTO_TCP)) {
        struct tcp_pcb *tp;

        lwip_stack_core_enter();
        tp = tcp_new_ip_type(
            domain == LINUX_AF_INET6 ? IPADDR_TYPE_V6 : IPADDR_TYPE_V4);
        if (!tp) {
            lwip_stack_core_exit();
            fd_abort_reserved(p, fd);
            memset(s, 0, sizeof(*s));
            return (uint64_t)((domain == LINUX_AF_INET6) ? -EAFNOSUPPORT : -ENOMEM);
        }
        tcp_arg(tp, s);
        tcp_recv(tp, edge_tcp_recv_cb);
        tcp_err(tp, edge_tcp_err_cb);
        tcp_sent(tp, edge_tcp_sent_cb);
        s->lwip_pcb = tp;
        lwip_stack_core_exit();
    }
    s->domain = domain;
    s->type = type;
    s->protocol = protocol;
    kernel_socket_option_state_initialize(
        &s->option_state, EDGE_SOCKET_RX_BUF_SIZE);
    if (domain == LINUX_AF_PACKET) {
        int packet_handle = edge_linux_packet_socket_create(
            (uint32_t)type, (uint16_t)protocol);
        if (packet_handle < 0) {
            socket_drop_ref(sid);
            fd_abort_reserved(p, fd);
            return (uint64_t)(int64_t)packet_handle;
        }
        s->packet_handle = packet_handle;
        __atomic_store_n(
            &s->external_readiness.packet_ring_sequence,
            edge_linux_packet_ring_readiness_sequence(packet_handle),
            __ATOMIC_RELEASE);
    }
    s->nonblock = nonblock ? 1 : 0;
    s->ip_ttl = 64;
    s->ip_mtu_discover = LINUX_IP_PMTUDISC_WANT;
    s->tcp_keepidle_sec = 7200;
    s->tcp_keepintvl_sec = 75;
    s->tcp_keepcnt = 9;
    s->unix_peer_id = -1;
    if (process_current_task())
        s->network_namespace = process_current_task()->namespaces.net;
    socket_apply_ip_pcb_options(s);
    socket_set_cred_from_task(s, process_current_task());
    p->fds[fd].kind = FD_SOCKET;
    p->fds[fd].file_ref = file_ref_alloc(
        LINUX_O_RDWR | (nonblock ? LINUX_O_NONBLOCK : 0));
    if (!p->fds[fd].file_ref) {
        socket_drop_ref(sid);
        fd_abort_reserved(p, fd);
        return (uint64_t)-ENFILE;
    }
    p->fds[fd].pipe_id = sid;
    p->fds[fd].flags = LINUX_O_RDWR | (nonblock ? LINUX_O_NONBLOCK : 0);
    p->fds[fd].fd_flags = cloexec ? LINUX_FD_CLOEXEC : 0;
    if (fd_publish(p, fd) < 0) {
        (void)file_ref_put(p->fds[fd].file_ref);
        socket_drop_ref(sid);
        fd_abort_reserved(p, fd);
        return (uint64_t)-EBADF;
    }
    return (uint64_t)fd;
}

static int x86_fd_publication_publish(
    void *context, const int32_t *descriptors, uint32_t count) {
    edge_fd_proc_t *process = (edge_fd_proc_t *)context;
    uint32_t batch[2];
    uint64_t irq_flags;
    int result;

    if (!process || !descriptors || !count ||
        count > sizeof(batch) / sizeof(batch[0]))
        return -EINVAL;
    for (uint32_t index = 0; index < count; ++index) {
        if (descriptors[index] < 0 ||
            descriptors[index] >= EDGE_MAX_FD)
            return -EBADF;
        batch[index] = (uint32_t)descriptors[index];
    }

    irq_flags = kernel_fd_table_lock(&process->table_runtime);
    for (uint32_t index = 0; index < count; ++index) {
        uint32_t descriptor = batch[index];

        if (kernel_fd_table_state_locked(
                &process->table_runtime, descriptor) !=
                KERNEL_FD_SLOT_RESERVED ||
            process->fds[descriptor].file_ref <= 0 ||
            __atomic_load_n(
                &process->fds[descriptor].used, __ATOMIC_ACQUIRE)) {
            kernel_fd_table_unlock(
                &process->table_runtime, irq_flags);
            return -EINVAL;
        }
    }
    result = kernel_fd_table_publish_batch_locked(
        &process->table_runtime, batch, count);
    if (result == 0) {
        /*
         * Normal lookup observes slot state and payload publication under the
         * same table lock; the batch state transition cannot partially commit.
         */
        for (uint32_t index = 0; index < count; ++index) {
            edge_fd_t *entry = &process->fds[batch[index]];

            __atomic_store_n(&entry->used, 1, __ATOMIC_RELEASE);
            fd_async_input_watch_update(entry);
        }
    }
    kernel_fd_table_unlock(&process->table_runtime, irq_flags);
    return result;
}

static void x86_fd_publication_abort(
    void *context, const int32_t *descriptors, uint32_t count) {
    edge_fd_proc_t *process = (edge_fd_proc_t *)context;
    edge_fd_t detached[2];
    uint32_t batch[2];
    uint64_t irq_flags;
    int result;

    if (!process || !descriptors || !count ||
        count > sizeof(batch) / sizeof(batch[0]))
        return;
    for (uint32_t index = 0; index < count; ++index) {
        if (descriptors[index] < 0 ||
            descriptors[index] >= EDGE_MAX_FD)
            return;
        batch[index] = (uint32_t)descriptors[index];
    }

    memset(detached, 0, sizeof(detached));
    irq_flags = kernel_fd_table_lock(&process->table_runtime);
    for (uint32_t index = 0; index < count; ++index) {
        uint32_t descriptor = batch[index];

        if (kernel_fd_table_state_locked(
                &process->table_runtime, descriptor) !=
                KERNEL_FD_SLOT_RESERVED ||
            __atomic_load_n(
                &process->fds[descriptor].used, __ATOMIC_ACQUIRE)) {
            kernel_fd_table_unlock(
                &process->table_runtime, irq_flags);
            return;
        }
        detached[index] = process->fds[descriptor];
    }
    result = kernel_fd_table_cancel_batch_locked(
        &process->table_runtime, batch, count);
    if (result == 0) {
        /*
         * Detach every payload while all slots are still serialized, then
         * release OFD and backing-object references after dropping the lock.
         */
        for (uint32_t index = 0; index < count; ++index)
            memset(&process->fds[batch[index]], 0,
                   sizeof(process->fds[batch[index]]));
    }
    kernel_fd_table_unlock(&process->table_runtime, irq_flags);
    if (result < 0)
        return;

    for (uint32_t index = 0; index < count; ++index) {
        if (detached[index].file_ref > 0) {
            detached[index].used = 1;
            (void)fd_release_entry(&detached[index], 0, 0, 0);
        } else if (detached[index].kind != FD_NONE) {
            /*
             * Construction can fail after a backing object is attached but
             * before its open-file description exists.  The empty RESERVED
             * slot still owns that backing reference and abort must release it.
             */
            detached[index].used = 1;
            fd_drop_backing_object(&detached[index]);
        }
    }
}

static int x86_fd_publication_acquire(
        void *context, int32_t descriptor, void *storage) {
    edge_fd_proc_t *process = (edge_fd_proc_t *)context;
    edge_fd_t *snapshot = (edge_fd_t *)storage;
    uint64_t irq_flags;
    int result = 0;

    if (!process || !snapshot || descriptor < 0 ||
        descriptor >= EDGE_MAX_FD)
        return -EBADF;
    memset(snapshot, 0, sizeof(*snapshot));
    irq_flags = kernel_fd_table_lock(&process->table_runtime);
    if (kernel_fd_table_state_locked(
            &process->table_runtime, (uint32_t)descriptor) !=
            KERNEL_FD_SLOT_RESERVED ||
        __atomic_load_n(
            &process->fds[descriptor].used, __ATOMIC_ACQUIRE) ||
        process->fds[descriptor].file_ref <= 0) {
        result = -EBADF;
    } else {
        *snapshot = process->fds[descriptor];
        snapshot->used = 1;
        if (file_ref_get(snapshot->file_ref) < 0) {
            result = -ENOMEM;
        } else if (fd_add_backing_object(snapshot) < 0) {
            (void)file_ref_put(snapshot->file_ref);
            result = -EBADF;
        }
    }
    kernel_fd_table_unlock(&process->table_runtime, irq_flags);
    if (result < 0) memset(snapshot, 0, sizeof(*snapshot));
    return result;
}

static int x86_fd_publication_initialize(
    edge_fd_proc_t *process, const int32_t *descriptors, uint32_t count,
    kernel_fd_publication_t *publication) {
    int result = kernel_fd_publication_initialize(
        publication, descriptors, count, process,
        x86_fd_publication_publish, x86_fd_publication_abort);

    if (result == 0)
        result = kernel_fd_publication_set_acquire(
            publication, x86_fd_publication_acquire);
    if (result < 0)
        x86_fd_publication_abort(process, descriptors, count);
    return result;
}

static int x86_socket_pair_publication_matches(
    edge_fd_proc_t *process, const int32_t descriptors[2],
    const kernel_fd_publication_t *publication, int require_empty) {
    uint64_t irq_flags;
    int result = 0;

    if (!process || !descriptors || !publication ||
        !publication->active || publication->context != process ||
        publication->descriptors != descriptors ||
        publication->count != 2u)
        return -EINVAL;
    if (descriptors[0] < 0 || descriptors[0] >= EDGE_MAX_FD ||
        descriptors[1] < 0 || descriptors[1] >= EDGE_MAX_FD ||
        descriptors[0] == descriptors[1])
        return -EBADF;

    irq_flags = kernel_fd_table_lock(&process->table_runtime);
    for (uint32_t index = 0; index < 2u; ++index) {
        edge_fd_t *entry = &process->fds[descriptors[index]];

        if (kernel_fd_table_state_locked(
                &process->table_runtime,
                (uint32_t)descriptors[index]) !=
                KERNEL_FD_SLOT_RESERVED ||
            __atomic_load_n(&entry->used, __ATOMIC_ACQUIRE) ||
            (require_empty &&
             (entry->kind != FD_NONE || entry->file_ref != 0))) {
            result = -EINVAL;
            break;
        }
    }
    kernel_fd_table_unlock(&process->table_runtime, irq_flags);
    return result;
}

int arch_socket_create_unix_pair_prepare(
    int32_t descriptors[2],
    kernel_fd_publication_t *publication) {
    edge_fd_proc_t *process;
    uint32_t numbers[2] = {0, 0};
    uint32_t reserved = 0;
    uint64_t irq_flags;
    int result;

    process = fd_proc_with_stdio();
    if (!process) return -ENOMEM;

    irq_flags = kernel_fd_table_lock(&process->table_runtime);
    result = kernel_fd_table_reserve_batch_below_locked(
        &process->table_runtime, 0, fd_current_allocation_limit(),
        numbers, 2u, &reserved);
    if (result == 0 && reserved != 2u)
        result = -EMFILE;
    if (result < 0 && reserved)
        (void)kernel_fd_table_cancel_batch_locked(
            &process->table_runtime, numbers, reserved);
    if (result == 0) {
        memset(&process->fds[numbers[0]], 0,
               sizeof(process->fds[numbers[0]]));
        memset(&process->fds[numbers[1]], 0,
               sizeof(process->fds[numbers[1]]));
    }
    kernel_fd_table_unlock(&process->table_runtime, irq_flags);
    if (result < 0) return result;

    descriptors[0] = (int32_t)numbers[0];
    descriptors[1] = (int32_t)numbers[1];
    result = x86_fd_publication_initialize(
        process, descriptors, 2u, publication);
    if (result < 0) {
        descriptors[0] = -1;
        descriptors[1] = -1;
    }
    return result;
}

int arch_socket_create_unix_pair_construct(
    uint32_t type_u, uint32_t flags, const int32_t descriptors[2],
    const kernel_fd_publication_t *publication) {
    edge_fd_proc_t *process =
        publication ? (edge_fd_proc_t *)publication->context : 0;
    edge_fd_t prepared[2];
    edge_socket_t *first_socket;
    edge_socket_t *second_socket;
    uint64_t irq_flags;
    int first_socket_id;
    int second_socket_id;
    int first_description;
    int second_description;
    int type = (int)type_u;
    int nonblock = (flags & LINUX_SOCK_NONBLOCK) != 0;
    int result;

    result = x86_socket_pair_publication_matches(
        process, descriptors, publication, 1);
    if (result < 0) return result;

    first_socket_id = socket_alloc();
    if (first_socket_id < 0) return -ENOMEM;
    second_socket_id = socket_alloc();
    if (second_socket_id < 0) {
        socket_drop_ref(first_socket_id);
        return -ENOMEM;
    }

    first_socket = &g_sockets[first_socket_id];
    second_socket = &g_sockets[second_socket_id];
    first_socket->domain = LINUX_AF_UNIX;
    first_socket->type = type;
    first_socket->protocol = 0;
    kernel_socket_option_state_initialize(
        &first_socket->option_state, EDGE_SOCKET_RX_BUF_SIZE);
    first_socket->nonblock = nonblock ? 1 : 0;
    first_socket->connected = 1;
    first_socket->ip_ttl = 64;
    first_socket->ip_mtu_discover = LINUX_IP_PMTUDISC_WANT;
    first_socket->tcp_keepidle_sec = 7200;
    first_socket->tcp_keepintvl_sec = 75;
    first_socket->tcp_keepcnt = 9;
    first_socket->unix_peer_id = second_socket_id;
    socket_set_cred_from_task(first_socket, process_current_task());
    second_socket->domain = LINUX_AF_UNIX;
    second_socket->type = type;
    second_socket->protocol = 0;
    kernel_socket_option_state_initialize(
        &second_socket->option_state, EDGE_SOCKET_RX_BUF_SIZE);
    second_socket->nonblock = nonblock ? 1 : 0;
    second_socket->connected = 1;
    second_socket->ip_ttl = 64;
    second_socket->ip_mtu_discover = LINUX_IP_PMTUDISC_WANT;
    second_socket->tcp_keepidle_sec = 7200;
    second_socket->tcp_keepintvl_sec = 75;
    second_socket->tcp_keepcnt = 9;
    second_socket->unix_peer_id = first_socket_id;
    socket_set_cred_from_task(second_socket, process_current_task());
    socket_set_peer_cred(first_socket, second_socket);
    socket_set_peer_cred(second_socket, first_socket);

    first_description = file_ref_alloc(
        LINUX_O_RDWR | (nonblock ? LINUX_O_NONBLOCK : 0));
    if (!first_description) {
        socket_drop_ref(first_socket_id);
        socket_drop_ref(second_socket_id);
        return -ENFILE;
    }
    second_description = file_ref_alloc(
        LINUX_O_RDWR | (nonblock ? LINUX_O_NONBLOCK : 0));
    if (!second_description) {
        (void)file_ref_put(first_description);
        socket_drop_ref(first_socket_id);
        socket_drop_ref(second_socket_id);
        return -ENFILE;
    }

    memset(prepared, 0, sizeof(prepared));
    prepared[0].kind = FD_SOCKET;
    prepared[0].file_ref = first_description;
    prepared[0].flags =
        LINUX_O_RDWR | (nonblock ? LINUX_O_NONBLOCK : 0);
    prepared[0].fd_flags =
        (flags & LINUX_SOCK_CLOEXEC) ? LINUX_FD_CLOEXEC : 0;
    prepared[0].pipe_id = first_socket_id;
    prepared[1].kind = FD_SOCKET;
    prepared[1].file_ref = second_description;
    prepared[1].flags =
        LINUX_O_RDWR | (nonblock ? LINUX_O_NONBLOCK : 0);
    prepared[1].fd_flags =
        (flags & LINUX_SOCK_CLOEXEC) ? LINUX_FD_CLOEXEC : 0;
    prepared[1].pipe_id = second_socket_id;

    irq_flags = kernel_fd_table_lock(&process->table_runtime);
    result = 0;
    for (uint32_t index = 0; index < 2u; ++index) {
        edge_fd_t *entry = &process->fds[descriptors[index]];

        if (kernel_fd_table_state_locked(
                &process->table_runtime,
                (uint32_t)descriptors[index]) !=
                KERNEL_FD_SLOT_RESERVED ||
            __atomic_load_n(&entry->used, __ATOMIC_ACQUIRE) ||
            entry->kind != FD_NONE || entry->file_ref != 0) {
            result = -EINVAL;
            break;
        }
    }
    if (result == 0) {
        process->fds[descriptors[0]] = prepared[0];
        process->fds[descriptors[1]] = prepared[1];
    }
    kernel_fd_table_unlock(&process->table_runtime, irq_flags);
    if (result < 0) {
        (void)file_ref_put(first_description);
        (void)file_ref_put(second_description);
        socket_drop_ref(first_socket_id);
        socket_drop_ref(second_socket_id);
    }
    return result;
}

static int x86_socket_describe_entry(
    const edge_fd_t *entry, kernel_socket_descriptor_info_t *info) {
    edge_socket_t *socket;

    if (!info) return -EINVAL;
    if (!entry) return -EBADF;
    if (entry->kind != FD_SOCKET) return -ENOTSOCK;
    socket = socket_from_fd_entry(entry);
    if (!socket) return -ENOTSOCK;
    memset(info, 0, sizeof(*info));
    info->domain = (uint32_t)socket->domain;
    info->type = (uint32_t)socket->type;
    info->protocol = (uint32_t)socket->protocol;
    info->connected = socket->connected ? 1u : 0u;
    info->listening = socket->listening ? 1u : 0u;
    return 0;
}

static int64_t x86_socket_bind_entry(
    int32_t diagnostic_fd, edge_fd_t *fde,
    const kernel_socket_address_t *address) {
    static uint32_t unix_autobind_sequence = 1;
    edge_socket_t *s = socket_from_fd_entry(fde);
    kernel_socket_address_t normalized;
    uint32_t len;
    struct edge_sockaddr_in sin;
    struct edge_sockaddr_in6 sin6;
    char unix_path[EDGE_UNIX_BINDING_KEY_SIZE];
    vfs_inode_t ino;
    if (!fde) return -EBADF;
    if (!s) return -ENOTSOCK;
    if (!address || !address->length ||
        address->length > sizeof(address->bytes))
        return -EINVAL;
    normalized = *address;
    len = normalized.length;
    if (s->bind_len > 0) return -EINVAL;
    if (s->domain == LINUX_AF_UNIX) {
        int rc;
        int abstract;
        if (!(s->type == LINUX_SOCK_STREAM || s->type == LINUX_SOCK_DGRAM ||
              s->type == LINUX_SOCK_SEQPACKET)) {
            return -EOPNOTSUPP;
        }
        if (len == sizeof(uint16_t)) {
            uint32_t attempts = 0;
            do {
                uint32_t value = unix_autobind_sequence++ & 0xfffffu;
                static const char digits[] = "0123456789abcdef";
                memset(&normalized, 0, sizeof(normalized));
                normalized.bytes[0] = LINUX_AF_UNIX;
                normalized.bytes[2] = 0;
                for (uint32_t index = 0; index < 5u; ++index)
                    normalized.bytes[3u + index] =
                        (uint8_t)digits[(value >> ((4u - index) * 4u)) & 15u];
                normalized.length = 8u;
                len = normalized.length;
                if (sockaddr_un_path_from_buf(
                        normalized.bytes, len, unix_path,
                        sizeof(unix_path)) < 0)
                    return -EINVAL;
                ++attempts;
            } while (unix_binding_find_path(unix_path) >= 0 &&
                     attempts < 0x100000u);
        } else if (sockaddr_un_path_from_buf(
                       normalized.bytes, len, unix_path,
                       sizeof(unix_path)) < 0) {
            return -EAFNOSUPPORT;
        }
        abstract = unix_binding_key_is_abstract(unix_path);
        x11_unix_trace_binding(
            "bind-enter", unix_path, diagnostic_fd,
            fde ? fde->pipe_id : -1, 0);
        if (unix_binding_find_path(unix_path) >= 0) {
            x11_unix_trace_binding(
                "bind-busy", unix_path, diagnostic_fd,
                fde ? fde->pipe_id : -1, -EADDRINUSE);
            return -EADDRINUSE;
        }
        if (!abstract) {
            if (vfs_resolve(unix_path, &ino, 0, 0, 0) == 0)
                return -EADDRINUSE;
            if (vfs_create_socket_node(
                    unix_path,
                    (uint16_t)(0777u & ~kernel_current_umask())) < 0) {
                x11_unix_trace_binding(
                    "bind-create-fail", unix_path, diagnostic_fd,
                    fde ? fde->pipe_id : -1, -ENOENT);
                return -ENOENT;
            }
        }
        if (!abstract) {
            uint32_t path_bytes = len - sizeof(uint16_t);
            for (uint32_t index = 0; index < path_bytes; ++index) {
                if (normalized.bytes[sizeof(uint16_t) + index] == 0) {
                    normalized.length = sizeof(uint16_t) + index + 1u;
                    break;
                }
            }
        }
        memcpy(s->bind_addr, normalized.bytes, normalized.length);
        s->bind_len = normalized.length;
        if (!abstract) {
            strncpy(fde->path, unix_path, sizeof(fde->path) - 1);
            fde->path[sizeof(fde->path) - 1] = 0;
        }
        rc = unix_binding_register(unix_path, fde ? fde->pipe_id : -1);
        if (rc < 0) {
            s->bind_len = 0;
            if (!abstract) (void)vfs_unlink(unix_path);
        }
        x11_unix_trace_binding(
            "bind-ret", unix_path, diagnostic_fd,
            fde ? fde->pipe_id : -1, rc);
        return rc;
    }
    if (s->domain == LINUX_AF_NETLINK) {
        struct edge_sockaddr_nl nl;
        int rc;
        if (len < sizeof(nl)) return -EINVAL;
        memcpy(&nl, normalized.bytes, sizeof(nl));
        if (nl.nl_family != LINUX_AF_NETLINK || nl.nl_pad != 0)
            return -EINVAL;
        rc = netlink_bind_port(s, nl.nl_pid, nl.nl_groups);
        if (rc < 0) return rc;
        nl.nl_pid = s->netlink_port_id;
        memcpy(s->bind_addr, &nl, sizeof(nl));
        s->bind_len = sizeof(nl);
        return 0;
    }
    if (s->domain == LINUX_AF_PACKET) {
        struct edge_linux_sockaddr_ll link;
        int result;
        if (len < sizeof(link)) return -EINVAL;
        memcpy(&link, normalized.bytes, sizeof(link));
        if (link.sll_family != LINUX_AF_PACKET)
            return -EAFNOSUPPORT;
        result = edge_linux_packet_socket_bind(
            s->packet_handle, s->network_namespace,
            link.sll_ifindex, link.sll_protocol);
        if (result < 0) return result;
        memcpy(s->bind_addr, &link, sizeof(link));
        s->bind_len = sizeof(link);
        s->ifindex = link.sll_ifindex;
        if (link.sll_protocol) s->protocol = link.sll_protocol;
        return 0;
    }
    if (s->domain == LINUX_AF_INET && len >= sizeof(sin)) {
        uint32_t transport_address;

        memcpy(&sin, normalized.bytes, sizeof(sin));
        if (sin.sin_family != LINUX_AF_INET) return -EAFNOSUPPORT;
        if (sin.sin_port == 0) sin.sin_port = socket_alloc_ephemeral_port_be();
        transport_address = sin.sin_addr;
        if (!transport_address && s->network_namespace)
            (void)edge_linux_rtnetlink_ipv4_primary(
                s->network_namespace, &transport_address);
        if (s->type == LINUX_SOCK_DGRAM && s->lwip_pcb) {
            struct udp_pcb *up = (struct udp_pcb *)s->lwip_pcb;
            ip_addr_t bind_ip;
            const ip_addr_t *ip = &bind_ip;
            ip_addr_set_zero_ip4(&bind_ip);
            if (transport_address != 0) {
                ip_2_ip4(&bind_ip)->addr = transport_address;
            }
            err_t berr = EDGE_LWIP_CALL(
                udp_bind(up, ip, edge_bswap16(sin.sin_port)));
            if (berr != ERR_OK) {
                if (berr == ERR_USE) return -EADDRINUSE;
                if (berr == ERR_MEM || berr == ERR_BUF) return -ENOMEM;
                return -EADDRNOTAVAIL;
            }
            s->local_port_be = sin.sin_port;
        } else if (s->type == LINUX_SOCK_STREAM && s->lwip_pcb) {
            struct tcp_pcb *tp = (struct tcp_pcb *)s->lwip_pcb;
            ip_addr_t bind_ip;
            const ip_addr_t *ip = &bind_ip;
            ip_addr_set_zero_ip4(&bind_ip);
            if (transport_address != 0) {
                ip_2_ip4(&bind_ip)->addr = transport_address;
            }
            err_t berr = EDGE_LWIP_CALL(
                tcp_bind(tp, ip, edge_bswap16(sin.sin_port)));
            if (berr != ERR_OK) {
                if (berr == ERR_USE) return -EADDRINUSE;
                if (berr == ERR_MEM || berr == ERR_BUF) return -ENOMEM;
                return -EADDRNOTAVAIL;
            }
            s->local_port_be = sin.sin_port;
        }
        socket_set_bind_inet(s, sin.sin_addr, sin.sin_port);
    } else if (s->domain == LINUX_AF_INET6 && len >= sizeof(sin6)) {
        ip_addr_t transport_ip;
        uint32_t transport_address = 0;
        int any = 1;

        memcpy(&sin6, normalized.bytes, sizeof(sin6));
        if (sin6.sin6_family != LINUX_AF_INET6) return -EAFNOSUPPORT;
        if (sin6.sin6_port == 0) sin6.sin6_port = socket_alloc_ephemeral_port_be();
        for (int i = 0; i < 16; ++i) {
            if (sin6.sin6_addr[i] != 0) {
                any = 0;
                break;
            }
        }
        ip_addr_set_zero_ip6(&transport_ip);
        if (any && s->network_namespace &&
            edge_linux_rtnetlink_ipv4_primary(
                s->network_namespace, &transport_address) == 0) {
            ip_addr_set_ip4_u32(&transport_ip, transport_address);
        } else if (!any) {
            memcpy(&ip_2_ip6(&transport_ip)->addr[0], sin6.sin6_addr, 16);
        }
        if (s->type == LINUX_SOCK_DGRAM && s->lwip_pcb) {
            struct udp_pcb *up = (struct udp_pcb *)s->lwip_pcb;
            err_t berr = EDGE_LWIP_CALL(udp_bind(
                up, &transport_ip, edge_bswap16(sin6.sin6_port)));
            if (berr != ERR_OK) {
                if (berr == ERR_USE) return -EADDRINUSE;
                if (berr == ERR_MEM || berr == ERR_BUF) return -ENOMEM;
                return -EADDRNOTAVAIL;
            }
            s->local_port_be = sin6.sin6_port;
        } else if (s->type == LINUX_SOCK_STREAM && s->lwip_pcb) {
            struct tcp_pcb *tp = (struct tcp_pcb *)s->lwip_pcb;
            err_t berr = EDGE_LWIP_CALL(tcp_bind(
                tp, &transport_ip, edge_bswap16(sin6.sin6_port)));
            if (berr != ERR_OK) {
                if (berr == ERR_USE) return -EADDRINUSE;
                if (berr == ERR_MEM || berr == ERR_BUF) return -ENOMEM;
                return -EADDRNOTAVAIL;
            }
            s->local_port_be = sin6.sin6_port;
        }
        socket_set_bind_inet6(s, sin6.sin6_addr, sin6.sin6_port, sin6.sin6_scope_id);
    } else {
        return -EAFNOSUPPORT;
    }
    return 0;
}

uint32_t arch_socket_netlink_payload_capacity(void) {
    return EDGE_RUNTIME_NETLINK_BUFFER_SIZE;
}

uint32_t arch_socket_netlink_endpoint_count(void) {
    return EDGE_MAX_SOCKETS;
}

int arch_socket_netlink_endpoint_view(
    uint32_t index, kernel_socket_netlink_endpoint_t *endpoint) {
    edge_socket_t *socket;

    if (!endpoint) return -EFAULT;
    if (index >= EDGE_MAX_SOCKETS) return -EINVAL;
    socket = &g_sockets[index];
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->identity = (int32_t)index;
    if (!socket->used || socket->domain != LINUX_AF_NETLINK)
        return 0;
    endpoint->active = 1;
    endpoint->protocol = (uint32_t)socket->protocol;
    endpoint->port_id = socket->netlink_port_id;
    endpoint->groups = socket->netlink_groups;
    endpoint->network_namespace = socket->network_namespace;
    return 0;
}

int arch_socket_netlink_sender_inspect(
    int32_t descriptor, uint32_t protocol,
    kernel_socket_netlink_source_t *source) {
    edge_socket_t *sender = socket_from_fd(descriptor);
    task_t *current = process_current_task();

    if (!source) return -EFAULT;
    if (!sender) return -EBADF;
    if (sender->domain != LINUX_AF_NETLINK) return -ENOTSOCK;
    if ((uint32_t)sender->protocol != protocol) return -EPROTONOSUPPORT;
    memset(source, 0, sizeof(*source));
    source->process_id = current ?
        (current->tgid > 0 ? current->tgid : current->pid) : 0;
    source->user_id = current ? current->euid : 0;
    source->group_id = current ? current->egid : 0;
    source->network_namespace = sender->network_namespace;
    source->endpoint_identity = socket_id_from_ptr(sender);
    source->backend_cookie = (uintptr_t)sender;
    return 0;
}

int arch_socket_netlink_sender_bind(
    kernel_socket_netlink_source_t *source) {
    edge_socket_t *sender;

    if (!source || !source->backend_cookie) return -EBADF;
    sender = (edge_socket_t *)source->backend_cookie;
    if (netlink_ensure_bound(sender) < 0) return -EADDRINUSE;
    source->port_id = sender->netlink_port_id;
    return 0;
}

int arch_socket_netlink_enqueue(
    uint32_t index, const void *payload, uint32_t length,
    const kernel_socket_netlink_source_t *source) {
    struct edge_sockaddr_nl source_address;
    edge_socket_t *receiver;
    uint32_t capacity;
    uint32_t start;

    if (!source || (!payload && length)) return -EFAULT;
    if (index >= EDGE_MAX_SOCKETS) return -EINVAL;
    receiver = &g_sockets[index];
    capacity = socket_rx_capacity(receiver);
    if (!receiver->used || receiver->domain != LINUX_AF_NETLINK)
        return -ENOTSOCK;
    if (receiver->packet_count >= EDGE_SOCKET_PACKET_QUEUE ||
        length > capacity || receiver->rx_len > capacity - length)
        return -ENOBUFS;
    memset(&source_address, 0, sizeof(source_address));
    source_address.nl_family = LINUX_AF_NETLINK;
    source_address.nl_pid = source->port_id;
    source_address.nl_groups = source->groups;
    start = receiver->rx_len;
    if (length) memcpy(receiver->rx_buf + start, payload, length);
    if (source->kernel_originated && length >= 16u) {
        struct edge_linux_nlmsghdr *header =
            (struct edge_linux_nlmsghdr *)(receiver->rx_buf + start);

        if (source->message_type)
            header->nlmsg_type = source->message_type;
        header->nlmsg_flags = 0u;
        header->nlmsg_seq = 0u;
        header->nlmsg_pid = 0u;
    }
    if (socket_packet_push_source(
            receiver, length, &source_address, sizeof(source_address),
            source->process_id, source->user_id, source->group_id, 0) < 0)
        return -ENOBUFS;
    receiver->rx_len = start + length;
    fd_wake_socket_waiters_events(
        (int)index, LINUX_POLLIN | LINUX_POLLPRI);
    return 0;
}

static int64_t x86_socket_connect_entry(
    int32_t diagnostic_fd, const kernel_socket_address_t *address,
    void *user_registers, edge_fd_t *fde) {
    task_t *cur = process_current_task();
    edge_socket_t *s = socket_from_fd_entry(fde);
    uint32_t len;
    uint16_t fam = 0;
    char unix_path[EDGE_UNIX_BINDING_KEY_SIZE];
    vfs_inode_t ino;
    int listener_sid;
    edge_socket_t *listener;
    int child_sid;
    edge_socket_t *child;
    int inet4_was_bound = 0;
    (void)user_registers;
    if (!fde) return -EBADF;
    if (!s) return -ENOTSOCK;
    if (!address || !address->length ||
        address->length > sizeof(address->bytes))
        return -EINVAL;
    len = address->length;
    memcpy(&fam, address->bytes, sizeof(fam));

    if (fam == 0) {
        if (s->type != LINUX_SOCK_DGRAM && s->type != LINUX_SOCK_RAW)
            return -EAFNOSUPPORT;
        if (s->domain == LINUX_AF_UNIX) s->unix_peer_id = -1;
        if ((s->domain == LINUX_AF_INET || s->domain == LINUX_AF_INET6) &&
            s->type == LINUX_SOCK_DGRAM && s->lwip_pcb)
            EDGE_LWIP_DO(
                udp_disconnect((struct udp_pcb *)s->lwip_pcb));
        s->connected = 0;
        s->peer_len = 0;
        s->rx_peer_len = 0;
        return 0;
    }

    if (s->domain == LINUX_AF_UNIX) {
        if (s->type == LINUX_SOCK_DGRAM) {
            int binding;
            if (sockaddr_un_path_from_buf(
                    address->bytes, len, unix_path,
                    sizeof(unix_path)) < 0)
                return -EAFNOSUPPORT;
            binding = unix_binding_find_path(unix_path);
            if (binding < 0) return -ENOENT;
            listener_sid = g_unix_bindings[binding].sock_id;
            if (listener_sid < 0 || listener_sid >= EDGE_MAX_SOCKETS ||
                !g_sockets[listener_sid].used)
                return -ECONNREFUSED;
            if (g_sockets[listener_sid].type != LINUX_SOCK_DGRAM)
                return -EDGE_LINUX_EPROTOTYPE;
            memcpy(s->peer_addr, address->bytes, len);
            s->peer_len = len;
            s->unix_peer_id = listener_sid;
            socket_set_peer_cred(s, &g_sockets[listener_sid]);
            s->connected = 1;
            return 0;
        }
        if (!(s->type == LINUX_SOCK_STREAM || s->type == LINUX_SOCK_SEQPACKET)) {
            return (uint64_t)-EPROTONOSUPPORT;
        }
        if (s->connected) return (uint64_t)-EISCONN;
        /* Only socketpair-backed AF_UNIX streams are supported right now. */
        if (s->unix_peer_id >= 0 && s->unix_peer_id < EDGE_MAX_SOCKETS) {
            if (!g_sockets[s->unix_peer_id].used) return (uint64_t)-ECONNREFUSED;
            s->connected = 1;
            socket_set_peer_cred(s, &g_sockets[s->unix_peer_id]);
            return 0;
        }
        if (sockaddr_un_path_from_buf(
                address->bytes, len, unix_path, sizeof(unix_path)) < 0)
            return (uint64_t)-EAFNOSUPPORT;
        if (!unix_path[0]) return (uint64_t)-EINVAL;
        x11_unix_trace_binding(
            "connect-enter", unix_path, diagnostic_fd,
            fde ? fde->pipe_id : -1, 0);
        if (x11_sockio_trace_task(cur) && g_x11_sock_trace_budget-- > 0) {
            printf("[x11dbg] unix-connect enter pid=%d cmd=%s fd=%d sid=%d path=%s\n",
                   cur->pid, cur->name, diagnostic_fd,
                   fde ? fde->pipe_id : -1, unix_path);
        }
        listener_sid = unix_binding_lookup_listener(unix_path);
        if (listener_sid < 0) {
            x11_unix_trace_binding(
                "connect-miss", unix_path, diagnostic_fd,
                fde ? fde->pipe_id : -1, -ENOENT);
            if (x11_sockio_trace_task(cur) && g_x11_sock_trace_budget-- > 0) {
                printf("[x11dbg] unix-connect miss pid=%d cmd=%s path=%s vfs=%d\n",
                       cur->pid, cur->name, unix_path,
                       (!unix_binding_key_is_abstract(unix_path) &&
                        vfs_resolve(unix_path, &ino, 0, 0, 0) == 0) ? 1 : 0);
            }
            if (!unix_binding_key_is_abstract(unix_path) &&
                vfs_resolve(unix_path, &ino, 0, 0, 0) == 0) return (uint64_t)-ECONNREFUSED;
            return (uint64_t)-ENOENT;
        }
        if (listener_sid < 0 || listener_sid >= EDGE_MAX_SOCKETS) {
            x11_unix_trace_binding(
                "connect-bad-listener", unix_path, diagnostic_fd,
                fde ? fde->pipe_id : -1, -ECONNREFUSED);
            return (uint64_t)-ECONNREFUSED;
        }
        listener = &g_sockets[listener_sid];
        if (!listener->used || listener->domain != LINUX_AF_UNIX ||
            listener->type != s->type || !listener->listening) {
            x11_unix_trace_binding(
                "connect-refused", unix_path, diagnostic_fd,
                listener_sid, -ECONNREFUSED);
            if (x11_sockio_trace_task(cur) && g_x11_sock_trace_budget-- > 0) {
                printf("[x11dbg] unix-connect refused pid=%d cmd=%s ls=%d used=%d listening=%d\n",
                       cur->pid, cur->name, listener_sid, listener->used, listener->listening);
            }
            return (uint64_t)-ECONNREFUSED;
        }
        if (socket_pending_count(listener) >= listener->backlog) {
            x11_unix_trace_binding(
                "connect-backlog", unix_path, diagnostic_fd,
                listener_sid, -EAGAIN);
            if (x11_sockio_trace_task(cur) && g_x11_sock_trace_budget-- > 0) {
                printf("[x11dbg] unix-connect backlog pid=%d cmd=%s ls=%d pending=%d backlog=%d\n",
                       cur->pid, cur->name, listener_sid,
                       socket_pending_count(listener),
                       listener->backlog);
            }
            if ((fde && (fde->flags & LINUX_O_NONBLOCK)) || s->nonblock) {
                gui_connect_backlog_trace(
                    "unix-nonblock", cur, diagnostic_fd,
                    listener, -EAGAIN);
                return (uint64_t)-EAGAIN;
            }
            gui_connect_backlog_trace(
                "unix-blocking", cur, diagnostic_fd,
                listener, -ECONNREFUSED);
            return (uint64_t)-ECONNREFUSED;
        }
        child_sid = socket_alloc();
        if (child_sid < 0) return (uint64_t)-ENOMEM;
        child = &g_sockets[child_sid];
        child->domain = LINUX_AF_UNIX;
        child->type = s->type;
        child->protocol = 0;
        child->ip_ttl = 64;
        child->ip_mtu_discover = LINUX_IP_PMTUDISC_WANT;
        child->tcp_keepidle_sec = 7200;
        child->tcp_keepintvl_sec = 75;
        child->tcp_keepcnt = 9;
        child->connected = 1;
        child->nonblock = 0;
        child->unix_peer_id = fde ? fde->pipe_id : -1;
        child->cred_pid = listener->cred_pid;
        child->cred_uid = listener->cred_uid;
        child->cred_gid = listener->cred_gid;
        socket_set_peer_cred_from_task(child, cur);
        socket_set_peer_cred(s, listener);
        if (listener->bind_len > 0) {
            memcpy(child->bind_addr, listener->bind_addr, listener->bind_len);
            child->bind_len = listener->bind_len;
        }
        if (s->bind_len > 0) {
            memcpy(child->peer_addr, s->bind_addr, s->bind_len);
            child->peer_len = s->bind_len;
            memcpy(child->rx_peer, s->bind_addr, s->bind_len);
            child->rx_peer_len = s->bind_len;
        } else {
            socket_set_peer_unix(child, "");
            socket_set_rx_peer_unix(child, "");
        }
        s->unix_peer_id = child_sid;
        s->connected = 1;
        memcpy(s->peer_addr, listener->bind_addr, listener->bind_len);
        s->peer_len = listener->bind_len;
        if (listener->bind_len > 0) {
            memcpy(s->rx_peer, listener->bind_addr, listener->bind_len);
            s->rx_peer_len = listener->bind_len;
        }
        if (socket_pending_enqueue(listener, child_sid) < 0) {
            s->unix_peer_id = -1;
            s->connected = 0;
            socket_drop_ref(child_sid);
            return (uint64_t)-ECONNREFUSED;
        }
        fd_wake_socket_waiters_events(listener_sid, LINUX_POLLIN | LINUX_POLLPRI);
        x11_unix_trace_binding(
            "connect-ok", unix_path, diagnostic_fd,
            fde ? fde->pipe_id : -1, 0);
        if (x11_sockio_trace_task(cur) && g_x11_sock_trace_budget-- > 0) {
            printf("[x11dbg] unix-connect ok pid=%d cmd=%s fd=%d sid=%d peer=%d child=%d ls=%d pending=%d\n",
                   cur->pid, cur->name, diagnostic_fd,
                   fde ? fde->pipe_id : -1,
                   s->unix_peer_id, child_sid, listener_sid,
                   socket_pending_count(listener));
        }
        if (EDGE_GUI_DEEP_TRACE && xfce_x11_peer_trace_task(cur, s)) {
            printf("[xfce-x11] connect-ok pid=%d cmd=%s fd=%d sid=%d path=%s peer=%d child=%d listener=%d pending=%d\n",
                   cur ? cur->pid : -1, cur ? cur->name : "?",
                   diagnostic_fd, fde ? fde->pipe_id : -1, unix_path,
                   s->unix_peer_id, child_sid, listener_sid,
                   socket_pending_count(listener));
        }
        /*
         * A successful Linux AF_UNIX connect wakes accept/poll waiters on the
         * listening socket.  EdgeOS scheduling is still cooperative, so hand
         * over after queueing the child socket.  X11 clients immediately send
         * their setup packet and then wait for the server; without this wakeup
         * point, a client can park in its reply read while Xorg has not yet
         * run its accept side.
         */
        scheduler_yield();
        return 0;
    }

    if (s->domain == LINUX_AF_INET) {
        inet4_was_bound = s->bind_len >= sizeof(struct edge_sockaddr_in);
        socket_autobind_inet(s);
    }
    if (s->domain == LINUX_AF_INET6) socket_autobind_inet6(s);
    memcpy(s->peer_addr, address->bytes, len);
    /*
     * Stage the complete peer identity before tcp_connect().  A nonblocking
     * connect returns EINPROGRESS before reaching the synchronous completion
     * path, but getpeername() must expose the peer once the transport callback
     * marks the socket connected.  ARM64 follows the same ordering.
     */
    s->peer_len = len;
    if (s->domain == LINUX_AF_INET && len >= sizeof(struct edge_sockaddr_in)) {
        struct edge_sockaddr_in sin;
        if (sockaddr_in_from_buf(s->peer_addr, len, &sin) < 0) return (uint64_t)-EAFNOSUPPORT;
        if (s->type == LINUX_SOCK_STREAM &&
            (s->protocol == 0 || s->protocol == LINUX_IPPROTO_TCP) &&
            socket_ipv4_is_local_be(sin.sin_addr)) {
            struct edge_sockaddr_in local_sin;
            int client_sid = socket_id_from_ptr(s);
            uint16_t local_port_be;
            uint32_t local_addr_be;
            listener_sid = socket_find_ipv4_loopback_listener(
                s, sin.sin_addr, sin.sin_port);
            if (listener_sid < 0 || client_sid < 0) return (uint64_t)-ECONNREFUSED;
            listener = &g_sockets[listener_sid];
            if (socket_pending_count(listener) >=
                listener->backlog) {
                if ((fde && (fde->flags & LINUX_O_NONBLOCK)) || s->nonblock) {
                    gui_connect_backlog_trace(
                        "inet4-loopback-nonblock", cur,
                        diagnostic_fd, listener, -EAGAIN);
                    return (uint64_t)-EAGAIN;
                }
                gui_connect_backlog_trace(
                    "inet4-loopback-blocking", cur,
                    diagnostic_fd, listener, -ECONNREFUSED);
                return (uint64_t)-ECONNREFUSED;
            }

            if (s->bind_len >= sizeof(local_sin) &&
                sockaddr_in_from_buf(s->bind_addr, s->bind_len, &local_sin) == 0) {
                local_port_be = local_sin.sin_port;
                local_addr_be = inet4_was_bound ? local_sin.sin_addr : g_if_lo.ipv4_addr_be;
            } else {
                local_port_be = socket_alloc_ephemeral_port_be();
                local_addr_be = g_if_lo.ipv4_addr_be;
            }
            if (!inet4_was_bound) socket_set_bind_inet(s, local_addr_be, local_port_be);
            s->local_port_be = local_port_be;

            child_sid = socket_alloc();
            if (child_sid < 0) return (uint64_t)-ENOMEM;
            child = &g_sockets[child_sid];
            child->domain = listener->domain;
            child->type = LINUX_SOCK_STREAM;
            child->protocol = LINUX_IPPROTO_TCP;
            socket_copy_ip_options(child, listener);
            child->connected = 1;
            child->nonblock = 0;
            child->network_namespace = listener->network_namespace;
            child->unix_peer_id = client_sid;
            child->local_port_be = sin.sin_port;
            if (listener->domain == LINUX_AF_INET6) {
                uint8_t local6[16];
                uint8_t peer6[16];

                socket_ipv6_address_from_ipv4(local6, sin.sin_addr);
                socket_ipv6_address_from_ipv4(peer6, local_addr_be);
                socket_set_bind_inet6(child, local6, sin.sin_port, 0);
                sockaddr_in6_to_user_peer(
                    child, peer6, local_port_be, 0);
            } else {
                socket_set_bind_inet(child, sin.sin_addr, sin.sin_port);
                sockaddr_in_to_user_peer(
                    child, local_addr_be, local_port_be);
            }
            memcpy(child->peer_addr, child->rx_peer, child->rx_peer_len);
            child->peer_len = child->rx_peer_len;

            s->unix_peer_id = child_sid;
            s->connected = 1;
            memcpy(s->peer_addr, &sin, sizeof(sin));
            s->peer_len = sizeof(sin);
            sockaddr_in_to_user_peer(s, sin.sin_addr, sin.sin_port);
            socket_release_lwip_pcb(s);
            if (socket_pending_enqueue(listener, child_sid) < 0) {
                s->unix_peer_id = -1;
                s->connected = 0;
                socket_drop_ref(child_sid);
                return (uint64_t)-ECONNREFUSED;
            }
            fd_wake_socket_waiters_events(listener_sid, LINUX_POLLIN | LINUX_POLLPRI);
            scheduler_yield();
            return 0;
        }
        if (s->type == LINUX_SOCK_DGRAM &&
            (s->protocol == 0 || s->protocol == LINUX_IPPROTO_UDP) &&
            s->lwip_pcb) {
            struct udp_pcb *up = (struct udp_pcb *)s->lwip_pcb;
            edge_linux_netfilter_tuple_t tuple;
            ip_addr_t dst;
            ip_addr_set_zero_ip4(&dst);
            ip_2_ip4(&dst)->addr = sin.sin_addr;
            memset(&tuple, 0, sizeof(tuple));
            tuple.network_namespace = s->network_namespace;
            tuple.output_ifindex = 2;
            tuple.family = LINUX_AF_INET;
            tuple.protocol = LINUX_IPPROTO_UDP;
            memcpy(tuple.output_interface, "eth0", sizeof("eth0"));
            tuple.source_port = up->local_port;
            tuple.destination_port = edge_bswap16(sin.sin_port);
            if (IP_IS_V4(&up->local_ip)) {
                uint32_t source_address =
                    ip4_addr_get_u32(ip_2_ip4(&up->local_ip));
                memcpy(tuple.source_address, &source_address,
                       sizeof(source_address));
            }
            memcpy(tuple.destination_address, &sin.sin_addr,
                   sizeof(sin.sin_addr));
            if (edge_linux_netfilter_translate_local(
                    &tuple,
                    EDGE_LINUX_NETFILTER_TRANSLATE_DESTINATION) > 0) {
                memcpy(&ip_2_ip4(&dst)->addr,
                       tuple.destination_address,
                       sizeof(ip_2_ip4(&dst)->addr));
            }
            if (s->ifindex > 0 || s->option_state.mark) {
                uint8_t preferred_source[16];

                if (!lwip_stack_select_socket_route(
                        s->network_namespace, LINUX_AF_INET,
                        tuple.source_address, tuple.destination_address,
                        s->option_state.mark, s->ifindex,
                        preferred_source, &tuple.output_ifindex))
                    return (uint64_t)-EHOSTUNREACH;
                if (ip4_addr_isany_val(*ip_2_ip4(&up->local_ip)) &&
                    (preferred_source[0] || preferred_source[1] ||
                     preferred_source[2] || preferred_source[3])) {
                    uint32_t source_address;

                    memcpy(&source_address, preferred_source, 4u);
                    ip_addr_set_ip4_u32(&up->local_ip, source_address);
                    memcpy(tuple.source_address, preferred_source, 4u);
                }
            }
            if (edge_linux_netfilter_translate_local(
                    &tuple,
                    EDGE_LINUX_NETFILTER_TRANSLATE_SOURCE) > 0 &&
                tuple.family == LINUX_AF_INET) {
                uint32_t source_address;

                memcpy(&source_address, tuple.source_address,
                       sizeof(source_address));
                ip_addr_set_ip4_u32(&up->local_ip, source_address);
            }
            socket_apply_ip_pcb_options(s);
            if (EDGE_LWIP_CALL(
                    udp_connect(up, &dst, tuple.destination_port)) != ERR_OK)
                return (uint64_t)-EHOSTUNREACH;
        } else if (s->type == LINUX_SOCK_STREAM &&
                   (s->protocol == 0 || s->protocol == LINUX_IPPROTO_TCP) &&
                   s->lwip_pcb) {
            struct tcp_pcb *tp = (struct tcp_pcb *)s->lwip_pcb;
            edge_linux_netfilter_tuple_t tuple;
            ip_addr_t dst;
            uint64_t start_us = boottime_monotonic_us();
            ip_addr_set_zero_ip4(&dst);
            memset(&tuple, 0, sizeof(tuple));
            tuple.network_namespace = s->network_namespace;
            tuple.output_ifindex = 2;
            tuple.family = LINUX_AF_INET;
            tuple.protocol = LINUX_IPPROTO_TCP;
            memcpy(tuple.output_interface, "eth0", sizeof("eth0"));
            tuple.source_port = tp->local_port;
            tuple.destination_port = edge_bswap16(sin.sin_port);
            if (IP_IS_V4(&tp->local_ip)) {
                uint32_t source_address =
                    ip4_addr_get_u32(ip_2_ip4(&tp->local_ip));

                memcpy(tuple.source_address, &source_address,
                       sizeof(source_address));
            }
            memcpy(tuple.destination_address, &sin.sin_addr,
                   sizeof(sin.sin_addr));
            (void)edge_linux_netfilter_translate_local(
                &tuple, EDGE_LINUX_NETFILTER_TRANSLATE_DESTINATION);
            if (s->ifindex > 0 || s->option_state.mark) {
                uint8_t preferred_source[16];

                if (!lwip_stack_select_socket_route(
                        s->network_namespace, LINUX_AF_INET,
                        tuple.source_address, tuple.destination_address,
                        s->option_state.mark, s->ifindex,
                        preferred_source, &tuple.output_ifindex))
                    return (uint64_t)-EHOSTUNREACH;
                if (ip4_addr_isany_val(*ip_2_ip4(&tp->local_ip)) &&
                    (preferred_source[0] || preferred_source[1] ||
                     preferred_source[2] || preferred_source[3])) {
                    uint32_t source_address;

                    memcpy(&source_address, preferred_source, 4u);
                    ip_addr_set_ip4_u32(&tp->local_ip, source_address);
                    memcpy(tuple.source_address, preferred_source, 4u);
                }
            }
            if (edge_linux_netfilter_translate_local(
                    &tuple,
                    EDGE_LINUX_NETFILTER_TRANSLATE_SOURCE) > 0) {
                uint32_t source_address;

                memcpy(&source_address, tuple.source_address,
                       sizeof(source_address));
                ip_addr_set_ip4_u32(&tp->local_ip, source_address);
            }
            memcpy(&ip_2_ip4(&dst)->addr,
                   tuple.destination_address,
                   sizeof(ip_2_ip4(&dst)->addr));
            s->connect_in_progress = 1;
            s->connect_error = 0;
            s->connect_start_us = start_us;
            s->rx_closed = 0;
            s->tcp_fin_pending = 0;
            s->closed = 0;
            s->rx_len = 0;
            s->rx_peer_len = 0;
            socket_apply_ip_pcb_options(s);
            if (EDGE_LWIP_CALL(tcp_connect(
                    tp, &dst, tuple.destination_port,
                    edge_tcp_connected_cb)) != ERR_OK) {
                s->connect_in_progress = 0;
                s->connect_start_us = 0;
                return (uint64_t)-ECONNREFUSED;
            }
            kernel_socket_connect_deadline_tracker_note(
                &g_socket_connect_deadline_tracker,
                kernel_socket_connect_deadline_us(
                    start_us, s->recv_timeout_us));
            while (s->connect_in_progress) {
                if (signal_pending_interrupt()) return tty_interrupt_current_ret();
                if ((fde && (fde->flags & LINUX_O_NONBLOCK)) || s->nonblock) {
                    return (uint64_t)-EINPROGRESS;
                }
                lwip_stack_poll();
                if (!s->connect_in_progress) break;
                socket_maybe_timeout_connect(s);
                if (!s->connect_in_progress) break;
                /*
                 * The deferred network bottom half invokes the lwIP completion
                 * callback and wakes this socket's POLLOUT waiters.  Register
                 * before the final state check, matching Linux's wait-queue
                 * ordering so a completion cannot be lost in the sleep gap.
                 */
                if (fde && cur) socket_waiter_add(fde->pipe_id, cur->pid, LINUX_POLLOUT);
                if (!s->connect_in_progress) {
                    if (cur) waiter_remove_pid(cur->pid);
                    break;
                }
                socket_blocking_wait_step(start_us + socket_connect_timeout_us(s));
            }
            if (s->connect_error != 0)
                return (uint64_t)-(int64_t)s->connect_error;
            if (!s->connected) return (uint64_t)-ECONNREFUSED;
            if (s->bind_len < sizeof(struct edge_sockaddr_in)) {
                struct edge_sockaddr_in lsin;
                memset(&lsin, 0, sizeof(lsin));
                lsin.sin_family = LINUX_AF_INET;
                lsin.sin_addr = g_if_eth0.ipv4_addr_be;
                lsin.sin_port = edge_bswap16(tp->local_port);
                socket_set_bind_inet(s, lsin.sin_addr, lsin.sin_port);
                s->local_port_be = lsin.sin_port;
            }
        }
    } else if (s->domain == LINUX_AF_INET6 && len >= sizeof(struct edge_sockaddr_in6)) {
        struct edge_sockaddr_in6 sin6;
        if (sockaddr_in6_from_buf(s->peer_addr, len, &sin6) < 0) return (uint64_t)-EAFNOSUPPORT;
        if (s->type == LINUX_SOCK_DGRAM &&
            (s->protocol == 0 || s->protocol == LINUX_IPPROTO_UDP) &&
            s->lwip_pcb) {
            struct udp_pcb *up = (struct udp_pcb *)s->lwip_pcb;
            edge_linux_netfilter_tuple_t tuple;
            ip_addr_t dst6;
            ip_addr_set_zero_ip6(&dst6);
            memcpy(&ip_2_ip6(&dst6)->addr[0], sin6.sin6_addr, 16);
            memset(&tuple, 0, sizeof(tuple));
            tuple.network_namespace = s->network_namespace;
            tuple.family = LINUX_AF_INET6;
            tuple.protocol = LINUX_IPPROTO_UDP;
            tuple.source_port = up->local_port;
            tuple.destination_port = edge_bswap16(sin6.sin6_port);
            if (IP_IS_V6(&up->local_ip))
                edge_ip6_to_bytes(
                    ip_2_ip6(&up->local_ip), tuple.source_address);
            memcpy(tuple.destination_address, sin6.sin6_addr,
                   sizeof(sin6.sin6_addr));
            if (edge_linux_netfilter_translate_local(
                    &tuple,
                    EDGE_LINUX_NETFILTER_TRANSLATE_DESTINATION) > 0) {
                memcpy(&ip_2_ip6(&dst6)->addr[0],
                       tuple.destination_address, 16u);
            }
            if (s->ifindex > 0 || s->option_state.mark) {
                uint8_t preferred_source[16];

                if (!lwip_stack_select_socket_route(
                        s->network_namespace, LINUX_AF_INET6,
                        tuple.source_address, tuple.destination_address,
                        s->option_state.mark, s->ifindex,
                        preferred_source, &tuple.output_ifindex))
                    return (uint64_t)-EHOSTUNREACH;
                if (ip6_addr_isany(ip_2_ip6(&up->local_ip)) &&
                    memcmp(preferred_source,
                           "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                           16u) != 0) {
                    ip_addr_set_zero_ip6(&up->local_ip);
                    memcpy(&ip_2_ip6(&up->local_ip)->addr[0],
                           preferred_source, 16u);
                }
            }
            socket_apply_ip_pcb_options(s);
            if (EDGE_LWIP_CALL(
                    udp_connect(up, &dst6, tuple.destination_port)) != ERR_OK)
                return (uint64_t)-EHOSTUNREACH;
        } else if (s->type == LINUX_SOCK_STREAM &&
                   (s->protocol == 0 || s->protocol == LINUX_IPPROTO_TCP) &&
                   s->lwip_pcb) {
            struct tcp_pcb *tp = (struct tcp_pcb *)s->lwip_pcb;
            uint8_t source_address[16];
            uint8_t preferred_source[16];
            int32_t selected_ifindex;
            ip_addr_t dst6;
            uint64_t start_us = boottime_monotonic_us();
            ip_addr_set_zero_ip6(&dst6);
            memcpy(&ip_2_ip6(&dst6)->addr[0], sin6.sin6_addr, 16);
            memset(source_address, 0, sizeof(source_address));
            if (IP_IS_V6(&tp->local_ip))
                edge_ip6_to_bytes(
                    ip_2_ip6(&tp->local_ip), source_address);
            if ((s->ifindex > 0 || s->option_state.mark) &&
                !lwip_stack_select_socket_route(
                    s->network_namespace, LINUX_AF_INET6,
                    source_address, sin6.sin6_addr,
                    s->option_state.mark, s->ifindex,
                    preferred_source, &selected_ifindex))
                return (uint64_t)-EHOSTUNREACH;
            if ((s->ifindex > 0 || s->option_state.mark) &&
                ip6_addr_isany(ip_2_ip6(&tp->local_ip)) &&
                memcmp(preferred_source,
                       "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                       16u) != 0) {
                ip_addr_set_zero_ip6(&tp->local_ip);
                memcpy(&ip_2_ip6(&tp->local_ip)->addr[0],
                       preferred_source, 16u);
            }
            s->connect_in_progress = 1;
            s->connect_error = 0;
            s->connect_start_us = start_us;
            s->rx_closed = 0;
            s->tcp_fin_pending = 0;
            s->closed = 0;
            s->rx_len = 0;
            s->rx_peer_len = 0;
            socket_apply_ip_pcb_options(s);
            if (EDGE_LWIP_CALL(tcp_connect(
                    tp, &dst6, edge_bswap16(sin6.sin6_port),
                    edge_tcp_connected_cb)) != ERR_OK) {
                s->connect_in_progress = 0;
                s->connect_start_us = 0;
                return (uint64_t)-ECONNREFUSED;
            }
            kernel_socket_connect_deadline_tracker_note(
                &g_socket_connect_deadline_tracker,
                kernel_socket_connect_deadline_us(
                    start_us, s->recv_timeout_us));
            while (s->connect_in_progress) {
                if (signal_pending_interrupt()) return tty_interrupt_current_ret();
                if ((fde && (fde->flags & LINUX_O_NONBLOCK)) || s->nonblock) return (uint64_t)-EINPROGRESS;
                lwip_stack_poll();
                if (!s->connect_in_progress) break;
                socket_maybe_timeout_connect(s);
                if (!s->connect_in_progress) break;
                /*
                 * IPv4 and IPv6 connect use the same exact socket wait queue;
                 * the architecture-independent callback wakes POLLOUT when the
                 * handshake completes or fails.
                 */
                if (fde && cur) socket_waiter_add(fde->pipe_id, cur->pid, LINUX_POLLOUT);
                if (!s->connect_in_progress) {
                    if (cur) waiter_remove_pid(cur->pid);
                    break;
                }
                socket_blocking_wait_step(start_us + socket_connect_timeout_us(s));
            }
            if (s->connect_error != 0)
                return (uint64_t)-(int64_t)s->connect_error;
            if (!s->connected) return (uint64_t)-ECONNREFUSED;
            if (s->bind_len < sizeof(struct edge_sockaddr_in6)) {
                struct edge_sockaddr_in6 lsin6;
                memset(&lsin6, 0, sizeof(lsin6));
                lsin6.sin6_family = LINUX_AF_INET6;
                edge_ip6_to_bytes(ip_2_ip6(&tp->local_ip), lsin6.sin6_addr);
                lsin6.sin6_port = edge_bswap16(tp->local_port);
                socket_set_bind_inet6(s, lsin6.sin6_addr, lsin6.sin6_port, 0);
                s->local_port_be = lsin6.sin6_port;
            }
        }
    }
    s->connected = 1;
    return 0;
}

static int64_t x86_socket_listen_entry(
    int32_t diagnostic_fd, edge_fd_t *fde,
    int32_t backlog_value) {
    uint32_t backlog =
        kernel_socket_accept_queue_normalize_backlog(
            backlog_value);
    edge_socket_t *s = socket_from_fd_entry(fde);
    struct tcp_pcb *tp;
    struct tcp_pcb *lp;
    err_t lerr = ERR_OK;

    if (!s) return -ENOTSOCK;
    if (s->listening) {
        s->backlog = backlog;
        kernel_socket_accept_queue_configure(
            &s->accept_queue, backlog_value);
        if ((s->domain == LINUX_AF_INET ||
             s->domain == LINUX_AF_INET6) &&
            s->type == LINUX_SOCK_STREAM &&
            s->lwip_pcb) {
            EDGE_LWIP_DO(tcp_backlog_set(
                (struct tcp_pcb *)s->lwip_pcb, (u8_t)backlog));
        }
        return 0;
    }

    if (s->domain == LINUX_AF_UNIX) {
        if (!(s->type == LINUX_SOCK_STREAM || s->type == LINUX_SOCK_SEQPACKET)) {
            return (uint64_t)-EOPNOTSUPP;
        }
        if (s->bind_len < sizeof(uint16_t)) return (uint64_t)-EINVAL;
        s->listening = 1;
        s->backlog = backlog;
        kernel_socket_accept_queue_configure(
            &s->accept_queue, backlog_value);
        x11_unix_trace_binding("listen-ok",
                                (fde && fde->path[0]) ? fde->path : unix_binding_path_for_sock(fde ? fde->pipe_id : -1),
                                diagnostic_fd,
                                fde ? fde->pipe_id : -1, 0);
        return 0;
    }

    if (!(s->domain == LINUX_AF_INET || s->domain == LINUX_AF_INET6)) return (uint64_t)-EAFNOSUPPORT;
    if (s->type != LINUX_SOCK_STREAM) return (uint64_t)-EOPNOTSUPP;
    if (!s->lwip_pcb) return (uint64_t)-EINVAL;

    tp = (struct tcp_pcb *)s->lwip_pcb;
    lp = EDGE_LWIP_CALL(
        tcp_listen_with_backlog_and_err(tp, (u8_t)backlog, &lerr));
    if (!lp || lerr != ERR_OK) return (uint64_t)-EADDRINUSE;

    s->lwip_pcb = lp;
    socket_apply_ip_pcb_options(s);
    s->listening = 1;
    s->backlog = backlog;
    kernel_socket_accept_queue_configure(
        &s->accept_queue, backlog_value);
    tcp_arg(lp, s);
    tcp_accept(lp, edge_tcp_accept_cb);
    return 0;
}

static int x86_socket_accept_prepare_entry(
    int32_t fd, uint32_t flags, kernel_socket_address_t *peer_address,
    uint64_t deferred_user_address, uint64_t deferred_user_length,
    void *user_registers, int32_t *accepted_descriptor,
    kernel_fd_publication_t *publication, edge_fd_proc_t *p,
    edge_fd_t *e) {
    task_t *cur = process_current_task();
    edge_socket_t *listener;
    int sid;
    edge_socket_t *child;
    int nfd;
    int status;
    const uint8_t *source_address;
    uint32_t source_length;

    (void)deferred_user_address;
    (void)deferred_user_length;
    (void)user_registers;
    if (!p || !e) {
        gui_accept_trace("badfd", cur, fd, 0, -EBADF);
        return -EBADF;
    }
    listener = socket_from_fd_entry(e);
    if (!listener) {
        gui_accept_trace("nosock", cur, fd, listener, -ENOTSOCK);
        return -ENOTSOCK;
    }
    if (!listener->listening) {
        gui_accept_trace("not-listening", cur, fd, listener, -EINVAL);
        return -EINVAL;
    }

    sid = e->pipe_id;

    while (socket_pending_count(listener) == 0) {
        if ((e->flags & LINUX_O_NONBLOCK) || listener->nonblock) {
            gui_accept_trace("empty-nonblock", cur, fd, listener, -EAGAIN);
            return -EAGAIN;
        }
        if (signal_pending_interrupt()) {
            uint64_t intr = tty_interrupt_current_ret();
            gui_accept_trace("signal", cur, fd, listener, (int)(int64_t)intr);
            return (int)(int64_t)intr;
        }
        lwip_stack_poll();
        /*
         * Accept sleeps on the listener socket's readable wait queue on Linux.
         * EdgeOS keeps compact per-socket waiters for AF_UNIX/X11 traffic; add
         * this task before blocking so fd_wake_socket_waiters() can avoid the
         * expensive and imprecise fd-owner fallback that wakes unrelated Xorg
         * helper threads.
         */
        if (sid >= 0 && cur) socket_waiter_add(sid, cur->pid, LINUX_POLLIN | LINUX_POLLPRI);
        socket_blocking_wait_step(0);
    }

    do {
        sid = socket_pending_dequeue(listener);
        if (sid >= 0 && sid < EDGE_MAX_SOCKETS && g_sockets[sid].used) break;
        if (gui_accept_trace_task(cur)) {
            static int stale_detail_budget = 128;
            if (stale_detail_budget > 0) {
                edge_socket_t *stale = (sid >= 0 && sid < EDGE_MAX_SOCKETS) ? &g_sockets[sid] : 0;
                printf("[acceptq] stale pid=%d cmd=%s fd=%d listener=%d child=%d child_used=%d child_refs=%d child_peer=%d pending=%d backlog=%d budget=%d\n",
                       cur ? cur->pid : -1,
                       cur && cur->name[0] ? cur->name : "?",
                       fd, socket_id_from_ptr(listener), sid,
                       stale ? stale->used : -1,
                       stale ? stale->refs : -1,
                       stale ? stale->unix_peer_id : -1,
                       socket_pending_count(listener),
                       listener->backlog,
                       stale_detail_budget - 1);
                stale_detail_budget--;
            }
        }
        gui_accept_trace("stale-child", cur, fd, listener, -EAGAIN);
        sid = -1;
    } while (socket_pending_count(listener) > 0);
#if EDGE_SSH_IO_DEBUG
    if (ssh_trace_task(process_current_task())) {
        printf("[sshdbg] accept-dequeue fd=%d sid=%d remaining=%d\n",
               fd, sid, socket_pending_count(listener));
    }
#endif
    if (sid < 0 || sid >= EDGE_MAX_SOCKETS || !g_sockets[sid].used) {
        return -EAGAIN;
    }
    child = &g_sockets[sid];

    nfd = fd_alloc(p, 0);
    if (nfd < 0) {
        gui_accept_trace("emfile", cur, fd, listener, -EMFILE);
        socket_acceptq_release(sid);
        if (sid >= 0 && sid < EDGE_MAX_SOCKETS && g_sockets[sid].used) socket_drop_ref(sid);
        return -EMFILE;
    }
    p->fds[nfd].kind = FD_SOCKET;
    p->fds[nfd].file_ref = file_ref_alloc(
        LINUX_O_RDWR |
        ((flags & LINUX_SOCK_NONBLOCK) ? LINUX_O_NONBLOCK : 0));
    if (!p->fds[nfd].file_ref) {
        gui_accept_trace("enfile", cur, fd, listener, -ENFILE);
        fd_abort_reserved(p, nfd);
        socket_acceptq_release(sid);
        if (sid >= 0 && sid < EDGE_MAX_SOCKETS && g_sockets[sid].used) socket_drop_ref(sid);
        return -ENFILE;
    }
    if (child->refs <= child->acceptq_refs) socket_add_ref(sid);
    p->fds[nfd].pipe_id = sid;
    p->fds[nfd].flags = LINUX_O_RDWR | ((flags & LINUX_SOCK_NONBLOCK) ? LINUX_O_NONBLOCK : 0);
    p->fds[nfd].fd_flags = (flags & LINUX_SOCK_CLOEXEC) ? LINUX_FD_CLOEXEC : 0;
    socket_acceptq_release(sid);
    child->nonblock = (flags & LINUX_SOCK_NONBLOCK) != 0;
    *accepted_descriptor = nfd;
    if (x11_sockio_trace_task(cur) && g_x11_sock_trace_budget-- > 0) {
        printf("[x11dbg] unix-accept pid=%d cmd=%s lfd=%d nfd=%d sid=%d peer=%d remaining=%d\n",
               cur->pid, cur->name, fd, nfd, sid,
               child->unix_peer_id,
               socket_pending_count(listener));
    }
#if EDGE_XFCE_BOOT_TRACE
    if (xfce_x11_peer_trace_task(cur, child)) {
        const task_t *peer = child->peer_cred_pid > 0 ? process_get_task(child->peer_cred_pid) : 0;
        printf("[xfce-x11] accept pid=%d cmd=%s lfd=%d nfd=%d sid=%d peer=%d peerpid=%d peercmd=%s remaining=%d\n",
               cur ? cur->pid : -1, cur ? cur->name : "?",
               fd, nfd, sid, child->unix_peer_id, child->peer_cred_pid,
               peer ? peer->name : "-",
               socket_pending_count(listener));
    }
#endif

    if (listener->lwip_pcb && child->lwip_pcb) {
        EDGE_LWIP_DO(
            tcp_backlog_accepted((struct tcp_pcb *)listener->lwip_pcb));
    }

    memset(peer_address, 0, sizeof(*peer_address));
    source_address = child->peer_len ? child->peer_addr : child->rx_peer;
    source_length = child->peer_len ? child->peer_len : child->rx_peer_len;
    if (source_length > sizeof(peer_address->bytes)) {
        x86_fd_publication_abort(p, accepted_descriptor, 1u);
        *accepted_descriptor = -1;
        return -EIO;
    }
    if (source_length) {
        memcpy(peer_address->bytes, source_address, source_length);
        peer_address->length = source_length;
    } else if (child->domain == LINUX_AF_UNIX) {
        peer_address->bytes[0] = LINUX_AF_UNIX;
        peer_address->length = sizeof(uint16_t);
    } else {
        x86_fd_publication_abort(p, accepted_descriptor, 1u);
        *accepted_descriptor = -1;
        return -EIO;
    }

    status = x86_fd_publication_initialize(
        p, accepted_descriptor, 1u, publication);
    if (status < 0) {
        *accepted_descriptor = -1;
        return status;
    }
    return 0;
}

int arch_socket_accept_prepare(
    int32_t fd, uint32_t flags, kernel_socket_address_t *peer_address,
    uint64_t deferred_user_address, uint64_t deferred_user_length,
    void *user_registers, int32_t *accepted_descriptor,
    kernel_fd_publication_t *publication) {
    kernel_fd_operation_lease_t lease = {0};
    edge_fd_proc_t *process;
    edge_fd_t *entry;
    task_t *current = process_current_task();
    int result;

    result = kernel_fd_operation_acquire(fd, &lease);
    if (result < 0) {
        gui_accept_trace("badfd", current, fd, 0, result);
        return result;
    }
    entry = (edge_fd_t *)kernel_fd_operation_view(&lease);
    process = fd_proc_with_stdio();
    if (!entry || !process) {
        (void)kernel_fd_operation_release(&lease);
        return -EIO;
    }
    result = x86_socket_accept_prepare_entry(
        fd, flags, peer_address, deferred_user_address,
        deferred_user_length, user_registers, accepted_descriptor,
        publication, process, entry);
    (void)kernel_fd_operation_release(&lease);
    return result;
}

static int socket_filter_accepts(const edge_socket_t *s, const uint8_t *pkt, uint32_t len) {
    uint32_t keep;
    if (!s || s->filter_len == 0) return 1;
    keep = edge_linux_bpf_run(s->filter, s->filter_len, pkt, len);
    return keep != 0;
}

static int x86_packet_page_allocate(void *context, void **kernel_address,
                                    uint64_t *mapping_cookie) {
    int page;
    (void)context;
    if (!kernel_address || !mapping_cookie) return -1;
    page = process_user_mmap_alloc_backing_page();
    if (page < 0) return -1;
    *kernel_address = process_user_mmap_backing_page_ptr(page);
    if (!*kernel_address) {
        process_user_mmap_release_backing_page(page);
        return -1;
    }
    *mapping_cookie = (uint64_t)(uint32_t)page;
    return 0;
}

static void x86_packet_page_release(void *context, void *kernel_address,
                                    uint64_t mapping_cookie) {
    (void)context;
    (void)kernel_address;
    process_user_mmap_release_backing_page((int)mapping_cookie);
}

static const struct edge_linux_packet_page_allocator
    g_x86_packet_page_allocator = {
        .allocate = x86_packet_page_allocate,
        .release = x86_packet_page_release,
        .context = 0,
    };

static void x86_socket_option_apply_effects(
    void *context, uint32_t effects) {
    edge_socket_t *socket = (edge_socket_t *)context;
    if (!socket) return;
    socket_sync_option_state(socket);
    if (effects & KERNEL_SOCKET_OPTION_EFFECT_IP_TRANSPORT)
        socket_apply_ip_pcb_options(socket);
}

static void x86_socket_option_prepare_error_take(void *context) {
    socket_maybe_timeout_connect((edge_socket_t *)context);
}

static int x86_socket_option_peer_credentials(
    void *context, kernel_socket_peer_credentials_t *credentials);
static int64_t x86_socket_option_peer_pidfd(void *context);
static int x86_socket_option_peer_group_count(
    void *context, uint32_t *count);
static int x86_socket_option_peer_group(
    void *context, uint32_t index, uint32_t *group_id);

int edge_socket_runtime_option_view(
    int32_t descriptor, kernel_socket_option_runtime_view_t *view) {
    edge_fd_proc_t *process;
    edge_fd_t *entry;
    edge_socket_t *socket;

    if (!view) return -EINVAL;
    process = fd_proc_with_stdio();
    entry = fd_get(process, descriptor);
    if (!entry) return -EBADF;
    socket = socket_from_fd_entry(entry);
    if (!socket) return -ENOTSOCK;
    memset(view, 0, sizeof(*view));
    view->state = &socket->option_state;
    view->bound_interface = &socket->ifindex;
    view->pending_error = &socket->connect_error;
    view->filter = socket->filter;
    view->filter_length = &socket->filter_len;
    view->context = socket;
    view->apply_effects = x86_socket_option_apply_effects;
    view->prepare_error_take = x86_socket_option_prepare_error_take;
    view->peer_credentials = x86_socket_option_peer_credentials;
    view->peer_pidfd = x86_socket_option_peer_pidfd;
    view->peer_group_count = x86_socket_option_peer_group_count;
    view->peer_group = x86_socket_option_peer_group;
    view->domain = socket->domain;
    view->type = socket->type;
    view->protocol = socket->protocol;
    view->network_namespace = socket->network_namespace;
    view->transport_mtu = g_if_eth0.mtu;
    view->netlink_groups = &socket->netlink_groups;
    view->packet_handle = socket->packet_handle;
    view->packet_page_allocator = &g_x86_packet_page_allocator;
    return 0;
}

static int socket_option_peer_pid(const edge_socket_t *socket) {
    if (!socket) return -1;
    if (socket->peer_cred_pid > 0) return socket->peer_cred_pid;
    if (socket->unix_peer_id >= 0 && socket->unix_peer_id < EDGE_MAX_SOCKETS &&
        g_sockets[socket->unix_peer_id].used)
        return g_sockets[socket->unix_peer_id].cred_pid;
    return -1;
}

static int x86_socket_option_peer_credentials(
    void *context, kernel_socket_peer_credentials_t *credentials) {
    edge_socket_t *socket = (edge_socket_t *)context;
    if (!socket || !credentials) return -EINVAL;
    if (socket->peer_cred_pid > 0) {
        credentials->process_id = socket->peer_cred_pid;
        credentials->user_id = socket->peer_cred_uid;
        credentials->group_id = socket->peer_cred_gid;
    } else if (socket->unix_peer_id >= 0 &&
               socket->unix_peer_id < EDGE_MAX_SOCKETS &&
               g_sockets[socket->unix_peer_id].used) {
        edge_socket_t *peer = &g_sockets[socket->unix_peer_id];
        credentials->process_id = peer->cred_pid;
        credentials->user_id = peer->cred_uid;
        credentials->group_id = peer->cred_gid;
    } else {
        credentials->process_id = socket->cred_pid;
        credentials->user_id = socket->cred_uid;
        credentials->group_id = socket->cred_gid;
    }
    return 0;
}

static int64_t x86_socket_option_peer_pidfd(void *context) {
    edge_socket_t *socket = (edge_socket_t *)context;
    int peer_pid;
    if (!socket) return -EINVAL;
    peer_pid = socket_option_peer_pid(socket);
    if (peer_pid <= 0 || !process_get_task(peer_pid)) return -ENOTCONN;
    return alloc_special_fd(FD_PIDFD, peer_pid, LINUX_O_CLOEXEC);
}

static int x86_socket_option_peer_group_count(
    void *context, uint32_t *count) {
    edge_socket_t *socket = (edge_socket_t *)context;
    const task_t *peer;
    int peer_pid;
    if (!socket || !count) return -EINVAL;
    peer_pid = socket_option_peer_pid(socket);
    peer = peer_pid > 0 ? process_get_task(peer_pid) : 0;
    *count = peer && peer->supplementary_groups.count ?
        peer->supplementary_groups.count : 1u;
    return 0;
}

static int x86_socket_option_peer_group(
    void *context, uint32_t index, uint32_t *group_id) {
    edge_socket_t *socket = (edge_socket_t *)context;
    const task_t *peer;
    int peer_pid;
    if (!socket || !group_id) return -EINVAL;
    peer_pid = socket_option_peer_pid(socket);
    peer = peer_pid > 0 ? process_get_task(peer_pid) : 0;
    if (peer && peer->supplementary_groups.count) {
        if (index >= peer->supplementary_groups.count) return -EINVAL;
        *group_id = linux_group_list_get(&peer->supplementary_groups, index);
        return 0;
    }
    if (index) return -EINVAL;
    *group_id = socket->peer_cred_pid > 0 ?
        socket->peer_cred_gid : socket->cred_gid;
    return 0;
}

static int64_t x86_socket_shutdown_entry(
    edge_fd_t *entry, int32_t how) {
    edge_socket_t *s = socket_from_fd_entry(entry);
    int socket_id;
    if (!s) return -ENOTSOCK;
    socket_id = socket_id_from_ptr(s);

    if (s->domain == LINUX_AF_UNIX) {
        if (how == 0 || how == 2) {
            s->shutdown_read = 1;
            if (++s->shutdown_read_generation == 0)
                s->shutdown_read_generation = 1;
        }
        if (how == 1 || how == 2) s->shutdown_write = 1;
        fd_wake_socket_waiters(socket_id);
        if ((how == 0 || how == 2) &&
            s->unix_peer_id >= 0 && s->unix_peer_id < EDGE_MAX_SOCKETS &&
            g_sockets[s->unix_peer_id].used) {
            /*
             * A peer blocked on a full send queue must observe EPIPE as soon
             * as this endpoint disables reception, even for SOCK_DGRAM.
             */
            fd_wake_socket_waiters(s->unix_peer_id);
        }
        if (kernel_socket_type_has_peer_eof(s->type) &&
            (how == 1 || how == 2) &&
            s->unix_peer_id >= 0 && s->unix_peer_id < EDGE_MAX_SOCKETS &&
            g_sockets[s->unix_peer_id].used) {
            /*
             * Linux SHUT_WR is observed by the peer as receive EOF.  Keep the
             * half-close state in rx_closed and wake waiters so poll/recvmsg
             * agree.  Do not set closed: the peer may still send in the reverse
             * direction after an orderly half-close.
             */
            g_sockets[s->unix_peer_id].rx_closed = 1;
            fd_wake_socket_waiters(s->unix_peer_id);
        }
        if (kernel_socket_type_has_peer_eof(s->type) &&
            (how == 0 || how == 2)) {
            s->rx_closed = 1;
        }
        return 0;
    }

    if ((s->domain == LINUX_AF_INET || s->domain == LINUX_AF_INET6) &&
        s->type == LINUX_SOCK_STREAM &&
        !s->lwip_pcb &&
        s->unix_peer_id >= 0) {
        if (how == 0 || how == 2) s->shutdown_read = 1;
        if (how == 1 || how == 2) s->shutdown_write = 1;
        if ((how == 1 || how == 2) &&
            s->unix_peer_id >= 0 && s->unix_peer_id < EDGE_MAX_SOCKETS &&
            g_sockets[s->unix_peer_id].used) {
            g_sockets[s->unix_peer_id].rx_closed = 1;
            fd_wake_socket_waiters(s->unix_peer_id);
        }
        if (how == 0 || how == 2) {
            s->rx_closed = 1;
        }
        return 0;
    }

    if ((s->domain == LINUX_AF_INET || s->domain == LINUX_AF_INET6) &&
        s->type == LINUX_SOCK_STREAM) {
        struct tcp_pcb *tp = (struct tcp_pcb *)s->lwip_pcb;
        err_t err;
        if (!tp) return s->closed ? 0 : (uint64_t)-ENOTCONN;
        err = EDGE_LWIP_CALL(tcp_shutdown(
            tp, how == 0 || how == 2, how == 1 || how == 2));
        if (err == ERR_OK) {
            if (how == 0 || how == 2) s->shutdown_read = 1;
            if (how == 1 || how == 2) s->shutdown_write = 1;
            if (how == 0 || how == 2) {
                s->rx_closed = 1;
            }
            return 0;
        }
        return (uint64_t)-lwip_err_to_linux_errno((int)err);
    }

    if (how == 0 || how == 2) s->shutdown_read = 1;
    if (how == 1 || how == 2) s->shutdown_write = 1;
    return 0;
}

static int x86_socket_message_copy_from_user(void *context, void *destination,
                                              uint64_t source,
                                              uint64_t size) {
    (void)context;
    return copy_from_user(destination, source, size);
}

static int x86_socket_message_copy_to_user(void *context,
                                            uint64_t destination,
                                            const void *source,
                                            uint64_t size) {
    (void)context;
    return copy_to_user(destination, source, size);
}

static int unix_record_destination_from_user(
    edge_socket_t *socket, uint64_t address_user, uint64_t address_length,
    int *peer_id) {
    uint8_t address[128];
    char path[EDGE_UNIX_BINDING_KEY_SIZE];
    int binding;
    int target;

    if (!socket || !peer_id) return -EINVAL;
    if (!address_user) {
        *peer_id = socket->unix_peer_id;
        if (*peer_id >= 0) return 0;
        return kernel_unix_socket_missing_peer_error(
            (uint32_t)socket->type, socket->closed);
    }
    if (address_length < sizeof(uint16_t) || address_length > sizeof(address))
        return -EINVAL;
    if (copy_from_user(address, address_user, address_length) < 0)
        return -EFAULT;
    if (sockaddr_un_path_from_buf(address, (uint32_t)address_length, path,
                                  sizeof(path)) < 0)
        return -EAFNOSUPPORT;
    binding = unix_binding_find_path(path);
    if (binding < 0) return -ENOENT;
    target = g_unix_bindings[binding].sock_id;
    if (target < 0 || target >= EDGE_MAX_SOCKETS ||
        !g_sockets[target].used)
        return -ECONNREFUSED;
    if (g_sockets[target].domain != LINUX_AF_UNIX ||
        g_sockets[target].type != socket->type)
        return -EDGE_LINUX_EPROTOTYPE;
    *peer_id = target;
    return 0;
}

static uint64_t unix_record_send_iov_to(
    int fd, edge_socket_t *s, edge_fd_t *fde,
    const kernel_socket_iovec_source_t *source, uint64_t iov_count,
    uint64_t flags_u, int peer_id,
    kernel_socket_rights_record_handle_t *rights) {
    task_t *cur = process_current_task();
    uint64_t total64 = 0;
    uint32_t total;
    int dontwait = (flags_u & LINUX_MSG_DONTWAIT) != 0;

    (void)fd;

    if (!s || s->domain != LINUX_AF_UNIX || !socket_type_is_record(s->type)) {
        return (uint64_t)-EOPNOTSUPP;
    }
    for (uint64_t i = 0; i < iov_count; ++i) {
        struct edge_linux_iovec iov;
        int status = kernel_socket_iovec_source_read(source, (uint32_t)i, &iov);
        if (status < 0) return (uint64_t)(int64_t)status;
        if (iov.iov_len > UINT32_MAX || total64 > UINT32_MAX - iov.iov_len) {
            return (uint64_t)-EMSGSIZE;
        }
        total64 += iov.iov_len;
    }
    total = (uint32_t)total64;
    if (total > EDGE_SOCKET_RX_BUF_SIZE) return (uint64_t)-EMSGSIZE;
    if (socket_iovec_user_access_prepare(
            source, (uint32_t)iov_count, total, 0) < 0)
        return (uint64_t)-EFAULT;

    for (;;) {
        edge_socket_t *peer;
        uint32_t room;
        uint32_t copied = 0;
        uint64_t irq_flags;

        if (peer_id < 0 || peer_id >= EDGE_MAX_SOCKETS) {
            return (uint64_t)(int64_t)
                kernel_unix_socket_missing_peer_error(
                    (uint32_t)s->type, s->closed);
        }
        peer = &g_sockets[peer_id];
        irq_flags = spin_lock_irqsave(&peer->io_lock);
        if (s->shutdown_write) {
            spin_unlock_irqrestore(&peer->io_lock, irq_flags);
            return (uint64_t)-EPIPE;
        }
        if (!peer->used || peer->closed || peer->shutdown_read ||
            peer->type != s->type) {
            spin_unlock_irqrestore(&peer->io_lock, irq_flags);
            return (uint64_t)-EPIPE;
        }
        room = peer->rx_len < socket_rx_capacity(peer) ?
               socket_rx_capacity(peer) - peer->rx_len : 0;
        if (peer->packet_count >= EDGE_SOCKET_PACKET_QUEUE || total > room ||
            (rights && *rights &&
             kernel_socket_rights_queue_count(&peer->rights) >=
                 peer->rights.limit)) {
            spin_unlock_irqrestore(&peer->io_lock, irq_flags);
            if (dontwait || (fde && (fde->flags & LINUX_O_NONBLOCK)) || s->nonblock) {
                return (uint64_t)-EAGAIN;
            }
            if (signal_pending_interrupt()) return tty_interrupt_current_ret();
            if (fde && cur) {
                socket_waiter_add(fde->pipe_id, cur->pid,
                                  LINUX_POLLOUT | LINUX_POLLWRNORM);
            }
            room = peer->rx_len < socket_rx_capacity(peer) ?
                   socket_rx_capacity(peer) - peer->rx_len : 0;
            if (peer->packet_count < EDGE_SOCKET_PACKET_QUEUE &&
                total <= room &&
                (!rights || !*rights ||
                 kernel_socket_rights_queue_count(&peer->rights) <
                     peer->rights.limit)) {
                if (cur) waiter_remove_pid(cur->pid);
                continue;
            }
            socket_blocking_wait_step(0);
            continue;
        }

        for (uint64_t i = 0; i < iov_count; ++i) {
            struct edge_linux_iovec iov;
            uint64_t iov_off = 0;
            int status = kernel_socket_iovec_source_read(source, (uint32_t)i, &iov);
            if (status < 0) {
                spin_unlock_irqrestore(&peer->io_lock, irq_flags);
                return (uint64_t)(int64_t)status;
            }
            while (iov_off < iov.iov_len) {
                uint8_t chunk[1024];
                uint32_t n = (uint32_t)(iov.iov_len - iov_off);
                if (n > sizeof(chunk)) n = sizeof(chunk);
                if (copy_from_user(chunk, iov.iov_base + iov_off, n) < 0) {
                    spin_unlock_irqrestore(&peer->io_lock, irq_flags);
                    return (uint64_t)-EFAULT;
                }
                memcpy(peer->rx_buf + peer->rx_len + copied, chunk, n);
                copied += n;
                iov_off += n;
            }
        }
        if (socket_packet_push_source(
                peer, total, s->bind_addr, s->bind_len,
                cur ? kernel_unix_socket_credential_pid(
                    cur->pid, cur->tgid) : 0,
                cur ? cur->euid : 0, cur ? cur->egid : 0, 0) < 0)
        {
            spin_unlock_irqrestore(&peer->io_lock, irq_flags);
            return (uint64_t)-EAGAIN;
        }
        if (rights && *rights &&
            socket_rights_enqueue(
                peer, rights, KERNEL_SOCKET_RIGHTS_ASSOCIATION_PACKET,
                peer->unix_packet_head_sequence +
                    peer->packet_count - 1u) < 0) {
            socket_packet_unpush(peer);
            spin_unlock_irqrestore(&peer->io_lock, irq_flags);
            return (uint64_t)-EAGAIN;
        }
        peer->rx_len += total;
        spin_unlock_irqrestore(&peer->io_lock, irq_flags);
        fd_wake_socket_waiters_events(peer_id, LINUX_POLLIN | LINUX_POLLPRI);
        return total;
    }
}

static void unix_record_consume_front_locked(
    edge_socket_t *socket, uint32_t packet_length,
    kernel_socket_rights_record_handle_t *received_rights,
    uint32_t *consumed_out) {
    kernel_socket_rights_record_info_t rights_info;

    if (!socket || !socket->packet_count ||
        packet_length > socket->rx_len)
        return;
    if (packet_length < socket->rx_len) {
        memmove(socket->rx_buf, socket->rx_buf + packet_length,
                socket->rx_len - packet_length);
    }
    socket->rx_len -= packet_length;
    socket_packet_pop(socket);
    while (socket_rights_peek_at(socket, 0, &rights_info) == 0 &&
           rights_info.association_kind ==
               KERNEL_SOCKET_RIGHTS_ASSOCIATION_PACKET &&
           rights_info.association_sequence <=
               socket->unix_packet_head_sequence) {
        if (received_rights && !*received_rights) {
            if (socket_rights_take_front(
                    socket, received_rights) < 0)
                break;
        } else {
            socket_rights_drop_front(socket);
        }
    }
    socket_rights_note_packet_read(socket);
    if (consumed_out) *consumed_out = packet_length;
}

static uint64_t unix_record_recv_iov(int fd, edge_socket_t *s, edge_fd_t *fde,
                                     const kernel_socket_iovec_source_t *source,
                                     uint64_t iov_count, uint64_t flags_u,
                                     kernel_socket_rights_record_handle_t
                                         *received_rights,
                                     int *msg_flags,
                                     uint32_t *consumed_out) {
    task_t *cur = process_current_task();
    uint64_t capacity = 0;
    uint32_t packet_len;
    uint32_t copied = 0;
    uint64_t deadline_us = 0;
    uint32_t shutdown_generation;
    int dontwait = (flags_u & LINUX_MSG_DONTWAIT) != 0;
    int peek = (flags_u & LINUX_MSG_PEEK) != 0;
    uint64_t irq_flags;

    if (consumed_out) *consumed_out = 0;
    if (!s || s->domain != LINUX_AF_UNIX || !socket_type_is_record(s->type)) {
        return (uint64_t)-EOPNOTSUPP;
    }
    shutdown_generation = s->shutdown_read_generation;
    for (uint64_t i = 0; i < iov_count; ++i) {
        struct edge_linux_iovec iov;
        int status = kernel_socket_iovec_source_read(source, (uint32_t)i, &iov);
        if (status < 0) return (uint64_t)(int64_t)status;
        if (UINT64_MAX - capacity < iov.iov_len) capacity = UINT64_MAX;
        else capacity += iov.iov_len;
    }
    if (s->recv_timeout_us) {
        uint64_t now_us = boottime_monotonic_us();
        deadline_us = now_us + s->recv_timeout_us;
        if (deadline_us < now_us) deadline_us = UINT64_MAX;
    }

unix_record_wait:
    while (s->packet_count == 0) {
        if (kernel_socket_type_has_peer_eof(s->type) &&
            (s->shutdown_read || s->rx_closed || s->closed))
            return 0;
        if (dontwait || (fde && (fde->flags & LINUX_O_NONBLOCK)) || s->nonblock) {
            return (uint64_t)-EAGAIN;
        }
        if (s->type == LINUX_SOCK_DGRAM &&
            s->shutdown_read_generation != shutdown_generation)
            return 0;
        if (signal_pending_interrupt()) return tty_interrupt_current_ret();
        if (fde && cur) {
            socket_waiter_add(fde->pipe_id, cur->pid,
                              LINUX_POLLIN | LINUX_POLLPRI);
        }
        if (s->packet_count != 0 ||
            (kernel_socket_type_has_peer_eof(s->type) &&
             (s->shutdown_read || s->rx_closed || s->closed))) {
            if (cur) waiter_remove_pid(cur->pid);
            continue;
        }
        if (s->type == LINUX_SOCK_DGRAM &&
            s->shutdown_read_generation != shutdown_generation) {
            if (cur) waiter_remove_pid(cur->pid);
            return 0;
        }
        if (deadline_us && boottime_monotonic_us() >= deadline_us) {
            if (cur) waiter_remove_pid(cur->pid);
            return (uint64_t)-EAGAIN;
        }
        socket_blocking_wait_step(deadline_us);
    }

    if (socket_iovec_user_access_prepare(
            source, (uint32_t)iov_count,
            capacity < EDGE_SOCKET_RX_BUF_SIZE ?
                capacity : EDGE_SOCKET_RX_BUF_SIZE,
            1) < 0)
        return (uint64_t)-EFAULT;

    irq_flags = spin_lock_irqsave(&s->io_lock);
    if (s->packet_count == 0) {
        spin_unlock_irqrestore(&s->io_lock, irq_flags);
        goto unix_record_wait;
    }
    packet_len = socket_packet_front_length(s);
    if (packet_len > s->rx_len) {
        printf("[unix-record] corrupt receive queue fd=%d packet=%u bytes=%u count=%u\n",
               fd, packet_len, s->rx_len, (uint32_t)s->packet_count);
        spin_unlock_irqrestore(&s->io_lock, irq_flags);
        return (uint64_t)-EIO;
    }
    s->received_timestamp_us = s->packet_timestamps_us[s->packet_head];
    s->received_cred_pid = s->packet_sender_pids[s->packet_head];
    s->received_cred_uid = s->packet_sender_uids[s->packet_head];
    s->received_cred_gid = s->packet_sender_gids[s->packet_head];
    s->rx_peer_len = s->packet_source_lengths[s->packet_head];
    if (s->rx_peer_len)
        memcpy(s->rx_peer, s->packet_source_addresses[s->packet_head],
               s->rx_peer_len);
    for (uint64_t i = 0; i < iov_count && copied < packet_len; ++i) {
        struct edge_linux_iovec iov;
        uint64_t room;
        uint32_t n = packet_len - copied;
        int status = kernel_socket_iovec_source_read(source, (uint32_t)i, &iov);
        if (status < 0) {
            if (!peek)
                unix_record_consume_front_locked(
                    s, packet_len, received_rights, consumed_out);
            spin_unlock_irqrestore(&s->io_lock, irq_flags);
            return (uint64_t)(int64_t)status;
        }
        room = iov.iov_len;
        if (room < n) n = (uint32_t)room;
        if (n != 0 && copy_to_user(iov.iov_base, s->rx_buf + copied, n) < 0) {
            if (!peek)
                unix_record_consume_front_locked(
                    s, packet_len, received_rights, consumed_out);
            spin_unlock_irqrestore(&s->io_lock, irq_flags);
            return (uint64_t)-EFAULT;
        }
        copied += n;
    }
    if (msg_flags) {
        if (s->type == LINUX_SOCK_SEQPACKET)
            *msg_flags |= LINUX_MSG_EOR;
        if (capacity < packet_len) *msg_flags |= LINUX_MSG_TRUNC;
    }

    if (!peek) {
        unix_record_consume_front_locked(
            s, packet_len, received_rights, consumed_out);
    } else if (received_rights && !*received_rights) {
        kernel_socket_rights_record_info_t rights_info;

        if (socket_rights_peek_at(s, 0, &rights_info) == 0 &&
            rights_info.association_kind ==
                KERNEL_SOCKET_RIGHTS_ASSOCIATION_PACKET &&
            rights_info.association_sequence <=
                s->unix_packet_head_sequence)
            *received_rights = rights_info.handle;
    }
    spin_unlock_irqrestore(&s->io_lock, irq_flags);
    if (!peek && s->unix_peer_id >= 0 &&
        s->unix_peer_id < EDGE_MAX_SOCKETS) {
        fd_wake_socket_waiters_events(s->unix_peer_id,
                                      LINUX_POLLOUT | LINUX_POLLWRNORM);
    }
    return (flags_u & LINUX_MSG_TRUNC) ? packet_len : copied;
}

static int x86_sock_diag_snapshot_at(
    void *context, uint32_t network_namespace, uint32_t ordinal,
    edge_linux_sock_diag_snapshot_t *snapshot) {
    edge_socket_t *socket;

    (void)context;
    if (!snapshot || !g_sockets || ordinal >= EDGE_MAX_SOCKETS) return 0;
    socket = &g_sockets[ordinal];
    if (!socket->used || socket->network_namespace != network_namespace ||
        (socket->domain != LINUX_AF_INET &&
         socket->domain != LINUX_AF_INET6))
        return 0;
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->family = (uint8_t)socket->domain;
    snapshot->interface_index =
        socket->ifindex > 0 ? (uint32_t)socket->ifindex : 0u;
    snapshot->cookie[0] = ordinal + 1u;
    snapshot->cookie[1] = network_namespace;
    snapshot->receive_queue = socket->rx_len;
    snapshot->user_id = socket->cred_uid;
    if (socket->type == LINUX_SOCK_STREAM && socket->lwip_pcb) {
        struct tcp_pcb *tcp = (struct tcp_pcb *)socket->lwip_pcb;

        snapshot->protocol = LINUX_IPPROTO_TCP;
        snapshot->state =
            edge_linux_sock_diag_state_from_lwip((uint8_t)tcp->state);
        snapshot->source_port = __builtin_bswap16(tcp->local_port);
        snapshot->destination_port = __builtin_bswap16(tcp->remote_port);
        if (socket->listening) {
            snapshot->receive_queue =
                kernel_socket_accept_queue_count(&socket->accept_queue);
            snapshot->write_queue =
                socket->backlog > 0 ? (uint32_t)socket->backlog : 0u;
        } else {
            snapshot->write_queue = tcp->snd_lbb - tcp->lastack;
        }
        if (IP_IS_V4(&tcp->local_ip))
            memcpy(snapshot->source_address,
                   &ip_2_ip4(&tcp->local_ip)->addr, 4u);
        else if (IP_IS_V6(&tcp->local_ip))
            memcpy(snapshot->source_address,
                   &ip_2_ip6(&tcp->local_ip)->addr[0], 16u);
        if (IP_IS_V4(&tcp->remote_ip))
            memcpy(snapshot->destination_address,
                   &ip_2_ip4(&tcp->remote_ip)->addr, 4u);
        else if (IP_IS_V6(&tcp->remote_ip))
            memcpy(snapshot->destination_address,
                   &ip_2_ip6(&tcp->remote_ip)->addr[0], 16u);
        return 1;
    }
    if (socket->type == LINUX_SOCK_DGRAM && socket->lwip_pcb) {
        struct udp_pcb *udp = (struct udp_pcb *)socket->lwip_pcb;

        snapshot->protocol = LINUX_IPPROTO_UDP;
        snapshot->state = EDGE_LINUX_TCP_CLOSE;
        snapshot->source_port = __builtin_bswap16(udp->local_port);
        snapshot->destination_port = __builtin_bswap16(udp->remote_port);
        if (IP_IS_V4(&udp->local_ip))
            memcpy(snapshot->source_address,
                   &ip_2_ip4(&udp->local_ip)->addr, 4u);
        else if (IP_IS_V6(&udp->local_ip))
            memcpy(snapshot->source_address,
                   &ip_2_ip6(&udp->local_ip)->addr[0], 16u);
        if (IP_IS_V4(&udp->remote_ip))
            memcpy(snapshot->destination_address,
                   &ip_2_ip4(&udp->remote_ip)->addr, 4u);
        else if (IP_IS_V6(&udp->remote_ip))
            memcpy(snapshot->destination_address,
                   &ip_2_ip6(&udp->remote_ip)->addr[0], 16u);
        return 1;
    }
    return 0;
}

static int netlink_kernel_request(void *context, const void *payload,
                                  uint32_t length) {
    edge_socket_t *socket = (edge_socket_t *)context;

    if (socket &&
        (uint32_t)socket->protocol == EDGE_LINUX_NETLINK_GENERIC) {
        uint32_t start = socket->rx_len;
        uint32_t response_length = 0;
        uint32_t capacity = socket_rx_capacity(socket);
        int result;

        if (netlink_ensure_bound(socket) < 0) return -EADDRINUSE;
        if (start > capacity) return -ENOBUFS;
        result = edge_linux_genetlink_respond(
            socket->network_namespace, socket->netlink_port_id,
            payload, length,
            socket->rx_buf + start, capacity - start, &response_length);
        if (result < 0) {
            if (!payload || length < sizeof(struct edge_linux_nlmsghdr))
                return result;
            return netlink_queue_error_reply(
                socket, (const struct edge_linux_nlmsghdr *)payload,
                result);
        }
        if (socket->packet_count >= EDGE_SOCKET_PACKET_QUEUE ||
            response_length > capacity - start)
            return -ENOBUFS;
        if (socket_packet_push(socket, response_length) < 0)
            return -EAGAIN;
        socket->rx_len = start + response_length;
        fd_wake_socket_waiters_events(
            socket_id_from_ptr(socket), LINUX_POLLIN | LINUX_POLLPRI);
        return 0;
    }
    if (socket &&
        (uint32_t)socket->protocol == EDGE_LINUX_NETLINK_SOCK_DIAG) {
        uint32_t start = socket->rx_len;
        uint32_t response_length = 0;
        uint32_t capacity = socket_rx_capacity(socket);
        int result;

        if (netlink_ensure_bound(socket) < 0) return -EADDRINUSE;
        if (start > capacity) return -ENOBUFS;
        result = edge_linux_sock_diag_respond(
            socket->network_namespace, socket->netlink_port_id,
            payload, length,
            x86_sock_diag_snapshot_at, 0, EDGE_MAX_SOCKETS,
            socket->rx_buf + start, capacity - start, &response_length);
        if (result < 0) {
            if (!payload || length < sizeof(struct edge_linux_nlmsghdr))
                return result;
            return netlink_queue_error_reply(
                socket, (const struct edge_linux_nlmsghdr *)payload,
                result);
        }
        if (socket->packet_count >= EDGE_SOCKET_PACKET_QUEUE ||
            response_length > capacity - start)
            return -ENOBUFS;
        if (socket_packet_push(socket, response_length) < 0)
            return -EAGAIN;
        socket->rx_len = start + response_length;
        fd_wake_socket_waiters_events(
            socket_id_from_ptr(socket), LINUX_POLLIN | LINUX_POLLPRI);
        return 0;
    }
    if (socket &&
        (uint32_t)socket->protocol == EDGE_LINUX_NETLINK_NETFILTER) {
        uint32_t start = socket->rx_len;
        uint32_t response_length = 0;
        uint32_t capacity = socket_rx_capacity(socket);
        int result;

        if (start > capacity) return -ENOBUFS;
        result = edge_linux_netfilter_respond_in_namespace(
            socket->network_namespace, socket->netlink_port_id,
            payload, length,
            socket->rx_buf + start,
            capacity - start, &response_length);

        if (result < 0) {
            if (!payload || length < sizeof(struct edge_linux_nlmsghdr))
                return result;
            return netlink_queue_error_reply(
                socket, (const struct edge_linux_nlmsghdr *)payload,
                result);
        }
        if (!response_length) return 0;
        if (socket->packet_count >= EDGE_SOCKET_PACKET_QUEUE ||
            response_length > capacity - start)
            return -ENOBUFS;
        if (socket_packet_push(socket, response_length) < 0)
            return -EAGAIN;
        socket->rx_len = start + response_length;
        fd_wake_socket_waiters_events(
            socket_id_from_ptr(socket), LINUX_POLLIN | LINUX_POLLPRI);
        return 0;
    }
    return netlink_queue_status(socket, (const uint8_t *)payload, length);
}

static int x86_udp_local_destination_is_bound(
        const ip_addr_t *destination, uint16_t destination_port) {
    if (!destination || !destination_port) return 0;
    for (int index = 0; index < EDGE_MAX_SOCKETS; ++index) {
        edge_socket_t *candidate = &g_sockets[index];
        struct udp_pcb *udp;

        if (!candidate->used ||
            candidate->type != LINUX_SOCK_DGRAM ||
            !candidate->lwip_pcb)
            continue;
        udp = (struct udp_pcb *)candidate->lwip_pcb;
        if (udp->local_port != destination_port)
            continue;
        if (ip_addr_isany(&udp->local_ip) ||
            ip_addr_cmp(&udp->local_ip, destination))
            return 1;
    }
    return 0;
}

static int x86_udp_deliver_local(
        const edge_socket_t *sender, const ip_addr_t *destination,
        uint16_t destination_port, struct pbuf *packet,
        const ip_addr_t *source, uint16_t source_port) {
    uint32_t destination_address;
    uint32_t destination_namespace;
    int destination_is_owned;
    kernel_socket_ip_receive_metadata_t metadata;

    if (!sender || !destination || !packet || !source ||
        !IP_IS_V4(destination) || !IP_IS_V4(source))
        return 0;
    destination_address = ip4_addr_get_u32(ip_2_ip4(destination));
    destination_is_owned = ip_addr_isloopback(destination) ||
        (edge_linux_rtnetlink_ipv4_owner(
             destination_address, &destination_namespace) == 0 &&
         destination_namespace == sender->network_namespace);
    for (int index = 0; index < EDGE_MAX_SOCKETS; ++index) {
        edge_socket_t *candidate = &g_sockets[index];
        struct udp_pcb *udp;
        uint32_t receiver_address;

        if (!candidate->used ||
            candidate->type != LINUX_SOCK_DGRAM ||
            !candidate->lwip_pcb)
            continue;
        udp = (struct udp_pcb *)candidate->lwip_pcb;
        if (!IP_IS_V4(&udp->local_ip)) continue;
        receiver_address = ip4_addr_get_u32(ip_2_ip4(&udp->local_ip));
        if (!kernel_socket_udp_local_delivery_match(
                sender->network_namespace, candidate->network_namespace,
                destination_port, udp->local_port,
                (const uint8_t *)&destination_address,
                (const uint8_t *)&receiver_address,
                sizeof(destination_address),
                destination_is_owned && ip_addr_isany(&udp->local_ip)))
            continue;
        edge_ip_receive_metadata_local(
            &metadata, sender, source, destination);
        edge_udp_receive_enqueue(
            candidate, udp, packet, source, source_port, &metadata);
        return 1;
    }
    return 0;
}

static void x86_udp_publish_local_refusal(
        edge_socket_t *socket, const ip_addr_t *destination,
        uint16_t destination_port) {
    int socket_id;

    if (!socket ||
        !kernel_socket_udp_local_refusal_policy(
            socket->connected, destination_port,
            destination && ip_addr_isloopback(destination),
            x86_udp_local_destination_is_bound(
                destination, destination_port)))
        return;
    socket->connect_error = ECONNREFUSED;
    socket_id = socket_id_from_ptr(socket);
    if (socket_id >= 0)
        fd_wake_socket_waiters_events(
            socket_id, LINUX_POLLIN | LINUX_POLLOUT |
                           LINUX_POLLERR);
}

static int x86_udp_payload_copy_from_iovec(
    struct pbuf *packet,
    const kernel_socket_iovec_source_t *source,
    uint64_t user_buffer, uint32_t length,
    uint8_t *scratch, uint32_t scratch_capacity) {
    uint32_t output_offset = 0u;

    if (!packet || !scratch || !scratch_capacity)
        return -EINVAL;
    if (source) {
        for (uint32_t index = 0; index < source->count; ++index) {
            struct edge_linux_iovec iov;
            uint64_t input_offset = 0u;
            int status = kernel_socket_iovec_source_read(
                source, index, &iov);

            if (status < 0) return status;
            if (output_offset > length ||
                iov.iov_len > length - output_offset)
                return -EINVAL;
            while (input_offset < iov.iov_len) {
                uint32_t count = (uint32_t)(iov.iov_len - input_offset);

                if (count > scratch_capacity) count = scratch_capacity;
                if (copy_from_user(
                        scratch, iov.iov_base + input_offset, count) < 0)
                    return -EFAULT;
                if (pbuf_take_at(
                        packet, scratch, (u16_t)count,
                        (u16_t)output_offset) != ERR_OK)
                    return -ENOMEM;
                input_offset += count;
                output_offset += count;
            }
        }
    } else {
        while (output_offset < length) {
            uint32_t count = length - output_offset;

            if (count > scratch_capacity) count = scratch_capacity;
            if (copy_from_user(
                    scratch, user_buffer + output_offset, count) < 0)
                return -EFAULT;
            if (pbuf_take_at(
                    packet, scratch, (u16_t)count,
                    (u16_t)output_offset) != ERR_OK)
                return -ENOMEM;
            output_offset += count;
        }
    }
    return output_offset == length ? 0 : -EINVAL;
}

static uint64_t x86_socket_sendto_entry_raw(
    int fd, edge_fd_t *fde, uint64_t buf_u, uint64_t len_u,
    uint64_t flags_u, uint64_t addr_u, uint64_t addrlen_u,
    const kernel_socket_iovec_source_t *datagram_source,
    const kernel_socket_ip_send_metadata_t *send_metadata) {
    task_t *cur = process_current_task();
    edge_socket_t *s = socket_from_fd_entry(fde);
    uint32_t len;
    int call_dontwait = (flags_u & LINUX_MSG_DONTWAIT) != 0;
    uint8_t tx[2048];
    uint8_t tcp_chunk[EDGE_RUNTIME_STREAM_COPY_CHUNK];
    uint8_t peer[28];
    uint32_t peer_len = 0;
    if (!s) return (uint64_t)-ENOTSOCK;
    if ((datagram_source &&
         datagram_source->total_length > UINT32_MAX) ||
        (!datagram_source && len_u > UINT32_MAX))
        return (uint64_t)-EMSGSIZE;
    len = datagram_source ?
        (uint32_t)datagram_source->total_length : (uint32_t)len_u;
    if (s->domain == LINUX_AF_UNIX && socket_type_is_record(s->type)) {
        struct edge_linux_iovec iov;
        kernel_socket_iovec_source_t source;
        int peer_id;
        int status;
        if (len != 0 && !buf_u) return (uint64_t)-EFAULT;
        status = unix_record_destination_from_user(
            s, addr_u, addrlen_u, &peer_id);
        if (status < 0) return (uint64_t)(int64_t)status;
        iov.iov_base = buf_u;
        iov.iov_len = len;
        if (kernel_socket_iovec_source_from_array(&source, &iov, 1) < 0)
            return (uint64_t)-EINVAL;
        return unix_record_send_iov_to(fd, s, fde, &source, 1, flags_u,
                                       peer_id, 0);
    }
    if (s->domain == LINUX_AF_UNIX && s->type == LINUX_SOCK_STREAM) {
        if (s->unix_peer_id < 0 || s->unix_peer_id >= EDGE_MAX_SOCKETS ||
            !g_sockets[s->unix_peer_id].used)
            return s->closed ? (uint64_t)-EPIPE : (uint64_t)-ENOTCONN;
        if (s->shutdown_write || g_sockets[s->unix_peer_id].shutdown_read)
            return (uint64_t)-EPIPE;
    }
    if (s->shutdown_write) return (uint64_t)-EPIPE;
    /*
     * Linux permits zero-length sends on stream sockets and returns 0.
     * X11/libxcb can exercise this through vector send paths; treating it as
     * EINVAL makes otherwise valid protocol writes look like client failures.
     */
    if (len == 0) return 0;
    if (!buf_u && !datagram_source) return (uint64_t)-EFAULT;

    if (s->domain == LINUX_AF_NETLINK) {
        kernel_socket_address_t destination;
        int queued;
        if (len > sizeof(tx)) return (uint64_t)-EMSGSIZE;
        if (copy_from_user(tx, buf_u, len) < 0) return (uint64_t)-EFAULT;
        memset(&destination, 0, sizeof(destination));
        if (addr_u) {
            if (addrlen_u > sizeof(destination.bytes))
                return (uint64_t)-EINVAL;
            destination.length = (uint32_t)addrlen_u;
            if (destination.length && copy_from_user(
                    destination.bytes, addr_u, destination.length) < 0)
                return (uint64_t)-EFAULT;
        } else if (addrlen_u) {
            return (uint64_t)-EFAULT;
        }
        queued = edge_linux_netlink_send(
            fd, (uint32_t)s->protocol, &destination, tx, len, s,
            netlink_kernel_request);
        return queued < 0 ? (uint64_t)(int64_t)queued : len;
    }

    if (s->domain == LINUX_AF_PACKET) {
        uint8_t frame[2062];
        uint16_t frame_len;
        if (len > sizeof(tx)) return (uint64_t)-EINVAL;
        if (copy_from_user(tx, buf_u, len) < 0) return (uint64_t)-EFAULT;
        if (len >= 14 && ((tx[12] == 0x08 && tx[13] == 0x00) ||
                          (tx[12] == 0x86 && tx[13] == 0xdd) ||
                          (tx[12] == 0x08 && tx[13] == 0x06))) {
            frame_len = (uint16_t)len;
            if (frame_len < 60) {
                memcpy(frame, tx, frame_len);
                memset(frame + frame_len, 0, 60 - frame_len);
                frame_len = 60;
                int result = s->ifindex > 2 ?
                    edge_linux_packet_transmit_frame(
                        s->network_namespace, s->ifindex, frame, frame_len) :
                    lwip_stack_send_packet_frame(frame, frame_len);
                if (result < 0) return (uint64_t)(int64_t)(
                    s->ifindex > 2 ? result : -ENETUNREACH);
            } else {
                int result = s->ifindex > 2 ?
                    edge_linux_packet_transmit_frame(
                        s->network_namespace, s->ifindex, tx, frame_len) :
                    lwip_stack_send_packet_frame(tx, frame_len);
                if (result < 0) return (uint64_t)(int64_t)(
                    s->ifindex > 2 ? result : -ENETUNREACH);
            }
        } else {
            if (len + 14 > sizeof(frame)) return (uint64_t)-EINVAL;
            memset(frame, 0xff, 6);
            memcpy(frame + 6, g_if_eth0.mac, 6);
            frame[12] = 0x08;
            frame[13] = 0x00;
            memcpy(frame + 14, tx, len);
            frame_len = (uint16_t)(len + 14);
            if (frame_len < 60) {
                memset(frame + frame_len, 0, 60 - frame_len);
                frame_len = 60;
            }
            {
                int result = s->ifindex > 2 ?
                    edge_linux_packet_transmit_frame(
                        s->network_namespace, s->ifindex, frame, frame_len) :
                    lwip_stack_send_packet_frame(frame, frame_len);
                if (result < 0) return (uint64_t)(int64_t)(
                    s->ifindex > 2 ? result : -ENETUNREACH);
            }
        }
        return len;
    }

    if (s->domain == LINUX_AF_UNIX && s->type == LINUX_SOCK_STREAM) {
        uint32_t off = 0;
        while (off < len) {
            edge_socket_t *peer;
            uint32_t room;
            uint32_t n;
            int peer_was_empty;
            uint64_t irq_flags;
            if (s->shutdown_write) return (uint64_t)-EPIPE;
            if (s->unix_peer_id < 0 || s->unix_peer_id >= EDGE_MAX_SOCKETS) {
            if (x11_sockio_trace_task(cur) && g_x11_sock_trace_budget-- > 0) {
                printf("[x11dbg] unix-send epipe pid=%d cmd=%s fd=%d sid=%d peer=%d len=%u off=%u\n",
                       cur->pid, cur->name, fd, fde ? fde->pipe_id : -1, s->unix_peer_id, len, off);
            }
                return (uint64_t)-EPIPE;
            }
            peer = &g_sockets[s->unix_peer_id];
            if (!peer->used || peer->shutdown_read) {
                if (x11_sockio_trace_task(cur) && g_x11_sock_trace_budget-- > 0) {
                    printf("[x11dbg] unix-send deadpeer pid=%d cmd=%s fd=%d sid=%d peer=%d len=%u off=%u\n",
                           cur->pid, cur->name, fd, fde ? fde->pipe_id : -1, s->unix_peer_id, len, off);
                }
                return (uint64_t)-EPIPE;
            }
            n = len - off;
            if (n > sizeof(tcp_chunk)) n = sizeof(tcp_chunk);
            if (copy_from_user(tcp_chunk, buf_u + off, n) < 0)
                return (uint64_t)-EFAULT;
            irq_flags = spin_lock_irqsave(&peer->io_lock);
            room = (peer->rx_len < socket_rx_capacity(peer)) ?
                   (uint32_t)(socket_rx_capacity(peer) - peer->rx_len) : 0;
            if (room == 0) {
                static int unix_send_full_budget = 32;
                spin_unlock_irqrestore(&peer->io_lock, irq_flags);
                /*
                 * Keep AF_UNIX stream progress observable to userland instead
                 * of blocking after a partial copy.  X11 clients and servers
                 * are prepared for short writes; returning the bytes already
                 * queued avoids a kernel-side wait that can stall the peer and
                 * make the desktop appear mapped but dead.
                 */
                if (off > 0) {
                    fd_wake_socket_waiters_events(s->unix_peer_id, LINUX_POLLIN | LINUX_POLLPRI);
                    fd_wake_unix_listener_for_pending_child(s->unix_peer_id);
                    return off;
                }
                if (call_dontwait || (fde && (fde->flags & LINUX_O_NONBLOCK)) || s->nonblock) {
                    return (uint64_t)-EAGAIN;
                }
                if (signal_pending_interrupt()) return tty_interrupt_current_ret();
                lwip_stack_poll();
                if (unix_send_full_budget > 0 && gui_diag_task(cur)) {
                    unix_send_full_budget--;
                    printf("[unix-send-full] pid=%d cmd=%s fd=%d sid=%d peer=%d len=%u off=%u peer_rx=%u cap=%u budget=%d\n",
                           cur ? cur->pid : -1, cur ? cur->name : "?",
                           fd, fde ? fde->pipe_id : -1, s->unix_peer_id,
                           len, off, peer->rx_len, (uint32_t)socket_rx_capacity(peer),
                           unix_send_full_budget);
                }
                /*
                 * Linux blocks stream writers on the socket writable wait
                 * queue.  The peer's receive path wakes POLLOUT on this socket
                 * after draining bytes; a generic sleep here misses that exact
                 * wakeup and can leave DBus/X11 writers advancing only at timer
                 * cadence under a full desktop.
                 */
                if (fde && cur) socket_waiter_add(fde->pipe_id, cur->pid,
                                                  LINUX_POLLOUT | LINUX_POLLWRNORM);
                room = (peer->rx_len < socket_rx_capacity(peer)) ?
                       (uint32_t)(socket_rx_capacity(peer) - peer->rx_len) : 0;
                if (room != 0) {
                    if (cur) waiter_remove_pid(cur->pid);
                    continue;
                }
                socket_blocking_wait_step(0);
                continue;
            }
            if (n > room) n = room;
            peer_was_empty = (peer->rx_len == 0);
            memcpy(peer->rx_buf + peer->rx_len, tcp_chunk, n);
            peer->rx_len += n;
            spin_unlock_irqrestore(&peer->io_lock, irq_flags);
            off += n;
            if (off == n) {
                x11_sockio_trace_bytes("send", cur, fd, fde ? fde->pipe_id : -1,
                                       s->unix_peer_id, len, peer->rx_len,
                                       tcp_chunk, n);
                xfce_sock_trace_bytes("send", cur, s, fd, fde ? fde->pipe_id : -1,
                                      s->unix_peer_id, len, peer->rx_len,
                                      tcp_chunk, n);
            }
            /*
             * A fresh AF_UNIX stream append is a fresh readiness event even if
             * the peer had unread bytes.  X11 clients and the window manager
             * use EPOLLET on their sockets; if EdgeOS only advances the read
             * generation on empty->non-empty transitions, later MapRequest,
             * ConfigureRequest, and ClientMessage records can sit behind
             * earlier unread bytes without waking the WM again.  Keep wakeups
             * exact through the registered socket waiter table rather than the
             * broad fd-owner fallback, but advance the read sequence for every
             * append so Linux-style edge consumers get another event when new
             * protocol bytes arrive.
             *
             * Red flag: do not replace this with a process-name or X11 path
             * special case.  The ABI contract belongs to AF_UNIX stream
             * readiness for all Linux userland.
             */
            (void)peer_was_empty;
            fd_wake_socket_waiters_events(s->unix_peer_id, LINUX_POLLIN | LINUX_POLLPRI);
            fd_wake_unix_listener_for_pending_child(s->unix_peer_id);
            /*
             * AF_UNIX streams are the hot path for X11 and usually carry many
             * small protocol records.  Waking the peer is the Linux-style event;
             * forcing a context switch for every queued fragment makes xcb/Xorg
             * startup crawl.  Blocking waits and the syscall return path still
             * provide scheduler handoff points when userland actually waits.
             */
        }
        if (x11_sockio_trace_task(cur) && g_x11_sock_trace_budget-- > 0) {
            printf("[x11dbg] unix-send ok pid=%d cmd=%s fd=%d sid=%d peer=%d len=%u queued=%u\n",
                   cur->pid, cur->name, fd, fde ? fde->pipe_id : -1, s->unix_peer_id, len,
                   (s->unix_peer_id >= 0 && s->unix_peer_id < EDGE_MAX_SOCKETS) ? g_sockets[s->unix_peer_id].rx_len : 0);
        }
        return off;
    }

    if ((s->domain == LINUX_AF_INET || s->domain == LINUX_AF_INET6) &&
        s->type == LINUX_SOCK_STREAM &&
        !s->lwip_pcb &&
        s->unix_peer_id >= 0) {
        if (!s->connected) return (uint64_t)-ENOTCONN;
        return socket_buffered_stream_send(s, fde, cur, fd, buf_u, len, call_dontwait);
    }

    if (addr_u && addrlen_u > 0) {
        peer_len = (uint32_t)addrlen_u;
        if (peer_len > sizeof(peer)) return (uint64_t)-EINVAL;
        if (copy_from_user(peer, addr_u, peer_len) < 0) return (uint64_t)-EFAULT;
    } else if (s->connected) {
        peer_len = s->peer_len;
        memcpy(peer, s->peer_addr, peer_len);
    } else {
        return (uint64_t)-EADDRNOTAVAIL;
    }
    if (s->domain == LINUX_AF_INET) socket_autobind_inet(s);

    if (s->domain == LINUX_AF_INET && s->type == LINUX_SOCK_RAW &&
        s->protocol == LINUX_IPPROTO_RAW) {
        uint64_t irq_flags;
        int status;
        if (len < 20u) return (uint64_t)-EINVAL;
        if (len > sizeof(g_raw_ipv4_tx)) return (uint64_t)-EMSGSIZE;
        irq_flags = spin_lock_irqsave(&g_raw_ipv4_tx_lock);
        if (copy_from_user(g_raw_ipv4_tx, buf_u, len) < 0) {
            spin_unlock_irqrestore(&g_raw_ipv4_tx_lock, irq_flags);
            return (uint64_t)-EFAULT;
        }
        status = lwip_stack_send_raw_ipv4(g_raw_ipv4_tx, (uint16_t)len);
        spin_unlock_irqrestore(&g_raw_ipv4_tx_lock, irq_flags);
        return status < 0 ? (uint64_t)-ENETUNREACH : len;
    }

    if ((s->domain == LINUX_AF_INET || s->domain == LINUX_AF_INET6) &&
        s->type == LINUX_SOCK_DGRAM &&
        (s->protocol == 0 || s->protocol == LINUX_IPPROTO_UDP) &&
        s->lwip_pcb) {
        struct edge_sockaddr_in sin;
        struct edge_sockaddr_in6 sin6;
        struct udp_pcb *up = (struct udp_pcb *)s->lwip_pcb;
        struct netif *output_netif = 0;
        edge_net_device_snapshot_t output_device;
        struct pbuf *p;
        ip_addr_t dst;
        ip_addr_t send_source;
        const ip_addr_t *send_source_pointer = 0;
        edge_linux_netfilter_tuple_t tuple;
        uint8_t route_source[16];
        int32_t requested_ifindex;
        int32_t selected_ifindex = 0;
        uint16_t destination_port;
        uint8_t saved_ttl;
        uint8_t saved_tos;
        err_t error;
        if (s->domain == LINUX_AF_INET) {
            if (sockaddr_in_from_buf(peer, peer_len, &sin) < 0) return (uint64_t)-EAFNOSUPPORT;
            ip_addr_set_zero_ip4(&dst);
            ip_2_ip4(&dst)->addr = sin.sin_addr;
        } else {
            if (sockaddr_in6_from_buf(peer, peer_len, &sin6) < 0) return (uint64_t)-EAFNOSUPPORT;
            ip_addr_set_zero_ip6(&dst);
            memcpy(&ip_2_ip6(&dst)->addr[0], sin6.sin6_addr, 16);
        }
        if (send_metadata) {
            if (send_metadata->family != (uint8_t)s->domain)
                return (uint64_t)-EINVAL;
            if (send_metadata->has_interface) {
                if (send_metadata->interface_index > UINT8_MAX ||
                    edge_net_route_interface_snapshot(
                        (int32_t)send_metadata->interface_index,
                        s->network_namespace,
                        &output_device) != EDGE_NET_OK)
                    return (uint64_t)-ENODEV;
                if (output_device.configuration.kind !=
                        EDGE_NET_DEVICE_LOOPBACK)
                    output_netif = 0;
            }
            if (send_metadata->has_source_address) {
                if (s->domain == LINUX_AF_INET) {
                    uint32_t source_address;

                    memcpy(&source_address,
                           send_metadata->source_address, 4u);
                    ip_addr_set_ip4_u32(&send_source, source_address);
                } else {
                    ip_addr_set_zero_ip6(&send_source);
                    memcpy(&ip_2_ip6(&send_source)->addr[0],
                           send_metadata->source_address, 16u);
                }
                send_source_pointer = &send_source;
            }
        }
        destination_port = edge_bswap16(
            s->domain == LINUX_AF_INET ?
                sin.sin_port : sin6.sin6_port);
        requested_ifindex = send_metadata &&
            send_metadata->has_interface ?
            (int32_t)send_metadata->interface_index : s->ifindex;
        memset(&tuple, 0, sizeof(tuple));
        tuple.network_namespace = s->network_namespace;
        tuple.output_ifindex = requested_ifindex > 0 ?
            requested_ifindex : 2;
        tuple.family = (uint8_t)s->domain;
        tuple.protocol = LINUX_IPPROTO_UDP;
        if (send_metadata && send_metadata->has_interface)
            memcpy(tuple.output_interface,
                   output_device.configuration.name,
                   sizeof(tuple.output_interface));
        else
            memcpy(tuple.output_interface, "eth0", sizeof("eth0"));
        tuple.source_port = up->local_port;
        tuple.destination_port = destination_port;
        if (s->domain == LINUX_AF_INET) {
            uint32_t source_address = send_source_pointer ?
                ip4_addr_get_u32(ip_2_ip4(send_source_pointer)) :
                (IP_IS_V4(&up->local_ip) ?
                 ip4_addr_get_u32(ip_2_ip4(&up->local_ip)) : 0u);
            memcpy(tuple.source_address, &source_address,
                   sizeof(source_address));
            memcpy(tuple.destination_address, &sin.sin_addr,
                   sizeof(sin.sin_addr));
        } else {
            if (send_source_pointer)
                edge_ip6_to_bytes(
                    ip_2_ip6(send_source_pointer), tuple.source_address);
            else if (IP_IS_V6(&up->local_ip))
                edge_ip6_to_bytes(
                    ip_2_ip6(&up->local_ip), tuple.source_address);
            memcpy(tuple.destination_address, sin6.sin6_addr,
                   sizeof(sin6.sin6_addr));
        }
        if (edge_linux_netfilter_translate_local(
                &tuple,
                EDGE_LINUX_NETFILTER_TRANSLATE_DESTINATION) > 0) {
            destination_port = tuple.destination_port;
            if (s->domain == LINUX_AF_INET) {
                memcpy(&ip_2_ip4(&dst)->addr,
                       tuple.destination_address,
                       sizeof(ip_2_ip4(&dst)->addr));
            } else {
                memcpy(&ip_2_ip6(&dst)->addr[0],
                       tuple.destination_address, 16u);
            }
        }
        memset(route_source, 0, sizeof(route_source));
        if (requested_ifindex > 0 || s->option_state.mark) {
            uint8_t preferred_source[16];

            output_netif = lwip_stack_select_socket_route(
                s->network_namespace, (uint8_t)s->domain,
                tuple.source_address, tuple.destination_address,
                s->option_state.mark, requested_ifindex,
                preferred_source, &selected_ifindex);
            if (!output_netif) return (uint64_t)-ENETUNREACH;
            tuple.output_ifindex = selected_ifindex;
            if (edge_net_device_snapshot(
                    selected_ifindex, &output_device) == EDGE_NET_OK)
                memcpy(tuple.output_interface,
                       output_device.configuration.name,
                       sizeof(tuple.output_interface));
            if (!send_source_pointer &&
                ((s->domain == LINUX_AF_INET &&
                  (preferred_source[0] || preferred_source[1] ||
                   preferred_source[2] || preferred_source[3])) ||
                 (s->domain == LINUX_AF_INET6 &&
                  memcmp(preferred_source, route_source, 16u) != 0))) {
                if (s->domain == LINUX_AF_INET) {
                    uint32_t source_address;

                    memcpy(&source_address, preferred_source, 4u);
                    ip_addr_set_ip4_u32(&send_source, source_address);
                } else {
                    ip_addr_set_zero_ip6(&send_source);
                    memcpy(&ip_2_ip6(&send_source)->addr[0],
                           preferred_source, 16u);
                }
                send_source_pointer = &send_source;
                memcpy(tuple.source_address, preferred_source,
                       s->domain == LINUX_AF_INET ? 4u : 16u);
            }
        }
        if (edge_linux_netfilter_translate_local(
                &tuple,
                EDGE_LINUX_NETFILTER_TRANSLATE_SOURCE) > 0 &&
            s->domain == LINUX_AF_INET) {
            uint32_t source_address;

            memcpy(&source_address, tuple.source_address,
                   sizeof(source_address));
            ip_addr_set_ip4_u32(&send_source, source_address);
            send_source_pointer = &send_source;
        }
        int copy_status;

        if (len > KERNEL_SOCKET_UDP_PAYLOAD_MAX)
            return (uint64_t)-EMSGSIZE;
        p = EDGE_LWIP_CALL(
            pbuf_alloc(PBUF_TRANSPORT, (u16_t)len, PBUF_RAM));
        if (!p) return (uint64_t)-ENOMEM;
        copy_status = x86_udp_payload_copy_from_iovec(
            p, datagram_source, buf_u, len, tx, sizeof(tx));
        if (copy_status < 0) {
            EDGE_LWIP_CALL(pbuf_free(p));
            return (uint64_t)(int64_t)copy_status;
        }
        saved_ttl = up->ttl;
        saved_tos = up->tos;
        up->ttl = send_metadata && send_metadata->has_hop_limit ?
            (uint8_t)send_metadata->hop_limit :
            (s->ip_ttl ? s->ip_ttl : 64u);
        up->tos = send_metadata && send_metadata->has_traffic_class ?
            (uint8_t)send_metadata->traffic_class : s->ip_tos;
        if (s->domain == LINUX_AF_INET) {
            ip_addr_t local_source;
            uint32_t source_address;

            memcpy(&source_address, tuple.source_address,
                   sizeof(source_address));
            ip_addr_set_ip4_u32(&local_source, source_address);
            if (EDGE_LWIP_CALL(x86_udp_deliver_local(
                    s, &dst, destination_port, p,
                    &local_source, tuple.source_port))) {
                up->ttl = saved_ttl;
                up->tos = saved_tos;
                return len;
            }
        }
        if (!output_netif && send_source_pointer)
            output_netif = ip_route(send_source_pointer, &dst);
        if (send_source_pointer && !output_netif) {
            up->ttl = saved_ttl;
            up->tos = saved_tos;
            EDGE_LWIP_CALL(pbuf_free(p));
            return (uint64_t)-ENETUNREACH;
        }
        if (output_netif && send_source_pointer)
            error = EDGE_LWIP_CALL(udp_sendto_if_src(
                up, p, &dst, destination_port,
                output_netif, send_source_pointer));
        else if (output_netif)
            error = EDGE_LWIP_CALL(udp_sendto_if(
                up, p, &dst, destination_port, output_netif));
        else
            error = EDGE_LWIP_CALL(
                udp_sendto(up, p, &dst, destination_port));
        up->ttl = saved_ttl;
        up->tos = saved_tos;
        EDGE_LWIP_CALL(pbuf_free(p));
        if (error != ERR_OK) return (uint64_t)-ENETUNREACH;
        x86_udp_publish_local_refusal(
            s, &dst, destination_port);
        return len;
    }

    if ((s->domain == LINUX_AF_INET || s->domain == LINUX_AF_INET6) &&
        s->type == LINUX_SOCK_STREAM &&
        (s->protocol == 0 || s->protocol == LINUX_IPPROTO_TCP) &&
        s->lwip_pcb) {
        uint32_t off = 0;
        if (!s->connected) return (uint64_t)-ENOTCONN;
        while (off < len) {
            uint32_t copied = len - off;
            uint32_t in_off = 0;
            if (copied > sizeof(tcp_chunk)) copied = sizeof(tcp_chunk);
            if (copy_from_user(tcp_chunk, buf_u + off, copied) < 0) return (uint64_t)-EFAULT;
            while (in_off < copied) {
                struct tcp_pcb *tp;
                uint16_t chunk;
                err_t er;
                chunk = (uint16_t)(
                    (copied - in_off) > EDGE_RUNTIME_STREAM_COPY_CHUNK ?
                        EDGE_RUNTIME_STREAM_COPY_CHUNK : (copied - in_off));
                lwip_stack_core_enter();
                tp = (struct tcp_pcb *)s->lwip_pcb;
                if (!tp) {
                    lwip_stack_core_exit();
                    return off || in_off ? off + in_off :
                           (uint64_t)-EPIPE;
                }
                er = tcp_write(tp, tcp_chunk + in_off, chunk,
                               TCP_WRITE_FLAG_COPY);
                lwip_stack_core_exit();
                if (er == ERR_MEM) {
                    if (call_dontwait || (fde && (fde->flags & LINUX_O_NONBLOCK)) || s->nonblock) {
                        if (off == 0 && in_off == 0) return (uint64_t)-EAGAIN;
                        return off + in_off;
                    }
                    if (signal_pending_interrupt()) return tty_interrupt_current_ret();
                    if (fde && cur) {
                        socket_waiter_add(fde->pipe_id, cur->pid,
                                          LINUX_POLLOUT | LINUX_POLLWRNORM);
                    }
                    lwip_stack_poll();
                    /*
                     * Recheck send space after waiter registration.  If it is
                     * still exhausted, leave the run queue until the lwIP sent
                     * callback observes an ACK and wakes POLLOUT.  This matches
                     * Linux blocking-send behavior and avoids a TLS writer
                     * burning a complete vCPU while waiting for the peer.
                     */
                    lwip_stack_core_enter();
                    tp = (struct tcp_pcb *)s->lwip_pcb;
                    if (tp && tcp_sndbuf(tp) >= chunk) {
                        lwip_stack_core_exit();
                        if (cur) waiter_remove_pid(cur->pid);
                        continue;
                    }
                    lwip_stack_core_exit();
                    if (!tp)
                        return off || in_off ? off + in_off :
                               (uint64_t)-EPIPE;
                    socket_blocking_wait_step(0);
                    continue;
                }
                if (er != ERR_OK) return off ? off : (uint64_t)-EIO;
                in_off += chunk;
            }
            off += copied;
            lwip_stack_core_enter();
            {
                struct tcp_pcb *tp = (struct tcp_pcb *)s->lwip_pcb;
                if (tp) (void)tcp_output(tp);
            }
            lwip_stack_core_exit();
        }
#if EDGE_SSH_IO_DEBUG
        if (ssh_trace_task(process_current_task())) {
            lwip_stack_core_enter();
            {
                struct tcp_pcb *tp = (struct tcp_pcb *)s->lwip_pcb;
                printf("[sshdbg] tcp-send fd=%d len=%u done=%u sndbuf=%u q=%u\n",
                       fd, len, off,
                       tp ? (unsigned)tcp_sndbuf(tp) : 0u,
                       tp ? (unsigned)tcp_sndqueuelen(tp) : 0u);
            }
            lwip_stack_core_exit();
        }
#endif
        return off;
    }

    if (len > sizeof(tx)) return (uint64_t)-EINVAL;
    if (copy_from_user(tx, buf_u, len) < 0) return (uint64_t)-EFAULT;

    if (s->domain == LINUX_AF_INET &&
        (s->type == LINUX_SOCK_RAW || s->type == LINUX_SOCK_DGRAM) &&
        s->protocol == LINUX_IPPROTO_ICMP) {
        struct edge_sockaddr_in sin;
        uint32_t dst_ip_be;
        if (len < 8) return len;
        if (len > sizeof(s->ping_req)) len = sizeof(s->ping_req);
        memcpy(s->ping_req, tx, len);
        s->ping_req_len = len;
        memcpy(s->ping_peer, peer, peer_len);
        s->ping_peer_len = peer_len;
        memcpy(&s->ping_next_seq_be, &tx[6], sizeof(uint16_t));
        memcpy(&s->ping_id_be, &tx[4], sizeof(uint16_t));
        s->ping_hw = 0;
        if (peer_len >= sizeof(sin)) {
            memcpy(&sin, peer, sizeof(sin));
            if (sin.sin_family == LINUX_AF_INET) {
                dst_ip_be = sin.sin_addr;
                if (lwip_stack_is_ready() &&
                    lwip_stack_send_icmp_echo(
                        s->network_namespace, dst_ip_be, tx,
                        (uint16_t)len, s->ip_ttl) == 0) {
                    s->ping_hw = 1;
                    return len;
                }
            }
        }
        return (uint64_t)-ENETUNREACH;
    }

    if (s->domain == LINUX_AF_INET6 &&
        (s->type == LINUX_SOCK_RAW || s->type == LINUX_SOCK_DGRAM) &&
        s->protocol == LINUX_IPPROTO_ICMPV6) {
        struct edge_sockaddr_in6 sin6;
        if (len < 8) return len;
        if (len > sizeof(s->ping_req)) len = sizeof(s->ping_req);
        memcpy(s->ping_req, tx, len);
        s->ping_req_len = len;
        memcpy(s->ping_peer, peer, peer_len);
        s->ping_peer_len = peer_len;
        memcpy(&s->ping_next_seq_be, &tx[6], sizeof(uint16_t));
        memcpy(&s->ping_id_be, &tx[4], sizeof(uint16_t));
        s->ping_hw = 0;
        if (peer_len >= sizeof(sin6)) {
            memcpy(&sin6, peer, sizeof(sin6));
            if (sin6.sin6_family == LINUX_AF_INET6) {
                if (lwip_stack_is_ready() &&
                    lwip_stack_send_icmpv6_echo(
                        s->network_namespace, sin6.sin6_addr, tx,
                        (uint16_t)len, s->ip_ttl) == 0) {
                    s->ping_hw = 1;
                    return len;
                }
            }
        }
        return (uint64_t)-ENETUNREACH;
    }

    return len;
}

static uint64_t x86_socket_sendto_raw(uint64_t fd_u, uint64_t buf_u,
                                      uint64_t len_u, uint64_t flags_u,
                                      uint64_t addr_u,
                                      uint64_t addrlen_u,
                                      const kernel_socket_iovec_source_t
                                          *datagram_source,
                                      const kernel_socket_ip_send_metadata_t
                                          *send_metadata) {
    kernel_fd_operation_lease_t lease = {0};
    edge_fd_t *entry;
    uint64_t result;
    int status;

    status = kernel_fd_operation_acquire((int32_t)fd_u, &lease);
    if (status < 0) return (uint64_t)(int64_t)status;
    entry = (edge_fd_t *)kernel_fd_operation_view(&lease);
    if (!entry) {
        (void)kernel_fd_operation_release(&lease);
        return (uint64_t)-EIO;
    }
    result = x86_socket_sendto_entry_raw(
        (int)fd_u, entry, buf_u, len_u, flags_u, addr_u, addrlen_u,
        datagram_source, send_metadata);
    (void)kernel_fd_operation_release(&lease);
    return result;
}

static uint64_t socket_recvfrom_entry_internal(
    int fd, edge_fd_t *e, uint64_t buf_u, uint64_t len_u,
    uint64_t flags_u, uint64_t addr_u, uint64_t addrlen_u,
    kernel_socket_rights_record_handle_t *received_rights) {
    task_t *cur = process_current_task();
    edge_socket_t *s = socket_from_fd_entry(e);
    uint32_t len = (uint32_t)len_u;
    int call_dontwait = (flags_u & LINUX_MSG_DONTWAIT) != 0;
    int call_peek = (flags_u & LINUX_MSG_PEEK) != 0;
    if (!s) return (uint64_t)-ENOTSOCK;
    /*
     * Linux recv with a zero byte count succeeds without touching the buffer.
     * Keep this before the NULL-buffer check so recv(fd, NULL, 0, ...) works.
     */
    if (len == 0) return 0;
    uint64_t start_us = boottime_monotonic_us();

    if (s->domain == LINUX_AF_PACKET && s->rx_len == 0) {
        (void)socket_try_fill_packet_frame(s);
    }

socket_recv_need_data:
    socket_maybe_promote_deferred_fin(s);
    while (s->rx_len == 0) {
        /*
         * lwIP retains a pbuf as refused_data when the fixed socket receive
         * queue is temporarily full.  Linux readers may call blocking recv(2)
         * again without an intervening poll(2); retrying refused data only from
         * poll readiness leaves a large TCP transfer permanently closed-window
         * after userspace drains the queue.  Refill before testing readiness so
         * apk, TLS clients, and ordinary streaming readers make forward progress
         * independent of which readiness API they use.
         */
        socket_try_refill_tcp_refused(s);
        (void)socket_try_fill_packet_frame(s);
        if (s->tcp_fin_pending) socket_drain_deferred_fin(s);
        else socket_maybe_promote_deferred_fin(s);
        if (s->rx_len > 0) break;
        if (s->type == LINUX_SOCK_STREAM && (s->rx_closed || s->closed)) {
            if (s->domain == LINUX_AF_UNIX && x11_sockio_trace_task(cur) && g_x11_sock_trace_budget-- > 0) {
                printf("[x11dbg] unix-recv closed pid=%d cmd=%s fd=%d sid=%d peer=%d len=%u\n",
                       cur->pid, cur->name, fd, e ? e->pipe_id : -1, s->unix_peer_id, len);
            }
            return 0;
        }
        (void)socket_try_fill_ping_hw_reply(s);
        if (s->rx_len > 0) break;
        if (s->domain != LINUX_AF_UNIX) {
            lwip_stack_poll();
            socket_try_refill_tcp_refused(s);
            (void)socket_try_fill_packet_frame(s);
            if (s->rx_len > 0) break;
        }
        if (call_dontwait || (e && (e->flags & LINUX_O_NONBLOCK)) || s->nonblock) {
            /*
             * A bounded always-on trace for AF_UNIX false-readiness.  If epoll
             * reports a local socket readable and the next nonblocking recv
             * gets EAGAIN, GUI stacks spin in syscalls and the whole desktop
             * feels slow even though no application is doing useful work.
             */
            static int unix_recv_eagain_diag_budget = EDGE_GUI_DEEP_TRACE ? 64 : 0;
            static int xfce_recv_eagain_budget = EDGE_XFCE_BOOT_TRACE ? 96 : 0;
            if (s->domain == LINUX_AF_UNIX && unix_recv_eagain_diag_budget > 0 &&
                gui_diag_task(cur)) {
                uint64_t read_sequence;
                uint64_t write_sequence;
                unix_recv_eagain_diag_budget--;
                kernel_socket_readiness_snapshot(
                    &s->readiness, &read_sequence, &write_sequence);
                printf("[unix-recv-eagain] pid=%d cmd=%s fd=%d sid=%d peer=%d len=%u flags=0x%x fdfl=0x%x rx=%u closed=%d rxclosed=%d rseq=%llu wseq=%llu budget=%d\n",
                       cur ? cur->pid : -1, cur ? cur->name : "?",
                       fd, e ? e->pipe_id : -1, s->unix_peer_id, len,
                       (uint32_t)flags_u, e ? (unsigned)e->flags : 0u,
                       s->rx_len, s->closed, s->rx_closed,
                       (unsigned long long)read_sequence,
                       (unsigned long long)write_sequence,
                       unix_recv_eagain_diag_budget);
            }
            if (s->domain == LINUX_AF_UNIX && xfce_recv_eagain_budget > 0 &&
                xfce_x11_peer_trace_task(cur, s)) {
                const task_t *peer = s->peer_cred_pid > 0 ? process_get_task(s->peer_cred_pid) : 0;
                uint64_t read_sequence;
                uint64_t write_sequence;
                kernel_socket_readiness_snapshot(
                    &s->readiness, &read_sequence, &write_sequence);
                printf("[xfce-x11io] eagain pid=%d cmd=%s fd=%d sid=%d peer=%d peerpid=%d peercmd=%s len=%u flags=0x%x fdfl=0x%x rx=%u closed=%d rxclosed=%d rseq=%llu wseq=%llu budget=%d\n",
                       cur ? cur->pid : -1, cur ? cur->name : "?",
                       fd, e ? e->pipe_id : -1, s->unix_peer_id,
                       s->peer_cred_pid, peer ? peer->name : "-",
                       len, (uint32_t)flags_u, e ? (unsigned)e->flags : 0u,
                       s->rx_len, s->closed, s->rx_closed,
                       (unsigned long long)read_sequence,
                       (unsigned long long)write_sequence,
                       xfce_recv_eagain_budget - 1);
                xfce_recv_eagain_budget--;
            }
            if (s->domain == LINUX_AF_UNIX && x11_sockio_trace_task(cur) && g_x11_sock_trace_budget-- > 0) {
                printf("[x11dbg] unix-recv eagain pid=%d cmd=%s fd=%d sid=%d peer=%d len=%u flags=0x%x nb=%d rx=%u closed=%d\n",
                       cur->pid, cur->name, fd, e ? e->pipe_id : -1, s->unix_peer_id, len,
                       (uint32_t)flags_u, s->nonblock, s->rx_len, s->closed);
            }
            return (uint64_t)-EAGAIN;
        }
        if (s->recv_timeout_us > 0) {
            uint64_t now_us = boottime_monotonic_us();
            if (now_us - start_us >= s->recv_timeout_us) return (uint64_t)-EAGAIN;
        }
        if (signal_pending_interrupt()) return tty_interrupt_current_ret();
        lwip_stack_poll();
        socket_try_refill_tcp_refused(s);
        (void)socket_try_fill_packet_frame(s);
        if (s->rx_len > 0) break;
        if (s->type == LINUX_SOCK_STREAM && (s->rx_closed || s->closed)) {
            continue;
        }
        /*
         * Blocking recv sleeps on the same exact socket wait queue used by
         * poll/select/epoll. External AF_PACKET and ICMP producers publish a
         * shared generation from the network bottom half, so they no longer
         * need a periodic 20 ms retry.
         */
        if (e && cur)
            socket_waiter_add(
                e->pipe_id, cur->pid,
                LINUX_POLLIN | LINUX_POLLPRI);
        /*
         * Linux's prepare-to-wait contract requires a final producer drain
         * after waiter installation. A packet can be queued after the empty
         * rx_len test but before this task leaves the run queue.
         */
        (void)socket_try_fill_packet_frame(s);
        (void)socket_try_fill_ping_hw_reply(s);
        if (s->rx_len > 0 ||
            (s->type == LINUX_SOCK_STREAM &&
             (s->rx_closed || s->closed))) {
            if (cur) waiter_remove_pid(cur->pid);
            continue;
        }
        socket_blocking_wait_step(
            s->recv_timeout_us > 0 ?
                start_us + s->recv_timeout_us : 0);
    }
#if EDGE_SSH_IO_DEBUG
    if (ssh_trace_task(process_current_task())) {
        printf("[sshdbg] recv-ready fd=%d len=%u rx_closed=%d closed=%d\n",
               fd, s->rx_len, s->rx_closed, s->closed);
    }
#endif

    uint64_t unix_io_flags = 0;
    int unix_io_locked = 0;
    int unix_wake_peer = -1;
    uint32_t unix_prepared_length = 0;
    uint32_t unix_address_length = 0;
    int unix_address_prepared = 0;
    if (s->domain == LINUX_AF_UNIX) {
        unix_prepared_length = s->rx_len < len ? s->rx_len : len;
        if (!user_access_ok(buf_u, unix_prepared_length, 1))
            return (uint64_t)-EFAULT;
        if (addr_u && addrlen_u) {
            if (copy_from_user(
                    &unix_address_length, addrlen_u,
                    sizeof(unix_address_length)) < 0 ||
                !user_access_ok(
                    addrlen_u, sizeof(unix_address_length), 1))
                return (uint64_t)-EFAULT;
            if (unix_address_length > sizeof(s->rx_peer))
                unix_address_length = sizeof(s->rx_peer);
            if (unix_address_length &&
                !user_access_ok(addr_u, unix_address_length, 1))
                return (uint64_t)-EFAULT;
            unix_address_prepared = 1;
        }
        unix_io_flags = spin_lock_irqsave(&s->io_lock);
        unix_io_locked = 1;
        /*
         * Another thread sharing this file description may have drained the
         * queue after the readiness check.  Retry the normal wait path rather
         * than copying stale bytes or underflowing rx_len.
         */
        if (s->rx_len == 0) {
            spin_unlock_irqrestore(&s->io_lock, unix_io_flags);
            goto socket_recv_need_data;
        }
    }

    if (s->domain != LINUX_AF_UNIX && s->filter_len != 0 &&
        !socket_filter_accepts(
            s, s->rx_buf,
            ((s->domain == LINUX_AF_INET ||
              s->domain == LINUX_AF_INET6) &&
             s->type == LINUX_SOCK_DGRAM && s->packet_count) ?
                socket_packet_front_length(s) : s->rx_len)) {
        if (!call_peek) {
            uint32_t dropped = s->rx_len;

            if ((s->domain == LINUX_AF_INET ||
                 s->domain == LINUX_AF_INET6) &&
                s->type == LINUX_SOCK_DGRAM && s->packet_count) {
                dropped = socket_packet_front_length(s);
                if (dropped < s->rx_len)
                    memmove(s->rx_buf, s->rx_buf + dropped,
                            s->rx_len - dropped);
                s->rx_len -= dropped;
                socket_packet_pop(s);
            } else {
                s->rx_len = 0;
            }
            socket_tcp_receive_consumed(s, dropped);
        }
        if (call_dontwait || (e && (e->flags & LINUX_O_NONBLOCK)) || s->nonblock) {
            return (uint64_t)-EAGAIN;
        }
        goto socket_recv_need_data;
    }

    uint32_t datagram_length = 0;
    uint32_t n;

    if ((s->domain == LINUX_AF_INET ||
         s->domain == LINUX_AF_INET6) &&
        s->type == LINUX_SOCK_DGRAM && s->packet_count) {
        datagram_length = socket_packet_front_length(s);
        s->received_timestamp_us =
            s->packet_timestamps_us[s->packet_head];
        s->received_ip_metadata =
            s->packet_ip_metadata[s->packet_head];
        s->rx_peer_len =
            s->packet_source_lengths[s->packet_head];
        if (s->rx_peer_len)
            memcpy(s->rx_peer,
                   s->packet_source_addresses[s->packet_head],
                   s->rx_peer_len);
        n = datagram_length;
    } else {
        n = s->rx_len;
    }
    if (n > len) n = len;
    if (s->domain == LINUX_AF_UNIX && n > unix_prepared_length)
        n = unix_prepared_length;
    if (s->domain == LINUX_AF_UNIX && received_rights) {
        kernel_socket_rights_record_info_t rights_info;
        uint32_t next_ordinal =
            *received_rights && call_peek ? 1u : 0u;
        int peek_status;

        if (!*received_rights &&
            socket_rights_peek_at(s, 0, &rights_info) == 0 &&
            rights_info.association_kind ==
                KERNEL_SOCKET_RIGHTS_ASSOCIATION_STREAM_BYTE &&
            rights_info.association_sequence <=
                s->unix_stream_head_sequence) {
            if (call_peek) {
                *received_rights = rights_info.handle;
                next_ordinal = 1u;
            } else if (socket_rights_take_front(
                           s, received_rights) < 0) {
                spin_unlock_irqrestore(
                    &s->io_lock, unix_io_flags);
                return (uint64_t)-EIO;
            }
        }
        peek_status =
            socket_rights_peek_at(
                s, next_ordinal, &rights_info);
        /*
         * Ancillary data is a stream barrier on Linux.  A recvmsg that owns one
         * SCM_RIGHTS record may consume bytes up to, but not including, the next
         * record's associated byte.  A recvmsg before the first record likewise
         * returns the preceding stream segment without stealing that record.
         */
        if (peek_status == 0 &&
            rights_info.association_kind ==
                KERNEL_SOCKET_RIGHTS_ASSOCIATION_STREAM_BYTE) {
            uint64_t barrier =
                rights_info.association_sequence >
                        s->unix_stream_head_sequence ?
                    rights_info.association_sequence -
                        s->unix_stream_head_sequence : 0;
            if (barrier < n) n = (uint32_t)barrier;
        }
    }
    if (n == 0) {
        if (unix_io_locked)
            spin_unlock_irqrestore(&s->io_lock, unix_io_flags);
        return (uint64_t)-EAGAIN;
    }
    if (copy_to_user(buf_u, s->rx_buf, n) < 0) {
        if (unix_io_locked)
            spin_unlock_irqrestore(&s->io_lock, unix_io_flags);
        return (uint64_t)-EFAULT;
    }
    if (s->domain == LINUX_AF_UNIX) {
        x11_sockio_trace_bytes("recv", cur, fd, e ? e->pipe_id : -1,
                               s->unix_peer_id, n,
                               s->rx_len > n ? s->rx_len - n : 0,
                               s->rx_buf, n);
        xfce_sock_trace_bytes("recv", cur, s, fd, e ? e->pipe_id : -1,
                              s->unix_peer_id, n,
                              s->rx_len > n ? s->rx_len - n : 0,
                              s->rx_buf, n);
    }
    if (addr_u && addrlen_u) {
        uint32_t alen = 0;
        if (unix_address_prepared) {
            alen = unix_address_length;
        } else if (copy_from_user(&alen, addrlen_u, sizeof(alen)) < 0) {
            if (unix_io_locked)
                spin_unlock_irqrestore(&s->io_lock, unix_io_flags);
            return (uint64_t)-EFAULT;
        }
        if (s->domain == LINUX_AF_NETLINK) {
            struct edge_sockaddr_nl source;
            uint32_t copied = alen;
            memset(&source, 0, sizeof(source));
            source.nl_family = LINUX_AF_NETLINK;
            if (copied > sizeof(source)) copied = (uint32_t)sizeof(source);
            if (copied && copy_to_user(addr_u, &source, copied) < 0) {
                if (unix_io_locked)
                    spin_unlock_irqrestore(&s->io_lock, unix_io_flags);
                return (uint64_t)-EFAULT;
            }
            alen = (uint32_t)sizeof(source);
        } else {
            if (alen > s->rx_peer_len) alen = s->rx_peer_len;
            if (alen && copy_to_user(addr_u, s->rx_peer, alen) < 0) {
                if (unix_io_locked)
                    spin_unlock_irqrestore(&s->io_lock, unix_io_flags);
                return (uint64_t)-EFAULT;
            }
        }
        if (copy_to_user(addrlen_u, &alen, sizeof(alen)) < 0) {
            if (unix_io_locked)
                spin_unlock_irqrestore(&s->io_lock, unix_io_flags);
            return (uint64_t)-EFAULT;
        }
    }
    if (!call_peek) {
        if (datagram_length) {
            if (datagram_length < s->rx_len)
                memmove(s->rx_buf,
                        s->rx_buf + datagram_length,
                        s->rx_len - datagram_length);
            s->rx_len -= datagram_length;
            socket_packet_pop(s);
        } else if (s->type == LINUX_SOCK_STREAM && n < s->rx_len) {
            memmove(s->rx_buf, s->rx_buf + n, s->rx_len - n);
            s->rx_len -= n;
        } else {
            s->rx_len = 0;
        }
        /*
         * Advancing lwIP's advertised window before userspace consumed these
         * bytes let a fast sender overrun EdgeOS' fixed socket queue.  The
         * resulting loss forced one TCP retransmission timeout per queue-sized
         * burst.  Linux credits receive-window space when data leaves the
         * socket receive queue, so do the same here (and never for MSG_PEEK).
         */
        socket_tcp_receive_consumed(s, n);
        if (s->domain == LINUX_AF_UNIX && e) {
            socket_rights_note_stream_read(s, n);
            if (!received_rights) {
                kernel_socket_rights_record_info_t rights_info;

                while (socket_rights_peek_at(
                           s, 0, &rights_info) == 0 &&
                       rights_info.association_kind ==
                           KERNEL_SOCKET_RIGHTS_ASSOCIATION_STREAM_BYTE &&
                       rights_info.association_sequence <
                           s->unix_stream_head_sequence)
                    socket_rights_drop_front(s);
            }
        }
        if ((s->domain == LINUX_AF_UNIX ||
             ((s->domain == LINUX_AF_INET || s->domain == LINUX_AF_INET6) && !s->lwip_pcb)) &&
            s->type == LINUX_SOCK_STREAM &&
            s->unix_peer_id >= 0 && s->unix_peer_id < EDGE_MAX_SOCKETS) {
            unix_wake_peer = s->unix_peer_id;
        }
    }
    if (unix_io_locked)
        spin_unlock_irqrestore(&s->io_lock, unix_io_flags);
    if (unix_wake_peer >= 0)
        fd_wake_socket_waiters_events(unix_wake_peer, LINUX_POLLOUT);
    /*
     * Do not yield after every successful stream read.  X11 clients and Xorg
     * drain sockets in short reads; syscall-boundary preemption is sufficient,
     * while per-read yields add visible latency to application mapping.
     */
    if (s->domain == LINUX_AF_UNIX && x11_sockio_trace_task(cur) && g_x11_sock_trace_budget-- > 0) {
        printf("[x11dbg] unix-recv ok pid=%d cmd=%s fd=%d sid=%d peer=%d got=%u remain=%u\n",
               cur->pid, cur->name, fd, e ? e->pipe_id : -1, s->unix_peer_id, n, s->rx_len);
    }
    return n;
}

static uint64_t socket_recvfrom_internal(
    uint64_t fd_u, uint64_t buf_u, uint64_t len_u,
    uint64_t flags_u, uint64_t addr_u, uint64_t addrlen_u,
    kernel_socket_rights_record_handle_t *received_rights) {
    kernel_fd_operation_lease_t lease = {0};
    edge_fd_t *entry;
    uint64_t result;
    int status;

    status = kernel_fd_operation_acquire((int32_t)fd_u, &lease);
    if (status < 0) return (uint64_t)(int64_t)status;
    entry = (edge_fd_t *)kernel_fd_operation_view(&lease);
    if (!entry) {
        (void)kernel_fd_operation_release(&lease);
        return (uint64_t)-EIO;
    }
    result = socket_recvfrom_entry_internal(
        (int)fd_u, entry, buf_u, len_u, flags_u, addr_u, addrlen_u,
        received_rights);
    (void)kernel_fd_operation_release(&lease);
    return result;
}

static uint64_t x86_socket_recvfrom_entry_raw(
    int fd, edge_fd_t *fde, uint64_t buf_u, uint64_t len_u,
    uint64_t flags_u, uint64_t addr_u, uint64_t addrlen_u) {
    edge_socket_t *s = socket_from_fd_entry(fde);
    if (s && s->domain == LINUX_AF_NETLINK) {
        struct edge_linux_iovec iov;
        kernel_socket_iovec_source_t source;
        uint64_t ret;
        if (len_u == 0) return 0;
        if (!buf_u) return (uint64_t)-EFAULT;
        iov.iov_base = buf_u;
        iov.iov_len = len_u;
        if (kernel_socket_iovec_source_from_array(&source, &iov, 1) < 0)
            return (uint64_t)-EINVAL;
        ret = netlink_record_recv_iov(fd, s, fde, &source, 1, flags_u, 0);
        if ((int64_t)ret < 0) return ret;
        if (addr_u && addrlen_u) {
            struct edge_sockaddr_nl source;
            uint32_t supplied;
            memset(&source, 0, sizeof(source));
            source.nl_family = LINUX_AF_NETLINK;
            if (s->rx_peer_len >= sizeof(source))
                memcpy(&source, s->rx_peer, sizeof(source));
            if (copy_from_user(&supplied, addrlen_u, sizeof(supplied)) < 0)
                return (uint64_t)-EFAULT;
            if (supplied > sizeof(source)) supplied = (uint32_t)sizeof(source);
            if (supplied && copy_to_user(addr_u, &source, supplied) < 0)
                return (uint64_t)-EFAULT;
            supplied = (uint32_t)sizeof(source);
            if (copy_to_user(addrlen_u, &supplied, sizeof(supplied)) < 0)
                return (uint64_t)-EFAULT;
        }
        return ret;
    }
    if (s && s->domain == LINUX_AF_UNIX && socket_type_is_record(s->type)) {
        struct edge_linux_iovec iov;
        kernel_socket_iovec_source_t source;
        uint64_t ret;
        int msg_flags = 0;
        uint32_t consumed = 0;
        if (len_u != 0 && !buf_u) return (uint64_t)-EFAULT;
        iov.iov_base = buf_u;
        iov.iov_len = len_u;
        if (kernel_socket_iovec_source_from_array(&source, &iov, 1) < 0)
            return (uint64_t)-EINVAL;
        ret = unix_record_recv_iov(fd, s, fde, &source, 1, flags_u, 0,
                                   &msg_flags, &consumed);
        if ((int64_t)ret < 0) return ret;
        if (addr_u && addrlen_u) {
            uint32_t alen = 0;
            if (copy_from_user(&alen, addrlen_u, sizeof(alen)) < 0) {
                return (uint64_t)-EFAULT;
            }
            if (alen > s->rx_peer_len) alen = s->rx_peer_len;
            if (alen && copy_to_user(addr_u, s->rx_peer, alen) < 0) {
                return (uint64_t)-EFAULT;
            }
            if (copy_to_user(addrlen_u, &alen, sizeof(alen)) < 0) {
                return (uint64_t)-EFAULT;
            }
        }
        return ret;
    }
    return socket_recvfrom_entry_internal(
        fd, fde, buf_u, len_u, flags_u, addr_u, addrlen_u, 0);
}

static uint64_t x86_socket_recvfrom_raw(
    uint64_t fd_u, uint64_t buf_u, uint64_t len_u,
    uint64_t flags_u, uint64_t addr_u, uint64_t addrlen_u) {
    kernel_fd_operation_lease_t lease = {0};
    edge_fd_t *entry;
    uint64_t result;
    int status;

    status = kernel_fd_operation_acquire((int32_t)fd_u, &lease);
    if (status < 0) return (uint64_t)(int64_t)status;
    entry = (edge_fd_t *)kernel_fd_operation_view(&lease);
    if (!entry) {
        (void)kernel_fd_operation_release(&lease);
        return (uint64_t)-EIO;
    }
    result = x86_socket_recvfrom_entry_raw(
        (int)fd_u, entry, buf_u, len_u, flags_u, addr_u, addrlen_u);
    (void)kernel_fd_operation_release(&lease);
    return result;
}

int64_t arch_socket_buffer_execute(
    const kernel_socket_buffer_request_t *request) {
    if (!request) return -EIO;
    return (int64_t)(request->receiving ?
        x86_socket_recvfrom_raw(
            (uint32_t)request->descriptor, request->user_buffer,
            request->length, request->flags, request->user_address,
            request->user_address_length) :
        x86_socket_sendto_raw(
            (uint32_t)request->descriptor, request->user_buffer,
            request->length, request->flags, request->user_address,
            request->user_address_length, 0, 0));
}

static int socket_recvmsg_deliver_rights(
    kernel_socket_rights_record_handle_t record,
    const kernel_socket_message_request_t *request,
    struct edge_linux_msghdr *msg,
    uint32_t *control_used, int *msg_flags, uint64_t flags_u,
    kernel_socket_rights_receive_result_t *delivery_result) {
    task_t *owner = request ?
        (task_t *)request->copy_context : 0;
    uint64_t common_used;
    int32_t common_flags;
    int status;

    if (delivery_result)
        memset(delivery_result, 0, sizeof(*delivery_result));
    if (!record) return 0;
    if (!msg || !control_used || !msg_flags || !delivery_result ||
        !request || !request->copy_to_user ||
        !owner || !owner->scratch)
        return -EINVAL;
    common_used = *control_used;
    common_flags = *msg_flags;
    status = kernel_socket_control_receive_rights_record(
        socket_rights_pool(), record,
        &owner->scratch->socket_rights_target,
        owner, request->copy_context, request->copy_to_user,
        msg->msg_control, msg->msg_controllen,
        &common_used, &common_flags, (uint32_t)flags_u,
        delivery_result);
    *control_used = common_used > UINT32_MAX ?
        UINT32_MAX : (uint32_t)common_used;
    *msg_flags = common_flags;
    return status;
}

static int64_t x86_socket_message_receive(
    const kernel_socket_message_request_t *request) {
    struct edge_linux_msghdr msg;
    kernel_socket_user_message_t imported;
    kernel_socket_iovec_source_t iov_source;
    edge_socket_t *s;
    task_t *cur = process_current_task();
    uint32_t control_used = 0;
    kernel_socket_rights_record_handle_t received_rights = 0;
    int out_msg_flags = 0;
    int control_delivery_stopped = 0;
    uint64_t total = 0;
    uint64_t fd_u;
    uint64_t msg_u;
    uint64_t flags_u;
    static int x11_recvmsg_diag_budget = EDGE_GUI_DEEP_TRACE ? 128 : 0;

    if (!request) return -EIO;
    fd_u = (uint32_t)request->descriptor;
    msg_u = request->user_header;
    flags_u = request->flags;
    out_msg_flags =
        kernel_socket_message_receive_output_flags((uint32_t)flags_u);
    imported = request->message;
    msg = imported.header;
    kernel_socket_iovec_source_from_message(&iov_source, &imported);
    s = socket_from_fd((int)fd_u);
    if (!s) return (uint64_t)-ENOTSOCK;
    if (x11_recvmsg_diag_budget > 0 && edge_x11_crash_trace_task(cur)) {
        struct edge_linux_iovec diagnostic_iov[2];
        memset(diagnostic_iov, 0, sizeof(diagnostic_iov));
        if (msg.msg_iovlen > 0)
            (void)kernel_socket_iovec_source_read(&iov_source, 0,
                                                  &diagnostic_iov[0]);
        if (msg.msg_iovlen > 1)
            (void)kernel_socket_iovec_source_read(&iov_source, 1,
                                                  &diagnostic_iov[1]);
        printf("[x11-recvmsg] enter pid=%d cmd=%s fd=%d domain=%d type=%d flags=0x%x msg=0x%x "
               "iovlen=%u i0=0x%x/%u i1=0x%x/%u ctrl=0x%x ctrllen=%u msgflags=0x%x rx=%u budget=%d\n",
               cur ? cur->pid : -1, cur ? cur->name : "?",
               (int)fd_u, s ? s->domain : -1, s ? s->type : -1,
               (uint32_t)flags_u, (uint32_t)msg_u,
               (uint32_t)msg.msg_iovlen,
               (uint32_t)diagnostic_iov[0].iov_base,
               (uint32_t)diagnostic_iov[0].iov_len,
               (uint32_t)diagnostic_iov[1].iov_base,
               (uint32_t)diagnostic_iov[1].iov_len,
               (uint32_t)msg.msg_control, (uint32_t)msg.msg_controllen,
               (uint32_t)msg.msg_flags, s ? s->rx_len : 0,
               x11_recvmsg_diag_budget - 1);
        x11_recvmsg_diag_budget--;
    }

    if (s && s->domain == LINUX_AF_UNIX && socket_type_is_record(s->type)) {
        uint64_t got = unix_record_recv_iov((int)fd_u, s,
                                            fd_get(fd_proc_with_stdio(), (int)fd_u),
                                            &iov_source, msg.msg_iovlen,
                                            flags_u, &received_rights,
                                            &out_msg_flags, 0);
        if ((int64_t)got < 0) {
            if (!(flags_u & LINUX_MSG_PEEK))
                socket_rights_record_drop(&received_rights);
            return got;
        }
        total = got;
        goto recvmsg_payload_done;
    }
    if (s && s->domain == LINUX_AF_NETLINK) {
        uint64_t got = netlink_record_recv_iov((int)fd_u, s,
                                               fd_get(fd_proc_with_stdio(),
                                                      (int)fd_u),
                                               &iov_source, msg.msg_iovlen,
                                               flags_u,
                                               &out_msg_flags);
        if ((int64_t)got < 0) return got;
        total = got;
        goto recvmsg_payload_done;
    }

    if (!msg.msg_iovlen) {
        edge_fd_t *fde = fd_get(fd_proc_with_stdio(), (int)fd_u);
        for (;;) {
            socket_maybe_promote_deferred_fin(s);
            socket_try_refill_tcp_refused(s);
            (void)socket_try_fill_packet_frame(s);
            if (s->rx_len ||
                (s->type == LINUX_SOCK_STREAM &&
                 (s->rx_closed || s->closed)))
                break;
            if ((flags_u & LINUX_MSG_DONTWAIT) ||
                (fde && (fde->flags & LINUX_O_NONBLOCK)) || s->nonblock)
                return (uint64_t)-EAGAIN;
            if (signal_pending_interrupt()) return tty_interrupt_current_ret();
            lwip_stack_poll();
            socket_try_refill_tcp_refused(s);
            if (s->rx_len) break;
            if (fde && cur)
                socket_waiter_add(fde->pipe_id, cur->pid,
                                  LINUX_POLLIN | LINUX_POLLPRI);
            if (s->rx_len ||
                (s->type == LINUX_SOCK_STREAM &&
                 (s->rx_closed || s->closed))) {
                if (cur) waiter_remove_pid(cur->pid);
                break;
            }
            socket_blocking_wait_step(0);
        }
        goto recvmsg_payload_done;
    }

    /*
     * X11 clients commonly use recvmsg/readv style buffers.  Consume across
     * every iovec, but after the first successful segment switch to a
     * nonblocking drain.  That matches Linux stream behavior: return available
     * bytes now instead of blocking forever trying to fill later iovecs.
     */
    for (uint64_t i = 0; i < msg.msg_iovlen; ++i) {
        struct edge_linux_iovec iov;
        uint64_t got;
        uint64_t call_flags = flags_u;
        int status = kernel_socket_iovec_source_read(
            &iov_source, (uint32_t)i, &iov);
        if (status < 0) {
            if (!(flags_u & LINUX_MSG_PEEK))
                socket_rights_record_drop(&received_rights);
            return (uint64_t)(int64_t)status;
        }
        if (iov.iov_len == 0) continue;
        if (total > 0) call_flags |= LINUX_MSG_DONTWAIT;
        /*
         * recvmsg owns SCM_RIGHTS delivery for the whole msghdr.  Do not let
         * the lower stream receive path pop rights records while filling the
         * payload iovecs.  This must be per-call state: AF_UNIX recvmsg can
         * block and yield, so a global "current recvmsg socket" corrupts
         * unrelated D-Bus/GTK/X11 threads running at the same time.
         */
        got = socket_recvfrom_internal(fd_u, iov.iov_base, iov.iov_len,
                                       call_flags, 0, 0, &received_rights);
        if ((int64_t)got < 0) {
            if (!total) {
                if (!(flags_u & LINUX_MSG_PEEK))
                    socket_rights_record_drop(&received_rights);
                return got;
            }
            break;
        }
        total += got;
        if (s && (s->domain == LINUX_AF_INET ||
                  s->domain == LINUX_AF_INET6) &&
            s->type == LINUX_SOCK_DGRAM)
            break;
        if (got < iov.iov_len) break;
    }
recvmsg_payload_done:
    if (s && s->domain == LINUX_AF_NETLINK && msg.msg_name && msg.msg_namelen > 0) {
        struct edge_sockaddr_nl nl;
        uint32_t nlen = msg.msg_namelen;
        memset(&nl, 0, sizeof(nl));
        nl.nl_family = LINUX_AF_NETLINK;
        if (s->rx_peer_len >= sizeof(nl))
            memcpy(&nl, s->rx_peer, sizeof(nl));
        if (nlen > sizeof(nl)) nlen = (uint32_t)sizeof(nl);
        if (copy_to_user(msg.msg_name, &nl, nlen) < 0) {
            if (!(flags_u & LINUX_MSG_PEEK))
                socket_rights_record_drop(&received_rights);
            return (uint64_t)-EFAULT;
        }
        msg.msg_namelen = (uint32_t)sizeof(nl);
    } else if (s && msg.msg_name && msg.msg_namelen > 0 && s->rx_peer_len > 0) {
        uint32_t nlen = msg.msg_namelen;
        if (nlen > s->rx_peer_len) nlen = s->rx_peer_len;
        if (copy_to_user(msg.msg_name, s->rx_peer, nlen) < 0) {
            if (!(flags_u & LINUX_MSG_PEEK))
                socket_rights_record_drop(&received_rights);
            return (uint64_t)-EFAULT;
        }
        msg.msg_namelen = nlen;
    } else if (s && msg.msg_name && msg.msg_namelen > 0) {
        msg.msg_namelen = 0;
    }
    if (!control_delivery_stopped && s && total > 0 &&
        (s->domain == LINUX_AF_INET ||
         s->domain == LINUX_AF_INET6) &&
        s->type == LINUX_SOCK_DGRAM &&
        msg.msg_controllen >= (uint64_t)control_used) {
        kernel_socket_control_receive_result_t control_result;
        uint64_t common_used = control_used;
        int32_t common_flags = out_msg_flags;
        int status;

        status = kernel_socket_ip_receive_control_append(
            &s->option_state, &s->received_ip_metadata,
            0, x86_socket_message_copy_to_user,
            msg.msg_control, msg.msg_controllen,
            &common_used, &common_flags, &control_result);
        if (status < 0) return (uint64_t)(int64_t)status;
        control_used = common_used > UINT32_MAX ?
            UINT32_MAX : (uint32_t)common_used;
        out_msg_flags = common_flags;
        control_delivery_stopped =
            control_result != KERNEL_SOCKET_CONTROL_RECEIVE_APPENDED;
    }
    if (!control_delivery_stopped && s &&
        s->domain == LINUX_AF_NETLINK && total > 0 &&
        s->option_state.netlink_packet_info &&
        msg.msg_controllen >= (uint64_t)control_used) {
        kernel_socket_control_receive_result_t control_result;
        uint64_t common_used = control_used;
        int32_t common_flags = out_msg_flags;
        uint32_t group = 0;
        int status;

        if (s->rx_peer_len >= sizeof(struct edge_sockaddr_nl)) {
            struct edge_sockaddr_nl source_address;
            uint32_t group_mask;
            memcpy(&source_address, s->rx_peer, sizeof(source_address));
            group_mask = source_address.nl_groups;
            while (group_mask && !(group_mask & 1u)) {
                ++group;
                group_mask >>= 1u;
            }
            if (group_mask) ++group;
        }
        status = kernel_socket_control_receive_metadata_append(
            0, x86_socket_message_copy_to_user,
            msg.msg_control, msg.msg_controllen,
            &common_used, &common_flags,
            EDGE_LINUX_SOL_NETLINK, EDGE_LINUX_NETLINK_PACKET_INFO,
            &group, sizeof(group), &control_result);
        if (status < 0) return (uint64_t)(int64_t)status;
        control_used = common_used > UINT32_MAX ?
            UINT32_MAX : (uint32_t)common_used;
        out_msg_flags = common_flags;
        control_delivery_stopped =
            control_result != KERNEL_SOCKET_CONTROL_RECEIVE_APPENDED;
    }
    if (s && s->domain == LINUX_AF_UNIX && received_rights) {
        uint64_t rights_irq_flags = 0;
        kernel_socket_rights_receive_result_t rights_result;
        int rights_locked = 0;
        int rc;

        if ((flags_u & LINUX_MSG_PEEK) && msg.msg_control &&
            msg.msg_controllen &&
            !user_access_ok(msg.msg_control, msg.msg_controllen, 1))
            return (uint64_t)-EFAULT;
        if (flags_u & LINUX_MSG_PEEK) {
            kernel_socket_rights_record_info_t rights_info;

            rights_irq_flags =
                spin_lock_irqsave(&s->io_lock);
            rights_locked = 1;
            if (socket_rights_peek_at(
                    s, 0, &rights_info) < 0 ||
                rights_info.handle != received_rights)
                received_rights = 0;
        }
        rc = socket_recvmsg_deliver_rights(
            received_rights, request, &msg, &control_used,
            &out_msg_flags, flags_u, &rights_result);
        if (rights_locked)
            spin_unlock_irqrestore(
                &s->io_lock, rights_irq_flags);
        if (!(flags_u & LINUX_MSG_PEEK))
            socket_rights_record_drop(&received_rights);
        if (rc < 0) return (uint64_t)(int64_t)rc;
        control_delivery_stopped =
            rights_result.truncated || rights_result.control_fault;
    }
    if (!control_delivery_stopped && s &&
        (s->domain == LINUX_AF_UNIX ||
         s->domain == LINUX_AF_NETLINK) &&
        s->option_state.pass_credentials && total > 0 &&
        msg.msg_controllen >= (uint64_t)control_used) {
        struct {
            int pid;
            uint32_t uid;
            uint32_t gid;
        } cred;
        kernel_socket_control_receive_result_t control_result;
        uint64_t common_used;
        int32_t common_flags;
        int status;

        memset(&cred, 0, sizeof(cred));
        if (s->domain == LINUX_AF_NETLINK) {
            cred.pid = s->received_cred_pid;
            cred.uid = s->received_cred_uid;
            cred.gid = s->received_cred_gid;
        } else if (socket_type_is_record(s->type) &&
                   s->received_cred_pid > 0) {
            cred.pid = s->received_cred_pid;
            cred.uid = s->received_cred_uid;
            cred.gid = s->received_cred_gid;
        } else if (s->peer_cred_pid > 0) {
            cred.pid = s->peer_cred_pid;
            cred.uid = s->peer_cred_uid;
            cred.gid = s->peer_cred_gid;
        } else if (s->unix_peer_id >= 0 && s->unix_peer_id < EDGE_MAX_SOCKETS &&
                   g_sockets[s->unix_peer_id].used) {
            edge_socket_t *peer = &g_sockets[s->unix_peer_id];
            cred.pid = peer->cred_pid;
            cred.uid = peer->cred_uid;
            cred.gid = peer->cred_gid;
        } else {
            cred.pid = s->cred_pid;
            cred.uid = s->cred_uid;
            cred.gid = s->cred_gid;
        }
        common_used = control_used;
        common_flags = out_msg_flags;
        status = kernel_socket_control_receive_metadata_append(
            0, x86_socket_message_copy_to_user,
            msg.msg_control, msg.msg_controllen,
            &common_used, &common_flags,
            LINUX_SOL_SOCKET, LINUX_SCM_CREDENTIALS,
            &cred, sizeof(cred), &control_result);
        if (status < 0) return (uint64_t)(int64_t)status;
        control_used = common_used > UINT32_MAX ?
            UINT32_MAX : (uint32_t)common_used;
        out_msg_flags = common_flags;
        control_delivery_stopped =
            control_result != KERNEL_SOCKET_CONTROL_RECEIVE_APPENDED;
    }
    if (!control_delivery_stopped && s && total > 0 &&
        s->option_state.timestamp_mode != KERNEL_SOCKET_TIMESTAMP_DISABLED) {
        kernel_socket_control_receive_result_t control_result;
        uint64_t common_used = control_used;
        int32_t common_flags = out_msg_flags;
        int status = kernel_socket_timestamp_control_receive_append(
            (kernel_socket_timestamp_mode_t)s->option_state.timestamp_mode,
            s->received_timestamp_us, 0, x86_socket_message_copy_to_user,
            msg.msg_control, msg.msg_controllen, &common_used, &common_flags,
            &control_result);
        control_used = common_used > UINT32_MAX ? UINT32_MAX :
                                                   (uint32_t)common_used;
        out_msg_flags = common_flags;
        if (status < 0) return (uint64_t)(int64_t)status;
    }
    if (x11_recvmsg_diag_budget > 0 && edge_x11_crash_trace_task(cur)) {
        uint8_t b[8];
        uint32_t got = 0;
        struct edge_linux_iovec first_iov;
        memset(b, 0, sizeof(b));
        memset(&first_iov, 0, sizeof(first_iov));
        if (msg.msg_iovlen > 0)
            (void)kernel_socket_iovec_source_read(
                &iov_source, 0, &first_iov);
        if (total > 0 && first_iov.iov_base) {
            got = total < sizeof(b) ? (uint32_t)total : (uint32_t)sizeof(b);
            if (got > first_iov.iov_len) got = (uint32_t)first_iov.iov_len;
            if (got > 0 && copy_from_user(b, first_iov.iov_base, got) < 0)
                got = 0;
        }
        printf("[x11-recvmsg] exit pid=%d cmd=%s fd=%d ret=%u used=%u outflags=0x%x rx=%u "
               "b=%x,%x,%x,%x,%x,%x,%x,%x budget=%d\n",
               cur ? cur->pid : -1, cur ? cur->name : "?",
               (int)fd_u, (uint32_t)total, control_used, (uint32_t)out_msg_flags,
               s ? s->rx_len : 0,
               b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
               x11_recvmsg_diag_budget - 1);
        x11_recvmsg_diag_budget--;
    }
    /*
     * Linux treats msg_name/msg_iov/msg_control as caller-owned input pointers.
     * recvmsg() writes back only the output scalar fields and ancillary/name
     * payloads.  Re-copying the whole msghdr can overwrite userland stack or
     * library bookkeeping with the kernel's stale input snapshot; GLib/D-Bus
     * exercise this heavily during XFCE startup.
     */
    if (kernel_socket_message_write_output(
            0, x86_socket_message_copy_to_user, &imported,
            msg.msg_namelen, control_used, out_msg_flags) < 0)
        return (uint64_t)-EFAULT;
    return total;
}

static int64_t unix_stream_sendmsg_rights_prefix(
    int descriptor, edge_socket_t *socket, edge_fd_t *description,
    const kernel_socket_iovec_source_t *source, uint64_t iov_count,
    uint64_t flags, kernel_socket_rights_record_handle_t *rights) {
    task_t *current = process_current_task();
    uint8_t first_byte;
    int call_dontwait = (flags & LINUX_MSG_DONTWAIT) != 0;

    (void)descriptor;
    if (!socket || socket->domain != LINUX_AF_UNIX ||
        socket->type != LINUX_SOCK_STREAM || !rights || !*rights)
        return -EINVAL;

    for (uint64_t index = 0; index < iov_count; ++index) {
        struct edge_linux_iovec iov;
        int status = kernel_socket_iovec_source_read(
            source, (uint32_t)index, &iov);
        if (status < 0) return status;
        if (!iov.iov_len) continue;
        if (copy_from_user(&first_byte, iov.iov_base, sizeof(first_byte)) < 0)
            return -EFAULT;
        for (;;) {
            edge_socket_t *peer;
            uint64_t irq_flags;
            uint32_t room;
            int can_send;

            if (socket->shutdown_write) return -EPIPE;
            if (socket->unix_peer_id < 0 ||
                socket->unix_peer_id >= EDGE_MAX_SOCKETS)
                return kernel_unix_socket_missing_peer_error(
                    (uint32_t)socket->type, socket->closed);
            peer = &g_sockets[socket->unix_peer_id];
            irq_flags = spin_lock_irqsave(&peer->io_lock);
            if (!peer->used || peer->closed || peer->shutdown_read ||
                peer->type != socket->type) {
                spin_unlock_irqrestore(&peer->io_lock, irq_flags);
                return -EPIPE;
            }
            room = peer->rx_len < socket_rx_capacity(peer) ?
                   socket_rx_capacity(peer) - peer->rx_len : 0;
            if (room != 0 &&
                kernel_socket_rights_queue_count(&peer->rights) <
                    peer->rights.limit) {
                uint64_t association_sequence =
                    peer->unix_stream_head_sequence + peer->rx_len;
                /*
                 * The rights record and its first byte become visible while
                 * holding the same queue lock used by every AF_UNIX writer and
                 * reader.  Linux associates ancillary data with this byte; no
                 * receiver may observe one without the other.
                 */
                if (socket_rights_enqueue(
                        peer, rights,
                        KERNEL_SOCKET_RIGHTS_ASSOCIATION_STREAM_BYTE,
                        association_sequence) < 0) {
                    spin_unlock_irqrestore(&peer->io_lock, irq_flags);
                    return -EAGAIN;
                }
                peer->rx_buf[peer->rx_len++] = first_byte;
                spin_unlock_irqrestore(&peer->io_lock, irq_flags);
                fd_wake_socket_waiters_events(
                    socket->unix_peer_id, LINUX_POLLIN | LINUX_POLLPRI);
                fd_wake_unix_listener_for_pending_child(socket->unix_peer_id);
                return 1;
            }
            spin_unlock_irqrestore(&peer->io_lock, irq_flags);

            if (call_dontwait ||
                (description &&
                 (description->flags & LINUX_O_NONBLOCK)) ||
                socket->nonblock)
                return -EAGAIN;
            if (signal_pending_interrupt()) return tty_interrupt_current_ret();
            if (description && current)
                socket_waiter_add(description->pipe_id, current->pid,
                                  LINUX_POLLOUT | LINUX_POLLWRNORM);
            irq_flags = spin_lock_irqsave(&peer->io_lock);
            room = peer->rx_len < socket_rx_capacity(peer) ?
                   socket_rx_capacity(peer) - peer->rx_len : 0;
            can_send = room != 0 &&
                kernel_socket_rights_queue_count(&peer->rights) <
                    peer->rights.limit;
            spin_unlock_irqrestore(&peer->io_lock, irq_flags);
            if (can_send) {
                if (current) waiter_remove_pid(current->pid);
                continue;
            }
            socket_blocking_wait_step(0);
        }
    }

    /*
     * Linux stream ancillary data requires a payload byte.  A zero-length
     * message therefore transfers neither data nor descriptors.
     */
    return 0;
}

static int64_t unix_stream_sendmsg_iov(
    int descriptor, edge_socket_t *socket, edge_fd_t *description,
    const kernel_socket_iovec_source_t *source, uint64_t iov_count,
    uint64_t flags, kernel_socket_rights_record_handle_t *rights) {
    task_t *current = process_current_task();
    uint64_t total64 = 0;
    uint32_t total;
    int call_dontwait = (flags & LINUX_MSG_DONTWAIT) != 0;

    (void)descriptor;
    if (!socket || socket->domain != LINUX_AF_UNIX ||
        socket->type != LINUX_SOCK_STREAM || !source)
        return -EINVAL;

    for (uint64_t index = 0; index < iov_count; ++index) {
        struct edge_linux_iovec iov;
        int status = kernel_socket_iovec_source_read(
            source, (uint32_t)index, &iov);

        if (status < 0) return status;
        if (iov.iov_len > UINT32_MAX ||
            total64 > UINT32_MAX - iov.iov_len)
            return -EMSGSIZE;
        total64 += iov.iov_len;
    }
    total = (uint32_t)total64;
    if (!total) return 0;
    if (socket_iovec_user_access_prepare(
            source, (uint32_t)iov_count, total, 0) < 0)
        return -EFAULT;

    for (;;) {
        edge_socket_t *peer;
        uint64_t irq_flags;
        uint32_t room;
        uint32_t send_length;
        uint32_t copied = 0;

        if (socket->shutdown_write) return -EPIPE;
        if (socket->unix_peer_id < 0 ||
            socket->unix_peer_id >= EDGE_MAX_SOCKETS)
            return kernel_unix_socket_missing_peer_error(
                (uint32_t)socket->type, socket->closed);
        peer = &g_sockets[socket->unix_peer_id];
        irq_flags = spin_lock_irqsave(&peer->io_lock);
        if (!peer->used || peer->closed || peer->shutdown_read ||
            peer->type != socket->type) {
            spin_unlock_irqrestore(&peer->io_lock, irq_flags);
            return -EPIPE;
        }
        room = peer->rx_len < socket_rx_capacity(peer) ?
               socket_rx_capacity(peer) - peer->rx_len : 0u;
        if (!room || (rights && *rights &&
            kernel_socket_rights_queue_count(&peer->rights) >=
                peer->rights.limit)) {
            spin_unlock_irqrestore(&peer->io_lock, irq_flags);
            if (call_dontwait ||
                (description &&
                 (description->flags & LINUX_O_NONBLOCK)) ||
                socket->nonblock)
                return -EAGAIN;
            if (signal_pending_interrupt())
                return tty_interrupt_current_ret();
            if (description && current)
                socket_waiter_add(description->pipe_id, current->pid,
                                  LINUX_POLLOUT | LINUX_POLLWRNORM);
            socket_blocking_wait_step(0);
            continue;
        }

        send_length = total < room ? total : room;
        for (uint64_t index = 0;
             index < iov_count && copied < send_length; ++index) {
            struct edge_linux_iovec iov;
            uint32_t count;
            int status = kernel_socket_iovec_source_read(
                source, (uint32_t)index, &iov);

            if (status < 0) {
                spin_unlock_irqrestore(&peer->io_lock, irq_flags);
                return status;
            }
            count = iov.iov_len > send_length - copied ?
                    send_length - copied : (uint32_t)iov.iov_len;
            if (count && copy_from_user(
                    peer->rx_buf + peer->rx_len + copied,
                    iov.iov_base, count) < 0) {
                spin_unlock_irqrestore(&peer->io_lock, irq_flags);
                return -EFAULT;
            }
            copied += count;
        }
        if (rights && *rights && socket_rights_enqueue(
                peer, rights,
                KERNEL_SOCKET_RIGHTS_ASSOCIATION_STREAM_BYTE,
                peer->unix_stream_head_sequence + peer->rx_len) < 0) {
            spin_unlock_irqrestore(&peer->io_lock, irq_flags);
            return -EAGAIN;
        }
        peer->rx_len += copied;
        spin_unlock_irqrestore(&peer->io_lock, irq_flags);
        if (current) waiter_remove_pid(current->pid);
        fd_wake_socket_waiters_events(
            socket->unix_peer_id, LINUX_POLLIN | LINUX_POLLPRI);
        fd_wake_unix_listener_for_pending_child(socket->unix_peer_id);
        return copied;
    }
}

static int64_t x86_socket_message_send(
    const kernel_socket_message_request_t *request) {
    struct edge_linux_msghdr msg;
    kernel_socket_user_message_t imported;
    kernel_socket_iovec_source_t iov_source;
    kernel_socket_rights_record_handle_t rights_record = 0;
    kernel_socket_ip_send_metadata_t ip_send_metadata;
    const kernel_socket_ip_send_metadata_t *ip_send_metadata_pointer = 0;
    edge_socket_t *s;
    int record_peer_id = -1;
    int stream_rights_prefixed = 0;
    int rc;
    uint64_t total = 0;
    uint64_t fd_u;
    uint64_t flags_u;

    if (!request) return -EIO;
    fd_u = (uint32_t)request->descriptor;
    flags_u = request->flags;
    imported = request->message;
    msg = imported.header;
    kernel_socket_iovec_source_from_message(&iov_source, &imported);
    if (msg.msg_controllen > UINT32_MAX) return (uint64_t)-EINVAL;
    rc = kernel_socket_rights_record_import(
        socket_rights_pool(), request->copy_context,
        request->copy_context, request->copy_from_user,
        msg.msg_control, msg.msg_controllen, &rights_record);
    if (rc < 0) return (uint64_t)rc;
    s = socket_from_fd((int)fd_u);
    if (!s) {
        socket_rights_record_drop(&rights_record);
        return (uint64_t)-ENOTSOCK;
    }
    if ((s->domain == LINUX_AF_INET ||
         s->domain == LINUX_AF_INET6) &&
        s->type == LINUX_SOCK_DGRAM && msg.msg_controllen) {
        rc = kernel_socket_ip_send_control_parse(
            (uint8_t)s->domain, request->copy_context,
            request->copy_from_user, msg.msg_control,
            msg.msg_controllen, &ip_send_metadata);
        if (rc < 0) {
            socket_rights_record_drop(&rights_record);
            return (uint64_t)(int64_t)rc;
        }
        ip_send_metadata_pointer = &ip_send_metadata;
    }
    if (s->domain == LINUX_AF_UNIX && socket_type_is_record(s->type)) {
        rc = unix_record_destination_from_user(
            s, msg.msg_name, msg.msg_namelen, &record_peer_id);
        if (rc < 0) {
            socket_rights_record_drop(&rights_record);
            return (uint64_t)(int64_t)rc;
        }
    }
    if (s && s->domain == LINUX_AF_NETLINK) {
        uint8_t request[2048];
        kernel_socket_address_t destination;
        uint32_t length = 0;
        int queued;
        socket_rights_record_drop(&rights_record);
        for (uint64_t index = 0; index < msg.msg_iovlen; ++index) {
            struct edge_linux_iovec iov;
            int status = kernel_socket_iovec_source_read(
                &iov_source, (uint32_t)index, &iov);
            if (status < 0) return (uint64_t)(int64_t)status;
            if (iov.iov_len > sizeof(request) - length)
                return (uint64_t)-EMSGSIZE;
            if (iov.iov_len && copy_from_user(request + length,
                    iov.iov_base, iov.iov_len) < 0)
                return (uint64_t)-EFAULT;
            length += (uint32_t)iov.iov_len;
        }
        memset(&destination, 0, sizeof(destination));
        if (msg.msg_name) {
            if (msg.msg_namelen > sizeof(destination.bytes))
                return (uint64_t)-EINVAL;
            destination.length = msg.msg_namelen;
            if (destination.length && copy_from_user(
                    destination.bytes, msg.msg_name,
                    destination.length) < 0)
                return (uint64_t)-EFAULT;
        } else if (msg.msg_namelen) {
            return (uint64_t)-EFAULT;
        }
        queued = edge_linux_netlink_send(
            (int32_t)fd_u, (uint32_t)s->protocol, &destination,
            request, length, s, netlink_kernel_request);
        return queued < 0 ? (uint64_t)(int64_t)queued : length;
    }
    if (rights_record) {
        if (!s || s->domain != LINUX_AF_UNIX ||
            !(s->type == LINUX_SOCK_STREAM || socket_type_is_record(s->type)) ||
            (socket_type_is_record(s->type) ? record_peer_id : s->unix_peer_id) < 0 ||
            (socket_type_is_record(s->type) ? record_peer_id : s->unix_peer_id) >= EDGE_MAX_SOCKETS ||
            !g_sockets[socket_type_is_record(s->type) ?
                       record_peer_id : s->unix_peer_id].used) {
            socket_rights_record_drop(&rights_record);
            return (uint64_t)-ENOTCONN;
        }
    }

    /*
     * A Linux stream sendmsg is serialized as one write operation.  Appending
     * each iovec through a separate send path allowed another thread sharing
     * the socket to interleave bytes between a protocol header and its body.
     * Copy and publish the complete available prefix while holding the peer
     * queue lock once; ancillary rights use the same publication point.
     */
    if (s->domain == LINUX_AF_UNIX &&
        s->type == LINUX_SOCK_STREAM) {
        edge_fd_t *description = fd_get(
            fd_proc_with_stdio(), (int)fd_u);
        int64_t sent = unix_stream_sendmsg_iov(
            (int)fd_u, s, description, &iov_source,
            msg.msg_iovlen, flags_u, &rights_record);

        socket_rights_record_drop(&rights_record);
        return sent;
    }

    if (s && s->domain == LINUX_AF_UNIX && socket_type_is_record(s->type)) {
        uint64_t sent = unix_record_send_iov_to(
            (int)fd_u, s, fd_get(fd_proc_with_stdio(), (int)fd_u),
            &iov_source, msg.msg_iovlen, flags_u, record_peer_id,
            &rights_record);
        if ((int64_t)sent < 0) {
            socket_rights_record_drop(&rights_record);
            return sent;
        }
        total = sent;
        goto sendmsg_payload_done;
    }

    if (rights_record && s->domain == LINUX_AF_UNIX &&
        s->type == LINUX_SOCK_STREAM) {
        edge_fd_t *description = fd_get(
            fd_proc_with_stdio(), (int)fd_u);
        int64_t prefixed = unix_stream_sendmsg_rights_prefix(
            (int)fd_u, s, description, &iov_source, msg.msg_iovlen,
            flags_u, &rights_record);
        if (prefixed < 0) {
            socket_rights_record_drop(&rights_record);
            return (uint64_t)prefixed;
        }
        if (prefixed > 0) {
            total = (uint64_t)prefixed;
            stream_rights_prefixed = 1;
        }
    }

    if ((s->domain == LINUX_AF_INET ||
         s->domain == LINUX_AF_INET6) &&
        s->type == LINUX_SOCK_DGRAM &&
        (s->protocol == 0 || s->protocol == LINUX_IPPROTO_UDP)) {
        uint64_t sent = x86_socket_sendto_raw(
            fd_u, 0, iov_source.total_length, flags_u,
            msg.msg_name, msg.msg_namelen, &iov_source,
            ip_send_metadata_pointer);

        socket_rights_record_drop(&rights_record);
        return sent;
    }

    /*
     * Linux sendmsg writes the complete iovec chain.  The old first-iovec-only
     * behavior truncated X11 protocol requests generated by libxcb/writev-like
     * paths, leaving X clients alive but unmapped on the visible server.
     */
    for (uint64_t i = 0; i < msg.msg_iovlen; ++i) {
        struct edge_linux_iovec iov;
        uint64_t sent;
        int status = kernel_socket_iovec_source_read(
            &iov_source, (uint32_t)i, &iov);
        if (status < 0) {
            socket_rights_record_drop(&rights_record);
            return (uint64_t)(int64_t)status;
        }
        if (iov.iov_len == 0) continue;
        if (stream_rights_prefixed) {
            iov.iov_base++;
            iov.iov_len--;
            stream_rights_prefixed = 0;
            if (iov.iov_len == 0) continue;
        }
        sent = x86_socket_sendto_raw(
            fd_u, iov.iov_base, iov.iov_len, flags_u,
            msg.msg_name, msg.msg_namelen, 0,
            ip_send_metadata_pointer);
        if ((int64_t)sent < 0) {
            if (total > 0) break;
            socket_rights_record_drop(&rights_record);
            return sent;
        }
        total += sent;
        if (sent < iov.iov_len) break;
    }
sendmsg_payload_done:
    socket_rights_record_drop(&rights_record);
    return total;
}

int64_t edge_socket_runtime_message_execute(
    const kernel_socket_message_request_t *request) {
    return request->receiving ?
        x86_socket_message_receive(request) :
        x86_socket_message_send(request);
}

typedef struct x86_socket_mmsg_call_context {
    uint8_t receiving;
    void *owner;
} x86_socket_mmsg_call_context_t;

static int64_t x86_socket_mmsg_call(
    void *opaque, int32_t descriptor, uint64_t user_message,
    uint32_t flags, void *user_registers) {
    x86_socket_mmsg_call_context_t *context =
        (x86_socket_mmsg_call_context_t *)opaque;
    if (!context) return -EIO;
    return kernel_socket_message_invoke(
        descriptor, user_message, flags, context->receiving,
        user_registers, context->owner,
        x86_socket_message_copy_from_user,
        x86_socket_message_copy_to_user);
}

int64_t arch_socket_message_batch(
    const kernel_socket_mmsg_request_t *request) {
    x86_socket_mmsg_call_context_t context;
    edge_fd_t *descriptor_entry;
    edge_socket_t *socket;
    uint32_t completed = 0;
    int blocking;
    int64_t result;

    if (!request) return -EIO;
    context.receiving = request->receiving;
    context.owner = request->copy_context;
    if (!request->receiving || !request->user_timeout)
        return kernel_socket_mmsg_run(
            request, 0u, 0, x86_socket_mmsg_call, &context, &completed);

    descriptor_entry = fd_get(
        fd_proc_with_stdio(), request->descriptor);
    socket = socket_from_fd(request->descriptor);
    blocking = descriptor_entry && socket &&
        !(descriptor_entry->flags & LINUX_O_NONBLOCK) &&
        !socket->nonblock &&
        !(request->flags & LINUX_MSG_DONTWAIT);
    for (;;) {
        result = kernel_socket_mmsg_run(
            request, completed, 1, x86_socket_mmsg_call,
            &context, &completed);
        if (result != -EAGAIN || !blocking) break;
        if (boottime_monotonic_us() >= request->timeout_deadline_us) {
            result = 0;
            break;
        }
        if (signal_pending_interrupt()) {
            result = (int64_t)tty_interrupt_current_ret();
            break;
        }
        socket_blocking_wait_step(request->timeout_deadline_us);
    }
    (void)kernel_socket_mmsg_timeout_write(
        request->copy_context, request->copy_to_user,
        request->user_timeout, request->timeout_deadline_us);
    return result;
}

static int x86_socket_name_entry(
    const edge_fd_t *fde, int peer,
    kernel_socket_address_t *address) {
    edge_socket_t *s;

    if (!address) return -EINVAL;
    if (!fde) return -EBADF;
    s = socket_from_fd_entry(fde);
    if (!s) return -ENOTSOCK;
    memset(address, 0, sizeof(*address));

    if (peer) {
        if (!s->connected) return -ENOTCONN;
        if (s->domain == LINUX_AF_NETLINK) return -ENOTCONN;
        if (s->peer_len) {
            if (s->peer_len > sizeof(address->bytes)) return -EIO;
            memcpy(address->bytes, s->peer_addr, s->peer_len);
            address->length = s->peer_len;
            return 0;
        }
        if (s->domain == LINUX_AF_UNIX) {
            address->bytes[0] = LINUX_AF_UNIX;
            address->length = sizeof(uint16_t);
            return 0;
        }
        return -ENOTCONN;
    }

    if (s->domain == LINUX_AF_NETLINK) {
        struct edge_sockaddr_nl nl;
        if (netlink_ensure_bound(s) < 0) return -EADDRINUSE;
        memset(&nl, 0, sizeof(nl));
        nl.nl_family = LINUX_AF_NETLINK;
        nl.nl_pid = s->netlink_port_id;
        nl.nl_groups = s->netlink_groups;
        memcpy(address->bytes, &nl, sizeof(nl));
        address->length = sizeof(nl);
        return 0;
    }
    if (s->domain == LINUX_AF_UNIX) {
        if (s->bind_len > 0) {
            memcpy(address->bytes, s->bind_addr, s->bind_len);
            address->length = s->bind_len;
        } else {
            address->bytes[0] = LINUX_AF_UNIX;
            address->length = sizeof(uint16_t);
        }
        return 0;
    }
    if (s->domain == LINUX_AF_INET || s->domain == LINUX_AF_INET6) {
        uint32_t expected = s->domain == LINUX_AF_INET ?
            sizeof(struct edge_sockaddr_in) :
            sizeof(struct edge_sockaddr_in6);
        if (s->bind_len >= expected) {
            memcpy(address->bytes, s->bind_addr, expected);
        } else {
            address->bytes[0] = (uint8_t)s->domain;
        }
        address->length = expected;
        return 0;
    }
    if (s->domain == LINUX_AF_PACKET) {
        struct edge_linux_sockaddr_ll link;
        memset(&link, 0, sizeof(link));
        link.sll_family = LINUX_AF_PACKET;
        link.sll_protocol = (uint16_t)s->protocol;
        if (s->bind_len >= sizeof(link))
            memcpy(&link, s->bind_addr, sizeof(link));
        memcpy(address->bytes, &link, sizeof(link));
        address->length = sizeof(link);
        return 0;
    }
    return -EOPNOTSUPP;
}

static int64_t x86_fd_operation_socket(
    void *context, void *storage,
    const struct kernel_socket_operation_request *request,
    struct kernel_socket_operation_result *result) {
    edge_fd_t *entry = (edge_fd_t *)storage;

    (void)context;
    if (!entry || !request || !result) return -EINVAL;
    /*
     * The lease owns this descriptor snapshot and its socket reference for the
     * complete operation. The normalized request deliberately has no numeric
     * descriptor, so trace-only helper arguments use -1 and never consult the
     * current descriptor table.
     */
    switch (request->operation) {
        case KERNEL_SOCKET_OPERATION_DESCRIBE:
            return x86_socket_describe_entry(
                entry, &result->output.description);
        case KERNEL_SOCKET_OPERATION_LISTEN:
            return x86_socket_listen_entry(
                -1, entry, request->arguments.listen_backlog);
        case KERNEL_SOCKET_OPERATION_SHUTDOWN:
            return x86_socket_shutdown_entry(
                entry, request->arguments.shutdown_how);
        case KERNEL_SOCKET_OPERATION_BIND:
            return x86_socket_bind_entry(
                -1, entry, &request->arguments.bind_address);
        case KERNEL_SOCKET_OPERATION_CONNECT:
            return x86_socket_connect_entry(
                -1, &request->arguments.connect.address,
                request->arguments.connect.user_registers, entry);
        case KERNEL_SOCKET_OPERATION_NAME:
            return x86_socket_name_entry(
                entry, (int)request->arguments.name_peer,
                &result->output.address);
        default:
            return -EOPNOTSUPP;
    }
}

#ifdef CONFIG_BSD_DRIVER_BRIDGE
typedef union x86_bsd_bridge_ioctl_payload {
    bsd_bridge_linux_termios_t termios;
    bsd_bridge_linux_winsize_t winsize;
    int32_t available;
    uint8_t bytes[BSD_BRIDGE_CDEV_IOCTL_MAX_PAYLOAD];
} x86_bsd_bridge_ioctl_payload_t;

_Static_assert(sizeof(struct linux_termios_abi) ==
               sizeof(bsd_bridge_linux_termios_t),
               "BSD bridge x86 termios ABI mismatch");
_Static_assert(sizeof(struct edge_winsize) ==
               sizeof(bsd_bridge_linux_winsize_t),
               "BSD bridge x86 winsize ABI mismatch");

static uint64_t
x86_bsd_bridge_ioctl(edge_fd_t *entry, uint32_t command,
                     uint64_t argument, int *handled) {
    x86_bsd_bridge_ioctl_payload_t payload;
    uint32_t input_size;
    uint32_t output_size;
    uint32_t payload_size;
    int result;

    if (handled) *handled = 0;
    if (!entry || entry->kind != FD_VFS ||
        (entry->inode.mode & 0xf000u) != VFS_INODE_CHR ||
        !bsd_bridge_cdev_present(entry->inode.rdev))
        return 0;
    if (!bsd_bridge_cdev_ioctl_supported(command)) {
        if (handled) *handled = 1;
        return (uint64_t)-ENOTTY;
    }
    input_size = bsd_bridge_cdev_ioctl_input_size(command);
    output_size = bsd_bridge_cdev_ioctl_output_size(command);
    payload_size = input_size > output_size ? input_size : output_size;
    if (payload_size > sizeof(payload))
        return (uint64_t)-EIO;
    memset(&payload, 0, sizeof(payload));
    if (input_size != 0) {
        if (!argument ||
            copy_from_user(&payload, argument, input_size) < 0) {
            if (handled) *handled = 1;
            return (uint64_t)-EFAULT;
        }
    }
    result = bsd_bridge_cdev_ioctl_session(
        entry->inode.rdev, file_ref_identity(entry->file_ref),
        command, argument, &payload, payload_size);
    if (result == BSD_BRIDGE_CDEV_NOT_HANDLED)
        return 0;
    if (handled) *handled = 1;
    if (result < 0)
        return (uint64_t)(int64_t)result;
    if (output_size != 0 &&
        (!argument ||
        copy_to_user(argument, &payload, output_size) < 0))
        return (uint64_t)-EFAULT;
    return 0;
}
#endif

static uint64_t x86_ioctl_execute_raw(uint64_t fd_u, uint64_t cmd_u,
                                      uint64_t arg_u) {
    int fd = (int)fd_u;
    uint32_t cmd = (uint32_t)cmd_u;
    task_t *cur = process_current_task();
    int trace_tty_cmd = tty_ioctl_cmd_is_traced(cmd);
    static int gui_pty_ioctl_budget = EDGE_GUI_DEEP_TRACE ? 128 : 0;
    static int pty_ioctl_trace_budget = EDGE_PTY_DIAG_TRACE ? 256 : 0;
#define PTY_IOCTL_TRACE() \
    ((gui_diag_task(cur) || EDGE_PTY_DIAG_TRACE) && \
     (gui_pty_ioctl_budget-- > 0 || pty_ioctl_trace_budget-- > 0))

    edge_fd_proc_t *p = fd_proc_with_stdio();
    edge_fd_t *e = fd_get(p, fd);
    if (cmd == LINUX_FBIOGET_FSCREENINFO || cmd == LINUX_FBIOGET_VSCREENINFO ||
        cmd == LINUX_FBIOPUT_VSCREENINFO || cmd == LINUX_FBIOPAN_DISPLAY) {
        static int fbio_entry_budget =
            EDGE_GUI_DEEP_TRACE ? 64 : 0;
        if (fbio_entry_budget-- > 0) {
            printf("[fbio-entry] pid=%d task=%s fd=%d kind=%s path=%s cmd=0x%x arg=0x%x budget=%d\n",
                   cur ? cur->pid : -1, cur ? cur->name : "?",
                   fd, e ? fd_kind_name(e->kind) : "bad",
                   (e && e->path[0]) ? e->path : "-", cmd, (unsigned)arg_u,
                   fbio_entry_budget);
        }
    }
#if EDGE_FD_FORK_DEBUG
    if (cmd == LINUX_TIOCSPGRP) {
        int pid = cur ? cur->pid : process_getpid();
        printf("[fd][forkdbg] ioctl pid=%d cmd=TIOCSPGRP fd=%d lookup=%s\n",
               pid, fd, e ? "hit" : "miss");
        if (e) {
            printf("[fd][forkdbg] ioctl-slot pid=%d fd=%d kind=%s ref=%d path=%s\n",
                   pid, fd, fd_kind_name(e->kind), e->file_ref, e->path[0] ? e->path : "-");
        }
    }
#endif
    if (!e) {
        if (gui_diag_task(cur) && gui_pty_ioctl_budget-- > 0) {
            printf("[ptydiag] ioctl pid=%d task=%s fd=%d cmd=0x%x res=EBADF\n",
                   cur ? cur->pid : -1, cur ? cur->name : "?", fd, cmd);
        }
        if (trace_tty_cmd) tty_log_ioctl_once(cur, fd, cmd, NULL, "EBADF(fd_lookup)");
        return (uint64_t)-EBADF;
    }
    if (e->kind == FD_TUN) {
        uint32_t network_namespace = cur ? cur->namespaces.net : 0u;

        return (uint64_t)(int64_t)edge_linux_tun_ioctl(
            file_ref_identity(e->file_ref), network_namespace,
            cmd, arg_u, x86_tun_copy_from_user,
            x86_tun_copy_to_user, 0);
    }
    if (cmd == LINUX_TIOCCONS) {
        int privileged = cur &&
            (cur->capabilities.effective &
             (1ULL << EDGE_LINUX_CAP_SYS_ADMIN)) != 0;
        if ((e->kind == FD_PTY_MASTER || e->kind == FD_PTY_SLAVE) &&
            e->pipe_id >= 0 && e->pipe_id < EDGE_MAX_PTYS &&
            g_ptys[e->pipe_id].used) {
            edge_pty_t *pty = &g_ptys[e->pipe_id];
            int64_t result;
            if (!privileged) return (uint64_t)-EPERM;
            if (pty->refs_slave == INT_MAX) return (uint64_t)-EMFILE;
            pty_add_ref(e->pipe_id, 0);
            result = edge_linux_tty_console_redirect_install(
                pty, pty_console_redirect_write, pty,
                pty_console_redirect_release_reference, privileged);
            if (result < 0) pty_drop_ref(e->pipe_id, 0);
            return (uint64_t)result;
        }
        if (e->kind == FD_CONSOLE &&
            strcmp(e->path, "/dev/console") == 0)
            return (uint64_t)edge_linux_tty_console_redirect_reset(privileged);
        return (uint64_t)-ENOTTY;
    }
#ifdef CONFIG_BSD_DRIVER_BRIDGE
    {
        int handled = 0;
        uint64_t result =
            x86_bsd_bridge_ioctl(e, cmd, arg_u, &handled);

        if (handled)
            return result;
    }
#endif
#ifdef CONFIG_LOOP_DEVICE
    if (e->kind == FD_VFS &&
        (edge_loop_is_device_number(e->inode.rdev) ||
         edge_loop_is_control_device_number(e->inode.rdev))) {
        edge_loop_ioctl_request_t loop_request;

        memset(&loop_request, 0, sizeof(loop_request));
        loop_request.device_number = e->inode.rdev;
        loop_request.command = cmd;
        loop_request.argument = arg_u;
        loop_request.privileged = cur &&
            (cur->capabilities.effective &
             (1ULL << EDGE_LINUX_CAP_SYS_ADMIN)) != 0;
        loop_request.copy_from_user = x86_loop_copy_from_user;
        loop_request.copy_to_user = x86_loop_copy_to_user;
        loop_request.resolve_context = cur;
        loop_request.resolve_backing = x86_loop_resolve_backing;
        return (uint64_t)edge_loop_ioctl_execute(&loop_request);
    }
#endif
#ifdef CONFIG_DEVICE_MAPPER
    if (e->kind == FD_VFS &&
        edge_dm_is_control_device_number(e->inode.rdev)) {
        edge_dm_ioctl_request_t dm_request;

        memset(&dm_request, 0, sizeof(dm_request));
        dm_request.device_number = e->inode.rdev;
        dm_request.command = cmd;
        dm_request.argument = arg_u;
        dm_request.privileged = cur &&
            (cur->capabilities.effective &
             (1ULL << EDGE_LINUX_CAP_SYS_ADMIN)) != 0;
        dm_request.copy_from_user = x86_loop_copy_from_user;
        dm_request.copy_to_user = x86_loop_copy_to_user;
        return (uint64_t)edge_dm_ioctl_execute(&dm_request);
    }
#endif
    if (e->kind == FD_VFS &&
        (e->inode.mode & 0xf000u) == VFS_INODE_BLK) {
        block_device_t *device = 0;
        uint64_t value = 0;
        uint32_t value_size = 0;
        int result;
        if (vfs_inode_get_block_device(&e->inode, &device) < 0)
            return (uint64_t)-ENXIO;
        result = block_linux_ioctl_query(device, cmd, &value, &value_size);
        if (result < 0) return (uint64_t)(int64_t)result;
        if (!arg_u) return (uint64_t)-EFAULT;
        return copy_to_user(arg_u, &value, value_size) < 0 ?
               (uint64_t)-EFAULT : 0;
    }
    if (tty_ioctl_cmd_requires_tty(cmd) && !fd_is_tty(e)) {
        /*
         * GTK/VTE probes stderr/stdout with TIOCGWINSZ even when those fds are
         * redirected to log files.  Linux returns ENOTTY; logging every probe
         * over UART makes XFCE terminal startup look much slower than the real
         * guest work.  Keep diagnostics for unusual tty commands and non-file
         * fds, but suppress the expected regular-file window-size probes.
         */
        if ((cmd != LINUX_TIOCGWINSZ || e->kind != FD_VFS) &&
            gui_diag_task(cur) && gui_pty_ioctl_budget-- > 0) {
            printf("[ptydiag] ioctl pid=%d task=%s fd=%d kind=%s path=%s cmd=0x%x res=ENOTTY requires-tty\n",
                   cur ? cur->pid : -1, cur ? cur->name : "?",
                   fd, fd_kind_name(e->kind), e->path[0] ? e->path : "-",
                   cmd);
        }
        tty_log_ioctl_once(cur, fd, cmd, e, "ENOTTY(non-tty-fd)");
        return (uint64_t)-ENOTTY;
    }

    if (cmd == LINUX_FIOASYNC) {
        int on = 0;
        if (!arg_u) return (uint64_t)-EINVAL;
        if (copy_from_user(&on, arg_u, sizeof(on)) < 0) return (uint64_t)-EFAULT;
        /*
         * Linux treats FIOASYNC as the ioctl form of toggling O_ASYNC.
         * Xorg's evdev backend may choose this route instead of adding input
         * fds to epoll.  Treating it as a no-op leaves /dev/input/event* open
         * and probed, but no SIGIO is generated when xHCI keyboard/mouse
         * events arrive.
         */
        if (kernel_fd_update_status_flags(
                fd, LINUX_O_ASYNC,
                on ? LINUX_O_ASYNC : 0) < 0)
            return (uint64_t)-EBADF;
        if (on && e->async_owner == 0 && cur)
            e->async_owner = cur->pid;
        return 0;
    }
    if (cmd == LINUX_FIOSETOWN || cmd == LINUX_SIOCSPGRP) {
        int owner = 0;
        if (!arg_u) return (uint64_t)-EINVAL;
        if (copy_from_user(&owner, arg_u, sizeof(owner)) < 0) return (uint64_t)-EFAULT;
        e->async_owner = owner;
        fd_async_input_watch_update(e);
        return 0;
    }
    if (cmd == LINUX_FIOGETOWN || cmd == LINUX_SIOCGPGRP) {
        if (!arg_u) return (uint64_t)-EINVAL;
        if (copy_to_user(arg_u, &e->async_owner, sizeof(e->async_owner)) < 0) return (uint64_t)-EFAULT;
        return 0;
    }
    if ((e->kind == FD_PTY_MASTER || e->kind == FD_PTY_SLAVE) &&
        cmd == LINUX_FIONREAD) {
        kernel_pty_poll_state_t state;
        int available;

        if (!arg_u) return (uint64_t)-EINVAL;
        if (pty_poll_state_snapshot(e, &state) < 0 || !state.valid)
            return (uint64_t)-EIO;
        available = (int)kernel_pty_readable_bytes(&state);
        if (copy_to_user(arg_u, &available, sizeof(available)) < 0)
            return (uint64_t)-EFAULT;
        return 0;
    }
    if ((e->kind == FD_PIPE_R || e->kind == FD_PIPE_W ||
         e->kind == FD_PIPE_RW) && cmd == LINUX_FIONREAD) {
        int available;

        if (!arg_u) return (uint64_t)-EFAULT;
        if (e->pipe_id < 0 || e->pipe_id >= EDGE_MAX_PIPES ||
            !g_pipes[e->pipe_id].used)
            return (uint64_t)-EBADF;
        available = (int)kernel_pipe_readable_bytes(
            &g_pipes[e->pipe_id]);
        if (copy_to_user(arg_u, &available, sizeof(available)) < 0)
            return (uint64_t)-EFAULT;
        return 0;
    }
    if (e->kind == FD_INOTIFY && cmd == LINUX_FIONREAD) {
        kernel_inotify_state_t state;
        int available;

        if (!arg_u) return (uint64_t)-EFAULT;
        if (kernel_inotify_query(e->pipe_id, &state) < 0)
            return (uint64_t)-EBADF;
        available = (int)state.queued_bytes;
        if (copy_to_user(arg_u, &available, sizeof(available)) < 0)
            return (uint64_t)-EFAULT;
        return 0;
    }
    if (e->kind == FD_FANOTIFY && cmd == LINUX_FIONREAD) {
        kernel_fanotify_state_t state;
        int available;
        if (!arg_u) return (uint64_t)-EFAULT;
        if (kernel_fanotify_query(e->pipe_id, &state) < 0)
            return (uint64_t)-EBADF;
        available = (int)state.queued_bytes;
        return copy_to_user(arg_u, &available, sizeof(available)) < 0 ?
            (uint64_t)-EFAULT : 0;
    }
    if (e->kind == FD_USERFAULTFD && cmd == LINUX_FIONREAD) {
        kernel_userfaultfd_state_t state;
        int available;
        if (!arg_u) return (uint64_t)-EFAULT;
        if (kernel_userfaultfd_query(e->pipe_id, &state) < 0)
            return (uint64_t)-EBADF;
        available = (int)(state.queued_events *
                          sizeof(kernel_userfaultfd_message_t));
        return copy_to_user(arg_u, &available, sizeof(available)) < 0 ?
            (uint64_t)-EFAULT : 0;
    }
    if (e->kind == FD_SOCKET) {
        if (cmd == LINUX_FIONREAD) {
            int avail = 0;
            if (!arg_u) return (uint64_t)-EINVAL;
            if (e->pipe_id >= 0 && e->pipe_id < EDGE_MAX_SOCKETS && g_sockets[e->pipe_id].used) {
                avail = (int)g_sockets[e->pipe_id].rx_len;
            }
            if (copy_to_user(arg_u, &avail, sizeof(avail)) < 0) return (uint64_t)-EFAULT;
            return 0;
        }
        uint64_t nrc = net_ioctl_socket(cmd, arg_u);
        if ((int64_t)nrc != -ENOTTY) return nrc;
    }
    if (e->kind == FD_VFS && path_is_mouse_input(e->path)) {
        if (cmd == LINUX_FIONREAD) {
            int avail;
            if (!arg_u) return (uint64_t)-EINVAL;
            avail = keyboard_mouse_pending();
            if (copy_to_user(arg_u, &avail, sizeof(avail)) < 0) return (uint64_t)-EFAULT;
            return 0;
        }
    }
    if (e->kind == FD_VFS && (path_is_event_input(e->path) || path_is_mouse_input(e->path))) {
        int event_id = path_input_event_index(e->path);
        int event_pointer = path_is_mouse_input(e->path) ||
            (event_id >= 0 &&
             input_device_role((uint32_t)event_id) ==
                 EDGE_INPUT_ROLE_POINTER);
        if (cmd == LINUX_FIONREAD) {
            int avail;
            if (!arg_u) return (uint64_t)-EINVAL;
            avail = path_is_mouse_input(e->path) ? keyboard_mouse_pending() : keyboard_event_pending(event_id);
            if (copy_to_user(arg_u, &avail, sizeof(avail)) < 0) return (uint64_t)-EFAULT;
            return 0;
        }
        {
            uint8_t input[EDGE_LINUX_INPUT_IOCTL_BUFFER_SIZE];
            uint8_t output[EDGE_LINUX_INPUT_IOCTL_BUFFER_SIZE];
            uint32_t input_length =
                edge_linux_input_ioctl_input_size((uint32_t)cmd);
            edge_linux_input_ioctl_result_t ioctl_result;
            kernel_file_description_locator_t input_locator =
                file_ref_locator(e->file_ref);
            int status;

            memset(input, 0, sizeof(input));
            memset(output, 0, sizeof(output));
            status = edge_linux_input_description_check(input_locator);
            if (status < 0) return (uint64_t)(int64_t)status;
            if (input_length > sizeof(input)) return (uint64_t)-EINVAL;
            if (input_length &&
                (!arg_u || copy_from_user(input, arg_u, input_length) < 0))
                return (uint64_t)-EFAULT;
            status = edge_linux_input_ioctl_execute(
                event_id >= 0 ? (uint32_t)event_id : UINT32_MAX,
                event_pointer ? EDGE_INPUT_ROLE_POINTER :
                                EDGE_INPUT_ROLE_KEYBOARD,
                (uint32_t)cmd, input, input_length, output, sizeof(output),
                &ioctl_result);
            if (status != -EDGE_LINUX_ENOTTY) {
                if (status < 0) return (uint64_t)(int64_t)status;
                if (ioctl_result.output_length &&
                    (!arg_u || copy_to_user(arg_u, output,
                              ioctl_result.output_length) < 0))
                    return (uint64_t)-EFAULT;
                status = edge_linux_input_description_action(
                    event_id >= 0 ? (uint32_t)event_id : UINT32_MAX,
                    input_locator, ioctl_result.action,
                    ioctl_result.action_value);
                if (status < 0) return (uint64_t)(int64_t)status;
                return (uint64_t)ioctl_result.return_value;
            }
        }
        if (cmd == LINUX_EVIOCGVERSION) {
            int version = 0x010001;
            if (!arg_u) return (uint64_t)-EINVAL;
            if (copy_to_user(arg_u, &version, sizeof(version)) < 0) return (uint64_t)-EFAULT;
            return 0;
        }
        if (cmd == LINUX_EVIOCGID) {
            struct edge_linux_input_id id;
            uint16_t virtio_id[4] = { 0, 0, 0, 0 };
            if (!arg_u) return (uint64_t)-EINVAL;
            memset(&id, 0, sizeof(id));
            if (path_is_event_input(e->path) && input_name((uint32_t)event_id)) {
                input_id((uint32_t)event_id, virtio_id);
                id.bustype = virtio_id[0];
                id.vendor = virtio_id[1];
                id.product = virtio_id[2];
                id.version = virtio_id[3];
            } else {
                id.bustype = 0x03; /* BUS_USB-compatible fallback device. */
                id.vendor = 0x1AF4;
                id.product = 0x0001;
                id.version = 1;
            }
            if (copy_to_user(arg_u, &id, sizeof(id)) < 0) return (uint64_t)-EFAULT;
            return 0;
        }
        if (cmd == 0x80084503u) { /* EVIOCGREP */
            uint32_t rep[2] = { 250, 33 };
            if (!arg_u) return (uint64_t)-EINVAL;
            (void)input_repeat_get((uint32_t)event_id, rep);
            if (copy_to_user(arg_u, rep, sizeof(rep)) < 0) return (uint64_t)-EFAULT;
            return 0;
        }
        if (cmd == 0x40084503u) { /* EVIOCSREP */
            uint32_t rep[2];
            if (!arg_u) return (uint64_t)-EINVAL;
            if (copy_from_user(rep, arg_u, sizeof(rep)) < 0)
                return (uint64_t)-EFAULT;
            if (input_repeat_set((uint32_t)event_id, rep) < 0)
                return (uint64_t)-EINVAL;
            return 0;
        }
        if (cmd == LINUX_EVIOCSCLOCKID) {
            int32_t clock_id;
            if (!arg_u) return (uint64_t)-EFAULT;
            if (copy_from_user(&clock_id, arg_u, sizeof(clock_id)) < 0)
                return (uint64_t)-EFAULT;
            if (!linux_evdev_clock_supported(clock_id))
                return (uint64_t)-EINVAL;
            fd_description_set_input_clock(e, clock_id);
            return 0;
        }
        if (cmd == 0x80084504u) { /* EVIOCGKEYCODE: unsigned int[2] */
            uint32_t map[2];
            if (!arg_u) return (uint64_t)-EINVAL;
            if (copy_from_user(map, arg_u, sizeof(map)) < 0) return (uint64_t)-EFAULT;
            if (event_pointer) return (uint64_t)-EINVAL;
            /*
             * EdgeOS currently reports set-1 compatible scancodes as Linux
             * KEY_* codes for the common PC keyboard range.  Xorg evdev probes
             * EVIOCGKEYCODE while building its key map; answer the Linux ABI
             * contract instead of falling through to ENOTTY.
             */
            if (map[0] == 0 || map[0] > 0x58u) return (uint64_t)-EINVAL;
            map[1] = map[0];
            if (copy_to_user(arg_u, map, sizeof(map)) < 0) return (uint64_t)-EFAULT;
            return 0;
        }
        if (cmd == 0x80284504u) { /* EVIOCGKEYCODE_V2: struct input_keymap_entry */
            struct {
                uint8_t flags;
                uint8_t len;
                uint16_t index;
                uint32_t keycode;
                uint8_t scancode[32];
            } ent;
            uint32_t sc = 0;
            if (!arg_u) return (uint64_t)-EINVAL;
            if (event_pointer) return (uint64_t)-EINVAL;
            if (copy_from_user(&ent, arg_u, sizeof(ent)) < 0) return (uint64_t)-EFAULT;
            sc = ent.scancode[0] ? ent.scancode[0] : (uint32_t)ent.index;
            if (sc == 0 || sc > 0x58u) return (uint64_t)-EINVAL;
            ent.keycode = sc;
            ent.len = 1;
            ent.scancode[0] = (uint8_t)sc;
            if (copy_to_user(arg_u, &ent, sizeof(ent)) < 0) return (uint64_t)-EFAULT;
            return 0;
        }
        if (cmd == 0x40084504u || cmd == 0x40284504u) { /* EVIOCSKEYCODE[_V2] */
            return 0;
        }
        if (cmd == 0x40044590u) { /* EVIOCGRAB */
            return 0;
        }
        if (((cmd >> 8) & 0xFFu) == 'E' &&
            ((cmd & 0xFFu) == 0x06u || (cmd & 0xFFu) == 0x07u || (cmd & 0xFFu) == 0x08u)) {
            static const char name_keyboard[] = "EdgeOS xHCI keyboard";
            const char *name = path_is_event_input(e->path) ?
                               input_name((uint32_t)event_id) : 0;
            uint32_t size = (cmd >> 16) & 0x3FFFu;
            if (!name)
                name = event_pointer ?
                       keyboard_mouse_device_name() : name_keyboard;
            if ((cmd & 0xFFu) != 0x06u) return (uint64_t)-ENOENT; /* EVIOCGPHYS / EVIOCGUNIQ */
            if (!arg_u) return (uint64_t)-EINVAL;
            {
                uint32_t name_len = (uint32_t)strlen(name) + 1u;
                if (size > name_len) size = name_len;
            }
            if (copy_to_user(arg_u, name, size) < 0) return (uint64_t)-EFAULT;
            return (uint64_t)size;
        }
        if (((cmd >> 8) & 0xFFu) == 'E' &&
            ((cmd & 0xFFu) == 0x09u || /* EVIOCGPROP */
             (cmd & 0xFFu) == 0x18u || /* EVIOCGKEY */
             (cmd & 0xFFu) == 0x19u || /* EVIOCGLED */
             (cmd & 0xFFu) == 0x1bu)) { /* EVIOCGSW */
            uint8_t bits[64];
            uint32_t size = (cmd >> 16) & 0x3FFFu;
            if (!arg_u) return (uint64_t)-EINVAL;
            if (size > sizeof(bits)) size = sizeof(bits);
            memset(bits, 0, sizeof(bits));
            if ((cmd & 0xFFu) == 0x09u && path_is_event_input(e->path) &&
                input_name((uint32_t)event_id)) {
                size = input_properties((uint32_t)event_id, bits, size);
            }
            if ((cmd & 0xFFu) == 0x18u && event_pointer) {
                uint8_t buttons = keyboard_mouse_buttons();
                if (buttons & 0x01u) bits[0x110 / 8] |= (uint8_t)(1u << (0x110 % 8));
                if (buttons & 0x02u) bits[0x111 / 8] |= (uint8_t)(1u << (0x111 % 8));
                if (buttons & 0x04u) bits[0x112 / 8] |= (uint8_t)(1u << (0x112 % 8));
            }
            if (copy_to_user(arg_u, bits, size) < 0) return (uint64_t)-EFAULT;
            return (uint64_t)size;
        }
        if (cmd == LINUX_EVIOCGBIT0 || cmd == LINUX_EVIOCGBIT1 || cmd == LINUX_EVIOCGBIT2 ||
            (((cmd >> 8) & 0xFFu) == 'E' && ((cmd & 0xFFu) >= 0x20u && (cmd & 0xFFu) <= 0x3Fu))) {
            uint8_t bits[128];
            uint32_t size = (cmd >> 16) & 0x3FFFu;
            static uint32_t evbit_debug_budget = EDGE_X11_TRACE ? 48 : 0;
            if (!arg_u) return (uint64_t)-EINVAL;
            if (size > sizeof(bits)) size = sizeof(bits);
            memset(bits, 0, sizeof(bits));
            if (path_is_event_input(e->path) && input_name((uint32_t)event_id)) {
                uint32_t event_type = (cmd & 0xFFu) - 0x20u;
                size = input_bits((uint32_t)event_id, event_type, bits, size);
            } else if ((cmd & 0xFFu) == 0x20u) {
                /*
                 * Keyboard event devices expose EV_MSC/MSC_SCAN as Linux HID
                 * keyboards do.  Xorg can operate from EV_KEY alone on some
                 * paths, but advertising the event type must match the stream
                 * EdgeOS actually emits.
                 */
                bits[0] = event_pointer ? 0x07 : 0x13; /* EV_SYN/KEY[/REL]/MSC */
            } else if ((cmd & 0xFFu) == 0x21u) {
                if (event_pointer) {
                    const int btns[] = { 0x110, 0x111, 0x112 };
                    for (uint32_t i = 0; i < sizeof(btns) / sizeof(btns[0]); ++i) {
                        int key = btns[i];
                        bits[key / 8] |= (uint8_t)(1u << (key % 8));
                    }
                } else {
                    for (int key = 1; key <= 0x58; ++key) {
                        bits[key / 8] |= (uint8_t)(1u << (key % 8));
                    }
                }
            } else if ((cmd & 0xFFu) == 0x22u) {
                if (event_pointer) bits[0] = 0x0B; /* REL_X/Y/WHEEL */
            } else if ((cmd & 0xFFu) == 0x24u) {
                if (!event_pointer) bits[0] = 0x10; /* MSC_SCAN */
            }
            if (evbit_debug_budget && event_pointer) {
                printf("[evdev] ioctl mouse cmd=0x%x ev=0x%x size=%u bits0=%02x bits34=%02x path=%s\n",
                       cmd, (cmd & 0xFFu) >= 0x20u ? (cmd & 0xFFu) - 0x20u : 0xffu,
                       size, bits[0], bits[34], e->path);
                evbit_debug_budget--;
            }
            if (copy_to_user(arg_u, bits, size) < 0) return (uint64_t)-EFAULT;
            return (uint64_t)size;
        }
        if (((cmd >> 8) & 0xFFu) == 'E' &&
            (cmd & 0xFFu) >= 0x40u && (cmd & 0xFFu) < 0x80u) {
            input_absinfo_t info;
            uint32_t axis = (cmd & 0xFFu) - 0x40u;
            if (!path_is_event_input(e->path) ||
                input_absinfo((uint32_t)event_id, axis, &info) < 0)
                return (uint64_t)-EINVAL;
            if (!arg_u) return (uint64_t)-EINVAL;
            if (copy_to_user(arg_u, &info, sizeof(info)) < 0)
                return (uint64_t)-EFAULT;
            return 0;
        }
    }
    if (e->kind == FD_VFS && path_is_kmsg_device(e->path)) {
        if (cmd == LINUX_FIONREAD) {
            int avail;
            if (!arg_u) return (uint64_t)-EINVAL;
            avail = (int)bootlog_kmsg_next_record_length(
                fd_description_offset(e));
            if (copy_to_user(arg_u, &avail, sizeof(avail)) < 0) return (uint64_t)-EFAULT;
            return 0;
        }
    }
#ifdef CONFIG_WATCHDOG
    if (e->kind == FD_VFS && path_is_watchdog_device(e->path)) {
        struct edge_linux_watchdog_info {
            uint32_t options;
            uint32_t firmware_version;
            uint8_t identity[32];
        };

        if (cmd == LINUX_FIONREAD) {
            int avail = 0;
            if (!arg_u) return (uint64_t)-EINVAL;
            if (copy_to_user(arg_u, &avail, sizeof(avail)) < 0) return (uint64_t)-EFAULT;
            return 0;
        }
        if (cmd == LINUX_WDIOC_GETSUPPORT) {
            struct edge_linux_watchdog_info info;
            const char *id = watchdog_identity();
            uint32_t n;

            if (!arg_u) return (uint64_t)-EINVAL;
            memset(&info, 0, sizeof(info));
            info.options = LINUX_WDIOF_SETTIMEOUT | LINUX_WDIOF_KEEPALIVEPING;
            info.firmware_version = 1;
            n = (uint32_t)strlen(id);
            if (n >= sizeof(info.identity)) n = sizeof(info.identity) - 1u;
            memcpy(info.identity, id, n);
            if (copy_to_user(arg_u, &info, sizeof(info)) < 0) return (uint64_t)-EFAULT;
            return 0;
        }
        if (cmd == LINUX_WDIOC_GETSTATUS || cmd == LINUX_WDIOC_GETBOOTSTATUS) {
            int status = 0;
            if (!arg_u) return (uint64_t)-EINVAL;
            if (copy_to_user(arg_u, &status, sizeof(status)) < 0) return (uint64_t)-EFAULT;
            return 0;
        }
        if (cmd == LINUX_WDIOC_SETOPTIONS) {
            int opts = 0;
            int rc = 0;
            if (!arg_u) return (uint64_t)-EINVAL;
            if (copy_from_user(&opts, arg_u, sizeof(opts)) < 0) return (uint64_t)-EFAULT;
            if (opts & LINUX_WDIOS_TEMPPANIC) return (uint64_t)-EOPNOTSUPP;
            if (opts & ~(LINUX_WDIOS_DISABLECARD | LINUX_WDIOS_ENABLECARD)) return (uint64_t)-EINVAL;
            if ((opts & (LINUX_WDIOS_DISABLECARD | LINUX_WDIOS_ENABLECARD)) ==
                (LINUX_WDIOS_DISABLECARD | LINUX_WDIOS_ENABLECARD)) {
                return (uint64_t)-EINVAL;
            }
            if (opts & LINUX_WDIOS_DISABLECARD) rc = watchdog_disable();
            else if (opts & LINUX_WDIOS_ENABLECARD) rc = watchdog_enable();
            else return (uint64_t)-EINVAL;
            return rc < 0 ? (uint64_t)rc : 0;
        }
        if (cmd == LINUX_WDIOC_KEEPALIVE) {
            int rc = watchdog_keepalive();
            return rc < 0 ? (uint64_t)rc : 0;
        }
        if (cmd == LINUX_WDIOC_SETTIMEOUT) {
            int timeout = 0;
            int rc;
            if (!arg_u) return (uint64_t)-EINVAL;
            if (copy_from_user(&timeout, arg_u, sizeof(timeout)) < 0) return (uint64_t)-EFAULT;
            rc = watchdog_set_timeout(timeout);
            if (rc < 0) return (uint64_t)rc;
            timeout = watchdog_get_timeout();
            if (copy_to_user(arg_u, &timeout, sizeof(timeout)) < 0) return (uint64_t)-EFAULT;
            return 0;
        }
        if (cmd == LINUX_WDIOC_GETTIMEOUT || cmd == LINUX_WDIOC_GETTIMELEFT) {
            int value = (cmd == LINUX_WDIOC_GETTIMEOUT) ?
                watchdog_get_timeout() : watchdog_get_timeleft();
            if (!arg_u) return (uint64_t)-EINVAL;
            if (value < 0) return (uint64_t)value;
            if (copy_to_user(arg_u, &value, sizeof(value)) < 0) return (uint64_t)-EFAULT;
            return 0;
        }
        if (cmd == LINUX_WDIOC_GETTEMP ||
            cmd == LINUX_WDIOC_SETPRETIMEOUT ||
            cmd == LINUX_WDIOC_GETPRETIMEOUT) {
            return (uint64_t)-EOPNOTSUPP;
        }
    }
#endif
    if (e->kind == FD_VFS && path_is_uinput_device(e->path)) {
        if (cmd == LINUX_UI_DEV_CREATE || cmd == LINUX_UI_DEV_DESTROY) return 0;
        if (((cmd >> 8) & 0xFFu) == 'U') return 0;
    }
    if (e->kind == FD_VFS && path_is_dri_device(e->path))
        return (uint64_t)-ENODEV;
#ifdef CONFIG_RTC
    if (e->kind == FD_VFS && path_is_rtc_device(e->path)) {
        if (cmd == LINUX_FIONREAD) {
            int avail = 4;
            if (!arg_u) return (uint64_t)-EINVAL;
            if (copy_to_user(arg_u, &avail, sizeof(avail)) < 0) return (uint64_t)-EFAULT;
            return 0;
        }
        if (cmd == LINUX_RTC_RD_TIME) {
            struct edge_rtc_time tm;
            if (!arg_u) return (uint64_t)-EINVAL;
            if (rtc_read_time(&tm) < 0) return (uint64_t)-EIO;
            if (copy_to_user(arg_u, &tm, sizeof(tm)) < 0) return (uint64_t)-EFAULT;
            return 0;
        }
        if (cmd == LINUX_RTC_IRQP_READ || cmd == LINUX_RTC_EPOCH_READ) {
            uint64_t value = (cmd == LINUX_RTC_IRQP_READ) ?
                (uint64_t)rtc_irq_rate() : (uint64_t)rtc_epoch();
            if (!arg_u) return (uint64_t)-EINVAL;
            if (copy_to_user(arg_u, &value, sizeof(value)) < 0) return (uint64_t)-EFAULT;
            return 0;
        }
        if (cmd == LINUX_RTC_VL_READ) {
            uint32_t flags = (uint32_t)rtc_voltage_low_flags();
            if (!arg_u) return (uint64_t)-EINVAL;
            if (copy_to_user(arg_u, &flags, sizeof(flags)) < 0) return (uint64_t)-EFAULT;
            return 0;
        }
        if (cmd == LINUX_RTC_VL_CLR) {
            return 0;
        }
        if (cmd == LINUX_RTC_PARAM_GET) {
            struct {
                uint64_t param;
                uint64_t uvalue;
                uint32_t index;
                uint32_t pad;
            } param;
            if (!arg_u) return (uint64_t)-EINVAL;
            if (copy_from_user(&param, arg_u, sizeof(param)) < 0) return (uint64_t)-EFAULT;
            if (param.param != LINUX_RTC_PARAM_FEATURES) return (uint64_t)-EINVAL;
            /*
             * Linux reports RTC feature bits through RTC_PARAM_GET.  EdgeOS
             * currently exposes a stable read-only wall clock but no alarm,
             * periodic, or update interrupt delivery, so the honest feature
             * mask is zero.  Red flag: do not advertise interrupt features
             * until read(2)/poll(2) can deliver matching RTC_IRQF events.
             */
            param.uvalue = 0;
            if (copy_to_user(arg_u, &param, sizeof(param)) < 0) return (uint64_t)-EFAULT;
            return 0;
        }
        if (cmd == LINUX_RTC_AIE_OFF || cmd == LINUX_RTC_UIE_OFF ||
            cmd == LINUX_RTC_PIE_OFF || cmd == LINUX_RTC_WIE_OFF) {
            return 0;
        }
        if (cmd == LINUX_RTC_AIE_ON || cmd == LINUX_RTC_UIE_ON ||
            cmd == LINUX_RTC_PIE_ON || cmd == LINUX_RTC_WIE_ON ||
            cmd == LINUX_RTC_ALM_SET || cmd == LINUX_RTC_ALM_READ ||
            cmd == LINUX_RTC_SET_TIME || cmd == LINUX_RTC_IRQP_SET ||
            cmd == LINUX_RTC_EPOCH_SET || cmd == LINUX_RTC_WKALM_SET ||
            cmd == LINUX_RTC_WKALM_RD || cmd == LINUX_RTC_PLL_GET ||
            cmd == LINUX_RTC_PLL_SET || cmd == LINUX_RTC_PARAM_SET) {
            return (uint64_t)-EOPNOTSUPP;
        }
    }
#endif

    if (cmd == LINUX_TIOCGPTN) {
        int n;
        if (e->kind != FD_PTY_MASTER) {
            if (PTY_IOCTL_TRACE()) {
                printf("[ptydiag] ioctl pid=%d task=%s fd=%d kind=%s path=%s cmd=TIOCGPTN res=ENOTTY\n",
                       cur ? cur->pid : -1, cur ? cur->name : "?",
                       fd, fd_kind_name(e->kind), e->path[0] ? e->path : "-");
            }
            return (uint64_t)-ENOTTY;
        }
        if (!arg_u) return (uint64_t)-EINVAL;
        n = e->pipe_id;
        if (copy_to_user(arg_u, &n, sizeof(n)) < 0) return (uint64_t)-EFAULT;
        if (PTY_IOCTL_TRACE()) {
            printf("[ptydiag] ioctl pid=%d task=%s fd=%d cmd=TIOCGPTN res=0 pty=%d\n",
                   cur ? cur->pid : -1, cur ? cur->name : "?", fd, n);
        }
        return 0;
    }
    if (cmd == LINUX_TIOCGPTPEER) {
        edge_fd_proc_t *p;
        edge_fd_t *peer;
        edge_pty_t *pty;
        int newfd;
        int flags = (int)arg_u;
        if (e->kind != FD_PTY_MASTER) {
            if (PTY_IOCTL_TRACE()) {
                printf("[ptydiag] ioctl pid=%d task=%s fd=%d kind=%s path=%s cmd=TIOCGPTPEER res=ENOTTY\n",
                       cur ? cur->pid : -1, cur ? cur->name : "?",
                       fd, fd_kind_name(e->kind), e->path[0] ? e->path : "-");
            }
            return (uint64_t)-ENOTTY;
        }
        if (e->pipe_id < 0 || e->pipe_id >= EDGE_MAX_PTYS) return (uint64_t)-EINVAL;
        pty = &g_ptys[e->pipe_id];
        if (!pty->used || !pty->unlocked) {
            if (PTY_IOCTL_TRACE()) {
                printf("[ptydiag] ioctl pid=%d task=%s fd=%d cmd=TIOCGPTPEER res=EIO pty=%d used=%d unlocked=%d\n",
                       cur ? cur->pid : -1, cur ? cur->name : "?",
                       fd, e->pipe_id, pty->used, pty->unlocked);
            }
            return (uint64_t)-EIO;
        }
        p = fd_proc_for_pid_empty(fd_owner_pid_current(), 1);
        if (!p) return (uint64_t)-ENOMEM;
        newfd = fd_alloc(p, 0);
        if (newfd < 0) return (uint64_t)-EMFILE;
        peer = &p->fds[newfd];
        peer->file_ref = file_ref_alloc((uint32_t)flags);
        if (!peer->file_ref) {
            fd_abort_reserved(p, newfd);
            return (uint64_t)-ENFILE;
        }
        pty_add_ref(e->pipe_id, 0);
        pty_maybe_assign_controlling_tty(e->pipe_id, flags);
        peer->kind = FD_PTY_SLAVE;
        peer->flags = flags;
        peer->fd_flags = (flags & LINUX_O_CLOEXEC) ? LINUX_FD_CLOEXEC : 0;
        peer->pipe_id = e->pipe_id;
        peer->pos = 0;
        strcpy(peer->path, "/dev/pts/");
        {
            char tmp[16];
            int n = 0;
            int x = e->pipe_id;
            int base = (int)strlen(peer->path);
            if (x == 0) {
                tmp[n++] = '0';
            } else {
                while (x > 0 && n < (int)sizeof(tmp)) {
                    tmp[n++] = (char)('0' + (x % 10));
                    x /= 10;
                }
            }
            for (int i = 0; i < n && base + i < (int)sizeof(peer->path) - 1; ++i) {
                peer->path[base + i] = tmp[n - 1 - i];
                peer->path[base + i + 1] = 0;
            }
        }
        if (fd_publish(p, newfd) < 0) {
            pty_drop_ref(e->pipe_id, 0);
            (void)file_ref_put(peer->file_ref);
            fd_abort_reserved(p, newfd);
            return (uint64_t)-EBADF;
        }
        if (PTY_IOCTL_TRACE()) {
            printf("[ptydiag] ioctl pid=%d task=%s fd=%d cmd=TIOCGPTPEER res=%d pty=%d flags=0x%x ctty=%d/%d refs=%d/%d\n",
                   cur ? cur->pid : -1, cur ? cur->name : "?",
                   fd, newfd, e->pipe_id, (unsigned)flags,
                   cur ? cur->ctty_kind : -1, cur ? cur->ctty_id : -1,
                   g_ptys[e->pipe_id].refs_master, g_ptys[e->pipe_id].refs_slave);
        }
        return (uint64_t)newfd;
    }
    if (cmd == LINUX_TIOCSPTLCK) {
        int lockv;
        edge_pty_t *pty;
        if (e->kind != FD_PTY_MASTER) {
            if (PTY_IOCTL_TRACE()) {
                printf("[ptydiag] ioctl pid=%d task=%s fd=%d kind=%s path=%s cmd=TIOCSPTLCK res=ENOTTY\n",
                       cur ? cur->pid : -1, cur ? cur->name : "?",
                       fd, fd_kind_name(e->kind), e->path[0] ? e->path : "-");
            }
            return (uint64_t)-ENOTTY;
        }
        if (!arg_u) return (uint64_t)-EINVAL;
        if (copy_from_user(&lockv, arg_u, sizeof(lockv)) < 0) return (uint64_t)-EFAULT;
        if (e->pipe_id < 0 || e->pipe_id >= EDGE_MAX_PTYS) return (uint64_t)-EINVAL;
        pty = &g_ptys[e->pipe_id];
        if (!pty->used) return (uint64_t)-EINVAL;
        pty->unlocked = (lockv == 0) ? 1 : 0;
        if (PTY_IOCTL_TRACE()) {
            printf("[ptydiag] ioctl pid=%d task=%s fd=%d cmd=TIOCSPTLCK res=0 pty=%d lock=%d unlocked=%d\n",
                   cur ? cur->pid : -1, cur ? cur->name : "?",
                   fd, e->pipe_id, lockv, pty->unlocked);
        }
        return 0;
    }
    if (cmd == LINUX_TIOCGPTLCK) {
        int lockv;
        edge_pty_t *pty;
        if (e->kind != FD_PTY_MASTER) {
            if (PTY_IOCTL_TRACE()) {
                printf("[ptydiag] ioctl pid=%d task=%s fd=%d kind=%s path=%s cmd=TIOCGPTLCK res=ENOTTY\n",
                       cur ? cur->pid : -1, cur ? cur->name : "?",
                       fd, fd_kind_name(e->kind), e->path[0] ? e->path : "-");
            }
            return (uint64_t)-ENOTTY;
        }
        if (!arg_u) return (uint64_t)-EINVAL;
        if (e->pipe_id < 0 || e->pipe_id >= EDGE_MAX_PTYS) return (uint64_t)-EINVAL;
        pty = &g_ptys[e->pipe_id];
        if (!pty->used) return (uint64_t)-EINVAL;
        /*
         * Linux exposes the ptmx slave lock as an integer where 0 means the
         * slave side is unlocked.  Modern terminal libraries probe this after
         * grantpt/unlockpt; returning ENOTTY makes an otherwise valid PTY look
         * unusable to VTE/xfce4-terminal.
         */
        lockv = pty->unlocked ? 0 : 1;
        if (copy_to_user(arg_u, &lockv, sizeof(lockv)) < 0) return (uint64_t)-EFAULT;
        if (PTY_IOCTL_TRACE()) {
            printf("[ptydiag] ioctl pid=%d task=%s fd=%d cmd=TIOCGPTLCK res=0 pty=%d lock=%d unlocked=%d\n",
                   cur ? cur->pid : -1, cur ? cur->name : "?",
                   fd, e->pipe_id, lockv, pty->unlocked);
        }
        return 0;
    }
    if (cmd == LINUX_TIOCPKT) {
        int pkt;
        edge_pty_t *pty;
        if (e->kind != FD_PTY_MASTER) {
            if (PTY_IOCTL_TRACE()) {
                printf("[ptydiag] ioctl pid=%d task=%s fd=%d kind=%s path=%s cmd=TIOCPKT res=ENOTTY\n",
                       cur ? cur->pid : -1, cur ? cur->name : "?",
                       fd, fd_kind_name(e->kind), e->path[0] ? e->path : "-");
            }
            return (uint64_t)-ENOTTY;
        }
        if (!arg_u) return (uint64_t)-EINVAL;
        if (copy_from_user(&pkt, arg_u, sizeof(pkt)) < 0) return (uint64_t)-EFAULT;
        if (e->pipe_id < 0 || e->pipe_id >= EDGE_MAX_PTYS) return (uint64_t)-EINVAL;
        pty = &g_ptys[e->pipe_id];
        if (!pty->used) return (uint64_t)-EINVAL;
        /*
         * Linux packet mode is enabled on the PTY master with TIOCPKT and
         * causes master reads to receive a leading status byte before normal
         * slave data.  VTE enables this during PTY setup; returning ENOTTY
         * makes the valid PTY look like a non-tty and surfaces as
         * "Failed to open PTY: Not a tty".
         *
         * EdgeOS does not currently emit control packets for stop/start/flush
         * state changes, but the normal-data prefix is enough for Linux
         * terminal emulators that enable packet mode and then spawn a shell.
         * Red flag: do not turn this into an XFCE special case; packet mode is
         * a PTY ABI feature.
         */
        pty->packet_mode = (pkt != 0);
        if (PTY_IOCTL_TRACE()) {
            printf("[ptydiag] ioctl pid=%d task=%s fd=%d cmd=TIOCPKT res=0 pty=%d pkt=%d\n",
                   cur ? cur->pid : -1, cur ? cur->name : "?",
                   fd, e->pipe_id, pty->packet_mode);
        }
        return 0;
    }
    if (cmd == LINUX_TIOCGPKT) {
        int pkt = 0;
        edge_pty_t *pty;
        if (e->kind != FD_PTY_MASTER) {
            if (PTY_IOCTL_TRACE()) {
                printf("[ptydiag] ioctl pid=%d task=%s fd=%d kind=%s path=%s cmd=TIOCGPKT res=ENOTTY\n",
                       cur ? cur->pid : -1, cur ? cur->name : "?",
                       fd, fd_kind_name(e->kind), e->path[0] ? e->path : "-");
            }
            return (uint64_t)-ENOTTY;
        }
        if (!arg_u) return (uint64_t)-EINVAL;
        if (e->pipe_id < 0 || e->pipe_id >= EDGE_MAX_PTYS) return (uint64_t)-EINVAL;
        pty = &g_ptys[e->pipe_id];
        if (!pty->used) return (uint64_t)-EINVAL;
        pkt = pty->packet_mode ? 1 : 0;
        if (copy_to_user(arg_u, &pkt, sizeof(pkt)) < 0) return (uint64_t)-EFAULT;
        if (PTY_IOCTL_TRACE()) {
            printf("[ptydiag] ioctl pid=%d task=%s fd=%d cmd=TIOCGPKT res=0 pty=%d pkt=%d\n",
                   cur ? cur->pid : -1, cur ? cur->name : "?",
                   fd, e->pipe_id, pkt);
        }
        return 0;
    }
    if (cmd == LINUX_TIOCSCTTY) {
        task_t *tcur = process_current_task();
        int line_id = console_line_from_fd_entry(e);
        edge_linux_tty_session_state_t *state =
            tty_session_state_from_entry(e);
        edge_linux_tty_session_caller_t caller;
        edge_linux_tty_session_transition_t transition;
        int64_t result;
        if (trace_initd_console_task(tcur)) {
            printf("[initd-spawn] pid=%d ioctl TIOCSCTTY fd=%d kind=%d path=%s\n",
                   tcur ? tcur->pid : -1, fd, e ? (int)e->kind : -1,
                   (e && e->path[0]) ? e->path : "-");
        }
        if (!tcur || !state) return (uint64_t)-ENOTTY;
        tty_session_caller_from_task(
            tcur, tty_fd_is_controlling_terminal(tcur, e), &caller);
        if (state->session_id != caller.sid)
            tty_session_reclaim_stale(state);
        result = edge_linux_tty_session_acquire(
            state, &caller, arg_u, &transition);
        if (result < 0) return (uint64_t)result;
        if (transition.displaced_session_id > 0) {
            tty_clear_session_tasks(transition.displaced_session_id);
            tty_notify_disassociated_process_group(
                transition.displaced_foreground_pgid);
        }
        if (e->kind == FD_PTY_MASTER || e->kind == FD_PTY_SLAVE) {
            tcur->ctty_kind = PROCESS_CTTY_PTY;
            tcur->ctty_id = e->pipe_id;
        } else {
            tcur->ctty_kind = PROCESS_CTTY_CONSOLE;
            tcur->ctty_id = line_id;
        }
        if (trace_vt_shell_task(tcur)) {
            printf("[ttydbg] pid=%d task=%s TIOCSCTTY fd=%d kind=%d path=%s line=%d pgid=%d ctty=%d/%d\n",
                   tcur->pid, tcur->name, fd, (int)e->kind,
                   e->path[0] ? e->path : "-", line_id,
                   process_getpgid(0), tcur->ctty_kind, tcur->ctty_id);
        }
        if (gui_diag_task(tcur) && gui_pty_ioctl_budget-- > 0) {
            printf("[ptydiag] ioctl pid=%d task=%s fd=%d kind=%s path=%s cmd=TIOCSCTTY res=0 pty=%d ctty=%d/%d pgid=%d\n",
                   tcur ? tcur->pid : -1, tcur ? tcur->name : "?",
                   fd, fd_kind_name(e->kind), e->path[0] ? e->path : "-",
                   (e->kind == FD_PTY_MASTER || e->kind == FD_PTY_SLAVE) ? e->pipe_id : -1,
                   tcur ? tcur->ctty_kind : -1, tcur ? tcur->ctty_id : -1,
                   process_getpgid(0));
        }
        return 0;
    }
    if (cmd == LINUX_TIOCNOTTY) {
        task_t *tcur = process_current_task();
        edge_linux_tty_session_state_t *state =
            tty_session_state_from_entry(e);
        edge_linux_tty_session_caller_t caller;
        edge_linux_tty_session_transition_t transition;
        int64_t result;
        if (!tcur || !state) return (uint64_t)-ENOTTY;
        tty_session_caller_from_task(
            tcur, tty_fd_is_controlling_terminal(tcur, e), &caller);
        result = edge_linux_tty_session_detach(state, &caller, &transition);
        if (result < 0) return (uint64_t)result;
        if (transition.detach_whole_session) {
            tty_clear_session_tasks(transition.detached_session_id);
            tty_notify_disassociated_process_group(
                transition.detached_foreground_pgid);
        } else {
            tcur->ctty_kind = PROCESS_CTTY_NONE;
            tcur->ctty_id = -1;
        }
        return 0;
    }
    if (cmd == LINUX_VT_OPENQRY) {
        int vt;
        if (!console_line_supports_linux_vt(e)) return (uint64_t)-ENOTTY;
        if (!arg_u) return (uint64_t)-EINVAL;
        vt = console_line_open_query();
        if (copy_to_user(arg_u, &vt, sizeof(vt)) < 0) return (uint64_t)-EFAULT;
        return 0;
    }
    if (cmd == LINUX_VT_GETMODE) {
        struct edge_linux_vt_mode mode;
        edge_console_line_t *line;
        if (!console_line_supports_linux_vt(e)) return (uint64_t)-ENOTTY;
        if (!arg_u) return (uint64_t)-EINVAL;
        line = console_line_state(console_line_from_fd_entry(e));
        if (!line) return (uint64_t)-EINVAL;
        memset(&mode, 0, sizeof(mode));
        mode.mode = line->vt_mode;
        mode.waitv = line->vt_waitv;
        mode.relsig = line->vt_relsig;
        mode.acqsig = line->vt_acqsig;
        mode.frsig = line->vt_frsig;
        if (copy_to_user(arg_u, &mode, sizeof(mode)) < 0) return (uint64_t)-EFAULT;
        return 0;
    }
    if (cmd == LINUX_VT_SETMODE) {
        struct edge_linux_vt_mode mode;
        edge_console_line_t *line;
        if (!console_line_supports_linux_vt(e)) return (uint64_t)-ENOTTY;
        if (!arg_u) return (uint64_t)-EINVAL;
        if (copy_from_user(&mode, arg_u, sizeof(mode)) < 0) return (uint64_t)-EFAULT;
        if (!(mode.mode == LINUX_VT_AUTO || mode.mode == LINUX_VT_PROCESS)) return (uint64_t)-EINVAL;
        line = console_line_state(console_line_from_fd_entry(e));
        if (!line) return (uint64_t)-EINVAL;
        line->vt_mode = mode.mode;
        line->vt_waitv = mode.waitv ? 1 : 0;
        line->vt_relsig = mode.relsig;
        line->vt_acqsig = mode.acqsig;
        line->vt_frsig = mode.frsig;
        return 0;
    }
    if (cmd == LINUX_VT_GETSTATE) {
        struct edge_linux_vt_stat st;
        int active = console_get_active_vt();
        if (!console_line_supports_linux_vt(e)) return (uint64_t)-ENOTTY;
        if (!arg_u) return (uint64_t)-EINVAL;
        memset(&st, 0, sizeof(st));
        st.v_active = (uint16_t)active;
        if (active >= 0 && active < 16) st.v_state = (uint16_t)(1u << active);
        if (copy_to_user(arg_u, &st, sizeof(st)) < 0) return (uint64_t)-EFAULT;
        return 0;
    }
    if (cmd == LINUX_VT_RELDISP) {
        if (!console_line_supports_linux_vt(e)) return (uint64_t)-ENOTTY;
        if (arg_u == 1 || arg_u == (uint64_t)LINUX_VT_ACKACQ) return 0;
        return (uint64_t)-EINVAL;
    }
    if (cmd == LINUX_VT_ACTIVATE || cmd == LINUX_VT_WAITACTIVE) {
        task_t *tcur = process_current_task();
        if (trace_initd_console_task(tcur)) {
            printf("[initd-spawn] pid=%d ioctl %s arg=0x%x\n",
                   tcur ? tcur->pid : -1,
                   cmd == LINUX_VT_ACTIVATE ? "VT_ACTIVATE" : "VT_WAITACTIVE",
                   (uint32_t)arg_u);
        }
        if ((int)arg_u < 1 || (int)arg_u > EDGE_FB_VT_COUNT)
            return (uint64_t)-ENXIO;
        if (cmd == LINUX_VT_ACTIVATE) {
            syscall_console_activate_vt((int)arg_u);
            return 0;
        }
        while (console_get_active_vt() != (int)arg_u) {
            if (!tcur || tcur->is_idle) return (uint64_t)-ESRCH;
            if (signal_pending_interrupt()) return tty_interrupt_current_ret();
            tcur->vt_wait_active = 1;
            tcur->vt_wait_target = (uint8_t)arg_u;
            scheduler_task_set_blocked(tcur);
            /* Close the condition-to-sleep race with a concurrent activator. */
            if (console_get_active_vt() == (int)arg_u) {
                tcur->vt_wait_active = 0;
                tcur->vt_wait_target = 0;
                scheduler_task_make_runnable(tcur, scheduler_cpu_id());
            }
            scheduler_yield();
            tcur = process_current_task();
            if (tcur) {
                tcur->vt_wait_active = 0;
                tcur->vt_wait_target = 0;
            }
        }
        return 0;
    }
    if (cmd == LINUX_KDGETMODE) {
        int mode;
        edge_console_line_t *line;
        if (!console_line_supports_linux_vt(e)) return (uint64_t)-ENOTTY;
        if (!arg_u) return (uint64_t)-EINVAL;
        line = console_line_state(console_line_from_fd_entry(e));
        if (!line) return (uint64_t)-EINVAL;
        mode = (int)line->kd_mode;
        if (copy_to_user(arg_u, &mode, sizeof(mode)) < 0) return (uint64_t)-EFAULT;
        return 0;
    }
    if (cmd == LINUX_KDSETMODE) {
        edge_console_line_t *line;
        int mode = (int)arg_u;
        if (!console_line_supports_linux_vt(e)) return (uint64_t)-ENOTTY;
        if (!(mode == LINUX_KD_TEXT || mode == LINUX_KD_GRAPHICS)) return (uint64_t)-EINVAL;
        line = console_line_state(console_line_from_fd_entry(e));
        if (!line) return (uint64_t)-EINVAL;
        line->kd_mode = (uint8_t)mode;
        line->kd_owner_pid =
            mode == LINUX_KD_GRAPHICS ? fd_owner_pid_current() : 0;
        /*
         * Linux text VTs stop repainting once Xorg owns the VT in KD_GRAPHICS.
         * Do the same at mode-switch time rather than relying only on /dev/fb0
         * open/close lifetime, otherwise the framebuffer console can replay its
         * underline cursor over the X root window after fbdev setup churn.
         */
        if (mode == LINUX_KD_GRAPHICS) {
            fb_console_set_present_enabled(0);
        } else if (!syscall_console_active_vt_in_graphics() && !fb_user_mmap_active()) {
            fb_console_set_present_enabled(1);
        }
        return 0;
    }
    if (cmd == LINUX_KDGKBMODE) {
        int mode;
        edge_console_line_t *line;
        if (!console_line_supports_linux_vt(e)) return (uint64_t)-ENOTTY;
        if (!arg_u) return (uint64_t)-EINVAL;
        line = console_line_state(console_line_from_fd_entry(e));
        if (!line) return (uint64_t)-EINVAL;
        mode = (int)line->kbd_mode;
        if (copy_to_user(arg_u, &mode, sizeof(mode)) < 0) return (uint64_t)-EFAULT;
        return 0;
    }
    if (cmd == LINUX_KDSKBMODE) {
        edge_console_line_t *line;
        int mode = (int)arg_u;
        if (!console_line_supports_linux_vt(e)) return (uint64_t)-ENOTTY;
        if (!(mode == LINUX_K_RAW || mode == LINUX_K_XLATE ||
              mode == LINUX_K_MEDIUMRAW || mode == LINUX_K_UNICODE ||
              mode == LINUX_K_OFF)) {
            return (uint64_t)-EINVAL;
        }
        line = console_line_state(console_line_from_fd_entry(e));
        if (!line) return (uint64_t)-EINVAL;
        line->kbd_mode = (uint8_t)mode;
        return 0;
    }
    if (cmd == LINUX_KDMKTONE) {
        if (!console_line_supports_linux_vt(e)) return (uint64_t)-ENOTTY;
        return 0;
    }
    if (cmd == LINUX_PIO_FONTRESET) {
        if (!console_line_supports_linux_vt(e)) return (uint64_t)-ENOTTY;
        fb_console_reset_font();
        return 0;
    }
    if (cmd == LINUX_PIO_FONT) {
        uint32_t bytes = 256u * 32u;
        if (!console_line_supports_linux_vt(e)) return (uint64_t)-ENOTTY;
        if (!arg_u) return (uint64_t)-EINVAL;
        if (copy_from_user(g_console_font_ioctl_buf, arg_u, bytes) < 0) return (uint64_t)-EFAULT;
        /*
         * Legacy PIO_FONT carries no height field.  Linux exposes it as an
         * expanded 32-byte-per-glyph font; preserve that layout and use the
         * traditional VGA 16-scanline cell for compatibility with older tools.
         */
        return (uint64_t)fb_console_set_font(g_console_font_ioctl_buf, 256u, 8u, 16u, 32u);
    }
    if (cmd == LINUX_GIO_FONT) {
        uint32_t charcount = 0, width = 0, height = 0;
        uint32_t bytes = 256u * 32u;
        int rc;
        if (!console_line_supports_linux_vt(e)) return (uint64_t)-ENOTTY;
        if (!arg_u) return (uint64_t)-EINVAL;
        rc = fb_console_get_font(g_console_font_ioctl_buf, &charcount, &width, &height, 32u);
        if (rc < 0) return (uint64_t)rc;
        (void)width;
        if (charcount < 256u) bytes = charcount * 32u;
        if (copy_to_user(arg_u, g_console_font_ioctl_buf, bytes) < 0) return (uint64_t)-EFAULT;
        return 0;
    }
    if (cmd == LINUX_PIO_FONTX) {
        struct edge_linux_consolefontdesc desc;
        uint32_t bytes;
        if (!console_line_supports_linux_vt(e)) return (uint64_t)-ENOTTY;
        if (!arg_u) return (uint64_t)-EINVAL;
        if (copy_from_user(&desc, arg_u, sizeof(desc)) < 0) return (uint64_t)-EFAULT;
        if (!desc.chardata || !(desc.charcount == 256u || desc.charcount == 512u) ||
            desc.charheight == 0u || desc.charheight > 32u) {
            return (uint64_t)-EINVAL;
        }
        bytes = (uint32_t)desc.charcount * (uint32_t)desc.charheight;
        if (bytes > sizeof(g_console_font_ioctl_buf)) return (uint64_t)-EINVAL;
        if (copy_from_user(g_console_font_ioctl_buf, desc.chardata, bytes) < 0) return (uint64_t)-EFAULT;
        return (uint64_t)fb_console_set_font(g_console_font_ioctl_buf, desc.charcount, 8u,
                                             desc.charheight, desc.charheight);
    }
    if (cmd == LINUX_GIO_FONTX) {
        struct edge_linux_consolefontdesc desc;
        uint32_t charcount = 0, width = 0, height = 0;
        uint32_t bytes;
        int rc;
        if (!console_line_supports_linux_vt(e)) return (uint64_t)-ENOTTY;
        if (!arg_u) return (uint64_t)-EINVAL;
        if (copy_from_user(&desc, arg_u, sizeof(desc)) < 0) return (uint64_t)-EFAULT;
        rc = fb_console_get_font(0, &charcount, &width, &height, 0);
        if (rc < 0) return (uint64_t)rc;
        (void)width;
        if (desc.charcount && desc.charcount < charcount) return (uint64_t)-EINVAL;
        if (desc.charheight && desc.charheight < height) return (uint64_t)-EINVAL;
        desc.charcount = (uint16_t)charcount;
        desc.charheight = (uint16_t)height;
        bytes = charcount * height;
        if (desc.chardata) {
            rc = fb_console_get_font(g_console_font_ioctl_buf, &charcount, &width, &height, height);
            if (rc < 0) return (uint64_t)rc;
            if (copy_to_user(desc.chardata, g_console_font_ioctl_buf, bytes) < 0) return (uint64_t)-EFAULT;
        }
        if (copy_to_user(arg_u, &desc, sizeof(desc)) < 0) return (uint64_t)-EFAULT;
        return 0;
    }
    if (cmd == LINUX_KDFONTOP) {
        struct edge_linux_console_font_op op;
        uint32_t pitch;
        uint32_t bytes;
        uint32_t charcount = 0, width = 0, height = 0;
        int rc;
        if (!console_line_supports_linux_vt(e)) return (uint64_t)-ENOTTY;
        if (!arg_u) return (uint64_t)-EINVAL;
        if (copy_from_user(&op, arg_u, sizeof(op)) < 0) return (uint64_t)-EFAULT;
        if (op.flags & ~LINUX_KD_FONT_FLAG_DONT_RECALC) return (uint64_t)-EINVAL;
        switch (op.op) {
            case LINUX_KD_FONT_OP_SET:
            case LINUX_KD_FONT_OP_SET_TALL:
                if (!op.data) return (uint64_t)-EINVAL;
                if (!(op.charcount == 256u || op.charcount == 512u)) return (uint64_t)-EINVAL;
                if (op.width == 0u) op.width = 8u;
                if (op.width > 8u || op.height == 0u || op.height > 32u) return (uint64_t)-EINVAL;
                pitch = (op.op == LINUX_KD_FONT_OP_SET_TALL) ? op.height : 32u;
                bytes = op.charcount * pitch;
                if (bytes > sizeof(g_console_font_ioctl_buf)) return (uint64_t)-EINVAL;
                if (copy_from_user(g_console_font_ioctl_buf, op.data, bytes) < 0) return (uint64_t)-EFAULT;
                return (uint64_t)fb_console_set_font(g_console_font_ioctl_buf, op.charcount,
                                                     op.width, op.height, pitch);
            case LINUX_KD_FONT_OP_GET:
            case LINUX_KD_FONT_OP_GET_TALL:
                rc = fb_console_get_font(0, &charcount, &width, &height, 0);
                if (rc < 0) return (uint64_t)rc;
                if (op.charcount && op.charcount < charcount) return (uint64_t)-EINVAL;
                if (op.height && op.height < height) return (uint64_t)-EINVAL;
                pitch = (op.op == LINUX_KD_FONT_OP_GET_TALL) ? height : 32u;
                bytes = charcount * pitch;
                if (bytes > sizeof(g_console_font_ioctl_buf)) return (uint64_t)-EINVAL;
                rc = fb_console_get_font(g_console_font_ioctl_buf, &charcount, &width, &height, pitch);
                if (rc < 0) return (uint64_t)rc;
                op.width = width;
                op.height = height;
                op.charcount = charcount;
                if (op.data && copy_to_user(op.data, g_console_font_ioctl_buf, bytes) < 0) return (uint64_t)-EFAULT;
                if (copy_to_user(arg_u, &op, sizeof(op)) < 0) return (uint64_t)-EFAULT;
                return 0;
            case LINUX_KD_FONT_OP_SET_DEFAULT:
                fb_console_reset_font();
                return 0;
            case LINUX_KD_FONT_OP_COPY:
            default:
                return (uint64_t)-EINVAL;
        }
    }

    if (cmd == LINUX_TIOCGWINSZ) {
        struct edge_winsize ws;
        ws.ws_row = 25;
        ws.ws_col = 80;
        ws.ws_xpixel = 0;
        ws.ws_ypixel = 0;
        if ((e->kind == FD_PTY_MASTER || e->kind == FD_PTY_SLAVE) &&
            e->pipe_id >= 0 && e->pipe_id < EDGE_MAX_PTYS && g_ptys[e->pipe_id].used) {
            ws = g_ptys[e->pipe_id].winsz;
        } else if (fd_is_tty(e)) {
            ws.ws_row = (uint16_t)fb_console_get_rows();
            ws.ws_col = (uint16_t)fb_console_get_cols();
        }
        if (arg_u && copy_to_user(arg_u, &ws, sizeof(ws)) < 0) return (uint64_t)-EFAULT;
        return 0;
    }
    if (cmd == LINUX_TIOCSWINSZ) {
        struct edge_winsize ws;
        if (!arg_u) return (uint64_t)-EINVAL;
        if (copy_from_user(&ws, arg_u, sizeof(ws)) < 0) return (uint64_t)-EFAULT;
        if ((e->kind == FD_PTY_MASTER || e->kind == FD_PTY_SLAVE) &&
            e->pipe_id >= 0 && e->pipe_id < EDGE_MAX_PTYS && g_ptys[e->pipe_id].used) {
            g_ptys[e->pipe_id].winsz = ws;
        }
        return 0;
    }
    if (cmd == LINUX_TCGETS) {
        edge_console_line_t *line = console_line_state(console_line_from_fd_entry(e));
        struct linux_termios_abi user_t;
        if (ssh_trace_task(cur)) {
            printf("[sshdbg] ioctl pid=%d cmd=%s fd=%d kind=%d path=%s line=%d\n",
                   cur ? cur->pid : -1, tty_ioctl_cmd_name(cmd), fd,
                   (int)e->kind, e->path[0] ? e->path : "-",
                   console_line_from_fd_entry(e));
        }
        if (e->kind == FD_PTY_MASTER || e->kind == FD_PTY_SLAVE) {
            if (!arg_u) return (uint64_t)-EINVAL;
            if (e->pipe_id < 0 || e->pipe_id >= EDGE_MAX_PTYS || !g_ptys[e->pipe_id].used) return (uint64_t)-EINVAL;
            termios_to_linux_abi(&g_ptys[e->pipe_id].termios, &user_t);
            if (copy_to_user(arg_u, &user_t, sizeof(user_t)) < 0) return (uint64_t)-EFAULT;
            if (gui_diag_task(cur) && gui_pty_ioctl_budget-- > 0) {
                printf("[ptydiag] ioctl pid=%d task=%s fd=%d kind=%s path=%s cmd=TCGETS res=0 pty=%d\n",
                       cur ? cur->pid : -1, cur ? cur->name : "?",
                       fd, fd_kind_name(e->kind), e->path[0] ? e->path : "-",
                       e->pipe_id);
            }
            tty_log_ioctl_once(cur, fd, cmd, e, "ok");
            return 0;
        }
        if (!arg_u) return (uint64_t)-EINVAL;
        if (!line) return (uint64_t)-EINVAL;
        termios_to_linux_abi(&line->termios, &user_t);
        if (copy_to_user(arg_u, &user_t, sizeof(user_t)) < 0) return (uint64_t)-EFAULT;
        tty_log_ioctl_once(cur, fd, cmd, e, "ok");
        return 0;
    }
    if (cmd == LINUX_TCSETS || cmd == LINUX_TCSETSW || cmd == LINUX_TCSETSF) {
        struct linux_termios_abi user_t;
        edge_console_line_t *line = console_line_state(console_line_from_fd_entry(e));
        if (!arg_u) return (uint64_t)-EINVAL;
        if (copy_from_user(&user_t, arg_u, sizeof(user_t)) < 0) return (uint64_t)-EFAULT;
        if (ssh_trace_task(cur)) {
            printf("[sshdbg] ioctl pid=%d cmd=%s fd=%d kind=%d path=%s line=%d set if=0x%x of=0x%x cf=0x%x lf=0x%x\n",
                   cur ? cur->pid : -1, tty_ioctl_cmd_name(cmd), fd,
                   (int)e->kind, e->path[0] ? e->path : "-",
                   console_line_from_fd_entry(e),
                   (unsigned)user_t.c_iflag, (unsigned)user_t.c_oflag,
                   (unsigned)user_t.c_cflag, (unsigned)user_t.c_lflag);
        }
        if (e->kind == FD_PTY_MASTER || e->kind == FD_PTY_SLAVE) {
            if (e->pipe_id < 0 || e->pipe_id >= EDGE_MAX_PTYS || !g_ptys[e->pipe_id].used) return (uint64_t)-EINVAL;
            termios_from_linux_abi(&g_ptys[e->pipe_id].termios, &user_t);
            if (cmd == LINUX_TCSETSF) {
                g_ptys[e->pipe_id].m2s_rpos =
                    g_ptys[e->pipe_id].m2s_wpos;
                g_ptys[e->pipe_id].m2s_count = 0;
            }
            tty_log_ioctl_once(cur, fd, cmd, e, "ok");
            return 0;
        }
        if (!line) return (uint64_t)-EINVAL;
        termios_from_linux_abi(&line->termios, &user_t);
        if (cmd == LINUX_TCSETSF) {
            line->line_len = 0;
            line->line_pos = 0;
        }
        tty_log_ioctl_once(cur, fd, cmd, e, "ok");
        return 0;
    }
    if (cmd == LINUX_TCSBRK || cmd == LINUX_TCXONC || cmd == LINUX_TCFLSH || cmd == LINUX_TCSBRKP) {
        /*
         * Line-control operations used by tcdrain/tcflush/tcsendbreak.  The
         * current console and pty backends have no deferred hardware queue to
         * drain here, so success is the Linux-compatible behavior userland
         * expects during getty/login tty setup.
         */
        if (cmd == LINUX_TCFLSH && e->kind == FD_CONSOLE) {
            edge_console_line_t *line = console_line_state(console_line_from_fd_entry(e));
            if (line) {
                line->line_len = 0;
                line->line_pos = 0;
            }
        }
        tty_log_ioctl_once(cur, fd, cmd, e, "ok");
        return 0;
    }
    if (cmd == LINUX_TIOCGPGRP || cmd == LINUX_TIOCGSID) {
        edge_linux_tty_session_state_t *state =
            tty_session_state_from_entry(e);
        edge_linux_tty_session_caller_t caller;
        int out_value = 0;
        int64_t result;
        if (!cur || !state) return (uint64_t)-ENOTTY;
        tty_session_caller_from_task(
            cur, tty_fd_is_controlling_terminal(cur, e), &caller);
        if (e->kind == FD_PTY_MASTER) {
            result = cmd == LINUX_TIOCGPGRP ?
                edge_linux_tty_session_get_peer_foreground(
                    state, &out_value) :
                edge_linux_tty_session_get_peer_id(state, &out_value);
        } else {
            result = cmd == LINUX_TIOCGPGRP ?
                edge_linux_tty_session_get_foreground(
                    state, &caller, &out_value) :
                edge_linux_tty_session_get_id(
                    state, &caller, &out_value);
        }
        if (result < 0) return (uint64_t)result;
        if (trace_vt_shell_task(cur)) {
            printf("[ttydbg] pid=%d task=%s TIOCGPGRP fd=%d kind=%d path=%s line=%d curpg=%d outpg=%d\n",
                   cur->pid, cur->name, fd, (int)e->kind,
                   e->path[0] ? e->path : "-",
                   console_line_from_fd_entry(e), cur->pgid, out_value);
        }
        if (!arg_u) return (uint64_t)-EINVAL;
        if (copy_to_user(arg_u, &out_value, sizeof(int)) < 0)
            return (uint64_t)-EFAULT;
        tty_log_ioctl_once(cur, fd, cmd, e, "ok");
        return 0;
    }
    if (cmd == LINUX_TIOCSPGRP) {
        int pg = 0;
        int group_sid = 0;
        int found;
        int64_t result;
        edge_linux_tty_session_state_t *state =
            tty_session_state_from_entry(e);
        edge_linux_tty_session_caller_t caller;
        if (!arg_u) return (uint64_t)-EINVAL;
        if (copy_from_user(&pg, arg_u, sizeof(int)) < 0) return (uint64_t)-EFAULT;
        if (!cur || !state) return (uint64_t)-ENOTTY;
        found = tty_process_group_session(pg, &group_sid);
        tty_session_caller_from_task(
            cur, tty_fd_is_controlling_terminal(cur, e), &caller);
        result = edge_linux_tty_session_set_foreground(
            state, &caller, pg, found, group_sid);
        if (result < 0) return (uint64_t)result;
        if (trace_vt_shell_task(cur)) {
            printf("[ttydbg] pid=%d task=%s TIOCSPGRP fd=%d kind=%d path=%s line=%d newpg=%d\n",
                   cur->pid, cur->name, fd, (int)e->kind,
                   e->path[0] ? e->path : "-", console_line_from_fd_entry(e), pg);
        }
        tty_log_ioctl_once(cur, fd, cmd, e, "ok");
        return 0;
    }

    if (e->kind == FD_VFS) {
        union {
            struct fb_info legacy;
            struct edge_fb_fix_screeninfo fix;
            struct edge_fb_var_screeninfo var;
        } fbarg;
        uint8_t uvc_arg[256];
        void *dev_arg = (void *)(uintptr_t)arg_u;
        int copy_back = 0;
        static int fb_ioctl_diag_budget =
            EDGE_GUI_DEEP_TRACE ? 64 : 0;
        if (path_is_alsa_device(e->path)) {
            int handled = 0;
            int64_t result;

            if (!cur || !cur->scratch) return (uint64_t)-EIO;
            result = alsa_ioctl_user(
                e->path, cmd, arg_u,
                cur->scratch->path_scratch[1],
                sizeof(cur->scratch->path_scratch[1]),
                x86_alsa_copy_from_user, x86_alsa_copy_to_user,
                cur, &handled);
            return handled ? (uint64_t)result : (uint64_t)-ENOTTY;
        }
        /*
         * /dev/fb0 is a graphics character device but it is not a V4L2/UVC
         * video-capture node.  Route Linux fbdev ioctls before the generic
         * video-device branch; otherwise FBIOPUT_VSCREENINFO falls through the
         * UVC handler as ENOSYS and userspace sees ENOTTY, which Xorg reports
         * as "FBIOPUT_VSCREENINFO: Not a tty".
         */
        if (strcmp(e->path, "/dev/fb0") != 0 && path_is_video_device(e->path)) {
            uint32_t sz = uvc_ioctl_arg_size(cmd);
            if (sz > sizeof(uvc_arg)) return (uint64_t)-EINVAL;
            if (sz > 0) {
                if (!arg_u) return (uint64_t)-EINVAL;
                if (copy_from_user(uvc_arg, arg_u, sz) < 0) return (uint64_t)-EFAULT;
                dev_arg = uvc_arg;
                copy_back = (int)sz;
            } else {
                dev_arg = 0;
                copy_back = 0;
            }
            int rc = vfs_dev_ioctl(e->path, cmd, dev_arg);
            if (rc == 0 && copy_back > 0) {
                if (copy_to_user(arg_u, dev_arg, (uint64_t)copy_back) < 0) return (uint64_t)-EFAULT;
            }
            if (rc == -ENOSYS) return (uint64_t)-ENOTTY;
            return (uint64_t)(int64_t)rc;
        }
        if (cmd == FB_IOCTL_GET_INFO_LEGACY) {
            dev_arg = &fbarg.legacy;
            copy_back = (int)sizeof(fbarg.legacy);
        } else if (cmd == LINUX_FBIOGET_FSCREENINFO) {
            dev_arg = &fbarg.fix;
            copy_back = (int)sizeof(fbarg.fix);
        } else if (cmd == LINUX_FBIOGET_VSCREENINFO) {
            dev_arg = &fbarg.var;
            copy_back = (int)sizeof(fbarg.var);
        } else if (cmd == LINUX_FBIOGETCMAP || cmd == LINUX_FBIOPUTCMAP) {
            if (strcmp(e->path, "/dev/fb0") == 0) return fbdev_ioctl_cmap(cmd, arg_u);
        } else if (cmd == LINUX_FBIOPUT_VSCREENINFO || cmd == LINUX_FBIOPAN_DISPLAY) {
            if (!arg_u || copy_from_user(&fbarg.var, arg_u, sizeof(fbarg.var)) < 0) return (uint64_t)-EFAULT;
            dev_arg = &fbarg.var;
        } else if (cmd == LINUX_FBIO_WAITFORVSYNC && strcmp(e->path, "/dev/fb0") == 0) {
            /*
             * Linux fbdev drivers commonly accept FBIO_WAITFORVSYNC as a
             * best-effort wait for the next display refresh.  The EdgeOS
             * virtio-gpu fbdev has no hardware vblank interrupt yet, but a
             * short scheduler yield preserves the Linux-visible success path
             * without lying about drawing: scanout publication still happens
             * through the fbdev mmap/write pump.
             */
            scheduler_yield();
            return 0;
        }
        int rc = vfs_dev_ioctl(e->path, cmd, dev_arg);
        if (rc == 0 && copy_back > 0) {
            if (!arg_u || copy_to_user(arg_u, dev_arg, (uint64_t)copy_back) < 0) return (uint64_t)-EFAULT;
        }
        /*
         * Keep a short always-on fbdev ABI trace while the desktop path is
         * under bring-up.  These are Linux-visible ioctl values, not policy:
         * bad smem_start, line_length, bpp, or rejected mode sets make Xorg
         * render into the wrong aperture or leave the screen black.  Red flag:
         * do not turn this into app/rootfs-specific behavior; remove or gate it
         * once fbdev is stable.
         */
        if (fb_ioctl_diag_budget > 0 && cur &&
            (cmd == LINUX_FBIOGET_FSCREENINFO || cmd == LINUX_FBIOGET_VSCREENINFO ||
             cmd == LINUX_FBIOPUT_VSCREENINFO || cmd == LINUX_FBIOPAN_DISPLAY)) {
            fb_ioctl_diag_budget--;
            if (cmd == LINUX_FBIOGET_FSCREENINFO && rc == 0) {
                struct edge_fb_fix_screeninfo *fix = &fbarg.fix;
                printf("[fbioctl] pid=%d task=%s fd=%d kind=%s path=%s cmd=FGET rc=%d smem=0x%x len=0x%x line=0x%x visual=%u type=%u budget=%d\n",
                       cur->pid, cur->name, fd, fd_kind_name(e->kind),
                       e->path[0] ? e->path : "-", rc,
                       (uint32_t)fix->smem_start,
                       fix->smem_len, fix->line_length, fix->visual, fix->type,
                       fb_ioctl_diag_budget);
            } else if (cmd == LINUX_FBIOGET_VSCREENINFO && rc == 0) {
                struct edge_fb_var_screeninfo *var = &fbarg.var;
                printf("[fbioctl] pid=%d task=%s fd=%d kind=%s path=%s cmd=VGET rc=%d res=%ux%u virt=%ux%u off=%u,%u bpp=%u rgb=%u/%u/%u widthmm=%u heightmm=%u budget=%d\n",
                       cur->pid, cur->name, fd, fd_kind_name(e->kind),
                       e->path[0] ? e->path : "-", rc,
                       var->xres, var->yres, var->xres_virtual, var->yres_virtual,
                       var->xoffset, var->yoffset, var->bits_per_pixel,
                       var->red.offset, var->green.offset, var->blue.offset,
                       var->width, var->height, fb_ioctl_diag_budget);
            } else if (cmd == LINUX_FBIOPUT_VSCREENINFO || cmd == LINUX_FBIOPAN_DISPLAY) {
                struct edge_fb_var_screeninfo *var = &fbarg.var;
                printf("[fbioctl] pid=%d task=%s fd=%d kind=%s path=%s cmd=%s rc=%d res=%ux%u virt=%ux%u off=%u,%u bpp=%u activate=0x%x budget=%d\n",
                       cur->pid, cur->name, fd, fd_kind_name(e->kind),
                       e->path[0] ? e->path : "-",
                       cmd == LINUX_FBIOPUT_VSCREENINFO ? "VPUT" : "PAN",
                       rc, var->xres, var->yres, var->xres_virtual, var->yres_virtual,
                       var->xoffset, var->yoffset, var->bits_per_pixel, var->activate,
                       fb_ioctl_diag_budget);
            } else {
                printf("[fbioctl] pid=%d task=%s fd=%d kind=%s path=%s cmd=0x%x rc=%d budget=%d\n",
                       cur->pid, cur->name, fd, fd_kind_name(e->kind),
                       e->path[0] ? e->path : "-", cmd, rc, fb_ioctl_diag_budget);
            }
        }
        if (EDGE_X11_TRACE && rc == 0 && cmd == LINUX_FBIOGET_FSCREENINFO && cur &&
            strcmp(cur->name, "Xorg") == 0) {
            struct edge_fb_fix_screeninfo *fix = &fbarg.fix;
            printf("[fbioctl] pid=%d task=%s fd=%d path=%s smem=0x%x len=0x%x line=0x%x\n",
                   cur->pid, cur->name, fd, e->path[0] ? e->path : "-",
                   (uint32_t)fix->smem_start, fix->smem_len, fix->line_length);
        }
        if (rc == 0) return 0;
        if (rc == -ENOSYS) return (uint64_t)-ENOTTY;
    }

    if ((e->kind == FD_PTY_MASTER || e->kind == FD_PTY_SLAVE) && PTY_IOCTL_TRACE()) {
        printf("[ptydiag] ioctl pid=%d task=%s fd=%d kind=%s path=%s cmd=0x%x arg=0x%x res=ENOTTY unsupported-pty-ioctl pty=%d flags=0x%x\n",
               cur ? cur->pid : -1, cur ? cur->name : "?",
               fd, fd_kind_name(e->kind), e->path[0] ? e->path : "-",
               cmd, (unsigned)arg_u, e->pipe_id, (unsigned)e->flags);
    }
    return (uint64_t)-ENOTTY;
#undef PTY_IOCTL_TRACE
}

int arch_ioctl_descriptor_is_fbdev(int32_t descriptor) {
    edge_fd_proc_t *process;
    edge_fd_t *entry;

    process = fd_proc_with_stdio();
    entry = fd_get(process, descriptor);
    return entry && strcmp(entry->path, "/dev/fb0") == 0;
}

int64_t arch_ioctl_execute(const kernel_ioctl_request_t *request) {
    edge_fd_proc_t *process;
    edge_fd_t *entry;

    if (!request) return -EIO;
    process = fd_proc_with_stdio();
    entry = fd_get(process, request->descriptor);
    if (entry && entry->kind == FD_VFS &&
        request->command == EDGE_LINUX_FS_IOC_FIEMAP)
        return kernel_linux_fiemap_ioctl(
            entry->sb, &entry->inode, request);
    if (entry && entry->kind == FD_VFS &&
        edge_drm_path_is_device(entry->path))
        return edge_drm_ioctl_path(
            file_ref_identity(entry->file_ref), entry->path, request);
    if (entry && entry->kind == FD_VFS &&
        path_is_dri_device(entry->path))
        return -ENODEV;
    return (int64_t)x86_ioctl_execute_raw(
        (uint32_t)request->descriptor, request->command,
        request->argument);
}

static uint64_t do_sys_fcntl(uint64_t fd_u, uint64_t cmd_u, uint64_t arg_u) {
    int fd = (int)fd_u;
    int cmd = (int)cmd_u;
    edge_fd_proc_t *p = fd_proc_with_stdio();
    edge_fd_t *e = fd_get(p, fd);
    task_t *cur = process_current_task();
    static int pty_fcntl_trace_budget = EDGE_PTY_DIAG_TRACE ? 192 : 0;
    if (!e) return (uint64_t)-EBADF;

    switch (cmd) {
        case LINUX_F_DUPFD:
        case LINUX_F_DUPFD_CLOEXEC: {
            int minfd = (int)arg_u;
            int32_t nfd = -1;
            int status;
            if (minfd < 0 ||
                (uint32_t)minfd >= kernel_fd_allocation_limit())
                return (uint64_t)-EINVAL;
            status = kernel_fd_duplicate(
                fd, minfd, 0,
                cmd == LINUX_F_DUPFD_CLOEXEC ?
                    KERNEL_FD_CLOEXEC : 0u,
                &nfd);
            return status < 0 ? (uint64_t)(int64_t)status :
                (uint64_t)(uint32_t)nfd;
        }
        case LINUX_F_GETFD:
            if ((e->kind == FD_PTY_MASTER || e->kind == FD_PTY_SLAVE) &&
                pty_fcntl_trace_budget-- > 0) {
                printf("[ptydiag] fcntl pid=%d task=%s fd=%d cmd=F_GETFD res=0x%x kind=%s pty=%d flags=0x%x fdflags=0x%x\n",
                       cur ? cur->pid : -1, cur ? cur->name : "?",
                       fd, (unsigned)(e->fd_flags & LINUX_FD_CLOEXEC),
                       fd_kind_name(e->kind), e->pipe_id,
                       (unsigned)e->flags, (unsigned)e->fd_flags);
            }
            return (uint64_t)(e->fd_flags & LINUX_FD_CLOEXEC);
        case LINUX_F_SETFD:
            e->fd_flags = (int)(arg_u & LINUX_FD_CLOEXEC);
            if ((e->kind == FD_PTY_MASTER || e->kind == FD_PTY_SLAVE) &&
                pty_fcntl_trace_budget-- > 0) {
                printf("[ptydiag] fcntl pid=%d task=%s fd=%d cmd=F_SETFD arg=0x%x res=0 kind=%s pty=%d flags=0x%x fdflags=0x%x\n",
                       cur ? cur->pid : -1, cur ? cur->name : "?",
                       fd, (unsigned)arg_u, fd_kind_name(e->kind), e->pipe_id,
                       (unsigned)e->flags, (unsigned)e->fd_flags);
            }
            return 0;
        case LINUX_F_GETFL:
            if (fd_description_refresh_status(e) < 0)
                return (uint64_t)-EBADF;
            if ((e->kind == FD_PTY_MASTER || e->kind == FD_PTY_SLAVE) &&
                pty_fcntl_trace_budget-- > 0) {
                printf("[ptydiag] fcntl pid=%d task=%s fd=%d cmd=F_GETFL res=0x%x kind=%s pty=%d flags=0x%x fdflags=0x%x\n",
                       cur ? cur->pid : -1, cur ? cur->name : "?",
                       fd, (unsigned)e->flags, fd_kind_name(e->kind),
                       e->pipe_id, (unsigned)e->flags, (unsigned)e->fd_flags);
            }
            return (uint64_t)e->flags;
        case LINUX_F_SETFL:
            if (kernel_fd_update_status_flags(
                    fd, ~((uint32_t)LINUX_O_ACCMODE),
                    (uint32_t)arg_u) < 0)
                return (uint64_t)-EBADF;
            if ((e->kind == FD_PTY_MASTER || e->kind == FD_PTY_SLAVE) &&
                pty_fcntl_trace_budget-- > 0) {
                printf("[ptydiag] fcntl pid=%d task=%s fd=%d cmd=F_SETFL arg=0x%x res=0 kind=%s pty=%d flags=0x%x fdflags=0x%x\n",
                       cur ? cur->pid : -1, cur ? cur->name : "?",
                       fd, (unsigned)arg_u, fd_kind_name(e->kind), e->pipe_id,
                       (unsigned)e->flags, (unsigned)e->fd_flags);
            }
            return 0;
        case LINUX_F_SETOWN:
            /*
             * Xorg's evdev path follows the Linux input setup sequence and may
             * set an async owner before enabling O_ASYNC.  EdgeOS still wakes
             * input consumers through poll/select today, but returning ENOSYS
             * here makes Linux userland treat the device as partially broken.
             * Preserve the requested owner so F_GETOWN observes Linux-like
             * descriptor state; the common blocking wait path delivers SIGIO
             * for async evdev descriptors when input arrives.
            */
            e->async_owner = (int)arg_u;
            fd_async_input_watch_update(e);
            return 0;
        case LINUX_F_GETOWN:
            return (uint64_t)(int64_t)e->async_owner;
        case LINUX_F_SETSIG:
            e->async_signal = (int)arg_u;
            return 0;
        case LINUX_F_GETSIG:
            return (uint64_t)(int64_t)e->async_signal;
        case LINUX_F_GETPIPE_SZ:
            if (e->kind != FD_PIPE_R && e->kind != FD_PIPE_W && e->kind != FD_PIPE_RW) return (uint64_t)-EBADF;
            if (e->pipe_id < 0 || e->pipe_id >= EDGE_MAX_PIPES || !g_pipes[e->pipe_id].used) return (uint64_t)-EBADF;
            return (uint64_t)EDGE_PIPE_SIZE;
        case LINUX_F_SETPIPE_SZ: {
            uint64_t requested = arg_u;
            if (e->kind != FD_PIPE_R && e->kind != FD_PIPE_W && e->kind != FD_PIPE_RW) return (uint64_t)-EBADF;
            if (e->pipe_id < 0 || e->pipe_id >= EDGE_MAX_PIPES || !g_pipes[e->pipe_id].used) return (uint64_t)-EBADF;
            if (requested == 0) return (uint64_t)-EINVAL;
            /*
             * EdgeOS pipes are backed by a real fixed-size 64 KiB ring today.
             * Linux permits unprivileged callers to ask for the current size
             * or smaller and returns the effective capacity; it rejects growth
             * that exceeds the caller's permission or kernel limits.  Do not
             * store a pretend per-pipe capacity until the read/write paths and
             * wakeup predicates use dynamically allocated rings.
             */
            if (requested > EDGE_PIPE_SIZE) return (uint64_t)-EPERM;
            return (uint64_t)EDGE_PIPE_SIZE;
        }
        case LINUX_F_GET_SEALS: {
            edge_memfd_t *mf;
            uint32_t seals;
            if (e->kind == FD_VFS && e->sb &&
                tmpfs_memfd_get_seals(e->sb, &e->inode, &seals) == 0)
                return (uint64_t)seals;
            if (e->kind != FD_MEMFD) return (uint64_t)-EINVAL;
            mf = memfd_get(e->pipe_id);
            if (!mf) return (uint64_t)-EBADF;
            if (mf->secret) return (uint64_t)-EINVAL;
            return (uint64_t)mf->seals;
        }
        case LINUX_F_ADD_SEALS:
            return memfd_fcntl_add_seals(e, arg_u);
        default:
            if ((e->kind == FD_PTY_MASTER || e->kind == FD_PTY_SLAVE) &&
                pty_fcntl_trace_budget-- > 0) {
                printf("[ptydiag] fcntl pid=%d task=%s fd=%d cmd=%d arg=0x%x res=ENOSYS kind=%s pty=%d flags=0x%x fdflags=0x%x\n",
                       cur ? cur->pid : -1, cur ? cur->name : "?",
                       fd, cmd, (unsigned)arg_u, fd_kind_name(e->kind), e->pipe_id,
                       (unsigned)e->flags, (unsigned)e->fd_flags);
            }
            return (uint64_t)-ENOSYS;
    }
}

static uint64_t do_sys_dup(uint64_t fd_u) {
    return do_sys_fcntl(fd_u, LINUX_F_DUPFD, 0);
}

static uint64_t do_sys_dup_exact(uint64_t oldfd_u, uint64_t newfd_u,
                                 uint32_t descriptor_flags) {
    int oldfd = (int)oldfd_u;
    int newfd = (int)newfd_u;
    edge_fd_proc_t *p = fd_proc_with_stdio();
    edge_fd_t copy;
    edge_fd_t closing;
    int replaced = 0;
    int status;

    if (!p || newfd < 0 || newfd >= EDGE_MAX_FD)
        return (uint64_t)-EBADF;
    if (oldfd == newfd)
        return fd_get(p, oldfd) ? (uint64_t)newfd :
               (uint64_t)-EBADF;
    status = fd_snapshot_retain(p, oldfd, &copy);
    if (status < 0)
        return (uint64_t)(status == -ENOMEM ? -ENOMEM : -EBADF);
    copy.fd_flags = (int)(descriptor_flags & LINUX_FD_CLOEXEC);
    status = fd_replace_exact(
        p, newfd, &copy, &closing, &replaced);
    if (status < 0) {
        (void)fd_release_entry(&copy, 0, 0, 0);
        return (uint64_t)status;
    }
    if (replaced)
        (void)fd_release_entry(
            &closing, process_current_task(), 1, 1);
    if (ssh_trace_task(process_current_task())) {
        printf("[sshdbg] dup2 pid=%d cmd=%s old=%d new=%d kind=%d fl=0x%x sid=%d\n",
               process_getpid(), process_current_task()->name, oldfd, newfd,
               (int)copy.kind, (unsigned)copy.flags, copy.pipe_id);
    }
    if (g_pipe_lifecycle_trace_budget > 0 && pipe_lifecycle_trace_task(process_current_task()) &&
        (copy.kind == FD_PIPE_R || copy.kind == FD_PIPE_W ||
         copy.kind == FD_PIPE_RW)) {
        edge_pipe_t *pp = &g_pipes[copy.pipe_id];
        printf("[pipefd] dup2 pid=%d cmd=%s old=%d new=%d kind=%s pipe=%d r=%d w=%d refs=%d budget=%d\n",
               process_getpid(), process_current_task()->name, oldfd, newfd,
               fd_kind_name(copy.kind), copy.pipe_id,
               pp->readers, pp->writers, copy.file_ref,
               g_pipe_lifecycle_trace_budget - 1);
        g_pipe_lifecycle_trace_budget--;
    }
    fd_log_lifecycle("dup2", process_getpid(), oldfd, &copy, newfd);
    fd_log_lifecycle("dup2-new", process_getpid(), newfd, &copy, oldfd);
    return (uint64_t)newfd;
}

static uint64_t do_sys_dup2(uint64_t oldfd_u, uint64_t newfd_u) {
    return do_sys_dup_exact(oldfd_u, newfd_u, 0);
}

int arch_fd_pipe_prepare(
    uint32_t flags_u, int32_t descriptors[2],
    kernel_fd_publication_t *publication) {
    int flags = (int)flags_u;
    int status;
    task_t *cur = process_current_task();
    edge_fd_proc_t *p = fd_proc_with_stdio();
    if (!p) return -ENOMEM;

    int pid = pipe_alloc();
    if (pid < 0) return -ENFILE;
    kernel_pipe_metadata_initialize(
        &g_pipes[pid], cur ? cur->euid : 0u, cur ? cur->egid : 0u, 0600u);
    if (flags & LINUX_O_DIRECT) {
        status = kernel_pipe_packet_mode_set(&g_pipes[pid], 1);
        if (status < 0) {
            memset(&g_pipes[pid], 0, sizeof(g_pipes[pid]));
            return status;
        }
    }

    int rfd = fd_alloc(p, 0);
    if (rfd < 0) {
        memset(&g_pipes[pid], 0, sizeof(g_pipes[pid]));
        return -EMFILE;
    }
    int wfd = fd_alloc(p, 0);
    if (wfd < 0) {
        fd_abort_reserved(p, rfd);
        memset(&g_pipes[pid], 0, sizeof(g_pipes[pid]));
        return -EMFILE;
    }

    p->fds[rfd].kind = FD_PIPE_R;
    p->fds[rfd].file_ref = file_ref_alloc(
        flags & (LINUX_O_NONBLOCK | LINUX_O_DIRECT));
    if (!p->fds[rfd].file_ref) {
        fd_abort_reserved(p, rfd);
        fd_abort_reserved(p, wfd);
        memset(&g_pipes[pid], 0, sizeof(g_pipes[pid]));
        return -ENFILE;
    }
    p->fds[rfd].pipe_id = pid;
    p->fds[rfd].flags =
        flags & (LINUX_O_NONBLOCK | LINUX_O_DIRECT);
    p->fds[rfd].fd_flags = (flags & LINUX_O_CLOEXEC) ? LINUX_FD_CLOEXEC : 0;
    p->fds[wfd].kind = FD_PIPE_W;
    p->fds[wfd].file_ref = file_ref_alloc(
        LINUX_O_WRONLY |
        (flags & (LINUX_O_NONBLOCK | LINUX_O_DIRECT)));
    if (!p->fds[wfd].file_ref) {
        (void)file_ref_put(p->fds[rfd].file_ref);
        fd_abort_reserved(p, rfd);
        fd_abort_reserved(p, wfd);
        memset(&g_pipes[pid], 0, sizeof(g_pipes[pid]));
        return -ENFILE;
    }
    p->fds[wfd].pipe_id = pid;
    p->fds[wfd].flags = LINUX_O_WRONLY |
        (flags & (LINUX_O_NONBLOCK | LINUX_O_DIRECT));
    p->fds[wfd].fd_flags = (flags & LINUX_O_CLOEXEC) ? LINUX_FD_CLOEXEC : 0;

    if (kernel_pipe_endpoint_retain(&g_pipes[pid], 1, 1) < 0) {
        (void)file_ref_put(p->fds[rfd].file_ref);
        (void)file_ref_put(p->fds[wfd].file_ref);
        fd_abort_reserved(p, rfd);
        fd_abort_reserved(p, wfd);
        memset(&g_pipes[pid], 0, sizeof(g_pipes[pid]));
        return -ENFILE;
    }

    descriptors[0] = rfd;
    descriptors[1] = wfd;
    status = x86_fd_publication_initialize(
        p, descriptors, 2u, publication);
    if (status < 0) {
        descriptors[0] = -1;
        descriptors[1] = -1;
        return status;
    }
    if (trace_initd_console_task(cur)) {
        printf("[initd-spawn] pid=%d pipe2 flags=0x%x rfd=%d wfd=%d\n",
               cur ? cur->pid : -1, flags, rfd, wfd);
    }
    if (cur && g_pipe_lifecycle_trace_budget > 0 && pipe_lifecycle_trace_task(cur)) {
        printf("[pipefd] create pid=%d cmd=%s pipe=%d rfd=%d wfd=%d flags=0x%x r=%d w=%d budget=%d\n",
               cur->pid, cur->name, pid, rfd, wfd, flags,
               g_pipes[pid].readers, g_pipes[pid].writers,
               g_pipe_lifecycle_trace_budget - 1);
        g_pipe_lifecycle_trace_budget--;
    }
    {
        static int dbus_pipe_create_trace_budget = EDGE_GUI_DEEP_TRACE ? 64 : 0;
        if (cur && dbus_pipe_create_trace_budget > 0 &&
            (strcmp(cur->name, "dbus-run-sessio") == 0 ||
             strcmp(cur->name, "dbus-run-session") == 0 ||
             strcmp(cur->name, "dbus-daemon") == 0)) {
            printf("[dbuspipe] create pid=%d cmd=%s pipe=%d rfd=%d wfd=%d flags=0x%x\n",
                   cur->pid, cur->name, pid, rfd, wfd, flags);
            dbus_pipe_create_trace_budget--;
        }
    }
    return 0;
}
