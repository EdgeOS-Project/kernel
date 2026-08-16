/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-neutral lwIP transport for the EdgeOS NFS server. */

#include "fs/nfsd.h"
#include "kernel/boot_command_line.h"
#include "kernel/linux_errno.h"
#include "net/lwip_stack.h"
#include "vfs/vfs.h"
#include "lwip/err.h"
#include "lwip/ip_addr.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "stdio.h"
#include "string.h"

#define NFSD_RPC_MAX 65536u
#define NFSD_TCP_CONNECTIONS 8u
#define NFSD_TCP_OUTPUT_MAX (NFSD_RPC_MAX * 2u + 8u)
#define NFSD_REQUEST_QUEUE_LENGTH 32u
#define NFSD_REQUEST_TCP 1u
#define NFSD_REQUEST_UDP 2u

typedef struct {
    struct tcp_pcb *pcb;
    uint8_t request[NFSD_RPC_MAX];
    uint8_t output[NFSD_TCP_OUTPUT_MAX];
    uint32_t request_bytes;
    uint32_t output_bytes;
    uint32_t output_offset;
    uint32_t fragment_bytes;
    uint8_t marker[4];
    uint8_t marker_bytes;
    uint8_t fragment_last;
    uint8_t used;
    uint16_t service_port;
    uint32_t generation;
} nfsd_tcp_connection_t;

typedef struct {
    nfsd_tcp_connection_t *connection;
    struct udp_pcb *udp_pcb;
    ip_addr_t address;
    uint32_t connection_generation;
    uint32_t request_bytes;
    uint16_t port;
    uint8_t kind;
    uint8_t request[NFSD_RPC_MAX];
} nfsd_request_t;

typedef struct {
    uint16_t port;
} nfsd_listener_t;

static struct udp_pcb *g_udp_rpcbind;
static struct udp_pcb *g_udp_mount;
static struct udp_pcb *g_udp_nfs;
static struct tcp_pcb *g_tcp_rpcbind;
static struct tcp_pcb *g_tcp_mount;
static struct tcp_pcb *g_tcp_nfs;
static nfsd_listener_t g_listener_rpcbind = {111u};
static nfsd_listener_t g_listener_mount = {20048u};
static nfsd_listener_t g_listener_nfs = {2049u};
static nfsd_tcp_connection_t g_connections[NFSD_TCP_CONNECTIONS];
static nfsd_request_t g_requests[NFSD_REQUEST_QUEUE_LENGTH];
static uint8_t g_udp_request[NFSD_RPC_MAX];
static uint8_t g_udp_response[NFSD_RPC_MAX];
static uint8_t g_tcp_response[NFSD_RPC_MAX];
static char g_boot_export_path[VFS_PATH_MAX];
static uint32_t g_request_head;
static uint32_t g_request_tail;
static uint32_t g_request_count;
static uint32_t g_connection_generation;
static uint8_t g_running;
static uint8_t g_trace;
static uint8_t g_worker_active;

static uint32_t nfsd_read_be32(const uint8_t bytes[4]) {
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | bytes[3];
}

static void nfsd_write_be32(uint8_t bytes[4], uint32_t value) {
    bytes[0] = (uint8_t)(value >> 24);
    bytes[1] = (uint8_t)(value >> 16);
    bytes[2] = (uint8_t)(value >> 8);
    bytes[3] = (uint8_t)value;
}

static nfsd_request_t *nfsd_request_reserve(void) {
    nfsd_request_t *request;
    if (g_request_count >= NFSD_REQUEST_QUEUE_LENGTH) return 0;
    request = &g_requests[g_request_tail];
    memset(request, 0, sizeof(*request));
    g_request_tail = (g_request_tail + 1u) % NFSD_REQUEST_QUEUE_LENGTH;
    ++g_request_count;
    return request;
}

static int nfsd_enqueue_tcp(nfsd_tcp_connection_t *connection,
                            const uint8_t *data, uint32_t length) {
    nfsd_request_t *request;
    if (!connection || !data || !length || length > NFSD_RPC_MAX)
        return -1;
    request = nfsd_request_reserve();
    if (!request) return -1;
    request->kind = NFSD_REQUEST_TCP;
    request->connection = connection;
    request->connection_generation = connection->generation;
    request->request_bytes = length;
    memcpy(request->request, data, length);
    if (g_trace)
        printf("[nfsd] TCP port %u queued=%u pending=%u\n",
               connection->service_port, length, g_request_count);
    return 0;
}

static int nfsd_enqueue_udp(struct udp_pcb *pcb, const ip_addr_t *address,
                            uint16_t port, const uint8_t *data,
                            uint32_t length) {
    nfsd_request_t *request;
    if (!pcb || !address || !data || !length || length > NFSD_RPC_MAX)
        return -1;
    request = nfsd_request_reserve();
    if (!request) return -1;
    request->kind = NFSD_REQUEST_UDP;
    request->udp_pcb = pcb;
    request->address = *address;
    request->port = port;
    request->request_bytes = length;
    memcpy(request->request, data, length);
    return 0;
}

static void nfsd_udp_receive(void *argument, struct udp_pcb *pcb,
                             struct pbuf *packet, const ip_addr_t *address,
                             u16_t port) {
    uint32_t request_bytes;
    (void)argument;
    if (!packet) return;
    request_bytes = packet->tot_len;
    if (request_bytes > sizeof(g_udp_request) ||
        pbuf_copy_partial(packet, g_udp_request, request_bytes, 0u) !=
            request_bytes) {
        pbuf_free(packet);
        return;
    }
    pbuf_free(packet);
    if (g_trace)
        printf("[nfsd] UDP local=%u request=%u\n",
               pcb ? pcb->local_port : 0u, request_bytes);
    (void)nfsd_enqueue_udp(pcb, address, port, g_udp_request,
                           request_bytes);
}

static void nfsd_tcp_release(nfsd_tcp_connection_t *connection) {
    if (!connection) return;
    memset(connection, 0, sizeof(*connection));
}

static void nfsd_tcp_abort(nfsd_tcp_connection_t *connection) {
    struct tcp_pcb *pcb;
    if (!connection || !connection->used) return;
    pcb = connection->pcb;
    if (pcb) {
        tcp_arg(pcb, 0);
        tcp_recv(pcb, 0);
        tcp_sent(pcb, 0);
        tcp_err(pcb, 0);
        tcp_abort(pcb);
    }
    nfsd_tcp_release(connection);
}

static void nfsd_tcp_flush(nfsd_tcp_connection_t *connection) {
    while (connection && connection->pcb &&
           connection->output_offset < connection->output_bytes) {
        uint32_t remaining = connection->output_bytes -
                             connection->output_offset;
        uint16_t available = tcp_sndbuf(connection->pcb);
        uint16_t chunk;
        err_t result;
        if (!available) break;
        chunk = remaining < available ? (uint16_t)remaining : available;
        result = tcp_write(connection->pcb,
            connection->output + connection->output_offset, chunk,
            TCP_WRITE_FLAG_COPY);
        if (result == ERR_MEM) break;
        if (result != ERR_OK) {
            nfsd_tcp_abort(connection);
            return;
        }
        connection->output_offset += chunk;
    }
    if (connection && connection->pcb) (void)tcp_output(connection->pcb);
    if (connection && connection->output_offset == connection->output_bytes) {
        connection->output_offset = 0u;
        connection->output_bytes = 0u;
    }
}

static int nfsd_tcp_queue_reply(nfsd_tcp_connection_t *connection,
                                const uint8_t *request,
                                uint32_t request_bytes) {
    uint32_t response_bytes = 0;
    uint32_t required;
    uint32_t program = request_bytes >= 16u ?
                       nfsd_read_be32(request + 12u) : 0u;
    uint32_t procedure = request_bytes >= 24u ?
                         nfsd_read_be32(request + 20u) : 0u;
    if (g_trace && request_bytes >= 24u)
        printf("[nfsd] TCP port %u program=%u procedure=%u\n",
               connection->service_port, program, procedure);
    if (edge_nfsd_rpc_dispatch(request, request_bytes, g_tcp_response,
            sizeof(g_tcp_response),
            &response_bytes) < 0 || !response_bytes)
        return -1;
    if (g_trace)
        printf("[nfsd] TCP port %u request=%u reply=%u\n",
               connection->service_port, request_bytes,
               response_bytes);
    if (g_trace && program == 100005u && procedure == 1u &&
        response_bytes >= 28u)
        printf("[nfsd] mount reply status=%u\n",
               nfsd_read_be32(g_tcp_response + 24u));
    if (g_trace && program == 100003u && response_bytes >= 28u)
        printf("[nfsd] NFS procedure=%u status=%u\n", procedure,
               nfsd_read_be32(g_tcp_response + 24u));
    required = response_bytes + 4u;
    if (connection->output_offset) {
        uint32_t remaining = connection->output_bytes -
                             connection->output_offset;
        memmove(connection->output,
                connection->output + connection->output_offset, remaining);
        connection->output_bytes = remaining;
        connection->output_offset = 0u;
    }
    if (required > sizeof(connection->output) - connection->output_bytes)
        return -1;
    nfsd_write_be32(connection->output + connection->output_bytes,
                    0x80000000u | response_bytes);
    memcpy(connection->output + connection->output_bytes + 4u,
           g_tcp_response, response_bytes);
    connection->output_bytes += required;
    nfsd_tcp_flush(connection);
    return 0;
}

static int nfsd_tcp_consume(nfsd_tcp_connection_t *connection,
                            const uint8_t *data, uint32_t length) {
    uint32_t offset = 0;
    while (offset < length) {
        if (connection->marker_bytes < 4u) {
            connection->marker[connection->marker_bytes++] = data[offset++];
            if (connection->marker_bytes == 4u) {
                uint32_t marker = nfsd_read_be32(connection->marker);
                connection->fragment_last = (marker >> 31) != 0u;
                connection->fragment_bytes = marker & 0x7fffffffu;
                if (!connection->fragment_bytes ||
                    connection->fragment_bytes >
                        NFSD_RPC_MAX - connection->request_bytes)
                    return -1;
            }
            continue;
        }
        {
            uint32_t available = length - offset;
            uint32_t amount = connection->fragment_bytes < available ?
                              connection->fragment_bytes : available;
            memcpy(connection->request + connection->request_bytes,
                   data + offset, amount);
            connection->request_bytes += amount;
            connection->fragment_bytes -= amount;
            offset += amount;
        }
        if (!connection->fragment_bytes) {
            uint8_t last = connection->fragment_last;
            connection->marker_bytes = 0u;
            connection->fragment_last = 0u;
            if (last) {
                if (nfsd_enqueue_tcp(connection, connection->request,
                                     connection->request_bytes) < 0)
                    return -1;
                connection->request_bytes = 0u;
            }
        }
    }
    return 0;
}

static err_t nfsd_tcp_sent(void *argument, struct tcp_pcb *pcb,
                           u16_t length) {
    nfsd_tcp_connection_t *connection = argument;
    (void)pcb;
    (void)length;
    nfsd_tcp_flush(connection);
    return ERR_OK;
}

static void nfsd_tcp_error(void *argument, err_t error) {
    nfsd_tcp_connection_t *connection = argument;
    (void)error;
    nfsd_tcp_release(connection);
}

static err_t nfsd_tcp_receive(void *argument, struct tcp_pcb *pcb,
                              struct pbuf *packet, err_t error) {
    nfsd_tcp_connection_t *connection = argument;
    struct pbuf *segment;
    if (!connection || !connection->used || error != ERR_OK) {
        if (packet) pbuf_free(packet);
        return ERR_OK;
    }
    if (!packet) {
        tcp_arg(pcb, 0);
        tcp_recv(pcb, 0);
        tcp_sent(pcb, 0);
        tcp_err(pcb, 0);
        if (tcp_close(pcb) != ERR_OK) tcp_abort(pcb);
        nfsd_tcp_release(connection);
        return ERR_OK;
    }
    if (g_trace)
        printf("[nfsd] TCP port %u received=%u\n",
               connection->service_port, (unsigned)packet->tot_len);
    tcp_recved(pcb, packet->tot_len);
    for (segment = packet; segment; segment = segment->next) {
        if (nfsd_tcp_consume(connection, segment->payload,
                             segment->len) < 0) {
            pbuf_free(packet);
            nfsd_tcp_abort(connection);
            return ERR_ABRT;
        }
    }
    pbuf_free(packet);
    return ERR_OK;
}

static err_t nfsd_tcp_accept(void *argument, struct tcp_pcb *pcb,
                             err_t error) {
    nfsd_listener_t *listener = argument;
    uint32_t index;
    if (!pcb || error != ERR_OK) {
        if (pcb) tcp_abort(pcb);
        return ERR_ABRT;
    }
    for (index = 0; index < NFSD_TCP_CONNECTIONS; ++index) {
        nfsd_tcp_connection_t *connection = &g_connections[index];
        if (connection->used) continue;
        memset(connection, 0, sizeof(*connection));
        connection->used = 1u;
        connection->pcb = pcb;
        connection->service_port = listener ? listener->port : 0u;
        connection->generation = ++g_connection_generation;
        if (!connection->generation)
            connection->generation = ++g_connection_generation;
        tcp_arg(pcb, connection);
        tcp_recv(pcb, nfsd_tcp_receive);
        tcp_sent(pcb, nfsd_tcp_sent);
        tcp_err(pcb, nfsd_tcp_error);
        if (g_trace)
            printf("[nfsd] TCP port %u client accepted\n",
                   connection->service_port);
        return ERR_OK;
    }
    tcp_abort(pcb);
    return ERR_ABRT;
}

static int nfsd_open_udp(struct udp_pcb **slot, uint16_t port) {
    struct udp_pcb *pcb = udp_new_ip_type(IPADDR_TYPE_ANY);
    if (!pcb) return -1;
    if (udp_bind(pcb, IP_ANY_TYPE, port) != ERR_OK) {
        udp_remove(pcb);
        return -1;
    }
    udp_recv(pcb, nfsd_udp_receive, 0);
    *slot = pcb;
    return 0;
}

void edge_nfsd_poll(void) {
    uint32_t budget = NFSD_REQUEST_QUEUE_LENGTH;
    if (!g_running || g_worker_active) return;
    g_worker_active = 1u;
    if (g_trace && g_request_count)
        printf("[nfsd] worker pending=%u\n", g_request_count);
    while (g_request_count && budget--) {
        nfsd_request_t *request = &g_requests[g_request_head];
        if (request->kind == NFSD_REQUEST_TCP) {
            nfsd_tcp_connection_t *connection = request->connection;
            if (g_trace)
                printf("[nfsd] worker TCP used=%u generation=%u expected=%u bytes=%u\n",
                       connection ? connection->used : 0u,
                       connection ? connection->generation : 0u,
                       request->connection_generation,
                       request->request_bytes);
            if (connection && connection->used &&
                connection->generation == request->connection_generation &&
                nfsd_tcp_queue_reply(connection, request->request,
                                     request->request_bytes) < 0)
                nfsd_tcp_abort(connection);
        } else if (request->kind == NFSD_REQUEST_UDP) {
            struct pbuf *reply;
            uint32_t response_bytes = 0;
            if (edge_nfsd_rpc_dispatch(request->request,
                    request->request_bytes, g_udp_response,
                    sizeof(g_udp_response), &response_bytes) == 0 &&
                response_bytes && response_bytes <= 65507u) {
                if (g_trace)
                    printf("[nfsd] UDP local=%u reply=%u\n",
                           request->udp_pcb ? request->udp_pcb->local_port : 0u,
                           response_bytes);
                reply = pbuf_alloc(PBUF_TRANSPORT, (u16_t)response_bytes,
                                   PBUF_RAM);
                if (reply) {
                    if (pbuf_take(reply, g_udp_response,
                                  (u16_t)response_bytes) == ERR_OK)
                        (void)udp_sendto(request->udp_pcb, reply,
                                         &request->address, request->port);
                    pbuf_free(reply);
                }
            }
        }
        memset(request, 0, sizeof(*request));
        g_request_head = (g_request_head + 1u) % NFSD_REQUEST_QUEUE_LENGTH;
        --g_request_count;
    }
    g_worker_active = 0u;
}

static int nfsd_open_tcp(struct tcp_pcb **slot, uint16_t port,
                         nfsd_listener_t *listener) {
    struct tcp_pcb *pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
    struct tcp_pcb *listening;
    if (!pcb) return -1;
    if (tcp_bind(pcb, IP_ANY_TYPE, port) != ERR_OK) {
        tcp_close(pcb);
        return -1;
    }
    listening = tcp_listen_with_backlog(pcb, NFSD_TCP_CONNECTIONS);
    if (!listening) {
        tcp_close(pcb);
        return -1;
    }
    tcp_arg(listening, listener);
    tcp_accept(listening, nfsd_tcp_accept);
    *slot = listening;
    return 0;
}

static void nfsd_close_udp(struct udp_pcb **slot) {
    if (*slot) udp_remove(*slot);
    *slot = 0;
}

static void nfsd_close_tcp(struct tcp_pcb **slot) {
    if (*slot) {
        tcp_arg(*slot, 0);
        tcp_accept(*slot, 0);
        if (tcp_close(*slot) != ERR_OK) tcp_abort(*slot);
    }
    *slot = 0;
}

int edge_nfsd_start(void) {
    if (g_running) return 0;
    if (!lwip_stack_is_ready() || edge_nfsd_export_count() == 0u)
        return -EDGE_LINUX_EINVAL;
    memset(g_connections, 0, sizeof(g_connections));
    memset(g_requests, 0, sizeof(g_requests));
    g_request_head = 0u;
    g_request_tail = 0u;
    g_request_count = 0u;
    g_worker_active = 0u;
    if (nfsd_open_udp(&g_udp_rpcbind, 111u) < 0 ||
        nfsd_open_udp(&g_udp_mount, 20048u) < 0 ||
        nfsd_open_udp(&g_udp_nfs, 2049u) < 0 ||
        nfsd_open_tcp(&g_tcp_rpcbind, 111u, &g_listener_rpcbind) < 0 ||
        nfsd_open_tcp(&g_tcp_mount, 20048u, &g_listener_mount) < 0 ||
        nfsd_open_tcp(&g_tcp_nfs, 2049u, &g_listener_nfs) < 0) {
        edge_nfsd_stop();
        return -EDGE_LINUX_EADDRINUSE;
    }
    g_running = 1u;
    printf("[nfsd] NFSv3 serving %u export(s) over TCP and UDP\n",
           edge_nfsd_export_count());
    return 0;
}

void edge_nfsd_stop(void) {
    uint32_t index;
    for (index = 0; index < NFSD_TCP_CONNECTIONS; ++index)
        if (g_connections[index].used) nfsd_tcp_abort(&g_connections[index]);
    nfsd_close_tcp(&g_tcp_nfs);
    nfsd_close_tcp(&g_tcp_mount);
    nfsd_close_tcp(&g_tcp_rpcbind);
    nfsd_close_udp(&g_udp_nfs);
    nfsd_close_udp(&g_udp_mount);
    nfsd_close_udp(&g_udp_rpcbind);
    memset(g_requests, 0, sizeof(g_requests));
    g_request_head = 0u;
    g_request_tail = 0u;
    g_request_count = 0u;
    g_worker_active = 0u;
    g_running = 0u;
}

int edge_nfsd_running(void) {
    return g_running ? 1 : 0;
}

int edge_nfsd_boot_start(void) {
    uint32_t flags = 0;
    int option;
    if (!kernel_boot_option_enabled("nfsd", 0)) return 0;
    g_trace = kernel_boot_option_enabled("nfsd.trace", 0) ? 1u : 0u;
    option = kernel_boot_option_get("nfsd.export", g_boot_export_path,
                                    sizeof(g_boot_export_path));
    if (option <= 0 || !g_boot_export_path[0]) {
        printf("[nfsd] nfsd=1 requires nfsd.export=/absolute/path\n");
        return -EDGE_LINUX_EINVAL;
    }
    if (kernel_boot_option_enabled("nfsd.read_only", 0))
        flags |= EDGE_NFSD_EXPORT_READ_ONLY;
    if (kernel_boot_option_enabled("nfsd.root_squash", 1))
        flags |= EDGE_NFSD_EXPORT_ROOT_SQUASH;
    if (edge_nfsd_initialize() < 0 ||
        edge_nfsd_export_add(g_boot_export_path, flags) < 0) {
        printf("[nfsd] failed to export %s\n", g_boot_export_path);
        return -EDGE_LINUX_EINVAL;
    }
    return edge_nfsd_start();
}
