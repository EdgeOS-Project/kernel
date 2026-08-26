/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent socket runtime interface.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_SOCKET_RUNTIME_H
#define EDGEOS_KERNEL_SOCKET_RUNTIME_H

#include <stdint.h>

#include "kernel/linux_abi.h"

#ifndef EDGEOS_KERNEL_FD_PUBLICATION_TYPEDEF
#define EDGEOS_KERNEL_FD_PUBLICATION_TYPEDEF
typedef struct kernel_fd_publication kernel_fd_publication_t;
#endif

typedef struct kernel_socket_address {
    uint8_t bytes[EDGE_LINUX_SOCKADDR_STORAGE_SIZE];
    uint32_t length;
} kernel_socket_address_t;

/*
 * Reserve one architecture-owned socket slot before its backing object is
 * initialized. The reservation is retained until final object teardown.
 */
int32_t kernel_socket_slot_claim(volatile uint8_t *claims,
                                 uint32_t claim_count);
void kernel_socket_slot_release(volatile uint8_t *claims,
                                uint32_t claim_count, uint32_t index);

#define EDGE_LINUX_SOCKET_ADDRESS_OPTIONAL 0x00000001u

int edge_linux_socket_address_copy_to_user(
    void *task, edge_linux_copy_from_user_fn copy_from_user,
    edge_linux_copy_to_user_fn copy_to_user, uint64_t user_address,
    uint64_t user_length, const kernel_socket_address_t *address,
    uint32_t flags);

typedef struct kernel_socket_descriptor_info {
    uint32_t domain;
    uint32_t type;
    uint32_t protocol;
    uint32_t receive_queue_bytes;
    uint32_t send_queue_bytes;
    uint8_t connected;
    uint8_t listening;
    uint8_t bound;
    uint8_t reuse_port;
} kernel_socket_descriptor_info_t;

/*
 * Descriptor-based socket syscalls first normalize Linux-visible arguments,
 * then execute one or more operations against a retained file description.
 * The request intentionally contains no descriptor number: once the operation
 * lease is acquired, an architecture backend must use only its retained
 * storage and must never resolve the descriptor table slot again.
 *
 * Accept, socketpair, message I/O, and socket options have separate ownership
 * or publication protocols and are deliberately not represented by this core
 * operation set.
 */
typedef enum kernel_socket_operation {
    KERNEL_SOCKET_OPERATION_DESCRIBE = 1,
    KERNEL_SOCKET_OPERATION_LISTEN,
    KERNEL_SOCKET_OPERATION_SHUTDOWN,
    KERNEL_SOCKET_OPERATION_BIND,
    KERNEL_SOCKET_OPERATION_CONNECT,
    KERNEL_SOCKET_OPERATION_NAME,
} kernel_socket_operation_t;

typedef struct kernel_socket_connect_operation {
    kernel_socket_address_t address;
    void *user_registers;
} kernel_socket_connect_operation_t;

typedef union kernel_socket_operation_arguments {
    int32_t listen_backlog;
    int32_t shutdown_how;
    kernel_socket_address_t bind_address;
    kernel_socket_connect_operation_t connect;
    uint32_t name_peer;
} kernel_socket_operation_arguments_t;

typedef struct kernel_socket_operation_request {
    uint32_t operation;
    uint32_t reserved;
    kernel_socket_operation_arguments_t arguments;
} kernel_socket_operation_request_t;

typedef union kernel_socket_operation_output {
    kernel_socket_descriptor_info_t description;
    kernel_socket_address_t address;
} kernel_socket_operation_output_t;

typedef struct kernel_socket_operation_result {
    kernel_socket_operation_output_t output;
} kernel_socket_operation_result_t;

/*
 * Execute one normalized operation with one acquire/release transaction.
 * Architecture backends return -ENOTSOCK when the retained object is not a
 * socket and -EOPNOTSUPP when the normalized operation is unsupported.
 * Every successful acquisition is paired with exactly one release, including
 * type, dispatch, and unsupported-operation failures. Result storage is
 * cleared before dispatch and remains cleared whenever this function returns
 * an error.
 */
int64_t kernel_socket_operation_execute(
    int32_t descriptor,
    const kernel_socket_operation_request_t *request,
    kernel_socket_operation_result_t *result);

typedef struct kernel_socket_stream_state {
    int32_t error;
    uint32_t send_space;
    uint8_t connecting;
    uint8_t connected;
    uint8_t closed;
    uint8_t shutdown_write;
} kernel_socket_stream_state_t;

#define KERNEL_SOCKET_POLL_INPUT  0x0001u
#define KERNEL_SOCKET_POLL_OUTPUT 0x0004u
#define KERNEL_SOCKET_POLL_ERROR  0x0008u
#define KERNEL_SOCKET_POLL_HANGUP 0x0010u
#define KERNEL_SOCKET_POLL_NVAL   0x0020u
#define KERNEL_SOCKET_POLL_RDHUP  0x2000u

/*
 * Readiness generations let edge-triggered waiters distinguish a new socket
 * transition from readiness that they have already consumed.  Generations
 * never use zero so a zero observation can remain the universal "unsupported
 * or not yet initialized" value in architecture descriptor adapters.
 */
typedef struct kernel_socket_readiness {
    uint64_t read_sequence;
    uint64_t write_sequence;
} kernel_socket_readiness_t;

/*
 * Network backends publish receive work outside an individual socket object.
 * Each architecture records the last producer generations observed by a
 * socket, while this common helper owns the race-safe comparison policy.
 */
typedef struct kernel_socket_external_readiness {
    uint64_t packet_frame_sequence;
    uint64_t icmp_sequence;
    uint64_t packet_ring_sequence;
} kernel_socket_external_readiness_t;

#define KERNEL_SOCKET_READINESS_READ_CHANGED  0x00000001u
#define KERNEL_SOCKET_READINESS_WRITE_CHANGED 0x00000002u

void kernel_socket_readiness_initialize(
    kernel_socket_readiness_t *readiness);
void kernel_socket_readiness_advance(
    kernel_socket_readiness_t *readiness, uint32_t changed);
void kernel_socket_readiness_snapshot(
    const kernel_socket_readiness_t *readiness,
    uint64_t *read_sequence, uint64_t *write_sequence);
void kernel_socket_external_readiness_initialize(
    kernel_socket_external_readiness_t *readiness,
    uint64_t packet_frame_sequence, uint64_t icmp_sequence,
    uint64_t packet_ring_sequence);
uint32_t kernel_socket_external_readiness_observe(
    kernel_socket_external_readiness_t *readiness,
    uint64_t packet_frame_sequence, uint64_t icmp_sequence,
    uint64_t packet_ring_sequence);
int kernel_socket_is_icmp_reader(
    uint32_t domain, uint32_t type, uint32_t protocol);

#define KERNEL_SOCKET_CONNECT_TIMEOUT_DEFAULT_US 10000000ull

typedef struct kernel_socket_connect_deadline_tracker {
    uint64_t earliest_us;
} kernel_socket_connect_deadline_tracker_t;

uint64_t kernel_socket_connect_timeout_us(
    uint64_t configured_receive_timeout_us);
uint64_t kernel_socket_connect_deadline_us(
    uint64_t started_us, uint64_t configured_receive_timeout_us);
int kernel_socket_connect_timeout_expired(
    uint64_t started_us, uint64_t now_us,
    uint64_t configured_receive_timeout_us);
void kernel_socket_connect_deadline_tracker_initialize(
    kernel_socket_connect_deadline_tracker_t *tracker);
void kernel_socket_connect_deadline_tracker_note(
    kernel_socket_connect_deadline_tracker_t *tracker,
    uint64_t deadline_us);
int kernel_socket_connect_deadline_tracker_take_due(
    kernel_socket_connect_deadline_tracker_t *tracker,
    uint64_t now_us);

typedef struct kernel_socket_poll_state {
    kernel_socket_stream_state_t stream;
    uint8_t valid;
    uint8_t readable;
    uint8_t writable;
    uint8_t read_closed;
    uint8_t hangup;
    uint8_t use_stream_write_policy;
} kernel_socket_poll_state_t;

typedef struct kernel_unix_socket_poll_state {
    uint32_t type;
    uint32_t peer_receive_used;
    uint32_t peer_receive_capacity;
    uint32_t peer_record_count;
    uint32_t peer_record_capacity;
    uint8_t connected;
    uint8_t shutdown_read;
    uint8_t shutdown_write;
    uint8_t peer_eof;
    uint8_t peer_valid;
    uint8_t peer_shutdown_read;
} kernel_unix_socket_poll_state_t;

typedef struct kernel_unix_socket_poll_result {
    uint8_t read_closed;
    uint8_t hangup;
    uint8_t writable;
} kernel_unix_socket_poll_result_t;

/*
 * Transport callbacks use lwIP error values internally.  Keep their
 * Linux-visible errno and connect-completion readiness policy here so every
 * architecture reports the same result to poll, epoll, and SO_ERROR.
 */
int kernel_socket_lwip_errno(int transport_error, int active_open);
uint32_t kernel_socket_stream_write_events(
    const kernel_socket_stream_state_t *state);
uint32_t kernel_socket_poll_events(
    const kernel_socket_poll_state_t *state);
int kernel_socket_type_has_peer_eof(uint32_t type);
int kernel_unix_socket_missing_peer_error(uint32_t type, int peer_closed);
int32_t kernel_unix_socket_credential_pid(int32_t thread_id,
                                          int32_t thread_group_id);
void kernel_unix_socket_poll_policy(
    const kernel_unix_socket_poll_state_t *state,
    kernel_unix_socket_poll_result_t *result);

typedef struct kernel_socket_buffer_request {
    int32_t descriptor;
    uint32_t flags;
    uint64_t user_buffer;
    uint64_t length;
    uint64_t user_address;
    uint64_t user_address_length;
    kernel_socket_address_t address;
    uint8_t receiving;
    uint8_t has_address;
    uint8_t reserved[6];
    void *user_registers;
    void *copy_context;
    edge_linux_copy_from_user_fn copy_from_user;
    edge_linux_copy_to_user_fn copy_to_user;
} kernel_socket_buffer_request_t;

typedef enum kernel_socket_option_id {
    KERNEL_SOCKET_OPTION_PASS_CREDENTIALS = 1,
    KERNEL_SOCKET_OPTION_TIMESTAMP_US_OLD,
    KERNEL_SOCKET_OPTION_TIMESTAMP_US_NEW,
    KERNEL_SOCKET_OPTION_TIMESTAMP_NS_OLD,
    KERNEL_SOCKET_OPTION_TIMESTAMP_NS_NEW,
    KERNEL_SOCKET_OPTION_REUSE_ADDRESS,
    KERNEL_SOCKET_OPTION_REUSE_PORT,
    KERNEL_SOCKET_OPTION_BROADCAST,
    KERNEL_SOCKET_OPTION_KEEPALIVE,
    KERNEL_SOCKET_OPTION_OOB_INLINE,
    KERNEL_SOCKET_OPTION_NO_CHECK,
    KERNEL_SOCKET_OPTION_LINGER_ENABLED,
    KERNEL_SOCKET_OPTION_LINGER_SECONDS,
    KERNEL_SOCKET_OPTION_PRIORITY,
    KERNEL_SOCKET_OPTION_MARK,
    KERNEL_SOCKET_OPTION_SEND_BUFFER,
    KERNEL_SOCKET_OPTION_RECEIVE_BUFFER,
    KERNEL_SOCKET_OPTION_SEND_LOW_WATER,
    KERNEL_SOCKET_OPTION_RECEIVE_LOW_WATER,
    KERNEL_SOCKET_OPTION_IP_TOS,
    KERNEL_SOCKET_OPTION_IP_TTL,
    KERNEL_SOCKET_OPTION_IP_MULTICAST_TTL,
    KERNEL_SOCKET_OPTION_IP_MULTICAST_LOOP,
    KERNEL_SOCKET_OPTION_IP_PACKET_INFO,
    KERNEL_SOCKET_OPTION_IP_RECEIVE_ERROR,
    KERNEL_SOCKET_OPTION_IP_RECEIVE_TTL,
    KERNEL_SOCKET_OPTION_IP_FREEBIND,
    KERNEL_SOCKET_OPTION_IP_MTU_DISCOVER,
    KERNEL_SOCKET_OPTION_IPV6_ONLY,
    KERNEL_SOCKET_OPTION_IPV6_MULTICAST_HOPS,
    KERNEL_SOCKET_OPTION_IPV6_MULTICAST_LOOP,
    KERNEL_SOCKET_OPTION_IPV6_RECEIVE_ERROR,
    KERNEL_SOCKET_OPTION_IPV6_RECEIVE_PACKET_INFO,
    KERNEL_SOCKET_OPTION_IPV6_RECEIVE_HOP_LIMIT,
    KERNEL_SOCKET_OPTION_IPV6_RECEIVE_TRAFFIC_CLASS,
    KERNEL_SOCKET_OPTION_IPV6_CHECKSUM,
    KERNEL_SOCKET_OPTION_TCP_NODELAY,
    KERNEL_SOCKET_OPTION_TCP_KEEP_IDLE,
    KERNEL_SOCKET_OPTION_TCP_KEEP_INTERVAL,
    KERNEL_SOCKET_OPTION_TCP_KEEP_COUNT,
    KERNEL_SOCKET_OPTION_RECEIVE_TIMEOUT_US,
    KERNEL_SOCKET_OPTION_SEND_TIMEOUT_US,
    KERNEL_SOCKET_OPTION_IP_HEADER_INCLUDED,
    KERNEL_SOCKET_OPTION_NETLINK_PACKET_INFO,
    KERNEL_SOCKET_OPTION_FILTER_LOCKED,
} kernel_socket_option_id_t;

#define KERNEL_SOCKET_MULTICAST_MEMBERSHIP_MAX 16u
#define KERNEL_SOCKET_ICMP6_FILTER_WORDS 8u

typedef struct kernel_socket_multicast_membership {
    uint8_t used;
    uint8_t domain;
    uint8_t reserved[2];
    uint32_t interface_index;
    uint8_t group[16];
} kernel_socket_multicast_membership_t;

typedef enum kernel_socket_timestamp_mode {
    KERNEL_SOCKET_TIMESTAMP_DISABLED = 0,
    KERNEL_SOCKET_TIMESTAMP_US_OLD,
    KERNEL_SOCKET_TIMESTAMP_US_NEW,
    KERNEL_SOCKET_TIMESTAMP_NS_OLD,
    KERNEL_SOCKET_TIMESTAMP_NS_NEW,
} kernel_socket_timestamp_mode_t;

/*
 * Architecture runtimes embed this state in their transport object.  Linux
 * option decoding and validation remains in the shared syscall core; this
 * object only records normalized policy values used by socket mechanics.
 */
typedef struct kernel_socket_option_state {
    uint64_t receive_timeout_us;
    uint64_t send_timeout_us;
    int32_t priority;
    uint32_t mark;
    int32_t linger_seconds;
    int32_t ip_mtu_discover;
    int32_t ipv6_checksum;
    int32_t ipv6_multicast_hops;
    uint32_t ip_multicast_interface_address;
    uint32_t ip_multicast_interface_index;
    uint32_t ipv6_multicast_interface_index;
    int32_t tcp_keep_idle;
    int32_t tcp_keep_interval;
    int32_t tcp_keep_count;
    uint32_t send_buffer;
    uint32_t receive_buffer;
    uint32_t send_low_water;
    uint32_t receive_low_water;
    uint8_t pass_credentials;
    uint8_t timestamp_mode;
    uint8_t reuse_address;
    uint8_t reuse_port;
    uint8_t broadcast;
    uint8_t keepalive;
    uint8_t oob_inline;
    uint8_t no_check;
    uint8_t linger_enabled;
    uint8_t ip_tos;
    uint8_t ip_ttl;
    uint8_t ip_multicast_ttl;
    uint8_t ip_multicast_loop;
    uint8_t ip_packet_info;
    uint8_t ip_receive_error;
    uint8_t ip_receive_ttl;
    uint8_t ip_freebind;
    uint8_t ipv6_only;
    uint8_t ipv6_multicast_loop;
    uint8_t ipv6_receive_error;
    uint8_t ipv6_receive_packet_info;
    uint8_t ipv6_receive_hop_limit;
    uint8_t ipv6_receive_traffic_class;
    uint8_t tcp_nodelay;
    uint8_t ip_header_included;
    uint8_t netlink_packet_info;
    uint8_t filter_locked;
    uint32_t icmp6_filter[KERNEL_SOCKET_ICMP6_FILTER_WORDS];
    kernel_socket_multicast_membership_t
        multicast_memberships[KERNEL_SOCKET_MULTICAST_MEMBERSHIP_MAX];
} kernel_socket_option_state_t;

typedef enum kernel_socket_option_effect {
    KERNEL_SOCKET_OPTION_EFFECT_NONE = 0,
    KERNEL_SOCKET_OPTION_EFFECT_PASS_CREDENTIALS = 1u << 0,
    KERNEL_SOCKET_OPTION_EFFECT_IP_TRANSPORT = 1u << 1,
} kernel_socket_option_effect_t;

typedef struct kernel_socket_peer_credentials {
    int32_t process_id;
    uint32_t user_id;
    uint32_t group_id;
} kernel_socket_peer_credentials_t;

struct edge_linux_packet_page_allocator;

typedef struct kernel_socket_option_runtime_view {
    kernel_socket_option_state_t *state;
    int32_t *bound_interface;
    int32_t *pending_error;
    struct edge_linux_sock_filter *filter;
    uint16_t *filter_length;
    int32_t *bpf_filter_object_id;
    void *context;
    void (*apply_effects)(void *context, uint32_t effects);
    void (*prepare_error_take)(void *context);
    int (*peer_credentials)(
        void *context, kernel_socket_peer_credentials_t *credentials);
    int64_t (*peer_pidfd)(void *context);
    int (*peer_group_count)(void *context, uint32_t *count);
    int (*peer_group)(void *context, uint32_t index, uint32_t *group_id);
    uint32_t domain;
    uint32_t type;
    uint32_t protocol;
    uint32_t network_namespace;
    uint32_t transport_mtu;
    uint32_t *netlink_groups;
    int32_t packet_handle;
    const struct edge_linux_packet_page_allocator *packet_page_allocator;
} kernel_socket_option_runtime_view_t;

void kernel_socket_option_state_initialize(
    kernel_socket_option_state_t *state, uint32_t buffer_capacity);
int kernel_socket_option_state_set_integer(
    kernel_socket_option_state_t *state, kernel_socket_option_id_t option,
    int64_t value, uint32_t *effects);
int kernel_socket_option_state_get_integer(
    const kernel_socket_option_state_t *state,
    kernel_socket_option_id_t option, int64_t *value);
int kernel_socket_bound_device_parse(
    const char *name, uint32_t length, int32_t *interface_index);
int kernel_socket_bound_device_format(
    int32_t interface_index, char *name, uint32_t capacity,
    uint32_t *length);
int kernel_socket_error_take(int32_t *stored_error, int32_t *error);
int32_t kernel_socket_mtu_normalize(uint32_t transport_mtu);
int kernel_socket_udp_local_refusal_policy(
    int connected, uint16_t destination_port,
    int destination_is_loopback, int destination_is_bound);
int kernel_socket_udp_local_delivery_match(
    uint32_t sender_namespace, uint32_t receiver_namespace,
    uint16_t destination_port, uint16_t receiver_port,
    const uint8_t *destination_address,
    const uint8_t *receiver_address, uint32_t address_length,
    int receiver_address_is_any);
int edge_socket_runtime_option_view(
    int32_t descriptor, kernel_socket_option_runtime_view_t *view);

/*
 * Linux-visible argument validation belongs to the shared syscall core.
 * Runtime implementations receive normalized domain, type, protocol, and
 * descriptor flags and provide only descriptor-table and transport mechanics.
 */
int64_t kernel_socket_create_descriptor(uint32_t domain, uint32_t type,
                                        uint32_t protocol, uint32_t flags);
int64_t arch_socket_create_descriptor(uint32_t domain, uint32_t type,
                                      uint32_t protocol, uint32_t flags);
/*
 * socketpair(2) exposes its reserved descriptor numbers before family,
 * protocol, and base-type validation.  Keep reservation and construction
 * separate so the shared syscall core can preserve that Linux-visible order.
 * A successful prepare owns two empty RESERVED slots through publication.
 * Construct fills those slots but leaves them invisible until commit.
 */
int kernel_socket_create_unix_pair_prepare(
    int32_t descriptors[2], kernel_fd_publication_t *publication);
int kernel_socket_create_unix_pair_construct(
    uint32_t type, uint32_t flags, const int32_t descriptors[2],
    const kernel_fd_publication_t *publication);
int arch_socket_create_unix_pair_prepare(
    int32_t descriptors[2], kernel_fd_publication_t *publication);
int arch_socket_create_unix_pair_construct(
    uint32_t type, uint32_t flags, const int32_t descriptors[2],
    const kernel_fd_publication_t *publication);
int kernel_socket_describe_descriptor(
    int32_t descriptor, kernel_socket_descriptor_info_t *info);
int64_t kernel_socket_listen_descriptor(int32_t descriptor, int32_t backlog);
int64_t kernel_socket_shutdown_descriptor(int32_t descriptor, int32_t how);
int64_t kernel_socket_bind_descriptor(
    int32_t descriptor, const kernel_socket_address_t *address);

typedef struct kernel_socket_netlink_endpoint {
    uint32_t protocol;
    uint32_t port_id;
    uint32_t groups;
    uint32_t network_namespace;
    int32_t identity;
    uint8_t active;
    uint8_t reserved[3];
} kernel_socket_netlink_endpoint_t;

typedef struct kernel_socket_netlink_source {
    uint32_t port_id;
    uint32_t groups;
    int32_t process_id;
    uint32_t user_id;
    uint32_t group_id;
    uint32_t network_namespace;
    uint16_t message_type;
    uint8_t kernel_originated;
    uint8_t reserved;
    int32_t endpoint_identity;
    uintptr_t backend_cookie;
} kernel_socket_netlink_source_t;

int kernel_socket_broadcast_netlink_datagram(
    uint32_t protocol, uint32_t destination_groups,
    const void *payload, uint32_t length);
int kernel_socket_broadcast_netlink_event(
    uint32_t network_namespace, uint32_t protocol,
    uint32_t destination_groups, uint16_t message_type,
    const void *payload, uint32_t length);
int kernel_socket_netlink_deliver_datagram(
    int32_t descriptor, uint32_t protocol, uint32_t destination_port,
    uint32_t destination_groups, const void *payload, uint32_t length);
uint32_t arch_socket_netlink_payload_capacity(void);
uint32_t arch_socket_netlink_endpoint_count(void);
int arch_socket_netlink_endpoint_view(
    uint32_t index, kernel_socket_netlink_endpoint_t *endpoint);
int arch_socket_netlink_sender_inspect(
    int32_t descriptor, uint32_t protocol,
    kernel_socket_netlink_source_t *source);
int arch_socket_netlink_sender_bind(
    kernel_socket_netlink_source_t *source);
int arch_socket_netlink_enqueue(
    uint32_t index, const void *payload, uint32_t length,
    const kernel_socket_netlink_source_t *source);
int kernel_socket_netlink_membership_update(
    int32_t descriptor, uint32_t group, int join);
int kernel_socket_netlink_memberships_get(
    int32_t descriptor, uint32_t *groups);
int64_t kernel_socket_connect_descriptor(
    int32_t descriptor, const kernel_socket_address_t *address,
    void *user_registers);
int kernel_socket_name_descriptor(
    int32_t descriptor, int peer, kernel_socket_address_t *address);
int kernel_socket_accept_prepare(
    int32_t descriptor, uint32_t flags, kernel_socket_address_t *address,
    uint64_t deferred_user_address, uint64_t deferred_user_length,
    void *user_registers, int32_t *accepted_descriptor,
    kernel_fd_publication_t *publication);
int arch_socket_accept_prepare(
    int32_t descriptor, uint32_t flags, kernel_socket_address_t *address,
    uint64_t deferred_user_address, uint64_t deferred_user_length,
    void *user_registers, int32_t *accepted_descriptor,
    kernel_fd_publication_t *publication);
int64_t kernel_socket_buffer_execute(
    const kernel_socket_buffer_request_t *request);
int64_t arch_socket_buffer_execute(
    const kernel_socket_buffer_request_t *request);
int kernel_socket_option_set_integer(
    int32_t descriptor, kernel_socket_option_id_t option, int64_t value);
int kernel_socket_option_get_integer(
    int32_t descriptor, kernel_socket_option_id_t option, int64_t *value);
int kernel_socket_option_set_icmp6_filter(
    int32_t descriptor,
    const uint32_t filter[KERNEL_SOCKET_ICMP6_FILTER_WORDS]);
int kernel_socket_option_get_icmp6_filter(
    int32_t descriptor,
    uint32_t filter[KERNEL_SOCKET_ICMP6_FILTER_WORDS]);
int kernel_socket_icmp6_filter_allows(
    const kernel_socket_option_state_t *state, uint8_t type);
int kernel_socket_option_set_bound_device(
    int32_t descriptor, const char *name, uint32_t length);
int kernel_socket_option_get_bound_device(
    int32_t descriptor, char *name, uint32_t capacity, uint32_t *length);
int kernel_socket_option_get_peer_credentials(
    int32_t descriptor, kernel_socket_peer_credentials_t *credentials);
int64_t kernel_socket_option_get_peer_pidfd(int32_t descriptor);
int kernel_socket_option_get_peer_group_count(
    int32_t descriptor, uint32_t *count);
int kernel_socket_option_get_peer_group(
    int32_t descriptor, uint32_t index, uint32_t *group_id);
int kernel_socket_option_attach_filter(
    int32_t descriptor, uint64_t user_program, uint32_t program_length,
    void *copy_context, edge_linux_copy_from_user_fn copy_from_user);
int kernel_socket_option_attach_bpf_filter(
    int32_t descriptor, int32_t object_id);
int kernel_socket_option_detach_filter(int32_t descriptor);
int kernel_socket_option_get_filter(
    int32_t descriptor, uint64_t user_program, uint32_t program_capacity,
    void *copy_context, edge_linux_copy_to_user_fn copy_to_user,
    uint32_t *program_length);
int kernel_socket_packet_set_option(
    int32_t descriptor, uint32_t option, const void *value,
    uint32_t value_length);
int kernel_socket_packet_get_option(
    int32_t descriptor, uint32_t option, void *value,
    uint32_t value_capacity, uint32_t *value_length);
int kernel_socket_option_take_error(int32_t descriptor, int32_t *error);
int kernel_socket_option_get_mtu(int32_t descriptor, int32_t *mtu);
int kernel_socket_multicast_membership_update(
    int32_t descriptor, uint32_t domain, const uint8_t *group,
    uint32_t interface_address, uint32_t interface_index, int joining);
int kernel_socket_multicast_interface_set(
    int32_t descriptor, uint32_t domain,
    uint32_t interface_address, uint32_t interface_index);
int kernel_socket_multicast_interface_get(
    int32_t descriptor, uint32_t domain,
    uint32_t *interface_address, uint32_t *interface_index);
int kernel_socket_multicast_state_update(
    kernel_socket_option_state_t *state, uint32_t domain,
    const uint8_t *group, uint32_t interface_address,
    uint32_t interface_index, int joining);
void kernel_socket_multicast_state_release(
    kernel_socket_option_state_t *state);

/*
 * Connection-oriented Unix sockets and reciprocal socketpair endpoints expose
 * peer shutdown when the last reference is released.  A pathname-connected
 * datagram client is not owned by its receiver, so closing that client must not
 * poison the bound socket for later senders.
 */
int kernel_unix_socket_close_notifies_peer(uint32_t type,
                                           int peer_points_back);
int kernel_unix_socket_resolve_path(const char *path, char *resolved,
                                    uint32_t capacity);

#endif
