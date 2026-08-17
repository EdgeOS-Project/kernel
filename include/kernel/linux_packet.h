/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux packet-socket implementation.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_LINUX_PACKET_H
#define EDGEOS_KERNEL_LINUX_PACKET_H

#include <stdint.h>

#include "kernel/linux_abi.h"

#define EDGE_LINUX_PACKET_FILTER_MAX 256u

struct edge_linux_packet_page_allocator {
    int (*allocate)(void *context, void **kernel_address,
                    uint64_t *mapping_cookie);
    void (*release)(void *context, void *kernel_address,
                    uint64_t mapping_cookie);
    void *context;
};

int edge_linux_packet_socket_create(uint32_t socket_type,
                                    uint16_t protocol);
void edge_linux_packet_socket_release(int handle);
int edge_linux_packet_socket_bind(int handle, uint32_t network_namespace,
                                  int32_t ifindex, uint16_t protocol);
int edge_linux_packet_transmit_frame(uint32_t network_namespace,
                                     int32_t ifindex, const uint8_t *frame,
                                     uint32_t length);

int edge_linux_packet_setsockopt(
    int handle, uint32_t option, const void *value, uint32_t value_length,
    const struct edge_linux_packet_page_allocator *allocator);
int edge_linux_packet_getsockopt(int handle, uint32_t option, void *value,
                                 uint32_t value_capacity,
                                 uint32_t *value_length);

int edge_linux_packet_attach_filter(
    int handle, const struct edge_linux_sock_filter *program,
    uint32_t program_length);
int edge_linux_packet_detach_filter(int handle);
int edge_linux_bpf_validate(const struct edge_linux_sock_filter *program,
                            uint32_t program_length);
typedef int (*edge_linux_bpf_load_fn)(void *context, uint32_t offset,
                                      uint32_t size, uint32_t *value);
uint32_t edge_linux_bpf_run_reader(
    const struct edge_linux_sock_filter *program, uint32_t program_length,
    uint32_t packet_length, edge_linux_bpf_load_fn load, void *context);
uint32_t edge_linux_bpf_run(const struct edge_linux_sock_filter *program,
                            uint32_t program_length, const uint8_t *packet,
                            uint32_t packet_length);

int edge_linux_packet_ring_mmap_info(int handle, uint64_t offset,
                                     uint64_t length,
                                     uint32_t *page_count);
int edge_linux_packet_ring_page(int handle, uint32_t page_index,
                                void **kernel_address,
                                uint64_t *mapping_cookie);
int edge_linux_packet_ring_ready(int handle);
uint64_t edge_linux_packet_readiness_sequence(void);
/*
 * Returns zero for an invalid handle and a nonzero capture generation
 * otherwise.
 */
uint64_t edge_linux_packet_ring_readiness_sequence(int handle);

void edge_linux_packet_capture_rx(const uint8_t *frame, uint32_t length,
                                  int32_t ifindex);
void edge_linux_packet_capture_tx(const uint8_t *frame, uint32_t length,
                                  int32_t ifindex);

#endif
