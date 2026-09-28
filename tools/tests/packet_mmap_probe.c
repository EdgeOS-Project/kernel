/* SPDX-License-Identifier: MPL-2.0 */
/* Exercise the Linux AF_PACKET TPACKET_V2 receive-ring ABI. */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#define PROBE_BLOCK_SIZE 4096u
#define PROBE_BLOCK_COUNT 2u
#define PROBE_FRAME_SIZE 2048u
#define PROBE_TIMEOUT_MS 5000

static int generate_udp_traffic(const char *interface_name) {
    static const char payload[] = "edgeos-packet-ring-probe";
    struct sockaddr_in destination;
    int fd;
    ssize_t sent;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    memset(&destination, 0, sizeof(destination));
    destination.sin_family = AF_INET;
    destination.sin_port = htons(53);
    if (inet_pton(AF_INET,
                  strcmp(interface_name, "lo") == 0 ? "127.0.0.1" :
                                                       "10.0.2.2",
                  &destination.sin_addr) != 1) {
        close(fd);
        errno = EINVAL;
        return -1;
    }
    sent = sendto(fd, payload, sizeof(payload), 0,
                  (const struct sockaddr *)&destination,
                  sizeof(destination));
    close(fd);
    return sent == (ssize_t)sizeof(payload) ? 0 : -1;
}

int main(int argc, char **argv) {
    const char *interface_name = argc > 1 ? argv[1] : "eth0";
    struct sock_filter accept_all[] = {
        BPF_STMT(BPF_RET | BPF_K, UINT32_MAX),
    };
    struct sock_fprog filter = {
        .len = (unsigned short)(sizeof(accept_all) / sizeof(accept_all[0])),
        .filter = accept_all,
    };
    struct sockaddr_ll address;
    struct tpacket_req request;
    struct tpacket_stats statistics;
    struct pollfd poll_fd;
    unsigned int interface_index;
    size_t ring_length;
    uint8_t *ring;
    int version = TPACKET_V2;
    int reserve = 32;
    int fd = -1;
    int result = 1;
    int captured = 0;
    socklen_t statistics_length = sizeof(statistics);

    interface_index = if_nametoindex(interface_name);
    if (!interface_index) {
        fprintf(stderr, "if_nametoindex(%s): %s\n", interface_name,
                strerror(errno));
        return 1;
    }
    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        perror("socket(AF_PACKET)");
        return 1;
    }
    memset(&address, 0, sizeof(address));
    address.sll_family = AF_PACKET;
    address.sll_protocol = htons(ETH_P_ALL);
    address.sll_ifindex = (int)interface_index;
    if (bind(fd, (const struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind(AF_PACKET)");
        goto out;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &filter,
                   sizeof(filter)) < 0) {
        perror("setsockopt(SO_ATTACH_FILTER)");
        goto out;
    }
    if (setsockopt(fd, SOL_PACKET, PACKET_VERSION, &version,
                   sizeof(version)) < 0) {
        perror("setsockopt(PACKET_VERSION)");
        goto out;
    }
    if (setsockopt(fd, SOL_PACKET, PACKET_RESERVE, &reserve,
                   sizeof(reserve)) < 0) {
        perror("setsockopt(PACKET_RESERVE)");
        goto out;
    }

    memset(&request, 0, sizeof(request));
    request.tp_block_size = PROBE_BLOCK_SIZE;
    request.tp_block_nr = PROBE_BLOCK_COUNT;
    request.tp_frame_size = PROBE_FRAME_SIZE;
    request.tp_frame_nr =
        request.tp_block_nr * (request.tp_block_size / request.tp_frame_size);
    if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &request,
                   sizeof(request)) < 0) {
        perror("setsockopt(PACKET_RX_RING)");
        goto out;
    }

    ring_length = (size_t)request.tp_block_size * request.tp_block_nr;
    ring = mmap(NULL, ring_length, PROT_READ | PROT_WRITE, MAP_SHARED,
                fd, 0);
    if (ring == MAP_FAILED) {
        perror("mmap(PACKET_RX_RING)");
        goto disable_ring;
    }
    if (generate_udp_traffic(interface_name) < 0) {
        perror("generate UDP traffic");
        goto unmap;
    }

    poll_fd.fd = fd;
    poll_fd.events = POLLIN;
    poll_fd.revents = 0;
    if (poll(&poll_fd, 1, PROBE_TIMEOUT_MS) <= 0 ||
        !(poll_fd.revents & POLLIN)) {
        fprintf(stderr, "poll(PACKET_RX_RING): timeout or invalid events "
                        "revents=0x%x errno=%d\n",
                poll_fd.revents, errno);
        goto unmap;
    }
    for (unsigned int frame = 0; frame < request.tp_frame_nr; ++frame) {
        unsigned int frames_per_block =
            request.tp_block_size / request.tp_frame_size;
        size_t offset =
            (size_t)(frame / frames_per_block) * request.tp_block_size +
            (size_t)(frame % frames_per_block) * request.tp_frame_size;
        struct tpacket2_hdr *header =
            (struct tpacket2_hdr *)(ring + offset);

        if (!(header->tp_status & TP_STATUS_USER)) continue;
        if (!header->tp_snaplen || header->tp_snaplen > header->tp_len ||
            header->tp_mac >= request.tp_frame_size ||
            header->tp_snaplen > request.tp_frame_size - header->tp_mac) {
            fprintf(stderr,
                    "invalid packet metadata status=0x%x len=%u snaplen=%u "
                    "mac=%u\n",
                    header->tp_status, header->tp_len, header->tp_snaplen,
                    header->tp_mac);
            goto unmap;
        }
        printf("frame=%u status=0x%x len=%u snaplen=%u mac=%u net=%u "
               "timestamp=%u.%09u\n",
               frame, header->tp_status, header->tp_len,
               header->tp_snaplen, header->tp_mac, header->tp_net,
               header->tp_sec, header->tp_nsec);
        header->tp_status = TP_STATUS_KERNEL;
        captured = 1;
        break;
    }
    if (!captured) {
        fputs("poll woke without a user-owned packet frame\n", stderr);
        goto unmap;
    }

    memset(&statistics, 0, sizeof(statistics));
    if (getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &statistics,
                   &statistics_length) < 0) {
        perror("getsockopt(PACKET_STATISTICS)");
        goto unmap;
    }
    if (statistics_length != sizeof(statistics) ||
        !statistics.tp_packets || statistics.tp_drops) {
        fprintf(stderr, "invalid packet statistics len=%u packets=%u "
                        "drops=%u\n",
                (unsigned int)statistics_length, statistics.tp_packets,
                statistics.tp_drops);
        goto unmap;
    }
    printf("packets=%u drops=%u\n", statistics.tp_packets,
           statistics.tp_drops);
    puts("PACKET_MMAP_PROBE_PASS");
    result = 0;

unmap:
    munmap(ring, ring_length);
disable_ring:
    memset(&request, 0, sizeof(request));
    (void)setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &request,
                     sizeof(request));
out:
    close(fd);
    return result;
}
