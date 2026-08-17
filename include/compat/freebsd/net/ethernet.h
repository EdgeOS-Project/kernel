/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef _NET_ETHERNET_H_
#define _NET_ETHERNET_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "if_var.h"

#define ETHER_ADDR_LEN 6
#define ETHER_TYPE_LEN 2
#define ETHER_HDR_LEN 14
#define ETHER_CRC_LEN 4
#define ETHER_VLAN_ENCAP_LEN 4
#define ETHER_ALIGN 2
#define ETHER_MAX_LEN 1518
#define ETHER_MIN_LEN 64
#define ETHER_MAX_LEN_JUMBO 9018
#define ETHERMTU (ETHER_MAX_LEN - ETHER_HDR_LEN - ETHER_CRC_LEN)
#define ETHERMIN (ETHER_MIN_LEN - ETHER_HDR_LEN - ETHER_CRC_LEN)
#define ETHERMTU_JUMBO (ETHER_MAX_LEN_JUMBO - ETHER_HDR_LEN - ETHER_CRC_LEN)
#define EVL_VLID_MASK 0x0fff
#define EVL_VLANOFTAG(tag) ((tag) & EVL_VLID_MASK)
#define EVL_PRIOFTAG(tag) (((tag) >> 13) & 7)
#define EVL_CFIOFTAG(tag) (((tag) >> 12) & 1)
#define EVL_MAKETAG(vlid, priority, cfi) \
    ((((((priority) & 7) << 1) | ((cfi) & 1)) << 12) | \
        ((vlid) & EVL_VLID_MASK))

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_AARP 0x80f3
#define ETHERTYPE_IPX 0x8137
#define ETHERTYPE_PAE 0x888e
#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_IPV6 0x86dd
#define ETHERTYPE_MAX 0xffff

#define ETHER_MAX_FRAME(ifp, etype, hasfcs) \
    (if_getmtu((ifp)) + ETHER_HDR_LEN + \
     ((hasfcs) ? ETHER_CRC_LEN : 0) + \
     (((etype) == ETHERTYPE_VLAN) ? ETHER_VLAN_ENCAP_LEN : 0))

#define ETHER_IS_MULTICAST(address) (((const uint8_t *)(address))[0] & 1u)
#define ETHER_IS_BROADCAST(address) \
    (((const uint8_t *)(address))[0] == 0xffu && \
     ((const uint8_t *)(address))[1] == 0xffu && \
     ((const uint8_t *)(address))[2] == 0xffu && \
     ((const uint8_t *)(address))[3] == 0xffu && \
     ((const uint8_t *)(address))[4] == 0xffu && \
     ((const uint8_t *)(address))[5] == 0xffu)
#define ETHER_IS_ZERO(address) \
    ((((const uint8_t *)(address))[0] | \
      ((const uint8_t *)(address))[1] | \
      ((const uint8_t *)(address))[2] | \
      ((const uint8_t *)(address))[3] | \
      ((const uint8_t *)(address))[4] | \
      ((const uint8_t *)(address))[5]) == 0)

struct ether_addr {
    uint8_t octet[ETHER_ADDR_LEN];
};

struct ether_header {
    uint8_t ether_dhost[ETHER_ADDR_LEN];
    uint8_t ether_shost[ETHER_ADDR_LEN];
    uint16_t ether_type;
} __attribute__((packed));

struct ether_vlan_header {
    uint8_t evl_dhost[ETHER_ADDR_LEN];
    uint8_t evl_shost[ETHER_ADDR_LEN];
    uint16_t evl_encap_proto;
    uint16_t evl_tag;
    uint16_t evl_proto;
} __attribute__((packed));

struct mbuf;

void ether_ifattach(if_t ifp, const uint8_t *address);
void ether_ifdetach(if_t ifp);
void ether_gen_addr(if_t ifp, struct ether_addr *address);
void ether_gen_addr_byname(const char *name, struct ether_addr *address);
int ether_ioctl(if_t ifp, unsigned long command, char *data);
struct mbuf *ether_vlanencap(struct mbuf *mbuf, uint16_t tag);
const char *ether_sprintf(const uint8_t *address);
uint32_t ether_crc32_be(const uint8_t *buffer, size_t length);
uint32_t ether_crc32_le(const uint8_t *buffer, size_t length);
void ether_bpf_mtap_if(if_t ifp, struct mbuf *mbuf);

#define ETHER_BPF_MTAP(ifp, mbuf) ether_bpf_mtap_if((ifp), (mbuf))

#endif
