/* SPDX-License-Identifier: BSD-3-Clause */
/* FreeBSD-compatible interface metadata for imported drivers. */

#ifndef _NET_IF_H_
#define _NET_IF_H_

#include <stddef.h>
#include <stdint.h>
#include <sys/ioccom.h>
#include <sys/socket.h>

#define IFNAMSIZ 16
#define IFQ_MAXLEN 50

#define IFF_UP 0x00000001
#define IFF_BROADCAST 0x00000002
#define IFF_DEBUG 0x00000004
#define IFF_POINTOPOINT 0x00000010
#define IFF_DRV_RUNNING 0x00000040
#define IFF_NOARP 0x00000080
#define IFF_PROMISC 0x00000100
#define IFF_ALLMULTI 0x00000200
#define IFF_DRV_OACTIVE 0x00000400
#define IFF_SIMPLEX 0x00000800
#define IFF_LINK0 0x00001000
#define IFF_MULTICAST 0x00008000
#define IFF_PPROMISC 0x00020000
#define IFF_MONITOR 0x00040000

#define LINK_STATE_UNKNOWN 0
#define LINK_STATE_DOWN 1
#define LINK_STATE_UP 2

#define IF_Kbps(value) ((uint64_t)(value) * 1000u)
#define IF_Mbps(value) (IF_Kbps((value) * 1000u))
#define IF_Gbps(value) (IF_Mbps((value) * 1000u))

#define IFCAP_RXCSUM (1u << 0)
#define IFCAP_TXCSUM (1u << 1)
#define IFCAP_VLAN_MTU (1u << 3)
#define IFCAP_VLAN_HWTAGGING (1u << 4)
#define IFCAP_JUMBO_MTU (1u << 5)
#define IFCAP_VLAN_HWCSUM (1u << 7)
#define IFCAP_TSO4 (1u << 8)
#define IFCAP_TSO6 (1u << 9)
#define IFCAP_LRO (1u << 10)
#define IFCAP_VLAN_HWFILTER (1u << 16)
#define IFCAP_VLAN_HWTSO (1u << 18)
#define IFCAP_LINKSTATE (1u << 19)
#define IFCAP_RXCSUM_IPV6 (1u << 21)
#define IFCAP_TXCSUM_IPV6 (1u << 22)
#define IFCAP_HWSTATS (1u << 23)
#define IFCAP_WOL_UCAST (1u << 24)
#define IFCAP_WOL_MCAST (1u << 25)
#define IFCAP_WOL_MAGIC (1u << 26)
#define IFCAP_MEXTPG (1u << 27)
#define IFCAP_HWCSUM (IFCAP_RXCSUM | IFCAP_TXCSUM)
#define IFCAP_HWCSUM_IPV6 (IFCAP_RXCSUM_IPV6 | IFCAP_TXCSUM_IPV6)
#define IFCAP_TSO (IFCAP_TSO4 | IFCAP_TSO6)
#define IFCAP_WOL (IFCAP_WOL_UCAST | IFCAP_WOL_MCAST | IFCAP_WOL_MAGIC)

struct ifnet;
typedef struct ifnet *if_t;

struct if_data {
    uint8_t ifi_type;
    uint8_t ifi_physical;
    uint8_t ifi_addrlen;
    uint8_t ifi_hdrlen;
    uint8_t ifi_link_state;
    uint8_t ifi_vhid;
    uint16_t ifi_datalen;
    uint32_t ifi_mtu;
    uint32_t ifi_metric;
    uint64_t ifi_baudrate;
    uint64_t ifi_ipackets;
    uint64_t ifi_ierrors;
    uint64_t ifi_opackets;
    uint64_t ifi_oerrors;
    uint64_t ifi_collisions;
    uint64_t ifi_ibytes;
    uint64_t ifi_obytes;
    uint64_t ifi_imcasts;
    uint64_t ifi_omcasts;
    uint64_t ifi_iqdrops;
    uint64_t ifi_oqdrops;
    uint64_t ifi_noproto;
    uint64_t ifi_hwassist;
    union {
        int64_t tt;
        uint64_t ph;
    } __ifi_epoch;
    union {
        struct {
            int64_t tv_sec;
            int64_t tv_usec;
        } tv;
        struct {
            uint64_t ph1;
            uint64_t ph2;
        } ph;
    } __ifi_lastchange;
};

#define ifi_epoch __ifi_epoch.tt
#define ifi_lastchange __ifi_lastchange.tv

struct ifreq {
    char ifr_name[IFNAMSIZ];
    union {
        struct sockaddr ifru_addr;
        short ifru_flags[2];
        int ifru_mtu;
        int ifru_reqcap;
        int ifru_media;
        void *ifru_data;
    } ifr_ifru;
};

#define ifr_mtu ifr_ifru.ifru_mtu
#define ifr_flags ifr_ifru.ifru_flags[0]
#define ifr_flagshigh ifr_ifru.ifru_flags[1]
#define ifr_addr ifr_ifru.ifru_addr
#define ifr_reqcap ifr_ifru.ifru_reqcap
#define ifr_media ifr_ifru.ifru_media
#define ifr_data ifr_ifru.ifru_data

static inline void *
ifr_data_get_ptr(struct ifreq *request)
{
    return request ? request->ifr_data : 0;
}

struct ifmediareq {
    char ifm_name[IFNAMSIZ];
    int ifm_current;
    int ifm_mask;
    int ifm_status;
    int ifm_active;
    int ifm_count;
    int *ifm_ulist;
};

struct ifdrv {
    char ifd_name[IFNAMSIZ];
    unsigned long ifd_cmd;
    size_t ifd_len;
    void *ifd_data;
};

#define IFDR_MSG_SIZE 64
#define IFDR_REASON_MSG 1
#define IFDR_REASON_VENDOR 2

struct ifi2creq {
    uint8_t dev_addr;
    uint8_t offset;
    uint8_t len;
    uint8_t page;
    uint8_t bank;
    uint8_t spare[3];
    uint8_t data[8];
};

struct ifdownreason {
    char ifdr_name[IFNAMSIZ];
    uint32_t ifdr_reason;
    uint32_t ifdr_vendor;
    char ifdr_msg[IFDR_MSG_SIZE];
};

#define RSS_FUNC_NONE 0
#define RSS_FUNC_PRIVATE 1
#define RSS_FUNC_TOEPLITZ 2

#define RSS_TYPE_IPV4 0x00000001u
#define RSS_TYPE_TCP_IPV4 0x00000002u
#define RSS_TYPE_IPV6 0x00000004u
#define RSS_TYPE_IPV6_EX 0x00000008u
#define RSS_TYPE_TCP_IPV6 0x00000010u
#define RSS_TYPE_TCP_IPV6_EX 0x00000020u
#define RSS_TYPE_UDP_IPV4 0x00000040u
#define RSS_TYPE_UDP_IPV6 0x00000080u
#define RSS_TYPE_UDP_IPV6_EX 0x00000100u

#define RSS_KEYLEN 128

struct ifrsskey {
    char ifrk_name[IFNAMSIZ];
    uint8_t ifrk_func;
    uint8_t ifrk_spare0;
    uint16_t ifrk_keylen;
    uint8_t ifrk_key[RSS_KEYLEN];
};

struct ifrsshash {
    char ifrh_name[IFNAMSIZ];
    uint8_t ifrh_func;
    uint8_t ifrh_spare0;
    uint16_t ifrh_spare1;
    uint32_t ifrh_types;
};

#endif
