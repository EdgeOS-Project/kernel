#ifndef EDGEOS_LWIPOPTS_H
#define EDGEOS_LWIPOPTS_H

#define NO_SYS                          1
#define SYS_LIGHTWEIGHT_PROT            0

#define LWIP_SOCKET                     0
#define LWIP_NETCONN                    0
#define LWIP_TCPIP_CORE_LOCKING         0

#define LWIP_IPV4                       1
#define IP_FORWARD                      1
#define ARP_TABLE_SIZE                  128
#define LWIP_IPV6                       1
#define LWIP_ARP                        1
#define ETHARP_SUPPORT_STATIC_ENTRIES   1
#define LWIP_ETHERNET                   1
#define LWIP_ICMP                       1
#define LWIP_ICMP6                      1
#define LWIP_RAW                        1
#define LWIP_UDP                        1
#define LWIP_TCP                        1
#define LWIP_TCP_KEEPALIVE              1
#define LWIP_DNS                        1
#define DNS_MAX_SERVERS                 4
#define LWIP_IGMP                       1
#define LWIP_IPV6_MLD                   1
#define LWIP_IPV6_AUTOCONFIG            1
#define LWIP_IPV6_FORWARD               1
#define LWIP_ND6_ALLOW_RA_UPDATES       1
#define LWIP_IPV6_DUP_DETECT_ATTEMPTS   1
#define LWIP_IPV6_NUM_ADDRESSES         16
#define LWIP_IPV6_ADDRESS_LIFETIMES     1
#define LWIP_IPV6_SCOPES                1
#define LWIP_ND6_NUM_NEIGHBORS          64
#define LWIP_ND6_NUM_DESTINATIONS       64
#define LWIP_ND6_NUM_PREFIXES           16
#define LWIP_ND6_NUM_ROUTERS            8
#define LWIP_ND6_QUEUEING                1
#define LWIP_ND6_RDNSS_MAX_DNS_SERVERS  DNS_MAX_SERVERS
#define MEMP_NUM_ND6_QUEUE              64
/* x86_64 pointers don't fit in the IPv6 fragment header helper overlay. */
#define IPV6_FRAG_COPYHEADER            1

#define LWIP_STATS                      1
#define LWIP_STATS_LARGE                1
#define LWIP_NETIF_STATUS_CALLBACK      0
#define LWIP_NETIF_LINK_CALLBACK        0
#define LWIP_NETIF_HOSTNAME             1
#define LWIP_SINGLE_NETIF               0
#define LWIP_HAVE_LOOPIF                1
#define LWIP_NETIF_LOOPBACK             1
#define LWIP_LOOPBACK_MAX_PBUFS         512
#define LWIP_HOOK_FILENAME              "net/lwip_hooks.h"
#include "net/lwip_hooks.h"

#define LWIP_NETIF_TX_SINGLE_PBUF       1
#define ETH_PAD_SIZE                    0
#define LWIP_CHKSUM_ALGORITHM           3
#define LWIP_NO_INTTYPES_H              1
#define LWIP_NO_CTYPE_H                 1
#define LWIP_RAND()                     ((u32_t)sys_now())

#define MEM_ALIGNMENT                   8
/*
 * lwIP defaults these pools for a tiny single-purpose appliance.  EdgeOS can
 * run a complete Linux desktop where system services, package managers, and
 * interactive applications hold sockets concurrently.  Keep the protocol
 * pools large enough that one service cannot exhaust a protocol globally.
 */
#define MEM_SIZE                        (8 * 1024 * 1024)
#define MEMP_NUM_PBUF                   1024
#define MEMP_NUM_UDP_PCB                128
#define MEMP_NUM_TCP_PCB                256
#define MEMP_NUM_TCP_PCB_LISTEN         64
#define MEMP_NUM_TCP_SEG                1024
#define MEMP_NUM_RAW_PCB                64
#define MEMP_NUM_IGMP_GROUP             128
#define MEMP_NUM_MLD6_GROUP             128
#define PBUF_POOL_SIZE                  1024
#define PBUF_POOL_BUFSIZE               1600

/*
 * The upstream lwIP defaults are intentionally conservative for tiny embedded
 * targets: TCP_MSS=536 and TCP_WND=4*MSS advertise only about 2 KiB of receive
 * window.  That is far below Linux desktop/server behavior and makes normal
 * Alpine HTTPS downloads crawl or time out behind QEMU user networking.
 *
 * EdgeOS targets Linux-compatible userspace, so use Ethernet MTU-sized TCP
 * segments and a nearly 128 KiB receive window.  Window scaling keeps sustained
 * transfers responsive when a desktop workload has several active streams.
 * A 32 KiB send buffer also caps a single connection at roughly 25-30 Mbps
 * when the single-core guest takes several milliseconds to poll an ACK.  Use
 * a 128 KiB send buffer so the transport can keep a full receive window in
 * flight without depending on architecture-specific polling speed.
 */
#define TCP_MSS                         1460
#define LWIP_WND_SCALE                  1
#define TCP_RCV_SCALE                   1
#define TCP_WND                         (2 * 65535)
#define TCP_SND_BUF                     (128 * 1024)
#define TCP_SND_QUEUELEN                512
#define TCP_SNDLOWAT                    (16 * 1024)
#define TCP_SNDQUEUELOWAT               64

#define IP_REASSEMBLY                   1
#define IP_FRAG                         1
#define IP_REASS_MAX_PBUFS              64
#define LWIP_ARP_QUEUEING               1

#define LWIP_TIMEVAL_PRIVATE            0

#define LWIP_DBG_MIN_LEVEL              LWIP_DBG_LEVEL_OFF
#define LWIP_DBG_TYPES_ON               0

#endif
