/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux netlink policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>
#include <string.h>

#include "kernel/linux_abi.h"
#include "kernel/linux_errno.h"
#include "kernel/linux_netlink.h"
#include "kernel/namespace_runtime.h"
#include "net/network_core.h"
#include "kernel/socket_runtime.h"

#define EDGE_NFNL_SUBSYS_CTNETLINK 1u
#define EDGE_NFNL_SUBSYS_NFTABLES 10u
#define EDGE_NFNL_SUBSYS_NFT_COMPAT 11u
#define EDGE_NFNL_MSG_BATCH_BEGIN 0x10u
#define EDGE_NFNL_MSG_BATCH_END 0x11u
#define EDGE_IPCTNL_MSG_CT_GET 1u
#define EDGE_IPCTNL_MSG_CT_DELETE 2u
#define EDGE_NFT_MSG_NEWTABLE 0u
#define EDGE_NFT_MSG_GETTABLE 1u
#define EDGE_NFT_MSG_DELTABLE 2u
#define EDGE_NFT_MSG_NEWCHAIN 3u
#define EDGE_NFT_MSG_GETCHAIN 4u
#define EDGE_NFT_MSG_DELCHAIN 5u
#define EDGE_NFT_MSG_NEWRULE 6u
#define EDGE_NFT_MSG_GETRULE 7u
#define EDGE_NFT_MSG_DELRULE 8u
#define EDGE_NFT_MSG_GETSET 10u
#define EDGE_NFT_MSG_GETSETELEM 13u
#define EDGE_NFT_MSG_NEWGEN 15u
#define EDGE_NFT_MSG_GETGEN 16u
#define EDGE_NFT_MSG_GETOBJ 19u
#define EDGE_NFT_MSG_GETFLOWTABLE 23u
#define EDGE_NFT_MSG_DESTROYTABLE 26u
#define EDGE_NFT_MSG_DESTROYCHAIN 27u
#define EDGE_NLMSG_DONE 3u
#define EDGE_NLMSG_ERROR 2u
#define EDGE_NLM_F_MULTI 0x0002u
#define EDGE_NLM_F_REPLACE 0x0100u
#define EDGE_NLM_F_EXCL 0x0200u
#define EDGE_NLM_F_CREATE 0x0400u
#define EDGE_NLM_F_DUMP 0x0300u
#define EDGE_NLA_F_NESTED 0x8000u
#define EDGE_NLA_TYPE_MASK 0x3fffu
#define EDGE_NFTA_TABLE_NAME 1u
#define EDGE_NFTA_TABLE_FLAGS 2u
#define EDGE_NFTA_TABLE_USE 3u
#define EDGE_NFTA_TABLE_HANDLE 4u
#define EDGE_NFTA_CHAIN_TABLE 1u
#define EDGE_NFTA_CHAIN_HANDLE 2u
#define EDGE_NFTA_CHAIN_NAME 3u
#define EDGE_NFTA_CHAIN_HOOK 4u
#define EDGE_NFTA_CHAIN_POLICY 5u
#define EDGE_NFTA_CHAIN_TYPE 7u
#define EDGE_NFTA_CHAIN_FLAGS 10u
#define EDGE_NFTA_RULE_TABLE 1u
#define EDGE_NFTA_RULE_CHAIN 2u
#define EDGE_NFTA_RULE_HANDLE 3u
#define EDGE_NFTA_RULE_EXPRESSIONS 4u
#define EDGE_NFTA_GEN_ID 1u
#define EDGE_NFTA_COMPAT_NAME 1u
#define EDGE_NFTA_COMPAT_REVISION 2u
#define EDGE_NFTA_COMPAT_TYPE 3u
#define EDGE_NETFILTER_TABLE_MAX 32u
#define EDGE_NETFILTER_CHAIN_MAX 128u
#define EDGE_NETFILTER_RULE_MAX 256u
#define EDGE_NETFILTER_NAME_MAX 256u
#define EDGE_NETFILTER_RULE_DATA_MAX 1024u
#define EDGE_NETFILTER_CONNTRACK_MAX 1024u

#define EDGE_CTA_TUPLE_ORIG 1u
#define EDGE_CTA_TUPLE_REPLY 2u
#define EDGE_CTA_STATUS 3u
#define EDGE_CTA_TIMEOUT 7u
#define EDGE_CTA_ID 12u
#define EDGE_CTA_TUPLE_IP 1u
#define EDGE_CTA_TUPLE_PROTO 2u
#define EDGE_CTA_IP_V4_SRC 1u
#define EDGE_CTA_IP_V4_DST 2u
#define EDGE_CTA_IP_V6_SRC 3u
#define EDGE_CTA_IP_V6_DST 4u
#define EDGE_CTA_PROTO_NUM 1u
#define EDGE_CTA_PROTO_SRC_PORT 2u
#define EDGE_CTA_PROTO_DST_PORT 3u

#define EDGE_NFTA_LIST_ELEM 1u
#define EDGE_NFTA_EXPR_NAME 1u
#define EDGE_NFTA_EXPR_DATA 2u
#define EDGE_NFTA_DATA_VALUE 1u
#define EDGE_NFTA_DATA_VERDICT 2u
#define EDGE_NFTA_VERDICT_CODE 1u
#define EDGE_NFTA_HOOK_HOOKNUM 1u
#define EDGE_NFTA_HOOK_PRIORITY 2u
#define EDGE_NFTA_IMMEDIATE_DREG 1u
#define EDGE_NFTA_IMMEDIATE_DATA 2u
#define EDGE_NFTA_PAYLOAD_DREG 1u
#define EDGE_NFTA_PAYLOAD_BASE 2u
#define EDGE_NFTA_PAYLOAD_OFFSET 3u
#define EDGE_NFTA_PAYLOAD_LEN 4u
#define EDGE_NFTA_CMP_SREG 1u
#define EDGE_NFTA_CMP_OP 2u
#define EDGE_NFTA_CMP_DATA 3u
#define EDGE_NFTA_BITWISE_SREG 1u
#define EDGE_NFTA_BITWISE_DREG 2u
#define EDGE_NFTA_BITWISE_LEN 3u
#define EDGE_NFTA_BITWISE_MASK 4u
#define EDGE_NFTA_BITWISE_XOR 5u
#define EDGE_NFTA_META_DREG 1u
#define EDGE_NFTA_META_KEY 2u
#define EDGE_NFTA_TARGET_NAME 1u
#define EDGE_NFTA_TARGET_REVISION 2u
#define EDGE_NFTA_TARGET_INFO 3u
#define EDGE_NFTA_MATCH_NAME 1u
#define EDGE_NFTA_MATCH_REVISION 2u
#define EDGE_NFTA_MATCH_INFO 3u
#define EDGE_NFTA_NAT_TYPE 1u
#define EDGE_NFTA_NAT_FAMILY 2u
#define EDGE_NFTA_NAT_REG_ADDR_MIN 3u
#define EDGE_NFTA_NAT_REG_PROTO_MIN 5u
#define EDGE_NFTA_MASQ_REG_PROTO_MIN 2u
#define EDGE_NFTA_REDIR_REG_PROTO_MIN 2u
#define EDGE_NFT_PAYLOAD_NETWORK_HEADER 1u
#define EDGE_NFT_PAYLOAD_TRANSPORT_HEADER 2u
#define EDGE_NFT_CMP_EQ 0u
#define EDGE_NFT_CMP_NEQ 1u
#define EDGE_NFT_CMP_LT 2u
#define EDGE_NFT_CMP_LTE 3u
#define EDGE_NFT_CMP_GT 4u
#define EDGE_NFT_CMP_GTE 5u
#define EDGE_NFT_NAT_SNAT 0u
#define EDGE_NFT_NAT_DNAT 1u
#define EDGE_NFT_META_IIF 4u
#define EDGE_NFT_META_OIF 5u
#define EDGE_NFT_META_IIFNAME 6u
#define EDGE_NFT_META_OIFNAME 7u
#define EDGE_NFT_META_NFPROTO 15u
#define EDGE_NFT_META_L4PROTO 16u
#define EDGE_NF_DROP 0u
#define EDGE_NF_ACCEPT 1u
#define EDGE_NFT_VERDICT_NONE UINT32_MAX
#define EDGE_NF_INET_PRE_ROUTING 0u
#define EDGE_NF_INET_LOCAL_IN 1u
#define EDGE_NF_INET_FORWARD 2u
#define EDGE_NF_INET_LOCAL_OUT 3u
#define EDGE_NF_INET_POST_ROUTING 4u
#define EDGE_NF_INET_INGRESS 5u
#define EDGE_NF_NAT_RANGE_MAP_IPS 1u
#define EDGE_NF_NAT_RANGE_PROTO_SPECIFIED 2u
#define EDGE_XT_ADDRTYPE_INVERT_SOURCE 0x0001u
#define EDGE_XT_ADDRTYPE_INVERT_DESTINATION 0x0002u
#define EDGE_XT_ADDRTYPE_LOCAL (1u << 2u)
#define EDGE_XT_CONNTRACK_STATE 0x0001u
#define EDGE_XT_CONNTRACK_STATE_INVALID (1u << 0u)
#define EDGE_XT_CONNTRACK_STATE_ESTABLISHED (1u << 1u)
#define EDGE_XT_CONNTRACK_STATE_RELATED (1u << 2u)
#define EDGE_XT_CONNTRACK_STATE_NEW (1u << 3u)

#define EDGE_RTM_NEWLINK 16u
#define EDGE_RTM_DELLINK 17u
#define EDGE_RTM_GETLINK 18u
#define EDGE_RTM_SETLINK 19u
#define EDGE_RTM_NEWADDR 20u
#define EDGE_RTM_DELADDR 21u
#define EDGE_RTM_GETADDR 22u
#define EDGE_RTM_NEWROUTE 24u
#define EDGE_RTM_DELROUTE 25u
#define EDGE_RTM_GETROUTE 26u
#define EDGE_RTM_NEWNEIGH 28u
#define EDGE_RTM_DELNEIGH 29u
#define EDGE_RTM_GETNEIGH 30u
#define EDGE_RTM_NEWRULE 32u
#define EDGE_RTM_DELRULE 33u
#define EDGE_RTM_GETRULE 34u
#define EDGE_RTM_NEWQDISC 36u
#define EDGE_RTM_DELQDISC 37u
#define EDGE_RTM_GETQDISC 38u
#define EDGE_RTM_NEWMDB 84u
#define EDGE_RTM_DELMDB 85u
#define EDGE_RTM_GETMDB 86u
#define EDGE_RTM_NEWNEXTHOP 104u
#define EDGE_RTM_DELNEXTHOP 105u
#define EDGE_RTM_GETNEXTHOP 106u
#define EDGE_RTNLGRP_LINK (1u << 0u)
#define EDGE_RTNLGRP_NEIGH (1u << 2u)
#define EDGE_RTNLGRP_TC (1u << 3u)
#define EDGE_RTNLGRP_IPV4_IFADDR (1u << 4u)
#define EDGE_RTNLGRP_IPV4_ROUTE (1u << 6u)
#define EDGE_RTNLGRP_IPV4_RULE (1u << 7u)
#define EDGE_RTNLGRP_IPV6_IFADDR (1u << 8u)
#define EDGE_RTNLGRP_IPV6_ROUTE (1u << 10u)
#define EDGE_RTNLGRP_IPV6_RULE (1u << 18u)
#define EDGE_RTNLGRP_MDB (1u << 28u)
#define EDGE_RTNLGRP_NEXTHOP (1u << 29u)
#define EDGE_NLM_F_ACK 0x0004u
#define EDGE_NLM_F_REPLACE 0x0100u
#define EDGE_NLM_F_EXCL 0x0200u
#define EDGE_IFF_UP 0x0001u
#define EDGE_IFF_BROADCAST 0x0002u
#define EDGE_IFF_POINTOPOINT 0x0010u
#define EDGE_IFF_RUNNING 0x0040u
#define EDGE_IFF_NOARP 0x0080u
#define EDGE_IFF_MULTICAST 0x1000u
#define EDGE_IFF_LOWER_UP 0x10000u
#define EDGE_ARPHRD_ETHER 1u
#define EDGE_ARPHRD_NONE 0xfffeu
#define EDGE_AF_INET 2u
#define EDGE_AF_BRIDGE 7u
#define EDGE_AF_INET6 10u
#define EDGE_IFLA_ADDRESS 1u
#define EDGE_IFLA_IFNAME 3u
#define EDGE_IFLA_MTU 4u
#define EDGE_IFLA_LINK 5u
#define EDGE_IFLA_MASTER 10u
#define EDGE_IFLA_PROTINFO 12u
#define EDGE_IFLA_LINKINFO 18u
#define EDGE_IFLA_AF_SPEC 26u
#define EDGE_IFLA_NET_NS_FD 28u
#define EDGE_IFLA_INFO_KIND 1u
#define EDGE_IFLA_INFO_DATA 2u
#define EDGE_IFLA_INFO_SLAVE_KIND 4u
#define EDGE_IFLA_INFO_SLAVE_DATA 5u
#define EDGE_IFLA_BRPORT_STATE 1u
#define EDGE_IFLA_BRPORT_MODE 4u
#define EDGE_IFLA_BRPORT_LEARNING 8u
#define EDGE_IFLA_BRPORT_UNICAST_FLOOD 9u
#define EDGE_IFLA_BRPORT_MCAST_FLOOD 27u
#define EDGE_IFLA_BRPORT_BCAST_FLOOD 30u
#define EDGE_IFLA_BRPORT_ISOLATED 33u
#define EDGE_IFLA_BR_VLAN_FILTERING 7u
#define EDGE_IFLA_BRIDGE_FLAGS 0u
#define EDGE_IFLA_BRIDGE_VLAN_INFO 2u
#define EDGE_BRIDGE_VLAN_INFO_MASTER 0x0001u
#define EDGE_BRIDGE_VLAN_INFO_PVID 0x0002u
#define EDGE_BRIDGE_VLAN_INFO_UNTAGGED 0x0004u
#define EDGE_BRIDGE_VLAN_INFO_RANGE_BEGIN 0x0008u
#define EDGE_BRIDGE_VLAN_INFO_RANGE_END 0x0010u
#define EDGE_VETH_INFO_PEER 1u
#define EDGE_IFLA_VLAN_ID 1u
#define EDGE_IFLA_VLAN_PROTOCOL 5u
#define EDGE_IFLA_MACVLAN_MODE 1u
#define EDGE_IFLA_MACVLAN_FLAGS 2u
#define EDGE_IFLA_IPVLAN_MODE 1u
#define EDGE_IFLA_IPVLAN_FLAGS 2u
#define EDGE_IFLA_BOND_MODE 1u
#define EDGE_IFLA_BOND_XMIT_HASH_POLICY 14u
#define EDGE_IFLA_VRF_TABLE 1u
#define EDGE_IFA_ADDRESS 1u
#define EDGE_IFA_LOCAL 2u
#define EDGE_IFA_BROADCAST 4u
#define EDGE_IFA_CACHEINFO 6u
#define EDGE_IFA_FLAGS 8u
#define EDGE_IFA_F_NOPREFIXROUTE 0x200u
#define EDGE_RTA_DST 1u
#define EDGE_RTA_SRC 2u
#define EDGE_RTA_IIF 3u
#define EDGE_RTA_OIF 4u
#define EDGE_RTA_GATEWAY 5u
#define EDGE_RTA_PRIORITY 6u
#define EDGE_RTA_PREFSRC 7u
#define EDGE_RTA_MULTIPATH 9u
#define EDGE_RTA_TABLE 15u
#define EDGE_RTA_MARK 16u
#define EDGE_RTA_UID 25u
#define EDGE_RTA_NH_ID 30u
#define EDGE_FRA_DST 1u
#define EDGE_FRA_SRC 2u
#define EDGE_FRA_IIFNAME 3u
#define EDGE_FRA_PRIORITY 6u
#define EDGE_FRA_FWMARK 10u
#define EDGE_FRA_TABLE 15u
#define EDGE_FRA_FWMASK 16u
#define EDGE_FRA_OIFNAME 17u
#define EDGE_FRA_UID_RANGE 20u
#define EDGE_NDA_DST 1u
#define EDGE_NDA_LLADDR 2u
#define EDGE_NDA_VLAN 5u
#define EDGE_MDBA_MDB 1u
#define EDGE_MDBA_MDB_ENTRY 1u
#define EDGE_MDBA_MDB_ENTRY_INFO 1u
#define EDGE_MDBA_SET_ENTRY 1u
#define EDGE_NHA_ID 1u
#define EDGE_NHA_GROUP 2u
#define EDGE_NHA_GROUP_TYPE 3u
#define EDGE_NHA_BLACKHOLE 4u
#define EDGE_NHA_OIF 5u
#define EDGE_NHA_GATEWAY 6u
#define EDGE_TCA_KIND 1u
#define EDGE_TCA_OPTIONS 2u
#define EDGE_TCA_STATS 3u
#define EDGE_TCA_STATS2 7u
#define EDGE_TCA_STATS_BASIC 1u
#define EDGE_TCA_STATS_QUEUE 3u
#define EDGE_TC_H_ROOT UINT32_MAX
#define EDGE_RT_TABLE_MAIN 254u
#define EDGE_RT_TABLE_DEFAULT 253u
#define EDGE_RT_TABLE_LOCAL 255u
#define EDGE_RTPROT_KERNEL 2u
#define EDGE_RTPROT_RA 9u
#define EDGE_RT_SCOPE_UNIVERSE 0u
#define EDGE_RT_SCOPE_LINK 253u
#define EDGE_RT_SCOPE_HOST 254u
#define EDGE_RTN_UNICAST 1u
#define EDGE_RTN_LOCAL 2u
#define EDGE_RTN_BLACKHOLE 6u
#define EDGE_RTN_UNREACHABLE 7u
#define EDGE_RTN_PROHIBIT 8u
#define EDGE_RTN_THROW 9u
#define EDGE_RTNEXTHOP_MAX 16u
#define EDGE_RTNL_NEXTHOP_OBJECT_MAX 128u
#define EDGE_RTNH_F_DEAD 0x01u
#define EDGE_RTNH_F_LINKDOWN 0x10u
#define EDGE_FR_ACT_TO_TBL 1u
#define EDGE_FR_ACT_GOTO 2u
#define EDGE_FR_ACT_NOP 3u
#define EDGE_FR_ACT_BLACKHOLE 6u
#define EDGE_FR_ACT_UNREACHABLE 7u
#define EDGE_FR_ACT_PROHIBIT 8u
#define EDGE_NTF_ROUTER 0x80u
#define EDGE_NTF_MASTER 0x04u
#define EDGE_NUD_REACHABLE 0x02u
#define EDGE_NUD_NOARP 0x40u
#define EDGE_NUD_PERMANENT 0x80u
#define EDGE_RTNL_LINK_MAX 64u
#define EDGE_RTNL_ROUTE_MAX 256u
#define EDGE_RTNL_RULE_MAX 128u
#define EDGE_RTNL_NAME_MAX 16u
#define EDGE_RTNL_KIND_MAX 16u
#define EDGE_RTNL_IPV6_ADDRESS_MAX 8u

typedef struct edge_netfilter_nlmsghdr {
    uint32_t length;
    uint16_t type;
    uint16_t flags;
    uint32_t sequence;
    uint32_t port_id;
} edge_netfilter_nlmsghdr_t;

typedef struct edge_nfgenmsg {
    uint8_t family;
    uint8_t version;
    uint16_t resource_id;
} edge_nfgenmsg_t;

typedef struct edge_netfilter_nlmsgerr {
    int32_t error;
    edge_netfilter_nlmsghdr_t request;
} edge_netfilter_nlmsgerr_t;

typedef struct edge_nlattr {
    uint16_t length;
    uint16_t type;
} edge_nlattr_t;

typedef struct edge_netfilter_table {
    uint8_t used;
    uint8_t family;
    uint32_t network_namespace;
    uint32_t flags;
    uint64_t handle;
    char name[EDGE_NETFILTER_NAME_MAX];
} edge_netfilter_table_t;

typedef struct edge_netfilter_chain {
    uint8_t used;
    uint8_t family;
    uint8_t base_chain;
    uint8_t hook;
    uint32_t network_namespace;
    uint32_t flags;
    int32_t priority;
    uint32_t policy;
    uint64_t handle;
    char table[EDGE_NETFILTER_NAME_MAX];
    char name[EDGE_NETFILTER_NAME_MAX];
    char type[EDGE_NETFILTER_NAME_MAX];
} edge_netfilter_chain_t;

typedef struct edge_netfilter_rule {
    uint8_t used;
    uint8_t family;
    uint16_t attribute_length;
    uint32_t network_namespace;
    uint64_t handle;
    char table[EDGE_NETFILTER_NAME_MAX];
    char chain[EDGE_NETFILTER_NAME_MAX];
    uint8_t attributes[EDGE_NETFILTER_RULE_DATA_MAX];
} edge_netfilter_rule_t;

typedef struct edge_netfilter_state {
    uint32_t generation;
    uint64_t next_handle;
    edge_netfilter_table_t tables[EDGE_NETFILTER_TABLE_MAX];
    edge_netfilter_chain_t chains[EDGE_NETFILTER_CHAIN_MAX];
    edge_netfilter_rule_t rules[EDGE_NETFILTER_RULE_MAX];
} edge_netfilter_state_t;

typedef struct edge_netfilter_conntrack {
    uint8_t used;
    uint64_t identifier;
    uint64_t packets;
    uint64_t last_used;
    edge_linux_netfilter_tuple_t original;
    edge_linux_netfilter_tuple_t translated;
} edge_netfilter_conntrack_t;

typedef struct edge_rtnl_ifinfomsg {
    uint8_t family;
    uint8_t pad;
    uint16_t type;
    int32_t index;
    uint32_t flags;
    uint32_t change;
} edge_rtnl_ifinfomsg_t;

typedef struct edge_rtnl_ifaddrmsg {
    uint8_t family;
    uint8_t prefix_length;
    uint8_t flags;
    uint8_t scope;
    uint32_t index;
} edge_rtnl_ifaddrmsg_t;

typedef struct edge_rtnl_rtmsg {
    uint8_t family;
    uint8_t destination_length;
    uint8_t source_length;
    uint8_t tos;
    uint8_t table;
    uint8_t protocol;
    uint8_t scope;
    uint8_t type;
    uint32_t flags;
} edge_rtnl_rtmsg_t;

typedef struct edge_rtnl_ndmsg {
    uint8_t family;
    uint8_t pad1;
    uint16_t pad2;
    int32_t index;
    uint16_t state;
    uint8_t flags;
    uint8_t type;
} edge_rtnl_ndmsg_t;

typedef struct edge_rtnl_tcmsg {
    uint8_t family;
    uint8_t pad1;
    uint16_t pad2;
    int32_t index;
    uint32_t handle;
    uint32_t parent;
    uint32_t info;
} edge_rtnl_tcmsg_t;

typedef struct edge_rtnl_tc_fifo_options {
    uint32_t limit;
} edge_rtnl_tc_fifo_options_t;

typedef struct edge_rtnl_tc_stats {
    uint64_t bytes;
    uint32_t packets;
    uint32_t drops;
    uint32_t overlimits;
    uint32_t bytes_per_second;
    uint32_t packets_per_second;
    uint32_t queue_length;
    uint32_t backlog;
} edge_rtnl_tc_stats_t;

typedef struct edge_rtnl_gnet_basic {
    uint64_t bytes;
    uint64_t packets;
} edge_rtnl_gnet_basic_t;

typedef struct edge_rtnl_gnet_queue {
    uint32_t queue_length;
    uint32_t backlog;
    uint32_t drops;
    uint32_t requeues;
    uint32_t overlimits;
} edge_rtnl_gnet_queue_t;

typedef struct edge_rtnl_rulemsg {
    uint8_t family;
    uint8_t destination_length;
    uint8_t source_length;
    uint8_t tos;
    uint8_t table;
    uint8_t reserved1;
    uint8_t reserved2;
    uint8_t action;
    uint32_t flags;
} edge_rtnl_rulemsg_t;

typedef struct edge_rtnl_nhmsg {
    uint8_t family;
    uint8_t scope;
    uint8_t protocol;
    uint8_t reserved;
    uint32_t flags;
} edge_rtnl_nhmsg_t;

typedef struct edge_rtnl_nexthop_group_wire {
    uint32_t id;
    uint8_t weight;
    uint8_t reserved1;
    uint16_t reserved2;
} edge_rtnl_nexthop_group_wire_t;

typedef struct edge_rtnl_uid_range {
    uint32_t start;
    uint32_t end;
} edge_rtnl_uid_range_t;

typedef struct edge_rtnl_ifa_cacheinfo {
    uint32_t preferred;
    uint32_t valid;
    uint32_t created;
    uint32_t updated;
} edge_rtnl_ifa_cacheinfo_t;

typedef struct edge_rtnl_ipv6_address {
    uint8_t used;
    uint8_t prefix_length;
    uint8_t scope;
    uint32_t flags;
    uint32_t valid_lifetime;
    uint32_t preferred_lifetime;
    uint8_t address[16];
} edge_rtnl_ipv6_address_t;

typedef struct edge_rtnl_link {
    uint8_t used;
    uint8_t prefix_length;
    uint16_t type;
    uint32_t network_namespace;
    int32_t index;
    int32_t master;
    int32_t peer_index;
    int32_t lower_index;
    uint32_t flags;
    uint32_t mtu;
    uint32_t tx_queue_length;
    uint32_t ipv4_address;
    uint32_t ipv4_gateway;
    uint16_t vlan_id;
    uint16_t vlan_protocol;
    uint16_t virtual_mode;
    uint16_t virtual_flags;
    uint8_t bridge_vlan_filtering;
    uint32_t routing_table;
    uint8_t mac[6];
    edge_rtnl_ipv6_address_t
        ipv6_addresses[EDGE_RTNL_IPV6_ADDRESS_MAX];
    char name[EDGE_RTNL_NAME_MAX];
    char kind[EDGE_RTNL_KIND_MAX];
} edge_rtnl_link_t;

typedef struct edge_rtnl_bridge_vlan_info {
    uint16_t flags;
    uint16_t vlan_id;
} edge_rtnl_bridge_vlan_info_t;

typedef struct edge_rtnl_bridge_port_message {
    uint8_t family;
    uint8_t padding[3];
    uint32_t ifindex;
} edge_rtnl_bridge_port_message_t;

typedef union edge_rtnl_mdb_address {
    uint32_t ipv4;
    uint8_t ipv6[16];
    uint8_t hardware_address[6];
} edge_rtnl_mdb_address_t;

typedef struct edge_rtnl_mdb_entry {
    uint32_t ifindex;
    uint8_t state;
    uint8_t flags;
    uint16_t vlan_id;
    edge_rtnl_mdb_address_t address;
    uint16_t protocol;
} edge_rtnl_mdb_entry_t;

typedef struct edge_rtnl_bridge_port_settings {
    uint32_t mask;
    uint8_t state;
    uint8_t hairpin;
    uint8_t learning;
    uint8_t unicast_flood;
    uint8_t multicast_flood;
    uint8_t broadcast_flood;
    uint8_t isolated;
} edge_rtnl_bridge_port_settings_t;

static int edge_rtnl_core_error(int result);

typedef struct edge_rtnl_nexthop {
    int32_t output_ifindex;
    uint8_t flags;
    uint8_t hops;
    uint8_t gateway[16];
} edge_rtnl_nexthop_t;

typedef struct edge_rtnl_nexthop_group_member {
    uint32_t id;
    uint8_t weight;
} edge_rtnl_nexthop_group_member_t;

typedef struct edge_rtnl_nexthop_object {
    uint8_t used;
    uint8_t family;
    uint8_t scope;
    uint8_t protocol;
    uint8_t blackhole;
    uint8_t group_type;
    uint8_t member_count;
    uint32_t network_namespace;
    uint32_t id;
    uint32_t flags;
    int32_t output_ifindex;
    uint8_t gateway[16];
    edge_rtnl_nexthop_group_member_t members[EDGE_RTNEXTHOP_MAX];
} edge_rtnl_nexthop_object_t;

typedef struct edge_rtnl_wire_nexthop {
    uint16_t length;
    uint8_t flags;
    uint8_t hops;
    int32_t output_ifindex;
} edge_rtnl_wire_nexthop_t;

typedef struct edge_rtnl_route {
    uint8_t used;
    uint8_t family;
    uint8_t destination_length;
    uint8_t source_length;
    uint8_t protocol;
    uint8_t scope;
    uint8_t type;
    uint8_t tos;
    uint32_t network_namespace;
    uint32_t table;
    uint32_t metric;
    uint32_t mark;
    uint32_t nexthop_id;
    int32_t input_ifindex;
    int32_t output_ifindex;
    uint8_t destination[16];
    uint8_t source[16];
    uint8_t gateway[16];
    uint8_t preferred_source[16];
    uint8_t nexthop_count;
    edge_rtnl_nexthop_t nexthops[EDGE_RTNEXTHOP_MAX];
} edge_rtnl_route_t;

typedef struct edge_rtnl_rule {
    uint8_t used;
    uint8_t family;
    uint8_t destination_length;
    uint8_t source_length;
    uint8_t action;
    uint32_t network_namespace;
    uint32_t table;
    uint32_t priority;
    uint32_t mark;
    uint32_t mark_mask;
    edge_rtnl_uid_range_t uid_range;
    uint8_t destination[16];
    uint8_t source[16];
    char input_interface[EDGE_RTNL_NAME_MAX];
    char output_interface[EDGE_RTNL_NAME_MAX];
} edge_rtnl_rule_t;

static volatile uint32_t g_edge_netfilter_lock;
static edge_netfilter_state_t g_edge_netfilter_state;
static edge_netfilter_state_t g_edge_netfilter_staging;
static edge_netfilter_conntrack_t
    g_edge_netfilter_conntrack[EDGE_NETFILTER_CONNTRACK_MAX];
static uint64_t g_edge_netfilter_conntrack_identifier = 1u;
static uint64_t g_edge_netfilter_conntrack_clock = 1u;
static uint32_t g_edge_netfilter_masquerade_ipv4;
static volatile uint32_t g_edge_rtnl_lock;
static int32_t g_edge_rtnl_next_index = 3;
static edge_rtnl_link_t g_edge_rtnl_links[EDGE_RTNL_LINK_MAX];
static edge_rtnl_route_t g_edge_rtnl_routes[EDGE_RTNL_ROUTE_MAX];
static edge_rtnl_rule_t g_edge_rtnl_rules[EDGE_RTNL_RULE_MAX];
static edge_rtnl_nexthop_object_t
    g_edge_rtnl_nexthops[EDGE_RTNL_NEXTHOP_OBJECT_MAX];
static int edge_rtnl_address_is_zero(
    const uint8_t *address, uint32_t length);
static edge_rtnl_link_t *edge_rtnl_find_index(int32_t index);
static int edge_rtnl_ipv4_is_connected(
    uint32_t network_namespace, uint32_t source, uint32_t destination);
static edge_linux_rtnetlink_ipv4_update_fn g_edge_rtnl_ipv4_update;
static const edge_linux_rtnetlink_ipv4_provider_t *g_edge_rtnl_ipv4_provider;
static const edge_linux_rtnetlink_ipv6_provider_t *g_edge_rtnl_ipv6_provider;

static void edge_rtnl_remove_ipv6_interface(edge_rtnl_link_t *link) {
    const edge_linux_rtnetlink_ipv6_provider_t *provider =
        __atomic_load_n(&g_edge_rtnl_ipv6_provider, __ATOMIC_ACQUIRE);
    uint32_t ordinal;

    if (!link || !link->used || !provider) return;
    if (provider->configure_address) {
        for (ordinal = 0; ordinal < EDGE_RTNL_IPV6_ADDRESS_MAX; ++ordinal) {
            edge_rtnl_ipv6_address_t *address =
                &link->ipv6_addresses[ordinal];

            if (!address->used) continue;
            (void)provider->configure_address(
                link->network_namespace, link->index, address->address,
                address->prefix_length, address->flags,
                address->valid_lifetime, address->preferred_lifetime, 0);
        }
    }
    if (provider->remove_interface)
        provider->remove_interface(link->network_namespace, link->index);
}

static void edge_rtnl_remove_interface_routes(
    const edge_rtnl_link_t *link) {
    uint32_t ordinal;

    if (!link || !link->used) return;
    for (ordinal = 0; ordinal < EDGE_RTNL_ROUTE_MAX; ++ordinal) {
        edge_rtnl_route_t *route = &g_edge_rtnl_routes[ordinal];

        if (!route->used ||
            route->network_namespace != link->network_namespace)
            continue;
        if (route->input_ifindex == link->index ||
            route->output_ifindex == link->index)
            memset(route, 0, sizeof(*route));
    }
}
static int edge_netfilter_find_buffer_attribute(
    const uint8_t *bytes, uint32_t length, uint16_t wanted,
    const uint8_t **data, uint32_t *data_length);
static int edge_netfilter_buffer_be32(
    const uint8_t *bytes, uint32_t length, uint16_t attribute_type,
    uint32_t *value);

static void edge_netfilter_lock(void) {
    while (__sync_lock_test_and_set(&g_edge_netfilter_lock, 1u)) {
        while (g_edge_netfilter_lock) {
#if defined(__x86_64__)
            __asm__ __volatile__("pause");
#elif defined(__aarch64__)
            __asm__ __volatile__("yield");
#endif
        }
    }
}

static void edge_netfilter_unlock(void) {
    __sync_lock_release(&g_edge_netfilter_lock);
}

static int edge_netfilter_append_ack(
    const edge_netfilter_nlmsghdr_t *request, uint32_t port_id,
    uint8_t *response, uint32_t capacity, uint32_t *response_length) {
    edge_netfilter_nlmsghdr_t header;
    edge_netfilter_nlmsgerr_t acknowledgement;
    uint32_t offset;

    if (!request || !response || !response_length ||
        !(request->flags & EDGE_NLM_F_ACK)) return 0;
    offset = *response_length;
    if (offset > capacity ||
        capacity - offset < sizeof(header) + sizeof(acknowledgement))
        return -EDGE_LINUX_ENOBUFS;
    memset(&header, 0, sizeof(header));
    memset(&acknowledgement, 0, sizeof(acknowledgement));
    header.length = sizeof(header) + sizeof(acknowledgement);
    header.type = EDGE_NLMSG_ERROR;
    header.sequence = request->sequence;
    header.port_id = port_id;
    acknowledgement.request = *request;
    memcpy(response + offset, &header, sizeof(header));
    memcpy(response + offset + sizeof(header),
           &acknowledgement, sizeof(acknowledgement));
    *response_length = offset + header.length;
    return 0;
}

static void edge_rtnl_lock(void) {
    while (__sync_lock_test_and_set(&g_edge_rtnl_lock, 1u)) {
        while (g_edge_rtnl_lock) {
#if defined(__x86_64__)
            __asm__ __volatile__("pause");
#elif defined(__aarch64__)
            __asm__ __volatile__("yield");
#endif
        }
    }
}

static void edge_rtnl_unlock(void) {
    __sync_lock_release(&g_edge_rtnl_lock);
}

static uint32_t edge_netlink_align(uint32_t length) {
    return (length + 3u) & ~3u;
}

static uint32_t edge_netlink_be32(uint32_t value) {
    return ((value & 0x000000ffu) << 24u) |
           ((value & 0x0000ff00u) << 8u) |
           ((value & 0x00ff0000u) >> 8u) |
           ((value & 0xff000000u) >> 24u);
}

static uint64_t edge_netlink_be64(uint64_t value) {
    return ((uint64_t)edge_netlink_be32((uint32_t)value) << 32u) |
           edge_netlink_be32((uint32_t)(value >> 32u));
}

static uint64_t edge_netlink_from_be64(const void *value) {
    uint64_t encoded;

    memcpy(&encoded, value, sizeof(encoded));
    return edge_netlink_be64(encoded);
}

static uint32_t edge_netlink_from_be32(const void *value) {
    uint32_t encoded;

    memcpy(&encoded, value, sizeof(encoded));
    return edge_netlink_be32(encoded);
}

static int edge_netfilter_find_attribute(
    const edge_netfilter_nlmsghdr_t *message, uint16_t wanted,
    const uint8_t **data, uint32_t *data_length) {
    const uint8_t *bytes = (const uint8_t *)message;
    uint32_t offset = sizeof(*message) + sizeof(edge_nfgenmsg_t);

    if (!message || message->length < offset) return -EDGE_LINUX_EINVAL;
    while (offset < message->length) {
        const edge_nlattr_t *attribute;
        uint32_t aligned;

        if (message->length - offset < sizeof(*attribute))
            return -EDGE_LINUX_EINVAL;
        attribute = (const edge_nlattr_t *)(bytes + offset);
        if (attribute->length < sizeof(*attribute) ||
            attribute->length > message->length - offset)
            return -EDGE_LINUX_EINVAL;
        if ((attribute->type & EDGE_NLA_TYPE_MASK) == wanted) {
            if (data) *data = bytes + offset + sizeof(*attribute);
            if (data_length)
                *data_length = attribute->length - sizeof(*attribute);
            return 0;
        }
        aligned = edge_netlink_align(attribute->length);
        if (aligned > message->length - offset)
            return -EDGE_LINUX_EINVAL;
        offset += aligned;
    }
    return -EDGE_LINUX_ENOENT;
}

static int edge_netfilter_read_name(
    const edge_netfilter_nlmsghdr_t *message, uint16_t attribute_type,
    char output[EDGE_NETFILTER_NAME_MAX]) {
    const uint8_t *data;
    uint32_t length;
    uint32_t index;
    int result = edge_netfilter_find_attribute(
        message, attribute_type, &data, &length);

    if (result < 0) return result;
    if (!length || length > EDGE_NETFILTER_NAME_MAX)
        return -EDGE_LINUX_EINVAL;
    for (index = 0; index < length; ++index) {
        output[index] = (char)data[index];
        if (!data[index]) break;
    }
    if (index == length || output[0] == '\0')
        return -EDGE_LINUX_EINVAL;
    while (++index < EDGE_NETFILTER_NAME_MAX) output[index] = '\0';
    return 0;
}

static int edge_netfilter_read_be32(
    const edge_netfilter_nlmsghdr_t *message, uint16_t attribute_type,
    uint32_t *value) {
    const uint8_t *data;
    uint32_t length;
    int result = edge_netfilter_find_attribute(
        message, attribute_type, &data, &length);

    if (result < 0) return result;
    if (length != sizeof(uint32_t)) return -EDGE_LINUX_EINVAL;
    if (value) *value = edge_netlink_from_be32(data);
    return 0;
}

static int edge_netfilter_read_be64(
    const edge_netfilter_nlmsghdr_t *message, uint16_t attribute_type,
    uint64_t *value) {
    const uint8_t *data;
    uint32_t length;
    int result = edge_netfilter_find_attribute(
        message, attribute_type, &data, &length);

    if (result < 0) return result;
    if (length != sizeof(uint64_t)) return -EDGE_LINUX_EINVAL;
    if (value) *value = edge_netlink_from_be64(data);
    return 0;
}

static edge_netfilter_table_t *edge_netfilter_find_table(
    edge_netfilter_state_t *state, uint32_t network_namespace,
    uint8_t family, const char *name) {
    uint32_t index;

    for (index = 0; index < EDGE_NETFILTER_TABLE_MAX; ++index) {
        edge_netfilter_table_t *table = &state->tables[index];

        if (table->used &&
            table->network_namespace == network_namespace &&
            table->family == family &&
            strcmp(table->name, name) == 0)
            return table;
    }
    return 0;
}

static edge_netfilter_chain_t *edge_netfilter_find_chain(
    edge_netfilter_state_t *state, uint32_t network_namespace,
    uint8_t family, const char *table_name, const char *chain_name) {
    uint32_t index;

    for (index = 0; index < EDGE_NETFILTER_CHAIN_MAX; ++index) {
        edge_netfilter_chain_t *chain = &state->chains[index];

        if (chain->used &&
            chain->network_namespace == network_namespace &&
            chain->family == family &&
            strcmp(chain->table, table_name) == 0 &&
            strcmp(chain->name, chain_name) == 0)
            return chain;
    }
    return 0;
}

static edge_netfilter_rule_t *edge_netfilter_find_rule(
    edge_netfilter_state_t *state, uint32_t network_namespace,
    uint8_t family, const char *table_name, const char *chain_name,
    uint64_t handle) {
    uint32_t index;

    for (index = 0; index < EDGE_NETFILTER_RULE_MAX; ++index) {
        edge_netfilter_rule_t *rule = &state->rules[index];

        if (rule->used &&
            rule->network_namespace == network_namespace &&
            rule->family == family &&
            rule->handle == handle &&
            strcmp(rule->table, table_name) == 0 &&
            strcmp(rule->chain, chain_name) == 0)
            return rule;
    }
    return 0;
}

static uint64_t edge_netfilter_next_handle(edge_netfilter_state_t *state) {
    ++state->next_handle;
    if (!state->next_handle) ++state->next_handle;
    return state->next_handle;
}

static int edge_netfilter_new_table(
    edge_netfilter_state_t *state, uint32_t network_namespace,
    const edge_netfilter_nlmsghdr_t *message) {
    const edge_nfgenmsg_t *family =
        (const edge_nfgenmsg_t *)(message + 1);
    edge_netfilter_table_t *table;
    char name[EDGE_NETFILTER_NAME_MAX];
    uint32_t flags = 0;
    uint32_t index;
    int result;

    result = edge_netfilter_read_name(message, EDGE_NFTA_TABLE_NAME, name);
    if (result < 0) return result;
    result = edge_netfilter_read_be32(
        message, EDGE_NFTA_TABLE_FLAGS, &flags);
    if (result < 0 && result != -EDGE_LINUX_ENOENT) return result;
    if (flags & ~7u) return -EDGE_LINUX_EOPNOTSUPP;
    table = edge_netfilter_find_table(
        state, network_namespace, family->family, name);
    if (table) {
        if (message->flags & EDGE_NLM_F_EXCL) return -EDGE_LINUX_EEXIST;
        if (message->flags & EDGE_NLM_F_REPLACE)
            return -EDGE_LINUX_EOPNOTSUPP;
        table->flags = flags;
        return 0;
    }
    for (index = 0; index < EDGE_NETFILTER_TABLE_MAX; ++index) {
        table = &state->tables[index];
        if (table->used) continue;
        memset(table, 0, sizeof(*table));
        table->used = 1u;
        table->family = family->family;
        table->network_namespace = network_namespace;
        table->flags = flags;
        table->handle = edge_netfilter_next_handle(state);
        memcpy(table->name, name, sizeof(table->name));
        return 0;
    }
    return -EDGE_LINUX_ENOSPC;
}

static int edge_netfilter_new_chain(
    edge_netfilter_state_t *state, uint32_t network_namespace,
    const edge_netfilter_nlmsghdr_t *message) {
    const edge_nfgenmsg_t *family =
        (const edge_nfgenmsg_t *)(message + 1);
    edge_netfilter_chain_t *chain;
    char table_name[EDGE_NETFILTER_NAME_MAX];
    char chain_name[EDGE_NETFILTER_NAME_MAX];
    char chain_type[EDGE_NETFILTER_NAME_MAX];
    const uint8_t *hook_data = 0;
    uint32_t hook_length = 0;
    uint32_t hook_number = 0;
    uint32_t encoded_priority = 0;
    uint32_t policy = EDGE_NF_ACCEPT;
    uint32_t flags = 0;
    int base_chain = 0;
    int policy_supplied = 0;
    uint32_t index;
    int result;

    result = edge_netfilter_read_name(
        message, EDGE_NFTA_CHAIN_TABLE, table_name);
    if (result < 0) return result;
    result = edge_netfilter_read_name(
        message, EDGE_NFTA_CHAIN_NAME, chain_name);
    if (result < 0) return result;
    if (!edge_netfilter_find_table(
            state, network_namespace, family->family, table_name))
        return -EDGE_LINUX_ENOENT;
    result = edge_netfilter_read_be32(
        message, EDGE_NFTA_CHAIN_FLAGS, &flags);
    if (result < 0 && result != -EDGE_LINUX_ENOENT) return result;
    if (flags & ~7u) return -EDGE_LINUX_EOPNOTSUPP;
    result = edge_netfilter_find_attribute(
        message, EDGE_NFTA_CHAIN_HOOK, &hook_data, &hook_length);
    if (result == 0) {
        if (edge_netfilter_buffer_be32(
                hook_data, hook_length, EDGE_NFTA_HOOK_HOOKNUM,
                &hook_number) < 0 ||
            edge_netfilter_buffer_be32(
                hook_data, hook_length, EDGE_NFTA_HOOK_PRIORITY,
                &encoded_priority) < 0 ||
            hook_number > EDGE_NF_INET_INGRESS)
            return -EDGE_LINUX_EINVAL;
        base_chain = 1;
    } else if (result != -EDGE_LINUX_ENOENT) {
        return result;
    }
    memset(chain_type, 0, sizeof(chain_type));
    result = edge_netfilter_read_name(
        message, EDGE_NFTA_CHAIN_TYPE, chain_type);
    if (result < 0 && result != -EDGE_LINUX_ENOENT) return result;
    if (base_chain && result == -EDGE_LINUX_ENOENT)
        return -EDGE_LINUX_EINVAL;
    if (!base_chain && result == 0)
        return -EDGE_LINUX_EINVAL;
    if (result == 0 && strcmp(chain_type, "filter") != 0 &&
        strcmp(chain_type, "nat") != 0 &&
        strcmp(chain_type, "route") != 0)
        return -EDGE_LINUX_EOPNOTSUPP;
    result = edge_netfilter_read_be32(
        message, EDGE_NFTA_CHAIN_POLICY, &policy);
    if (result < 0 && result != -EDGE_LINUX_ENOENT) return result;
    if (result == 0) {
        policy_supplied = 1;
        if (policy != EDGE_NF_ACCEPT && policy != EDGE_NF_DROP)
            return -EDGE_LINUX_EINVAL;
    }
    chain = edge_netfilter_find_chain(
        state, network_namespace, family->family,
        table_name, chain_name);
    if (chain) {
        if (message->flags & EDGE_NLM_F_EXCL) return -EDGE_LINUX_EEXIST;
        if (message->flags & EDGE_NLM_F_REPLACE)
            return -EDGE_LINUX_EOPNOTSUPP;
        chain->flags = flags;
        if (base_chain) {
            chain->base_chain = 1u;
            chain->hook = (uint8_t)hook_number;
            chain->priority = (int32_t)encoded_priority;
            memcpy(chain->type, chain_type, sizeof(chain->type));
        }
        if (policy_supplied) chain->policy = policy;
        return 0;
    }
    for (index = 0; index < EDGE_NETFILTER_CHAIN_MAX; ++index) {
        chain = &state->chains[index];
        if (chain->used) continue;
        memset(chain, 0, sizeof(*chain));
        chain->used = 1u;
        chain->family = family->family;
        chain->network_namespace = network_namespace;
        chain->flags = flags;
        chain->base_chain = base_chain ? 1u : 0u;
        chain->hook = (uint8_t)hook_number;
        chain->priority = (int32_t)encoded_priority;
        chain->policy = policy;
        chain->handle = edge_netfilter_next_handle(state);
        memcpy(chain->table, table_name, sizeof(chain->table));
        memcpy(chain->name, chain_name, sizeof(chain->name));
        memcpy(chain->type, chain_type, sizeof(chain->type));
        return 0;
    }
    return -EDGE_LINUX_ENOSPC;
}

static int edge_netfilter_new_rule(
    edge_netfilter_state_t *state, uint32_t network_namespace,
    const edge_netfilter_nlmsghdr_t *message) {
    const edge_nfgenmsg_t *family =
        (const edge_nfgenmsg_t *)(message + 1);
    edge_netfilter_rule_t *rule;
    char table_name[EDGE_NETFILTER_NAME_MAX];
    char chain_name[EDGE_NETFILTER_NAME_MAX];
    uint32_t attribute_offset = sizeof(*message) + sizeof(*family);
    uint32_t attribute_length = message->length - attribute_offset;
    uint32_t index;
    int result;

    result = edge_netfilter_read_name(
        message, EDGE_NFTA_RULE_TABLE, table_name);
    if (result < 0) return result;
    result = edge_netfilter_read_name(
        message, EDGE_NFTA_RULE_CHAIN, chain_name);
    if (result < 0) return result;
    if (!edge_netfilter_find_chain(
            state, network_namespace, family->family,
            table_name, chain_name))
        return -EDGE_LINUX_ENOENT;
    if (!attribute_length ||
        attribute_length > EDGE_NETFILTER_RULE_DATA_MAX)
        return -EDGE_LINUX_EMSGSIZE;
    if (message->flags & EDGE_NLM_F_REPLACE)
        return -EDGE_LINUX_EOPNOTSUPP;
    for (index = 0; index < EDGE_NETFILTER_RULE_MAX; ++index) {
        rule = &state->rules[index];
        if (rule->used) continue;
        memset(rule, 0, sizeof(*rule));
        rule->used = 1u;
        rule->family = family->family;
        rule->network_namespace = network_namespace;
        rule->handle = edge_netfilter_next_handle(state);
        rule->attribute_length = (uint16_t)attribute_length;
        memcpy(rule->table, table_name, sizeof(rule->table));
        memcpy(rule->chain, chain_name, sizeof(rule->chain));
        memcpy(rule->attributes,
               (const uint8_t *)message + attribute_offset,
               attribute_length);
        return 0;
    }
    return -EDGE_LINUX_ENOSPC;
}

static int edge_netfilter_delete_rule(
    edge_netfilter_state_t *state, uint32_t network_namespace,
    const edge_netfilter_nlmsghdr_t *message) {
    const edge_nfgenmsg_t *family =
        (const edge_nfgenmsg_t *)(message + 1);
    edge_netfilter_rule_t *rule;
    char table_name[EDGE_NETFILTER_NAME_MAX];
    char chain_name[EDGE_NETFILTER_NAME_MAX];
    uint64_t handle;
    int result;

    result = edge_netfilter_read_name(
        message, EDGE_NFTA_RULE_TABLE, table_name);
    if (result < 0) return result;
    result = edge_netfilter_read_name(
        message, EDGE_NFTA_RULE_CHAIN, chain_name);
    if (result < 0) return result;
    result = edge_netfilter_read_be64(
        message, EDGE_NFTA_RULE_HANDLE, &handle);
    if (result < 0) return result;
    rule = edge_netfilter_find_rule(
        state, network_namespace, family->family,
        table_name, chain_name, handle);
    if (!rule) return -EDGE_LINUX_ENOENT;
    memset(rule, 0, sizeof(*rule));
    return 0;
}

static int edge_netfilter_delete_chain(
    edge_netfilter_state_t *state, uint32_t network_namespace,
    const edge_netfilter_nlmsghdr_t *message) {
    const edge_nfgenmsg_t *family =
        (const edge_nfgenmsg_t *)(message + 1);
    edge_netfilter_chain_t *chain;
    char table_name[EDGE_NETFILTER_NAME_MAX];
    char chain_name[EDGE_NETFILTER_NAME_MAX];
    int result;

    result = edge_netfilter_read_name(
        message, EDGE_NFTA_CHAIN_TABLE, table_name);
    if (result < 0) return result;
    result = edge_netfilter_read_name(
        message, EDGE_NFTA_CHAIN_NAME, chain_name);
    if (result < 0) return result;
    chain = edge_netfilter_find_chain(
        state, network_namespace, family->family,
        table_name, chain_name);
    if (!chain) return -EDGE_LINUX_ENOENT;
    for (uint32_t index = 0; index < EDGE_NETFILTER_RULE_MAX; ++index) {
        const edge_netfilter_rule_t *rule = &state->rules[index];

        if (rule->used &&
            rule->network_namespace == network_namespace &&
            rule->family == family->family &&
            strcmp(rule->table, table_name) == 0 &&
            strcmp(rule->chain, chain_name) == 0)
            return -EDGE_LINUX_EBUSY;
    }
    memset(chain, 0, sizeof(*chain));
    return 0;
}

static int edge_netfilter_delete_table(
    edge_netfilter_state_t *state, uint32_t network_namespace,
    const edge_netfilter_nlmsghdr_t *message) {
    const edge_nfgenmsg_t *family =
        (const edge_nfgenmsg_t *)(message + 1);
    edge_netfilter_table_t *table;
    char name[EDGE_NETFILTER_NAME_MAX];
    uint32_t index;
    int result;

    result = edge_netfilter_read_name(message, EDGE_NFTA_TABLE_NAME, name);
    if (result < 0) return result;
    table = edge_netfilter_find_table(
        state, network_namespace, family->family, name);
    if (!table) return -EDGE_LINUX_ENOENT;
    for (index = 0; index < EDGE_NETFILTER_RULE_MAX; ++index) {
        edge_netfilter_rule_t *rule = &state->rules[index];

        if (rule->used &&
            rule->network_namespace == network_namespace &&
            rule->family == family->family &&
            strcmp(rule->table, name) == 0)
            memset(rule, 0, sizeof(*rule));
    }
    for (index = 0; index < EDGE_NETFILTER_CHAIN_MAX; ++index) {
        edge_netfilter_chain_t *chain = &state->chains[index];

        if (chain->used &&
            chain->network_namespace == network_namespace &&
            chain->family == family->family &&
            strcmp(chain->table, name) == 0)
            memset(chain, 0, sizeof(*chain));
    }
    memset(table, 0, sizeof(*table));
    return 0;
}

static int edge_netfilter_apply(
    edge_netfilter_state_t *state, uint32_t network_namespace,
    const edge_netfilter_nlmsghdr_t *message) {
    uint16_t subsystem = (uint16_t)((message->type >> 8u) & 0xffu);
    uint16_t operation = (uint16_t)(message->type & 0xffu);

    if (subsystem != EDGE_NFNL_SUBSYS_NFTABLES)
        return -EDGE_LINUX_EINVAL;
    switch (operation) {
        case EDGE_NFT_MSG_NEWTABLE:
            return edge_netfilter_new_table(
                state, network_namespace, message);
        case EDGE_NFT_MSG_DELTABLE:
        case EDGE_NFT_MSG_DESTROYTABLE:
            return edge_netfilter_delete_table(
                state, network_namespace, message);
        case EDGE_NFT_MSG_NEWCHAIN:
            return edge_netfilter_new_chain(
                state, network_namespace, message);
        case EDGE_NFT_MSG_DELCHAIN:
        case EDGE_NFT_MSG_DESTROYCHAIN:
            return edge_netfilter_delete_chain(
                state, network_namespace, message);
        case EDGE_NFT_MSG_NEWRULE:
            return edge_netfilter_new_rule(
                state, network_namespace, message);
        case EDGE_NFT_MSG_DELRULE:
            return edge_netfilter_delete_rule(
                state, network_namespace, message);
        default:
            return -EDGE_LINUX_EOPNOTSUPP;
    }
}

static int edge_netfilter_append(
    uint8_t *response, uint32_t capacity, uint32_t *offset,
    const void *data, uint32_t length) {
    uint32_t aligned = edge_netlink_align(length);

    if (aligned < length || *offset > capacity ||
        aligned > capacity - *offset)
        return -EDGE_LINUX_ENOBUFS;
    memcpy(response + *offset, data, length);
    if (aligned > length)
        memset(response + *offset + length, 0, aligned - length);
    *offset += aligned;
    return 0;
}

static int edge_netfilter_append_attribute(
    uint8_t *response, uint32_t capacity, uint32_t *offset,
    uint16_t type, const void *data, uint32_t length) {
    edge_nlattr_t attribute;
    uint32_t start = *offset;
    int result;

    if (length > UINT16_MAX - sizeof(attribute))
        return -EDGE_LINUX_EINVAL;
    attribute.length = (uint16_t)(sizeof(attribute) + length);
    attribute.type = type;
    result = edge_netfilter_append(
        response, capacity, offset, &attribute, sizeof(attribute));
    if (result < 0) return result;
    *offset = start + sizeof(attribute);
    result = edge_netfilter_append(
        response, capacity, offset, data, length);
    if (result < 0) return result;
    *offset = start + edge_netlink_align(attribute.length);
    return 0;
}

static int edge_netfilter_begin_reply(
    uint8_t *response, uint32_t capacity, uint32_t *offset,
    uint16_t type, uint16_t flags, uint32_t sequence, uint32_t port_id,
    uint8_t family, uint32_t *start) {
    edge_netfilter_nlmsghdr_t header;
    edge_nfgenmsg_t family_message;
    int result;

    memset(&header, 0, sizeof(header));
    memset(&family_message, 0, sizeof(family_message));
    header.type = type;
    header.flags = flags;
    header.sequence = sequence;
    header.port_id = port_id;
    family_message.family = family;
    *start = *offset;
    result = edge_netfilter_append(
        response, capacity, offset, &header, sizeof(header));
    if (result < 0) return result;
    return edge_netfilter_append(
        response, capacity, offset, &family_message,
        sizeof(family_message));
}

static void edge_netfilter_finish_reply(
    uint8_t *response, uint32_t start, uint32_t offset) {
    edge_netfilter_nlmsghdr_t *header =
        (edge_netfilter_nlmsghdr_t *)(response + start);

    header->length = offset - start;
}

static int edge_netfilter_append_done(
    uint8_t *response, uint32_t capacity, uint32_t *offset,
    uint32_t sequence, uint32_t port_id) {
    edge_netfilter_nlmsghdr_t done;

    memset(&done, 0, sizeof(done));
    done.length = sizeof(done);
    done.type = EDGE_NLMSG_DONE;
    done.flags = EDGE_NLM_F_MULTI;
    done.sequence = sequence;
    done.port_id = port_id;
    return edge_netfilter_append(
        response, capacity, offset, &done, sizeof(done));
}

static uint32_t edge_netfilter_tuple_address_length(uint8_t family) {
    return family == EDGE_AF_INET ? 4u :
           family == EDGE_AF_INET6 ? 16u : 0u;
}

static int edge_netfilter_tuple_equal(
    const edge_linux_netfilter_tuple_t *left,
    const edge_linux_netfilter_tuple_t *right) {
    uint32_t address_length;

    if (!left || !right ||
        left->network_namespace != right->network_namespace ||
        left->family != right->family ||
        left->protocol != right->protocol ||
        left->source_port != right->source_port ||
        left->destination_port != right->destination_port)
        return 0;
    address_length = edge_netfilter_tuple_address_length(left->family);
    return address_length &&
        memcmp(left->source_address, right->source_address,
               address_length) == 0 &&
        memcmp(left->destination_address, right->destination_address,
               address_length) == 0;
}

static void edge_netfilter_tuple_reverse(
    const edge_linux_netfilter_tuple_t *source,
    edge_linux_netfilter_tuple_t *destination) {
    uint32_t address_length;

    memset(destination, 0, sizeof(*destination));
    destination->network_namespace = source->network_namespace;
    destination->family = source->family;
    destination->protocol = source->protocol;
    destination->source_port = source->destination_port;
    destination->destination_port = source->source_port;
    address_length = edge_netfilter_tuple_address_length(source->family);
    memcpy(destination->source_address, source->destination_address,
           address_length);
    memcpy(destination->destination_address, source->source_address,
           address_length);
}

static int edge_netfilter_conntrack_apply_locked(
    edge_linux_netfilter_tuple_t *tuple,
    enum edge_linux_netfilter_translation translation) {
    uint32_t index;

    for (index = 0; index < EDGE_NETFILTER_CONNTRACK_MAX; ++index) {
        edge_netfilter_conntrack_t *entry =
            &g_edge_netfilter_conntrack[index];
        edge_linux_netfilter_tuple_t reply;
        edge_linux_netfilter_tuple_t original_reply;
        uint32_t address_length;

        if (!entry->used ||
            entry->original.network_namespace != tuple->network_namespace ||
            entry->original.family != tuple->family ||
            entry->original.protocol != tuple->protocol)
            continue;
        edge_netfilter_tuple_reverse(&entry->translated, &reply);
        if (!edge_netfilter_tuple_equal(tuple, &reply)) continue;
        edge_netfilter_tuple_reverse(&entry->original, &original_reply);
        address_length = edge_netfilter_tuple_address_length(tuple->family);
        if (translation == EDGE_LINUX_NETFILTER_TRANSLATE_SOURCE) {
            memcpy(tuple->source_address, original_reply.source_address,
                   address_length);
            tuple->source_port = original_reply.source_port;
        } else {
            memcpy(tuple->destination_address,
                   original_reply.destination_address, address_length);
            tuple->destination_port = original_reply.destination_port;
        }
        ++entry->packets;
        entry->last_used = ++g_edge_netfilter_conntrack_clock;
        return 1;
    }
    return 0;
}

static void edge_netfilter_conntrack_record_locked(
    const edge_linux_netfilter_tuple_t *original,
    const edge_linux_netfilter_tuple_t *translated) {
    edge_netfilter_conntrack_t *entry = 0;
    edge_netfilter_conntrack_t *oldest = 0;
    uint32_t index;

    if (edge_netfilter_tuple_equal(original, translated)) return;
    for (index = 0; index < EDGE_NETFILTER_CONNTRACK_MAX; ++index) {
        edge_netfilter_conntrack_t *candidate =
            &g_edge_netfilter_conntrack[index];

        if (candidate->used &&
            (edge_netfilter_tuple_equal(&candidate->original, original) ||
             edge_netfilter_tuple_equal(&candidate->translated, original))) {
            entry = candidate;
            break;
        }
        if (!candidate->used && !entry) entry = candidate;
        if (candidate->used &&
            (!oldest || candidate->last_used < oldest->last_used))
            oldest = candidate;
    }
    if (!entry) entry = oldest;
    if (!entry) return;
    if (!entry->used ||
        !edge_netfilter_tuple_equal(&entry->translated, original)) {
        memset(entry, 0, sizeof(*entry));
        entry->used = 1u;
        entry->identifier = g_edge_netfilter_conntrack_identifier++;
        if (!g_edge_netfilter_conntrack_identifier)
            g_edge_netfilter_conntrack_identifier = 1u;
        entry->original = *original;
    }
    entry->translated = *translated;
    ++entry->packets;
    entry->last_used = ++g_edge_netfilter_conntrack_clock;
}

static int edge_netfilter_append_conntrack_tuple(
    uint8_t *response, uint32_t capacity, uint32_t *offset,
    uint16_t type, const edge_linux_netfilter_tuple_t *tuple) {
    uint8_t ip[64];
    uint8_t protocol[64];
    uint8_t nested[160];
    uint32_t ip_length = 0;
    uint32_t protocol_length = 0;
    uint32_t nested_length = 0;
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t address_length =
        edge_netfilter_tuple_address_length(tuple->family);
    int result;

    if (!address_length) return -EDGE_LINUX_EAFNOSUPPORT;
    result = edge_netfilter_append_attribute(
        ip, sizeof(ip), &ip_length,
        tuple->family == EDGE_AF_INET ? EDGE_CTA_IP_V4_SRC :
                                       EDGE_CTA_IP_V6_SRC,
        tuple->source_address, address_length);
    if (result < 0) return result;
    result = edge_netfilter_append_attribute(
        ip, sizeof(ip), &ip_length,
        tuple->family == EDGE_AF_INET ? EDGE_CTA_IP_V4_DST :
                                       EDGE_CTA_IP_V6_DST,
        tuple->destination_address, address_length);
    if (result < 0) return result;
    result = edge_netfilter_append_attribute(
        protocol, sizeof(protocol), &protocol_length,
        EDGE_CTA_PROTO_NUM, &tuple->protocol, sizeof(tuple->protocol));
    if (result < 0) return result;
    source_port = (uint16_t)((tuple->source_port << 8u) |
                             (tuple->source_port >> 8u));
    destination_port = (uint16_t)((tuple->destination_port << 8u) |
                                  (tuple->destination_port >> 8u));
    result = edge_netfilter_append_attribute(
        protocol, sizeof(protocol), &protocol_length,
        EDGE_CTA_PROTO_SRC_PORT, &source_port, sizeof(source_port));
    if (result < 0) return result;
    result = edge_netfilter_append_attribute(
        protocol, sizeof(protocol), &protocol_length,
        EDGE_CTA_PROTO_DST_PORT, &destination_port,
        sizeof(destination_port));
    if (result < 0) return result;
    result = edge_netfilter_append_attribute(
        nested, sizeof(nested), &nested_length,
        (uint16_t)(EDGE_CTA_TUPLE_IP | 0x8000u), ip, ip_length);
    if (result < 0) return result;
    result = edge_netfilter_append_attribute(
        nested, sizeof(nested), &nested_length,
        (uint16_t)(EDGE_CTA_TUPLE_PROTO | 0x8000u),
        protocol, protocol_length);
    if (result < 0) return result;
    return edge_netfilter_append_attribute(
        response, capacity, offset, (uint16_t)(type | 0x8000u),
        nested, nested_length);
}

static int edge_netfilter_append_conntrack(
    const edge_netfilter_conntrack_t *entry,
    const edge_netfilter_nlmsghdr_t *request, uint32_t port_id,
    uint8_t *response, uint32_t capacity, uint32_t *offset) {
    edge_linux_netfilter_tuple_t reply;
    uint32_t start;
    uint32_t status = edge_netlink_be32(0x0eu);
    uint32_t timeout = edge_netlink_be32(300u);
    uint32_t identifier = edge_netlink_be32((uint32_t)entry->identifier);
    int result = edge_netfilter_begin_reply(
        response, capacity, offset,
        (uint16_t)(EDGE_NFNL_SUBSYS_CTNETLINK << 8u),
        EDGE_NLM_F_MULTI, request->sequence, port_id,
        entry->original.family, &start);

    if (result < 0) return result;
    result = edge_netfilter_append_conntrack_tuple(
        response, capacity, offset, EDGE_CTA_TUPLE_ORIG,
        &entry->original);
    if (result < 0) return result;
    edge_netfilter_tuple_reverse(&entry->translated, &reply);
    result = edge_netfilter_append_conntrack_tuple(
        response, capacity, offset, EDGE_CTA_TUPLE_REPLY, &reply);
    if (result < 0) return result;
    result = edge_netfilter_append_attribute(
        response, capacity, offset, EDGE_CTA_STATUS,
        &status, sizeof(status));
    if (result < 0) return result;
    result = edge_netfilter_append_attribute(
        response, capacity, offset, EDGE_CTA_TIMEOUT,
        &timeout, sizeof(timeout));
    if (result < 0) return result;
    result = edge_netfilter_append_attribute(
        response, capacity, offset, EDGE_CTA_ID,
        &identifier, sizeof(identifier));
    if (result < 0) return result;
    edge_netfilter_finish_reply(response, start, *offset);
    return 0;
}

static uint32_t edge_netfilter_table_use(
    const edge_netfilter_state_t *state,
    const edge_netfilter_table_t *table) {
    uint32_t count = 0;
    uint32_t index;

    for (index = 0; index < EDGE_NETFILTER_CHAIN_MAX; ++index) {
        const edge_netfilter_chain_t *chain = &state->chains[index];

        if (chain->used &&
            chain->network_namespace == table->network_namespace &&
            chain->family == table->family &&
            strcmp(chain->table, table->name) == 0)
            ++count;
    }
    return count;
}

static int edge_netfilter_append_table(
    const edge_netfilter_state_t *state,
    const edge_netfilter_table_t *table,
    const edge_netfilter_nlmsghdr_t *request, uint32_t port_id,
    uint16_t reply_flags, uint8_t *response, uint32_t capacity,
    uint32_t *offset) {
    uint32_t start;
    uint32_t flags = edge_netlink_be32(table->flags);
    uint32_t use = edge_netlink_be32(
        edge_netfilter_table_use(state, table));
    uint64_t handle = edge_netlink_be64(table->handle);
    int result = edge_netfilter_begin_reply(
        response, capacity, offset,
        (uint16_t)((EDGE_NFNL_SUBSYS_NFTABLES << 8u) |
                   EDGE_NFT_MSG_NEWTABLE),
        reply_flags, request->sequence, port_id, table->family, &start);

    if (result < 0) return result;
    result = edge_netfilter_append_attribute(
        response, capacity, offset, EDGE_NFTA_TABLE_NAME,
        table->name, (uint32_t)strlen(table->name) + 1u);
    if (result < 0) return result;
    result = edge_netfilter_append_attribute(
        response, capacity, offset, EDGE_NFTA_TABLE_FLAGS,
        &flags, sizeof(flags));
    if (result < 0) return result;
    result = edge_netfilter_append_attribute(
        response, capacity, offset, EDGE_NFTA_TABLE_USE,
        &use, sizeof(use));
    if (result < 0) return result;
    result = edge_netfilter_append_attribute(
        response, capacity, offset, EDGE_NFTA_TABLE_HANDLE,
        &handle, sizeof(handle));
    if (result < 0) return result;
    edge_netfilter_finish_reply(response, start, *offset);
    return 0;
}

static int edge_netfilter_append_chain(
    const edge_netfilter_chain_t *chain,
    const edge_netfilter_nlmsghdr_t *request, uint32_t port_id,
    uint16_t reply_flags, uint8_t *response, uint32_t capacity,
    uint32_t *offset) {
    uint32_t start;
    uint32_t flags = edge_netlink_be32(chain->flags);
    uint32_t policy = edge_netlink_be32(chain->policy);
    uint64_t handle = edge_netlink_be64(chain->handle);
    int result = edge_netfilter_begin_reply(
        response, capacity, offset,
        (uint16_t)((EDGE_NFNL_SUBSYS_NFTABLES << 8u) |
                   EDGE_NFT_MSG_NEWCHAIN),
        reply_flags, request->sequence, port_id, chain->family, &start);

    if (result < 0) return result;
    result = edge_netfilter_append_attribute(
        response, capacity, offset, EDGE_NFTA_CHAIN_TABLE,
        chain->table, (uint32_t)strlen(chain->table) + 1u);
    if (result < 0) return result;
    result = edge_netfilter_append_attribute(
        response, capacity, offset, EDGE_NFTA_CHAIN_NAME,
        chain->name, (uint32_t)strlen(chain->name) + 1u);
    if (result < 0) return result;
    result = edge_netfilter_append_attribute(
        response, capacity, offset, EDGE_NFTA_CHAIN_HANDLE,
        &handle, sizeof(handle));
    if (result < 0) return result;
    result = edge_netfilter_append_attribute(
        response, capacity, offset, EDGE_NFTA_CHAIN_FLAGS,
        &flags, sizeof(flags));
    if (result < 0) return result;
    if (chain->base_chain) {
        uint8_t hook[32];
        uint32_t hook_length = 0u;
        uint32_t hook_number = edge_netlink_be32(chain->hook);
        uint32_t priority = edge_netlink_be32((uint32_t)chain->priority);

        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_NFTA_CHAIN_TYPE,
            chain->type, (uint32_t)strlen(chain->type) + 1u);
        if (result < 0) return result;
        result = edge_netfilter_append_attribute(
            hook, sizeof(hook), &hook_length, EDGE_NFTA_HOOK_HOOKNUM,
            &hook_number, sizeof(hook_number));
        if (result < 0) return result;
        result = edge_netfilter_append_attribute(
            hook, sizeof(hook), &hook_length, EDGE_NFTA_HOOK_PRIORITY,
            &priority, sizeof(priority));
        if (result < 0) return result;
        result = edge_netfilter_append_attribute(
            response, capacity, offset,
            (uint16_t)(EDGE_NFTA_CHAIN_HOOK | EDGE_NLA_F_NESTED),
            hook, hook_length);
        if (result < 0) return result;
        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_NFTA_CHAIN_POLICY,
            &policy, sizeof(policy));
        if (result < 0) return result;
    }
    edge_netfilter_finish_reply(response, start, *offset);
    return 0;
}

static int edge_netfilter_append_rule(
    const edge_netfilter_rule_t *rule,
    const edge_netfilter_nlmsghdr_t *request, uint32_t port_id,
    uint16_t reply_flags, uint8_t *response, uint32_t capacity,
    uint32_t *offset) {
    uint32_t start;
    uint64_t handle = edge_netlink_be64(rule->handle);
    int result = edge_netfilter_begin_reply(
        response, capacity, offset,
        (uint16_t)((EDGE_NFNL_SUBSYS_NFTABLES << 8u) |
                   EDGE_NFT_MSG_NEWRULE),
        reply_flags, request->sequence, port_id, rule->family, &start);

    if (result < 0) return result;
    result = edge_netfilter_append(
        response, capacity, offset,
        rule->attributes, rule->attribute_length);
    if (result < 0) return result;
    result = edge_netfilter_append_attribute(
        response, capacity, offset, EDGE_NFTA_RULE_HANDLE,
        &handle, sizeof(handle));
    if (result < 0) return result;
    edge_netfilter_finish_reply(response, start, *offset);
    return 0;
}

static int edge_netfilter_get_tables(
    const edge_netfilter_state_t *state, uint32_t network_namespace,
    const edge_netfilter_nlmsghdr_t *request, uint32_t port_id,
    uint8_t *response, uint32_t capacity, uint32_t *response_length) {
    const edge_nfgenmsg_t *family =
        (const edge_nfgenmsg_t *)(request + 1);
    char name[EDGE_NETFILTER_NAME_MAX];
    int dump = (request->flags & EDGE_NLM_F_DUMP) == EDGE_NLM_F_DUMP;
    uint32_t offset = 0;
    uint32_t index;
    int result;

    if (!dump) {
        edge_netfilter_table_t *table;

        result = edge_netfilter_read_name(
            request, EDGE_NFTA_TABLE_NAME, name);
        if (result < 0) return result;
        table = edge_netfilter_find_table(
            (edge_netfilter_state_t *)state, network_namespace,
            family->family, name);
        if (!table) return -EDGE_LINUX_ENOENT;
        result = edge_netfilter_append_table(
            state, table, request, port_id, 0, response, capacity, &offset);
        if (result < 0) return result;
        *response_length = offset;
        return 0;
    }
    for (index = 0; index < EDGE_NETFILTER_TABLE_MAX; ++index) {
        const edge_netfilter_table_t *table = &state->tables[index];

        if (!table->used ||
            table->network_namespace != network_namespace ||
            (family->family && table->family != family->family))
            continue;
        result = edge_netfilter_append_table(
            state, table, request, port_id, EDGE_NLM_F_MULTI,
            response, capacity, &offset);
        if (result < 0) return result;
    }
    result = edge_netfilter_append_done(
        response, capacity, &offset, request->sequence, port_id);
    if (result < 0) return result;
    *response_length = offset;
    return 0;
}

static int edge_netfilter_get_chains(
    const edge_netfilter_state_t *state, uint32_t network_namespace,
    const edge_netfilter_nlmsghdr_t *request, uint32_t port_id,
    uint8_t *response, uint32_t capacity, uint32_t *response_length) {
    const edge_nfgenmsg_t *family =
        (const edge_nfgenmsg_t *)(request + 1);
    char table_name[EDGE_NETFILTER_NAME_MAX];
    char chain_name[EDGE_NETFILTER_NAME_MAX];
    int dump = (request->flags & EDGE_NLM_F_DUMP) == EDGE_NLM_F_DUMP;
    uint32_t offset = 0;
    uint32_t index;
    int result;

    if (!dump) {
        edge_netfilter_chain_t *chain;

        result = edge_netfilter_read_name(
            request, EDGE_NFTA_CHAIN_TABLE, table_name);
        if (result < 0) return result;
        result = edge_netfilter_read_name(
            request, EDGE_NFTA_CHAIN_NAME, chain_name);
        if (result < 0) return result;
        chain = edge_netfilter_find_chain(
            (edge_netfilter_state_t *)state, network_namespace,
            family->family,
            table_name, chain_name);
        if (!chain) return -EDGE_LINUX_ENOENT;
        result = edge_netfilter_append_chain(
            chain, request, port_id, 0, response, capacity, &offset);
        if (result < 0) return result;
        *response_length = offset;
        return 0;
    }
    for (index = 0; index < EDGE_NETFILTER_CHAIN_MAX; ++index) {
        const edge_netfilter_chain_t *chain = &state->chains[index];

        if (!chain->used ||
            chain->network_namespace != network_namespace ||
            (family->family && chain->family != family->family))
            continue;
        result = edge_netfilter_append_chain(
            chain, request, port_id, EDGE_NLM_F_MULTI,
            response, capacity, &offset);
        if (result < 0) return result;
    }
    result = edge_netfilter_append_done(
        response, capacity, &offset, request->sequence, port_id);
    if (result < 0) return result;
    *response_length = offset;
    return 0;
}

static int edge_netfilter_get_rules(
    const edge_netfilter_state_t *state, uint32_t network_namespace,
    const edge_netfilter_nlmsghdr_t *request, uint32_t port_id,
    uint8_t *response, uint32_t capacity, uint32_t *response_length) {
    const edge_nfgenmsg_t *family =
        (const edge_nfgenmsg_t *)(request + 1);
    char table_name[EDGE_NETFILTER_NAME_MAX];
    char chain_name[EDGE_NETFILTER_NAME_MAX];
    uint64_t handle = 0;
    int have_table;
    int have_chain;
    int have_handle;
    int dump = (request->flags & EDGE_NLM_F_DUMP) == EDGE_NLM_F_DUMP;
    uint32_t offset = 0;
    uint32_t index;
    uint32_t matched = 0;
    int result;

    have_table = edge_netfilter_read_name(
        request, EDGE_NFTA_RULE_TABLE, table_name) == 0;
    have_chain = edge_netfilter_read_name(
        request, EDGE_NFTA_RULE_CHAIN, chain_name) == 0;
    have_handle = edge_netfilter_read_be64(
        request, EDGE_NFTA_RULE_HANDLE, &handle) == 0;
    for (index = 0; index < EDGE_NETFILTER_RULE_MAX; ++index) {
        const edge_netfilter_rule_t *rule = &state->rules[index];

        if (!rule->used ||
            rule->network_namespace != network_namespace ||
            (family->family && rule->family != family->family) ||
            (have_table && strcmp(rule->table, table_name) != 0) ||
            (have_chain && strcmp(rule->chain, chain_name) != 0) ||
            (have_handle && rule->handle != handle))
            continue;
        result = edge_netfilter_append_rule(
            rule, request, port_id, dump ? EDGE_NLM_F_MULTI : 0,
            response, capacity, &offset);
        if (result < 0) return result;
        ++matched;
        if (!dump) break;
    }
    if (!dump && !matched) return -EDGE_LINUX_ENOENT;
    if (dump) {
        result = edge_netfilter_append_done(
            response, capacity, &offset, request->sequence, port_id);
        if (result < 0) return result;
    }
    *response_length = offset;
    return 0;
}

static int edge_netfilter_transaction(
    uint32_t network_namespace,
    const uint8_t *payload, uint32_t length) {
    const edge_netfilter_nlmsghdr_t *begin =
        (const edge_netfilter_nlmsghdr_t *)payload;
    uint32_t expected_generation;
    uint32_t offset;
    int result;

    result = edge_netfilter_read_be32(
        begin, EDGE_NFTA_GEN_ID, &expected_generation);
    if (result < 0 && result != -EDGE_LINUX_ENOENT) return result;
    if (result == 0 && expected_generation != g_edge_netfilter_state.generation)
        return -EDGE_LINUX_EAGAIN;
    memcpy(&g_edge_netfilter_staging, &g_edge_netfilter_state,
           sizeof(g_edge_netfilter_staging));
    offset = edge_netlink_align(begin->length);
    while (offset < length) {
        const edge_netfilter_nlmsghdr_t *message;
        uint32_t aligned;

        if (length - offset < sizeof(*message))
            return -EDGE_LINUX_EINVAL;
        message = (const edge_netfilter_nlmsghdr_t *)(payload + offset);
        if (message->length < sizeof(*message) + sizeof(edge_nfgenmsg_t) ||
            message->length > length - offset)
            return -EDGE_LINUX_EINVAL;
        if (message->type == EDGE_NFNL_MSG_BATCH_END) {
            g_edge_netfilter_staging.generation =
                g_edge_netfilter_state.generation + 1u;
            if (!g_edge_netfilter_staging.generation)
                g_edge_netfilter_staging.generation = 1u;
            memcpy(&g_edge_netfilter_state, &g_edge_netfilter_staging,
                   sizeof(g_edge_netfilter_state));
            return 0;
        }
        result = edge_netfilter_apply(
            &g_edge_netfilter_staging, network_namespace, message);
        if (result < 0) return result;
        aligned = edge_netlink_align(message->length);
        if (aligned > length - offset) return -EDGE_LINUX_EINVAL;
        offset += aligned;
    }
    return -EDGE_LINUX_EINVAL;
}

typedef struct edge_netfilter_extension_revision {
    const char *name;
    uint8_t target;
    uint8_t lowest;
    uint8_t highest;
} edge_netfilter_extension_revision_t;

static const edge_netfilter_extension_revision_t
    g_edge_netfilter_extension_revisions[] = {
        {"MASQUERADE", 1u, 0u, 0u},
        {"DNAT", 1u, 0u, 2u},
        {"SNAT", 1u, 0u, 2u},
        {"REDIRECT", 1u, 0u, 0u},
        {"addrtype", 0u, 0u, 1u},
        {"conntrack", 0u, 1u, 3u},
        {"tcp", 0u, 0u, 0u},
        {"udp", 0u, 0u, 0u},
        {"comment", 0u, 0u, 0u},
    };

int edge_linux_netfilter_extension_revision(
    const char *name, int target, uint8_t requested,
    uint8_t *highest_supported) {
    uint32_t index;

    if (!name || !highest_supported) return -EDGE_LINUX_EINVAL;
    for (index = 0u;
         index < sizeof(g_edge_netfilter_extension_revisions) /
                     sizeof(g_edge_netfilter_extension_revisions[0]);
         ++index) {
        const edge_netfilter_extension_revision_t *extension =
            &g_edge_netfilter_extension_revisions[index];

        if (extension->target == (target != 0) &&
            strcmp(extension->name, name) == 0) {
            *highest_supported = extension->highest;
            if (requested < extension->lowest ||
                requested > extension->highest)
                return -EDGE_LINUX_EPROTONOSUPPORT;
            return 0;
        }
    }
    return -EDGE_LINUX_ENOENT;
}

static int edge_netfilter_compat_get(
    const edge_netfilter_nlmsghdr_t *request, uint32_t port_id,
    uint8_t *response, uint32_t capacity, uint32_t *response_length) {
    const edge_nfgenmsg_t *family =
        (const edge_nfgenmsg_t *)(request + 1);
    char name[EDGE_NETFILTER_NAME_MAX];
    uint32_t revision;
    uint32_t extension_type;
    uint32_t encoded_revision;
    uint32_t encoded_type;
    uint32_t offset = 0;
    uint32_t start;
    uint8_t highest_revision;
    int result;

    result = edge_netfilter_read_name(
        request, EDGE_NFTA_COMPAT_NAME, name);
    if (result < 0) return result;
    result = edge_netfilter_read_be32(
        request, EDGE_NFTA_COMPAT_REVISION, &revision);
    if (result < 0) return result;
    result = edge_netfilter_read_be32(
        request, EDGE_NFTA_COMPAT_TYPE, &extension_type);
    if (result < 0) return result;
    if (family->family != EDGE_AF_INET || revision > UINT8_MAX ||
        extension_type > 1u)
        return -EDGE_LINUX_EOPNOTSUPP;
    result = edge_linux_netfilter_extension_revision(
        name, extension_type == 1u, (uint8_t)revision,
        &highest_revision);
    if (result < 0) return result;
    result = edge_netfilter_begin_reply(
        response, capacity, &offset,
        (uint16_t)(EDGE_NFNL_SUBSYS_NFT_COMPAT << 8u),
        port_id ? EDGE_NLM_F_MULTI : 0u,
        request->sequence, port_id, family->family, &start);
    if (result < 0) return result;
    result = edge_netfilter_append_attribute(
        response, capacity, &offset, EDGE_NFTA_COMPAT_NAME,
        name, (uint32_t)strlen(name) + 1u);
    if (result < 0) return result;
    encoded_revision = edge_netlink_be32(highest_revision);
    result = edge_netfilter_append_attribute(
        response, capacity, &offset, EDGE_NFTA_COMPAT_REVISION,
        &encoded_revision, sizeof(encoded_revision));
    if (result < 0) return result;
    encoded_type = edge_netlink_be32(extension_type);
    result = edge_netfilter_append_attribute(
        response, capacity, &offset, EDGE_NFTA_COMPAT_TYPE,
        &encoded_type, sizeof(encoded_type));
    if (result < 0) return result;
    edge_netfilter_finish_reply(response, start, offset);
    *response_length = offset;
    return 0;
}

int edge_linux_netfilter_respond_in_namespace(
    uint32_t network_namespace, uint32_t port_id,
    const void *payload, uint32_t length,
    void *response, uint32_t capacity, uint32_t *response_length) {
    const edge_netfilter_nlmsghdr_t *request =
        (const edge_netfilter_nlmsghdr_t *)payload;
    edge_netfilter_nlmsghdr_t reply;
    edge_nfgenmsg_t family;
    edge_nlattr_t attribute;
    uint32_t generation;
    uint8_t *output = (uint8_t *)response;
    uint16_t subsystem;
    uint16_t operation;
    uint8_t request_family;
    uint32_t required;

    if (!payload || !response || !response_length ||
        length < sizeof(*request))
        return -EDGE_LINUX_EINVAL;
    *response_length = 0;
    if (request->length < sizeof(*request) + sizeof(family) ||
        request->length > length ||
        edge_netlink_align(request->length) > length)
        return -EDGE_LINUX_EINVAL;
    request_family = ((const edge_nfgenmsg_t *)(request + 1))->family;
    edge_netfilter_lock();
    if (request->type == EDGE_NFNL_MSG_BATCH_BEGIN) {
        int result = edge_netfilter_transaction(
            network_namespace, (const uint8_t *)payload, length);

        edge_netfilter_unlock();
        return result;
    }
    subsystem = (uint16_t)((request->type >> 8u) & 0xffu);
    operation = (uint16_t)(request->type & 0xffu);
    if (subsystem == EDGE_NFNL_SUBSYS_CTNETLINK &&
        operation == EDGE_IPCTNL_MSG_CT_GET &&
        (request->flags & EDGE_NLM_F_DUMP) == EDGE_NLM_F_DUMP) {
        uint32_t offset = 0;
        uint32_t index;
        int result = 0;

        for (index = 0; index < EDGE_NETFILTER_CONNTRACK_MAX; ++index) {
            const edge_netfilter_conntrack_t *entry =
                &g_edge_netfilter_conntrack[index];

            if (!entry->used ||
                entry->original.network_namespace != network_namespace ||
                (request_family &&
                 request_family != entry->original.family))
                continue;
            result = edge_netfilter_append_conntrack(
                entry, request, port_id,
                output, capacity, &offset);
            if (result < 0) break;
        }
        if (result == 0)
            result = edge_netfilter_append_done(
                output, capacity, &offset, request->sequence, port_id);

        if (result == 0) *response_length = offset;
        edge_netfilter_unlock();
        return result;
    }
    if (subsystem == EDGE_NFNL_SUBSYS_CTNETLINK &&
        operation == EDGE_IPCTNL_MSG_CT_DELETE) {
        uint32_t index;

        for (index = 0; index < EDGE_NETFILTER_CONNTRACK_MAX; ++index) {
            edge_netfilter_conntrack_t *entry =
                &g_edge_netfilter_conntrack[index];

            if (entry->used &&
                entry->original.network_namespace == network_namespace &&
                (!request_family ||
                 request_family == entry->original.family))
                memset(entry, 0, sizeof(*entry));
        }
        edge_netfilter_unlock();
        return edge_netfilter_append_ack(
            request, port_id, output, capacity, response_length);
    }
    if (subsystem == EDGE_NFNL_SUBSYS_NFT_COMPAT && operation == 0u) {
        int result = edge_netfilter_compat_get(
            request, port_id, output, capacity, response_length);

        if (result == 0)
            result = edge_netfilter_append_ack(
                request, port_id, output, capacity, response_length);
        edge_netfilter_unlock();
        return result;
    }
    if (subsystem != EDGE_NFNL_SUBSYS_NFTABLES) {
        edge_netfilter_unlock();
        return -EDGE_LINUX_EOPNOTSUPP;
    }
    if (operation == EDGE_NFT_MSG_GETTABLE) {
        int result = edge_netfilter_get_tables(
            &g_edge_netfilter_state, network_namespace,
            request, port_id,
            output, capacity, response_length);

        if (result == 0)
            result = edge_netfilter_append_ack(
                request, port_id, output, capacity, response_length);
        edge_netfilter_unlock();
        return result;
    }
    if (operation == EDGE_NFT_MSG_GETCHAIN) {
        int result = edge_netfilter_get_chains(
            &g_edge_netfilter_state, network_namespace,
            request, port_id,
            output, capacity, response_length);

        if (result == 0)
            result = edge_netfilter_append_ack(
                request, port_id, output, capacity, response_length);
        edge_netfilter_unlock();
        return result;
    }
    if (operation == EDGE_NFT_MSG_GETRULE) {
        int result = edge_netfilter_get_rules(
            &g_edge_netfilter_state, network_namespace,
            request, port_id,
            output, capacity, response_length);

        if (result == 0)
            result = edge_netfilter_append_ack(
                request, port_id, output, capacity, response_length);
        edge_netfilter_unlock();
        return result;
    }
    if (operation == EDGE_NFT_MSG_GETSET ||
        operation == EDGE_NFT_MSG_GETSETELEM ||
        operation == EDGE_NFT_MSG_GETOBJ ||
        operation == EDGE_NFT_MSG_GETFLOWTABLE) {
        uint32_t offset = 0u;
        int result;

        if ((request->flags & EDGE_NLM_F_DUMP) != EDGE_NLM_F_DUMP) {
            edge_netfilter_unlock();
            return -EDGE_LINUX_ENOENT;
        }
        result = edge_netfilter_append_done(
            output, capacity, &offset, request->sequence, port_id);
        if (result == 0) *response_length = offset;
        edge_netfilter_unlock();
        return result;
    }
    if (operation != EDGE_NFT_MSG_GETGEN) {
        edge_netfilter_unlock();
        return -EDGE_LINUX_EINVAL;
    }

    required = (uint32_t)(sizeof(reply) + sizeof(family) +
                           sizeof(attribute) + sizeof(generation));
    if (capacity < required) {
        edge_netfilter_unlock();
        return -EDGE_LINUX_ENOBUFS;
    }
    memset(&reply, 0, sizeof(reply));
    memset(&family, 0, sizeof(family));
    memset(&attribute, 0, sizeof(attribute));
    reply.length = required;
    reply.type = (uint16_t)((EDGE_NFNL_SUBSYS_NFTABLES << 8u) |
                            EDGE_NFT_MSG_NEWGEN);
    reply.sequence = request->sequence;
    reply.port_id = port_id;
    attribute.length = (uint16_t)(sizeof(attribute) + sizeof(generation));
    attribute.type = EDGE_NFTA_GEN_ID;
    generation = edge_netlink_be32(g_edge_netfilter_state.generation);
    memcpy(output, &reply, sizeof(reply));
    memcpy(output + sizeof(reply), &family, sizeof(family));
    memcpy(output + sizeof(reply) + sizeof(family),
           &attribute, sizeof(attribute));
    memcpy(output + sizeof(reply) + sizeof(family) + sizeof(attribute),
           &generation, sizeof(generation));
    *response_length = required;
    edge_netfilter_unlock();
    return 0;
}

int edge_linux_netfilter_respond(
    uint32_t port_id, const void *payload, uint32_t length,
    void *response, uint32_t capacity, uint32_t *response_length) {
    return edge_linux_netfilter_respond_in_namespace(
        0u, port_id, payload, length,
        response, capacity, response_length);
}

typedef struct edge_netfilter_register {
    uint8_t bytes[16];
    uint8_t length;
} edge_netfilter_register_t;

static int edge_netfilter_find_buffer_attribute(
    const uint8_t *bytes, uint32_t length, uint16_t wanted,
    const uint8_t **data, uint32_t *data_length) {
    uint32_t offset = 0;

    if (!bytes) return -EDGE_LINUX_EINVAL;
    while (offset < length) {
        const edge_nlattr_t *attribute;
        uint32_t aligned;

        if (length - offset < sizeof(*attribute))
            return -EDGE_LINUX_EINVAL;
        attribute = (const edge_nlattr_t *)(bytes + offset);
        if (attribute->length < sizeof(*attribute) ||
            attribute->length > length - offset)
            return -EDGE_LINUX_EINVAL;
        if ((attribute->type & EDGE_NLA_TYPE_MASK) == wanted) {
            if (data) *data = bytes + offset + sizeof(*attribute);
            if (data_length)
                *data_length = attribute->length - sizeof(*attribute);
            return 0;
        }
        aligned = edge_netlink_align(attribute->length);
        if (aligned > length - offset) return -EDGE_LINUX_EINVAL;
        offset += aligned;
    }
    return -EDGE_LINUX_ENOENT;
}

static int edge_netfilter_buffer_be32(
    const uint8_t *bytes, uint32_t length, uint16_t attribute_type,
    uint32_t *value) {
    const uint8_t *data;
    uint32_t data_length;
    int result = edge_netfilter_find_buffer_attribute(
        bytes, length, attribute_type, &data, &data_length);

    if (result < 0) return result;
    if (data_length != sizeof(uint32_t)) return -EDGE_LINUX_EINVAL;
    if (value) *value = edge_netlink_from_be32(data);
    return 0;
}

static int edge_netfilter_payload_read(
    const edge_linux_netfilter_tuple_t *tuple,
    uint32_t base, uint32_t offset, uint32_t length,
    uint8_t output[16]) {
    uint8_t network_header[40];
    uint8_t transport_header[4];
    const uint8_t *source;
    uint32_t capacity;

    if (!tuple || !output || !length || length > 16u)
        return -EDGE_LINUX_EINVAL;
    memset(network_header, 0, sizeof(network_header));
    memset(transport_header, 0, sizeof(transport_header));
    if (tuple->family == EDGE_AF_INET) {
        network_header[0] = 0x45u;
        network_header[9] = tuple->protocol;
        memcpy(network_header + 12u, tuple->source_address, 4u);
        memcpy(network_header + 16u, tuple->destination_address, 4u);
        capacity = 20u;
    } else if (tuple->family == 10u) {
        network_header[0] = 0x60u;
        network_header[6] = tuple->protocol;
        memcpy(network_header + 8u, tuple->source_address, 16u);
        memcpy(network_header + 24u, tuple->destination_address, 16u);
        capacity = sizeof(network_header);
    } else {
        return -EDGE_LINUX_EAFNOSUPPORT;
    }
    transport_header[0] = (uint8_t)(tuple->source_port >> 8u);
    transport_header[1] = (uint8_t)tuple->source_port;
    transport_header[2] = (uint8_t)(tuple->destination_port >> 8u);
    transport_header[3] = (uint8_t)tuple->destination_port;
    if (base == EDGE_NFT_PAYLOAD_NETWORK_HEADER) {
        source = network_header;
    } else if (base == EDGE_NFT_PAYLOAD_TRANSPORT_HEADER) {
        source = transport_header;
        capacity = sizeof(transport_header);
    } else {
        return -EDGE_LINUX_EOPNOTSUPP;
    }
    if (offset > capacity || length > capacity - offset)
        return -EDGE_LINUX_EINVAL;
    memcpy(output, source + offset, length);
    return 0;
}

static int edge_netfilter_compare(
    const uint8_t *left, const uint8_t *right,
    uint32_t length, uint32_t operation) {
    int comparison = memcmp(left, right, length);

    switch (operation) {
        case EDGE_NFT_CMP_EQ: return comparison == 0;
        case EDGE_NFT_CMP_NEQ: return comparison != 0;
        case EDGE_NFT_CMP_LT: return comparison < 0;
        case EDGE_NFT_CMP_LTE: return comparison <= 0;
        case EDGE_NFT_CMP_GT: return comparison > 0;
        case EDGE_NFT_CMP_GTE: return comparison >= 0;
        default: return 0;
    }
}

static int edge_netfilter_apply_xt_nat_target(
    edge_linux_netfilter_tuple_t *tuple,
    enum edge_linux_netfilter_translation translation,
    const char *name, uint32_t revision,
    const uint8_t *info, uint32_t info_length) {
    uint32_t range_count;
    uint32_t flags;
    uint32_t address_offset = 0u;
    uint32_t port_offset = 0u;
    uint16_t port;
    int destination;
    int masquerade;
    int redirect;

    if (!tuple || !name || tuple->family != EDGE_AF_INET)
        return 0;
    masquerade = strcmp(name, "MASQUERADE") == 0;
    redirect = strcmp(name, "REDIRECT") == 0;
    destination = strcmp(name, "DNAT") == 0 || redirect;
    if (!destination && strcmp(name, "SNAT") != 0 &&
        !masquerade)
        return 0;
    if ((destination &&
         translation != EDGE_LINUX_NETFILTER_TRANSLATE_DESTINATION) ||
        (!destination &&
         translation != EDGE_LINUX_NETFILTER_TRANSLATE_SOURCE))
        return 0;
    if (revision > 2u) return 0;
    if (!info ||
        (revision == 0u && info_length < 20u) ||
        (revision == 1u && info_length < 40u) ||
        (revision == 2u && info_length < 44u))
        flags = 0u;
    else if (revision == 0u) {
        memcpy(&range_count, info, sizeof(range_count));
        memcpy(&flags, info + 4u, sizeof(flags));
        if (range_count != 1u) return 0;
        address_offset = 8u;
        port_offset = 16u;
    } else {
        memcpy(&flags, info, sizeof(flags));
        address_offset = 4u;
        port_offset = 36u;
    }
    if (masquerade && !(flags & EDGE_NF_NAT_RANGE_MAP_IPS)) {
        if (!g_edge_netfilter_masquerade_ipv4) return 0;
        memcpy(tuple->source_address,
               &g_edge_netfilter_masquerade_ipv4, 4u);
    } else if (redirect && !(flags & EDGE_NF_NAT_RANGE_MAP_IPS)) {
        static const uint8_t loopback[4] = {127u, 0u, 0u, 1u};

        memcpy(tuple->destination_address, loopback, sizeof(loopback));
    }
    if (!info ||
        (revision == 0u && info_length < 20u) ||
        (revision == 1u && info_length < 40u) ||
        (revision == 2u && info_length < 44u))
        return 1;
    if (flags & EDGE_NF_NAT_RANGE_MAP_IPS) {
        memcpy(destination ? tuple->destination_address :
                             tuple->source_address,
               info + address_offset, 4u);
    }
    if (flags & EDGE_NF_NAT_RANGE_PROTO_SPECIFIED) {
        memcpy(&port, info + port_offset, sizeof(port));
        port = (uint16_t)((port << 8u) | (port >> 8u));
        if (destination) tuple->destination_port = port;
        else tuple->source_port = port;
    }
    return 1;
}

static int edge_netfilter_tuple_is_tracked_locked(
    const edge_linux_netfilter_tuple_t *tuple) {
    uint32_t index;

    for (index = 0u; index < EDGE_NETFILTER_CONNTRACK_MAX; ++index) {
        edge_linux_netfilter_tuple_t reply;
        edge_linux_netfilter_tuple_t translated_reply;
        const edge_netfilter_conntrack_t *entry =
            &g_edge_netfilter_conntrack[index];

        if (!entry->used) continue;
        if (edge_netfilter_tuple_equal(tuple, &entry->original) ||
            edge_netfilter_tuple_equal(tuple, &entry->translated))
            return 1;
        edge_netfilter_tuple_reverse(&entry->original, &reply);
        edge_netfilter_tuple_reverse(&entry->translated,
                                     &translated_reply);
        if (edge_netfilter_tuple_equal(tuple, &reply) ||
            edge_netfilter_tuple_equal(tuple, &translated_reply))
            return 1;
    }
    return 0;
}

static uint16_t edge_netfilter_xt_address_type(
    const edge_linux_netfilter_tuple_t *tuple, const uint8_t address[16]) {
    uint32_t ipv4;

    if (tuple->family != EDGE_AF_INET) return 0u;
    memcpy(&ipv4, address, sizeof(ipv4));
    if (address[0] == 127u ||
        edge_linux_rtnetlink_ipv4_is_local_in_namespace(
            tuple->network_namespace, ipv4) ||
        edge_linux_rtnetlink_ipv4_is_local(ipv4))
        return EDGE_XT_ADDRTYPE_LOCAL;
    return 1u << 1u;
}

static int edge_netfilter_apply_xt_match(
    const edge_linux_netfilter_tuple_t *tuple, const char *name,
    uint32_t revision, const uint8_t *info, uint32_t info_length) {
    if (strcmp(name, "addrtype") == 0) {
        uint16_t source_mask;
        uint16_t destination_mask;
        uint32_t flags;
        int source_match;
        int destination_match;

        if (!info || (revision == 0u && info_length < 12u) ||
            (revision == 1u && info_length < 8u) || revision > 1u)
            return 0;
        memcpy(&source_mask, info, sizeof(source_mask));
        memcpy(&destination_mask, info + 2u,
               sizeof(destination_mask));
        memcpy(&flags, info + 4u, sizeof(flags));
        source_match = !source_mask ||
            (source_mask & edge_netfilter_xt_address_type(
                tuple, tuple->source_address)) != 0u;
        destination_match = !destination_mask ||
            (destination_mask & edge_netfilter_xt_address_type(
                tuple, tuple->destination_address)) != 0u;
        if (revision == 0u) {
            uint32_t invert_destination;

            if (flags) source_match = !source_match;
            memcpy(&invert_destination, info + 8u,
                   sizeof(invert_destination));
            if (invert_destination)
                destination_match = !destination_match;
        } else {
            if (flags & EDGE_XT_ADDRTYPE_INVERT_SOURCE)
                source_match = !source_match;
            if (flags & EDGE_XT_ADDRTYPE_INVERT_DESTINATION)
                destination_match = !destination_match;
        }
        return source_match && destination_match;
    }
    if (strcmp(name, "conntrack") == 0) {
        uint16_t match_flags;
        uint16_t invert_flags;
        uint16_t state_mask;
        uint16_t state;
        int matched;

        if (!info || revision < 1u || revision > 3u ||
            info_length < (revision == 3u ? 164u : 156u))
            return 0;
        memcpy(&match_flags, info + 148u, sizeof(match_flags));
        memcpy(&invert_flags, info + 150u, sizeof(invert_flags));
        if (revision == 1u)
            state_mask = info[152u];
        else
            memcpy(&state_mask, info + 152u, sizeof(state_mask));
        if (match_flags & ~EDGE_XT_CONNTRACK_STATE) return 0;
        if (!(match_flags & EDGE_XT_CONNTRACK_STATE)) return 1;
        state = edge_netfilter_tuple_is_tracked_locked(tuple) ?
            EDGE_XT_CONNTRACK_STATE_ESTABLISHED |
                EDGE_XT_CONNTRACK_STATE_RELATED :
            EDGE_XT_CONNTRACK_STATE_NEW;
        matched = (state_mask & state) != 0u;
        if (invert_flags & EDGE_XT_CONNTRACK_STATE) matched = !matched;
        return matched;
    }
    if (strcmp(name, "tcp") == 0 || strcmp(name, "udp") == 0 ||
        strcmp(name, "comment") == 0)
        return 1;
    return 0;
}

static int edge_netfilter_apply_implicit_nat(
    edge_linux_netfilter_tuple_t *tuple,
    enum edge_linux_netfilter_translation translation,
    const char *name, const uint8_t *data, uint32_t length,
    const edge_netfilter_register_t registers[5]) {
    uint32_t port_register = 0;
    int destination = strcmp(name, "redir") == 0;

    if ((!destination && strcmp(name, "masq") != 0) ||
        tuple->family != EDGE_AF_INET ||
        (destination &&
         translation != EDGE_LINUX_NETFILTER_TRANSLATE_DESTINATION) ||
        (!destination &&
         translation != EDGE_LINUX_NETFILTER_TRANSLATE_SOURCE))
        return 0;
    if (destination) {
        static const uint8_t loopback[4] = {127u, 0u, 0u, 1u};

        memcpy(tuple->destination_address, loopback, sizeof(loopback));
    } else {
        if (!g_edge_netfilter_masquerade_ipv4) return 0;
        memcpy(tuple->source_address,
               &g_edge_netfilter_masquerade_ipv4, 4u);
    }
    if (data &&
        edge_netfilter_buffer_be32(
            data, length,
            destination ? EDGE_NFTA_REDIR_REG_PROTO_MIN :
                          EDGE_NFTA_MASQ_REG_PROTO_MIN,
            &port_register) == 0 &&
        port_register < 5u && registers[port_register].length >= 2u) {
        uint16_t port = (uint16_t)(
            ((uint16_t)registers[port_register].bytes[0] << 8u) |
            registers[port_register].bytes[1]);

        if (destination) tuple->destination_port = port;
        else tuple->source_port = port;
    }
    return 1;
}

static int edge_netfilter_apply_native_nat(
    edge_linux_netfilter_tuple_t *tuple,
    enum edge_linux_netfilter_translation translation,
    const uint8_t *data, uint32_t length,
    const edge_netfilter_register_t registers[5]) {
    uint32_t type;
    uint32_t family;
    uint32_t address_register = 0;
    uint32_t port_register = 0;
    int destination;

    if (edge_netfilter_buffer_be32(
            data, length, EDGE_NFTA_NAT_TYPE, &type) < 0 ||
        edge_netfilter_buffer_be32(
            data, length, EDGE_NFTA_NAT_FAMILY, &family) < 0)
        return 0;
    destination = type == EDGE_NFT_NAT_DNAT;
    if ((!destination && type != EDGE_NFT_NAT_SNAT) ||
        (destination &&
         translation != EDGE_LINUX_NETFILTER_TRANSLATE_DESTINATION) ||
        (!destination &&
         translation != EDGE_LINUX_NETFILTER_TRANSLATE_SOURCE) ||
        family != tuple->family)
        return 0;
    if (edge_netfilter_buffer_be32(
            data, length, EDGE_NFTA_NAT_REG_ADDR_MIN,
            &address_register) == 0 &&
        address_register < 5u &&
        registers[address_register].length >=
            (tuple->family == EDGE_AF_INET ? 4u : 16u)) {
        memcpy(destination ? tuple->destination_address :
                             tuple->source_address,
               registers[address_register].bytes,
               tuple->family == EDGE_AF_INET ? 4u : 16u);
    }
    if (edge_netfilter_buffer_be32(
            data, length, EDGE_NFTA_NAT_REG_PROTO_MIN,
            &port_register) == 0 &&
        port_register < 5u && registers[port_register].length >= 2u) {
        uint16_t port = (uint16_t)(
            ((uint16_t)registers[port_register].bytes[0] << 8u) |
            registers[port_register].bytes[1]);
        if (destination) tuple->destination_port = port;
        else tuple->source_port = port;
    }
    return 1;
}

static int edge_netfilter_evaluate_rule(
    const edge_netfilter_rule_t *rule,
    edge_linux_netfilter_tuple_t *tuple,
    enum edge_linux_netfilter_translation translation,
    uint32_t *verdict) {
    edge_netfilter_register_t registers[5];
    const uint8_t *expressions;
    uint32_t expressions_length;
    uint32_t offset = 0;

    memset(registers, 0, sizeof(registers));
    if (verdict) *verdict = EDGE_NFT_VERDICT_NONE;
    if (edge_netfilter_find_buffer_attribute(
            rule->attributes, rule->attribute_length,
            EDGE_NFTA_RULE_EXPRESSIONS,
            &expressions, &expressions_length) < 0)
        return 0;
    while (offset < expressions_length) {
        const edge_nlattr_t *element;
        const uint8_t *expression;
        const uint8_t *name_data;
        const uint8_t *data;
        uint32_t expression_length;
        uint32_t name_length;
        uint32_t data_length;
        uint32_t aligned;
        char name[32];

        if (expressions_length - offset < sizeof(*element)) return 0;
        element = (const edge_nlattr_t *)(expressions + offset);
        if (element->length < sizeof(*element) ||
            element->length > expressions_length - offset ||
            (element->type & EDGE_NLA_TYPE_MASK) != EDGE_NFTA_LIST_ELEM)
            return 0;
        expression = expressions + offset + sizeof(*element);
        expression_length = element->length - sizeof(*element);
        if (edge_netfilter_find_buffer_attribute(
                expression, expression_length, EDGE_NFTA_EXPR_NAME,
                &name_data, &name_length) < 0 ||
            !name_length || name_length > sizeof(name))
            return 0;
        memcpy(name, name_data, name_length);
        name[sizeof(name) - 1u] = '\0';
        if (name[name_length - 1u] != '\0') return 0;
        data = 0;
        data_length = 0;
        (void)edge_netfilter_find_buffer_attribute(
            expression, expression_length, EDGE_NFTA_EXPR_DATA,
            &data, &data_length);
        if (strcmp(name, "payload") == 0 && data) {
            uint32_t destination_register;
            uint32_t base;
            uint32_t payload_offset;
            uint32_t payload_length;

            if (edge_netfilter_buffer_be32(
                    data, data_length, EDGE_NFTA_PAYLOAD_DREG,
                    &destination_register) < 0 ||
                edge_netfilter_buffer_be32(
                    data, data_length, EDGE_NFTA_PAYLOAD_BASE,
                    &base) < 0 ||
                edge_netfilter_buffer_be32(
                    data, data_length, EDGE_NFTA_PAYLOAD_OFFSET,
                    &payload_offset) < 0 ||
                edge_netfilter_buffer_be32(
                    data, data_length, EDGE_NFTA_PAYLOAD_LEN,
                    &payload_length) < 0 ||
                destination_register >= 5u || payload_length > 16u ||
                edge_netfilter_payload_read(
                    tuple, base, payload_offset, payload_length,
                    registers[destination_register].bytes) < 0)
                return 0;
            registers[destination_register].length =
                (uint8_t)payload_length;
        } else if (strcmp(name, "meta") == 0 && data) {
            uint32_t destination_register;
            uint32_t key;
            edge_netfilter_register_t *result_register;

            if (edge_netfilter_buffer_be32(
                    data, data_length, EDGE_NFTA_META_DREG,
                    &destination_register) < 0 ||
                edge_netfilter_buffer_be32(
                    data, data_length, EDGE_NFTA_META_KEY, &key) < 0 ||
                destination_register >= 5u)
                return 0;
            result_register = &registers[destination_register];
            memset(result_register, 0, sizeof(*result_register));
            if (key == EDGE_NFT_META_IIF || key == EDGE_NFT_META_OIF) {
                uint32_t interface_index = (uint32_t)(
                    key == EDGE_NFT_META_IIF ? tuple->input_ifindex :
                                              tuple->output_ifindex);

                memcpy(result_register->bytes, &interface_index,
                       sizeof(interface_index));
                result_register->length = sizeof(interface_index);
            } else if (key == EDGE_NFT_META_IIFNAME ||
                       key == EDGE_NFT_META_OIFNAME) {
                const char *interface_name =
                    key == EDGE_NFT_META_IIFNAME ?
                    tuple->input_interface : tuple->output_interface;

                memcpy(result_register->bytes, interface_name,
                       sizeof(tuple->input_interface));
                result_register->length = sizeof(tuple->input_interface);
            } else if (key == EDGE_NFT_META_NFPROTO) {
                result_register->bytes[0] = tuple->family;
                result_register->length = 1u;
            } else if (key == EDGE_NFT_META_L4PROTO) {
                result_register->bytes[0] = tuple->protocol;
                result_register->length = 1u;
            } else {
                return 0;
            }
        } else if (strcmp(name, "bitwise") == 0 && data) {
            const uint8_t *mask_data;
            const uint8_t *xor_data;
            const uint8_t *mask;
            const uint8_t *xor_value;
            uint32_t source_register;
            uint32_t destination_register;
            uint32_t operation_length;
            uint32_t mask_data_length;
            uint32_t xor_data_length;
            uint32_t mask_length;
            uint32_t xor_length;
            uint32_t byte;

            if (edge_netfilter_buffer_be32(
                    data, data_length, EDGE_NFTA_BITWISE_SREG,
                    &source_register) < 0 ||
                edge_netfilter_buffer_be32(
                    data, data_length, EDGE_NFTA_BITWISE_DREG,
                    &destination_register) < 0 ||
                edge_netfilter_buffer_be32(
                    data, data_length, EDGE_NFTA_BITWISE_LEN,
                    &operation_length) < 0 ||
                source_register >= 5u || destination_register >= 5u ||
                operation_length > sizeof(registers[0].bytes) ||
                operation_length > registers[source_register].length ||
                edge_netfilter_find_buffer_attribute(
                    data, data_length, EDGE_NFTA_BITWISE_MASK,
                    &mask_data, &mask_data_length) < 0 ||
                edge_netfilter_find_buffer_attribute(
                    mask_data, mask_data_length, EDGE_NFTA_DATA_VALUE,
                    &mask, &mask_length) < 0 ||
                edge_netfilter_find_buffer_attribute(
                    data, data_length, EDGE_NFTA_BITWISE_XOR,
                    &xor_data, &xor_data_length) < 0 ||
                edge_netfilter_find_buffer_attribute(
                    xor_data, xor_data_length, EDGE_NFTA_DATA_VALUE,
                    &xor_value, &xor_length) < 0 ||
                mask_length < operation_length ||
                xor_length < operation_length)
                return 0;
            for (byte = 0; byte < operation_length; ++byte)
                registers[destination_register].bytes[byte] =
                    (uint8_t)((registers[source_register].bytes[byte] &
                               mask[byte]) ^ xor_value[byte]);
            registers[destination_register].length =
                (uint8_t)operation_length;
        } else if (strcmp(name, "cmp") == 0 && data) {
            const uint8_t *comparison_data;
            const uint8_t *value;
            uint32_t source_register;
            uint32_t operation;
            uint32_t comparison_length;
            uint32_t value_length;

            if (edge_netfilter_buffer_be32(
                    data, data_length, EDGE_NFTA_CMP_SREG,
                    &source_register) < 0 ||
                edge_netfilter_buffer_be32(
                    data, data_length, EDGE_NFTA_CMP_OP,
                    &operation) < 0 || source_register >= 5u ||
                edge_netfilter_find_buffer_attribute(
                    data, data_length, EDGE_NFTA_CMP_DATA,
                    &comparison_data, &comparison_length) < 0 ||
                edge_netfilter_find_buffer_attribute(
                    comparison_data, comparison_length,
                    EDGE_NFTA_DATA_VALUE, &value, &value_length) < 0 ||
                value_length != registers[source_register].length ||
                !edge_netfilter_compare(
                    registers[source_register].bytes, value,
                    value_length, operation))
                return 0;
        } else if (strcmp(name, "immediate") == 0 && data) {
            const uint8_t *immediate_data;
            const uint8_t *value;
            const uint8_t *verdict_data;
            uint32_t destination_register;
            uint32_t immediate_length;
            uint32_t value_length;
            uint32_t verdict_length;
            uint32_t verdict_code;

            if (edge_netfilter_buffer_be32(
                    data, data_length, EDGE_NFTA_IMMEDIATE_DREG,
                    &destination_register) < 0 ||
                destination_register >= 5u ||
                edge_netfilter_find_buffer_attribute(
                    data, data_length, EDGE_NFTA_IMMEDIATE_DATA,
                    &immediate_data, &immediate_length) < 0)
                return 0;
            if (destination_register == 0u &&
                edge_netfilter_find_buffer_attribute(
                    immediate_data, immediate_length,
                    EDGE_NFTA_DATA_VERDICT,
                    &verdict_data, &verdict_length) == 0) {
                if (edge_netfilter_buffer_be32(
                        verdict_data, verdict_length,
                        EDGE_NFTA_VERDICT_CODE, &verdict_code) < 0)
                    return 0;
                if (verdict_code == EDGE_NF_ACCEPT ||
                    verdict_code == EDGE_NF_DROP) {
                    if (verdict) *verdict = verdict_code;
                    return 1;
                }
                return 0;
            }
            if (edge_netfilter_find_buffer_attribute(
                    immediate_data, immediate_length,
                    EDGE_NFTA_DATA_VALUE, &value, &value_length) < 0 ||
                value_length > sizeof(registers[0].bytes))
                return 0;
            memcpy(registers[destination_register].bytes,
                   value, value_length);
            registers[destination_register].length = (uint8_t)value_length;
        } else if (strcmp(name, "target") == 0 && data) {
            const uint8_t *target_name;
            const uint8_t *target_info;
            uint32_t target_revision = 0u;
            uint32_t target_name_length;
            uint32_t target_info_length;

            if (edge_netfilter_find_buffer_attribute(
                    data, data_length, EDGE_NFTA_TARGET_NAME,
                    &target_name, &target_name_length) == 0 &&
                target_name_length &&
                target_name[target_name_length - 1u] == '\0') {
                target_info = 0;
                target_info_length = 0;
                (void)edge_netfilter_buffer_be32(
                    data, data_length, EDGE_NFTA_TARGET_REVISION,
                    &target_revision);
                (void)edge_netfilter_find_buffer_attribute(
                    data, data_length, EDGE_NFTA_TARGET_INFO,
                    &target_info, &target_info_length);
                if (edge_netfilter_apply_xt_nat_target(
                        tuple, translation, (const char *)target_name,
                        target_revision,
                        target_info, target_info_length))
                    return 1;
            }
        } else if (strcmp(name, "match") == 0 && data) {
            const uint8_t *match_name;
            const uint8_t *match_info;
            uint32_t match_revision = 0u;
            uint32_t match_name_length;
            uint32_t match_info_length;

            if (edge_netfilter_find_buffer_attribute(
                    data, data_length, EDGE_NFTA_MATCH_NAME,
                    &match_name, &match_name_length) < 0 ||
                !match_name_length ||
                match_name[match_name_length - 1u] != '\0')
                return 0;
            match_info = 0;
            match_info_length = 0u;
            (void)edge_netfilter_buffer_be32(
                data, data_length, EDGE_NFTA_MATCH_REVISION,
                &match_revision);
            (void)edge_netfilter_find_buffer_attribute(
                data, data_length, EDGE_NFTA_MATCH_INFO,
                &match_info, &match_info_length);
            if (!edge_netfilter_apply_xt_match(
                    tuple, (const char *)match_name, match_revision,
                    match_info, match_info_length))
                return 0;
        } else if (strcmp(name, "nat") == 0 && data) {
            if (edge_netfilter_apply_native_nat(
                    tuple, translation, data, data_length, registers))
                return 1;
        } else if ((strcmp(name, "masq") == 0 ||
                    strcmp(name, "redir") == 0) &&
                   edge_netfilter_apply_implicit_nat(
                       tuple, translation, name, data, data_length,
                       registers)) {
            return 1;
        } else if (strcmp(name, "counter") != 0) {
            /* An unknown expression cannot safely be treated as a match. */
            return 0;
        }
        aligned = edge_netlink_align(element->length);
        if (aligned > expressions_length - offset) return 0;
        offset += aligned;
    }
    return 0;
}

static int edge_netfilter_packet_tuple(
    const edge_net_packet_t *packet,
    edge_linux_netfilter_tuple_t *tuple) {
    edge_net_device_snapshot_t snapshot;
    uint8_t ethernet[18];
    uint8_t network[40];
    uint8_t ports[4];
    uint32_t network_offset;
    uint32_t transport_offset;
    uint16_t protocol;

    if (!packet || !tuple) return -1;
    protocol = packet->metadata.protocol;
    if (packet->metadata.network_header == 0u &&
        (protocol == 0x0800u || protocol == 0x86ddu)) {
        network_offset = 0u;
    } else {
        network_offset = packet->metadata.network_header ?
            packet->metadata.network_header : 14u;
        if (network_offset < 14u || packet->total_length < 14u ||
            edge_net_packet_read(
                packet, 0u, ethernet, 14u) != EDGE_NET_OK)
            return -1;
        protocol = (uint16_t)(
            ((uint16_t)ethernet[12] << 8u) | ethernet[13]);
        if (protocol == 0x8100u || protocol == 0x88a8u) {
            if (packet->total_length < sizeof(ethernet) ||
                edge_net_packet_read(
                    packet, 14u, ethernet + 14u, 4u) != EDGE_NET_OK)
                return -1;
            protocol = (uint16_t)(
                ((uint16_t)ethernet[16] << 8u) | ethernet[17]);
            network_offset = 18u;
        }
    }
    memset(tuple, 0, sizeof(*tuple));
    tuple->network_namespace = packet->metadata.network_namespace;
    tuple->input_ifindex = packet->metadata.input_ifindex;
    tuple->output_ifindex = packet->metadata.output_ifindex;
    if (tuple->input_ifindex > 0 &&
        edge_net_device_snapshot(tuple->input_ifindex, &snapshot) ==
            EDGE_NET_OK)
        memcpy(tuple->input_interface, snapshot.configuration.name,
               sizeof(tuple->input_interface));
    if (tuple->output_ifindex > 0 &&
        edge_net_device_snapshot(tuple->output_ifindex, &snapshot) ==
            EDGE_NET_OK)
        memcpy(tuple->output_interface, snapshot.configuration.name,
               sizeof(tuple->output_interface));
    if (protocol == 0x0800u) {
        uint32_t header_length;

        if (packet->total_length < network_offset + 20u ||
            edge_net_packet_read(
                packet, network_offset, network, 20u) != EDGE_NET_OK ||
            (network[0] >> 4u) != 4u)
            return -1;
        header_length = (uint32_t)(network[0] & 0x0fu) * 4u;
        if (header_length < 20u ||
            packet->total_length < network_offset + header_length)
            return -1;
        tuple->family = EDGE_AF_INET;
        tuple->protocol = network[9];
        memcpy(tuple->source_address, network + 12u, 4u);
        memcpy(tuple->destination_address, network + 16u, 4u);
        transport_offset = network_offset + header_length;
    } else if (protocol == 0x86ddu) {
        if (packet->total_length < network_offset + sizeof(network) ||
            edge_net_packet_read(
                packet, network_offset, network,
                sizeof(network)) != EDGE_NET_OK ||
            (network[0] >> 4u) != 6u)
            return -1;
        tuple->family = EDGE_AF_INET6;
        tuple->protocol = network[6];
        memcpy(tuple->source_address, network + 8u, 16u);
        memcpy(tuple->destination_address, network + 24u, 16u);
        transport_offset = network_offset + sizeof(network);
    } else {
        return -1;
    }
    if ((tuple->protocol == 6u || tuple->protocol == 17u) &&
        packet->total_length >= transport_offset + sizeof(ports) &&
        edge_net_packet_read(
            packet, transport_offset, ports, sizeof(ports)) == EDGE_NET_OK) {
        tuple->source_port = (uint16_t)(
            ((uint16_t)ports[0] << 8u) | ports[1]);
        tuple->destination_port = (uint16_t)(
            ((uint16_t)ports[2] << 8u) | ports[3]);
    }
    return 0;
}

static int edge_netfilter_family_matches(
    uint8_t chain_family, uint8_t packet_family, uint8_t hook) {
    if (chain_family == packet_family || chain_family == 1u) return 1;
    return chain_family == 5u && hook == EDGE_NF_INET_INGRESS;
}

static uint32_t edge_netfilter_hook_verdict_locked(
    edge_linux_netfilter_tuple_t *tuple, uint8_t hook) {
    const edge_netfilter_chain_t *chains[EDGE_NETFILTER_CHAIN_MAX];
    uint32_t chain_count = 0u;
    uint32_t chain_index;
    uint32_t index;

    for (index = 0; index < EDGE_NETFILTER_CHAIN_MAX; ++index) {
        const edge_netfilter_chain_t *chain =
            &g_edge_netfilter_state.chains[index];
        uint32_t insert;

        if (!chain->used || !chain->base_chain || chain->hook != hook ||
            chain->network_namespace != tuple->network_namespace ||
            !edge_netfilter_family_matches(
                chain->family, tuple->family, hook))
            continue;
        insert = chain_count;
        while (insert > 0u &&
               chains[insert - 1u]->priority > chain->priority) {
            chains[insert] = chains[insert - 1u];
            --insert;
        }
        chains[insert] = chain;
        ++chain_count;
    }
    for (chain_index = 0; chain_index < chain_count; ++chain_index) {
        const edge_netfilter_chain_t *chain = chains[chain_index];
        uint32_t chain_verdict = EDGE_NFT_VERDICT_NONE;

        for (index = 0; index < EDGE_NETFILTER_RULE_MAX; ++index) {
            const edge_netfilter_rule_t *rule =
                &g_edge_netfilter_state.rules[index];
            uint32_t verdict = EDGE_NFT_VERDICT_NONE;
            enum edge_linux_netfilter_translation translation =
                hook == EDGE_NF_INET_PRE_ROUTING ||
                hook == EDGE_NF_INET_LOCAL_IN ?
                EDGE_LINUX_NETFILTER_TRANSLATE_DESTINATION :
                EDGE_LINUX_NETFILTER_TRANSLATE_SOURCE;

            if (!rule->used ||
                rule->network_namespace != tuple->network_namespace ||
                strcmp(rule->table, chain->table) != 0 ||
                strcmp(rule->chain, chain->name) != 0)
                continue;
            if (edge_netfilter_evaluate_rule(
                    rule, tuple, translation, &verdict) &&
                verdict != EDGE_NFT_VERDICT_NONE) {
                chain_verdict = verdict;
                break;
            }
        }
        if (chain_verdict == EDGE_NF_DROP ||
            (chain_verdict == EDGE_NFT_VERDICT_NONE &&
             chain->policy == EDGE_NF_DROP))
            return EDGE_NF_DROP;
    }
    return EDGE_NF_ACCEPT;
}

static enum edge_net_hook_verdict edge_netfilter_packet_hook(
    enum edge_net_hook_stage stage, edge_net_packet_t *packet,
    void *context) {
    edge_linux_netfilter_tuple_t tuple;
    uint32_t verdict = EDGE_NF_ACCEPT;

    (void)context;
    if (edge_netfilter_packet_tuple(packet, &tuple) < 0)
        return EDGE_NET_VERDICT_ACCEPT;
    edge_netfilter_lock();
    if (stage == EDGE_NET_HOOK_INGRESS) {
        verdict = edge_netfilter_hook_verdict_locked(
            &tuple, EDGE_NF_INET_INGRESS);
        if (verdict == EDGE_NF_ACCEPT)
            verdict = edge_netfilter_hook_verdict_locked(
                &tuple, EDGE_NF_INET_PRE_ROUTING);
    } else if (stage == EDGE_NET_HOOK_LOCAL_INPUT) {
        verdict = edge_netfilter_hook_verdict_locked(
            &tuple, EDGE_NF_INET_LOCAL_IN);
    } else if (stage == EDGE_NET_HOOK_FORWARD) {
        verdict = edge_netfilter_hook_verdict_locked(
            &tuple, EDGE_NF_INET_FORWARD);
    } else if (stage == EDGE_NET_HOOK_LOCAL_OUTPUT) {
        verdict = edge_netfilter_hook_verdict_locked(
            &tuple, EDGE_NF_INET_LOCAL_OUT);
    } else if (stage == EDGE_NET_HOOK_EGRESS) {
        verdict = edge_netfilter_hook_verdict_locked(
            &tuple, EDGE_NF_INET_POST_ROUTING);
    }
    edge_netfilter_unlock();
    return verdict == EDGE_NF_DROP ?
        EDGE_NET_VERDICT_DROP : EDGE_NET_VERDICT_ACCEPT;
}

int edge_linux_netfilter_enable_datapath(void) {
    edge_net_hook_registration_t registration;
    uint32_t handle;
    uint32_t stage;

    memset(&registration, 0, sizeof(registration));
    registration.network_namespace = EDGE_NET_NAMESPACE_ALL;
    registration.priority = -200;
    registration.callback = edge_netfilter_packet_hook;
    for (stage = EDGE_NET_HOOK_INGRESS;
         stage <= EDGE_NET_HOOK_EGRESS; ++stage) {
        registration.stage = (enum edge_net_hook_stage)stage;
        if (edge_net_hook_register(&registration, &handle) != EDGE_NET_OK)
            return -EDGE_LINUX_ENOSPC;
    }
    return 0;
}

static int edge_netfilter_rule_has_masquerade(
    const edge_netfilter_rule_t *rule) {
    const uint8_t *expressions;
    uint32_t expressions_length;
    uint32_t offset = 0;

    if (!rule ||
        edge_netfilter_find_buffer_attribute(
            rule->attributes, rule->attribute_length,
            EDGE_NFTA_RULE_EXPRESSIONS,
            &expressions, &expressions_length) < 0)
        return 0;
    while (offset < expressions_length) {
        const edge_nlattr_t *element;
        const uint8_t *expression;
        const uint8_t *name_data;
        const uint8_t *data;
        uint32_t expression_length;
        uint32_t name_length;
        uint32_t data_length;
        uint32_t aligned;

        if (expressions_length - offset < sizeof(*element)) return 0;
        element = (const edge_nlattr_t *)(expressions + offset);
        if (element->length < sizeof(*element) ||
            element->length > expressions_length - offset)
            return 0;
        expression = expressions + offset + sizeof(*element);
        expression_length = element->length - sizeof(*element);
        if (edge_netfilter_find_buffer_attribute(
                expression, expression_length, EDGE_NFTA_EXPR_NAME,
                &name_data, &name_length) == 0 &&
            name_length == sizeof("masq") &&
            memcmp(name_data, "masq", sizeof("masq")) == 0)
            return 1;
        data = 0;
        data_length = 0;
        if (edge_netfilter_find_buffer_attribute(
                expression, expression_length, EDGE_NFTA_EXPR_NAME,
                &name_data, &name_length) == 0 &&
            name_length == sizeof("target") &&
            memcmp(name_data, "target", sizeof("target")) == 0 &&
            edge_netfilter_find_buffer_attribute(
                expression, expression_length, EDGE_NFTA_EXPR_DATA,
                &data, &data_length) == 0) {
            const uint8_t *target_name;
            uint32_t target_name_length;

            if (edge_netfilter_find_buffer_attribute(
                    data, data_length, EDGE_NFTA_TARGET_NAME,
                    &target_name, &target_name_length) == 0 &&
                target_name_length == sizeof("MASQUERADE") &&
                memcmp(target_name, "MASQUERADE",
                       sizeof("MASQUERADE")) == 0)
                return 1;
        }
        aligned = edge_netlink_align(element->length);
        if (aligned > expressions_length - offset) return 0;
        offset += aligned;
    }
    return 0;
}

int edge_linux_netfilter_translate_local(
    edge_linux_netfilter_tuple_t *tuple,
    enum edge_linux_netfilter_translation translation) {
    uint32_t index;
    uint32_t ipv4_source = 0;
    uint32_t ipv4_destination = 0;
    int ipv4_destination_is_local = 0;
    int translated = 0;
    edge_linux_netfilter_tuple_t original;

    if (!tuple ||
        (translation != EDGE_LINUX_NETFILTER_TRANSLATE_DESTINATION &&
         translation != EDGE_LINUX_NETFILTER_TRANSLATE_SOURCE))
        return -EDGE_LINUX_EINVAL;
    if (tuple->family == EDGE_AF_INET) {
        memcpy(&ipv4_source, tuple->source_address,
               sizeof(ipv4_source));
        memcpy(&ipv4_destination, tuple->destination_address,
               sizeof(ipv4_destination));
        if (translation == EDGE_LINUX_NETFILTER_TRANSLATE_SOURCE &&
            tuple->network_namespace &&
            tuple->destination_address[0] == 127u)
            return 0;
        ipv4_destination_is_local =
            edge_linux_rtnetlink_ipv4_is_local(ipv4_destination) ||
            edge_rtnl_ipv4_is_connected(
                tuple->network_namespace, ipv4_source,
                ipv4_destination);
        if (tuple->network_namespace && ipv4_destination_is_local)
            return 0;
    }
    edge_netfilter_lock();
    if (edge_netfilter_conntrack_apply_locked(tuple, translation)) {
        edge_netfilter_unlock();
        return 1;
    }
    original = *tuple;
    if (tuple->family == EDGE_AF_INET && !ipv4_destination)
        memcpy(&ipv4_destination, tuple->destination_address,
               sizeof(ipv4_destination));
    for (index = 0; index < EDGE_NETFILTER_RULE_MAX; ++index) {
        const edge_netfilter_rule_t *rule =
            &g_edge_netfilter_state.rules[index];

        if (!rule->used ||
            rule->network_namespace != tuple->network_namespace ||
            rule->family != tuple->family)
            continue;
        {
            uint32_t verdict;

            if (edge_netfilter_evaluate_rule(
                    rule, tuple, translation, &verdict) &&
                verdict == EDGE_NFT_VERDICT_NONE) {
                translated = 1;
                edge_netfilter_conntrack_record_locked(&original, tuple);
                break;
            }
        }
    }
    if (!translated &&
        translation == EDGE_LINUX_NETFILTER_TRANSLATE_SOURCE &&
        tuple->network_namespace && tuple->family == EDGE_AF_INET &&
        g_edge_netfilter_masquerade_ipv4 &&
        !ipv4_destination_is_local) {
        for (index = 0; index < EDGE_NETFILTER_RULE_MAX; ++index) {
            const edge_netfilter_rule_t *rule =
                &g_edge_netfilter_state.rules[index];

            if (!rule->used || rule->network_namespace != 0u ||
                rule->family != tuple->family ||
                !edge_netfilter_rule_has_masquerade(rule))
                continue;
            memcpy(tuple->source_address,
                   &g_edge_netfilter_masquerade_ipv4, 4u);
            edge_netfilter_conntrack_record_locked(&original, tuple);
            translated = 1;
            break;
        }
    }
    edge_netfilter_unlock();
    return translated;
}

int edge_linux_netfilter_translate_forward(
    edge_linux_netfilter_tuple_t *tuple,
    enum edge_linux_netfilter_translation translation) {
    edge_net_device_snapshot_t output_snapshot;
    edge_linux_netfilter_tuple_t original;
    uint32_t previous_masquerade_address = 0u;
    uint32_t output_masquerade_address = 0u;
    uint8_t hook;
    uint32_t verdict;
    int translated;

    if (!tuple ||
        (translation != EDGE_LINUX_NETFILTER_TRANSLATE_DESTINATION &&
         translation != EDGE_LINUX_NETFILTER_TRANSLATE_SOURCE))
        return -EDGE_LINUX_EINVAL;
    hook = translation == EDGE_LINUX_NETFILTER_TRANSLATE_DESTINATION ?
        EDGE_NF_INET_PRE_ROUTING : EDGE_NF_INET_POST_ROUTING;
    if (translation == EDGE_LINUX_NETFILTER_TRANSLATE_SOURCE &&
        tuple->family == EDGE_AF_INET && tuple->output_ifindex > 0 &&
        edge_net_device_snapshot(
            tuple->output_ifindex, &output_snapshot) == EDGE_NET_OK &&
        output_snapshot.configuration.network_namespace ==
            tuple->network_namespace)
        output_masquerade_address = output_snapshot.ipv4_address;
    edge_netfilter_lock();
    if (edge_netfilter_conntrack_apply_locked(tuple, translation)) {
        edge_netfilter_unlock();
        return 1;
    }
    if (output_masquerade_address) {
        previous_masquerade_address = g_edge_netfilter_masquerade_ipv4;
        g_edge_netfilter_masquerade_ipv4 = output_masquerade_address;
    }
    original = *tuple;
    verdict = edge_netfilter_hook_verdict_locked(tuple, hook);
    if (verdict == EDGE_NF_DROP) {
        if (output_masquerade_address)
            g_edge_netfilter_masquerade_ipv4 =
                previous_masquerade_address;
        edge_netfilter_unlock();
        return -EDGE_LINUX_EPERM;
    }
    translated = !edge_netfilter_tuple_equal(&original, tuple);
    if (translated)
        edge_netfilter_conntrack_record_locked(&original, tuple);
    if (output_masquerade_address)
        g_edge_netfilter_masquerade_ipv4 = previous_masquerade_address;
    edge_netfilter_unlock();
    return translated;
}

void edge_linux_netfilter_set_ipv4_masquerade_address(uint32_t address) {
    edge_netfilter_lock();
    g_edge_netfilter_masquerade_ipv4 = address;
    edge_netfilter_unlock();
}

int edge_linux_conntrack_snapshot(
    uint32_t network_namespace, uint32_t ordinal,
    edge_linux_conntrack_snapshot_t *snapshot) {
    uint32_t index;
    uint32_t current = 0;

    if (!snapshot) return -EDGE_LINUX_EINVAL;
    edge_netfilter_lock();
    for (index = 0; index < EDGE_NETFILTER_CONNTRACK_MAX; ++index) {
        const edge_netfilter_conntrack_t *entry =
            &g_edge_netfilter_conntrack[index];

        if (!entry->used ||
            entry->original.network_namespace != network_namespace)
            continue;
        if (current++ != ordinal) continue;
        memset(snapshot, 0, sizeof(*snapshot));
        snapshot->identifier = entry->identifier;
        snapshot->packets = entry->packets;
        snapshot->original = entry->original;
        snapshot->translated = entry->translated;
        edge_netfilter_unlock();
        return 0;
    }
    edge_netfilter_unlock();
    return -EDGE_LINUX_ENOENT;
}

static int edge_rtnl_find_attribute(
    const edge_netfilter_nlmsghdr_t *message, uint32_t payload_offset,
    uint16_t wanted, const uint8_t **data, uint32_t *data_length) {
    const uint8_t *bytes = (const uint8_t *)message;
    uint32_t offset = payload_offset;

    if (!message || message->length < offset) return -EDGE_LINUX_EINVAL;
    while (offset < message->length) {
        const edge_nlattr_t *attribute;
        uint32_t aligned;

        if (message->length - offset < sizeof(*attribute))
            return -EDGE_LINUX_EINVAL;
        attribute = (const edge_nlattr_t *)(bytes + offset);
        if (attribute->length < sizeof(*attribute) ||
            attribute->length > message->length - offset)
            return -EDGE_LINUX_EINVAL;
        if ((attribute->type & EDGE_NLA_TYPE_MASK) == wanted) {
            if (data) *data = bytes + offset + sizeof(*attribute);
            if (data_length)
                *data_length = attribute->length - sizeof(*attribute);
            return 0;
        }
        aligned = edge_netlink_align(attribute->length);
        if (aligned > message->length - offset)
            return -EDGE_LINUX_EINVAL;
        offset += aligned;
    }
    return -EDGE_LINUX_ENOENT;
}

static int edge_rtnl_read_name(
    const edge_netfilter_nlmsghdr_t *message, uint32_t payload_offset,
    uint16_t type, char output[EDGE_RTNL_NAME_MAX]) {
    const uint8_t *data;
    uint32_t length;
    uint32_t index;
    int result = edge_rtnl_find_attribute(
        message, payload_offset, type, &data, &length);

    if (result < 0) return result;
    if (!length || length > EDGE_RTNL_NAME_MAX)
        return -EDGE_LINUX_EINVAL;
    memset(output, 0, EDGE_RTNL_NAME_MAX);
    for (index = 0; index < length && index + 1u < EDGE_RTNL_NAME_MAX;
         ++index) {
        output[index] = (char)data[index];
        if (!data[index]) break;
    }
    if (!output[0]) return -EDGE_LINUX_EINVAL;
    if (index == length && length < EDGE_RTNL_NAME_MAX)
        output[length] = 0;
    else if (index + 1u == EDGE_RTNL_NAME_MAX &&
             data[EDGE_RTNL_NAME_MAX - 1u] != 0)
        return -EDGE_LINUX_EINVAL;
    return 0;
}

static int edge_rtnl_read_u32(
    const edge_netfilter_nlmsghdr_t *message, uint32_t payload_offset,
    uint16_t type, uint32_t *value) {
    const uint8_t *data;
    uint32_t length;
    int result = edge_rtnl_find_attribute(
        message, payload_offset, type, &data, &length);

    if (result < 0) return result;
    if (length != sizeof(uint32_t)) return -EDGE_LINUX_EINVAL;
    if (value) memcpy(value, data, sizeof(uint32_t));
    return 0;
}

static int edge_rtnl_copy_attribute(
    const edge_netfilter_nlmsghdr_t *message, uint32_t payload_offset,
    uint16_t type, void *output, uint32_t expected_length) {
    const uint8_t *data;
    uint32_t length;
    int result = edge_rtnl_find_attribute(
        message, payload_offset, type, &data, &length);

    if (result < 0) return result;
    if (length != expected_length) return -EDGE_LINUX_EINVAL;
    if (output) memcpy(output, data, length);
    return 0;
}

static int edge_rtnl_decode_multipath(
    const edge_netfilter_nlmsghdr_t *request, uint32_t payload_offset,
    uint32_t address_length, edge_rtnl_route_t *entry) {
    const uint8_t *multipath;
    uint32_t multipath_length;
    uint32_t offset = 0u;
    int result;

    result = edge_rtnl_find_attribute(
        request, payload_offset, EDGE_RTA_MULTIPATH,
        &multipath, &multipath_length);
    if (result == -EDGE_LINUX_ENOENT) return 0;
    if (result < 0) return result;
    if (!multipath_length) return -EDGE_LINUX_EINVAL;
    while (offset < multipath_length) {
        const edge_rtnl_wire_nexthop_t *wire;
        edge_rtnl_nexthop_t *nexthop;
        uint32_t attribute_offset;

        if (multipath_length - offset < sizeof(*wire) ||
            entry->nexthop_count >= EDGE_RTNEXTHOP_MAX)
            return -EDGE_LINUX_EINVAL;
        wire = (const edge_rtnl_wire_nexthop_t *)(multipath + offset);
        if (wire->length < sizeof(*wire) ||
            wire->length > multipath_length - offset ||
            wire->output_ifindex <= 0)
            return -EDGE_LINUX_EINVAL;
        nexthop = &entry->nexthops[entry->nexthop_count];
        memset(nexthop, 0, sizeof(*nexthop));
        nexthop->output_ifindex = wire->output_ifindex;
        nexthop->flags = wire->flags;
        nexthop->hops = wire->hops;
        attribute_offset = sizeof(*wire);
        while (attribute_offset < wire->length) {
            const edge_nlattr_t *attribute;
            uint32_t aligned;

            if (wire->length - attribute_offset < sizeof(*attribute))
                return -EDGE_LINUX_EINVAL;
            attribute = (const edge_nlattr_t *)
                ((const uint8_t *)wire + attribute_offset);
            if (attribute->length < sizeof(*attribute) ||
                attribute->length > wire->length - attribute_offset)
                return -EDGE_LINUX_EINVAL;
            if ((attribute->type & EDGE_NLA_TYPE_MASK) ==
                    EDGE_RTA_GATEWAY) {
                if (attribute->length !=
                        sizeof(*attribute) + address_length)
                    return -EDGE_LINUX_EINVAL;
                memcpy(nexthop->gateway,
                       (const uint8_t *)attribute + sizeof(*attribute),
                       address_length);
            }
            aligned = edge_netlink_align(attribute->length);
            if (aligned > wire->length - attribute_offset)
                return -EDGE_LINUX_EINVAL;
            attribute_offset += aligned;
        }
        if (attribute_offset != wire->length)
            return -EDGE_LINUX_EINVAL;
        ++entry->nexthop_count;
        offset += edge_netlink_align(wire->length);
    }
    return offset == multipath_length ? 0 : -EDGE_LINUX_EINVAL;
}

static uint32_t edge_rtnl_route_table(
    const edge_netfilter_nlmsghdr_t *request,
    const edge_rtnl_rtmsg_t *route, uint32_t payload_offset) {
    uint32_t table = route->table;

    if (edge_rtnl_read_u32(
            request, payload_offset, EDGE_RTA_TABLE, &table) < 0)
        table = route->table;
    return table;
}

static edge_rtnl_nexthop_object_t *edge_rtnl_nexthop_find_locked(
    uint32_t network_namespace, uint32_t id) {
    uint32_t ordinal;

    if (!id) return 0;
    for (ordinal = 0; ordinal < EDGE_RTNL_NEXTHOP_OBJECT_MAX; ++ordinal) {
        edge_rtnl_nexthop_object_t *object =
            &g_edge_rtnl_nexthops[ordinal];

        if (object->used && object->network_namespace == network_namespace &&
            object->id == id)
            return object;
    }
    return 0;
}

static int edge_rtnl_decode_nexthop(
    uint32_t network_namespace,
    const edge_netfilter_nlmsghdr_t *request,
    edge_rtnl_nexthop_object_t *object) {
    const edge_rtnl_nhmsg_t *message =
        (const edge_rtnl_nhmsg_t *)(request + 1);
    uint32_t payload_offset = sizeof(*request) + sizeof(*message);
    const uint8_t *group = 0;
    uint32_t group_length = 0u;
    const uint8_t *blackhole = 0;
    uint32_t blackhole_length = 0u;
    uint16_t group_type = 0u;
    uint32_t address_length;
    uint32_t ordinal;
    int result;

    if (!object ||
        (message->family != 0u && message->family != EDGE_AF_INET &&
         message->family != EDGE_AF_INET6))
        return -EDGE_LINUX_EAFNOSUPPORT;
    memset(object, 0, sizeof(*object));
    object->used = 1u;
    object->network_namespace = network_namespace;
    object->family = message->family;
    object->scope = message->scope;
    object->protocol = message->protocol;
    object->flags = message->flags;
    result = edge_rtnl_read_u32(
        request, payload_offset, EDGE_NHA_ID, &object->id);
    if (result < 0 || !object->id)
        return result < 0 ? result : -EDGE_LINUX_EINVAL;
    result = edge_rtnl_find_attribute(
        request, payload_offset, EDGE_NHA_GROUP, &group, &group_length);
    if (result < 0 && result != -EDGE_LINUX_ENOENT) return result;
    result = edge_rtnl_find_attribute(
        request, payload_offset, EDGE_NHA_BLACKHOLE,
        &blackhole, &blackhole_length);
    if (result < 0 && result != -EDGE_LINUX_ENOENT) return result;
    if (result == 0) {
        if (blackhole_length) return -EDGE_LINUX_EINVAL;
        object->blackhole = 1u;
    }
    if (group) {
        const uint8_t *group_type_data;
        uint32_t group_type_length;

        if (object->blackhole || !group_length ||
            group_length % sizeof(edge_rtnl_nexthop_group_wire_t) != 0u ||
            group_length / sizeof(edge_rtnl_nexthop_group_wire_t) >
                EDGE_RTNEXTHOP_MAX)
            return -EDGE_LINUX_EINVAL;
        result = edge_rtnl_find_attribute(
            request, payload_offset, EDGE_NHA_GROUP_TYPE,
            &group_type_data, &group_type_length);
        if (result == 0) {
            if (group_type_length != sizeof(group_type))
                return -EDGE_LINUX_EINVAL;
            memcpy(&group_type, group_type_data, sizeof(group_type));
            if (group_type != 0u) return -EDGE_LINUX_EOPNOTSUPP;
        } else if (result != -EDGE_LINUX_ENOENT) {
            return result;
        }
        object->group_type = (uint8_t)group_type;
        object->member_count = (uint8_t)(
            group_length / sizeof(edge_rtnl_nexthop_group_wire_t));
        for (ordinal = 0; ordinal < object->member_count; ++ordinal) {
            edge_rtnl_nexthop_group_wire_t member;

            memcpy(&member,
                   group + ordinal * sizeof(member), sizeof(member));
            if (!member.id) return -EDGE_LINUX_EINVAL;
            object->members[ordinal].id = member.id;
            object->members[ordinal].weight = member.weight;
        }
        return 0;
    }
    if (object->blackhole) return 0;
    result = edge_rtnl_read_u32(
        request, payload_offset, EDGE_NHA_OIF,
        (uint32_t *)&object->output_ifindex);
    if (result < 0 || object->output_ifindex <= 0)
        return result < 0 ? result : -EDGE_LINUX_EINVAL;
    address_length = object->family == EDGE_AF_INET6 ? 16u : 4u;
    result = edge_rtnl_copy_attribute(
        request, payload_offset, EDGE_NHA_GATEWAY,
        object->gateway, address_length);
    if (result < 0 && result != -EDGE_LINUX_ENOENT) return result;
    return 0;
}

static int edge_rtnl_nexthop_object_validate_locked(
    const edge_rtnl_nexthop_object_t *object) {
    uint32_t ordinal;

    if (!object) return -EDGE_LINUX_EINVAL;
    if (object->member_count) {
        for (ordinal = 0; ordinal < object->member_count; ++ordinal) {
            edge_rtnl_nexthop_object_t *member =
                edge_rtnl_nexthop_find_locked(
                    object->network_namespace,
                    object->members[ordinal].id);

            if (!member || member->member_count || member->blackhole)
                return -EDGE_LINUX_ENOENT;
            if (object->family && member->family &&
                object->family != member->family)
                return -EDGE_LINUX_EINVAL;
        }
    } else if (!object->blackhole) {
        edge_rtnl_link_t *link =
            edge_rtnl_find_index(object->output_ifindex);

        if (object->output_ifindex == 1)
            return 0;
        if (object->output_ifindex == 2 &&
            object->network_namespace == 0u)
            return 0;
        if (!link || link->network_namespace != object->network_namespace)
            return -EDGE_LINUX_ENODEV;
    }
    return 0;
}

static int edge_rtnl_apply_nexthop(
    uint32_t network_namespace,
    const edge_netfilter_nlmsghdr_t *request, int deleting) {
    edge_rtnl_nexthop_object_t decoded;
    edge_rtnl_nexthop_object_t *existing;
    edge_rtnl_nexthop_object_t *free_object = 0;
    uint32_t ordinal;
    int result;

    if (deleting) {
        memset(&decoded, 0, sizeof(decoded));
        decoded.network_namespace = network_namespace;
        result = edge_rtnl_read_u32(
            request, sizeof(*request) + sizeof(edge_rtnl_nhmsg_t),
            EDGE_NHA_ID, &decoded.id);
        if (result < 0 || !decoded.id)
            return result < 0 ? result : -EDGE_LINUX_EINVAL;
    } else {
        result = edge_rtnl_decode_nexthop(
            network_namespace, request, &decoded);
        if (result < 0) return result;
    }
    edge_rtnl_lock();
    existing = edge_rtnl_nexthop_find_locked(
        network_namespace, decoded.id);
    if (deleting) {
        if (!existing) {
            edge_rtnl_unlock();
            return -EDGE_LINUX_ENOENT;
        }
        for (ordinal = 0; ordinal < EDGE_RTNL_ROUTE_MAX; ++ordinal) {
            if (g_edge_rtnl_routes[ordinal].used &&
                g_edge_rtnl_routes[ordinal].network_namespace ==
                    network_namespace &&
                g_edge_rtnl_routes[ordinal].nexthop_id == decoded.id) {
                edge_rtnl_unlock();
                return -EDGE_LINUX_EBUSY;
            }
        }
        for (ordinal = 0; ordinal < EDGE_RTNL_NEXTHOP_OBJECT_MAX;
             ++ordinal) {
            edge_rtnl_nexthop_object_t *group_object =
                &g_edge_rtnl_nexthops[ordinal];
            uint32_t member_ordinal;

            if (!group_object->used ||
                group_object->network_namespace != network_namespace)
                continue;
            for (member_ordinal = 0;
                 member_ordinal < group_object->member_count;
                 ++member_ordinal) {
                if (group_object->members[member_ordinal].id == decoded.id) {
                    edge_rtnl_unlock();
                    return -EDGE_LINUX_EBUSY;
                }
            }
        }
        memset(existing, 0, sizeof(*existing));
        edge_rtnl_unlock();
        return 0;
    }
    result = edge_rtnl_nexthop_object_validate_locked(&decoded);
    if (result < 0) {
        edge_rtnl_unlock();
        return result;
    }
    if (existing) {
        uint32_t route_ordinal;

        if (request->flags & EDGE_NLM_F_EXCL) {
            edge_rtnl_unlock();
            return -EDGE_LINUX_EEXIST;
        }
        for (route_ordinal = 0; route_ordinal < EDGE_RTNL_ROUTE_MAX;
             ++route_ordinal) {
            const edge_rtnl_route_t *route =
                &g_edge_rtnl_routes[route_ordinal];

            if (route->used &&
                route->network_namespace == network_namespace &&
                route->nexthop_id == decoded.id && decoded.family &&
                route->family != decoded.family) {
                edge_rtnl_unlock();
                return -EDGE_LINUX_EBUSY;
            }
        }
        if (decoded.member_count || decoded.blackhole) {
            for (route_ordinal = 0;
                 route_ordinal < EDGE_RTNL_NEXTHOP_OBJECT_MAX;
                 ++route_ordinal) {
                const edge_rtnl_nexthop_object_t *group_object =
                    &g_edge_rtnl_nexthops[route_ordinal];
                uint32_t member_ordinal;

                if (!group_object->used ||
                    group_object->network_namespace != network_namespace ||
                    group_object == existing)
                    continue;
                for (member_ordinal = 0;
                     member_ordinal < group_object->member_count;
                     ++member_ordinal) {
                    if (group_object->members[member_ordinal].id ==
                            decoded.id) {
                        edge_rtnl_unlock();
                        return -EDGE_LINUX_EBUSY;
                    }
                }
            }
        }
        *existing = decoded;
        edge_rtnl_unlock();
        return 0;
    }
    for (ordinal = 0; ordinal < EDGE_RTNL_NEXTHOP_OBJECT_MAX; ++ordinal) {
        if (!g_edge_rtnl_nexthops[ordinal].used) {
            free_object = &g_edge_rtnl_nexthops[ordinal];
            break;
        }
    }
    if (!free_object) {
        edge_rtnl_unlock();
        return -EDGE_LINUX_ENOSPC;
    }
    *free_object = decoded;
    edge_rtnl_unlock();
    return 0;
}

static int edge_rtnl_decode_route(
    uint32_t network_namespace,
    const edge_netfilter_nlmsghdr_t *request,
    edge_rtnl_route_t *entry) {
    const edge_rtnl_rtmsg_t *route =
        (const edge_rtnl_rtmsg_t *)(request + 1);
    uint32_t payload_offset = sizeof(*request) + sizeof(*route);
    uint32_t address_length;
    int result;

    if (!entry || (route->family != EDGE_AF_INET &&
                   route->family != EDGE_AF_INET6))
        return -EDGE_LINUX_EAFNOSUPPORT;
    address_length = route->family == EDGE_AF_INET ? 4u : 16u;
    if (route->destination_length > address_length * 8u ||
        route->source_length > address_length * 8u)
        return -EDGE_LINUX_EINVAL;
    memset(entry, 0, sizeof(*entry));
    entry->used = 1u;
    entry->network_namespace = network_namespace;
    entry->family = route->family;
    entry->destination_length = route->destination_length;
    entry->source_length = route->source_length;
    entry->protocol = route->protocol;
    entry->scope = route->scope;
    entry->type = route->type ? route->type : EDGE_RTN_UNICAST;
    entry->tos = route->tos;
    entry->table = edge_rtnl_route_table(request, route, payload_offset);
    if (!entry->table) entry->table = EDGE_RT_TABLE_MAIN;

    result = edge_rtnl_copy_attribute(
        request, payload_offset, EDGE_RTA_DST,
        entry->destination, address_length);
    if (result < 0 && result != -EDGE_LINUX_ENOENT) return result;
    if (entry->destination_length && result == -EDGE_LINUX_ENOENT)
        return -EDGE_LINUX_EINVAL;
    result = edge_rtnl_copy_attribute(
        request, payload_offset, EDGE_RTA_SRC,
        entry->source, address_length);
    if (result < 0 && result != -EDGE_LINUX_ENOENT) return result;
    result = edge_rtnl_copy_attribute(
        request, payload_offset, EDGE_RTA_GATEWAY,
        entry->gateway, address_length);
    if (result < 0 && result != -EDGE_LINUX_ENOENT) return result;
    result = edge_rtnl_copy_attribute(
        request, payload_offset, EDGE_RTA_PREFSRC,
        entry->preferred_source, address_length);
    if (result < 0 && result != -EDGE_LINUX_ENOENT) return result;
    result = edge_rtnl_read_u32(
        request, payload_offset, EDGE_RTA_IIF,
        (uint32_t *)&entry->input_ifindex);
    if (result < 0 && result != -EDGE_LINUX_ENOENT) return result;
    result = edge_rtnl_read_u32(
        request, payload_offset, EDGE_RTA_OIF,
        (uint32_t *)&entry->output_ifindex);
    if (result < 0 && result != -EDGE_LINUX_ENOENT) return result;
    result = edge_rtnl_read_u32(
        request, payload_offset, EDGE_RTA_PRIORITY, &entry->metric);
    if (result < 0 && result != -EDGE_LINUX_ENOENT) return result;
    result = edge_rtnl_read_u32(
        request, payload_offset, EDGE_RTA_MARK, &entry->mark);
    if (result < 0 && result != -EDGE_LINUX_ENOENT) return result;
    result = edge_rtnl_read_u32(
        request, payload_offset, EDGE_RTA_NH_ID, &entry->nexthop_id);
    if (result < 0 && result != -EDGE_LINUX_ENOENT) return result;
    result = edge_rtnl_decode_multipath(
        request, payload_offset, address_length, entry);
    if (result < 0) return result;
    if ((entry->nexthop_count || entry->nexthop_id) &&
        (entry->output_ifindex ||
         (entry->nexthop_count && entry->nexthop_id) ||
         !edge_rtnl_address_is_zero(entry->gateway, address_length)))
        return -EDGE_LINUX_EINVAL;
    if (entry->nexthop_id) {
        edge_rtnl_nexthop_object_t *object;

        edge_rtnl_lock();
        object = edge_rtnl_nexthop_find_locked(
            network_namespace, entry->nexthop_id);
        result = object &&
            (!object->family || object->family == entry->family) ?
            0 : -EDGE_LINUX_ENOENT;
        edge_rtnl_unlock();
        if (result < 0) return result;
    }
    return 0;
}

static int edge_rtnl_route_equal(
    const edge_rtnl_route_t *first, const edge_rtnl_route_t *second) {
    edge_rtnl_route_t a = *first;
    edge_rtnl_route_t b = *second;

    a.used = b.used = 0u;
    return memcmp(&a, &b, sizeof(a)) == 0;
}

static int edge_rtnl_route_delete_matches(
    const edge_rtnl_route_t *installed,
    const edge_rtnl_route_t *selector) {
    uint32_t address_length =
        selector->family == EDGE_AF_INET ? 4u : 16u;

    if (installed->network_namespace != selector->network_namespace ||
        installed->family != selector->family ||
        installed->table != selector->table ||
        installed->destination_length != selector->destination_length ||
        memcmp(installed->destination, selector->destination,
               address_length) != 0 ||
        (selector->source_length &&
         (installed->source_length != selector->source_length ||
          memcmp(installed->source, selector->source,
                 address_length) != 0)) ||
        (selector->type != EDGE_RTN_UNICAST &&
         installed->type != selector->type) ||
        (selector->input_ifindex &&
         installed->input_ifindex != selector->input_ifindex) ||
        (selector->output_ifindex &&
         installed->output_ifindex != selector->output_ifindex) ||
        (selector->metric && installed->metric != selector->metric) ||
        (selector->mark && installed->mark != selector->mark) ||
        (!edge_rtnl_address_is_zero(selector->gateway, address_length) &&
         memcmp(installed->gateway, selector->gateway,
                address_length) != 0) ||
        (!edge_rtnl_address_is_zero(
             selector->preferred_source, address_length) &&
         memcmp(installed->preferred_source, selector->preferred_source,
                address_length) != 0))
        return 0;
    return 1;
}

static int edge_rtnl_store_route(
    const edge_rtnl_route_t *entry, uint16_t flags, int deleting) {
    uint32_t ordinal;
    int32_t free_ordinal = -1;

    edge_rtnl_lock();
    for (ordinal = 0; ordinal < EDGE_RTNL_ROUTE_MAX; ++ordinal) {
        if (!g_edge_rtnl_routes[ordinal].used) {
            if (free_ordinal < 0) free_ordinal = (int32_t)ordinal;
            continue;
        }
        if (!(deleting ? edge_rtnl_route_delete_matches(
                           &g_edge_rtnl_routes[ordinal], entry) :
                       edge_rtnl_route_equal(
                           &g_edge_rtnl_routes[ordinal], entry)))
            continue;
        if (deleting) {
            memset(&g_edge_rtnl_routes[ordinal], 0,
                   sizeof(g_edge_rtnl_routes[ordinal]));
            edge_rtnl_unlock();
            return 0;
        }
        if (flags & EDGE_NLM_F_EXCL) {
            edge_rtnl_unlock();
            return -EDGE_LINUX_EEXIST;
        }
        g_edge_rtnl_routes[ordinal] = *entry;
        edge_rtnl_unlock();
        return 0;
    }
    if (deleting) {
        edge_rtnl_unlock();
        return -EDGE_LINUX_ESRCH;
    }
    if (free_ordinal < 0) {
        edge_rtnl_unlock();
        return -EDGE_LINUX_ENOBUFS;
    }
    g_edge_rtnl_routes[free_ordinal] = *entry;
    edge_rtnl_unlock();
    return 0;
}

static int edge_rtnl_decode_rule(
    uint32_t network_namespace,
    const edge_netfilter_nlmsghdr_t *request,
    edge_rtnl_rule_t *entry) {
    const edge_rtnl_rulemsg_t *rule =
        (const edge_rtnl_rulemsg_t *)(request + 1);
    uint32_t payload_offset = sizeof(*request) + sizeof(*rule);
    uint32_t address_length;
    int result;

    if (!entry || (rule->family != EDGE_AF_INET &&
                   rule->family != EDGE_AF_INET6))
        return -EDGE_LINUX_EAFNOSUPPORT;
    address_length = rule->family == EDGE_AF_INET ? 4u : 16u;
    if (rule->destination_length > address_length * 8u ||
        rule->source_length > address_length * 8u)
        return -EDGE_LINUX_EINVAL;
    memset(entry, 0, sizeof(*entry));
    entry->used = 1u;
    entry->network_namespace = network_namespace;
    entry->family = rule->family;
    entry->destination_length = rule->destination_length;
    entry->source_length = rule->source_length;
    entry->action = rule->action ? rule->action : EDGE_FR_ACT_TO_TBL;
    entry->table = rule->table;
    result = edge_rtnl_read_u32(
        request, payload_offset, EDGE_FRA_TABLE, &entry->table);
    if (result < 0 && result != -EDGE_LINUX_ENOENT) return result;
    result = edge_rtnl_read_u32(
        request, payload_offset, EDGE_FRA_PRIORITY, &entry->priority);
    if (result < 0 && result != -EDGE_LINUX_ENOENT) return result;
    result = edge_rtnl_read_u32(
        request, payload_offset, EDGE_FRA_FWMARK, &entry->mark);
    if (result < 0 && result != -EDGE_LINUX_ENOENT) return result;
    result = edge_rtnl_read_u32(
        request, payload_offset, EDGE_FRA_FWMASK, &entry->mark_mask);
    if (result < 0 && result != -EDGE_LINUX_ENOENT) return result;
    if (entry->mark && !entry->mark_mask) entry->mark_mask = UINT32_MAX;
    result = edge_rtnl_copy_attribute(
        request, payload_offset, EDGE_FRA_DST,
        entry->destination, address_length);
    if (result < 0 && result != -EDGE_LINUX_ENOENT) return result;
    result = edge_rtnl_copy_attribute(
        request, payload_offset, EDGE_FRA_SRC,
        entry->source, address_length);
    if (result < 0 && result != -EDGE_LINUX_ENOENT) return result;
    result = edge_rtnl_read_name(
        request, payload_offset, EDGE_FRA_IIFNAME,
        entry->input_interface);
    if (result < 0 && result != -EDGE_LINUX_ENOENT) return result;
    result = edge_rtnl_read_name(
        request, payload_offset, EDGE_FRA_OIFNAME,
        entry->output_interface);
    if (result < 0 && result != -EDGE_LINUX_ENOENT) return result;
    result = edge_rtnl_copy_attribute(
        request, payload_offset, EDGE_FRA_UID_RANGE,
        &entry->uid_range, sizeof(entry->uid_range));
    if (result == -EDGE_LINUX_ENOENT) {
        entry->uid_range.start = 0u;
        entry->uid_range.end = UINT32_MAX;
    } else if (result < 0) {
        return result;
    }
    return 0;
}

static int edge_rtnl_rule_equal(
    const edge_rtnl_rule_t *first, const edge_rtnl_rule_t *second) {
    edge_rtnl_rule_t a = *first;
    edge_rtnl_rule_t b = *second;

    a.used = b.used = 0u;
    return memcmp(&a, &b, sizeof(a)) == 0;
}

static int edge_rtnl_rule_delete_matches(
    const edge_rtnl_rule_t *installed,
    const edge_rtnl_rule_t *selector) {
    if (installed->network_namespace != selector->network_namespace ||
        installed->family != selector->family ||
        (selector->priority &&
         installed->priority != selector->priority) ||
        (selector->table && installed->table != selector->table) ||
        (selector->source_length &&
         (installed->source_length != selector->source_length ||
          memcmp(installed->source, selector->source,
                 selector->family == EDGE_AF_INET ? 4u : 16u) != 0)) ||
        (selector->destination_length &&
         (installed->destination_length != selector->destination_length ||
          memcmp(installed->destination, selector->destination,
                 selector->family == EDGE_AF_INET ? 4u : 16u) != 0)) ||
        (selector->mark_mask &&
         (installed->mark != selector->mark ||
          installed->mark_mask != selector->mark_mask)) ||
        (selector->input_interface[0] &&
         strcmp(installed->input_interface,
                selector->input_interface) != 0) ||
        (selector->output_interface[0] &&
         strcmp(installed->output_interface,
                selector->output_interface) != 0) ||
        ((selector->uid_range.start ||
          selector->uid_range.end != UINT32_MAX) &&
         (installed->uid_range.start != selector->uid_range.start ||
          installed->uid_range.end != selector->uid_range.end)))
        return 0;
    return 1;
}

static int edge_rtnl_apply_rule(
    uint32_t network_namespace,
    const edge_netfilter_nlmsghdr_t *request, int deleting) {
    edge_rtnl_rule_t entry;
    uint32_t ordinal;
    int32_t free_ordinal = -1;
    int result = edge_rtnl_decode_rule(
        network_namespace, request, &entry);

    if (result < 0) return result;
    if (!deleting && !entry.table && entry.action == EDGE_FR_ACT_TO_TBL)
        return -EDGE_LINUX_EINVAL;
    edge_rtnl_lock();
    for (ordinal = 0; ordinal < EDGE_RTNL_RULE_MAX; ++ordinal) {
        if (!g_edge_rtnl_rules[ordinal].used) {
            if (free_ordinal < 0) free_ordinal = (int32_t)ordinal;
            continue;
        }
        if (!(deleting ? edge_rtnl_rule_delete_matches(
                           &g_edge_rtnl_rules[ordinal], &entry) :
                       edge_rtnl_rule_equal(
                           &g_edge_rtnl_rules[ordinal], &entry)))
            continue;
        if (deleting) {
            memset(&g_edge_rtnl_rules[ordinal], 0,
                   sizeof(g_edge_rtnl_rules[ordinal]));
            edge_rtnl_unlock();
            return 0;
        }
        if (request->flags & EDGE_NLM_F_EXCL) {
            edge_rtnl_unlock();
            return -EDGE_LINUX_EEXIST;
        }
        g_edge_rtnl_rules[ordinal] = entry;
        edge_rtnl_unlock();
        return 0;
    }
    if (deleting) {
        edge_rtnl_unlock();
        return -EDGE_LINUX_ESRCH;
    }
    if (free_ordinal < 0) {
        edge_rtnl_unlock();
        return -EDGE_LINUX_ENOBUFS;
    }
    g_edge_rtnl_rules[free_ordinal] = entry;
    edge_rtnl_unlock();
    return 0;
}

static edge_rtnl_link_t *edge_rtnl_find_index(int32_t index) {
    uint32_t ordinal;

    for (ordinal = 0; ordinal < EDGE_RTNL_LINK_MAX; ++ordinal) {
        edge_rtnl_link_t *link = &g_edge_rtnl_links[ordinal];

        if (link->used && link->index == index) return link;
    }
    return 0;
}

static edge_rtnl_link_t *edge_rtnl_find_name(
    uint32_t network_namespace, const char *name) {
    uint32_t ordinal;

    for (ordinal = 0; ordinal < EDGE_RTNL_LINK_MAX; ++ordinal) {
        edge_rtnl_link_t *link = &g_edge_rtnl_links[ordinal];

        if (link->used &&
            link->network_namespace == network_namespace &&
            strcmp(link->name, name) == 0)
            return link;
    }
    return 0;
}

static int edge_rtnl_ipv4_is_connected(
    uint32_t network_namespace, uint32_t source, uint32_t destination) {
    const uint8_t *source_bytes = (const uint8_t *)&source;
    const uint8_t *destination_bytes = (const uint8_t *)&destination;
    uint32_t ordinal;
    int connected = 0;

    if (!network_namespace || !source || !destination) return 0;
    edge_rtnl_lock();
    for (ordinal = 0; ordinal < EDGE_RTNL_LINK_MAX; ++ordinal) {
        const edge_rtnl_link_t *link = &g_edge_rtnl_links[ordinal];
        const uint8_t *link_bytes;
        uint32_t bit;

        if (!link->used ||
            link->network_namespace != network_namespace ||
            link->ipv4_address != source ||
            !link->prefix_length || link->prefix_length > 32u)
            continue;
        link_bytes = (const uint8_t *)&link->ipv4_address;
        connected = 1;
        for (bit = 0; bit < link->prefix_length; ++bit) {
            uint8_t mask = (uint8_t)(1u << (7u - (bit % 8u)));

            if ((link_bytes[bit / 8u] & mask) !=
                (destination_bytes[bit / 8u] & mask)) {
                connected = 0;
                break;
            }
        }
        if (connected && memcmp(source_bytes, link_bytes, 4u) == 0)
            break;
    }
    edge_rtnl_unlock();
    return connected;
}

static int edge_rtnl_parse_kind(
    const edge_netfilter_nlmsghdr_t *message, uint32_t payload_offset,
    char kind[EDGE_RTNL_KIND_MAX], const uint8_t **info_data,
    uint32_t *info_data_length) {
    const uint8_t *linkinfo;
    uint32_t linkinfo_length;
    uint32_t offset = 0;
    int result = edge_rtnl_find_attribute(
        message, payload_offset, EDGE_IFLA_LINKINFO,
        &linkinfo, &linkinfo_length);

    if (result < 0) return result;
    if (info_data) *info_data = 0;
    if (info_data_length) *info_data_length = 0;
    while (offset < linkinfo_length) {
        const edge_nlattr_t *attribute;
        uint32_t data_length;
        uint32_t index;

        if (linkinfo_length - offset < sizeof(*attribute))
            return -EDGE_LINUX_EINVAL;
        attribute = (const edge_nlattr_t *)(linkinfo + offset);
        if (attribute->length < sizeof(*attribute) ||
            attribute->length > linkinfo_length - offset)
            return -EDGE_LINUX_EINVAL;
        if ((attribute->type & EDGE_NLA_TYPE_MASK) == EDGE_IFLA_INFO_KIND) {
            data_length = attribute->length - sizeof(*attribute);
            if (!data_length || data_length >= EDGE_RTNL_KIND_MAX)
                return -EDGE_LINUX_EINVAL;
            memset(kind, 0, EDGE_RTNL_KIND_MAX);
            for (index = 0; index < data_length; ++index) {
                kind[index] = (char)linkinfo[offset + sizeof(*attribute) + index];
                if (!kind[index]) break;
            }
            if (!kind[0]) return -EDGE_LINUX_EINVAL;
        } else if ((attribute->type & EDGE_NLA_TYPE_MASK) ==
                   EDGE_IFLA_INFO_DATA) {
            if (info_data)
                *info_data = linkinfo + offset + sizeof(*attribute);
            if (info_data_length)
                *info_data_length = attribute->length - sizeof(*attribute);
        }
        offset += edge_netlink_align(attribute->length);
    }
    return kind[0] ? 0 : -EDGE_LINUX_ENOENT;
}

static int edge_rtnl_parse_bridge_port(
    const uint8_t *attributes, uint32_t attributes_length,
    edge_rtnl_bridge_port_settings_t *settings) {
    uint32_t offset = 0u;

    if (!settings || (attributes_length && !attributes))
        return -EDGE_LINUX_EINVAL;
    while (offset < attributes_length) {
        const edge_nlattr_t *attribute;
        uint32_t data_length;
        uint16_t type;
        uint8_t value;

        if (attributes_length - offset < sizeof(*attribute))
            return -EDGE_LINUX_EINVAL;
        attribute = (const edge_nlattr_t *)(attributes + offset);
        if (attribute->length < sizeof(*attribute) ||
            attribute->length > attributes_length - offset)
            return -EDGE_LINUX_EINVAL;
        data_length = attribute->length - sizeof(*attribute);
        type = attribute->type & EDGE_NLA_TYPE_MASK;
        if (type == EDGE_IFLA_BRPORT_STATE ||
            type == EDGE_IFLA_BRPORT_MODE ||
            type == EDGE_IFLA_BRPORT_LEARNING ||
            type == EDGE_IFLA_BRPORT_UNICAST_FLOOD ||
            type == EDGE_IFLA_BRPORT_MCAST_FLOOD ||
            type == EDGE_IFLA_BRPORT_BCAST_FLOOD ||
            type == EDGE_IFLA_BRPORT_ISOLATED) {
            if (data_length != sizeof(value))
                return -EDGE_LINUX_EINVAL;
            memcpy(&value, attribute + 1, sizeof(value));
            if (type == EDGE_IFLA_BRPORT_STATE) {
                if (value > EDGE_NET_BRIDGE_STATE_BLOCKING)
                    return -EDGE_LINUX_EINVAL;
                settings->state = value;
                settings->mask |= EDGE_NET_BRIDGE_PORT_STATE;
            } else {
                if (value > 1u) return -EDGE_LINUX_EINVAL;
                if (type == EDGE_IFLA_BRPORT_MODE) {
                    settings->hairpin = value;
                    settings->mask |= EDGE_NET_BRIDGE_PORT_HAIRPIN;
                } else if (type == EDGE_IFLA_BRPORT_LEARNING) {
                    settings->learning = value;
                    settings->mask |= EDGE_NET_BRIDGE_PORT_LEARNING;
                } else if (type == EDGE_IFLA_BRPORT_UNICAST_FLOOD) {
                    settings->unicast_flood = value;
                    settings->mask |=
                        EDGE_NET_BRIDGE_PORT_UNICAST_FLOOD;
                } else if (type == EDGE_IFLA_BRPORT_MCAST_FLOOD) {
                    settings->multicast_flood = value;
                    settings->mask |=
                        EDGE_NET_BRIDGE_PORT_MULTICAST_FLOOD;
                } else if (type == EDGE_IFLA_BRPORT_BCAST_FLOOD) {
                    settings->broadcast_flood = value;
                    settings->mask |=
                        EDGE_NET_BRIDGE_PORT_BROADCAST_FLOOD;
                } else {
                    settings->isolated = value;
                    settings->mask |= EDGE_NET_BRIDGE_PORT_ISOLATED;
                }
            }
        }
        offset += edge_netlink_align(attribute->length);
    }
    return 0;
}

static int edge_rtnl_parse_bridge(
    const uint8_t *attributes, uint32_t attributes_length,
    uint8_t *vlan_filtering, int *have_vlan_filtering) {
    uint32_t offset = 0u;

    if (!vlan_filtering || !have_vlan_filtering ||
        (attributes_length && !attributes))
        return -EDGE_LINUX_EINVAL;
    *have_vlan_filtering = 0;
    while (offset < attributes_length) {
        const edge_nlattr_t *attribute;
        uint32_t data_length;

        if (attributes_length - offset < sizeof(*attribute))
            return -EDGE_LINUX_EINVAL;
        attribute = (const edge_nlattr_t *)(attributes + offset);
        if (attribute->length < sizeof(*attribute) ||
            attribute->length > attributes_length - offset)
            return -EDGE_LINUX_EINVAL;
        data_length = attribute->length - sizeof(*attribute);
        if ((attribute->type & EDGE_NLA_TYPE_MASK) ==
                EDGE_IFLA_BR_VLAN_FILTERING) {
            if (data_length != sizeof(*vlan_filtering))
                return -EDGE_LINUX_EINVAL;
            memcpy(vlan_filtering, attribute + 1,
                   sizeof(*vlan_filtering));
            if (*vlan_filtering > 1u) return -EDGE_LINUX_EINVAL;
            *have_vlan_filtering = 1;
        }
        offset += edge_netlink_align(attribute->length);
    }
    return 0;
}

static int edge_rtnl_apply_bridge_vlans(
    uint32_t network_namespace,
    const edge_netfilter_nlmsghdr_t *request, int deleting) {
    const edge_rtnl_ifinfomsg_t *info =
        (const edge_rtnl_ifinfomsg_t *)(request + 1);
    uint32_t payload_offset = sizeof(*request) + sizeof(*info);
    const uint8_t *attributes;
    uint32_t attributes_length;
    edge_rtnl_bridge_vlan_info_t pending;
    int have_pending = 0;
    uint32_t offset = 0u;
    int result;

    result = edge_rtnl_find_attribute(
        request, payload_offset, EDGE_IFLA_AF_SPEC,
        &attributes, &attributes_length);
    if (result == -EDGE_LINUX_ENOENT) return 1;
    if (result < 0) return result;
    if (info->family != EDGE_AF_BRIDGE || info->index <= 2)
        return -EDGE_LINUX_EINVAL;
    while (offset < attributes_length) {
        const edge_nlattr_t *attribute;
        edge_rtnl_bridge_vlan_info_t vlan;
        uint16_t flags;

        if (attributes_length - offset < sizeof(*attribute))
            return -EDGE_LINUX_EINVAL;
        attribute = (const edge_nlattr_t *)(attributes + offset);
        if (attribute->length < sizeof(*attribute) ||
            attribute->length > attributes_length - offset)
            return -EDGE_LINUX_EINVAL;
        if ((attribute->type & EDGE_NLA_TYPE_MASK) ==
                EDGE_IFLA_BRIDGE_VLAN_INFO) {
            if (attribute->length != sizeof(*attribute) + sizeof(vlan))
                return -EDGE_LINUX_EINVAL;
            memcpy(&vlan, attribute + 1, sizeof(vlan));
            flags = vlan.flags;
            if (!vlan.vlan_id ||
                vlan.vlan_id > EDGE_NET_BRIDGE_VLAN_MAX ||
                (flags & ~(EDGE_BRIDGE_VLAN_INFO_MASTER |
                           EDGE_BRIDGE_VLAN_INFO_PVID |
                           EDGE_BRIDGE_VLAN_INFO_UNTAGGED |
                           EDGE_BRIDGE_VLAN_INFO_RANGE_BEGIN |
                           EDGE_BRIDGE_VLAN_INFO_RANGE_END)))
                return -EDGE_LINUX_EINVAL;
            if ((flags & EDGE_BRIDGE_VLAN_INFO_RANGE_BEGIN) &&
                (flags & EDGE_BRIDGE_VLAN_INFO_RANGE_END))
                return -EDGE_LINUX_EINVAL;
            if (flags & EDGE_BRIDGE_VLAN_INFO_RANGE_BEGIN) {
                if (have_pending ||
                    (flags & EDGE_BRIDGE_VLAN_INFO_PVID))
                    return -EDGE_LINUX_EINVAL;
                pending = vlan;
                have_pending = 1;
            } else {
                uint16_t first_vlan = vlan.vlan_id;
                uint16_t last_vlan = vlan.vlan_id;
                int32_t target_ifindex = info->index;
                edge_rtnl_link_t *link;

                if (flags & EDGE_BRIDGE_VLAN_INFO_RANGE_END) {
                    uint16_t comparable_flags;
                    uint16_t pending_flags;

                    if (!have_pending || pending.vlan_id > vlan.vlan_id)
                        return -EDGE_LINUX_EINVAL;
                    comparable_flags = flags &
                        ~(uint16_t)EDGE_BRIDGE_VLAN_INFO_RANGE_END;
                    pending_flags = pending.flags &
                        ~(uint16_t)EDGE_BRIDGE_VLAN_INFO_RANGE_BEGIN;
                    if (comparable_flags != pending_flags)
                        return -EDGE_LINUX_EINVAL;
                    first_vlan = pending.vlan_id;
                    flags = comparable_flags;
                    have_pending = 0;
                } else if (have_pending) {
                    return -EDGE_LINUX_EINVAL;
                }
                edge_rtnl_lock();
                link = edge_rtnl_find_index(info->index);
                if (!link || link->network_namespace != network_namespace) {
                    edge_rtnl_unlock();
                    return -EDGE_LINUX_ENODEV;
                }
                if ((flags & EDGE_BRIDGE_VLAN_INFO_MASTER) &&
                    link->master > 0)
                    target_ifindex = link->master;
                result = edge_net_bridge_vlan_update(
                    target_ifindex, first_vlan, last_vlan,
                    (flags & EDGE_BRIDGE_VLAN_INFO_PVID) != 0u,
                    (flags & EDGE_BRIDGE_VLAN_INFO_UNTAGGED) != 0u,
                    deleting ? 0 : 1);
                edge_rtnl_unlock();
                if (result < 0) return edge_rtnl_core_error(result);
            }
        }
        offset += edge_netlink_align(attribute->length);
    }
    return have_pending ? -EDGE_LINUX_EINVAL : 0;
}

static int edge_rtnl_parse_veth_peer(
    const uint8_t *info_data, uint32_t info_data_length,
    char peer_name[EDGE_RTNL_NAME_MAX]) {
    const edge_nlattr_t *peer;
    const uint8_t *attributes;
    uint32_t attributes_length;
    uint32_t offset;

    if (!info_data || !peer_name) return -EDGE_LINUX_EINVAL;
    offset = 0;
    while (offset < info_data_length) {
        if (info_data_length - offset < sizeof(*peer))
            return -EDGE_LINUX_EINVAL;
        peer = (const edge_nlattr_t *)(info_data + offset);
        if (peer->length < sizeof(*peer) ||
            peer->length > info_data_length - offset)
            return -EDGE_LINUX_EINVAL;
        if ((peer->type & EDGE_NLA_TYPE_MASK) == EDGE_VETH_INFO_PEER) {
            const edge_nlattr_t *attribute;
            uint32_t attribute_offset = 0;

            if (peer->length < sizeof(*peer) +
                               sizeof(edge_rtnl_ifinfomsg_t))
                return -EDGE_LINUX_EINVAL;
            attributes = (const uint8_t *)(peer + 1) +
                         sizeof(edge_rtnl_ifinfomsg_t);
            attributes_length = peer->length - sizeof(*peer) -
                                sizeof(edge_rtnl_ifinfomsg_t);
            while (attribute_offset < attributes_length) {
                uint32_t data_length;
                uint32_t index;

                if (attributes_length - attribute_offset < sizeof(*attribute))
                    return -EDGE_LINUX_EINVAL;
                attribute = (const edge_nlattr_t *)(
                    attributes + attribute_offset);
                if (attribute->length < sizeof(*attribute) ||
                    attribute->length > attributes_length - attribute_offset)
                    return -EDGE_LINUX_EINVAL;
                if ((attribute->type & EDGE_NLA_TYPE_MASK) ==
                    EDGE_IFLA_IFNAME) {
                    data_length = attribute->length - sizeof(*attribute);
                    if (!data_length || data_length > EDGE_RTNL_NAME_MAX)
                        return -EDGE_LINUX_EINVAL;
                    memset(peer_name, 0, EDGE_RTNL_NAME_MAX);
                    for (index = 0; index < data_length; ++index) {
                        peer_name[index] = (char)attributes[
                            attribute_offset + sizeof(*attribute) + index];
                        if (!peer_name[index]) break;
                    }
                    if (index == data_length || !peer_name[0])
                        return -EDGE_LINUX_EINVAL;
                    return 0;
                }
                attribute_offset += edge_netlink_align(attribute->length);
            }
            return -EDGE_LINUX_EINVAL;
        }
        offset += edge_netlink_align(peer->length);
    }
    return -EDGE_LINUX_EINVAL;
}

static int edge_rtnl_parse_vlan(
    const uint8_t *info_data, uint32_t info_data_length,
    uint16_t *vlan_id, uint16_t *vlan_protocol) {
    uint32_t offset = 0u;
    int have_id = 0;

    if (!info_data || !vlan_id || !vlan_protocol)
        return -EDGE_LINUX_EINVAL;
    *vlan_id = 0u;
    *vlan_protocol = 0x8100u;
    while (offset < info_data_length) {
        const edge_nlattr_t *attribute;
        const uint8_t *data;
        uint32_t data_length;
        uint16_t type;

        if (info_data_length - offset < sizeof(*attribute))
            return -EDGE_LINUX_EINVAL;
        attribute = (const edge_nlattr_t *)(info_data + offset);
        if (attribute->length < sizeof(*attribute) ||
            attribute->length > info_data_length - offset)
            return -EDGE_LINUX_EINVAL;
        type = attribute->type & EDGE_NLA_TYPE_MASK;
        data = (const uint8_t *)(attribute + 1);
        data_length = attribute->length - sizeof(*attribute);
        if (type == EDGE_IFLA_VLAN_ID) {
            if (data_length != sizeof(uint16_t))
                return -EDGE_LINUX_EINVAL;
            memcpy(vlan_id, data, sizeof(*vlan_id));
            have_id = 1;
        } else if (type == EDGE_IFLA_VLAN_PROTOCOL) {
            if (data_length != sizeof(uint16_t))
                return -EDGE_LINUX_EINVAL;
            *vlan_protocol = (uint16_t)(((uint16_t)data[0] << 8u) |
                                        data[1]);
        }
        offset += edge_netlink_align(attribute->length);
    }
    if (!have_id || !*vlan_id || *vlan_id > 4094u ||
        (*vlan_protocol != 0x8100u && *vlan_protocol != 0x88a8u))
        return -EDGE_LINUX_EINVAL;
    return 0;
}

static int edge_rtnl_parse_macvlan(
    const uint8_t *info_data, uint32_t info_data_length,
    uint16_t *mode, uint16_t *flags) {
    uint32_t offset = 0u;
    uint32_t selected_mode = EDGE_NET_MACVLAN_MODE_VEPA;
    uint32_t selected_flags = 0u;

    if (!mode || !flags || (info_data_length && !info_data))
        return -EDGE_LINUX_EINVAL;
    while (offset < info_data_length) {
        const edge_nlattr_t *attribute;
        const uint8_t *data;
        uint32_t data_length;
        uint32_t value;

        if (info_data_length - offset < sizeof(*attribute))
            return -EDGE_LINUX_EINVAL;
        attribute = (const edge_nlattr_t *)(info_data + offset);
        if (attribute->length < sizeof(*attribute) ||
            attribute->length > info_data_length - offset)
            return -EDGE_LINUX_EINVAL;
        data = (const uint8_t *)attribute + sizeof(*attribute);
        data_length = attribute->length - sizeof(*attribute);
        if ((attribute->type & EDGE_NLA_TYPE_MASK) ==
                EDGE_IFLA_MACVLAN_MODE ||
            (attribute->type & EDGE_NLA_TYPE_MASK) ==
                EDGE_IFLA_MACVLAN_FLAGS) {
            if (data_length != sizeof(value))
                return -EDGE_LINUX_EINVAL;
            memcpy(&value, data, sizeof(value));
            if ((attribute->type & EDGE_NLA_TYPE_MASK) ==
                    EDGE_IFLA_MACVLAN_MODE)
                selected_mode = value;
            else
                selected_flags = value;
        }
        offset += edge_netlink_align(attribute->length);
    }
    if ((selected_mode != EDGE_NET_MACVLAN_MODE_PRIVATE &&
         selected_mode != EDGE_NET_MACVLAN_MODE_VEPA &&
         selected_mode != EDGE_NET_MACVLAN_MODE_BRIDGE &&
         selected_mode != EDGE_NET_MACVLAN_MODE_PASSTHRU) ||
        (selected_flags & ~1u) != 0u)
        return -EDGE_LINUX_EOPNOTSUPP;
    *mode = (uint16_t)selected_mode;
    *flags = (uint16_t)selected_flags;
    return 0;
}

static int edge_rtnl_parse_ipvlan(
    const uint8_t *info_data, uint32_t info_data_length,
    uint16_t *mode, uint16_t *flags) {
    uint32_t offset = 0u;
    uint16_t selected_mode = EDGE_NET_IPVLAN_MODE_L3;
    uint16_t selected_flags = EDGE_NET_IPVLAN_FLAG_BRIDGE;

    if (!mode || !flags || (info_data_length && !info_data))
        return -EDGE_LINUX_EINVAL;
    while (offset < info_data_length) {
        const edge_nlattr_t *attribute;
        const uint8_t *data;
        uint32_t data_length;
        uint16_t type;

        if (info_data_length - offset < sizeof(*attribute))
            return -EDGE_LINUX_EINVAL;
        attribute = (const edge_nlattr_t *)(info_data + offset);
        if (attribute->length < sizeof(*attribute) ||
            attribute->length > info_data_length - offset)
            return -EDGE_LINUX_EINVAL;
        type = attribute->type & EDGE_NLA_TYPE_MASK;
        data = (const uint8_t *)(attribute + 1);
        data_length = attribute->length - sizeof(*attribute);
        if (type == EDGE_IFLA_IPVLAN_MODE ||
            type == EDGE_IFLA_IPVLAN_FLAGS) {
            if (data_length != sizeof(uint16_t))
                return -EDGE_LINUX_EINVAL;
            if (type == EDGE_IFLA_IPVLAN_MODE)
                memcpy(&selected_mode, data, sizeof(selected_mode));
            else
                memcpy(&selected_flags, data, sizeof(selected_flags));
        }
        offset += edge_netlink_align(attribute->length);
    }
    if (selected_mode > EDGE_NET_IPVLAN_MODE_L3S ||
        selected_flags > EDGE_NET_IPVLAN_FLAG_VEPA)
        return -EDGE_LINUX_EOPNOTSUPP;
    *mode = selected_mode;
    *flags = selected_flags;
    return 0;
}

static int edge_rtnl_parse_bond(
    const uint8_t *info_data, uint32_t info_data_length,
    uint16_t *mode, uint16_t *hash_policy) {
    uint32_t offset = 0u;
    uint8_t selected_mode = EDGE_NET_BOND_MODE_ROUND_ROBIN;
    uint8_t selected_hash = EDGE_NET_BOND_HASH_LAYER2;

    if (!mode || !hash_policy || (info_data_length && !info_data))
        return -EDGE_LINUX_EINVAL;
    while (offset < info_data_length) {
        const edge_nlattr_t *attribute;
        const uint8_t *data;
        uint32_t data_length;
        uint16_t type;

        if (info_data_length - offset < sizeof(*attribute))
            return -EDGE_LINUX_EINVAL;
        attribute = (const edge_nlattr_t *)(info_data + offset);
        if (attribute->length < sizeof(*attribute) ||
            attribute->length > info_data_length - offset)
            return -EDGE_LINUX_EINVAL;
        type = attribute->type & EDGE_NLA_TYPE_MASK;
        data = (const uint8_t *)(attribute + 1);
        data_length = attribute->length - sizeof(*attribute);
        if (type == EDGE_IFLA_BOND_MODE ||
            type == EDGE_IFLA_BOND_XMIT_HASH_POLICY) {
            if (data_length != sizeof(uint8_t))
                return -EDGE_LINUX_EINVAL;
            if (type == EDGE_IFLA_BOND_MODE)
                selected_mode = data[0];
            else
                selected_hash = data[0];
        }
        offset += edge_netlink_align(attribute->length);
    }
    if (selected_mode > EDGE_NET_BOND_MODE_BROADCAST ||
        (selected_hash > EDGE_NET_BOND_HASH_LAYER23 &&
         selected_hash != EDGE_NET_BOND_HASH_VLAN_SRCMAC))
        return -EDGE_LINUX_EOPNOTSUPP;
    *mode = selected_mode;
    *hash_policy = selected_hash;
    return 0;
}

static int edge_rtnl_parse_vrf(
    const uint8_t *info_data, uint32_t info_data_length,
    uint32_t *routing_table) {
    uint32_t offset = 0u;
    uint32_t selected_table = 0u;

    if (!routing_table || (info_data_length && !info_data))
        return -EDGE_LINUX_EINVAL;
    while (offset < info_data_length) {
        const edge_nlattr_t *attribute;
        const uint8_t *data;
        uint32_t data_length;

        if (info_data_length - offset < sizeof(*attribute))
            return -EDGE_LINUX_EINVAL;
        attribute = (const edge_nlattr_t *)(info_data + offset);
        if (attribute->length < sizeof(*attribute) ||
            attribute->length > info_data_length - offset)
            return -EDGE_LINUX_EINVAL;
        data = (const uint8_t *)(attribute + 1);
        data_length = attribute->length - sizeof(*attribute);
        if ((attribute->type & EDGE_NLA_TYPE_MASK) == EDGE_IFLA_VRF_TABLE) {
            if (data_length != sizeof(selected_table))
                return -EDGE_LINUX_EINVAL;
            memcpy(&selected_table, data, sizeof(selected_table));
        }
        offset += edge_netlink_align(attribute->length);
    }
    if (!selected_table) return -EDGE_LINUX_EINVAL;
    *routing_table = selected_table;
    return 0;
}

static void edge_rtnl_initialize_link(
    edge_rtnl_link_t *link, const char *name, const char *kind) {
    memset(link, 0, sizeof(*link));
    link->used = 1u;
    link->index = g_edge_rtnl_next_index++;
    if (g_edge_rtnl_next_index < 3) g_edge_rtnl_next_index = 3;
    link->type = EDGE_ARPHRD_ETHER;
    link->flags = EDGE_IFF_BROADCAST | EDGE_IFF_MULTICAST;
    link->mtu = 1500u;
    link->tx_queue_length = 1000u;
    link->mac[0] = 0x02u;
    link->mac[1] = 0x42u;
    link->mac[4] = (uint8_t)((uint32_t)link->index >> 8u);
    link->mac[5] = (uint8_t)link->index;
    memcpy(link->name, name, sizeof(link->name));
    memcpy(link->kind, kind, sizeof(link->kind));
}

static int edge_rtnl_core_error(int result) {
    switch (result) {
        case EDGE_NET_OK:
            return 0;
        case EDGE_NET_INVALID:
            return -EDGE_LINUX_EINVAL;
        case EDGE_NET_NOT_FOUND:
            return -EDGE_LINUX_ENODEV;
        case EDGE_NET_EXISTS:
            return -EDGE_LINUX_EEXIST;
        case EDGE_NET_NO_SPACE:
            return -EDGE_LINUX_ENOSPC;
        case EDGE_NET_WRONG_NAMESPACE:
            return -EDGE_LINUX_EXDEV;
        case EDGE_NET_NOT_SUPPORTED:
            return -EDGE_LINUX_EOPNOTSUPP;
        case EDGE_NET_BUSY:
            return -EDGE_LINUX_EBUSY;
        default:
            return -EDGE_LINUX_EIO;
    }
}

static void edge_rtnl_core_configuration(
    const edge_rtnl_link_t *link,
    edge_net_device_configuration_t *configuration) {
    memset(configuration, 0, sizeof(*configuration));
    configuration->ifindex = link->index;
    configuration->network_namespace = link->network_namespace;
    if (strcmp(link->kind, "bridge") == 0)
        configuration->kind = EDGE_NET_DEVICE_BRIDGE;
    else if (strcmp(link->kind, "tun") == 0)
        configuration->kind = EDGE_NET_DEVICE_TUN;
    else if (strcmp(link->kind, "tap") == 0)
        configuration->kind = EDGE_NET_DEVICE_TAP;
    else if (strcmp(link->kind, "vlan") == 0)
        configuration->kind = EDGE_NET_DEVICE_VLAN;
    else if (strcmp(link->kind, "dummy") == 0)
        configuration->kind = EDGE_NET_DEVICE_DUMMY;
    else if (strcmp(link->kind, "macvlan") == 0)
        configuration->kind = EDGE_NET_DEVICE_MACVLAN;
    else if (strcmp(link->kind, "ipvlan") == 0)
        configuration->kind = EDGE_NET_DEVICE_IPVLAN;
    else if (strcmp(link->kind, "bond") == 0)
        configuration->kind = EDGE_NET_DEVICE_BOND;
    else if (strcmp(link->kind, "vrf") == 0)
        configuration->kind = EDGE_NET_DEVICE_VRF;
    else
        configuration->kind = EDGE_NET_DEVICE_VETH;
    configuration->flags = link->flags;
    configuration->mtu = link->mtu;
    configuration->tx_queue_length = link->tx_queue_length;
    configuration->carrier =
        configuration->kind == EDGE_NET_DEVICE_BRIDGE ||
        configuration->kind == EDGE_NET_DEVICE_DUMMY ? 1u : 0u;
    configuration->lower_ifindex = link->lower_index;
    configuration->vlan_id = link->vlan_id;
    configuration->vlan_protocol = link->vlan_protocol;
    configuration->virtual_mode = link->virtual_mode;
    configuration->virtual_flags = link->virtual_flags;
    configuration->routing_table = link->routing_table;
    memcpy(configuration->hardware_address, link->mac,
           sizeof(configuration->hardware_address));
    memcpy(configuration->name, link->name,
           sizeof(configuration->name));
}

static int edge_rtnl_apply_link(
    uint32_t network_namespace,
    const edge_netfilter_nlmsghdr_t *request, int deleting) {
    const edge_rtnl_ifinfomsg_t *info =
        (const edge_rtnl_ifinfomsg_t *)(request + 1);
    uint32_t payload_offset = sizeof(*request) + sizeof(*info);
    edge_rtnl_link_t *link;
    char name[EDGE_RTNL_NAME_MAX];
    char kind[EDGE_RTNL_KIND_MAX];
    char peer_name[EDGE_RTNL_NAME_MAX];
    const uint8_t *info_data;
    uint32_t info_data_length;
    uint32_t mtu;
    uint32_t master;
    uint32_t lower_index = 0u;
    uint32_t namespace_descriptor;
    uint32_t target_namespace = network_namespace;
    int target_namespace_supplied = 0;
    int have_name = 0;
    int have_lower = 0;
    edge_rtnl_bridge_port_settings_t bridge_port;
    uint8_t bridge_vlan_filtering = 0u;
    int have_bridge_vlan_filtering = 0;
    uint32_t ordinal;
    int result;

    memset(&bridge_port, 0, sizeof(bridge_port));
    if (info->index > 0 && info->index <= 2) return 1;
    result = edge_rtnl_read_u32(
        request, payload_offset, EDGE_IFLA_NET_NS_FD,
        &namespace_descriptor);
    if (result == 0) {
        kernel_namespace_descriptor_t descriptor;

        result = kernel_namespace_descriptor_get(
            (int32_t)namespace_descriptor, &descriptor);
        if (result < 0) return result;
        if (descriptor.kind != EDGE_NAMESPACE_NET)
            return -EDGE_LINUX_EINVAL;
        target_namespace = descriptor.id;
        target_namespace_supplied = 1;
    } else if (result != -EDGE_LINUX_ENOENT) {
        return result;
    }
    result = edge_rtnl_read_name(
        request, payload_offset, EDGE_IFLA_IFNAME, name);
    if (result == 0) {
        have_name = 1;
    } else if (result != -EDGE_LINUX_ENOENT) {
        return result;
    }
    result = edge_rtnl_read_u32(
        request, payload_offset, EDGE_IFLA_LINK, &lower_index);
    if (result == 0) {
        have_lower = 1;
    } else if (result != -EDGE_LINUX_ENOENT) {
        return result;
    }
    memset(kind, 0, sizeof(kind));
    info_data = 0;
    info_data_length = 0u;
    result = edge_rtnl_parse_kind(
        request, payload_offset, kind, &info_data, &info_data_length);
    if (result == 0) {
        if (strcmp(kind, "bridge_slave") == 0) {
            result = edge_rtnl_parse_bridge_port(
                info_data, info_data_length, &bridge_port);
            if (result < 0) return result;
        } else if (strcmp(kind, "bridge") == 0) {
            result = edge_rtnl_parse_bridge(
                info_data, info_data_length, &bridge_vlan_filtering,
                &have_bridge_vlan_filtering);
            if (result < 0) return result;
        }
    } else if (result != 0 && result != -EDGE_LINUX_ENOENT) {
        return result;
    }
    {
        const uint8_t *protocol_info;
        uint32_t protocol_info_length;
        result = edge_rtnl_find_attribute(
            request, payload_offset, EDGE_IFLA_PROTINFO,
            &protocol_info, &protocol_info_length);
        if (result == 0) {
            result = edge_rtnl_parse_bridge_port(
                protocol_info, protocol_info_length, &bridge_port);
            if (result < 0) return result;
        } else if (result != -EDGE_LINUX_ENOENT) {
            return result;
        }
    }
    if (info->family == EDGE_AF_BRIDGE) {
        result = edge_rtnl_apply_bridge_vlans(
            network_namespace, request, deleting);
        if (result != 1) return result;
    }
    edge_rtnl_lock();
    link = info->index > 0 ? edge_rtnl_find_index(info->index) : 0;
    if (deleting) {
        int32_t dependent_ifindex[EDGE_RTNL_LINK_MAX];
        uint32_t dependent_namespace[EDGE_RTNL_LINK_MAX];
        uint32_t dependent_address[EDGE_RTNL_LINK_MAX];
        uint8_t dependent_prefix[EDGE_RTNL_LINK_MAX];
        uint32_t dependent_count = 0u;
        int32_t peer_index;
        int notify_link;
        int core_result;
        int32_t removed_ifindex;
        uint32_t removed_namespace;
        uint32_t removed_address;
        uint8_t removed_prefix;
        int32_t peer_removed_ifindex = 0;
        uint32_t peer_removed_namespace = 0;
        uint32_t peer_removed_address = 0;
        uint8_t peer_removed_prefix = 0;

        if (!link) {
            edge_rtnl_unlock();
            return -EDGE_LINUX_ENODEV;
        }
        if (link->network_namespace != network_namespace) {
            edge_rtnl_unlock();
            return -EDGE_LINUX_ENODEV;
        }
        peer_index = link->peer_index;
        removed_ifindex = link->index;
        removed_namespace = link->network_namespace;
        notify_link = link->ipv4_address != 0u;
        removed_address = link->ipv4_address;
        removed_prefix = link->prefix_length;
        for (;;) {
            int found = 0;
            uint32_t candidate_ordinal;

            for (candidate_ordinal = 0;
                 candidate_ordinal < EDGE_RTNL_LINK_MAX;
                 ++candidate_ordinal) {
                edge_rtnl_link_t *candidate =
                    &g_edge_rtnl_links[candidate_ordinal];
                uint32_t parent_ordinal;
                int parent_removed;

                if (!candidate->used ||
                    (strcmp(candidate->kind, "vlan") != 0 &&
                     strcmp(candidate->kind, "macvlan") != 0))
                    continue;
                parent_removed = candidate->lower_index == link->index;
                for (parent_ordinal = 0;
                     !parent_removed && parent_ordinal < dependent_count;
                     ++parent_ordinal)
                    parent_removed = candidate->lower_index ==
                        dependent_ifindex[parent_ordinal];
                if (!parent_removed) continue;
                for (parent_ordinal = 0;
                     parent_ordinal < dependent_count;
                     ++parent_ordinal) {
                    if (dependent_ifindex[parent_ordinal] ==
                            candidate->index)
                        break;
                }
                if (parent_ordinal < dependent_count) continue;
                dependent_ifindex[dependent_count] = candidate->index;
                dependent_namespace[dependent_count] =
                    candidate->network_namespace;
                dependent_address[dependent_count] =
                    candidate->ipv4_address;
                dependent_prefix[dependent_count] =
                    candidate->prefix_length;
                ++dependent_count;
                found = 1;
            }
            if (!found) break;
        }
        if (peer_index > 0) {
            edge_rtnl_link_t *peer_link = edge_rtnl_find_index(peer_index);

            if (peer_link) {
                peer_removed_ifindex = peer_link->index;
                peer_removed_namespace = peer_link->network_namespace;
                peer_removed_address = peer_link->ipv4_address;
                peer_removed_prefix = peer_link->prefix_length;
            }
        }
        edge_rtnl_remove_ipv6_interface(link);
        edge_rtnl_remove_interface_routes(link);
        for (ordinal = 0; ordinal < dependent_count; ++ordinal) {
            edge_rtnl_link_t *dependent = edge_rtnl_find_index(
                dependent_ifindex[ordinal]);

            if (dependent) {
                edge_rtnl_remove_ipv6_interface(dependent);
                edge_rtnl_remove_interface_routes(dependent);
            }
        }
        if (peer_index > 0) {
            edge_rtnl_link_t *peer_link = edge_rtnl_find_index(peer_index);

            if (peer_link) {
                edge_rtnl_remove_ipv6_interface(peer_link);
                edge_rtnl_remove_interface_routes(peer_link);
            }
        }
        core_result = edge_net_device_unregister(link->index);
        if (core_result < 0 && core_result != EDGE_NET_NOT_FOUND) {
            edge_rtnl_unlock();
            return edge_rtnl_core_error(core_result);
        }
        for (ordinal = 0; ordinal < EDGE_RTNL_LINK_MAX; ++ordinal) {
            edge_rtnl_link_t *candidate = &g_edge_rtnl_links[ordinal];

            if (candidate->used && candidate->master == removed_ifindex)
                candidate->master = 0;
        }
        memset(link, 0, sizeof(*link));
        for (ordinal = 0; ordinal < dependent_count; ++ordinal) {
            edge_rtnl_link_t *dependent = edge_rtnl_find_index(
                dependent_ifindex[ordinal]);

            if (dependent) memset(dependent, 0, sizeof(*dependent));
        }
        if (peer_index > 0) {
            edge_rtnl_link_t *peer_link = edge_rtnl_find_index(peer_index);

            if (peer_link) memset(peer_link, 0, sizeof(*peer_link));
        }
        edge_rtnl_unlock();
        if (notify_link && g_edge_rtnl_ipv4_update)
            (void)g_edge_rtnl_ipv4_update(
                removed_ifindex, removed_namespace,
                removed_address, removed_prefix, 0);
        if (peer_removed_address && g_edge_rtnl_ipv4_update)
            (void)g_edge_rtnl_ipv4_update(
                peer_removed_ifindex, peer_removed_namespace,
                peer_removed_address, peer_removed_prefix, 0);
        if (g_edge_rtnl_ipv4_update) {
            for (ordinal = 0; ordinal < dependent_count; ++ordinal) {
                if (dependent_address[ordinal])
                    (void)g_edge_rtnl_ipv4_update(
                        dependent_ifindex[ordinal],
                        dependent_namespace[ordinal],
                        dependent_address[ordinal],
                        dependent_prefix[ordinal], 0);
            }
        }
        return 0;
    }
    if (link) {
        int have_master;
        int have_mtu;
        int core_result;
        int moved = 0;
        int32_t notify_ifindex;
        uint32_t old_network_namespace;
        uint32_t notify_network_namespace;
        uint32_t notify_address;
        uint8_t notify_prefix;
        const edge_linux_rtnetlink_ipv6_provider_t *ipv6_provider;
        edge_rtnl_ipv6_address_t
            moved_ipv6[EDGE_RTNL_IPV6_ADDRESS_MAX];

        if (link->network_namespace != network_namespace) {
            edge_rtnl_unlock();
            return -EDGE_LINUX_ENODEV;
        }
        old_network_namespace = link->network_namespace;
        memset(moved_ipv6, 0, sizeof(moved_ipv6));
        have_mtu = edge_rtnl_read_u32(
            request, payload_offset, EDGE_IFLA_MTU, &mtu) == 0;
        have_master = edge_rtnl_read_u32(
            request, payload_offset, EDGE_IFLA_MASTER, &master) == 0;
        if (have_mtu && (mtu < 68u || mtu > 65535u)) {
            edge_rtnl_unlock();
            return -EDGE_LINUX_EINVAL;
        }
        if (have_name && strcmp(link->name, name) != 0) {
            edge_rtnl_link_t *named = edge_rtnl_find_name(
                target_namespace, name);

            if (named && named != link) {
                edge_rtnl_unlock();
                return -EDGE_LINUX_EEXIST;
            }
        }
        if (target_namespace_supplied) {
            core_result = edge_net_device_move(
                link->index, target_namespace);
            if (core_result < 0) {
                edge_rtnl_unlock();
                return edge_rtnl_core_error(core_result);
            }
            link->network_namespace = target_namespace;
            link->master = 0;
            moved = old_network_namespace != target_namespace;
            if (moved)
                memcpy(moved_ipv6, link->ipv6_addresses,
                       sizeof(moved_ipv6));
        }
        if (have_name && strcmp(link->name, name) != 0) {
            core_result = edge_net_device_rename(
                link->index, link->network_namespace, name);
            if (core_result < 0) {
                edge_rtnl_unlock();
                return edge_rtnl_core_error(core_result);
            }
            memset(link->name, 0, sizeof(link->name));
            memcpy(link->name, name, strlen(name) + 1u);
        }
        core_result = edge_net_device_set_link(
            link->index, info->flags, info->change,
            mtu, have_mtu);
        if (core_result < 0) {
            edge_rtnl_unlock();
            return edge_rtnl_core_error(core_result);
        }
        link->flags = (link->flags & ~info->change) |
                      (info->flags & info->change);
        if (have_mtu) link->mtu = mtu;
        if (have_master) {
            core_result = edge_net_device_set_master(
                link->index, (int32_t)master);
            if (core_result < 0) {
                edge_rtnl_unlock();
                return edge_rtnl_core_error(core_result);
            }
            link->master = (int32_t)master;
        }
        if (bridge_port.mask) {
            edge_rtnl_link_t *master_link =
                link->master > 0 ? edge_rtnl_find_index(link->master) : 0;

            if (!master_link || strcmp(master_link->kind, "bridge") != 0) {
                edge_rtnl_unlock();
                return -EDGE_LINUX_EINVAL;
            }
            core_result = edge_net_device_set_bridge_port_controls(
                link->index, bridge_port.mask, bridge_port.state,
                bridge_port.hairpin != 0u,
                bridge_port.learning != 0u,
                bridge_port.unicast_flood != 0u,
                bridge_port.multicast_flood != 0u,
                bridge_port.broadcast_flood != 0u,
                bridge_port.isolated != 0u);
            if (core_result < 0) {
                edge_rtnl_unlock();
                return edge_rtnl_core_error(core_result);
            }
        }
        if (have_bridge_vlan_filtering) {
            if (strcmp(link->kind, "bridge") != 0) {
                edge_rtnl_unlock();
                return -EDGE_LINUX_EINVAL;
            }
            core_result = edge_net_bridge_vlan_filtering_set(
                link->index, bridge_vlan_filtering != 0u);
            if (core_result < 0) {
                edge_rtnl_unlock();
                return edge_rtnl_core_error(core_result);
            }
            link->bridge_vlan_filtering = bridge_vlan_filtering;
        }
        notify_ifindex = link->index;
        notify_network_namespace = link->network_namespace;
        notify_address = link->ipv4_address;
        notify_prefix = link->prefix_length;
        edge_rtnl_unlock();
        ipv6_provider = __atomic_load_n(
            &g_edge_rtnl_ipv6_provider, __ATOMIC_ACQUIRE);
        if (ipv6_provider && ipv6_provider->synchronize_links)
            ipv6_provider->synchronize_links();
        if (notify_address && g_edge_rtnl_ipv4_update) {
            if (moved)
                (void)g_edge_rtnl_ipv4_update(
                    notify_ifindex, old_network_namespace,
                    notify_address, notify_prefix, 0);
            if (g_edge_rtnl_ipv4_update(
                    notify_ifindex, notify_network_namespace,
                    notify_address, notify_prefix, 1) < 0)
                return -EDGE_LINUX_EIO;
        }
        if (moved) {
            if (ipv6_provider && ipv6_provider->configure_address) {
                for (ordinal = 0;
                     ordinal < EDGE_RTNL_IPV6_ADDRESS_MAX; ++ordinal) {
                    edge_rtnl_ipv6_address_t *ipv6 =
                        &moved_ipv6[ordinal];

                    if (!ipv6->used) continue;
                    (void)ipv6_provider->configure_address(
                        old_network_namespace, notify_ifindex,
                        ipv6->address, ipv6->prefix_length, ipv6->flags,
                        ipv6->valid_lifetime,
                        ipv6->preferred_lifetime, 0);
                    if (ipv6_provider->configure_address(
                            notify_network_namespace, notify_ifindex,
                            ipv6->address, ipv6->prefix_length,
                            ipv6->flags, ipv6->valid_lifetime,
                            ipv6->preferred_lifetime, 1) != 0)
                        return -EDGE_LINUX_EIO;
                }
            }
        }
        return 0;
    }
    if (info->index > 2) {
        edge_rtnl_unlock();
        return -EDGE_LINUX_ENODEV;
    }
    if (!have_name) {
        edge_rtnl_unlock();
        return -EDGE_LINUX_EINVAL;
    }
    if (!kind[0]) {
        result = edge_rtnl_parse_kind(
            request, payload_offset, kind, &info_data, &info_data_length);
    } else {
        result = 0;
    }
    if (result < 0) {
        edge_rtnl_unlock();
        return result;
    }
    if (strcmp(kind, "bridge") != 0 && strcmp(kind, "veth") != 0 &&
        strcmp(kind, "vlan") != 0 && strcmp(kind, "dummy") != 0 &&
        strcmp(kind, "macvlan") != 0 && strcmp(kind, "ipvlan") != 0 &&
        strcmp(kind, "bond") != 0 && strcmp(kind, "vrf") != 0) {
        edge_rtnl_unlock();
        return -EDGE_LINUX_EOPNOTSUPP;
    } else if (strcmp(kind, "bond") == 0) {
        uint16_t mode;
        uint16_t hash_policy;

        result = edge_rtnl_parse_bond(
            info_data, info_data_length, &mode, &hash_policy);
        if (result < 0) {
            edge_rtnl_unlock();
            return result;
        }
    } else if (strcmp(kind, "vrf") == 0) {
        uint32_t routing_table;

        result = edge_rtnl_parse_vrf(
            info_data, info_data_length, &routing_table);
        if (result < 0) {
            edge_rtnl_unlock();
            return result;
        }
    }
    if (edge_rtnl_find_name(target_namespace, name)) {
        edge_rtnl_unlock();
        return -EDGE_LINUX_EEXIST;
    }
    memset(peer_name, 0, sizeof(peer_name));
    if (strcmp(kind, "veth") == 0) {
        result = edge_rtnl_parse_veth_peer(
            info_data, info_data_length, peer_name);
        if (result < 0) {
            edge_rtnl_unlock();
            return result;
        }
        if (strcmp(name, peer_name) == 0 ||
            edge_rtnl_find_name(network_namespace, peer_name)) {
            edge_rtnl_unlock();
            return -EDGE_LINUX_EEXIST;
        }
    } else if (strcmp(kind, "vlan") == 0 ||
               strcmp(kind, "macvlan") == 0 ||
               strcmp(kind, "ipvlan") == 0) {
        edge_rtnl_link_t *lower_link;

        if (!have_lower || !lower_index) {
            edge_rtnl_unlock();
            return -EDGE_LINUX_EINVAL;
        }
        lower_link = edge_rtnl_find_index((int32_t)lower_index);
        if (!lower_link ||
            lower_link->network_namespace != target_namespace) {
            edge_rtnl_unlock();
            return -EDGE_LINUX_ENODEV;
        }
        if (strcmp(kind, "vlan") == 0) {
            uint16_t vlan_id;
            uint16_t vlan_protocol;

            result = edge_rtnl_parse_vlan(
                info_data, info_data_length, &vlan_id, &vlan_protocol);
            if (result < 0) {
                edge_rtnl_unlock();
                return result;
            }
            for (ordinal = 0; ordinal < EDGE_RTNL_LINK_MAX; ++ordinal) {
                const edge_rtnl_link_t *candidate =
                    &g_edge_rtnl_links[ordinal];

                if (candidate->used &&
                    strcmp(candidate->kind, "vlan") == 0 &&
                    candidate->lower_index == (int32_t)lower_index &&
                    candidate->vlan_id == vlan_id &&
                    candidate->vlan_protocol == vlan_protocol) {
                    edge_rtnl_unlock();
                    return -EDGE_LINUX_EEXIST;
                }
            }
        } else if (strcmp(kind, "macvlan") == 0) {
            uint16_t mode;
            uint16_t flags;

            result = edge_rtnl_parse_macvlan(
                info_data, info_data_length, &mode, &flags);
            if (result < 0) {
                edge_rtnl_unlock();
                return result;
            }
        } else {
            uint16_t mode;
            uint16_t flags;

            result = edge_rtnl_parse_ipvlan(
                info_data, info_data_length, &mode, &flags);
            if (result < 0) {
                edge_rtnl_unlock();
                return result;
            }
        }
    }
    for (ordinal = 0; ordinal < EDGE_RTNL_LINK_MAX; ++ordinal) {
        link = &g_edge_rtnl_links[ordinal];
        if (link->used) continue;
        edge_rtnl_initialize_link(link, name, kind);
        link->network_namespace = target_namespace;
        if (strcmp(kind, "bridge") == 0) {
            result = edge_rtnl_parse_bridge(
                info_data, info_data_length, &link->bridge_vlan_filtering,
                &have_bridge_vlan_filtering);
            if (result < 0) {
                memset(link, 0, sizeof(*link));
                edge_rtnl_unlock();
                return result;
            }
        } else if (strcmp(kind, "vlan") == 0) {
            edge_rtnl_link_t *lower_link = edge_rtnl_find_index(
                (int32_t)lower_index);

            result = edge_rtnl_parse_vlan(
                info_data, info_data_length, &link->vlan_id,
                &link->vlan_protocol);
            if (result < 0 || !lower_link) {
                memset(link, 0, sizeof(*link));
                edge_rtnl_unlock();
                return result < 0 ? result : -EDGE_LINUX_ENODEV;
            }
            link->lower_index = (int32_t)lower_index;
            link->mtu = lower_link->mtu;
            memcpy(link->mac, lower_link->mac, sizeof(link->mac));
        } else if (strcmp(kind, "macvlan") == 0) {
            edge_rtnl_link_t *lower_link = edge_rtnl_find_index(
                (int32_t)lower_index);

            result = edge_rtnl_parse_macvlan(
                info_data, info_data_length, &link->virtual_mode,
                &link->virtual_flags);
            if (result < 0 || !lower_link) {
                memset(link, 0, sizeof(*link));
                edge_rtnl_unlock();
                return result < 0 ? result : -EDGE_LINUX_ENODEV;
            }
            link->lower_index = (int32_t)lower_index;
            link->mtu = lower_link->mtu;
            if (link->virtual_mode == EDGE_NET_MACVLAN_MODE_PASSTHRU)
                memcpy(link->mac, lower_link->mac, sizeof(link->mac));
        } else if (strcmp(kind, "ipvlan") == 0) {
            edge_rtnl_link_t *lower_link = edge_rtnl_find_index(
                (int32_t)lower_index);

            result = edge_rtnl_parse_ipvlan(
                info_data, info_data_length, &link->virtual_mode,
                &link->virtual_flags);
            if (result < 0 || !lower_link) {
                memset(link, 0, sizeof(*link));
                edge_rtnl_unlock();
                return result < 0 ? result : -EDGE_LINUX_ENODEV;
            }
            link->lower_index = (int32_t)lower_index;
            link->mtu = lower_link->mtu;
            memcpy(link->mac, lower_link->mac, sizeof(link->mac));
        } else if (strcmp(kind, "bond") == 0) {
            result = edge_rtnl_parse_bond(
                info_data, info_data_length, &link->virtual_mode,
                &link->virtual_flags);
            if (result < 0) {
                memset(link, 0, sizeof(*link));
                edge_rtnl_unlock();
                return result;
            }
        } else if (strcmp(kind, "vrf") == 0) {
            result = edge_rtnl_parse_vrf(
                info_data, info_data_length, &link->routing_table);
            if (result < 0) {
                memset(link, 0, sizeof(*link));
                edge_rtnl_unlock();
                return result;
            }
        }
        if (strcmp(kind, "veth") == 0) {
            edge_net_device_configuration_t first_configuration;
            edge_net_device_configuration_t second_configuration;
            uint32_t peer_ordinal;
            edge_rtnl_link_t *peer_link = 0;

            for (peer_ordinal = ordinal + 1u;
                 peer_ordinal < EDGE_RTNL_LINK_MAX; ++peer_ordinal) {
                if (!g_edge_rtnl_links[peer_ordinal].used) {
                    peer_link = &g_edge_rtnl_links[peer_ordinal];
                    break;
                }
            }
            if (!peer_link) {
                memset(link, 0, sizeof(*link));
                edge_rtnl_unlock();
                return -EDGE_LINUX_ENOSPC;
            }
            edge_rtnl_initialize_link(peer_link, peer_name, kind);
            peer_link->network_namespace = network_namespace;
            link->peer_index = peer_link->index;
            peer_link->peer_index = link->index;
            edge_rtnl_core_configuration(
                link, &first_configuration);
            edge_rtnl_core_configuration(
                peer_link, &second_configuration);
            result = edge_net_veth_register_pair(
                &first_configuration, &second_configuration);
            if (result < 0) {
                memset(peer_link, 0, sizeof(*peer_link));
                memset(link, 0, sizeof(*link));
                edge_rtnl_unlock();
                return edge_rtnl_core_error(result);
            }
        } else {
            edge_net_device_configuration_t configuration;

            edge_rtnl_core_configuration(link, &configuration);
            result = edge_net_device_register(&configuration);
            if (result < 0) {
                memset(link, 0, sizeof(*link));
                edge_rtnl_unlock();
                return edge_rtnl_core_error(result);
            }
            if (strcmp(kind, "bridge") == 0 &&
                link->bridge_vlan_filtering) {
                result = edge_net_bridge_vlan_filtering_set(
                    link->index, 1);
                if (result < 0) {
                    (void)edge_net_device_unregister(link->index);
                    memset(link, 0, sizeof(*link));
                    edge_rtnl_unlock();
                    return edge_rtnl_core_error(result);
                }
            }
        }
        edge_rtnl_unlock();
        return 0;
    }
    edge_rtnl_unlock();
    return -EDGE_LINUX_ENOSPC;
}

static int edge_rtnl_apply_address(
    uint32_t network_namespace,
    const edge_netfilter_nlmsghdr_t *request, int deleting) {
    const edge_rtnl_ifaddrmsg_t *address =
        (const edge_rtnl_ifaddrmsg_t *)(request + 1);
    uint32_t payload_offset = sizeof(*request) + sizeof(*address);
    const uint8_t *data;
    uint32_t data_length;
    edge_rtnl_link_t *link;
    uint32_t ipv4 = 0;
    int32_t notify_ifindex;
    int result;

    if (address->family == EDGE_AF_INET6) {
        const edge_linux_rtnetlink_ipv6_provider_t *provider =
            __atomic_load_n(&g_edge_rtnl_ipv6_provider, __ATOMIC_ACQUIRE);
        edge_rtnl_ifa_cacheinfo_t cacheinfo;
        uint8_t ipv6[16];
        uint32_t flags = address->flags;

        if (address->prefix_length > 128u)
            return -EDGE_LINUX_EINVAL;
        if (!provider || !provider->configure_address)
            return -EDGE_LINUX_EOPNOTSUPP;
        result = edge_rtnl_find_attribute(
            request, payload_offset, EDGE_IFA_LOCAL, &data, &data_length);
        if (result == -EDGE_LINUX_ENOENT)
            result = edge_rtnl_find_attribute(
                request, payload_offset, EDGE_IFA_ADDRESS,
                &data, &data_length);
        if (result < 0) return result;
        if (data_length != sizeof(ipv6)) return -EDGE_LINUX_EINVAL;
        memcpy(ipv6, data, sizeof(ipv6));
        memset(&cacheinfo, 0xff, sizeof(cacheinfo));
        result = edge_rtnl_find_attribute(
            request, payload_offset, EDGE_IFA_FLAGS, &data, &data_length);
        if (result == 0) {
            if (data_length != sizeof(flags)) return -EDGE_LINUX_EINVAL;
            memcpy(&flags, data, sizeof(flags));
        } else if (result != -EDGE_LINUX_ENOENT) {
            return result;
        }
        result = edge_rtnl_find_attribute(
            request, payload_offset, EDGE_IFA_CACHEINFO,
            &data, &data_length);
        if (result == 0) {
            if (data_length != sizeof(cacheinfo))
                return -EDGE_LINUX_EINVAL;
            memcpy(&cacheinfo, data, sizeof(cacheinfo));
        } else if (result != -EDGE_LINUX_ENOENT) {
            return result;
        }
        if (address->index != 2u) {
            edge_rtnl_link_t *ipv6_link;

            edge_rtnl_lock();
            ipv6_link = edge_rtnl_find_index((int32_t)address->index);
            if (!ipv6_link ||
                ipv6_link->network_namespace != network_namespace) {
                edge_rtnl_unlock();
                return -EDGE_LINUX_ENODEV;
            }
            edge_rtnl_unlock();
        } else if (network_namespace) {
            return -EDGE_LINUX_ENODEV;
        }
        result = provider->configure_address(
            network_namespace, (int32_t)address->index, ipv6,
            address->prefix_length, flags, cacheinfo.valid,
            cacheinfo.preferred, deleting ? 0 : 1);
        if (result != 0) return -EDGE_LINUX_EIO;
        if (address->index != 2u) {
            edge_rtnl_link_t *ipv6_link;
            edge_rtnl_ipv6_address_t *slot = 0;
            edge_rtnl_ipv6_address_t *free_slot = 0;

            edge_rtnl_lock();
            ipv6_link = edge_rtnl_find_index((int32_t)address->index);
            if (!ipv6_link ||
                ipv6_link->network_namespace != network_namespace) {
                edge_rtnl_unlock();
                (void)provider->configure_address(
                    network_namespace, (int32_t)address->index, ipv6,
                    address->prefix_length, flags, cacheinfo.valid,
                    cacheinfo.preferred, 0);
                return -EDGE_LINUX_ENODEV;
            }
            for (uint32_t ordinal = 0;
                 ordinal < EDGE_RTNL_IPV6_ADDRESS_MAX; ++ordinal) {
                edge_rtnl_ipv6_address_t *candidate =
                    &ipv6_link->ipv6_addresses[ordinal];

                if (!candidate->used) {
                    if (!free_slot) free_slot = candidate;
                    continue;
                }
                if (memcmp(candidate->address, ipv6, sizeof(ipv6)) == 0) {
                    slot = candidate;
                    break;
                }
            }
            if (deleting) {
                if (slot) memset(slot, 0, sizeof(*slot));
            } else {
                if (!slot) slot = free_slot;
                if (!slot) {
                    edge_rtnl_unlock();
                    (void)provider->configure_address(
                        network_namespace, (int32_t)address->index, ipv6,
                        address->prefix_length, flags, cacheinfo.valid,
                        cacheinfo.preferred, 0);
                    return -EDGE_LINUX_ENOSPC;
                }
                memset(slot, 0, sizeof(*slot));
                slot->used = 1u;
                slot->prefix_length = address->prefix_length;
                slot->scope = address->scope;
                slot->flags = flags;
                slot->valid_lifetime = cacheinfo.valid;
                slot->preferred_lifetime = cacheinfo.preferred;
                memcpy(slot->address, ipv6, sizeof(slot->address));
            }
            edge_rtnl_unlock();
        }
        return 0;
    }
    if (address->index <= 2u) return 1;
    if (address->family != EDGE_AF_INET || address->prefix_length > 32u)
        return -EDGE_LINUX_EAFNOSUPPORT;
    result = edge_rtnl_find_attribute(
        request, payload_offset, EDGE_IFA_LOCAL, &data, &data_length);
    if (result == -EDGE_LINUX_ENOENT)
        result = edge_rtnl_find_attribute(
            request, payload_offset, EDGE_IFA_ADDRESS,
            &data, &data_length);
    if (result < 0 && !deleting) return result;
    if (result == 0) {
        if (data_length != sizeof(ipv4)) return -EDGE_LINUX_EINVAL;
        memcpy(&ipv4, data, sizeof(ipv4));
    }
    edge_rtnl_lock();
    link = edge_rtnl_find_index((int32_t)address->index);
    if (!link) {
        edge_rtnl_unlock();
        return -EDGE_LINUX_ENODEV;
    }
    if (link->network_namespace != network_namespace) {
        edge_rtnl_unlock();
        return -EDGE_LINUX_ENODEV;
    }
    result = edge_net_device_set_ipv4(
        link->index, deleting ? 0u : ipv4,
        deleting ? 0u : address->prefix_length,
        link->ipv4_gateway);
    if (result < 0) {
        edge_rtnl_unlock();
        return edge_rtnl_core_error(result);
    }
    link->ipv4_address = deleting ? 0u : ipv4;
    link->prefix_length = deleting ? 0u : address->prefix_length;
    notify_ifindex = link->index;
    edge_rtnl_unlock();
    if (g_edge_rtnl_ipv4_update &&
        g_edge_rtnl_ipv4_update(
            notify_ifindex, network_namespace,
            ipv4, address->prefix_length, deleting ? 0 : 1) < 0)
        return -EDGE_LINUX_EIO;
    return 0;
}

void edge_linux_rtnetlink_set_ipv4_update_callback(
    edge_linux_rtnetlink_ipv4_update_fn callback) {
    g_edge_rtnl_ipv4_update = callback;
}

void edge_linux_rtnetlink_set_ipv4_provider(
    const edge_linux_rtnetlink_ipv4_provider_t *provider) {
    __atomic_store_n(&g_edge_rtnl_ipv4_provider, provider, __ATOMIC_RELEASE);
}

void edge_linux_rtnetlink_set_ipv6_provider(
    const edge_linux_rtnetlink_ipv6_provider_t *provider) {
    __atomic_store_n(&g_edge_rtnl_ipv6_provider, provider, __ATOMIC_RELEASE);
}

int edge_linux_rtnetlink_ipv4_is_local(uint32_t address) {
    uint32_t ordinal;
    int found = 0;

    if (!address) return 0;
    edge_rtnl_lock();
    for (ordinal = 0; ordinal < EDGE_RTNL_LINK_MAX; ++ordinal) {
        const edge_rtnl_link_t *link = &g_edge_rtnl_links[ordinal];

        if (link->used && link->ipv4_address == address) {
            found = 1;
            break;
        }
    }
    edge_rtnl_unlock();
    return found;
}

int edge_linux_rtnetlink_ipv4_is_local_in_namespace(
    uint32_t network_namespace, uint32_t address) {
    uint32_t ordinal;
    int found = 0;

    if (!address) return 0;
    edge_rtnl_lock();
    for (ordinal = 0; ordinal < EDGE_RTNL_LINK_MAX; ++ordinal) {
        const edge_rtnl_link_t *link = &g_edge_rtnl_links[ordinal];

        if (link->used &&
            link->network_namespace == network_namespace &&
            link->ipv4_address == address) {
            found = 1;
            break;
        }
    }
    edge_rtnl_unlock();
    return found;
}

int edge_linux_rtnetlink_ipv4_primary(
    uint32_t network_namespace, uint32_t *address) {
    uint32_t ordinal;
    int found = 0;

    if (!address) return -EDGE_LINUX_EINVAL;
    *address = 0;
    edge_rtnl_lock();
    for (ordinal = 0; ordinal < EDGE_RTNL_LINK_MAX; ++ordinal) {
        const edge_rtnl_link_t *link = &g_edge_rtnl_links[ordinal];

        if (!link->used || !link->ipv4_address ||
            link->network_namespace != network_namespace)
            continue;
        *address = link->ipv4_address;
        found = 1;
        break;
    }
    edge_rtnl_unlock();
    return found ? 0 : -EDGE_LINUX_ENOENT;
}

int edge_linux_rtnetlink_ipv4_owner(
    uint32_t address, uint32_t *network_namespace) {
    uint32_t ordinal;
    int found = 0;

    if (!address || !network_namespace) return -EDGE_LINUX_EINVAL;
    *network_namespace = 0;
    edge_rtnl_lock();
    for (ordinal = 0; ordinal < EDGE_RTNL_LINK_MAX; ++ordinal) {
        const edge_rtnl_link_t *link = &g_edge_rtnl_links[ordinal];

        if (!link->used || link->ipv4_address != address) continue;
        *network_namespace = link->network_namespace;
        found = 1;
        break;
    }
    edge_rtnl_unlock();
    return found ? 0 : -EDGE_LINUX_ENOENT;
}

static void edge_netfilter_namespace_purge(
    edge_netfilter_state_t *state, uint32_t network_namespace) {
    uint32_t index;

    if (!state) return;
    for (index = 0; index < EDGE_NETFILTER_TABLE_MAX; ++index) {
        if (state->tables[index].used &&
            state->tables[index].network_namespace == network_namespace)
            memset(&state->tables[index], 0, sizeof(state->tables[index]));
    }
    for (index = 0; index < EDGE_NETFILTER_CHAIN_MAX; ++index) {
        if (state->chains[index].used &&
            state->chains[index].network_namespace == network_namespace)
            memset(&state->chains[index], 0, sizeof(state->chains[index]));
    }
    for (index = 0; index < EDGE_NETFILTER_RULE_MAX; ++index) {
        if (state->rules[index].used &&
            state->rules[index].network_namespace == network_namespace)
            memset(&state->rules[index], 0, sizeof(state->rules[index]));
    }
}

void edge_linux_network_namespace_destroy(uint32_t network_namespace) {
    uint32_t ordinal;

    if (!network_namespace) return;
    edge_rtnl_lock();
    for (ordinal = 0; ordinal < EDGE_RTNL_LINK_MAX; ++ordinal) {
        edge_rtnl_link_t *link = &g_edge_rtnl_links[ordinal];
        int32_t peer_index;

        if (!link->used ||
            link->network_namespace != network_namespace)
            continue;
        peer_index = link->peer_index;
        edge_rtnl_remove_ipv6_interface(link);
        edge_rtnl_remove_interface_routes(link);
        if (peer_index > 0) {
            edge_rtnl_link_t *peer = edge_rtnl_find_index(peer_index);

            if (peer) {
                edge_rtnl_remove_ipv6_interface(peer);
                edge_rtnl_remove_interface_routes(peer);
            }
        }
        (void)edge_net_device_unregister(link->index);
        if (link->ipv4_address && g_edge_rtnl_ipv4_update)
            (void)g_edge_rtnl_ipv4_update(
                link->index, link->network_namespace,
                link->ipv4_address, link->prefix_length, 0);
        memset(link, 0, sizeof(*link));
        if (peer_index > 0) {
            edge_rtnl_link_t *peer = edge_rtnl_find_index(peer_index);

            if (peer) {
                if (peer->ipv4_address && g_edge_rtnl_ipv4_update)
                    (void)g_edge_rtnl_ipv4_update(
                        peer->index, peer->network_namespace,
                        peer->ipv4_address, peer->prefix_length, 0);
                memset(peer, 0, sizeof(*peer));
            }
        }
    }
    for (ordinal = 0; ordinal < EDGE_RTNL_ROUTE_MAX; ++ordinal) {
        if (g_edge_rtnl_routes[ordinal].used &&
            g_edge_rtnl_routes[ordinal].network_namespace ==
                network_namespace)
            memset(&g_edge_rtnl_routes[ordinal], 0,
                   sizeof(g_edge_rtnl_routes[ordinal]));
    }
    for (ordinal = 0; ordinal < EDGE_RTNL_RULE_MAX; ++ordinal) {
        if (g_edge_rtnl_rules[ordinal].used &&
            g_edge_rtnl_rules[ordinal].network_namespace ==
                network_namespace)
            memset(&g_edge_rtnl_rules[ordinal], 0,
                   sizeof(g_edge_rtnl_rules[ordinal]));
    }
    for (ordinal = 0; ordinal < EDGE_RTNL_NEXTHOP_OBJECT_MAX; ++ordinal) {
        if (g_edge_rtnl_nexthops[ordinal].used &&
            g_edge_rtnl_nexthops[ordinal].network_namespace ==
                network_namespace)
            memset(&g_edge_rtnl_nexthops[ordinal], 0,
                   sizeof(g_edge_rtnl_nexthops[ordinal]));
    }
    edge_rtnl_unlock();
    (void)edge_net_namespace_destroy(network_namespace);
    edge_netfilter_lock();
    edge_netfilter_namespace_purge(
        &g_edge_netfilter_state, network_namespace);
    edge_netfilter_namespace_purge(
        &g_edge_netfilter_staging, network_namespace);
    for (ordinal = 0; ordinal < EDGE_NETFILTER_CONNTRACK_MAX; ++ordinal) {
        if (g_edge_netfilter_conntrack[ordinal].used &&
            g_edge_netfilter_conntrack[ordinal].original.network_namespace ==
                network_namespace)
            memset(&g_edge_netfilter_conntrack[ordinal], 0,
                   sizeof(g_edge_netfilter_conntrack[ordinal]));
    }
    ++g_edge_netfilter_state.generation;
    ++g_edge_netfilter_staging.generation;
    edge_netfilter_unlock();
}

static int edge_rtnl_apply_route(
    uint32_t network_namespace,
    const edge_netfilter_nlmsghdr_t *request, int deleting) {
    const edge_rtnl_rtmsg_t *route =
        (const edge_rtnl_rtmsg_t *)(request + 1);
    uint32_t payload_offset = sizeof(*request) + sizeof(*route);
    uint32_t interface_index = 0;
    uint32_t gateway = 0;
    uint32_t notify_address = 0;
    uint8_t notify_prefix = 0;
    int32_t notify_ifindex = 0;
    edge_rtnl_link_t *link;
    int result;

    {
        edge_rtnl_route_t stored;
        uint32_t table;
        int simple_default;

        result = edge_rtnl_decode_route(
            network_namespace, request, &stored);
        if (result < 0) return result;
        table = stored.table;
        simple_default = table == EDGE_RT_TABLE_MAIN &&
            stored.destination_length == 0u &&
            stored.source_length == 0u &&
            stored.type == EDGE_RTN_UNICAST && stored.metric == 0u &&
            stored.mark == 0u && stored.input_ifindex == 0 &&
            stored.nexthop_id == 0u &&
            (stored.family != EDGE_AF_INET6 ||
             (network_namespace == 0u && stored.output_ifindex == 2));
        if (!simple_default)
            return edge_rtnl_store_route(
                &stored, request->flags, deleting);
    }

    if (route->family == EDGE_AF_INET6) {
        const edge_linux_rtnetlink_ipv6_provider_t *provider =
            __atomic_load_n(&g_edge_rtnl_ipv6_provider, __ATOMIC_ACQUIRE);
        const uint8_t *gateway_data;
        uint32_t gateway_length;

        if (network_namespace || route->destination_length != 0u) return 1;
        result = edge_rtnl_read_u32(
            request, payload_offset, EDGE_RTA_OIF, &interface_index);
        if (result < 0 && result != -EDGE_LINUX_ENOENT) return result;
        if (result == 0 && interface_index != 2u) return 1;
        if (!provider || !provider->configure_default_router)
            return -EDGE_LINUX_EOPNOTSUPP;
        result = edge_rtnl_find_attribute(
            request, payload_offset, EDGE_RTA_GATEWAY,
            &gateway_data, &gateway_length);
        if (result < 0) return result;
        if (gateway_length != 16u) return -EDGE_LINUX_EINVAL;
        return provider->configure_default_router(
                   gateway_data, deleting ? 0 : 1) == 0 ?
            0 : -EDGE_LINUX_EIO;
    }
    if (route->family != EDGE_AF_INET)
        return -EDGE_LINUX_EAFNOSUPPORT;
    result = edge_rtnl_read_u32(
        request, payload_offset, EDGE_RTA_OIF, &interface_index);
    if (result == -EDGE_LINUX_ENOENT || interface_index <= 2u) return 1;
    if (result < 0) return result;
    result = edge_rtnl_read_u32(
        request, payload_offset, EDGE_RTA_GATEWAY, &gateway);
    if (result < 0 && result != -EDGE_LINUX_ENOENT) return result;

    edge_rtnl_lock();
    link = edge_rtnl_find_index((int32_t)interface_index);
    if (!link) {
        edge_rtnl_unlock();
        return -EDGE_LINUX_ENODEV;
    }
    if (link->network_namespace != network_namespace) {
        edge_rtnl_unlock();
        return -EDGE_LINUX_ENODEV;
    }
    if (route->destination_length == 0u) {
        result = edge_net_device_set_ipv4(
            link->index, link->ipv4_address, link->prefix_length,
            deleting ? 0u : gateway);
        if (result < 0) {
            edge_rtnl_unlock();
            return edge_rtnl_core_error(result);
        }
        link->ipv4_gateway = deleting ? 0u : gateway;
        notify_ifindex = link->index;
        notify_address = link->ipv4_address;
        notify_prefix = link->prefix_length;
    }
    edge_rtnl_unlock();
    if (notify_address && g_edge_rtnl_ipv4_update &&
        g_edge_rtnl_ipv4_update(
            notify_ifindex, network_namespace, notify_address,
            notify_prefix, 1) < 0)
        return -EDGE_LINUX_EIO;
    return 0;
}

static int edge_rtnl_apply_ipv4_neighbor(
    uint32_t network_namespace,
    const edge_netfilter_nlmsghdr_t *request, int deleting) {
    const edge_rtnl_ndmsg_t *neighbor =
        (const edge_rtnl_ndmsg_t *)(request + 1);
    const edge_linux_rtnetlink_ipv4_provider_t *provider;
    uint32_t payload_offset = sizeof(*request) + sizeof(*neighbor);
    const uint8_t *destination;
    const uint8_t *hardware_address = 0;
    uint32_t destination_length;
    uint32_t hardware_address_length = 0u;
    uint32_t address;
    int result;

    if (neighbor->family != EDGE_AF_INET) return 1;
    if (neighbor->index <= 1) return -EDGE_LINUX_EINVAL;
    result = edge_rtnl_find_attribute(
        request, payload_offset, EDGE_NDA_DST,
        &destination, &destination_length);
    if (result < 0) return result;
    if (destination_length != sizeof(address)) return -EDGE_LINUX_EINVAL;
    memcpy(&address, destination, sizeof(address));
    result = edge_rtnl_find_attribute(
        request, payload_offset, EDGE_NDA_LLADDR,
        &hardware_address, &hardware_address_length);
    if (result < 0 && (!deleting || result != -EDGE_LINUX_ENOENT))
        return result;
    if (!deleting && hardware_address_length != 6u)
        return -EDGE_LINUX_EINVAL;
    if (deleting && hardware_address_length &&
        hardware_address_length != 6u)
        return -EDGE_LINUX_EINVAL;
    if (neighbor->index == 2) {
        if (network_namespace) return -EDGE_LINUX_ENODEV;
    } else {
        edge_rtnl_link_t *link;

        edge_rtnl_lock();
        link = edge_rtnl_find_index(neighbor->index);
        if (!link || link->network_namespace != network_namespace) {
            edge_rtnl_unlock();
            return -EDGE_LINUX_ENODEV;
        }
        edge_rtnl_unlock();
    }
    provider = __atomic_load_n(
        &g_edge_rtnl_ipv4_provider, __ATOMIC_ACQUIRE);
    if (!provider || !provider->configure_neighbor)
        return -EDGE_LINUX_EOPNOTSUPP;
    return provider->configure_neighbor(
        network_namespace, neighbor->index, address,
        hardware_address, neighbor->state, neighbor->flags,
        deleting ? 0 : 1) == 0 ? 0 : -EDGE_LINUX_EIO;
}

static int edge_rtnl_apply_bridge_neighbor(
    uint32_t network_namespace,
    const edge_netfilter_nlmsghdr_t *request, int deleting) {
    const edge_rtnl_ndmsg_t *neighbor =
        (const edge_rtnl_ndmsg_t *)(request + 1);
    uint32_t payload_offset = sizeof(*request) + sizeof(*neighbor);
    const uint8_t *hardware_address;
    uint32_t hardware_address_length;
    const uint8_t *vlan_data;
    uint32_t vlan_length;
    uint16_t vlan_id = 0u;
    edge_rtnl_link_t *port;
    int result;

    if (neighbor->family != EDGE_AF_BRIDGE) return 1;
    result = edge_rtnl_find_attribute(
        request, payload_offset, EDGE_NDA_LLADDR,
        &hardware_address, &hardware_address_length);
    if (result < 0) return result;
    if (hardware_address_length != 6u || neighbor->index <= 2)
        return -EDGE_LINUX_EINVAL;
    result = edge_rtnl_find_attribute(
        request, payload_offset, EDGE_NDA_VLAN,
        &vlan_data, &vlan_length);
    if (result == 0) {
        if (vlan_length != sizeof(vlan_id))
            return -EDGE_LINUX_EINVAL;
        memcpy(&vlan_id, vlan_data, sizeof(vlan_id));
        if (!vlan_id || vlan_id > EDGE_NET_BRIDGE_VLAN_MAX)
            return -EDGE_LINUX_EINVAL;
    } else if (result != -EDGE_LINUX_ENOENT) {
        return result;
    }
    edge_rtnl_lock();
    port = edge_rtnl_find_index(neighbor->index);
    if (!port || port->network_namespace != network_namespace) {
        edge_rtnl_unlock();
        return -EDGE_LINUX_ENODEV;
    }
    if (port->master <= 0) {
        edge_rtnl_unlock();
        return -EDGE_LINUX_EINVAL;
    }
    if (deleting) {
        result = edge_net_bridge_fdb_delete_vlan(
            port->master, hardware_address, vlan_id);
    } else {
        result = edge_net_bridge_fdb_add_vlan(
            port->master, hardware_address, port->index,
            vlan_id,
            (neighbor->state &
             (EDGE_NUD_NOARP | EDGE_NUD_PERMANENT)) != 0u,
            0u);
    }
    edge_rtnl_unlock();
    return edge_rtnl_core_error(result);
}

static int edge_rtnl_mdb_decode(
    const edge_rtnl_mdb_entry_t *source,
    edge_net_bridge_mdb_entry_t *destination) {
    const uint8_t *protocol;

    if (!source || !destination) return -EDGE_LINUX_EINVAL;
    memset(destination, 0, sizeof(*destination));
    destination->port_ifindex = (int32_t)source->ifindex;
    destination->vlan_id = source->vlan_id;
    destination->is_static = source->state == 1u ? 1u : 0u;
    protocol = (const uint8_t *)&source->protocol;
    if (protocol[0] == 0x08u && protocol[1] == 0x00u) {
        const uint8_t *address =
            (const uint8_t *)&source->address.ipv4;

        if (address[0] < 224u || address[0] > 239u)
            return -EDGE_LINUX_EINVAL;
        destination->family = EDGE_AF_INET;
        memcpy(destination->group_address, address, 4u);
        destination->hardware_address[0] = 0x01u;
        destination->hardware_address[1] = 0x00u;
        destination->hardware_address[2] = 0x5eu;
        destination->hardware_address[3] = address[1] & 0x7fu;
        destination->hardware_address[4] = address[2];
        destination->hardware_address[5] = address[3];
        return 0;
    }
    if (protocol[0] == 0x86u && protocol[1] == 0xddu) {
        if (source->address.ipv6[0] != 0xffu)
            return -EDGE_LINUX_EINVAL;
        destination->family = EDGE_AF_INET6;
        memcpy(destination->group_address, source->address.ipv6, 16u);
        destination->hardware_address[0] = 0x33u;
        destination->hardware_address[1] = 0x33u;
        memcpy(destination->hardware_address + 2u,
               source->address.ipv6 + 12u, 4u);
        return 0;
    }
    return -EDGE_LINUX_EAFNOSUPPORT;
}

static int edge_rtnl_apply_bridge_mdb(
    uint32_t network_namespace,
    const edge_netfilter_nlmsghdr_t *request, int deleting) {
    const edge_rtnl_bridge_port_message_t *message =
        (const edge_rtnl_bridge_port_message_t *)(request + 1);
    uint32_t payload_offset = sizeof(*request) + sizeof(*message);
    const uint8_t *entry_data;
    uint32_t entry_length;
    edge_rtnl_mdb_entry_t source;
    edge_net_bridge_mdb_entry_t entry;
    edge_rtnl_link_t *bridge;
    edge_rtnl_link_t *port;
    int result;

    if (message->family != EDGE_AF_BRIDGE || message->ifindex <= 2u)
        return -EDGE_LINUX_EINVAL;
    result = edge_rtnl_find_attribute(
        request, payload_offset, EDGE_MDBA_SET_ENTRY,
        &entry_data, &entry_length);
    if (result < 0) return result;
    if (entry_length < sizeof(source)) return -EDGE_LINUX_EINVAL;
    memcpy(&source, entry_data, sizeof(source));
    result = edge_rtnl_mdb_decode(&source, &entry);
    if (result < 0) return result;
    entry.bridge_ifindex = (int32_t)message->ifindex;
    edge_rtnl_lock();
    bridge = edge_rtnl_find_index((int32_t)message->ifindex);
    port = edge_rtnl_find_index((int32_t)source.ifindex);
    if (!bridge || !port ||
        bridge->network_namespace != network_namespace ||
        port->network_namespace != network_namespace) {
        edge_rtnl_unlock();
        return -EDGE_LINUX_ENODEV;
    }
    if (strcmp(bridge->kind, "bridge") != 0 ||
        port->master != bridge->index) {
        edge_rtnl_unlock();
        return -EDGE_LINUX_EINVAL;
    }
    if (deleting)
        result = edge_net_bridge_mdb_delete_group(
            bridge->index, port->index, entry.family,
            entry.group_address, entry.vlan_id);
    else
        result = edge_net_bridge_mdb_add(&entry);
    edge_rtnl_unlock();
    return edge_rtnl_core_error(result);
}

static int edge_rtnl_apply_qdisc(
    uint32_t network_namespace,
    const edge_netfilter_nlmsghdr_t *request, int deleting) {
    const edge_rtnl_tcmsg_t *message =
        (const edge_rtnl_tcmsg_t *)(request + 1);
    uint32_t payload_offset = sizeof(*request) + sizeof(*message);
    edge_net_device_snapshot_t device;
    edge_net_qdisc_configuration_t configuration;
    edge_rtnl_tc_fifo_options_t options;
    const uint8_t *options_data;
    uint32_t options_length;
    char kind[EDGE_RTNL_KIND_MAX];
    int result;

    if (message->index <= 1 ||
        (message->parent && message->parent != EDGE_TC_H_ROOT))
        return -EDGE_LINUX_EINVAL;
    result = edge_net_route_interface_snapshot(
        message->index, network_namespace, &device);
    if (result < 0) return edge_rtnl_core_error(result);
    if (deleting) {
        result = edge_net_qdisc_delete(message->index, message->handle);
        if (result == EDGE_NET_NOT_FOUND) return -EDGE_LINUX_ENOENT;
        return result < 0 ? edge_rtnl_core_error(result) : 0;
    }
    result = edge_rtnl_read_name(
        request, payload_offset, EDGE_TCA_KIND, kind);
    if (result < 0) return result;
    memset(&configuration, 0, sizeof(configuration));
    configuration.handle = message->handle;
    configuration.parent = EDGE_TC_H_ROOT;
    if (strcmp(kind, "pfifo") == 0)
        configuration.kind = EDGE_NET_QDISC_PFIFO;
    else if (strcmp(kind, "bfifo") == 0)
        configuration.kind = EDGE_NET_QDISC_BFIFO;
    else
        return -EDGE_LINUX_EOPNOTSUPP;
    result = edge_rtnl_find_attribute(
        request, payload_offset, EDGE_TCA_OPTIONS,
        &options_data, &options_length);
    if (result == -EDGE_LINUX_ENOENT) {
        uint64_t byte_limit;

        configuration.limit = configuration.kind == EDGE_NET_QDISC_PFIFO ?
            device.configuration.tx_queue_length : 0u;
        byte_limit = (uint64_t)device.configuration.tx_queue_length *
            device.configuration.mtu;
        if (configuration.kind == EDGE_NET_QDISC_BFIFO)
            configuration.limit = byte_limit > UINT32_MAX ?
                UINT32_MAX : (uint32_t)byte_limit;
    } else {
        if (result < 0) return result;
        if (options_length != sizeof(options))
            return -EDGE_LINUX_EINVAL;
        memcpy(&options, options_data, sizeof(options));
        configuration.limit = options.limit;
    }
    result = edge_net_qdisc_replace(message->index, &configuration);
    return result < 0 ? edge_rtnl_core_error(result) : 0;
}

static uint32_t edge_rtnl_notification_group(
    const edge_netfilter_nlmsghdr_t *request) {
    uint8_t family = 0u;

    if (!request || request->length < sizeof(*request)) return 0u;
    if (request->length > sizeof(*request))
        family = *((const uint8_t *)(request + 1));
    switch (request->type) {
        case EDGE_RTM_NEWLINK:
        case EDGE_RTM_SETLINK:
        case EDGE_RTM_DELLINK:
            return EDGE_RTNLGRP_LINK;
        case EDGE_RTM_NEWADDR:
        case EDGE_RTM_DELADDR:
            return family == EDGE_AF_INET6 ?
                EDGE_RTNLGRP_IPV6_IFADDR : EDGE_RTNLGRP_IPV4_IFADDR;
        case EDGE_RTM_NEWROUTE:
        case EDGE_RTM_DELROUTE:
            return family == EDGE_AF_INET6 ?
                EDGE_RTNLGRP_IPV6_ROUTE : EDGE_RTNLGRP_IPV4_ROUTE;
        case EDGE_RTM_NEWNEIGH:
        case EDGE_RTM_DELNEIGH:
            return EDGE_RTNLGRP_NEIGH;
        case EDGE_RTM_NEWRULE:
        case EDGE_RTM_DELRULE:
            return family == EDGE_AF_INET6 ?
                EDGE_RTNLGRP_IPV6_RULE : EDGE_RTNLGRP_IPV4_RULE;
        case EDGE_RTM_NEWQDISC:
        case EDGE_RTM_DELQDISC:
            return EDGE_RTNLGRP_TC;
        case EDGE_RTM_NEWMDB:
        case EDGE_RTM_DELMDB:
            return EDGE_RTNLGRP_MDB;
        case EDGE_RTM_NEWNEXTHOP:
        case EDGE_RTM_DELNEXTHOP:
            return EDGE_RTNLGRP_NEXTHOP;
        default:
            return 0u;
    }
}

static void edge_rtnl_notify_change(
    uint32_t network_namespace,
    const edge_netfilter_nlmsghdr_t *request) {
    uint32_t group = edge_rtnl_notification_group(request);
    uint16_t message_type;

    if (!group) return;
    message_type = request->type == EDGE_RTM_SETLINK ?
        EDGE_RTM_NEWLINK : request->type;
    (void)kernel_socket_broadcast_netlink_event(
        network_namespace, EDGE_LINUX_NETLINK_ROUTE, group,
        message_type, request, request->length);
}

static int edge_rtnl_apply_complete(
    uint32_t network_namespace,
    const edge_netfilter_nlmsghdr_t *request,
    int result, int *handled) {
    if (result == 1) return 0;
    if (handled) *handled = 1;
    if (result == 0) edge_rtnl_notify_change(network_namespace, request);
    return result;
}

int edge_linux_rtnetlink_apply(
    uint32_t network_namespace, const void *payload, uint32_t length,
    int *handled) {
    const edge_netfilter_nlmsghdr_t *request =
        (const edge_netfilter_nlmsghdr_t *)payload;
    int result;

    if (handled) *handled = 0;
    if (!payload || length < sizeof(*request) ||
        request->length < sizeof(*request) || request->length > length)
        return -EDGE_LINUX_EINVAL;
    if (request->type == EDGE_RTM_NEWLINK ||
        request->type == EDGE_RTM_SETLINK ||
        request->type == EDGE_RTM_DELLINK) {
        if (request->length < sizeof(*request) + sizeof(edge_rtnl_ifinfomsg_t))
            return -EDGE_LINUX_EINVAL;
        result = edge_rtnl_apply_link(
            network_namespace, request,
            request->type == EDGE_RTM_DELLINK);
        return edge_rtnl_apply_complete(
            network_namespace, request, result, handled);
    }
    if (request->type == EDGE_RTM_NEWADDR ||
        request->type == EDGE_RTM_DELADDR) {
        if (request->length < sizeof(*request) + sizeof(edge_rtnl_ifaddrmsg_t))
            return -EDGE_LINUX_EINVAL;
        result = edge_rtnl_apply_address(
            network_namespace, request,
            request->type == EDGE_RTM_DELADDR);
        return edge_rtnl_apply_complete(
            network_namespace, request, result, handled);
    }
    if (request->type == EDGE_RTM_NEWROUTE ||
        request->type == EDGE_RTM_DELROUTE) {
        if (request->length < sizeof(*request) + sizeof(edge_rtnl_rtmsg_t))
            return -EDGE_LINUX_EINVAL;
        result = edge_rtnl_apply_route(
            network_namespace, request,
            request->type == EDGE_RTM_DELROUTE);
        return edge_rtnl_apply_complete(
            network_namespace, request, result, handled);
    }
    if (request->type == EDGE_RTM_NEWNEIGH ||
        request->type == EDGE_RTM_DELNEIGH) {
        if (request->length < sizeof(*request) + sizeof(edge_rtnl_ndmsg_t))
            return -EDGE_LINUX_EINVAL;
        result = edge_rtnl_apply_ipv4_neighbor(
            network_namespace, request,
            request->type == EDGE_RTM_DELNEIGH);
        if (result == 1)
            result = edge_rtnl_apply_bridge_neighbor(
                network_namespace, request,
                request->type == EDGE_RTM_DELNEIGH);
        return edge_rtnl_apply_complete(
            network_namespace, request, result, handled);
    }
    if (request->type == EDGE_RTM_NEWRULE ||
        request->type == EDGE_RTM_DELRULE) {
        if (request->length < sizeof(*request) + sizeof(edge_rtnl_rulemsg_t))
            return -EDGE_LINUX_EINVAL;
        result = edge_rtnl_apply_rule(
            network_namespace, request,
            request->type == EDGE_RTM_DELRULE);
        return edge_rtnl_apply_complete(
            network_namespace, request, result, handled);
    }
    if (request->type == EDGE_RTM_NEWQDISC ||
        request->type == EDGE_RTM_DELQDISC) {
        if (request->length < sizeof(*request) + sizeof(edge_rtnl_tcmsg_t))
            return -EDGE_LINUX_EINVAL;
        result = edge_rtnl_apply_qdisc(
            network_namespace, request,
            request->type == EDGE_RTM_DELQDISC);
        return edge_rtnl_apply_complete(
            network_namespace, request, result, handled);
    }
    if (request->type == EDGE_RTM_NEWNEXTHOP ||
        request->type == EDGE_RTM_DELNEXTHOP) {
        if (request->length < sizeof(*request) + sizeof(edge_rtnl_nhmsg_t))
            return -EDGE_LINUX_EINVAL;
        result = edge_rtnl_apply_nexthop(
            network_namespace, request,
            request->type == EDGE_RTM_DELNEXTHOP);
        return edge_rtnl_apply_complete(
            network_namespace, request, result, handled);
    }
    if (request->type == EDGE_RTM_NEWMDB ||
        request->type == EDGE_RTM_DELMDB) {
        if (request->length < sizeof(*request) +
                sizeof(edge_rtnl_bridge_port_message_t))
            return -EDGE_LINUX_EINVAL;
        result = edge_rtnl_apply_bridge_mdb(
            network_namespace, request,
            request->type == EDGE_RTM_DELMDB);
        return edge_rtnl_apply_complete(
            network_namespace, request, result, handled);
    }
    return 0;
}

static int edge_rtnl_append_link(
    const edge_rtnl_link_t *link,
    const edge_netfilter_nlmsghdr_t *request, uint32_t port_id,
    uint8_t *response, uint32_t capacity, uint32_t *offset) {
    edge_netfilter_nlmsghdr_t header;
    edge_rtnl_ifinfomsg_t info;
    uint8_t linkinfo[160];
    uint8_t info_data[24];
    uint8_t slave_data[64];
    uint32_t slave_data_length = 0u;
    uint32_t linkinfo_length = 0;
    uint32_t info_data_length = 0;
    uint32_t start = *offset;
    edge_net_device_snapshot_t snapshot;
    int result;

    memset(&header, 0, sizeof(header));
    memset(&info, 0, sizeof(info));
    memset(&snapshot, 0, sizeof(snapshot));
    memset(linkinfo, 0, sizeof(linkinfo));
    memset(info_data, 0, sizeof(info_data));
    memset(slave_data, 0, sizeof(slave_data));
    header.type = EDGE_RTM_NEWLINK;
    if ((request->flags & EDGE_NLM_F_DUMP) == EDGE_NLM_F_DUMP)
        header.flags = EDGE_NLM_F_MULTI;
    header.sequence = request->sequence;
    header.port_id = port_id;
    info.type = link->type;
    if (request->length >= sizeof(*request) + sizeof(info)) {
        const edge_rtnl_ifinfomsg_t *query =
            (const edge_rtnl_ifinfomsg_t *)(request + 1);

        info.family = query->family;
    }
    info.index = link->index;
    info.flags = link->flags;
    if (edge_net_device_snapshot(link->index, &snapshot) == EDGE_NET_OK &&
        snapshot.configuration.carrier &&
        (snapshot.configuration.flags & EDGE_NET_DEVICE_FLAG_UP))
        info.flags |= EDGE_IFF_RUNNING | EDGE_IFF_LOWER_UP;
    else
        info.flags &= ~(EDGE_IFF_RUNNING | EDGE_IFF_LOWER_UP);
    info.change = UINT32_MAX;
    result = edge_netfilter_append(
        response, capacity, offset, &header, sizeof(header));
    if (result < 0) return result;
    result = edge_netfilter_append(
        response, capacity, offset, &info, sizeof(info));
    if (result < 0) return result;
    result = edge_netfilter_append_attribute(
        response, capacity, offset, EDGE_IFLA_ADDRESS,
        link->mac, sizeof(link->mac));
    if (result < 0) return result;
    result = edge_netfilter_append_attribute(
        response, capacity, offset, EDGE_IFLA_IFNAME,
        link->name, (uint32_t)strlen(link->name) + 1u);
    if (result < 0) return result;
    result = edge_netfilter_append_attribute(
        response, capacity, offset, EDGE_IFLA_MTU,
        &link->mtu, sizeof(link->mtu));
    if (result < 0) return result;
    if (link->master) {
        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_IFLA_MASTER,
            &link->master, sizeof(link->master));
        if (result < 0) return result;
    }
    if (link->peer_index || link->lower_index) {
        int32_t linked_index = link->peer_index ?
            link->peer_index : link->lower_index;

        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_IFLA_LINK,
            &linked_index, sizeof(linked_index));
        if (result < 0) return result;
    }
    result = edge_netfilter_append_attribute(
        linkinfo, sizeof(linkinfo), &linkinfo_length,
        EDGE_IFLA_INFO_KIND, link->kind,
        (uint32_t)strlen(link->kind) + 1u);
    if (result < 0) return result;
    if (strcmp(link->kind, "bridge") == 0) {
        uint8_t vlan_filtering = snapshot.bridge_vlan_filtering;

        result = edge_netfilter_append_attribute(
            info_data, sizeof(info_data), &info_data_length,
            EDGE_IFLA_BR_VLAN_FILTERING, &vlan_filtering,
            sizeof(vlan_filtering));
        if (result < 0) return result;
        result = edge_netfilter_append_attribute(
            linkinfo, sizeof(linkinfo), &linkinfo_length,
            EDGE_IFLA_INFO_DATA, info_data, info_data_length);
        if (result < 0) return result;
    } else if (strcmp(link->kind, "vlan") == 0) {
        uint8_t protocol[2];

        protocol[0] = (uint8_t)(link->vlan_protocol >> 8u);
        protocol[1] = (uint8_t)link->vlan_protocol;
        result = edge_netfilter_append_attribute(
            info_data, sizeof(info_data), &info_data_length,
            EDGE_IFLA_VLAN_ID, &link->vlan_id, sizeof(link->vlan_id));
        if (result < 0) return result;
        result = edge_netfilter_append_attribute(
            info_data, sizeof(info_data), &info_data_length,
            EDGE_IFLA_VLAN_PROTOCOL, protocol, sizeof(protocol));
        if (result < 0) return result;
        result = edge_netfilter_append_attribute(
            linkinfo, sizeof(linkinfo), &linkinfo_length,
            EDGE_IFLA_INFO_DATA, info_data, info_data_length);
        if (result < 0) return result;
    } else if (strcmp(link->kind, "macvlan") == 0) {
        uint32_t mode = link->virtual_mode;
        uint32_t flags = link->virtual_flags;

        result = edge_netfilter_append_attribute(
            info_data, sizeof(info_data), &info_data_length,
            EDGE_IFLA_MACVLAN_MODE, &mode, sizeof(mode));
        if (result < 0) return result;
        result = edge_netfilter_append_attribute(
            info_data, sizeof(info_data), &info_data_length,
            EDGE_IFLA_MACVLAN_FLAGS, &flags, sizeof(flags));
        if (result < 0) return result;
        result = edge_netfilter_append_attribute(
            linkinfo, sizeof(linkinfo), &linkinfo_length,
            EDGE_IFLA_INFO_DATA, info_data, info_data_length);
        if (result < 0) return result;
    } else if (strcmp(link->kind, "ipvlan") == 0) {
        result = edge_netfilter_append_attribute(
            info_data, sizeof(info_data), &info_data_length,
            EDGE_IFLA_IPVLAN_MODE, &link->virtual_mode,
            sizeof(link->virtual_mode));
        if (result < 0) return result;
        result = edge_netfilter_append_attribute(
            info_data, sizeof(info_data), &info_data_length,
            EDGE_IFLA_IPVLAN_FLAGS, &link->virtual_flags,
            sizeof(link->virtual_flags));
        if (result < 0) return result;
        result = edge_netfilter_append_attribute(
            linkinfo, sizeof(linkinfo), &linkinfo_length,
            EDGE_IFLA_INFO_DATA, info_data, info_data_length);
        if (result < 0) return result;
    } else if (strcmp(link->kind, "bond") == 0) {
        uint8_t mode = (uint8_t)link->virtual_mode;
        uint8_t hash_policy = (uint8_t)link->virtual_flags;

        result = edge_netfilter_append_attribute(
            info_data, sizeof(info_data), &info_data_length,
            EDGE_IFLA_BOND_MODE, &mode, sizeof(mode));
        if (result < 0) return result;
        result = edge_netfilter_append_attribute(
            info_data, sizeof(info_data), &info_data_length,
            EDGE_IFLA_BOND_XMIT_HASH_POLICY, &hash_policy,
            sizeof(hash_policy));
        if (result < 0) return result;
        result = edge_netfilter_append_attribute(
            linkinfo, sizeof(linkinfo), &linkinfo_length,
            EDGE_IFLA_INFO_DATA, info_data, info_data_length);
        if (result < 0) return result;
    } else if (strcmp(link->kind, "vrf") == 0) {
        result = edge_netfilter_append_attribute(
            info_data, sizeof(info_data), &info_data_length,
            EDGE_IFLA_VRF_TABLE, &link->routing_table,
            sizeof(link->routing_table));
        if (result < 0) return result;
        result = edge_netfilter_append_attribute(
            linkinfo, sizeof(linkinfo), &linkinfo_length,
            EDGE_IFLA_INFO_DATA, info_data, info_data_length);
        if (result < 0) return result;
    }
    if (link->master > 0) {
        edge_rtnl_link_t *master = edge_rtnl_find_index(link->master);

        if (master && strcmp(master->kind, "bridge") == 0) {
            uint8_t state = snapshot.bridge_state;
            uint8_t hairpin = snapshot.hairpin ? 1u : 0u;
            uint8_t learning = snapshot.bridge_learning ? 1u : 0u;
            uint8_t unicast_flood =
                snapshot.bridge_unicast_flood ? 1u : 0u;
            uint8_t multicast_flood =
                snapshot.bridge_multicast_flood ? 1u : 0u;
            uint8_t broadcast_flood =
                snapshot.bridge_broadcast_flood ? 1u : 0u;
            uint8_t isolated = snapshot.bridge_isolated ? 1u : 0u;

            result = edge_netfilter_append_attribute(
                slave_data, sizeof(slave_data), &slave_data_length,
                EDGE_IFLA_BRPORT_STATE, &state, sizeof(state));
            if (result < 0) return result;
            result = edge_netfilter_append_attribute(
                slave_data, sizeof(slave_data), &slave_data_length,
                EDGE_IFLA_BRPORT_MODE, &hairpin, sizeof(hairpin));
            if (result < 0) return result;
            result = edge_netfilter_append_attribute(
                slave_data, sizeof(slave_data), &slave_data_length,
                EDGE_IFLA_BRPORT_LEARNING, &learning, sizeof(learning));
            if (result < 0) return result;
            result = edge_netfilter_append_attribute(
                slave_data, sizeof(slave_data), &slave_data_length,
                EDGE_IFLA_BRPORT_UNICAST_FLOOD, &unicast_flood,
                sizeof(unicast_flood));
            if (result < 0) return result;
            result = edge_netfilter_append_attribute(
                slave_data, sizeof(slave_data), &slave_data_length,
                EDGE_IFLA_BRPORT_MCAST_FLOOD, &multicast_flood,
                sizeof(multicast_flood));
            if (result < 0) return result;
            result = edge_netfilter_append_attribute(
                slave_data, sizeof(slave_data), &slave_data_length,
                EDGE_IFLA_BRPORT_BCAST_FLOOD, &broadcast_flood,
                sizeof(broadcast_flood));
            if (result < 0) return result;
            result = edge_netfilter_append_attribute(
                slave_data, sizeof(slave_data), &slave_data_length,
                EDGE_IFLA_BRPORT_ISOLATED, &isolated,
                sizeof(isolated));
            if (result < 0) return result;
            result = edge_netfilter_append_attribute(
                linkinfo, sizeof(linkinfo), &linkinfo_length,
                EDGE_IFLA_INFO_SLAVE_KIND,
                "bridge", sizeof("bridge"));
            if (result < 0) return result;
            result = edge_netfilter_append_attribute(
                linkinfo, sizeof(linkinfo), &linkinfo_length,
                EDGE_IFLA_INFO_SLAVE_DATA,
                slave_data, slave_data_length);
            if (result < 0) return result;
            result = edge_netfilter_append_attribute(
                response, capacity, offset,
                EDGE_IFLA_PROTINFO | EDGE_NLA_F_NESTED,
                slave_data, slave_data_length);
            if (result < 0) return result;
        }
    }
    result = edge_netfilter_append_attribute(
        response, capacity, offset, EDGE_IFLA_LINKINFO,
        linkinfo, linkinfo_length);
    if (result < 0) return result;
    if (strcmp(link->kind, "bridge") == 0 ||
        (link->master > 0 &&
         edge_net_device_snapshot(link->master, &snapshot) == EDGE_NET_OK &&
         snapshot.configuration.kind == EDGE_NET_DEVICE_BRIDGE)) {
        edge_nlattr_t outer;
        uint32_t outer_start = *offset;
        uint32_t vlan_ordinal = 0u;
        edge_net_bridge_vlan_entry_t vlan_entry;

        memset(&outer, 0, sizeof(outer));
        outer.length = sizeof(outer);
        outer.type = EDGE_IFLA_AF_SPEC;
        result = edge_netfilter_append(
            response, capacity, offset, &outer, sizeof(outer));
        if (result < 0) return result;
        while (edge_net_bridge_vlan_snapshot(
                   link->index, vlan_ordinal++, &vlan_entry) ==
               EDGE_NET_OK) {
            edge_rtnl_bridge_vlan_info_t vlan;

            memset(&vlan, 0, sizeof(vlan));
            vlan.vlan_id = vlan_entry.vlan_id;
            if (vlan_entry.pvid)
                vlan.flags |= EDGE_BRIDGE_VLAN_INFO_PVID;
            if (vlan_entry.untagged)
                vlan.flags |= EDGE_BRIDGE_VLAN_INFO_UNTAGGED;
            result = edge_netfilter_append_attribute(
                response, capacity, offset, EDGE_IFLA_BRIDGE_VLAN_INFO,
                &vlan, sizeof(vlan));
            if (result < 0) return result;
        }
        ((edge_nlattr_t *)(response + outer_start))->length =
            (uint16_t)(*offset - outer_start);
    }
    ((edge_netfilter_nlmsghdr_t *)(response + start))->length =
        *offset - start;
    return 0;
}

int edge_linux_rtnetlink_append_links(
    uint32_t network_namespace, uint32_t port_id,
    const void *payload, uint32_t length,
    void *response, uint32_t capacity, uint32_t *offset,
    uint32_t *match_count) {
    const edge_netfilter_nlmsghdr_t *request =
        (const edge_netfilter_nlmsghdr_t *)payload;
    edge_rtnl_ifinfomsg_t query_storage;
    const edge_rtnl_ifinfomsg_t *query;
    uint32_t payload_offset;
    char wanted_name[EDGE_RTNL_NAME_MAX];
    int have_name;
    uint32_t ordinal;
    int result = 0;

    if (!payload || !response || !offset || !match_count ||
        length < sizeof(*request) || request->length < sizeof(*request) ||
        request->length > length || request->type != EDGE_RTM_GETLINK)
        return -EDGE_LINUX_EINVAL;
    memset(&query_storage, 0, sizeof(query_storage));
    if (request->length >= sizeof(*request) + sizeof(query_storage)) {
        memcpy(&query_storage, request + 1, sizeof(query_storage));
    } else if ((request->flags & EDGE_NLM_F_DUMP) != EDGE_NLM_F_DUMP) {
        return -EDGE_LINUX_EINVAL;
    }
    query = &query_storage;
    payload_offset = sizeof(*request) + sizeof(*query);
    have_name = request->length >= payload_offset &&
        edge_rtnl_read_name(
            request, payload_offset, EDGE_IFLA_IFNAME, wanted_name) == 0;
    edge_rtnl_lock();
    for (ordinal = 0; ordinal < EDGE_RTNL_LINK_MAX; ++ordinal) {
        const edge_rtnl_link_t *link = &g_edge_rtnl_links[ordinal];

        if (!link->used ||
            link->network_namespace != network_namespace ||
            (query->index && query->index != link->index) ||
            (have_name && strcmp(wanted_name, link->name) != 0))
            continue;
        result = edge_rtnl_append_link(
            link, request, port_id, (uint8_t *)response,
            capacity, offset);
        if (result < 0) break;
        ++*match_count;
        if ((request->flags & EDGE_NLM_F_DUMP) != EDGE_NLM_F_DUMP)
            break;
    }
    edge_rtnl_unlock();
    return result;
}

static int edge_rtnl_append_qdisc(
    int32_t ifindex, const edge_net_qdisc_snapshot_t *source,
    const edge_netfilter_nlmsghdr_t *request, uint32_t port_id,
    uint8_t *response, uint32_t capacity, uint32_t *offset) {
    edge_netfilter_nlmsghdr_t header;
    edge_rtnl_tcmsg_t message;
    edge_rtnl_tc_fifo_options_t options;
    edge_rtnl_tc_stats_t statistics;
    edge_rtnl_gnet_basic_t basic;
    edge_rtnl_gnet_queue_t queue;
    uint8_t statistics2[64];
    uint32_t statistics2_length = 0u;
    const char *kind;
    uint32_t start = *offset;
    int result;

    if (!source) return -EDGE_LINUX_EINVAL;
    if (source->configuration.kind == EDGE_NET_QDISC_NOQUEUE)
        kind = "noqueue";
    else if (source->configuration.kind == EDGE_NET_QDISC_PFIFO)
        kind = "pfifo";
    else if (source->configuration.kind == EDGE_NET_QDISC_BFIFO)
        kind = "bfifo";
    else
        return -EDGE_LINUX_EOPNOTSUPP;
    memset(&header, 0, sizeof(header));
    memset(&message, 0, sizeof(message));
    memset(&statistics, 0, sizeof(statistics));
    memset(&basic, 0, sizeof(basic));
    memset(&queue, 0, sizeof(queue));
    header.type = EDGE_RTM_NEWQDISC;
    if ((request->flags & EDGE_NLM_F_DUMP) == EDGE_NLM_F_DUMP)
        header.flags = EDGE_NLM_F_MULTI;
    header.sequence = request->sequence;
    header.port_id = port_id;
    message.family = 0u;
    message.index = ifindex;
    message.handle = source->configuration.handle;
    message.parent = EDGE_TC_H_ROOT;
    statistics.bytes = source->bytes;
    statistics.packets = source->packets > UINT32_MAX ?
        UINT32_MAX : (uint32_t)source->packets;
    statistics.drops = source->drops > UINT32_MAX ?
        UINT32_MAX : (uint32_t)source->drops;
    statistics.queue_length = source->queue_length;
    statistics.backlog = source->backlog;
    basic.bytes = source->bytes;
    basic.packets = source->packets;
    queue.queue_length = source->queue_length;
    queue.backlog = source->backlog;
    queue.drops = statistics.drops;
    result = edge_netfilter_append_attribute(
        statistics2, sizeof(statistics2), &statistics2_length,
        EDGE_TCA_STATS_BASIC, &basic, sizeof(basic));
    if (result == 0)
        result = edge_netfilter_append_attribute(
            statistics2, sizeof(statistics2), &statistics2_length,
            EDGE_TCA_STATS_QUEUE, &queue, sizeof(queue));
    if (result < 0) return result;
    result = edge_netfilter_append(
        response, capacity, offset, &header, sizeof(header));
    if (result == 0)
        result = edge_netfilter_append(
            response, capacity, offset, &message, sizeof(message));
    if (result == 0)
        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_TCA_KIND,
            kind, (uint32_t)strlen(kind) + 1u);
    if (result == 0 &&
        source->configuration.kind != EDGE_NET_QDISC_NOQUEUE) {
        options.limit = source->configuration.limit;
        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_TCA_OPTIONS,
            &options, sizeof(options));
    }
    if (result == 0)
        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_TCA_STATS,
            &statistics, sizeof(statistics));
    if (result == 0)
        result = edge_netfilter_append_attribute(
            response, capacity, offset,
            (uint16_t)(EDGE_TCA_STATS2 | EDGE_NLA_F_NESTED),
            statistics2, statistics2_length);
    if (result == 0)
        ((edge_netfilter_nlmsghdr_t *)(response + start))->length =
            *offset - start;
    return result;
}

int edge_linux_rtnetlink_append_qdiscs(
    uint32_t network_namespace, uint32_t port_id,
    const void *payload, uint32_t length,
    void *response, uint32_t capacity, uint32_t *offset,
    uint32_t *match_count) {
    const edge_netfilter_nlmsghdr_t *request =
        (const edge_netfilter_nlmsghdr_t *)payload;
    edge_rtnl_tcmsg_t query;
    uint32_t ordinal;
    int result;

    if (!payload || !response || !offset || !match_count ||
        length < sizeof(*request) || request->length < sizeof(*request) ||
        request->length > length || request->type != EDGE_RTM_GETQDISC)
        return -EDGE_LINUX_EINVAL;
    memset(&query, 0, sizeof(query));
    if (request->length >= sizeof(*request) + sizeof(query))
        memcpy(&query, request + 1, sizeof(query));
    else if ((request->flags & EDGE_NLM_F_DUMP) != EDGE_NLM_F_DUMP)
        return -EDGE_LINUX_EINVAL;
    if (!query.index || query.index == 1) {
        edge_net_qdisc_snapshot_t noqueue;

        memset(&noqueue, 0, sizeof(noqueue));
        noqueue.configuration.kind = EDGE_NET_QDISC_NOQUEUE;
        noqueue.configuration.parent = EDGE_TC_H_ROOT;
        result = edge_rtnl_append_qdisc(
            1, &noqueue, request, port_id, (uint8_t *)response,
            capacity, offset);
        if (result < 0) return result;
        ++*match_count;
        if ((request->flags & EDGE_NLM_F_DUMP) != EDGE_NLM_F_DUMP)
            return 0;
    }
    for (ordinal = 0u; ; ++ordinal) {
        edge_net_device_snapshot_t device;
        edge_net_qdisc_snapshot_t qdisc;

        result = edge_net_device_snapshot_at(
            network_namespace, ordinal, &device);
        if (result == EDGE_NET_NOT_FOUND) break;
        if (result < 0) return edge_rtnl_core_error(result);
        if (query.index && query.index !=
                device.configuration.ifindex)
            continue;
        result = edge_net_qdisc_snapshot(
            device.configuration.ifindex, &qdisc);
        if (result < 0) return edge_rtnl_core_error(result);
        result = edge_rtnl_append_qdisc(
            device.configuration.ifindex, &qdisc, request, port_id,
            (uint8_t *)response, capacity, offset);
        if (result < 0) return result;
        ++*match_count;
        if ((request->flags & EDGE_NLM_F_DUMP) != EDGE_NLM_F_DUMP)
            return 0;
    }
    return 0;
}

static uint32_t edge_rtnl_ipv4_broadcast(
    uint32_t address, uint8_t prefix_length) {
    uint8_t *bytes = (uint8_t *)&address;
    uint32_t bit;

    for (bit = prefix_length; bit < 32u; ++bit)
        bytes[bit / 8u] |= (uint8_t)(1u << (7u - (bit % 8u)));
    return address;
}

static int edge_rtnl_append_ipv6_address(
    const edge_linux_rtnetlink_ipv6_address_t *source,
    int32_t ifindex,
    const edge_netfilter_nlmsghdr_t *request, uint32_t port_id,
    uint8_t *response, uint32_t capacity, uint32_t *offset) {
    edge_netfilter_nlmsghdr_t header;
    edge_rtnl_ifaddrmsg_t address;
    edge_rtnl_ifa_cacheinfo_t cacheinfo;
    uint32_t flags;
    uint32_t start = *offset;
    int result;

    memset(&header, 0, sizeof(header));
    memset(&address, 0, sizeof(address));
    memset(&cacheinfo, 0, sizeof(cacheinfo));
    header.type = EDGE_RTM_NEWADDR;
    if ((request->flags & EDGE_NLM_F_DUMP) == EDGE_NLM_F_DUMP)
        header.flags = EDGE_NLM_F_MULTI;
    header.sequence = request->sequence;
    header.port_id = port_id;
    address.family = EDGE_AF_INET6;
    address.prefix_length = source->prefix_length;
    address.flags = source->flags;
    address.scope = source->scope;
    address.index = (uint32_t)ifindex;
    flags = source->flags;
    cacheinfo.preferred = source->preferred_lifetime;
    cacheinfo.valid = source->valid_lifetime;
    result = edge_netfilter_append(
        response, capacity, offset, &header, sizeof(header));
    if (result == 0)
        result = edge_netfilter_append(
            response, capacity, offset, &address, sizeof(address));
    if (result == 0)
        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_IFA_ADDRESS,
            source->address, sizeof(source->address));
    if (result == 0)
        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_IFA_CACHEINFO,
            &cacheinfo, sizeof(cacheinfo));
    if (result == 0)
        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_IFA_FLAGS,
            &flags, sizeof(flags));
    if (result == 0)
        ((edge_netfilter_nlmsghdr_t *)(response + start))->length =
            *offset - start;
    return result;
}

int edge_linux_rtnetlink_append_addresses(
    uint32_t network_namespace, uint32_t port_id,
    const void *payload, uint32_t length,
    void *response, uint32_t capacity, uint32_t *offset,
    uint32_t *match_count) {
    const edge_netfilter_nlmsghdr_t *request =
        (const edge_netfilter_nlmsghdr_t *)payload;
    edge_rtnl_ifaddrmsg_t query_storage;
    const edge_rtnl_ifaddrmsg_t *query;
    uint32_t ordinal;
    int result = 0;

    if (!payload || !response || !offset || !match_count ||
        length < sizeof(*request) || request->length < sizeof(*request) ||
        request->length > length || request->type != EDGE_RTM_GETADDR)
        return -EDGE_LINUX_EINVAL;
    memset(&query_storage, 0, sizeof(query_storage));
    if (request->length >= sizeof(*request) + sizeof(query_storage)) {
        memcpy(&query_storage, request + 1, sizeof(query_storage));
    } else if ((request->flags & EDGE_NLM_F_DUMP) != EDGE_NLM_F_DUMP) {
        return -EDGE_LINUX_EINVAL;
    }
    query = &query_storage;
    if (query->family != 0u && query->family != EDGE_AF_INET &&
        query->family != EDGE_AF_INET6)
        return 0;

    if (!network_namespace &&
        (query->family == 0u || query->family == EDGE_AF_INET6) &&
        (!query->index || query->index == 2u)) {
        const edge_linux_rtnetlink_ipv6_provider_t *provider =
            __atomic_load_n(&g_edge_rtnl_ipv6_provider, __ATOMIC_ACQUIRE);

        if (provider && provider->address_at) {
            for (int index = 0; ; ++index) {
                edge_linux_rtnetlink_ipv6_address_t address;

                if (provider->address_at(index, &address) < 0) break;
                result = edge_rtnl_append_ipv6_address(
                    &address, 2, request, port_id, (uint8_t *)response,
                    capacity, offset);
                if (result < 0) return result;
                ++*match_count;
                if ((request->flags & EDGE_NLM_F_DUMP) != EDGE_NLM_F_DUMP)
                    return 0;
            }
        }
    }
    if (query->family == 0u || query->family == EDGE_AF_INET6) {
        edge_rtnl_lock();
        for (ordinal = 0; ordinal < EDGE_RTNL_LINK_MAX; ++ordinal) {
            const edge_rtnl_link_t *link = &g_edge_rtnl_links[ordinal];

            if (!link->used ||
                link->network_namespace != network_namespace ||
                (query->index && query->index != (uint32_t)link->index))
                continue;
            for (uint32_t address_ordinal = 0;
                 address_ordinal < EDGE_RTNL_IPV6_ADDRESS_MAX;
                 ++address_ordinal) {
                const edge_rtnl_ipv6_address_t *stored =
                    &link->ipv6_addresses[address_ordinal];
                edge_linux_rtnetlink_ipv6_address_t address;

                if (!stored->used) continue;
                memset(&address, 0, sizeof(address));
                memcpy(address.address, stored->address,
                       sizeof(address.address));
                address.prefix_length = stored->prefix_length;
                address.scope = stored->scope;
                address.flags = stored->flags;
                address.valid_lifetime = stored->valid_lifetime;
                address.preferred_lifetime = stored->preferred_lifetime;
                result = edge_rtnl_append_ipv6_address(
                    &address, link->index, request, port_id,
                    (uint8_t *)response, capacity, offset);
                if (result < 0) {
                    edge_rtnl_unlock();
                    return result;
                }
                ++*match_count;
                if ((request->flags & EDGE_NLM_F_DUMP) !=
                    EDGE_NLM_F_DUMP) {
                    edge_rtnl_unlock();
                    return 0;
                }
            }
        }
        edge_rtnl_unlock();
    }
    if ((query->family == 0u || query->family == EDGE_AF_INET6) &&
        (!query->index || query->index == 1u)) {
        static const edge_linux_rtnetlink_ipv6_address_t loopback = {
            .address = {
                0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
                0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u
            },
            .prefix_length = 128u,
            .scope = EDGE_RT_SCOPE_HOST,
            .flags = 0x80u,
            .valid_lifetime = UINT32_MAX,
            .preferred_lifetime = UINT32_MAX,
        };

        result = edge_rtnl_append_ipv6_address(
            &loopback, 1, request, port_id, (uint8_t *)response,
            capacity, offset);
        if (result < 0) return result;
        ++*match_count;
        if ((request->flags & EDGE_NLM_F_DUMP) != EDGE_NLM_F_DUMP)
            return 0;
    }
    if (query->family == EDGE_AF_INET6) return 0;

    edge_rtnl_lock();
    for (ordinal = 0; ordinal < EDGE_RTNL_LINK_MAX; ++ordinal) {
        const edge_rtnl_link_t *link = &g_edge_rtnl_links[ordinal];
        edge_netfilter_nlmsghdr_t header;
        edge_rtnl_ifaddrmsg_t address;
        uint32_t broadcast;
        uint32_t start;

        if (!link->used || !link->ipv4_address ||
            link->network_namespace != network_namespace ||
            (query->index && query->index != (uint32_t)link->index))
            continue;
        memset(&header, 0, sizeof(header));
        memset(&address, 0, sizeof(address));
        header.type = EDGE_RTM_NEWADDR;
        if ((request->flags & EDGE_NLM_F_DUMP) == EDGE_NLM_F_DUMP)
            header.flags = EDGE_NLM_F_MULTI;
        header.sequence = request->sequence;
        header.port_id = port_id;
        address.family = EDGE_AF_INET;
        address.prefix_length = link->prefix_length;
        address.index = (uint32_t)link->index;
        broadcast = edge_rtnl_ipv4_broadcast(
            link->ipv4_address, link->prefix_length);
        start = *offset;
        result = edge_netfilter_append(
            response, capacity, offset, &header, sizeof(header));
        if (result == 0)
            result = edge_netfilter_append(
                response, capacity, offset, &address, sizeof(address));
        if (result == 0)
            result = edge_netfilter_append_attribute(
                response, capacity, offset, EDGE_IFA_ADDRESS,
                &link->ipv4_address, sizeof(link->ipv4_address));
        if (result == 0)
            result = edge_netfilter_append_attribute(
                response, capacity, offset, EDGE_IFA_LOCAL,
                &link->ipv4_address, sizeof(link->ipv4_address));
        if (result == 0)
            result = edge_netfilter_append_attribute(
                response, capacity, offset, EDGE_IFA_BROADCAST,
                &broadcast, sizeof(broadcast));
        if (result < 0) break;
        ((edge_netfilter_nlmsghdr_t *)
            ((uint8_t *)response + start))->length = *offset - start;
        ++*match_count;
        if ((request->flags & EDGE_NLM_F_DUMP) != EDGE_NLM_F_DUMP)
            break;
    }
    edge_rtnl_unlock();
    return result;
}

static int edge_rtnl_ipv4_prefix_matches(
    uint32_t first, uint32_t second, uint8_t prefix_length) {
    const uint8_t *first_bytes = (const uint8_t *)&first;
    const uint8_t *second_bytes = (const uint8_t *)&second;
    uint32_t full_bytes = prefix_length / 8u;
    uint32_t remainder = prefix_length % 8u;
    uint32_t index;

    for (index = 0; index < full_bytes; ++index) {
        if (first_bytes[index] != second_bytes[index]) return 0;
    }
    if (remainder) {
        uint8_t mask = (uint8_t)(0xffu << (8u - remainder));

        if ((first_bytes[full_bytes] & mask) !=
            (second_bytes[full_bytes] & mask)) return 0;
    }
    return 1;
}

static uint32_t edge_rtnl_ipv4_mask_prefix(
    uint32_t address, uint8_t prefix_length) {
    uint8_t *bytes = (uint8_t *)&address;
    uint32_t bit;

    for (bit = prefix_length; bit < 32u; ++bit)
        bytes[bit / 8u] &= (uint8_t)~(1u << (7u - (bit % 8u)));
    return address;
}

static int edge_rtnl_append_ipv4_route_message(
    const edge_netfilter_nlmsghdr_t *request, uint32_t port_id,
    uint8_t *response, uint32_t capacity, uint32_t *offset,
    uint32_t destination, uint8_t prefix_length, uint32_t gateway,
    uint32_t preferred_source, int32_t interface_index,
    uint8_t protocol, uint8_t scope) {
    edge_netfilter_nlmsghdr_t header;
    edge_rtnl_rtmsg_t route;
    uint32_t start = *offset;
    int result;

    memset(&header, 0, sizeof(header));
    memset(&route, 0, sizeof(route));
    header.type = EDGE_RTM_NEWROUTE;
    if ((request->flags & EDGE_NLM_F_DUMP) == EDGE_NLM_F_DUMP)
        header.flags = EDGE_NLM_F_MULTI;
    header.sequence = request->sequence;
    header.port_id = port_id;
    route.family = EDGE_AF_INET;
    route.destination_length = prefix_length;
    route.table = EDGE_RT_TABLE_MAIN;
    route.protocol = protocol;
    route.scope = scope;
    route.type = EDGE_RTN_UNICAST;
    result = edge_netfilter_append(
        response, capacity, offset, &header, sizeof(header));
    if (result == 0)
        result = edge_netfilter_append(
            response, capacity, offset, &route, sizeof(route));
    if (result == 0 && prefix_length)
        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_RTA_DST,
            &destination, sizeof(destination));
    if (result == 0)
        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_RTA_OIF,
            &interface_index, sizeof(interface_index));
    if (result == 0 && gateway)
        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_RTA_GATEWAY,
            &gateway, sizeof(gateway));
    if (result == 0 && preferred_source)
        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_RTA_PREFSRC,
            &preferred_source, sizeof(preferred_source));
    if (result == 0)
        ((edge_netfilter_nlmsghdr_t *)(response + start))->length =
            *offset - start;
    return result;
}

static int edge_rtnl_ipv6_prefix_matches(
    const uint8_t first[16], const uint8_t second[16],
    uint8_t prefix_length) {
    uint32_t full_bytes = prefix_length / 8u;
    uint32_t remainder = prefix_length % 8u;

    if (full_bytes && memcmp(first, second, full_bytes) != 0) return 0;
    if (remainder) {
        uint8_t mask = (uint8_t)(0xffu << (8u - remainder));
        if ((first[full_bytes] & mask) != (second[full_bytes] & mask))
            return 0;
    }
    return 1;
}

static void edge_rtnl_ipv6_mask_prefix(
    uint8_t address[16], uint8_t prefix_length) {
    for (uint32_t bit = prefix_length; bit < 128u; ++bit)
        address[bit / 8u] &= (uint8_t)~(1u << (7u - (bit % 8u)));
}

static int edge_rtnl_append_ipv6_route_message(
    const edge_netfilter_nlmsghdr_t *request, uint32_t port_id,
    uint8_t *response, uint32_t capacity, uint32_t *offset,
    const uint8_t *destination, uint8_t prefix_length,
    const uint8_t *gateway, const uint8_t *preferred_source,
    int32_t interface_index, uint8_t protocol, uint8_t scope) {
    edge_netfilter_nlmsghdr_t header;
    edge_rtnl_rtmsg_t route;
    uint32_t start = *offset;
    int result;

    memset(&header, 0, sizeof(header));
    memset(&route, 0, sizeof(route));
    header.type = EDGE_RTM_NEWROUTE;
    if ((request->flags & EDGE_NLM_F_DUMP) == EDGE_NLM_F_DUMP)
        header.flags = EDGE_NLM_F_MULTI;
    header.sequence = request->sequence;
    header.port_id = port_id;
    route.family = EDGE_AF_INET6;
    route.destination_length = prefix_length;
    route.table = EDGE_RT_TABLE_MAIN;
    route.protocol = protocol;
    route.scope = scope;
    route.type = EDGE_RTN_UNICAST;
    result = edge_netfilter_append(
        response, capacity, offset, &header, sizeof(header));
    if (result == 0)
        result = edge_netfilter_append(
            response, capacity, offset, &route, sizeof(route));
    if (result == 0 && destination && prefix_length)
        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_RTA_DST, destination, 16u);
    if (result == 0)
        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_RTA_OIF,
            &interface_index, sizeof(interface_index));
    if (result == 0 && gateway)
        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_RTA_GATEWAY, gateway, 16u);
    if (result == 0 && preferred_source)
        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_RTA_PREFSRC,
            preferred_source, 16u);
    if (result == 0)
        ((edge_netfilter_nlmsghdr_t *)(response + start))->length =
            *offset - start;
    return result;
}

static int edge_rtnl_address_is_zero(
    const uint8_t *address, uint32_t length) {
    uint32_t index;

    for (index = 0; index < length; ++index) {
        if (address[index]) return 0;
    }
    return 1;
}

static int edge_rtnl_prefix_matches(
    const uint8_t *prefix, const uint8_t *address,
    uint8_t prefix_length) {
    uint32_t full_bytes = prefix_length / 8u;
    uint32_t remainder = prefix_length % 8u;

    if (full_bytes && memcmp(prefix, address, full_bytes) != 0) return 0;
    if (remainder) {
        uint8_t mask = (uint8_t)(0xffu << (8u - remainder));

        if ((prefix[full_bytes] & mask) !=
            (address[full_bytes] & mask)) return 0;
    }
    return 1;
}

static int edge_rtnl_append_stored_route(
    const edge_rtnl_route_t *entry,
    const edge_netfilter_nlmsghdr_t *request, uint32_t port_id,
    uint8_t *response, uint32_t capacity, uint32_t *offset) {
    edge_netfilter_nlmsghdr_t header;
    edge_rtnl_rtmsg_t route;
    uint32_t address_length = entry->family == EDGE_AF_INET ? 4u : 16u;
    uint32_t start = *offset;
    int result;

    memset(&header, 0, sizeof(header));
    memset(&route, 0, sizeof(route));
    header.type = EDGE_RTM_NEWROUTE;
    if ((request->flags & EDGE_NLM_F_DUMP) == EDGE_NLM_F_DUMP)
        header.flags = EDGE_NLM_F_MULTI;
    header.sequence = request->sequence;
    header.port_id = port_id;
    route.family = entry->family;
    route.destination_length = entry->destination_length;
    route.source_length = entry->source_length;
    route.tos = entry->tos;
    route.table = entry->table <= UINT8_MAX ? (uint8_t)entry->table : 0u;
    route.protocol = entry->protocol;
    route.scope = entry->scope;
    route.type = entry->type;
    result = edge_netfilter_append(
        response, capacity, offset, &header, sizeof(header));
    if (result == 0)
        result = edge_netfilter_append(
            response, capacity, offset, &route, sizeof(route));
    if (result == 0 && entry->destination_length)
        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_RTA_DST,
            entry->destination, address_length);
    if (result == 0 && entry->source_length)
        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_RTA_SRC,
            entry->source, address_length);
    if (result == 0 && entry->input_ifindex)
        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_RTA_IIF,
            &entry->input_ifindex, sizeof(entry->input_ifindex));
    if (result == 0 && entry->output_ifindex)
        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_RTA_OIF,
            &entry->output_ifindex, sizeof(entry->output_ifindex));
    if (result == 0 && !edge_rtnl_address_is_zero(
            entry->gateway, address_length))
        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_RTA_GATEWAY,
            entry->gateway, address_length);
    if (result == 0 && entry->metric)
        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_RTA_PRIORITY,
            &entry->metric, sizeof(entry->metric));
    if (result == 0 && !edge_rtnl_address_is_zero(
            entry->preferred_source, address_length))
        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_RTA_PREFSRC,
            entry->preferred_source, address_length);
    if (result == 0 && entry->nexthop_count) {
        uint8_t multipath[EDGE_RTNEXTHOP_MAX *
                          (sizeof(edge_rtnl_wire_nexthop_t) + 20u)];
        uint32_t multipath_length = 0u;
        uint32_t ordinal;

        memset(multipath, 0, sizeof(multipath));
        for (ordinal = 0; ordinal < entry->nexthop_count; ++ordinal) {
            const edge_rtnl_nexthop_t *source = &entry->nexthops[ordinal];
            edge_rtnl_wire_nexthop_t wire;
            uint32_t nexthop_start = multipath_length;

            memset(&wire, 0, sizeof(wire));
            wire.length = sizeof(wire);
            wire.flags = source->flags;
            wire.hops = source->hops;
            wire.output_ifindex = source->output_ifindex;
            result = edge_netfilter_append(
                multipath, sizeof(multipath), &multipath_length,
                &wire, sizeof(wire));
            if (result < 0) break;
            if (!edge_rtnl_address_is_zero(
                    source->gateway, address_length)) {
                result = edge_netfilter_append_attribute(
                    multipath, sizeof(multipath), &multipath_length,
                    EDGE_RTA_GATEWAY, source->gateway, address_length);
                if (result < 0) break;
            }
            ((edge_rtnl_wire_nexthop_t *)
                (multipath + nexthop_start))->length =
                    (uint16_t)(multipath_length - nexthop_start);
        }
        if (result == 0)
            result = edge_netfilter_append_attribute(
                response, capacity, offset, EDGE_RTA_MULTIPATH,
                multipath, multipath_length);
    }
    if (result == 0)
        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_RTA_TABLE,
            &entry->table, sizeof(entry->table));
    if (result == 0 && entry->mark)
        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_RTA_MARK,
            &entry->mark, sizeof(entry->mark));
    if (result == 0 && entry->nexthop_id)
        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_RTA_NH_ID,
            &entry->nexthop_id, sizeof(entry->nexthop_id));
    if (result == 0)
        ((edge_netfilter_nlmsghdr_t *)(response + start))->length =
            *offset - start;
    return result;
}

static int edge_rtnl_append_matching_stored_routes(
    uint32_t network_namespace, const edge_netfilter_nlmsghdr_t *request,
    const edge_rtnl_rtmsg_t *query, uint32_t payload_offset,
    uint32_t port_id, uint8_t *response, uint32_t capacity,
    uint32_t *offset, uint32_t *match_count) {
    const uint8_t *destination = NULL;
    uint32_t destination_length = 0;
    uint32_t wanted_table = edge_rtnl_route_table(
        request, query, payload_offset);
    uint32_t ordinal;
    int find_result;
    int result = 0;
    int32_t best = -1;

    find_result = edge_rtnl_find_attribute(
        request, payload_offset, EDGE_RTA_DST,
        &destination, &destination_length);
    if (find_result < 0 && find_result != -EDGE_LINUX_ENOENT)
        return find_result;
    if (find_result == 0 &&
        (request->flags & EDGE_NLM_F_DUMP) != EDGE_NLM_F_DUMP &&
        !wanted_table && query->family) {
        edge_linux_route_query_t lookup;
        edge_linux_route_result_t resolved;
        edge_rtnl_route_t selected;
        uint32_t address_length =
            query->family == EDGE_AF_INET ? 4u : 16u;
        int lookup_result;

        if (destination_length != address_length)
            return -EDGE_LINUX_EINVAL;
        memset(&lookup, 0, sizeof(lookup));
        lookup.network_namespace = network_namespace;
        lookup.family = query->family;
        memcpy(lookup.destination, destination, address_length);
        lookup.uid = 0u;
        lookup_result = edge_rtnl_copy_attribute(
            request, payload_offset, EDGE_RTA_SRC,
            lookup.source, address_length);
        if (lookup_result < 0 && lookup_result != -EDGE_LINUX_ENOENT)
            return lookup_result;
        lookup_result = edge_rtnl_read_u32(
            request, payload_offset, EDGE_RTA_MARK, &lookup.mark);
        if (lookup_result < 0 && lookup_result != -EDGE_LINUX_ENOENT)
            return lookup_result;
        lookup_result = edge_rtnl_read_u32(
            request, payload_offset, EDGE_RTA_IIF,
            (uint32_t *)&lookup.input_ifindex);
        if (lookup_result < 0 && lookup_result != -EDGE_LINUX_ENOENT)
            return lookup_result;
        lookup_result = edge_rtnl_read_u32(
            request, payload_offset, EDGE_RTA_OIF,
            (uint32_t *)&lookup.output_ifindex);
        if (lookup_result < 0 && lookup_result != -EDGE_LINUX_ENOENT)
            return lookup_result;
        lookup_result = edge_rtnl_read_u32(
            request, payload_offset, EDGE_RTA_UID, &lookup.uid);
        if (lookup_result < 0 && lookup_result != -EDGE_LINUX_ENOENT)
            return lookup_result;
        lookup_result = edge_linux_route_lookup(&lookup, &resolved);
        if (lookup_result == 0) {
            memset(&selected, 0, sizeof(selected));
            selected.used = 1u;
            selected.family = resolved.family;
            selected.destination_length = query->destination_length;
            selected.scope = resolved.scope;
            selected.type = resolved.type;
            selected.table = resolved.table;
            selected.metric = resolved.metric;
            selected.output_ifindex = resolved.output_ifindex;
            memcpy(selected.destination, destination, address_length);
            memcpy(selected.gateway, resolved.gateway,
                   sizeof(selected.gateway));
            memcpy(selected.preferred_source, resolved.preferred_source,
                   sizeof(selected.preferred_source));
            lookup_result = edge_rtnl_append_stored_route(
                &selected, request, port_id, response, capacity, offset);
            if (lookup_result == 0) ++*match_count;
            return lookup_result;
        }
        if (lookup_result != -EDGE_LINUX_ENOENT)
            return lookup_result;
    }
    edge_rtnl_lock();
    for (ordinal = 0; ordinal < EDGE_RTNL_ROUTE_MAX; ++ordinal) {
        const edge_rtnl_route_t *entry = &g_edge_rtnl_routes[ordinal];
        uint32_t address_length;

        if (!entry->used ||
            entry->network_namespace != network_namespace ||
            (query->family && query->family != entry->family) ||
            (wanted_table && wanted_table != entry->table))
            continue;
        address_length = entry->family == EDGE_AF_INET ? 4u : 16u;
        if (find_result == 0) {
            if (destination_length != address_length ||
                !edge_rtnl_prefix_matches(
                    entry->destination, destination,
                    entry->destination_length))
                continue;
            if (best >= 0 &&
                (g_edge_rtnl_routes[best].destination_length >
                     entry->destination_length ||
                 (g_edge_rtnl_routes[best].destination_length ==
                      entry->destination_length &&
                  g_edge_rtnl_routes[best].metric <= entry->metric)))
                continue;
            best = (int32_t)ordinal;
            continue;
        }
        result = edge_rtnl_append_stored_route(
            entry, request, port_id, response, capacity, offset);
        if (result < 0) break;
        ++*match_count;
    }
    if (result == 0 && best >= 0) {
        result = edge_rtnl_append_stored_route(
            &g_edge_rtnl_routes[best], request, port_id,
            response, capacity, offset);
        if (result == 0) ++*match_count;
    }
    edge_rtnl_unlock();
    return result;
}

static int edge_rtnl_append_ipv6_routes(
    const edge_netfilter_nlmsghdr_t *request,
    const edge_rtnl_rtmsg_t *query, uint32_t payload_offset,
    uint32_t port_id, uint8_t *response, uint32_t capacity,
    uint32_t *offset, uint32_t *match_count) {
    const edge_linux_rtnetlink_ipv6_provider_t *provider =
        __atomic_load_n(&g_edge_rtnl_ipv6_provider, __ATOMIC_ACQUIRE);
    const uint8_t *destination_data = NULL;
    uint32_t destination_length = 0;
    int have_destination;
    int result;

    if (!provider) return 0;
    result = edge_rtnl_find_attribute(
        request, payload_offset, EDGE_RTA_DST,
        &destination_data, &destination_length);
    have_destination = result == 0;
    if (result < 0 && result != -EDGE_LINUX_ENOENT) return result;
    if (have_destination && destination_length != 16u)
        return -EDGE_LINUX_EINVAL;

    if (provider->address_at) {
        int best_index = -1;
        uint8_t best_prefix = 0;

        for (int index = 0; ; ++index) {
            edge_linux_rtnetlink_ipv6_address_t address;
            uint8_t prefix[16];

            if (provider->address_at(index, &address) < 0) break;
            if (!address.prefix_length || address.prefix_length > 128u ||
                (address.flags & 0x48u))
                continue;
            if (have_destination && !edge_rtnl_ipv6_prefix_matches(
                    address.address, destination_data,
                    address.prefix_length))
                continue;
            if (have_destination) {
                if (best_index < 0 || address.prefix_length > best_prefix) {
                    best_index = index;
                    best_prefix = address.prefix_length;
                }
                continue;
            }
            memcpy(prefix, address.address, sizeof(prefix));
            edge_rtnl_ipv6_mask_prefix(prefix, address.prefix_length);
            result = edge_rtnl_append_ipv6_route_message(
                request, port_id, response, capacity, offset,
                prefix, address.prefix_length, NULL, address.address,
                2, EDGE_RTPROT_KERNEL, EDGE_RT_SCOPE_LINK);
            if (result < 0) return result;
            ++*match_count;
        }
        if (best_index >= 0) {
            edge_linux_rtnetlink_ipv6_address_t address;
            uint8_t route_destination[16];

            if (provider->address_at(best_index, &address) < 0) return 0;
            memcpy(route_destination, destination_data,
                   sizeof(route_destination));
            result = edge_rtnl_append_ipv6_route_message(
                request, port_id, response, capacity, offset,
                route_destination, query->destination_length,
                NULL, address.address,
                2, EDGE_RTPROT_KERNEL, EDGE_RT_SCOPE_LINK);
            if (result < 0) return result;
            ++*match_count;
            return 0;
        }
    }

    if (provider->router_at) {
        edge_linux_rtnetlink_ipv6_router_t router;
        edge_linux_rtnetlink_ipv6_address_t source;
        const uint8_t *preferred_source = NULL;

        if (provider->router_at(0, &router) < 0) return 0;
        if (provider->address_at) {
            for (int index = 0; ; ++index) {
                if (provider->address_at(index, &source) < 0) break;
                if (source.scope == EDGE_RT_SCOPE_UNIVERSE &&
                    !(source.flags & 0x48u)) {
                    preferred_source = source.address;
                    break;
                }
            }
        }
        result = edge_rtnl_append_ipv6_route_message(
            request, port_id, response, capacity, offset,
            have_destination ? destination_data : NULL,
            have_destination ? query->destination_length : 0u,
            router.address, preferred_source,
            2, EDGE_RTPROT_RA, EDGE_RT_SCOPE_UNIVERSE);
        if (result < 0) return result;
        ++*match_count;
    }
    return 0;
}

static int edge_rtnl_append_dynamic_ipv6_routes(
    uint32_t network_namespace,
    const edge_netfilter_nlmsghdr_t *request,
    const edge_rtnl_rtmsg_t *query, uint32_t payload_offset,
    uint32_t port_id, uint8_t *response, uint32_t capacity,
    uint32_t *offset, uint32_t *match_count) {
    const uint8_t *destination = NULL;
    uint32_t destination_length = 0;
    int destination_result;
    int32_t best_link = -1;
    int32_t best_address = -1;
    uint8_t best_prefix = 0u;
    uint32_t link_ordinal;
    int result = 0;

    destination_result = edge_rtnl_find_attribute(
        request, payload_offset, EDGE_RTA_DST,
        &destination, &destination_length);
    if (destination_result < 0 &&
        destination_result != -EDGE_LINUX_ENOENT)
        return destination_result;
    if (destination_result == 0 && destination_length != 16u)
        return -EDGE_LINUX_EINVAL;

    edge_rtnl_lock();
    for (link_ordinal = 0; link_ordinal < EDGE_RTNL_LINK_MAX;
         ++link_ordinal) {
        const edge_rtnl_link_t *link = &g_edge_rtnl_links[link_ordinal];
        uint32_t address_ordinal;

        if (!link->used ||
            link->network_namespace != network_namespace)
            continue;
        for (address_ordinal = 0;
             address_ordinal < EDGE_RTNL_IPV6_ADDRESS_MAX;
             ++address_ordinal) {
            const edge_rtnl_ipv6_address_t *address =
                &link->ipv6_addresses[address_ordinal];

            if (!address->used || !address->prefix_length ||
                address->prefix_length > 128u ||
                (address->flags & (0x48u | EDGE_IFA_F_NOPREFIXROUTE)))
                continue;
            if (destination_result == 0) {
                if (!edge_rtnl_ipv6_prefix_matches(
                        address->address, destination,
                        address->prefix_length))
                    continue;
                if (best_link < 0 ||
                    address->prefix_length > best_prefix) {
                    best_link = (int32_t)link_ordinal;
                    best_address = (int32_t)address_ordinal;
                    best_prefix = address->prefix_length;
                }
                continue;
            }
            {
                uint8_t prefix[16];

                memcpy(prefix, address->address, sizeof(prefix));
                edge_rtnl_ipv6_mask_prefix(
                    prefix, address->prefix_length);
                result = edge_rtnl_append_ipv6_route_message(
                    request, port_id, response, capacity, offset,
                    prefix, address->prefix_length, NULL,
                    address->address, link->index,
                    EDGE_RTPROT_KERNEL, EDGE_RT_SCOPE_LINK);
                if (result < 0) goto out;
                ++*match_count;
            }
        }
    }
    if (best_link >= 0 && best_address >= 0) {
        const edge_rtnl_link_t *link = &g_edge_rtnl_links[best_link];
        const edge_rtnl_ipv6_address_t *address =
            &link->ipv6_addresses[best_address];

        result = edge_rtnl_append_ipv6_route_message(
            request, port_id, response, capacity, offset,
            destination, query->destination_length, NULL,
            address->address, link->index,
            EDGE_RTPROT_KERNEL, EDGE_RT_SCOPE_LINK);
        if (result == 0) ++*match_count;
    }
out:
    edge_rtnl_unlock();
    return result;
}

int edge_linux_rtnetlink_append_route(
    uint32_t network_namespace, uint32_t port_id,
    const void *payload, uint32_t length,
    void *response, uint32_t capacity, uint32_t *offset,
    uint32_t *match_count) {
    const edge_netfilter_nlmsghdr_t *request =
        (const edge_netfilter_nlmsghdr_t *)payload;
    edge_rtnl_rtmsg_t query_storage;
    const edge_rtnl_rtmsg_t *query;
    const uint8_t *destination_data;
    uint32_t destination_length;
    uint32_t destination;
    uint32_t payload_offset;
    const edge_rtnl_link_t *selected = 0;
    uint32_t ordinal;
    int result;

    if (!payload || !response || !offset || !match_count ||
        length < sizeof(*request) || request->length < sizeof(*request) ||
        request->length > length || request->type != EDGE_RTM_GETROUTE)
        return -EDGE_LINUX_EINVAL;
    memset(&query_storage, 0, sizeof(query_storage));
    if (request->length >= sizeof(*request) + sizeof(query_storage)) {
        memcpy(&query_storage, request + 1, sizeof(query_storage));
    } else if ((request->flags & EDGE_NLM_F_DUMP) != EDGE_NLM_F_DUMP) {
        return -EDGE_LINUX_EINVAL;
    }
    query = &query_storage;
    payload_offset = sizeof(*request) + sizeof(*query);
    if (request->length < payload_offset) return 0;
    {
        uint32_t matches_before = *match_count;
        uint32_t wanted_table = edge_rtnl_route_table(
            request, query, payload_offset);

        result = edge_rtnl_append_matching_stored_routes(
            network_namespace, request, query, payload_offset, port_id,
            (uint8_t *)response, capacity, offset, match_count);
        if (result < 0) return result;
        if ((request->flags & EDGE_NLM_F_DUMP) != EDGE_NLM_F_DUMP &&
            *match_count != matches_before)
            return 0;
        if (wanted_table && wanted_table != EDGE_RT_TABLE_MAIN)
            return 0;
    }
    if (query->family == EDGE_AF_INET6) {
        uint32_t matches_before = *match_count;

        result = edge_rtnl_append_dynamic_ipv6_routes(
            network_namespace, request, query, payload_offset, port_id,
            (uint8_t *)response, capacity, offset, match_count);
        if (result < 0) return result;
        if ((request->flags & EDGE_NLM_F_DUMP) != EDGE_NLM_F_DUMP &&
            *match_count != matches_before)
            return 0;
        if (network_namespace) return 0;
        return edge_rtnl_append_ipv6_routes(
            request, query, payload_offset, port_id,
            (uint8_t *)response, capacity, offset, match_count);
    }
    if (query->family != 0u && query->family != EDGE_AF_INET)
        return 0;
    result = edge_rtnl_find_attribute(
        request, payload_offset, EDGE_RTA_DST,
        &destination_data, &destination_length);
    if (result == -EDGE_LINUX_ENOENT &&
        (request->flags & EDGE_NLM_F_DUMP) == EDGE_NLM_F_DUMP) {
        int dump_result = 0;

        edge_rtnl_lock();
        for (ordinal = 0; ordinal < EDGE_RTNL_LINK_MAX; ++ordinal) {
            const edge_rtnl_link_t *link = &g_edge_rtnl_links[ordinal];
            uint32_t network;

            if (!link->used || !link->ipv4_address ||
                !link->prefix_length ||
                link->network_namespace != network_namespace)
                continue;
            network = edge_rtnl_ipv4_mask_prefix(
                link->ipv4_address, link->prefix_length);
            dump_result = edge_rtnl_append_ipv4_route_message(
                request, port_id, (uint8_t *)response, capacity, offset,
                network, link->prefix_length, 0u, link->ipv4_address,
                link->index, EDGE_RTPROT_KERNEL, EDGE_RT_SCOPE_LINK);
            if (dump_result < 0) break;
            ++*match_count;
            if (!link->ipv4_gateway) continue;
            dump_result = edge_rtnl_append_ipv4_route_message(
                request, port_id, (uint8_t *)response, capacity, offset,
                0u, 0u, link->ipv4_gateway, link->ipv4_address,
                link->index, EDGE_RTPROT_KERNEL, EDGE_RT_SCOPE_UNIVERSE);
            if (dump_result < 0) break;
            ++*match_count;
        }
        edge_rtnl_unlock();
        return dump_result;
    }
    if (result == -EDGE_LINUX_ENOENT) return 0;
    if (result < 0) return result;
    if (destination_length != sizeof(destination))
        return -EDGE_LINUX_EINVAL;
    memcpy(&destination, destination_data, sizeof(destination));

    edge_rtnl_lock();
    for (ordinal = 0; ordinal < EDGE_RTNL_LINK_MAX; ++ordinal) {
        const edge_rtnl_link_t *link = &g_edge_rtnl_links[ordinal];

        if (!link->used || !link->ipv4_address || !link->prefix_length ||
            link->network_namespace != network_namespace ||
            !edge_rtnl_ipv4_prefix_matches(
                link->ipv4_address, destination, link->prefix_length))
            continue;
        if (!selected || link->prefix_length > selected->prefix_length ||
            (link->prefix_length == selected->prefix_length &&
             strcmp(link->kind, "veth") == 0 &&
             strcmp(selected->kind, "veth") != 0))
            selected = link;
    }
    if (!selected) {
        edge_rtnl_unlock();
        return 0;
    }

    result = edge_rtnl_append_ipv4_route_message(
        request, port_id, (uint8_t *)response, capacity, offset,
        destination, query->destination_length, 0u,
        selected->ipv4_address, selected->index,
        EDGE_RTPROT_KERNEL, EDGE_RT_SCOPE_LINK);
    if (result == 0) ++*match_count;
    edge_rtnl_unlock();
    return result;
}

static int edge_rtnl_append_rule_message(
    const edge_rtnl_rule_t *entry,
    const edge_netfilter_nlmsghdr_t *request, uint32_t port_id,
    uint8_t *response, uint32_t capacity, uint32_t *offset) {
    edge_netfilter_nlmsghdr_t header;
    edge_rtnl_rulemsg_t rule;
    uint32_t address_length = entry->family == EDGE_AF_INET ? 4u : 16u;
    uint32_t start = *offset;
    int result;

    memset(&header, 0, sizeof(header));
    memset(&rule, 0, sizeof(rule));
    header.type = EDGE_RTM_NEWRULE;
    if ((request->flags & EDGE_NLM_F_DUMP) == EDGE_NLM_F_DUMP)
        header.flags = EDGE_NLM_F_MULTI;
    header.sequence = request->sequence;
    header.port_id = port_id;
    rule.family = entry->family;
    rule.destination_length = entry->destination_length;
    rule.source_length = entry->source_length;
    rule.table = entry->table <= UINT8_MAX ? (uint8_t)entry->table : 0u;
    rule.action = entry->action;
    result = edge_netfilter_append(
        response, capacity, offset, &header, sizeof(header));
    if (result == 0)
        result = edge_netfilter_append(
            response, capacity, offset, &rule, sizeof(rule));
    if (result == 0 && entry->destination_length)
        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_FRA_DST,
            entry->destination, address_length);
    if (result == 0 && entry->source_length)
        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_FRA_SRC,
            entry->source, address_length);
    if (result == 0 && entry->input_interface[0])
        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_FRA_IIFNAME,
            entry->input_interface,
            (uint32_t)strlen(entry->input_interface) + 1u);
    if (result == 0)
        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_FRA_PRIORITY,
            &entry->priority, sizeof(entry->priority));
    if (result == 0 && entry->mark)
        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_FRA_FWMARK,
            &entry->mark, sizeof(entry->mark));
    if (result == 0 && entry->mark_mask != UINT32_MAX && entry->mark_mask)
        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_FRA_FWMASK,
            &entry->mark_mask, sizeof(entry->mark_mask));
    if (result == 0)
        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_FRA_TABLE,
            &entry->table, sizeof(entry->table));
    if (result == 0 && entry->output_interface[0])
        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_FRA_OIFNAME,
            entry->output_interface,
            (uint32_t)strlen(entry->output_interface) + 1u);
    if (result == 0 &&
        (entry->uid_range.start || entry->uid_range.end != UINT32_MAX))
        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_FRA_UID_RANGE,
            &entry->uid_range, sizeof(entry->uid_range));
    if (result == 0)
        ((edge_netfilter_nlmsghdr_t *)(response + start))->length =
            *offset - start;
    return result;
}

static void edge_rtnl_builtin_rule(
    uint8_t family, uint32_t priority, uint32_t table,
    edge_rtnl_rule_t *rule) {
    memset(rule, 0, sizeof(*rule));
    rule->used = 1u;
    rule->family = family;
    rule->action = EDGE_FR_ACT_TO_TBL;
    rule->priority = priority;
    rule->table = table;
    rule->uid_range.end = UINT32_MAX;
}

int edge_linux_rtnetlink_append_rules(
    uint32_t network_namespace, uint32_t port_id,
    const void *payload, uint32_t length,
    void *response, uint32_t capacity, uint32_t *offset,
    uint32_t *match_count) {
    const edge_netfilter_nlmsghdr_t *request =
        (const edge_netfilter_nlmsghdr_t *)payload;
    edge_rtnl_rulemsg_t query;
    edge_rtnl_rule_t builtin;
    uint32_t ordinal;
    uint32_t last_priority = 0u;
    uint8_t emitted[EDGE_RTNL_RULE_MAX];
    int main_emitted = 0;
    int default_emitted = 0;
    int result;

    if (!payload || !response || !offset || !match_count ||
        length < sizeof(*request) || request->length < sizeof(*request) ||
        request->length > length || request->type != EDGE_RTM_GETRULE)
        return -EDGE_LINUX_EINVAL;
    memset(&query, 0, sizeof(query));
    if (request->length >= sizeof(*request) + sizeof(query))
        memcpy(&query, request + 1, sizeof(query));
    else if ((request->flags & EDGE_NLM_F_DUMP) != EDGE_NLM_F_DUMP)
        return -EDGE_LINUX_EINVAL;
    if (query.family != 0u && query.family != EDGE_AF_INET &&
        query.family != EDGE_AF_INET6)
        return 0;
    memset(emitted, 0, sizeof(emitted));

    edge_rtnl_builtin_rule(
        query.family ? query.family : EDGE_AF_INET,
        0u, EDGE_RT_TABLE_LOCAL, &builtin);
    result = edge_rtnl_append_rule_message(
        &builtin, request, port_id, response, capacity, offset);
    if (result < 0) return result;
    ++*match_count;

    edge_rtnl_lock();
    for (;;) {
        int32_t selected = -1;
        uint32_t selected_priority = UINT32_MAX;

        for (ordinal = 0; ordinal < EDGE_RTNL_RULE_MAX; ++ordinal) {
            const edge_rtnl_rule_t *entry = &g_edge_rtnl_rules[ordinal];

            if (emitted[ordinal] || !entry->used ||
                entry->network_namespace != network_namespace ||
                (query.family && query.family != entry->family) ||
                entry->priority < last_priority ||
                entry->priority > selected_priority)
                continue;
            selected = (int32_t)ordinal;
            selected_priority = entry->priority;
        }
        if (selected < 0) break;
        emitted[selected] = 1u;
        last_priority = g_edge_rtnl_rules[selected].priority;
        if (!main_emitted && last_priority >= 32766u) {
            edge_rtnl_builtin_rule(
                query.family ? query.family : EDGE_AF_INET,
                32766u, EDGE_RT_TABLE_MAIN, &builtin);
            result = edge_rtnl_append_rule_message(
                &builtin, request, port_id, response, capacity, offset);
            if (result < 0) break;
            ++*match_count;
            main_emitted = 1;
        }
        if (!default_emitted && last_priority >= 32767u) {
            edge_rtnl_builtin_rule(
                query.family ? query.family : EDGE_AF_INET,
                32767u, EDGE_RT_TABLE_DEFAULT, &builtin);
            result = edge_rtnl_append_rule_message(
                &builtin, request, port_id, response, capacity, offset);
            if (result < 0) break;
            ++*match_count;
            default_emitted = 1;
        }
        result = edge_rtnl_append_rule_message(
            &g_edge_rtnl_rules[selected], request, port_id,
            response, capacity, offset);
        if (result < 0) break;
        ++*match_count;
    }
    edge_rtnl_unlock();
    if (result < 0) return result;

    if (!main_emitted) {
        edge_rtnl_builtin_rule(
            query.family ? query.family : EDGE_AF_INET,
            32766u, EDGE_RT_TABLE_MAIN, &builtin);
        result = edge_rtnl_append_rule_message(
            &builtin, request, port_id, response, capacity, offset);
        if (result < 0) return result;
        ++*match_count;
    }
    if (!default_emitted) {
        edge_rtnl_builtin_rule(
            query.family ? query.family : EDGE_AF_INET,
            32767u, EDGE_RT_TABLE_DEFAULT, &builtin);
        result = edge_rtnl_append_rule_message(
            &builtin, request, port_id, response, capacity, offset);
        if (result == 0) ++*match_count;
    }
    return result;
}

static int edge_rtnl_append_nexthop_message(
    const edge_rtnl_nexthop_object_t *object,
    const edge_netfilter_nlmsghdr_t *request, uint32_t port_id,
    uint8_t *response, uint32_t capacity, uint32_t *offset) {
    edge_netfilter_nlmsghdr_t header;
    edge_rtnl_nhmsg_t message;
    uint32_t address_length =
        object->family == EDGE_AF_INET6 ? 16u : 4u;
    uint32_t start = *offset;
    int result;

    memset(&header, 0, sizeof(header));
    memset(&message, 0, sizeof(message));
    header.type = EDGE_RTM_NEWNEXTHOP;
    if ((request->flags & EDGE_NLM_F_DUMP) == EDGE_NLM_F_DUMP)
        header.flags = EDGE_NLM_F_MULTI;
    header.sequence = request->sequence;
    header.port_id = port_id;
    message.family = object->family;
    message.scope = object->scope;
    message.protocol = object->protocol;
    message.flags = object->flags;
    result = edge_netfilter_append(
        response, capacity, offset, &header, sizeof(header));
    if (result == 0)
        result = edge_netfilter_append(
            response, capacity, offset, &message, sizeof(message));
    if (result == 0)
        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_NHA_ID,
            &object->id, sizeof(object->id));
    if (result == 0 && object->member_count) {
        edge_rtnl_nexthop_group_wire_t group[EDGE_RTNEXTHOP_MAX];
        uint32_t ordinal;

        memset(group, 0, sizeof(group));
        for (ordinal = 0; ordinal < object->member_count; ++ordinal) {
            group[ordinal].id = object->members[ordinal].id;
            group[ordinal].weight = object->members[ordinal].weight;
        }
        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_NHA_GROUP, group,
            object->member_count * sizeof(group[0]));
    } else if (result == 0 && object->blackhole) {
        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_NHA_BLACKHOLE,
            &object->blackhole, 0u);
    } else if (result == 0) {
        result = edge_netfilter_append_attribute(
            response, capacity, offset, EDGE_NHA_OIF,
            &object->output_ifindex, sizeof(object->output_ifindex));
        if (result == 0 && !edge_rtnl_address_is_zero(
                object->gateway, address_length))
            result = edge_netfilter_append_attribute(
                response, capacity, offset, EDGE_NHA_GATEWAY,
                object->gateway, address_length);
    }
    if (result == 0)
        ((edge_netfilter_nlmsghdr_t *)(response + start))->length =
            *offset - start;
    return result;
}

int edge_linux_rtnetlink_append_nexthops(
    uint32_t network_namespace, uint32_t port_id,
    const void *payload, uint32_t length,
    void *response, uint32_t capacity, uint32_t *offset,
    uint32_t *match_count) {
    const edge_netfilter_nlmsghdr_t *request =
        (const edge_netfilter_nlmsghdr_t *)payload;
    edge_rtnl_nhmsg_t query;
    uint32_t wanted_id = 0u;
    uint32_t payload_offset;
    uint32_t ordinal;
    int result;

    if (!payload || !response || !offset || !match_count ||
        length < sizeof(*request) || request->length < sizeof(*request) ||
        request->length > length || request->type != EDGE_RTM_GETNEXTHOP)
        return -EDGE_LINUX_EINVAL;
    memset(&query, 0, sizeof(query));
    if (request->length >= sizeof(*request) + sizeof(query))
        memcpy(&query, request + 1, sizeof(query));
    else if ((request->flags & EDGE_NLM_F_DUMP) != EDGE_NLM_F_DUMP)
        return -EDGE_LINUX_EINVAL;
    if (query.family != 0u && query.family != EDGE_AF_INET &&
        query.family != EDGE_AF_INET6)
        return 0;
    payload_offset = sizeof(*request) + sizeof(query);
    result = edge_rtnl_read_u32(
        request, payload_offset, EDGE_NHA_ID, &wanted_id);
    if (result < 0 && result != -EDGE_LINUX_ENOENT) return result;
    if (!wanted_id &&
        (request->flags & EDGE_NLM_F_DUMP) != EDGE_NLM_F_DUMP)
        return -EDGE_LINUX_EINVAL;

    edge_rtnl_lock();
    result = 0;
    for (ordinal = 0; ordinal < EDGE_RTNL_NEXTHOP_OBJECT_MAX; ++ordinal) {
        const edge_rtnl_nexthop_object_t *object =
            &g_edge_rtnl_nexthops[ordinal];

        if (!object->used ||
            object->network_namespace != network_namespace ||
            (wanted_id && object->id != wanted_id) ||
            (query.family && object->family &&
             object->family != query.family))
            continue;
        result = edge_rtnl_append_nexthop_message(
            object, request, port_id, response, capacity, offset);
        if (result < 0) break;
        ++*match_count;
        if (wanted_id) break;
    }
    edge_rtnl_unlock();
    if (result == 0 && wanted_id && !*match_count)
        return -EDGE_LINUX_ENOENT;
    return result;
}

static const char *edge_rtnl_interface_name_locked(int32_t ifindex) {
    edge_rtnl_link_t *link;

    if (ifindex == 1) return "lo";
    if (ifindex == 2) return "eth0";
    link = edge_rtnl_find_index(ifindex);
    return link ? link->name : "";
}

static uint32_t edge_rtnl_interface_vrf_table_locked(int32_t ifindex) {
    const edge_rtnl_link_t *link;
    const edge_rtnl_link_t *master;

    if (ifindex <= 0) return 0u;
    link = edge_rtnl_find_index(ifindex);
    if (!link) return 0u;
    if (strcmp(link->kind, "vrf") == 0) return link->routing_table;
    if (link->master <= 0) return 0u;
    master = edge_rtnl_find_index(link->master);
    if (!master || strcmp(master->kind, "vrf") != 0) return 0u;
    return master->routing_table;
}

static int edge_rtnl_rule_matches_query(
    const edge_rtnl_rule_t *rule,
    const edge_linux_route_query_t *query) {
    const char *input_name;
    const char *output_name;

    if (rule->family != query->family ||
        (rule->source_length && !edge_rtnl_prefix_matches(
            rule->source, query->source, rule->source_length)) ||
        (rule->destination_length && !edge_rtnl_prefix_matches(
            rule->destination, query->destination,
            rule->destination_length)) ||
        ((query->mark & rule->mark_mask) !=
         (rule->mark & rule->mark_mask)) ||
        query->uid < rule->uid_range.start ||
        query->uid > rule->uid_range.end)
        return 0;
    input_name = edge_rtnl_interface_name_locked(query->input_ifindex);
    output_name = edge_rtnl_interface_name_locked(query->output_ifindex);
    if ((rule->input_interface[0] &&
         strcmp(rule->input_interface, input_name) != 0) ||
        (rule->output_interface[0] &&
         strcmp(rule->output_interface, output_name) != 0))
        return 0;
    return 1;
}

static uint32_t edge_rtnl_flow_hash(
    const edge_linux_route_query_t *query) {
    const uint8_t *fields[] = {
        query->source, query->destination,
        (const uint8_t *)&query->mark,
        (const uint8_t *)&query->input_ifindex,
        (const uint8_t *)&query->output_ifindex,
        (const uint8_t *)&query->uid
    };
    const uint32_t lengths[] = {
        query->family == EDGE_AF_INET ? 4u : 16u,
        query->family == EDGE_AF_INET ? 4u : 16u,
        sizeof(query->mark), sizeof(query->input_ifindex),
        sizeof(query->output_ifindex), sizeof(query->uid)
    };
    uint32_t hash = 2166136261u;
    uint32_t field;

    for (field = 0; field < sizeof(fields) / sizeof(fields[0]); ++field) {
        uint32_t index;

        for (index = 0; index < lengths[field]; ++index) {
            hash ^= fields[field][index];
            hash *= 16777619u;
        }
    }
    return hash;
}

static int edge_rtnl_nexthop_available(
    const edge_rtnl_nexthop_t *nexthop) {
    edge_net_device_snapshot_t snapshot;

    if (!nexthop || nexthop->output_ifindex <= 0 ||
        (nexthop->flags & (EDGE_RTNH_F_DEAD | EDGE_RTNH_F_LINKDOWN)))
        return 0;
    if (edge_net_device_snapshot(
            nexthop->output_ifindex, &snapshot) != EDGE_NET_OK)
        return 1;
    return snapshot.configuration.carrier &&
           (snapshot.configuration.flags & EDGE_NET_DEVICE_FLAG_UP);
}

static int edge_rtnl_route_has_output(
    const edge_rtnl_route_t *route, int32_t output_ifindex) {
    uint32_t ordinal;

    if (!output_ifindex) return 1;
    if (route->nexthop_id) {
        const edge_rtnl_nexthop_object_t *object =
            edge_rtnl_nexthop_find_locked(
                route->network_namespace, route->nexthop_id);

        if (!object || object->blackhole) return 0;
        if (!object->member_count)
            return object->output_ifindex == output_ifindex;
        for (ordinal = 0; ordinal < object->member_count; ++ordinal) {
            const edge_rtnl_nexthop_object_t *member =
                edge_rtnl_nexthop_find_locked(
                    route->network_namespace,
                    object->members[ordinal].id);

            if (member && member->output_ifindex == output_ifindex)
                return 1;
        }
        return 0;
    }
    if (!route->nexthop_count)
        return route->output_ifindex == output_ifindex;
    for (ordinal = 0; ordinal < route->nexthop_count; ++ordinal) {
        if (route->nexthops[ordinal].output_ifindex == output_ifindex)
            return 1;
    }
    return 0;
}

static int edge_rtnl_select_nexthop_object_locked(
    const edge_rtnl_route_t *route,
    const edge_linux_route_query_t *query,
    edge_rtnl_nexthop_t *selected) {
    const edge_rtnl_nexthop_object_t *object;
    uint32_t total_weight = 0u;
    uint32_t choice;
    uint32_t ordinal;

    if (!route || !query || !selected || !route->nexthop_id)
        return -EDGE_LINUX_EINVAL;
    object = edge_rtnl_nexthop_find_locked(
        route->network_namespace, route->nexthop_id);
    if (!object) return -EDGE_LINUX_ENOENT;
    if (object->blackhole) return -EDGE_LINUX_EINVAL;
    if (!object->member_count) {
        memset(selected, 0, sizeof(*selected));
        selected->output_ifindex = object->output_ifindex;
        selected->flags = (uint8_t)object->flags;
        memcpy(selected->gateway, object->gateway,
               sizeof(selected->gateway));
        return edge_rtnl_nexthop_available(selected) ?
            0 : -EDGE_LINUX_ENETUNREACH;
    }
    for (ordinal = 0; ordinal < object->member_count; ++ordinal) {
        const edge_rtnl_nexthop_object_t *member =
            edge_rtnl_nexthop_find_locked(
                route->network_namespace, object->members[ordinal].id);
        edge_rtnl_nexthop_t candidate;

        if (!member || member->member_count || member->blackhole)
            continue;
        memset(&candidate, 0, sizeof(candidate));
        candidate.output_ifindex = member->output_ifindex;
        candidate.flags = (uint8_t)member->flags;
        memcpy(candidate.gateway, member->gateway,
               sizeof(candidate.gateway));
        if ((!query->output_ifindex ||
             candidate.output_ifindex == query->output_ifindex) &&
            edge_rtnl_nexthop_available(&candidate))
            total_weight +=
                (uint32_t)object->members[ordinal].weight + 1u;
    }
    if (!total_weight) return -EDGE_LINUX_ENETUNREACH;
    choice = edge_rtnl_flow_hash(query) % total_weight;
    for (ordinal = 0; ordinal < object->member_count; ++ordinal) {
        const edge_rtnl_nexthop_object_t *member =
            edge_rtnl_nexthop_find_locked(
                route->network_namespace, object->members[ordinal].id);
        uint32_t weight;

        if (!member || member->member_count || member->blackhole)
            continue;
        memset(selected, 0, sizeof(*selected));
        selected->output_ifindex = member->output_ifindex;
        selected->flags = (uint8_t)member->flags;
        memcpy(selected->gateway, member->gateway,
               sizeof(selected->gateway));
        if ((query->output_ifindex &&
             selected->output_ifindex != query->output_ifindex) ||
            !edge_rtnl_nexthop_available(selected))
            continue;
        weight = (uint32_t)object->members[ordinal].weight + 1u;
        if (choice < weight) return 0;
        choice -= weight;
    }
    return -EDGE_LINUX_ENETUNREACH;
}

static int edge_rtnl_lookup_implicit_ipv4_locked(
    const edge_linux_route_query_t *query,
    uint32_t table,
    edge_linux_route_result_t *result) {
    const edge_rtnl_link_t *connected = NULL;
    const edge_rtnl_link_t *fallback = NULL;
    const edge_rtnl_link_t *selected;
    uint32_t destination;
    uint32_t ordinal;
    int via_gateway;

    if (!query || !result || query->family != EDGE_AF_INET)
        return -EDGE_LINUX_ENOENT;
    memcpy(&destination, query->destination, sizeof(destination));
    for (ordinal = 0; ordinal < EDGE_RTNL_LINK_MAX; ++ordinal) {
        const edge_rtnl_link_t *link = &g_edge_rtnl_links[ordinal];
        uint32_t link_vrf_table;

        if (!link->used || link->network_namespace !=
                query->network_namespace || !link->ipv4_address ||
            !link->prefix_length ||
            (query->output_ifindex &&
             link->index != query->output_ifindex))
            continue;
        link_vrf_table = edge_rtnl_interface_vrf_table_locked(link->index);
        if ((table == EDGE_RT_TABLE_MAIN && link_vrf_table) ||
            (table != EDGE_RT_TABLE_MAIN && link_vrf_table != table))
            continue;
        if (edge_rtnl_ipv4_prefix_matches(
                link->ipv4_address, destination, link->prefix_length) &&
            (!connected ||
             link->prefix_length > connected->prefix_length))
            connected = link;
        if (link->ipv4_gateway &&
            (!fallback || link->index < fallback->index))
            fallback = link;
    }
    if (!connected && !fallback) return -EDGE_LINUX_ENOENT;
    via_gateway = connected == NULL;
    selected = connected ? connected : fallback;
    memset(result, 0, sizeof(*result));
    result->table = table;
    result->family = EDGE_AF_INET;
    result->type = EDGE_RTN_UNICAST;
    result->scope = via_gateway ?
        EDGE_RT_SCOPE_UNIVERSE : EDGE_RT_SCOPE_LINK;
    result->prefix_length = via_gateway ? 0u : selected->prefix_length;
    result->output_ifindex = selected->index;
    memcpy(result->preferred_source, &selected->ipv4_address,
           sizeof(selected->ipv4_address));
    if (via_gateway)
        memcpy(result->gateway, &selected->ipv4_gateway,
               sizeof(selected->ipv4_gateway));
    return 0;
}

static int edge_rtnl_lookup_implicit_ipv6_locked(
    const edge_linux_route_query_t *query,
    uint32_t table,
    edge_linux_route_result_t *result) {
    const edge_rtnl_link_t *selected_link = NULL;
    const edge_rtnl_ipv6_address_t *selected_address = NULL;
    uint32_t link_ordinal;

    if (!query || !result || query->family != EDGE_AF_INET6)
        return -EDGE_LINUX_ENOENT;
    for (link_ordinal = 0; link_ordinal < EDGE_RTNL_LINK_MAX;
         ++link_ordinal) {
        const edge_rtnl_link_t *link = &g_edge_rtnl_links[link_ordinal];
        uint32_t link_vrf_table;
        uint32_t address_ordinal;

        if (!link->used ||
            link->network_namespace != query->network_namespace ||
            (query->output_ifindex &&
             link->index != query->output_ifindex))
            continue;
        link_vrf_table = edge_rtnl_interface_vrf_table_locked(link->index);
        if ((table == EDGE_RT_TABLE_MAIN && link_vrf_table) ||
            (table != EDGE_RT_TABLE_MAIN && link_vrf_table != table))
            continue;
        for (address_ordinal = 0;
             address_ordinal < EDGE_RTNL_IPV6_ADDRESS_MAX;
             ++address_ordinal) {
            const edge_rtnl_ipv6_address_t *address =
                &link->ipv6_addresses[address_ordinal];

            if (!address->used || !address->prefix_length ||
                address->prefix_length > 128u ||
                (address->flags &
                 (0x48u | EDGE_IFA_F_NOPREFIXROUTE)) ||
                !edge_rtnl_prefix_matches(
                    address->address, query->destination,
                    address->prefix_length))
                continue;
            if (!selected_address ||
                address->prefix_length >
                    selected_address->prefix_length) {
                selected_link = link;
                selected_address = address;
            }
        }
    }
    if (!selected_link || !selected_address)
        return -EDGE_LINUX_ENOENT;
    memset(result, 0, sizeof(*result));
    result->table = table;
    result->family = EDGE_AF_INET6;
    result->type = EDGE_RTN_UNICAST;
    result->scope = EDGE_RT_SCOPE_LINK;
    result->prefix_length = selected_address->prefix_length;
    result->output_ifindex = selected_link->index;
    memcpy(result->preferred_source, selected_address->address, 16u);
    return 0;
}

static const edge_rtnl_nexthop_t *edge_rtnl_select_nexthop(
    const edge_rtnl_route_t *route,
    const edge_linux_route_query_t *query) {
    uint32_t total_weight = 0u;
    uint32_t ordinal;
    uint32_t selected;

    if (!route || !query || !route->nexthop_count) return 0;
    for (ordinal = 0; ordinal < route->nexthop_count; ++ordinal) {
        if ((!query->output_ifindex ||
             route->nexthops[ordinal].output_ifindex ==
                 query->output_ifindex) &&
            edge_rtnl_nexthop_available(&route->nexthops[ordinal]))
            total_weight += (uint32_t)route->nexthops[ordinal].hops + 1u;
    }
    if (!total_weight) return 0;
    selected = edge_rtnl_flow_hash(query) % total_weight;
    for (ordinal = 0; ordinal < route->nexthop_count; ++ordinal) {
        const edge_rtnl_nexthop_t *nexthop = &route->nexthops[ordinal];
        uint32_t weight;

        if ((query->output_ifindex && nexthop->output_ifindex !=
                 query->output_ifindex) ||
            !edge_rtnl_nexthop_available(nexthop))
            continue;
        weight = (uint32_t)nexthop->hops + 1u;
        if (selected < weight) return nexthop;
        selected -= weight;
    }
    return 0;
}

static int edge_rtnl_lookup_table_locked(
    const edge_linux_route_query_t *query, uint32_t table,
    edge_linux_route_result_t *result) {
    const edge_rtnl_route_t *selected = NULL;
    edge_linux_route_result_t implicit;
    int implicit_result = -EDGE_LINUX_ENOENT;
    uint32_t ordinal;

    for (ordinal = 0; ordinal < EDGE_RTNL_ROUTE_MAX; ++ordinal) {
        const edge_rtnl_route_t *entry = &g_edge_rtnl_routes[ordinal];

        if (!entry->used || entry->network_namespace !=
                query->network_namespace || entry->family != query->family ||
            entry->table != table ||
            (entry->source_length && !edge_rtnl_prefix_matches(
                entry->source, query->source, entry->source_length)) ||
            !edge_rtnl_prefix_matches(
                entry->destination, query->destination,
                entry->destination_length) ||
            (entry->mark && entry->mark != query->mark) ||
            (entry->input_ifindex &&
             entry->input_ifindex != query->input_ifindex) ||
            !edge_rtnl_route_has_output(entry, query->output_ifindex))
            continue;
        if (!selected ||
            entry->destination_length > selected->destination_length ||
            (entry->destination_length == selected->destination_length &&
             entry->metric < selected->metric))
            selected = entry;
    }
    if (query->family == EDGE_AF_INET)
        implicit_result = edge_rtnl_lookup_implicit_ipv4_locked(
            query, table, &implicit);
    else
        implicit_result = edge_rtnl_lookup_implicit_ipv6_locked(
            query, table, &implicit);
    if (!selected) {
        if (implicit_result == 0) {
            memcpy(result, &implicit, sizeof(*result));
            return 0;
        }
        return -EDGE_LINUX_ENOENT;
    }
    if (implicit_result == 0 &&
        implicit.prefix_length > selected->destination_length) {
        memcpy(result, &implicit, sizeof(*result));
        return 0;
    }
    if (selected->type == EDGE_RTN_THROW) return -EDGE_LINUX_EAGAIN;
    if (selected->type == EDGE_RTN_UNREACHABLE)
        return -EDGE_LINUX_ENETUNREACH;
    if (selected->type == EDGE_RTN_PROHIBIT)
        return -EDGE_LINUX_EACCES;
    if (selected->type == EDGE_RTN_BLACKHOLE)
        return -EDGE_LINUX_EINVAL;
    memset(result, 0, sizeof(*result));
    result->table = selected->table;
    result->metric = selected->metric;
    result->output_ifindex = selected->output_ifindex;
    result->family = selected->family;
    result->type = selected->type;
    result->scope = selected->scope;
    result->prefix_length = selected->destination_length;
    memcpy(result->gateway, selected->gateway, sizeof(result->gateway));
    memcpy(result->preferred_source, selected->preferred_source,
           sizeof(result->preferred_source));
    if (selected->nexthop_id) {
        edge_rtnl_nexthop_t nexthop;
        int nexthop_result = edge_rtnl_select_nexthop_object_locked(
            selected, query, &nexthop);

        if (nexthop_result < 0) return nexthop_result;
        result->output_ifindex = nexthop.output_ifindex;
        memcpy(result->gateway, nexthop.gateway,
               sizeof(result->gateway));
    } else if (selected->nexthop_count) {
        const edge_rtnl_nexthop_t *nexthop =
            edge_rtnl_select_nexthop(selected, query);

        if (!nexthop) return -EDGE_LINUX_ENETUNREACH;
        result->output_ifindex = nexthop->output_ifindex;
        memcpy(result->gateway, nexthop->gateway,
               sizeof(result->gateway));
    }
    return 0;
}

int edge_linux_route_lookup(
    const edge_linux_route_query_t *query,
    edge_linux_route_result_t *result) {
    uint8_t consumed[EDGE_RTNL_RULE_MAX];
    uint32_t ordinal;
    int lookup_result = -EDGE_LINUX_ENOENT;
    int main_checked = 0;
    int default_checked = 0;
    int vrf_checked = 0;
    uint32_t vrf_table;

    if (!query || !result ||
        (query->family != EDGE_AF_INET && query->family != EDGE_AF_INET6))
        return -EDGE_LINUX_EINVAL;
    if (query->family == EDGE_AF_INET &&
        (!query->output_ifindex || query->output_ifindex == 1) &&
        query->destination[0] == 127u) {
        static const uint8_t loopback[4] = {127u, 0u, 0u, 1u};

        memset(result, 0, sizeof(*result));
        result->table = EDGE_RT_TABLE_LOCAL;
        result->family = EDGE_AF_INET;
        result->type = EDGE_RTN_LOCAL;
        result->scope = EDGE_RT_SCOPE_HOST;
        result->prefix_length = 8u;
        result->output_ifindex = 1;
        if (query->source[0] == 127u)
            memcpy(result->preferred_source, query->source, 4u);
        else
            memcpy(result->preferred_source, loopback, sizeof(loopback));
        return 0;
    }
    if (query->family == EDGE_AF_INET6 &&
        (!query->output_ifindex || query->output_ifindex == 1) &&
        memcmp(query->destination,
               "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1", 16u) == 0) {
        memset(result, 0, sizeof(*result));
        result->table = EDGE_RT_TABLE_LOCAL;
        result->family = EDGE_AF_INET6;
        result->type = EDGE_RTN_LOCAL;
        result->scope = EDGE_RT_SCOPE_HOST;
        result->prefix_length = 128u;
        result->output_ifindex = 1;
        memcpy(result->preferred_source, query->destination, 16u);
        return 0;
    }
    memset(consumed, 0, sizeof(consumed));
    edge_rtnl_lock();
    vrf_table = edge_rtnl_interface_vrf_table_locked(
        query->output_ifindex ? query->output_ifindex :
                                query->input_ifindex);
    lookup_result = edge_rtnl_lookup_table_locked(
        query, EDGE_RT_TABLE_LOCAL, result);
    if (lookup_result == 0) {
        result->priority = 0u;
        edge_rtnl_unlock();
        return 0;
    }
    lookup_result = -EDGE_LINUX_ENOENT;
    for (;;) {
        int32_t selected = -1;
        uint32_t priority = UINT32_MAX;
        const edge_rtnl_rule_t *rule;

        for (ordinal = 0; ordinal < EDGE_RTNL_RULE_MAX; ++ordinal) {
            if (consumed[ordinal] || !g_edge_rtnl_rules[ordinal].used ||
                g_edge_rtnl_rules[ordinal].network_namespace !=
                    query->network_namespace ||
                g_edge_rtnl_rules[ordinal].priority > priority)
                continue;
            selected = (int32_t)ordinal;
            priority = g_edge_rtnl_rules[ordinal].priority;
        }
        if (selected < 0) break;
        consumed[selected] = 1u;
        rule = &g_edge_rtnl_rules[selected];
        if (vrf_table && !vrf_checked && rule->priority >= 1000u) {
            lookup_result = edge_rtnl_lookup_table_locked(
                query, vrf_table, result);
            vrf_checked = 1;
            if (lookup_result == 0) {
                result->priority = 1000u;
                break;
            }
            if (lookup_result != -EDGE_LINUX_ENOENT &&
                lookup_result != -EDGE_LINUX_EAGAIN)
                break;
        }
        if (!main_checked && rule->priority >= 32766u) {
            lookup_result = edge_rtnl_lookup_table_locked(
                query, EDGE_RT_TABLE_MAIN, result);
            main_checked = 1;
            if (lookup_result == 0) {
                result->priority = 32766u;
                break;
            }
            if (lookup_result != -EDGE_LINUX_ENOENT &&
                lookup_result != -EDGE_LINUX_EAGAIN)
                break;
        }
        if (!default_checked && rule->priority >= 32767u) {
            lookup_result = edge_rtnl_lookup_table_locked(
                query, EDGE_RT_TABLE_DEFAULT, result);
            default_checked = 1;
            if (lookup_result == 0) {
                result->priority = 32767u;
                break;
            }
            if (lookup_result != -EDGE_LINUX_ENOENT &&
                lookup_result != -EDGE_LINUX_EAGAIN)
                break;
        }
        if (!edge_rtnl_rule_matches_query(rule, query)) continue;
        if (rule->action == EDGE_FR_ACT_BLACKHOLE) {
            lookup_result = -EDGE_LINUX_EINVAL;
            break;
        }
        if (rule->action == EDGE_FR_ACT_UNREACHABLE) {
            lookup_result = -EDGE_LINUX_ENETUNREACH;
            break;
        }
        if (rule->action == EDGE_FR_ACT_PROHIBIT) {
            lookup_result = -EDGE_LINUX_EACCES;
            break;
        }
        if (rule->action != EDGE_FR_ACT_TO_TBL) continue;
        lookup_result = edge_rtnl_lookup_table_locked(
            query, rule->table, result);
        if (lookup_result == -EDGE_LINUX_EAGAIN ||
            lookup_result == -EDGE_LINUX_ENOENT)
            continue;
        result->priority = rule->priority;
        break;
    }
    if (vrf_table && !vrf_checked &&
        (lookup_result == -EDGE_LINUX_ENOENT ||
         lookup_result == -EDGE_LINUX_EAGAIN)) {
        lookup_result = edge_rtnl_lookup_table_locked(
            query, vrf_table, result);
        vrf_checked = 1;
        if (lookup_result == 0) result->priority = 1000u;
    }
    if (!main_checked && (lookup_result == -EDGE_LINUX_ENOENT ||
                          lookup_result == -EDGE_LINUX_EAGAIN)) {
        lookup_result = edge_rtnl_lookup_table_locked(
            query, EDGE_RT_TABLE_MAIN, result);
        if (lookup_result == 0) result->priority = 32766u;
        main_checked = 1;
    }
    if (!default_checked && (lookup_result == -EDGE_LINUX_ENOENT ||
                             lookup_result == -EDGE_LINUX_EAGAIN)) {
        lookup_result = edge_rtnl_lookup_table_locked(
            query, EDGE_RT_TABLE_DEFAULT, result);
        if (lookup_result == 0) result->priority = 32767u;
    }
    edge_rtnl_unlock();
    return lookup_result;
}

static int edge_rtnl_append_bridge_neighbors(
    uint32_t network_namespace, uint32_t port_id,
    const edge_netfilter_nlmsghdr_t *request,
    const edge_rtnl_ndmsg_t *query,
    void *response, uint32_t capacity, uint32_t *offset,
    uint32_t *match_count) {
    uint32_t link_ordinal;

    edge_rtnl_lock();
    for (link_ordinal = 0; link_ordinal < EDGE_RTNL_LINK_MAX;
         ++link_ordinal) {
        const edge_rtnl_link_t *bridge =
            &g_edge_rtnl_links[link_ordinal];
        uint32_t fdb_ordinal;

        if (!bridge->used ||
            bridge->network_namespace != network_namespace ||
            strcmp(bridge->kind, "bridge") != 0)
            continue;
        for (fdb_ordinal = 0; ; ++fdb_ordinal) {
            edge_net_bridge_fdb_entry_t source;
            edge_netfilter_nlmsghdr_t header;
            edge_rtnl_ndmsg_t neighbor;
            uint32_t start;
            int result;

            if (edge_net_bridge_fdb_snapshot(
                    bridge->index, fdb_ordinal, &source) != EDGE_NET_OK)
                break;
            if (query->index && query->index != source.port_ifindex &&
                query->index != bridge->index)
                continue;
            memset(&header, 0, sizeof(header));
            memset(&neighbor, 0, sizeof(neighbor));
            header.type = EDGE_RTM_NEWNEIGH;
            if ((request->flags & EDGE_NLM_F_DUMP) == EDGE_NLM_F_DUMP)
                header.flags = EDGE_NLM_F_MULTI;
            header.sequence = request->sequence;
            header.port_id = port_id;
            neighbor.family = EDGE_AF_BRIDGE;
            neighbor.index = source.port_ifindex;
            neighbor.state = source.is_static ?
                EDGE_NUD_PERMANENT : EDGE_NUD_REACHABLE;
            neighbor.flags = EDGE_NTF_MASTER;
            neighbor.type = EDGE_RTN_UNICAST;
            start = *offset;
            result = edge_netfilter_append(
                response, capacity, offset, &header, sizeof(header));
            if (result == 0)
                result = edge_netfilter_append(
                    response, capacity, offset,
                    &neighbor, sizeof(neighbor));
            if (result == 0)
                result = edge_netfilter_append_attribute(
                    response, capacity, offset, EDGE_NDA_LLADDR,
                    source.hardware_address,
                    sizeof(source.hardware_address));
            if (result == 0 && source.vlan_id)
                result = edge_netfilter_append_attribute(
                    response, capacity, offset, EDGE_NDA_VLAN,
                    &source.vlan_id, sizeof(source.vlan_id));
            if (result < 0) {
                edge_rtnl_unlock();
                return result;
            }
            ((edge_netfilter_nlmsghdr_t *)
                ((uint8_t *)response + start))->length = *offset - start;
            ++*match_count;
            if ((request->flags & EDGE_NLM_F_DUMP) != EDGE_NLM_F_DUMP) {
                edge_rtnl_unlock();
                return 0;
            }
        }
    }
    edge_rtnl_unlock();
    return 0;
}

int edge_linux_rtnetlink_append_neighbors(
    uint32_t network_namespace, uint32_t port_id,
    const void *payload, uint32_t length,
    void *response, uint32_t capacity, uint32_t *offset,
    uint32_t *match_count) {
    const edge_netfilter_nlmsghdr_t *request =
        (const edge_netfilter_nlmsghdr_t *)payload;
    edge_rtnl_ndmsg_t query_storage;
    const edge_rtnl_ndmsg_t *query;
    const edge_linux_rtnetlink_ipv6_provider_t *provider;

    if (!payload || !response || !offset || !match_count ||
        length < sizeof(*request) || request->length < sizeof(*request) ||
        request->length > length || request->type != EDGE_RTM_GETNEIGH)
        return -EDGE_LINUX_EINVAL;
    memset(&query_storage, 0, sizeof(query_storage));
    if (request->length >= sizeof(*request) + sizeof(query_storage)) {
        memcpy(&query_storage, request + 1, sizeof(query_storage));
    } else if ((request->flags & EDGE_NLM_F_DUMP) != EDGE_NLM_F_DUMP) {
        return -EDGE_LINUX_EINVAL;
    }
    query = &query_storage;
    if (query->family == EDGE_AF_BRIDGE)
        return edge_rtnl_append_bridge_neighbors(
            network_namespace, port_id, request, query,
            response, capacity, offset, match_count);
    if (query->family == 0u || query->family == EDGE_AF_INET) {
        const edge_linux_rtnetlink_ipv4_provider_t *ipv4_provider =
            __atomic_load_n(
                &g_edge_rtnl_ipv4_provider, __ATOMIC_ACQUIRE);
        int index;

        if (ipv4_provider && ipv4_provider->neighbor_at) {
            for (index = 0; ; ++index) {
                edge_linux_rtnetlink_ipv4_neighbor_t source;
                edge_netfilter_nlmsghdr_t header;
                edge_rtnl_ndmsg_t neighbor;
                uint32_t start = *offset;
                int result;

                if (ipv4_provider->neighbor_at(
                        network_namespace, index, &source) < 0)
                    break;
                if (query->index && query->index != source.ifindex)
                    continue;
                memset(&header, 0, sizeof(header));
                memset(&neighbor, 0, sizeof(neighbor));
                header.type = EDGE_RTM_NEWNEIGH;
                if ((request->flags & EDGE_NLM_F_DUMP) == EDGE_NLM_F_DUMP)
                    header.flags = EDGE_NLM_F_MULTI;
                header.sequence = request->sequence;
                header.port_id = port_id;
                neighbor.family = EDGE_AF_INET;
                neighbor.index = source.ifindex;
                neighbor.state = source.state;
                neighbor.flags = source.flags;
                neighbor.type = EDGE_RTN_UNICAST;
                result = edge_netfilter_append(
                    response, capacity, offset, &header, sizeof(header));
                if (result == 0)
                    result = edge_netfilter_append(
                        response, capacity, offset,
                        &neighbor, sizeof(neighbor));
                if (result == 0)
                    result = edge_netfilter_append_attribute(
                        response, capacity, offset, EDGE_NDA_DST,
                        &source.address, sizeof(source.address));
                if (result == 0 && source.state != 0x01u)
                    result = edge_netfilter_append_attribute(
                        response, capacity, offset, EDGE_NDA_LLADDR,
                        source.hardware_address,
                        sizeof(source.hardware_address));
                if (result < 0) return result;
                ((edge_netfilter_nlmsghdr_t *)
                    ((uint8_t *)response + start))->length =
                        *offset - start;
                ++*match_count;
                if ((request->flags & EDGE_NLM_F_DUMP) != EDGE_NLM_F_DUMP)
                    return 0;
            }
        }
        if (query->family == EDGE_AF_INET) return 0;
    }
    if (network_namespace ||
        (query->family != 0u && query->family != EDGE_AF_INET6) ||
        (query->index && query->index != 2))
        return 0;
    provider = __atomic_load_n(
        &g_edge_rtnl_ipv6_provider, __ATOMIC_ACQUIRE);
    if (!provider || !provider->neighbor_at) return 0;

    for (int index = 0; ; ++index) {
        edge_linux_rtnetlink_ipv6_neighbor_t source;
        edge_netfilter_nlmsghdr_t header;
        edge_rtnl_ndmsg_t neighbor;
        uint32_t start = *offset;
        int result;

        if (provider->neighbor_at(index, &source) < 0) break;
        memset(&header, 0, sizeof(header));
        memset(&neighbor, 0, sizeof(neighbor));
        header.type = EDGE_RTM_NEWNEIGH;
        if ((request->flags & EDGE_NLM_F_DUMP) == EDGE_NLM_F_DUMP)
            header.flags = EDGE_NLM_F_MULTI;
        header.sequence = request->sequence;
        header.port_id = port_id;
        neighbor.family = EDGE_AF_INET6;
        neighbor.index = 2;
        neighbor.state = source.state;
        neighbor.flags = source.is_router ? EDGE_NTF_ROUTER : 0u;
        neighbor.type = EDGE_RTN_UNICAST;
        result = edge_netfilter_append(
            response, capacity, offset, &header, sizeof(header));
        if (result == 0)
            result = edge_netfilter_append(
                response, capacity, offset, &neighbor, sizeof(neighbor));
        if (result == 0)
            result = edge_netfilter_append_attribute(
                response, capacity, offset, EDGE_NDA_DST,
                source.address, sizeof(source.address));
        if (result == 0 && source.state != 0x01u)
            result = edge_netfilter_append_attribute(
                response, capacity, offset, EDGE_NDA_LLADDR,
                source.hardware_address,
                sizeof(source.hardware_address));
        if (result < 0) return result;
        ((edge_netfilter_nlmsghdr_t *)
            ((uint8_t *)response + start))->length = *offset - start;
        ++*match_count;
        if ((request->flags & EDGE_NLM_F_DUMP) != EDGE_NLM_F_DUMP)
            break;
    }
    return 0;
}

int edge_linux_rtnetlink_append_mdb(
    uint32_t network_namespace, uint32_t port_id,
    const void *payload, uint32_t length,
    void *response, uint32_t capacity, uint32_t *offset,
    uint32_t *match_count) {
    const edge_netfilter_nlmsghdr_t *request =
        (const edge_netfilter_nlmsghdr_t *)payload;
    edge_rtnl_bridge_port_message_t query;
    uint32_t link_ordinal;

    if (!payload || !response || !offset || !match_count ||
        length < sizeof(*request) || request->length < sizeof(*request) ||
        request->length > length || request->type != EDGE_RTM_GETMDB)
        return -EDGE_LINUX_EINVAL;
    memset(&query, 0, sizeof(query));
    if (request->length >= sizeof(*request) + sizeof(query))
        memcpy(&query, request + 1, sizeof(query));
    edge_rtnl_lock();
    for (link_ordinal = 0u; link_ordinal < EDGE_RTNL_LINK_MAX;
         ++link_ordinal) {
        const edge_rtnl_link_t *bridge =
            &g_edge_rtnl_links[link_ordinal];
        uint32_t mdb_ordinal;

        if (!bridge->used ||
            bridge->network_namespace != network_namespace ||
            strcmp(bridge->kind, "bridge") != 0 ||
            (query.ifindex && query.ifindex !=
                (uint32_t)bridge->index))
            continue;
        for (mdb_ordinal = 0u; ; ++mdb_ordinal) {
            edge_net_bridge_mdb_entry_t source;
            edge_netfilter_nlmsghdr_t header;
            edge_rtnl_bridge_port_message_t message;
            edge_rtnl_mdb_entry_t entry;
            edge_nlattr_t outer;
            uint32_t start = *offset;
            uint32_t outer_start;
            uint32_t list_start;
            int result;

            if (edge_net_bridge_mdb_snapshot(
                    bridge->index, mdb_ordinal, &source) != EDGE_NET_OK)
                break;
            memset(&header, 0, sizeof(header));
            memset(&message, 0, sizeof(message));
            memset(&entry, 0, sizeof(entry));
            header.type = EDGE_RTM_NEWMDB;
            if ((request->flags & EDGE_NLM_F_DUMP) == EDGE_NLM_F_DUMP)
                header.flags = EDGE_NLM_F_MULTI;
            header.sequence = request->sequence;
            header.port_id = port_id;
            message.family = EDGE_AF_BRIDGE;
            message.ifindex = (uint32_t)bridge->index;
            entry.ifindex = (uint32_t)source.port_ifindex;
            entry.state = source.is_static ? 1u : 0u;
            entry.vlan_id = source.vlan_id;
            if (source.family == EDGE_AF_INET) {
                uint8_t *protocol = (uint8_t *)&entry.protocol;

                memcpy(&entry.address.ipv4,
                       source.group_address, 4u);
                protocol[0] = 0x08u;
                protocol[1] = 0x00u;
            } else if (source.family == EDGE_AF_INET6) {
                uint8_t *protocol = (uint8_t *)&entry.protocol;

                memcpy(entry.address.ipv6,
                       source.group_address, 16u);
                protocol[0] = 0x86u;
                protocol[1] = 0xddu;
            } else {
                continue;
            }
            result = edge_netfilter_append(
                response, capacity, offset, &header, sizeof(header));
            if (result == 0)
                result = edge_netfilter_append(
                    response, capacity, offset,
                    &message, sizeof(message));
            if (result < 0) {
                edge_rtnl_unlock();
                return result;
            }
            memset(&outer, 0, sizeof(outer));
            outer.length = sizeof(outer);
            outer.type = EDGE_MDBA_MDB;
            outer_start = *offset;
            result = edge_netfilter_append(
                response, capacity, offset, &outer, sizeof(outer));
            if (result < 0) {
                edge_rtnl_unlock();
                return result;
            }
            outer.type = EDGE_MDBA_MDB_ENTRY;
            list_start = *offset;
            result = edge_netfilter_append(
                response, capacity, offset, &outer, sizeof(outer));
            if (result == 0)
                result = edge_netfilter_append_attribute(
                    response, capacity, offset,
                    EDGE_MDBA_MDB_ENTRY_INFO,
                    &entry, sizeof(entry));
            if (result < 0) {
                edge_rtnl_unlock();
                return result;
            }
            ((edge_nlattr_t *)((uint8_t *)response + list_start))->length =
                (uint16_t)(*offset - list_start);
            ((edge_nlattr_t *)((uint8_t *)response + outer_start))->length =
                (uint16_t)(*offset - outer_start);
            ((edge_netfilter_nlmsghdr_t *)
                ((uint8_t *)response + start))->length = *offset - start;
            ++*match_count;
            if ((request->flags & EDGE_NLM_F_DUMP) != EDGE_NLM_F_DUMP) {
                edge_rtnl_unlock();
                return 0;
            }
        }
    }
    edge_rtnl_unlock();
    return 0;
}

static void edge_linux_network_interface_copy(
    const edge_rtnl_link_t *link,
    edge_linux_network_interface_snapshot_t *snapshot) {
    edge_net_device_snapshot_t device;

    memset(snapshot, 0, sizeof(*snapshot));
    memcpy(snapshot->name, link->name, sizeof(snapshot->name));
    snapshot->ifindex = link->index;
    snapshot->flags = link->flags;
    snapshot->mtu = link->mtu;
    snapshot->tx_queue_length = link->tx_queue_length;
    snapshot->ipv4_address = link->ipv4_address;
    snapshot->ipv4_gateway = link->ipv4_gateway;
    snapshot->ipv4_prefix_length = link->prefix_length;
    snapshot->hardware_type = link->type;
    memcpy(snapshot->hardware_address, link->mac,
           sizeof(snapshot->hardware_address));
    if (edge_net_device_snapshot(link->index, &device) == EDGE_NET_OK) {
        snapshot->carrier = device.configuration.carrier;
        snapshot->flags = device.configuration.flags;
        snapshot->mtu = device.configuration.mtu;
        snapshot->tx_queue_length =
            device.configuration.tx_queue_length;
    } else {
        snapshot->carrier =
            (link->flags & EDGE_IFF_RUNNING) != 0u ? 1u : 0u;
    }
}

int edge_linux_network_interface_by_name(
    uint32_t network_namespace, const char *name,
    edge_linux_network_interface_snapshot_t *snapshot) {
    edge_rtnl_link_t copy;
    edge_rtnl_link_t *link;

    if (!name || !snapshot) return -EDGE_LINUX_EINVAL;
    edge_rtnl_lock();
    link = edge_rtnl_find_name(network_namespace, name);
    if (!link) {
        edge_rtnl_unlock();
        return -EDGE_LINUX_ENODEV;
    }
    memcpy(&copy, link, sizeof(copy));
    edge_rtnl_unlock();
    edge_linux_network_interface_copy(&copy, snapshot);
    return 0;
}

int edge_linux_network_interface_by_index(
    uint32_t network_namespace, int32_t ifindex,
    edge_linux_network_interface_snapshot_t *snapshot) {
    edge_rtnl_link_t copy;
    edge_rtnl_link_t *link;

    if (ifindex <= 0 || !snapshot) return -EDGE_LINUX_EINVAL;
    edge_rtnl_lock();
    link = edge_rtnl_find_index(ifindex);
    if (!link || link->network_namespace != network_namespace) {
        edge_rtnl_unlock();
        return -EDGE_LINUX_ENODEV;
    }
    memcpy(&copy, link, sizeof(copy));
    edge_rtnl_unlock();
    edge_linux_network_interface_copy(&copy, snapshot);
    return 0;
}

int edge_linux_network_interface_at(
    uint32_t network_namespace, uint32_t ordinal,
    edge_linux_network_interface_snapshot_t *snapshot) {
    edge_rtnl_link_t copy;
    uint32_t index;
    uint32_t match = 0u;

    if (!snapshot) return -EDGE_LINUX_EINVAL;
    edge_rtnl_lock();
    for (index = 0; index < EDGE_RTNL_LINK_MAX; ++index) {
        const edge_rtnl_link_t *link = &g_edge_rtnl_links[index];

        if (!link->used ||
            link->network_namespace != network_namespace)
            continue;
        if (match++ != ordinal) continue;
        memcpy(&copy, link, sizeof(copy));
        edge_rtnl_unlock();
        edge_linux_network_interface_copy(&copy, snapshot);
        return 0;
    }
    edge_rtnl_unlock();
    return -EDGE_LINUX_ENODEV;
}

int edge_linux_network_interface_configure(
    uint32_t network_namespace, int32_t ifindex,
    uint32_t flags, uint32_t change, uint32_t mtu, int set_mtu,
    uint32_t tx_queue_length, int set_tx_queue_length) {
    edge_rtnl_link_t *link;
    int result;

    edge_rtnl_lock();
    link = edge_rtnl_find_index(ifindex);
    if (!link || link->network_namespace != network_namespace) {
        edge_rtnl_unlock();
        return -EDGE_LINUX_ENODEV;
    }
    result = edge_net_device_set_link(
        ifindex, flags, change, mtu, set_mtu);
    if (result < 0) {
        edge_rtnl_unlock();
        return edge_rtnl_core_error(result);
    }
    if (set_tx_queue_length) {
        result = edge_net_device_set_tx_queue_length(
            ifindex, tx_queue_length);
        if (result < 0) {
            edge_rtnl_unlock();
            return edge_rtnl_core_error(result);
        }
        link->tx_queue_length = tx_queue_length;
    }
    link->flags = (link->flags & ~change) | (flags & change);
    if (set_mtu) link->mtu = mtu;
    edge_rtnl_unlock();
    return 0;
}

int edge_linux_network_interface_configure_ipv4(
    uint32_t network_namespace, int32_t ifindex,
    uint32_t address, uint8_t prefix_length, uint32_t gateway) {
    edge_rtnl_link_t *link;
    int result;

    if (prefix_length > 32u) return -EDGE_LINUX_EINVAL;
    edge_rtnl_lock();
    link = edge_rtnl_find_index(ifindex);
    if (!link || link->network_namespace != network_namespace) {
        edge_rtnl_unlock();
        return -EDGE_LINUX_ENODEV;
    }
    result = edge_net_device_set_ipv4(
        ifindex, address, prefix_length, gateway);
    if (result < 0) {
        edge_rtnl_unlock();
        return edge_rtnl_core_error(result);
    }
    link->ipv4_address = address;
    link->prefix_length = prefix_length;
    link->ipv4_gateway = gateway;
    edge_rtnl_unlock();
    return 0;
}

int edge_linux_network_tuntap_create(
    uint32_t network_namespace, const char *name,
    enum edge_net_device_kind kind, edge_net_receive_fn receive,
    edge_net_transmit_fn transmit, void *context,
    int32_t requested_ifindex, int32_t *ifindex) {
    edge_net_device_configuration_t configuration;
    edge_rtnl_link_t *link = 0;
    uint32_t ordinal;
    int result;

    if (!name || !name[0] || !ifindex || requested_ifindex < 0 ||
        requested_ifindex == INT32_MAX ||
        (kind != EDGE_NET_DEVICE_TUN && kind != EDGE_NET_DEVICE_TAP))
        return -EDGE_LINUX_EINVAL;
    edge_rtnl_lock();
    if (edge_rtnl_find_name(network_namespace, name) ||
        (requested_ifindex > 0 &&
         edge_rtnl_find_index(requested_ifindex))) {
        edge_rtnl_unlock();
        return -EDGE_LINUX_EEXIST;
    }
    for (ordinal = 0; ordinal < EDGE_RTNL_LINK_MAX; ++ordinal) {
        if (!g_edge_rtnl_links[ordinal].used) {
            link = &g_edge_rtnl_links[ordinal];
            break;
        }
    }
    if (!link) {
        edge_rtnl_unlock();
        return -EDGE_LINUX_ENOSPC;
    }
    edge_rtnl_initialize_link(
        link, name, kind == EDGE_NET_DEVICE_TUN ? "tun" : "tap");
    if (requested_ifindex > 0) {
        link->index = requested_ifindex;
        if (g_edge_rtnl_next_index <= requested_ifindex)
            g_edge_rtnl_next_index = requested_ifindex + 1;
        if (g_edge_rtnl_next_index < 3) g_edge_rtnl_next_index = 3;
        link->mac[4] = (uint8_t)((uint32_t)link->index >> 8u);
        link->mac[5] = (uint8_t)link->index;
    }
    link->network_namespace = network_namespace;
    link->flags = EDGE_IFF_MULTICAST;
    if (kind == EDGE_NET_DEVICE_TAP) {
        link->flags |= EDGE_NET_DEVICE_FLAG_BROADCAST;
    } else {
        link->flags |= EDGE_IFF_POINTOPOINT | EDGE_IFF_NOARP;
        link->type = EDGE_ARPHRD_NONE;
        memset(link->mac, 0, sizeof(link->mac));
    }
    edge_rtnl_core_configuration(link, &configuration);
    configuration.kind = kind;
    configuration.carrier = 1u;
    configuration.receive = receive;
    configuration.transmit = transmit;
    configuration.receive_context = context;
    configuration.transmit_context = context;
    result = edge_net_device_register(&configuration);
    if (result < 0) {
        memset(link, 0, sizeof(*link));
        edge_rtnl_unlock();
        return edge_rtnl_core_error(result);
    }
    *ifindex = link->index;
    edge_rtnl_unlock();
    return 0;
}

int edge_linux_network_tuntap_destroy(
    uint32_t network_namespace, int32_t ifindex) {
    edge_rtnl_link_t *link;
    uint32_t address;
    uint8_t prefix;
    int result;

    if (ifindex <= 2) return -EDGE_LINUX_EINVAL;
    edge_rtnl_lock();
    link = edge_rtnl_find_index(ifindex);
    if (!link || link->network_namespace != network_namespace ||
        (strcmp(link->kind, "tun") != 0 &&
         strcmp(link->kind, "tap") != 0)) {
        edge_rtnl_unlock();
        return -EDGE_LINUX_ENODEV;
    }
    address = link->ipv4_address;
    prefix = link->prefix_length;
    edge_rtnl_remove_ipv6_interface(link);
    edge_rtnl_remove_interface_routes(link);
    result = edge_net_device_unregister(ifindex);
    if (result < 0 && result != EDGE_NET_NOT_FOUND) {
        edge_rtnl_unlock();
        return edge_rtnl_core_error(result);
    }
    memset(link, 0, sizeof(*link));
    edge_rtnl_unlock();
    if (address && g_edge_rtnl_ipv4_update)
        (void)g_edge_rtnl_ipv4_update(
            ifindex, network_namespace, address, prefix, 0);
    return 0;
}

int edge_linux_netlink_send(
    int32_t descriptor, uint32_t protocol,
    const kernel_socket_address_t *destination,
    const void *payload, uint32_t length,
    void *request_context,
    edge_linux_netlink_kernel_request_fn kernel_request) {
    struct edge_linux_sockaddr_nl address;

    if (!payload && length) return -EDGE_LINUX_EFAULT;
    memset(&address, 0, sizeof(address));
    address.nl_family = EDGE_LINUX_AF_NETLINK;
    if (destination && destination->length) {
        if (destination->length < sizeof(address))
            return -EDGE_LINUX_EINVAL;
        memcpy(&address, destination->bytes, sizeof(address));
        if (address.nl_family != EDGE_LINUX_AF_NETLINK)
            return -EDGE_LINUX_EAFNOSUPPORT;
        if (address.nl_pad) return -EDGE_LINUX_EINVAL;
    }

    if (!address.nl_pid && !address.nl_groups) {
        if (!kernel_request) return -EDGE_LINUX_EDESTADDRREQ;
        return kernel_request(request_context, payload, length);
    }

    return kernel_socket_netlink_deliver_datagram(
        descriptor, protocol, address.nl_pid, address.nl_groups,
        payload, length);
}
