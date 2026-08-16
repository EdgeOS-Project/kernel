/* SPDX-License-Identifier: BSD-3-Clause */
/* EdgeOS interface-scoped extensions for the vendored lwIP ARP table. */

#include "../../third_party/lwip/src/core/ipv4/etharp.c"

#if ETHARP_SUPPORT_STATIC_ENTRIES
err_t edge_lwip_etharp_add_static_entry(
    struct netif *netif, const ip4_addr_t *ipaddr,
    struct eth_addr *ethaddr) {
    if (!netif || !ipaddr || !ethaddr) return ERR_ARG;
    return etharp_update_arp_entry(
        netif, ipaddr, ethaddr,
        ETHARP_FLAG_TRY_HARD | ETHARP_FLAG_STATIC_ENTRY);
}

err_t edge_lwip_etharp_remove_static_entry(
    struct netif *netif, const ip4_addr_t *ipaddr) {
    s16_t index;

    if (!netif || !ipaddr) return ERR_ARG;
    index = etharp_find_entry(ipaddr, ETHARP_FLAG_FIND_ONLY, netif);
    if (index < 0) return (err_t)index;
    if (arp_table[index].state != ETHARP_STATE_STATIC ||
        arp_table[index].netif != netif)
        return ERR_ARG;
    etharp_free_entry(index);
    return ERR_OK;
}
#endif
