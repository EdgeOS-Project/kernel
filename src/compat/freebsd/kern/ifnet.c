/* SPDX-License-Identifier: MPL-2.0 */
/* Shared FreeBSD ifnet gateway backed by the EdgeOS network registry. */

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#ifdef BSD_BRIDGE_HOST_TEST
#include <stdio.h>
#else
void printf(const char *format, ...);
#endif

#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/sys/socket.h"
#include "compat/freebsd/net/bpf.h"
#include "compat/freebsd/net/ethernet.h"
#include "compat/freebsd/net/if_dl.h"
#include "compat/freebsd/net/if_media.h"
#include "compat/freebsd/net/if_types.h"
#include "compat/freebsd/net/if_var.h"
#include "compat/freebsd/netinet/in.h"
#include "compat/freebsd/net/pfil.h"
#include "compat/freebsd/netinet/if_ether.h"
#include "compat/freebsd/sys/random.h"
#include "compat/freebsd/sys/sockio.h"
#include "net/lwip_stack.h"
#include "net/netdev.h"

void rt_ifmsg(struct ifnet *interface, int flags_mask);

#define BSD_IFNET_EINVAL 22
#define BSD_IFNET_ENOMEM 12
#define BSD_IFNET_EBUSY 16
#define BSD_IFNET_ENOBUFS 55
#define BSD_IFNET_EOPNOTSUPP 45
#define BSD_IFNET_INDEX_MAX 1024u

#define BSD_IFNET_SUPPORTED_CAPS \
    (IFCAP_VLAN_MTU | IFCAP_JUMBO_MTU | IFCAP_LINKSTATE | IFCAP_HWSTATS)

int ifqmaxlen = IFQ_MAXLEN;
static struct vnet g_default_vnet;
struct vnet *vnet0 = &g_default_vnet;

static volatile uint8_t g_ifnet_write_guard;
static if_t g_ifnet_by_index[BSD_IFNET_INDEX_MAX];
static volatile uint32_t g_ether_format_slot;
static char g_ether_format_buffers[8][18];
static const uint8_t g_ether_broadcast_address[ETHER_ADDR_LEN] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static void
ifnet_copy(void *destination, const void *source, size_t length)
{
    uint8_t *out = destination;
    const uint8_t *in = source;

    while (length--)
        *out++ = *in++;
}

static unsigned int
ifnet_registry_insert(if_t interface)
{
    unsigned int index;

    ifnet_global_write_lock();
    for (index = 1; index < BSD_IFNET_INDEX_MAX; ++index) {
        if (__atomic_load_n(&g_ifnet_by_index[index], __ATOMIC_ACQUIRE))
            continue;
        __atomic_store_n(&g_ifnet_by_index[index], interface,
            __ATOMIC_RELEASE);
        interface->if_index = index;
        break;
    }
    ifnet_global_write_unlock();
    return index < BSD_IFNET_INDEX_MAX ? index : 0;
}

static void
ifnet_registry_remove(if_t interface)
{
    unsigned int index;

    if (!interface)
        return;
    index = interface->if_index;
    if (index == 0 || index >= BSD_IFNET_INDEX_MAX)
        return;
    ifnet_global_write_lock();
    if (__atomic_load_n(&g_ifnet_by_index[index], __ATOMIC_ACQUIRE) ==
        interface)
        __atomic_store_n(&g_ifnet_by_index[index], 0, __ATOMIC_RELEASE);
    interface->if_index = 0;
    ifnet_global_write_unlock();
}

static int
ifnet_link_address_create(if_t interface, const uint8_t *mac)
{
    struct ifaddr *address;
    struct sockaddr_dl *link_address;
    size_t name_length = 0;

    address = bsd_malloc(sizeof(*address), M_DEVBUF, M_NOWAIT | M_ZERO);
    link_address = bsd_malloc(sizeof(*link_address), M_DEVBUF,
        M_NOWAIT | M_ZERO);
    if (!address || !link_address) {
        if (address)
            bsd_free(address, M_DEVBUF);
        if (link_address)
            bsd_free(link_address, M_DEVBUF);
        return BSD_IFNET_ENOMEM;
    }
    while (name_length < IFNAMSIZ - 1u &&
        interface->if_name_storage[name_length])
        name_length++;
    link_address->sdl_len = sizeof(*link_address);
    link_address->sdl_family = AF_LINK;
    link_address->sdl_type = interface->if_type;
    link_address->sdl_nlen = (uint8_t)name_length;
    link_address->sdl_alen = ETHER_ADDR_LEN;
    ifnet_copy(link_address->sdl_data, interface->if_name_storage,
        name_length);
    ifnet_copy(LLADDR(link_address), mac, ETHER_ADDR_LEN);
    address->ifa_addr = (struct sockaddr *)link_address;
    address->ifa_ifp = interface;
    address->ifa_refcount = 1;
    interface->if_addr = address;
    return 0;
}

static void
ifnet_link_address_destroy(if_t interface)
{
    if (!interface || !interface->if_addr)
        return;
    if (interface->if_addr->ifa_addr)
        bsd_free(interface->if_addr->ifa_addr, M_DEVBUF);
    bsd_free(interface->if_addr, M_DEVBUF);
    interface->if_addr = 0;
}

if_t
if_alloc(unsigned char type)
{
    if_t ifp;

    if (type != IFT_ETHER && type != IFT_OTHER && type != IFT_MBIM)
        return 0;
    ifp = bsd_malloc(sizeof(*ifp), M_DEVBUF, M_NOWAIT | M_ZERO);
    if (!ifp)
        return 0;
    ifp->if_type = type;
    ifp->if_mtu = ETHERMTU;
    ifp->if_send_limit = IFQ_MAXLEN;
    ifp->if_link_state = LINK_STATE_UNKNOWN;
    ifp->if_refcount = 1;
    ifp->if_counter_callback = if_get_counter_default;
    ifp->if_input = if_input;
    ifp->if_vnet = vnet0;
    return ifp;
}

void *
if_gethandle(unsigned char type)
{
    return if_alloc(type);
}

if_t
if_alloc_dev(unsigned char type, device_t device)
{
    if_t interface = if_alloc(type);

    if (interface)
        interface->if_device = device;
    return interface;
}

void
if_setdev(if_t interface, device_t device)
{
    if (interface)
        interface->if_device = device;
}

void
if_setrcvif(struct mbuf *mbuf, if_t interface)
{
    if (mbuf)
        mbuf->m_pkthdr.rcvif = interface;
}

void
ether_bpf_mtap_if(if_t interface, struct mbuf *mbuf)
{
    struct ether_vlan_header vlan;

    if (!interface || !mbuf || !bpf_peers_present_if(interface))
        return;
    if ((mbuf->m_flags & M_VLANTAG) == 0) {
        bpf_mtap_if(interface, mbuf);
        return;
    }
    if (mbuf->m_len < ETHER_HDR_LEN)
        return;

    ifnet_copy(&vlan, mbuf->m_data, ETHER_HDR_LEN);
    vlan.evl_proto = vlan.evl_encap_proto;
    vlan.evl_encap_proto = __builtin_bswap16(ETHERTYPE_VLAN);
    vlan.evl_tag = __builtin_bswap16(mbuf->m_pkthdr.ether_vtag);

    mbuf->m_data += ETHER_HDR_LEN;
    mbuf->m_len -= ETHER_HDR_LEN;
    bpf_mtap2_if(interface, &vlan, sizeof(vlan), mbuf);
    mbuf->m_len += ETHER_HDR_LEN;
    mbuf->m_data -= ETHER_HDR_LEN;
}

void
if_free(if_t ifp)
{
    if (!ifp || ifp->if_attached || ifp->if_bridge_handle ||
        ifp->if_inflight)
        return;
    if_rele(ifp);
}

void
if_ref(if_t ifp)
{
    uint32_t current;

    if (!ifp)
        return;
    current = __atomic_load_n(&ifp->if_refcount, __ATOMIC_ACQUIRE);
    while (current != 0 && current != UINT32_MAX &&
        !__atomic_compare_exchange_n(&ifp->if_refcount, &current,
            current + 1u, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
    }
}

void
if_rele(if_t ifp)
{
    uint32_t current;

    if (!ifp)
        return;
    current = __atomic_load_n(&ifp->if_refcount, __ATOMIC_ACQUIRE);
    while (current != 0 && !__atomic_compare_exchange_n(
        &ifp->if_refcount, &current, current - 1u, 0,
        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
    }
    if (current != 1)
        return;
    if_qflush(ifp);
    ifnet_link_address_destroy(ifp);
    bsd_free(ifp, M_DEVBUF);
}

void
if_initname(if_t ifp, const char *name, int unit)
{
    if (!ifp || !name || unit < 0)
        return;
    (void)bsd_snprintf(ifp->if_name_storage,
        sizeof(ifp->if_name_storage), "%s%d", name, unit);
    (void)bsd_strlcpy(ifp->if_driver_name, name,
        sizeof(ifp->if_driver_name));
    ifp->if_dunit = (unsigned int)unit;
}

const char *
if_name(if_t ifp)
{
    return ifp ? ifp->if_name_storage : "";
}

int
if_printf(if_t ifp, const char *format, ...)
{
    char message[256];
    va_list arguments;
    int result;

    if (!format)
        return -1;
    va_start(arguments, format);
    result = bsd_vsnprintf(message, sizeof(message), format, arguments);
    va_end(arguments);
    printf("%s: %s", if_name(ifp), message);
    return result;
}

uint64_t
if_setbaudrate(if_t ifp, uint64_t baudrate)
{
    uint64_t previous;

    if (!ifp)
        return 0;
    previous = ifp->if_baudrate;
    ifp->if_baudrate = baudrate;
    return previous;
}

uint64_t
if_getbaudrate(const if_t ifp)
{
    return ifp ? ifp->if_baudrate : 0;
}

int
if_getdunit(const if_t ifp)
{
    return ifp ? (int)ifp->if_dunit : IF_DUNIT_NONE;
}

int
if_getindex(const if_t ifp)
{
    return ifp ? (int)ifp->if_index : 0;
}

int
if_getalloctype(const if_t ifp)
{
    return ifp ? ifp->if_type : 0;
}

const char *
if_getdname(const if_t ifp)
{
    return ifp ? ifp->if_driver_name : "";
}

int
if_setcapabilitiesbit(if_t ifp, int set_bits, int clear_bits)
{
    if (!ifp)
        return BSD_IFNET_EINVAL;
    ifp->if_capabilities =
        ((ifp->if_capabilities | set_bits) & ~clear_bits) &
        BSD_IFNET_SUPPORTED_CAPS;
    ifp->if_capenable &= ifp->if_capabilities;
    return 0;
}

int
if_setcapabilities(if_t ifp, int capabilities)
{
    if (!ifp)
        return BSD_IFNET_EINVAL;
    ifp->if_capabilities = capabilities & BSD_IFNET_SUPPORTED_CAPS;
    ifp->if_capenable &= ifp->if_capabilities;
    return 0;
}

int
if_getcapabilities(const if_t ifp)
{
    return ifp ? ifp->if_capabilities : 0;
}

int
if_setcapenable(if_t ifp, int capabilities)
{
    if (!ifp)
        return BSD_IFNET_EINVAL;
    ifp->if_capenable = capabilities & ifp->if_capabilities;
    return 0;
}

int
if_setcapenablebit(if_t ifp, int set_bits, int clear_bits)
{
    if (!ifp)
        return BSD_IFNET_EINVAL;
    ifp->if_capenable =
        ((ifp->if_capenable | set_bits) & ~clear_bits) &
        ifp->if_capabilities;
    return 0;
}

int
if_togglecapenable(if_t ifp, int toggle_bits)
{
    if (!ifp)
        return BSD_IFNET_EINVAL;
    ifp->if_capenable ^= toggle_bits & ifp->if_capabilities;
    return 0;
}

int
if_getcapenable(const if_t ifp)
{
    return ifp ? ifp->if_capenable : 0;
}

int
if_setdrvflagbits(if_t ifp, int set_bits, int clear_bits)
{
    if (!ifp)
        return BSD_IFNET_EINVAL;
    ifp->if_drv_flags = (ifp->if_drv_flags | set_bits) & ~clear_bits;
    return 0;
}

int
if_setdrvflags(if_t ifp, int flags)
{
    if (!ifp)
        return BSD_IFNET_EINVAL;
    ifp->if_drv_flags = flags;
    return 0;
}

int
if_getdrvflags(const if_t ifp)
{
    return ifp ? ifp->if_drv_flags : 0;
}

int
if_sethwassistbits(if_t ifp, int set_bits, int clear_bits)
{
    if (!ifp)
        return BSD_IFNET_EINVAL;
    ifp->if_hwassist = (ifp->if_hwassist | set_bits) & ~clear_bits;
    return 0;
}

int
if_sethwassist(if_t ifp, int value)
{
    if (!ifp)
        return BSD_IFNET_EINVAL;
    ifp->if_hwassist = value;
    return 0;
}

int
if_gethwassist(const if_t ifp)
{
    return ifp ? ifp->if_hwassist : 0;
}

void
if_clearhwassist(if_t ifp)
{
    if (ifp)
        ifp->if_hwassist = 0;
}

int
if_togglehwassist(if_t ifp, int toggle_bits)
{
    if (!ifp)
        return BSD_IFNET_EINVAL;
    ifp->if_hwassist ^= toggle_bits;
    return 0;
}

int
if_setsoftc(if_t ifp, void *softc)
{
    if (!ifp)
        return BSD_IFNET_EINVAL;
    ifp->if_softc = softc;
    return 0;
}

void *
if_getsoftc(if_t ifp)
{
    return ifp ? ifp->if_softc : 0;
}

int
if_setflags(if_t ifp, int flags)
{
    if (!ifp)
        return BSD_IFNET_EINVAL;
    ifp->if_flags = flags;
    return 0;
}

int
if_setflagbits(if_t ifp, int set_bits, int clear_bits)
{
    if (!ifp)
        return BSD_IFNET_EINVAL;
    ifp->if_flags = (ifp->if_flags | set_bits) & ~clear_bits;
    return 0;
}

int
if_getflags(const if_t ifp)
{
    return ifp ? ifp->if_flags : 0;
}

void
if_down(if_t ifp)
{
    if (!ifp)
        return;
    ifp->if_flags &= ~IFF_UP;
    if_qflush(ifp);
    rt_ifmsg(ifp, IFF_UP);
}

void
if_up(if_t ifp)
{
    if (!ifp)
        return;
    ifp->if_flags |= IFF_UP;
    rt_ifmsg(ifp, IFF_UP);
}

int
if_setmtu(if_t ifp, int mtu)
{
    if (!ifp || mtu < 68 || mtu > (int)EDGE_NETDEV_FRAME_MAX - ETHER_HDR_LEN)
        return BSD_IFNET_EINVAL;
    ifp->if_mtu = mtu;
    return 0;
}

int
if_getmtu(const if_t ifp)
{
    return ifp ? ifp->if_mtu : 0;
}

int
if_setsendqready(if_t ifp)
{
    return ifp ? 0 : BSD_IFNET_EINVAL;
}

int
if_setsendqlen(if_t ifp, int length)
{
    if (!ifp || length <= 0)
        return BSD_IFNET_EINVAL;
    ifp->if_send_limit = (unsigned int)length;
    return 0;
}

int
if_sethwtsomax(if_t ifp, unsigned int value)
{
    if (!ifp)
        return BSD_IFNET_EINVAL;
    ifp->if_tsomax = value;
    return 0;
}

int
if_sethwtsomaxsegcount(if_t ifp, unsigned int value)
{
    if (!ifp)
        return BSD_IFNET_EINVAL;
    ifp->if_tsomaxsegcount = value;
    return 0;
}

int
if_sethwtsomaxsegsize(if_t ifp, unsigned int value)
{
    if (!ifp)
        return BSD_IFNET_EINVAL;
    ifp->if_tsomaxsegsize = value;
    return 0;
}

unsigned int
if_gethwtsomax(const if_t ifp)
{
    return ifp ? ifp->if_tsomax : 0;
}

unsigned int
if_gethwtsomaxsegcount(const if_t ifp)
{
    return ifp ? ifp->if_tsomaxsegcount : 0;
}

unsigned int
if_gethwtsomaxsegsize(const if_t ifp)
{
    return ifp ? ifp->if_tsomaxsegsize : 0;
}

int
if_setifheaderlen(if_t ifp, int length)
{
    if (!ifp || length < 0 || length > UINT16_MAX)
        return BSD_IFNET_EINVAL;
    ifp->if_header_length = (uint16_t)length;
    return 0;
}

char *
if_getlladdr(const struct ifnet *ifp)
{
    return ifp ? (char *)ifp->if_mac : 0;
}

const uint8_t *
if_getbroadcastaddr(const if_t ifp)
{
    return ifp ? g_ether_broadcast_address : 0;
}

struct vnet *
if_getvnet(const if_t ifp)
{
    return ifp ? ifp->if_vnet : 0;
}

int
if_getlinkstate(if_t ifp)
{
    return ifp ? ifp->if_link_state : LINK_STATE_UNKNOWN;
}

void
if_init(if_t ifp, void *context)
{
    if (ifp && ifp->if_init_callback)
        ifp->if_init_callback(context);
}

uint32_t
ether_crc32_be(const uint8_t *buffer, size_t length)
{
    uint32_t crc = UINT32_C(0xffffffff);

    if (!buffer)
        return crc;
    for (size_t index = 0; index < length; ++index) {
        uint8_t data = buffer[index];

        for (unsigned int bit = 0; bit < 8; ++bit, data >>= 1) {
            uint32_t carry = ((crc >> 31) ^ data) & 1u;

            crc <<= 1;
            if (carry)
                crc = (crc ^ UINT32_C(0x04c11db6)) | carry;
        }
    }
    return crc;
}

uint32_t
ether_crc32_le(const uint8_t *buffer, size_t length)
{
    uint32_t crc = UINT32_C(0xffffffff);

    if (!buffer)
        return crc;
    for (size_t index = 0; index < length; ++index) {
        uint8_t data = buffer[index];

        for (unsigned int bit = 0; bit < 8; ++bit, data >>= 1) {
            uint32_t carry = (crc ^ data) & 1u;

            crc >>= 1;
            if (carry)
                crc ^= UINT32_C(0xedb88320);
        }
    }
    return crc;
}

static int
ifnet_bridge_transmit(void *context, const void *frame, uint32_t length)
{
    if_t ifp = context;
    struct mbuf *mbuf;
    struct sockaddr destination = {0};
    const uint8_t *bytes = frame;
    uint32_t payload_offset = 0;
    int allocation_size;
    int error;

    if (!ifp || !frame || length == 0 ||
        length > EDGE_NETDEV_FRAME_MAX)
        return BSD_IFNET_EINVAL;
    if (ifp->if_type != IFT_ETHER) {
        uint16_t ether_type;

        if (length <= ETHER_HDR_LEN)
            return BSD_IFNET_EINVAL;
        ether_type = ((uint16_t)bytes[12] << 8) | bytes[13];
        if (ether_type == ETHERTYPE_IP)
            destination.sa_family = AF_INET;
        else if (ether_type == ETHERTYPE_IPV6)
            destination.sa_family = AF_INET6;
        else
            return BSD_IFNET_EOPNOTSUPP;
        destination.sa_len = sizeof(destination);
        payload_offset = ETHER_HDR_LEN;
    }
    length -= payload_offset;
    allocation_size = length < MCLBYTES ? MCLBYTES : (int)length;
    mbuf = m_getjcl(M_NOWAIT, MT_DATA, M_PKTHDR, allocation_size);
    if (!mbuf)
        return BSD_IFNET_ENOMEM;
    ifnet_copy(mbuf->m_data, bytes + payload_offset, length);
    mbuf->m_len = (int32_t)length;
    mbuf->m_pkthdr.len = (int32_t)length;
    if (ifp->if_type != IFT_ETHER && ifp->if_output_callback)
        error = ifp->if_output_callback(ifp, mbuf, &destination, 0);
    else
        error = if_transmit(ifp, mbuf);
    return error == 0 ? 0 : -error;
}

void
if_input_raw(if_t ifp, struct mbuf *mbuf, unsigned int family)
{
    uint8_t *frame;
    unsigned int length;
    uint16_t ether_type;

    if (!ifp || !mbuf || !ifp->if_bridge_handle) {
        if (ifp)
            ifp->if_counters[IFCOUNTER_IQDROPS]++;
        m_freem(mbuf);
        return;
    }
    if (family == AF_INET)
        ether_type = ETHERTYPE_IP;
    else if (family == AF_INET6)
        ether_type = ETHERTYPE_IPV6;
    else {
        ifp->if_counters[IFCOUNTER_NOPROTO]++;
        m_freem(mbuf);
        return;
    }
    length = m_length(mbuf, 0);
    if (length == 0 || length > EDGE_NETDEV_FRAME_MAX - ETHER_HDR_LEN) {
        ifp->if_counters[IFCOUNTER_IQDROPS]++;
        m_freem(mbuf);
        return;
    }
    frame = bsd_malloc(length + ETHER_HDR_LEN, M_DEVBUF, M_NOWAIT);
    if (!frame) {
        ifp->if_counters[IFCOUNTER_IQDROPS]++;
        m_freem(mbuf);
        return;
    }
    ifnet_copy(frame, ifp->if_mac, ETHER_ADDR_LEN);
    for (unsigned int index = 0; index < ETHER_ADDR_LEN; ++index)
        frame[ETHER_ADDR_LEN + index] = 0;
    frame[12] = (uint8_t)(ether_type >> 8);
    frame[13] = (uint8_t)ether_type;
    m_copydata(mbuf, 0, (int)length, (char *)frame + ETHER_HDR_LEN);
    if (edge_netdev_receive(ifp->if_bridge_handle, frame,
        length + ETHER_HDR_LEN) != 0) {
        ifp->if_counters[IFCOUNTER_IQDROPS]++;
    } else {
        ifp->if_counters[IFCOUNTER_IPACKETS]++;
        ifp->if_counters[IFCOUNTER_IBYTES] += length;
    }
    bsd_free(frame, M_DEVBUF);
    m_freem(mbuf);
}

static int
ifnet_bridge_set_up(void *context, int up)
{
    if_t ifp = context;

    if (!ifp)
        return BSD_IFNET_EINVAL;
    if (up) {
        if_up(ifp);
        if (ifp->if_init_callback)
            ifp->if_init_callback(ifp->if_softc);
    } else {
        ifp->if_drv_flags &=
            ~(IFF_DRV_RUNNING | IFF_DRV_OACTIVE);
        if_down(ifp);
    }
    return 0;
}

static void
ifnet_input_packet(if_t ifp, struct mbuf *mbuf)
{
    uint8_t *frame;
    unsigned int length;

    if (!ifp || !mbuf) {
        m_freem(mbuf);
        return;
    }
    length = m_length(mbuf, 0);
    if (length == 0 || length > EDGE_NETDEV_FRAME_MAX ||
        !ifp->if_bridge_handle) {
        ifp->if_counters[IFCOUNTER_IQDROPS]++;
        m_freem(mbuf);
        return;
    }
    frame = bsd_malloc(length, M_DEVBUF, M_NOWAIT);
    if (!frame) {
        ifp->if_counters[IFCOUNTER_IQDROPS]++;
        m_freem(mbuf);
        return;
    }
    m_copydata(mbuf, 0, (int)length, (char *)frame);
    if (edge_netdev_receive(ifp->if_bridge_handle, frame, length) != 0)
        ifp->if_counters[IFCOUNTER_IQDROPS]++;
    else {
        ifp->if_counters[IFCOUNTER_IPACKETS]++;
        ifp->if_counters[IFCOUNTER_IBYTES] += length;
    }
    bsd_free(frame, M_DEVBUF);
    m_freem(mbuf);
}

void
if_input(if_t ifp, struct mbuf *packets)
{
    while (packets) {
        struct mbuf *packet = packets;

        packets = packet->m_nextpkt;
        packet->m_nextpkt = 0;
        ifnet_input_packet(ifp, packet);
    }
}

int
if_transmit(if_t ifp, struct mbuf *mbuf)
{
    if (!ifp || !mbuf)
        return BSD_IFNET_EINVAL;
    if (ifp->if_transmit_callback)
        return ifp->if_transmit_callback(ifp, mbuf);
    if (ifp->if_send_length >= ifp->if_send_limit) {
        ifp->if_counters[IFCOUNTER_OQDROPS]++;
        m_freem(mbuf);
        return BSD_IFNET_ENOBUFS;
    }
    mbuf->m_nextpkt = 0;
    if (ifp->if_send_tail)
        ifp->if_send_tail->m_nextpkt = mbuf;
    else
        ifp->if_send_head = mbuf;
    ifp->if_send_tail = mbuf;
    ifp->if_send_length++;
    if (ifp->if_start_callback)
        ifp->if_start_callback(ifp);
    return 0;
}

int
if_sendq_prepend(if_t ifp, struct mbuf *mbuf)
{
    if (!ifp || !mbuf || ifp->if_send_length >= ifp->if_send_limit)
        return BSD_IFNET_ENOBUFS;
    mbuf->m_nextpkt = ifp->if_send_head;
    ifp->if_send_head = mbuf;
    if (!ifp->if_send_tail)
        ifp->if_send_tail = mbuf;
    ifp->if_send_length++;
    return 0;
}

struct mbuf *
if_dequeue(if_t ifp)
{
    struct mbuf *mbuf;

    if (!ifp || !ifp->if_send_head)
        return 0;
    mbuf = ifp->if_send_head;
    ifp->if_send_head = mbuf->m_nextpkt;
    if (!ifp->if_send_head)
        ifp->if_send_tail = 0;
    mbuf->m_nextpkt = 0;
    ifp->if_send_length--;
    return mbuf;
}

int
if_sendq_empty(if_t ifp)
{
    return !ifp || ifp->if_send_length == 0;
}

void
if_qflush(if_t ifp)
{
    if (!ifp)
        return;
    if (ifp->if_qflush_callback) {
        ifp->if_qflush_callback(ifp);
        return;
    }
    while (ifp->if_send_head)
        m_freem(if_dequeue(ifp));
}

void
if_link_state_change(if_t ifp, int state)
{
    if (!ifp || state < LINK_STATE_UNKNOWN || state > LINK_STATE_UP)
        return;
    ifp->if_link_state = state;
    if (ifp->if_bridge_handle)
        (void)edge_netdev_set_link(ifp->if_bridge_handle,
            state == LINK_STATE_UP);
    rt_ifmsg(ifp, IFF_DRV_RUNNING);
}

void
if_inc_counter(if_t ifp, ift_counter counter, int64_t value)
{
    if (!ifp || counter < 0 || counter >= IFCOUNTERS)
        return;
    if (value >= 0)
        (void)__atomic_fetch_add(&ifp->if_counters[counter],
            (uint64_t)value, __ATOMIC_RELAXED);
    else
        (void)__atomic_fetch_sub(&ifp->if_counters[counter],
            (uint64_t)-value, __ATOMIC_RELAXED);
}

uint64_t
if_getcounter(if_t ifp, ift_counter counter)
{
    if (!ifp || counter < 0 || counter >= IFCOUNTERS)
        return 0;
    return ifp->if_counter_callback ?
        ifp->if_counter_callback(ifp, counter) :
        if_get_counter_default(ifp, counter);
}

uint64_t
if_get_counter_default(if_t ifp, ift_counter counter)
{
    if (!ifp || counter < 0 || counter >= IFCOUNTERS)
        return 0;
    return ifp->if_counters[counter];
}

unsigned int
if_foreach_lladdr(if_t ifp, iflladdr_cb_t callback, void *argument)
{
    struct sockaddr_dl address = {0};
    size_t name_length = 0;

    if (!ifp || !callback)
        return 0;
    while (name_length < IFNAMSIZ - 1u &&
        ifp->if_name_storage[name_length])
        name_length++;
    address.sdl_len = sizeof(address);
    address.sdl_family = AF_LINK;
    address.sdl_type = ifp->if_type;
    address.sdl_nlen = (uint8_t)name_length;
    address.sdl_alen = ETHER_ADDR_LEN;
    ifnet_copy(address.sdl_data, ifp->if_name_storage, name_length);
    ifnet_copy(LLADDR(&address), ifp->if_mac, ETHER_ADDR_LEN);
    return callback(argument, &address, 1);
}

unsigned int
if_foreach_llmaddr(if_t ifp, iflladdr_cb_t callback, void *argument)
{
    (void)ifp;
    (void)callback;
    (void)argument;
    return 0;
}

unsigned int
if_llmaddr_count(if_t ifp)
{
    (void)ifp;
    return 0;
}

bool
if_maddr_empty(if_t ifp)
{
    return if_llmaddr_count(ifp) == 0;
}

struct ifaddr *
if_getifaddr(const if_t ifp)
{
    return ifp ? ifp->if_addr : 0;
}

if_t
ifnet_byindex(unsigned int index)
{
    if (index == 0 || index >= BSD_IFNET_INDEX_MAX)
        return 0;
    return __atomic_load_n(&g_ifnet_by_index[index], __ATOMIC_ACQUIRE);
}

void if_setinitfn(if_t ifp, if_init_fn_t callback)
{
    if (ifp)
        ifp->if_init_callback = callback;
}

void if_setioctlfn(if_t ifp, if_ioctl_fn_t callback)
{
    if (ifp)
        ifp->if_ioctl_callback = callback;
}

void if_setstartfn(if_t ifp, if_start_fn_t callback)
{
    if (ifp)
        ifp->if_start_callback = callback;
}

if_start_fn_t
if_getstartfn(if_t ifp)
{
    return ifp ? ifp->if_start_callback : 0;
}

void if_settransmitfn(if_t ifp, if_transmit_fn_t callback)
{
    if (ifp)
        ifp->if_transmit_callback = callback;
}

void if_setinputfn(if_t ifp, if_input_fn_t callback)
{
    if (ifp)
        ifp->if_input = callback;
}

if_input_fn_t
if_getinputfn(if_t ifp)
{
    return ifp ? ifp->if_input : 0;
}

void if_setoutputfn(if_t ifp, if_output_fn_t callback)
{
    if (ifp)
        ifp->if_output_callback = callback;
}

void if_setqflushfn(if_t ifp, if_qflush_fn_t callback)
{
    if (ifp)
        ifp->if_qflush_callback = callback;
}

void if_setgetcounterfn(if_t ifp, if_get_counter_t callback)
{
    if (ifp)
        ifp->if_counter_callback = callback;
}

int
if_altq_is_enabled(if_t ifp)
{
    (void)ifp;
    return 0;
}

void
if_vlancap(if_t ifp)
{
    if (!ifp)
        return;
    ifp->if_capenable &= ifp->if_capabilities;
}

int
if_vlantrunkinuse(if_t ifp)
{
    return ifp && ifp->if_vlantrunk != 0;
}

struct ifvlantrunk *
if_getvlantrunk(if_t ifp)
{
    return ifp ? ifp->if_vlantrunk : 0;
}

void
ifnet_global_write_lock(void)
{
    while (__atomic_test_and_set(&g_ifnet_write_guard, __ATOMIC_ACQUIRE)) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#elif defined(__aarch64__)
        __asm__ __volatile__("yield");
#endif
    }
}

void
ifnet_global_write_unlock(void)
{
    __atomic_clear(&g_ifnet_write_guard, __ATOMIC_RELEASE);
}

void
arp_ifinit(if_t interface, struct ifaddr *address)
{
    (void)interface;
    (void)address;
}

void
ether_ifattach(if_t ifp, const uint8_t *address)
{
    edge_netdev_config_t config = {0};
    edge_netdev_handle_t handle;

    if (!ifp || !address || ifp->if_attached ||
        !ifp->if_name_storage[0])
        return;
    ifnet_copy(ifp->if_mac, address, ETHER_ADDR_LEN);
    if (ifnet_link_address_create(ifp, address) != 0)
        return;
    config.name = ifp->if_name_storage;
    ifnet_copy(config.mac, address, ETHER_ADDR_LEN);
    config.mtu = (uint32_t)ifp->if_mtu;
    config.link_up = ifp->if_link_state != LINK_STATE_DOWN;
    config.ops.transmit = ifnet_bridge_transmit;
    config.ops.set_up = ifnet_bridge_set_up;
    config.context = ifp;
    if (edge_netdev_register(&config, &handle) != 0) {
        ifnet_link_address_destroy(ifp);
        return;
    }
    if (ifnet_registry_insert(ifp) == 0) {
        (void)edge_netdev_unregister(handle);
        ifnet_link_address_destroy(ifp);
        return;
    }
    ifp->if_bridge_handle = handle;
    ifp->if_attached = 1;
}

void
if_attach(if_t ifp)
{
    uint8_t address[ETHER_ADDR_LEN] = {0x02, 0, 0, 0, 0, 0};
    uint32_t hash = UINT32_C(2166136261);

    if (!ifp || ifp->if_attached)
        return;
    for (const char *cursor = ifp->if_name_storage; *cursor; ++cursor) {
        hash ^= (uint8_t)*cursor;
        hash *= UINT32_C(16777619);
    }
    address[2] = (uint8_t)(hash >> 24);
    address[3] = (uint8_t)(hash >> 16);
    address[4] = (uint8_t)(hash >> 8);
    address[5] = (uint8_t)hash;
    ether_ifattach(ifp, address);
}

void
if_detach(if_t ifp)
{
    if (!ifp)
        return;
    bpfdetach(ifp);
    ether_ifdetach(ifp);
}

void
if_dead(if_t ifp)
{
    if (!ifp)
        return;
    if_down(ifp);
    if_qflush(ifp);
    ifp->if_drv_flags = 0;
    ifp->if_init_callback = 0;
    ifp->if_ioctl_callback = 0;
    ifp->if_start_callback = 0;
    ifp->if_output_callback = 0;
    ifp->if_transmit_callback = 0;
}

int
if_getfib(if_t ifp)
{
    return ifp ? (int)ifp->if_fib : 0;
}

const char *
ether_sprintf(const uint8_t *address)
{
    uint32_t slot;
    char *buffer;

    if (!address)
        return "00:00:00:00:00:00";
    slot = __atomic_fetch_add(
        &g_ether_format_slot, 1, __ATOMIC_RELAXED) %
        (sizeof(g_ether_format_buffers) /
         sizeof(g_ether_format_buffers[0]));
    buffer = g_ether_format_buffers[slot];
    (void)bsd_snprintf(buffer, sizeof(g_ether_format_buffers[slot]),
        "%02x:%02x:%02x:%02x:%02x:%02x",
        address[0], address[1], address[2],
        address[3], address[4], address[5]);
    return buffer;
}

void
ether_ifdetach(if_t ifp)
{
    if (!ifp || !ifp->if_attached)
        return;
    if (ifp->if_bridge_handle) {
        if (lwip_stack_get_netdev() == ifp->if_bridge_handle &&
            lwip_stack_unbind_netdev(ifp->if_bridge_handle) != 0)
            return;
        (void)edge_netdev_set_up(ifp->if_bridge_handle, 0);
        if (edge_netdev_unregister(ifp->if_bridge_handle) != 0)
            return;
    }
    ifnet_registry_remove(ifp);
    ifnet_link_address_destroy(ifp);
    ifp->if_bridge_handle = 0;
    ifp->if_attached = 0;
}

int
ifhwioctl(unsigned long command, if_t ifp, char *data,
    struct thread *thread)
{
    struct ifreq *request = (struct ifreq *)data;
    int old_flags;
    int new_flags;
    int error = 0;

    (void)thread;
    if (!ifp || !request)
        return BSD_IFNET_EINVAL;
    if (command != SIOCSIFFLAGS)
        return ifp->if_ioctl_callback ?
            ifp->if_ioctl_callback(ifp, command, data) :
            BSD_IFNET_EOPNOTSUPP;
    old_flags = ifp->if_flags;
    new_flags = (uint16_t)request->ifr_flags |
        ((int)(uint16_t)request->ifr_flagshigh << 16);
    ifp->if_flags = new_flags;
    if (ifp->if_ioctl_callback)
        error = ifp->if_ioctl_callback(ifp, command, data);
    if (error) {
        ifp->if_flags = old_flags;
        return error;
    }
    if (ifp->if_bridge_handle)
        (void)edge_netdev_set_up(ifp->if_bridge_handle,
            (new_flags & IFF_UP) != 0);
    if ((old_flags ^ new_flags) & IFF_UP)
        rt_ifmsg(ifp, IFF_UP);
    return 0;
}

void
ether_gen_addr_byname(const char *name, struct ether_addr *address)
{
    uint64_t hash = UINT64_C(1469598103934665603);

    if (!address)
        return;
    if (!name || name[0] == '\0') {
        arc4rand(address->octet, sizeof(address->octet), 0);
    } else {
        for (size_t index = 0; name[index] != '\0'; ++index) {
            hash ^= (uint8_t)name[index];
            hash *= UINT64_C(1099511628211);
        }
        for (size_t index = 0; index < sizeof(address->octet); ++index)
            address->octet[index] =
                (uint8_t)(hash >> (index * 8u));
    }
    address->octet[0] &= 0xfeu;
    address->octet[0] |= 0x02u;
}

void
ether_gen_addr(if_t ifp, struct ether_addr *address)
{
    ether_gen_addr_byname(ifp ? if_name(ifp) : 0, address);
}

int
ether_ioctl(if_t ifp, unsigned long command, char *data)
{
    struct ifreq *request = (struct ifreq *)data;

    if (!ifp || !request)
        return BSD_IFNET_EINVAL;
    switch (command) {
    case SIOCSIFFLAGS:
        return 0;
    case SIOCSIFMTU:
        return if_setmtu(ifp, request->ifr_mtu);
    case SIOCSIFCAP:
        return if_setcapenable(ifp, request->ifr_reqcap);
    case SIOCADDMULTI:
    case SIOCDELMULTI:
        return 0;
    default:
        return BSD_IFNET_EOPNOTSUPP;
    }
}

struct mbuf *
ether_vlanencap(struct mbuf *mbuf, uint16_t tag)
{
    struct mbuf *replacement;
    unsigned int length;
    int allocation_size;
    uint8_t *source;
    uint8_t *destination;

    if (!mbuf)
        return 0;
    length = m_length(mbuf, 0);
    if (length < ETHER_HDR_LEN ||
        length > EDGE_NETDEV_FRAME_MAX - ETHER_VLAN_ENCAP_LEN) {
        m_freem(mbuf);
        return 0;
    }
    allocation_size = (int)(length + ETHER_VLAN_ENCAP_LEN);
    if (allocation_size < MCLBYTES)
        allocation_size = MCLBYTES;
    replacement = m_getjcl(M_NOWAIT, MT_DATA, M_PKTHDR,
        allocation_size);
    if (!replacement) {
        m_freem(mbuf);
        return 0;
    }
    source = bsd_malloc(length, M_TEMP, M_NOWAIT);
    if (!source) {
        m_freem(replacement);
        m_freem(mbuf);
        return 0;
    }
    m_copydata(mbuf, 0, (int)length, (char *)source);
    destination = (uint8_t *)replacement->m_data;
    ifnet_copy(destination, source, 12);
    destination[12] = 0x81;
    destination[13] = 0x00;
    destination[14] = (uint8_t)(tag >> 8);
    destination[15] = (uint8_t)tag;
    ifnet_copy(destination + 16, source + 12, length - 12);
    replacement->m_len = (int32_t)(length + ETHER_VLAN_ENCAP_LEN);
    replacement->m_pkthdr = mbuf->m_pkthdr;
    replacement->m_pkthdr.len = replacement->m_len;
    bsd_free(source, M_TEMP);
    m_freem(mbuf);
    return replacement;
}

struct buf_ring *
buf_ring_alloc(int count, struct malloc_type *type, int flags,
    struct mtx *mutex)
{
    struct buf_ring *ring;
    size_t bytes;

    (void)mutex;
    if (count <= 1 || ((unsigned int)count &
        ((unsigned int)count - 1u)) != 0)
        return 0;
    if ((size_t)count > (SIZE_MAX - sizeof(*ring)) / sizeof(void *))
        return 0;
    bytes = sizeof(*ring) + (size_t)count * sizeof(void *);
    ring = bsd_malloc(bytes, type, flags | M_ZERO);
    if (!ring)
        return 0;
    ring->br_prod_size = count;
    ring->br_cons_size = count;
    ring->br_prod_mask = count - 1;
    ring->br_cons_mask = count - 1;
    return ring;
}

void
buf_ring_free(struct buf_ring *ring, struct malloc_type *type)
{
    if (!ring)
        return;
    bsd_free(ring, type);
}

int
drbr_enqueue(if_t ifp, struct buf_ring *ring, struct mbuf *mbuf)
{
    int error;

    (void)ifp;
    if (!ring || !mbuf)
        return BSD_IFNET_EINVAL;
    error = buf_ring_enqueue(ring, mbuf);
    if (error)
        m_freem(mbuf);
    return error;
}

struct mbuf *
drbr_dequeue(if_t ifp, struct buf_ring *ring)
{
    (void)ifp;
    if (!ring)
        return 0;
    return (struct mbuf *)buf_ring_dequeue_sc(ring);
}

int
drbr_needs_enqueue(if_t ifp, struct buf_ring *ring)
{
    (void)ifp;
    return ring && !buf_ring_empty(ring);
}

void
drbr_putback(if_t ifp, struct buf_ring *ring, struct mbuf *mbuf)
{
    (void)ifp;
    if (!ring || !mbuf)
        return;
    buf_ring_putback_sc(ring, mbuf);
}

struct mbuf *
drbr_peek(if_t ifp, struct buf_ring *ring)
{
    (void)ifp;
    if (!ring)
        return 0;
    return (struct mbuf *)buf_ring_peek_clear_sc(ring);
}

void
drbr_flush(if_t ifp, struct buf_ring *ring)
{
    struct mbuf *mbuf;

    (void)ifp;
    if (!ring)
        return;
    while ((mbuf = (struct mbuf *)buf_ring_dequeue_sc(ring)) != 0)
        m_freem(mbuf);
}

void
drbr_free(struct buf_ring *ring, struct malloc_type *type)
{
    if (!ring)
        return;
    drbr_flush(0, ring);
    buf_ring_free(ring, type);
}

void
drbr_advance(if_t ifp, struct buf_ring *ring)
{
    (void)ifp;
    if (ring)
        buf_ring_advance_sc(ring);
}

int
drbr_empty(if_t ifp, struct buf_ring *ring)
{
    (void)ifp;
    if (!ring)
        return 1;
    return buf_ring_empty(ring);
}

int
drbr_inuse(if_t ifp, struct buf_ring *ring)
{
    (void)ifp;
    if (!ring)
        return 0;
    return buf_ring_count(ring);
}

void
ifmedia_init(struct ifmedia *media, int mask,
    ifm_change_cb_t change_callback, ifm_stat_cb_t status_callback)
{
    if (!media)
        return;
    bsd_memset(media, 0, sizeof(*media));
    LIST_INIT(&media->ifm_list);
    media->ifm_mask = mask;
    media->ifm_change = change_callback;
    media->ifm_status = status_callback;
}

void
ifmedia_removeall(struct ifmedia *media)
{
    struct ifmedia_entry *entry;

    if (!media)
        return;
    while ((entry = LIST_FIRST(&media->ifm_list)) != 0) {
        LIST_REMOVE(entry, ifm_list);
        bsd_free(entry, M_DEVBUF);
    }
    media->ifm_cur = 0;
}

void
ifmedia_add(struct ifmedia *media, int media_word, int data, void *auxiliary)
{
    struct ifmedia_entry *entry;

    if (!media)
        return;
    entry = bsd_malloc(sizeof(*entry), M_DEVBUF, M_NOWAIT | M_ZERO);
    if (!entry)
        return;
    entry->ifm_media = media_word;
    entry->ifm_data = data;
    entry->ifm_aux = auxiliary;
    LIST_INSERT_HEAD(&media->ifm_list, entry, ifm_list);
}

void
ifmedia_set(struct ifmedia *media, int media_word)
{
    struct ifmedia_entry *entry;

    if (!media)
        return;
    media->ifm_media = media_word;
    LIST_FOREACH(entry, &media->ifm_list, ifm_list) {
        if (entry->ifm_media == media_word) {
            media->ifm_cur = entry;
            return;
        }
    }
}

uint64_t
ifmedia_baudrate(int media_word)
{
    if (IFM_TYPE(media_word) != IFM_ETHER)
        return 0;
    switch (IFM_SUBTYPE(media_word)) {
    case IFM_HPNA_1:
        return IF_Mbps(1);
    case IFM_10_T:
    case IFM_10_2:
    case IFM_10_5:
    case IFM_10_STP:
    case IFM_10_FL:
        return IF_Mbps(10);
    case IFM_100_TX:
    case IFM_100_FX:
    case IFM_100_T4:
    case IFM_100_VG:
    case IFM_100_T2:
    case IFM_100_SGMII:
        return IF_Mbps(100);
    case IFM_1000_SX:
    case IFM_1000_LX:
    case IFM_1000_CX:
    case IFM_1000_T:
    case IFM_1000_KX:
    case IFM_1000_SGMII:
    case IFM_1000_BX:
        return IF_Gbps(1);
    case IFM_2500_SX:
    case IFM_2500_KX:
    case IFM_2500_T:
    case IFM_2500_X:
        return IF_Mbps(2500);
    case IFM_5000_T:
    case IFM_5000_KR:
        return IF_Mbps(5000);
    case IFM_10G_LR:
    case IFM_10G_SR:
    case IFM_10G_CX4:
    case IFM_10G_TWINAX:
    case IFM_10G_TWINAX_LONG:
    case IFM_10G_LRM:
    case IFM_10G_T:
    case IFM_10G_KX4:
    case IFM_10G_KR:
    case IFM_10G_CR1:
    case IFM_10G_SFI:
    case IFM_10G_AOC:
        return IF_Gbps(10);
    case IFM_20G_KR2:
        return IF_Gbps(20);
    case IFM_25G_CR:
    case IFM_25G_KR:
    case IFM_25G_SR:
    case IFM_25G_LR:
    case IFM_25G_ACC:
    case IFM_25G_AOC:
    case IFM_25G_T:
    case IFM_25G_CR_S:
    case IFM_25G_CR1:
    case IFM_25G_KR_S:
    case IFM_25G_AUI:
    case IFM_25G_KR1:
        return IF_Gbps(25);
    case IFM_40G_CR4:
    case IFM_40G_SR4:
    case IFM_40G_LR4:
    case IFM_40G_XLPPI:
    case IFM_40G_KR4:
    case IFM_40G_XLAUI:
    case IFM_40G_XLAUI_AC:
        return IF_Gbps(40);
    case IFM_50G_CR2:
    case IFM_50G_KR2:
    case IFM_50G_SR2:
    case IFM_50G_LR2:
    case IFM_50G_LAUI2_AC:
    case IFM_50G_LAUI2:
    case IFM_50G_AUI2_AC:
    case IFM_50G_AUI2:
    case IFM_50G_CP:
    case IFM_50G_SR:
    case IFM_50G_LR:
    case IFM_50G_FR:
    case IFM_50G_KR_PAM4:
    case IFM_50G_AUI1_AC:
    case IFM_50G_AUI1:
        return IF_Gbps(50);
    case IFM_100G_CR4:
    case IFM_100G_SR4:
    case IFM_100G_KR4:
    case IFM_100G_LR4:
    case IFM_100G_CAUI4_AC:
    case IFM_100G_CAUI4:
    case IFM_100G_AUI4_AC:
    case IFM_100G_AUI4:
    case IFM_100G_CR_PAM4:
    case IFM_100G_KR_PAM4:
    case IFM_100G_CP2:
    case IFM_100G_SR2:
    case IFM_100G_DR:
    case IFM_100G_KR2_PAM4:
    case IFM_100G_CAUI2_AC:
    case IFM_100G_CAUI2:
    case IFM_100G_AUI2_AC:
    case IFM_100G_AUI2:
        return IF_Gbps(100);
    case IFM_200G_CR4_PAM4:
    case IFM_200G_SR4:
    case IFM_200G_FR4:
    case IFM_200G_LR4:
    case IFM_200G_DR4:
    case IFM_200G_KR4_PAM4:
    case IFM_200G_AUI4_AC:
    case IFM_200G_AUI4:
    case IFM_200G_AUI8_AC:
    case IFM_200G_AUI8:
        return IF_Gbps(200);
    default:
        return 0;
    }
}

int
ifmedia_ioctl(struct ifnet *ifp, struct ifreq *request,
    struct ifmedia *media, unsigned long command)
{
    if (!ifp || !request || !media)
        return BSD_IFNET_EINVAL;
    if (command == SIOCSIFMEDIA) {
        ifmedia_set(media, request->ifr_media);
        return media->ifm_change ? media->ifm_change(ifp) : 0;
    }
    if (command == SIOCGIFMEDIA || command == SIOCGIFXMEDIA)
        return 0;
    return BSD_IFNET_EOPNOTSUPP;
}

pfil_head_t
pfil_head_register(struct pfil_head_args *arguments)
{
    if (!arguments || arguments->pa_version != PFIL_VERSION)
        return 0;
    return bsd_malloc(sizeof(struct pfil_head), M_DEVBUF,
        M_NOWAIT | M_ZERO);
}

void
pfil_head_unregister(pfil_head_t head)
{
    if (head)
        bsd_free(head, M_DEVBUF);
}

pfil_return_t
pfil_mbuf_in(pfil_head_t head, struct mbuf **mbuf, struct ifnet *ifp,
    struct inpcb *pcb)
{
    (void)ifp;
    (void)pcb;
    if (!head || !mbuf || !*mbuf)
        return PFIL_DROPPED;
    return PFIL_PASS;
}

pfil_return_t
pfil_mem_in(pfil_head_t head, void *data, unsigned int length,
    struct ifnet *ifp, struct mbuf **mbuf)
{
    (void)ifp;
    if (mbuf)
        *mbuf = 0;
    if (!head || !data || length == 0)
        return PFIL_DROPPED;
    return PFIL_PASS;
}
