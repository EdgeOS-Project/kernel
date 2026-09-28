/* SPDX-License-Identifier: MPL-2.0 */
/* Shared FreeBSD mbuf implementation for imported network drivers. */

#include <stddef.h>
#include <stdint.h>

#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/net/ethernet.h"
#include "compat/freebsd/sys/mbuf.h"
#include "compat/freebsd/vm/pmap.h"

static volatile uint8_t g_mbuf_zone_guard;
static uma_zone_t g_mbuf_cluster_zone;
static uma_zone_t g_mbuf_page_zone;
static uma_zone_t g_mbuf_jumbo9_zone;
static uma_zone_t g_mbuf_jumbo16_zone;
unsigned int max_linkhdr = ETHER_HDR_LEN;

void
max_linkhdr_grow(unsigned int length)
{
    unsigned int current = __atomic_load_n(
        &max_linkhdr, __ATOMIC_ACQUIRE);

    while (current < length &&
        !__atomic_compare_exchange_n(&max_linkhdr, &current, length, 0,
            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
    }
}

static void
mbuf_copy(void *destination, const void *source, size_t length)
{
    uint8_t *out = destination;
    const uint8_t *in = source;

    while (length--)
        *out++ = *in++;
}

struct mbuf *
m_getjcl(int how, short type, int flags, int size)
{
    struct mbuf *mbuf;
    size_t total;

    if (size <= 0 || (size_t)size > SIZE_MAX - sizeof(*mbuf))
        return 0;
    total = sizeof(*mbuf) + (size_t)size;
    mbuf = bsd_malloc(total, M_DEVBUF,
        (how & (M_NOWAIT | M_WAITOK | M_USE_RESERVE)) | M_ZERO);
    if (!mbuf)
        return 0;
    mbuf->m_bridge_allocation = mbuf;
    mbuf->m_bridge_capacity = (uint32_t)size;
    mbuf->m_data = (char *)(mbuf + 1);
    mbuf->m_type = (uint8_t)type;
    mbuf->m_flags = (uint32_t)flags | M_EXT;
    mbuf->m_ext.ext_count = 1;
    mbuf->m_ext.ext_buf = mbuf->m_data;
    mbuf->m_ext.ext_size = (uint32_t)size;
    mbuf->m_ext.ext_type = (uint8_t)m_gettype(size);
    return mbuf;
}

struct mbuf *
m_get(int how, short type)
{
    return m_getjcl(how, type, 0, MSIZE);
}

struct mbuf *
m_gethdr_raw(int how, short type)
{
    struct mbuf *mbuf = bsd_malloc(sizeof(*mbuf), M_DEVBUF,
        (how & (M_NOWAIT | M_WAITOK | M_USE_RESERVE)) | M_ZERO);

    if (!mbuf)
        return 0;
    mbuf->m_bridge_allocation = mbuf;
    mbuf->m_bridge_raw_header = 1;
    mbuf->m_type = (uint8_t)type;
    return mbuf;
}

struct mbuf *
m_gethdr(int how, short type)
{
    return m_getjcl(how, type, M_PKTHDR, MHLEN);
}

struct mbuf *
m_get2(int size, int how, short type, int flags)
{
    int capacity;

    if (size < 0)
        return 0;
    if (size <= ((flags & M_PKTHDR) ? MHLEN : MSIZE))
        capacity = (flags & M_PKTHDR) ? MHLEN : MSIZE;
    else if (size <= MCLBYTES)
        capacity = MCLBYTES;
    else if (size <= MJUMPAGESIZE)
        capacity = MJUMPAGESIZE;
    else
        return 0;
    return m_getjcl(how, type, flags, capacity);
}

struct mbuf *
m_get3(int size, int how, short type, int flags)
{
    int capacity;

    if (size <= MJUMPAGESIZE)
        return m_get2(size, how, type, flags);
    if (size <= MJUM9BYTES)
        capacity = MJUM9BYTES;
    else if (size <= MJUM16BYTES)
        capacity = MJUM16BYTES;
    else
        return 0;
    return m_getjcl(how, type, flags, capacity);
}

struct mbuf *
m_getm2(struct mbuf *mbuf, int length, int how, short type, int flags)
{
    struct mbuf *new_head = 0;
    struct mbuf *new_tail = 0;
    struct mbuf *tail = mbuf;
    int remaining = length;

    if (length < 0)
        return 0;
    while (tail && tail->m_next)
        tail = tail->m_next;
    if (mbuf)
        flags &= ~M_PKTHDR;
    do {
        struct mbuf *current;
        int capacity;

        if (remaining > MJUM16BYTES)
            capacity = MJUM16BYTES;
        else if (remaining > MJUM9BYTES)
            capacity = MJUM16BYTES;
        else if (remaining > MJUMPAGESIZE)
            capacity = MJUM9BYTES;
        else if (remaining > MCLBYTES)
            capacity = MJUMPAGESIZE;
        else if (remaining > MHLEN)
            capacity = MCLBYTES;
        else
            capacity = (flags & M_PKTHDR) ? MHLEN : MSIZE;
        current = m_getjcl(how, type, flags, capacity);
        if (!current) {
            m_freem(new_head);
            return 0;
        }
        if (new_tail)
            new_tail->m_next = current;
        else
            new_head = current;
        new_tail = current;
        remaining -= capacity;
        flags &= ~M_PKTHDR;
    } while (remaining > 0);
    if (tail)
        tail->m_next = new_head;
    return mbuf ? mbuf : new_head;
}

struct mbuf *
m_getcl(int how, short type, int flags)
{
    return m_getjcl(how, type, flags, MCLBYTES);
}

int
m_clget(struct mbuf *mbuf, int how)
{
    uma_zone_t zone;
    void *cluster;

    if (!mbuf)
        return 0;
    zone = m_getzone(MCLBYTES);
    if (!zone)
        return 0;
    cluster = uma_zalloc(zone, how);
    if (!cluster)
        return 0;
    if (mbuf->m_ext.ext_free) {
        mbuf->m_ext.ext_free(mbuf);
        mbuf->m_ext.ext_free = 0;
    } else if (mbuf->m_bridge_ext_zone && mbuf->m_ext.ext_buf) {
        uma_zfree(mbuf->m_bridge_ext_zone, mbuf->m_ext.ext_buf);
    }
    mbuf->m_bridge_ext_zone = 0;
    m_cljset(mbuf, cluster, EXT_CLUSTER);
    return 1;
}

struct mbuf *
m_devget(char *buffer, int total_length, int offset,
    struct ifnet *interface,
    void (*copy)(char *source, char *destination, unsigned int length))
{
    struct mbuf *head = 0;
    struct mbuf **next = &head;
    int packet_length = total_length;

    if (!buffer || total_length < 0 || offset < 0 || offset > MHLEN)
        return 0;
    while (total_length > 0) {
        struct mbuf *mbuf;
        int capacity;
        int length;
        int flags = head ? 0 : M_PKTHDR;

        capacity = total_length + offset >= MINCLSIZE ? MCLBYTES :
            (head ? MSIZE : MHLEN);
        mbuf = m_getjcl(M_NOWAIT, MT_DATA, flags, capacity);
        if (!mbuf) {
            m_freem(head);
            return 0;
        }
        if (!head) {
            mbuf->m_pkthdr.rcvif = interface;
            mbuf->m_pkthdr.len = packet_length;
            if (capacity == MHLEN &&
                total_length + offset + (int)max_linkhdr <= capacity) {
                mbuf->m_data += max_linkhdr;
                capacity -= (int)max_linkhdr;
            }
        }
        if (offset != 0) {
            mbuf->m_data += offset;
            capacity -= offset;
            offset = 0;
        }
        length = total_length < capacity ? total_length : capacity;
        mbuf->m_len = length;
        if (copy)
            copy(buffer, mbuf->m_data, (unsigned int)length);
        else
            mbuf_copy(mbuf->m_data, buffer, (size_t)length);
        buffer += length;
        total_length -= length;
        *next = mbuf;
        next = &mbuf->m_next;
    }
    return head;
}

void
m_init(struct mbuf *mbuf, int how, short type, int flags)
{
    void *allocation;
    uint8_t raw_header;

    (void)how;
    if (!mbuf)
        return;
    allocation = mbuf->m_bridge_allocation;
    raw_header = mbuf->m_bridge_raw_header;
    bsd_memset(mbuf, 0, sizeof(*mbuf));
    mbuf->m_bridge_allocation = allocation;
    mbuf->m_bridge_raw_header = raw_header;
    mbuf->m_type = (uint8_t)type;
    mbuf->m_flags = (uint32_t)flags;
}

static uma_zone_t
mbuf_zone_create(uma_zone_t *slot, const char *name, size_t size)
{
    uma_zone_t zone;

    while (__atomic_test_and_set(&g_mbuf_zone_guard, __ATOMIC_ACQUIRE)) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#elif defined(__aarch64__)
        __asm__ __volatile__("yield");
#endif
    }
    zone = *slot;
    if (!zone) {
        zone = uma_zcreate(name, size, 0, 0, 0, 0,
            UMA_ALIGN_PTR, 0);
        if (zone)
            *slot = zone;
    }
    __atomic_clear(&g_mbuf_zone_guard, __ATOMIC_RELEASE);
    return zone;
}

int
m_gettype(int size)
{
    if (size <= 0)
        return 0;
    if (size <= MCLBYTES)
        return EXT_CLUSTER;
    if (size <= MJUMPAGESIZE)
        return EXT_JUMBOP;
    if (size <= MJUM9BYTES)
        return EXT_JUMBO9;
    if (size <= MJUM16BYTES)
        return EXT_JUMBO16;
    return 0;
}

uma_zone_t
m_getzone(int size)
{
    switch (m_gettype(size)) {
    case EXT_CLUSTER:
        return mbuf_zone_create(
            &g_mbuf_cluster_zone, "mbuf-cluster", MCLBYTES);
    case EXT_JUMBOP:
        return mbuf_zone_create(
            &g_mbuf_page_zone, "mbuf-page", MJUMPAGESIZE);
    case EXT_JUMBO9:
        return mbuf_zone_create(
            &g_mbuf_jumbo9_zone, "mbuf-jumbo9", MJUM9BYTES);
    case EXT_JUMBO16:
        return mbuf_zone_create(
            &g_mbuf_jumbo16_zone, "mbuf-jumbo16", MJUM16BYTES);
    default:
        return 0;
    }
}

void
m_cljset(struct mbuf *mbuf, void *cluster, int type)
{
    int size;

    if (!mbuf || !cluster)
        return;
    switch (type) {
    case EXT_CLUSTER:
        size = MCLBYTES;
        break;
    case EXT_JUMBOP:
        size = MJUMPAGESIZE;
        break;
    case EXT_JUMBO9:
        size = MJUM9BYTES;
        break;
    case EXT_JUMBO16:
        size = MJUM16BYTES;
        break;
    default:
        return;
    }
    mbuf->m_data = cluster;
    mbuf->m_ext.ext_buf = cluster;
    mbuf->m_ext.ext_size = (uint32_t)size;
    mbuf->m_ext.ext_count = 1;
    mbuf->m_ext.ext_type = (uint8_t)type;
    mbuf->m_ext.ext_flags = 0;
    mbuf->m_ext.ext_free = 0;
    mbuf->m_ext.ext_arg1 = 0;
    mbuf->m_ext.ext_arg2 = 0;
    mbuf->m_bridge_capacity = (uint32_t)size;
    mbuf->m_bridge_ext_zone = m_getzone(size);
    mbuf->m_flags &= ~M_RDONLY;
    mbuf->m_flags |= M_EXT;
}

void
m_extadd(struct mbuf *mbuf, char *buffer, unsigned int size,
    m_ext_free_t free_callback, void *argument1, void *argument2,
    int flags, int type)
{
    if (!mbuf || !buffer || size == 0)
        return;
    if (mbuf->m_bridge_ext_zone && mbuf->m_ext.ext_buf) {
        uma_zfree(mbuf->m_bridge_ext_zone, mbuf->m_ext.ext_buf);
        mbuf->m_bridge_ext_zone = 0;
    }
    mbuf->m_data = buffer;
    mbuf->m_ext.ext_count = 1;
    mbuf->m_ext.ext_buf = buffer;
    mbuf->m_ext.ext_size = size;
    mbuf->m_ext.ext_type = (uint8_t)type;
    mbuf->m_ext.ext_flags = 0;
    mbuf->m_ext.ext_free = free_callback;
    mbuf->m_ext.ext_arg1 = argument1;
    mbuf->m_ext.ext_arg2 = argument2;
    mbuf->m_bridge_capacity = size;
    mbuf->m_flags |= M_EXT | (uint32_t)flags;
}

void
m_free_raw(struct mbuf *mbuf)
{
    if (!mbuf)
        return;
    if ((mbuf->m_flags & M_PKTHDR) != 0)
        m_tag_delete_chain(mbuf, 0);
    if (mbuf->m_ext.ext_free)
        mbuf->m_ext.ext_free(mbuf);
    else if (mbuf->m_bridge_ext_zone && mbuf->m_ext.ext_buf)
        uma_zfree(mbuf->m_bridge_ext_zone, mbuf->m_ext.ext_buf);
    bsd_free(mbuf->m_bridge_allocation ?
        mbuf->m_bridge_allocation : mbuf, M_DEVBUF);
}

struct mbuf *
m_free(struct mbuf *mbuf)
{
    struct mbuf *next;

    if (!mbuf)
        return 0;
    next = mbuf->m_next;
    mbuf->m_next = 0;
    m_free_raw(mbuf);
    return next;
}

void
m_adj(struct mbuf *mbuf, int length)
{
    if (!mbuf || length == 0)
        return;
    if (length > 0) {
        int remaining = length;
        int removed = 0;

        for (struct mbuf *current = mbuf;
            current && remaining != 0; current = current->m_next) {
            int take = current->m_len < remaining ?
                current->m_len : remaining;

            current->m_data += take;
            current->m_len -= take;
            remaining -= take;
            removed += take;
        }
        if ((mbuf->m_flags & M_PKTHDR) != 0) {
            if (removed >= mbuf->m_pkthdr.len)
                mbuf->m_pkthdr.len = 0;
            else
                mbuf->m_pkthdr.len -= removed;
        }
        return;
    }

    {
        int total = (int)m_length(mbuf, 0);
        int keep = total + length;
        int consumed = 0;

        if (keep < 0)
            keep = 0;
        for (struct mbuf *current = mbuf; current;
            current = current->m_next) {
            if (consumed >= keep) {
                current->m_len = 0;
            } else if (current->m_len > keep - consumed) {
                current->m_len = keep - consumed;
            }
            consumed += current->m_len;
        }
        if ((mbuf->m_flags & M_PKTHDR) != 0)
            mbuf->m_pkthdr.len = keep;
    }
}

int
m_apply(struct mbuf *mbuf, int offset, int length,
    int (*callback)(void *, void *, unsigned int), void *argument)
{
    if (offset < 0 || length < 0 || !callback)
        return 22;
    while (mbuf && offset >= mbuf->m_len) {
        offset -= mbuf->m_len;
        mbuf = mbuf->m_next;
    }
    while (length != 0) {
        unsigned int available;
        unsigned int portion;
        int error;

        if (!mbuf)
            return 22;
        available = (unsigned int)(mbuf->m_len - offset);
        portion = available < (unsigned int)length ?
            available : (unsigned int)length;
        error = callback(argument, mbuf->m_data + offset, portion);
        if (error)
            return error;
        length -= (int)portion;
        offset = 0;
        mbuf = mbuf->m_next;
    }
    return 0;
}

void
m_copydata(const struct mbuf *mbuf, int offset, int length,
    char *destination)
{
    char *output = destination;
    int requested = length;

    if (!mbuf || !destination || offset < 0 || length <= 0)
        return;
    while (mbuf && offset >= mbuf->m_len) {
        offset -= mbuf->m_len;
        mbuf = mbuf->m_next;
    }
    while (mbuf && length != 0) {
        int available = mbuf->m_len - offset;
        int take = available < length ? available : length;

        if (take > 0) {
            mbuf_copy(destination, mbuf->m_data + offset, (size_t)take);
            destination += take;
            length -= take;
        }
        offset = 0;
        mbuf = mbuf->m_next;
    }
    if (requested > length)
        (void)bsd_pmap_sync_device_mapping(output,
            (vm_size_t)(requested - length), 1);
}

void
m_copyback(struct mbuf *mbuf, int offset, int length, const void *source)
{
    const uint8_t *input = source;
    struct mbuf *current;
    int total;

    if (!mbuf || offset < 0 || length < 0 ||
        (length != 0 && !source))
        return;
    if (length != 0 &&
        bsd_pmap_sync_device_mapping((void *)source,
            (vm_size_t)length, 0) != 0)
        return;
    total = (int)m_length(mbuf, 0);
    if (offset > total) {
        static const uint8_t zeroes[64];
        int gap = offset - total;

        while (gap != 0) {
            int chunk = gap > (int)sizeof(zeroes) ?
                (int)sizeof(zeroes) : gap;

            if (!m_append(mbuf, chunk, zeroes))
                return;
            gap -= chunk;
        }
    }
    current = mbuf;
    while (current && offset >= current->m_len) {
        offset -= current->m_len;
        current = current->m_next;
    }
    while (current && length != 0) {
        int available = current->m_len - offset;
        int chunk = available < length ? available : length;

        if (chunk > 0) {
            mbuf_copy(current->m_data + offset, input, (size_t)chunk);
            input += chunk;
            length -= chunk;
        }
        offset = 0;
        current = current->m_next;
    }
    if (length != 0)
        (void)m_append(mbuf, length, input);
}

struct mbuf *
m_prepend(struct mbuf *mbuf, int length, int how)
{
    struct mbuf *head;
    uint32_t leading;

    if (!mbuf || length < 0) {
        m_freem(mbuf);
        return 0;
    }
    if (length == 0)
        return mbuf;
    leading = mbuf->m_data && mbuf->m_ext.ext_buf &&
        mbuf->m_data >= mbuf->m_ext.ext_buf ?
        (uint32_t)(mbuf->m_data - mbuf->m_ext.ext_buf) : 0;
    if (leading >= (uint32_t)length) {
        mbuf->m_data -= length;
        mbuf->m_len += length;
        if (mbuf->m_flags & M_PKTHDR)
            mbuf->m_pkthdr.len += length;
        return mbuf;
    }
    head = m_getjcl(how, (short)mbuf->m_type,
        (int)(mbuf->m_flags & M_PKTHDR),
        length < MHLEN ? MHLEN : length);
    if (!head) {
        m_freem(mbuf);
        return 0;
    }
    head->m_len = length;
    if (mbuf->m_flags & M_PKTHDR) {
        head->m_pkthdr = mbuf->m_pkthdr;
        head->m_pkthdr.len += length;
        mbuf->m_flags &= ~M_PKTHDR;
    }
    head->m_next = mbuf;
    return head;
}

struct mbuf *
m_split(struct mbuf *mbuf, int length, int how)
{
    struct mbuf *current;
    struct mbuf *tail;
    int offset;
    int remainder;
    int has_header;
    struct pkthdr original_header;

    if (!mbuf || length < 0)
        return 0;
    if ((unsigned int)length > m_length(mbuf, 0))
        return 0;
    has_header = (mbuf->m_flags & M_PKTHDR) != 0;
    original_header = mbuf->m_pkthdr;
    current = mbuf;
    offset = length;
    while (current && offset > current->m_len) {
        offset -= current->m_len;
        current = current->m_next;
    }
    if (!current)
        return 0;
    remainder = current->m_len - offset;
    if (remainder == 0) {
        struct mbuf *following = current->m_next;

        if (!following)
            return 0;
        if (has_header) {
            tail = m_gethdr(how, (short)mbuf->m_type);
            if (!tail)
                return 0;
            tail->m_next = following;
        } else {
            tail = following;
        }
        current->m_next = 0;
    } else {
        int capacity = remainder < MHLEN ? MHLEN : remainder;

        tail = m_getjcl(how, (short)current->m_type,
            has_header ? M_PKTHDR : 0, capacity);
        if (!tail)
            return 0;
        mbuf_copy(tail->m_data, current->m_data + offset,
            (size_t)remainder);
        tail->m_len = remainder;
        tail->m_next = current->m_next;
        current->m_len = offset;
        current->m_next = 0;
    }
    if (has_header) {
        tail->m_pkthdr = original_header;
        tail->m_pkthdr.tags = 0;
        tail->m_pkthdr.len = original_header.len - length;
        mbuf->m_pkthdr.len = length;
    }
    return tail;
}

void
m_catpkt(struct mbuf *head, struct mbuf *tail)
{
    struct mbuf *last;
    unsigned int tail_length;

    if (!head || !tail)
        return;
    (void)m_length(head, &last);
    tail_length = m_length(tail, 0);
    last->m_next = tail;
    if (head->m_flags & M_PKTHDR) {
        if (tail_length > (unsigned int)(INT32_MAX - head->m_pkthdr.len))
            head->m_pkthdr.len = INT32_MAX;
        else
            head->m_pkthdr.len += (int32_t)tail_length;
    }
    tail->m_flags &= ~M_PKTHDR;
}

struct mbuf *
m_copypacket(const struct mbuf *mbuf, int how)
{
    return m_dup(mbuf, how);
}

static int
mbuf_copy_tags(struct mbuf *destination, const struct mbuf *source, int how)
{
    struct m_tag **next = &destination->m_pkthdr.tags;

    destination->m_pkthdr.tags = 0;
    for (const struct m_tag *tag = source->m_pkthdr.tags; tag;
        tag = tag->next) {
        struct m_tag *copy = m_tag_alloc(
            tag->cookie, tag->type, tag->length, how);

        if (!copy) {
            m_tag_delete_chain(destination, 0);
            return 0;
        }
        mbuf_copy(copy + 1, tag + 1, tag->length);
        copy->next = 0;
        *next = copy;
        next = &copy->next;
    }
    return 1;
}

struct mbuf *
m_copym(struct mbuf *mbuf, int offset, int length, int how)
{
    struct mbuf *head = 0;
    struct mbuf **next = &head;
    struct mbuf *source = mbuf;
    unsigned int total;
    unsigned int copy_length;
    unsigned int remaining;
    int source_offset = offset;
    int copy_header;

    if (!mbuf || offset < 0 || length < 0)
        return 0;
    total = m_length(mbuf, 0);
    if ((unsigned int)offset > total)
        return 0;
    if (length == M_COPYALL) {
        copy_length = total - (unsigned int)offset;
    } else {
        if ((unsigned int)length > total - (unsigned int)offset)
            return 0;
        copy_length = (unsigned int)length;
    }
    if (copy_length == 0)
        return 0;
    while (source && source_offset >= source->m_len) {
        source_offset -= source->m_len;
        source = source->m_next;
    }
    if (!source)
        return 0;

    copy_header = offset == 0 && (mbuf->m_flags & M_PKTHDR) != 0;
    remaining = copy_length;
    while (source && remaining != 0) {
        unsigned int available = source->m_len > source_offset ?
            (unsigned int)(source->m_len - source_offset) : 0;
        unsigned int segment_length = available < remaining ?
            available : remaining;
        uint32_t flags = 0;
        int capacity;
        struct mbuf *copy;

        if (segment_length == 0) {
            source_offset = 0;
            source = source->m_next;
            continue;
        }
        if (copy_header) {
            flags = M_PKTHDR |
                (mbuf->m_flags & (M_BCAST | M_MCAST | M_VLANTAG |
                M_PROTOFLAGS));
        }
        capacity = segment_length < (unsigned int)(copy_header ?
            MHLEN : MSIZE) ? (copy_header ? MHLEN : MSIZE) :
            (int)segment_length;
        copy = m_getjcl(how, (short)source->m_type, (int)flags, capacity);
        if (!copy)
            goto fail;
        mbuf_copy(copy->m_data, source->m_data + source_offset,
            segment_length);
        copy->m_len = (int32_t)segment_length;
        if (copy_header) {
            copy->m_pkthdr = mbuf->m_pkthdr;
            if (!mbuf_copy_tags(copy, mbuf, how)) {
                m_free_raw(copy);
                goto fail;
            }
            copy->m_pkthdr.len = (int32_t)copy_length;
            copy_header = 0;
        }
        *next = copy;
        next = &copy->m_next;
        remaining -= segment_length;
        source_offset = 0;
        source = source->m_next;
    }
    if (remaining != 0)
        goto fail;
    return head;

fail:
    m_freem(head);
    return 0;
}

unsigned int
m_length(struct mbuf *mbuf, struct mbuf **last)
{
    unsigned int total = 0;
    struct mbuf *tail = 0;

    for (; mbuf; mbuf = mbuf->m_next) {
        if (mbuf->m_len > 0) {
            if ((unsigned int)mbuf->m_len > UINT32_MAX - total)
                total = UINT32_MAX;
            else
                total += (unsigned int)mbuf->m_len;
        }
        tail = mbuf;
    }
    if (last)
        *last = tail;
    return total;
}

struct mbuf *
m_defrag(struct mbuf *mbuf, int how)
{
    struct mbuf *replacement;
    unsigned int total;
    int allocation_size;

    if (!mbuf || !mbuf->m_next)
        return mbuf;
    total = m_length(mbuf, 0);
    if (total == 0 || total > INT32_MAX)
        return 0;
    allocation_size = total < MCLBYTES ? MCLBYTES : (int)total;
    replacement = m_getjcl(how, (short)mbuf->m_type,
        (int)(mbuf->m_flags & (M_PKTHDR | M_MCAST | M_VLANTAG)),
        allocation_size);
    if (!replacement)
        return 0;
    m_copydata(mbuf, 0, (int)total, replacement->m_data);
    replacement->m_len = (int32_t)total;
    replacement->m_pkthdr = mbuf->m_pkthdr;
    mbuf->m_pkthdr.tags = 0;
    if ((replacement->m_flags & M_PKTHDR) != 0)
        replacement->m_pkthdr.len = (int32_t)total;
    m_freem(mbuf);
    return replacement;
}

struct mbuf *
m_collapse(struct mbuf *mbuf, int how, int max_segments)
{
    int segments = 0;

    if (!mbuf || max_segments <= 0)
        return 0;
    for (struct mbuf *current = mbuf; current;
        current = current->m_next)
        ++segments;
    if (segments <= max_segments)
        return mbuf;
    return m_defrag(mbuf, how);
}

struct mbuf *
m_dup(const struct mbuf *mbuf, int how)
{
    struct mbuf *copy;
    unsigned int length;
    int allocation_size;

    if (!mbuf)
        return 0;
    length = m_length((struct mbuf *)(uintptr_t)mbuf, 0);
    if (length > INT32_MAX)
        return 0;
    allocation_size = length < MCLBYTES ? MCLBYTES : (int)length;
    copy = m_getjcl(how, (short)mbuf->m_type,
        (int)(mbuf->m_flags & (M_PKTHDR | M_BCAST | M_MCAST |
        M_VLANTAG)), allocation_size);
    if (!copy)
        return 0;
    m_copydata(mbuf, 0, (int)length, copy->m_data);
    copy->m_len = (int32_t)length;
    copy->m_pkthdr = mbuf->m_pkthdr;
    if (!mbuf_copy_tags(copy, mbuf, how)) {
        m_freem(copy);
        return 0;
    }
    if ((copy->m_flags & M_PKTHDR) != 0)
        copy->m_pkthdr.len = (int32_t)length;
    return copy;
}

struct mbuf *
m_unshare(struct mbuf *mbuf, int how)
{
    (void)how;
    /*
     * EdgeOS mbuf data allocations are never reference-shared. Splits copy
     * their partial segment, so every live chain is already writable.
     */
    return mbuf;
}

void
m_align(struct mbuf *mbuf, int length)
{
    uint32_t offset;

    if (!mbuf || length < 0 || !mbuf->m_ext.ext_buf ||
        (uint32_t)length > mbuf->m_bridge_capacity)
        return;
    offset = mbuf->m_bridge_capacity - (uint32_t)length;
    offset &= ~1u;
    mbuf->m_data = mbuf->m_ext.ext_buf + offset;
}

void
m_move_pkthdr(struct mbuf *destination, struct mbuf *source)
{
    if (!destination || !source)
        return;
    destination->m_pkthdr = source->m_pkthdr;
    destination->m_flags =
        (destination->m_flags & ~M_PKTHDR) |
        (source->m_flags & M_PKTHDR);
    source->m_pkthdr.tags = 0;
    source->m_flags &= ~M_PKTHDR;
}

int
m_dup_pkthdr(struct mbuf *destination, const struct mbuf *source, int how)
{
    uint32_t allocation_flags;

    if (!destination || !source ||
        (source->m_flags & M_PKTHDR) == 0)
        return 0;
    if ((destination->m_flags & M_PKTHDR) != 0)
        m_tag_delete_chain(destination, 0);
    allocation_flags = destination->m_flags & M_EXT;
    destination->m_flags =
        (source->m_flags & M_COPYFLAGS) | allocation_flags;
    destination->m_pkthdr = source->m_pkthdr;
    destination->m_pkthdr.tags = 0;
    if (!mbuf_copy_tags(destination, source, how)) {
        destination->m_pkthdr.tags = 0;
        return 0;
    }
    return 1;
}

struct m_tag *
m_tag_alloc(uint32_t cookie, int type, int length, int how)
{
    struct m_tag *tag;

    if (length < 0 || length > UINT16_MAX ||
        (size_t)length > SIZE_MAX - sizeof(*tag))
        return 0;
    tag = bsd_malloc(sizeof(*tag) + (size_t)length,
        M_DEVBUF, how | M_ZERO);
    if (!tag)
        return 0;
    tag->cookie = cookie;
    tag->type = type;
    tag->length = (uint16_t)length;
    return tag;
}

void
m_tag_prepend(struct mbuf *mbuf, struct m_tag *tag)
{
    if (!mbuf || !tag || (mbuf->m_flags & M_PKTHDR) == 0)
        return;
    tag->next = mbuf->m_pkthdr.tags;
    mbuf->m_pkthdr.tags = tag;
}

struct m_tag *
m_tag_locate(struct mbuf *mbuf, uint32_t cookie, int type,
    struct m_tag *start)
{
    struct m_tag *tag;

    if (!mbuf || (mbuf->m_flags & M_PKTHDR) == 0)
        return 0;
    tag = start ? start->next : mbuf->m_pkthdr.tags;
    while (tag) {
        if (tag->cookie == cookie && tag->type == type)
            return tag;
        tag = tag->next;
    }
    return 0;
}

void
m_tag_delete(struct mbuf *mbuf, struct m_tag *tag)
{
    struct m_tag **position;

    if (!mbuf || !tag || (mbuf->m_flags & M_PKTHDR) == 0)
        return;
    position = &mbuf->m_pkthdr.tags;
    while (*position && *position != tag)
        position = &(*position)->next;
    if (*position) {
        *position = tag->next;
        bsd_free(tag, M_DEVBUF);
    }
}

void
m_tag_delete_chain(struct mbuf *mbuf, struct m_tag *tag)
{
    struct m_tag **position;
    struct m_tag *current;

    if (!mbuf || (mbuf->m_flags & M_PKTHDR) == 0)
        return;
    position = &mbuf->m_pkthdr.tags;
    if (tag) {
        while (*position && *position != tag)
            position = &(*position)->next;
        if (!*position)
            return;
    }
    current = *position;
    *position = 0;
    while (current) {
        struct m_tag *next = current->next;

        bsd_free(current, M_DEVBUF);
        current = next;
    }
}

struct mbuf *
m_pullup(struct mbuf *mbuf, int length)
{
    struct mbuf *replacement;

    if (!mbuf || length < 0) {
        m_freem(mbuf);
        return 0;
    }
    if (mbuf->m_len >= length)
        return mbuf;
    if (m_length(mbuf, 0) < (unsigned int)length) {
        m_freem(mbuf);
        return 0;
    }
    replacement = m_defrag(mbuf, M_NOWAIT);
    if (!replacement)
        m_freem(mbuf);
    return replacement;
}

void
m_cat(struct mbuf *head, struct mbuf *tail)
{
    struct mbuf *last;

    if (!head)
        return;
    last = head;
    while (last->m_next)
        last = last->m_next;
    while (tail) {
        if (!M_WRITABLE(last) || M_TRAILINGSPACE(last) < tail->m_len) {
            last->m_next = tail;
            return;
        }
        mbuf_copy(last->m_data + last->m_len, tail->m_data,
            (size_t)tail->m_len);
        last->m_len += tail->m_len;
        tail = m_free(tail);
    }
}

int
m_append(struct mbuf *mbuf, int length, const void *data)
{
    const uint8_t *source = data;
    struct mbuf *head = mbuf;
    struct mbuf *tail;
    int remaining = length;

    if (!mbuf || length < 0 || (length != 0 && !data))
        return 0;
    while (mbuf->m_next)
        mbuf = mbuf->m_next;
    tail = mbuf;
    while (remaining != 0) {
        uint32_t offset = tail->m_data && tail->m_ext.ext_buf ?
            (uint32_t)(tail->m_data - tail->m_ext.ext_buf) : 0;
        uint32_t used = offset + (uint32_t)(tail->m_len > 0 ?
            tail->m_len : 0);
        uint32_t available = used < tail->m_bridge_capacity ?
            tail->m_bridge_capacity - used : 0;

        if (available != 0) {
            uint32_t chunk = available < (uint32_t)remaining ?
                available : (uint32_t)remaining;

            mbuf_copy(tail->m_data + tail->m_len, source, chunk);
            tail->m_len += (int32_t)chunk;
            source += chunk;
            remaining -= (int)chunk;
            continue;
        }
        tail->m_next = m_getjcl(M_NOWAIT, (short)tail->m_type, 0,
            remaining < MCLBYTES ? MCLBYTES : remaining);
        if (!tail->m_next)
            break;
        tail = tail->m_next;
    }
    if ((head->m_flags & M_PKTHDR) != 0)
        head->m_pkthdr.len += length - remaining;
    return remaining == 0;
}

void
m_freem(struct mbuf *mbuf)
{
    while (mbuf)
        mbuf = m_free(mbuf);
}

struct mbuf *
m_getptr(struct mbuf *mbuf, int location, int *offset)
{
    if (!offset)
        return 0;
    while (mbuf && location >= 0) {
        if (mbuf->m_len > location) {
            *offset = location;
            return mbuf;
        }
        location -= mbuf->m_len;
        if (!mbuf->m_next) {
            if (location == 0) {
                *offset = mbuf->m_len;
                return mbuf;
            }
            return 0;
        }
        mbuf = mbuf->m_next;
    }
    return 0;
}
