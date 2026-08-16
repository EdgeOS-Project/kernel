/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS code. */

#include "fs/proc_sysctl.h"
#include "kernel/inotify.h"
#include "kernel/process_runtime.h"
#include "kernel/random.h"
#include "kernel/runtime_limits.h"
#include "kernel/linux_utsname.h"
#include "net/network_core.h"

#ifndef CONFIG_LINUX_ABI_RELEASE
#define CONFIG_LINUX_ABI_RELEASE "unknown"
#endif

static uint32_t g_overflowuid = 65534u;
static uint32_t g_overflowgid = 65534u;
static uint64_t g_file_max = 0x7fffffffffffffffull;
static uint64_t g_nr_open = UINT64_MAX;
static uint32_t g_ip_local_port_low = 32768u;
static uint32_t g_ip_local_port_high = 60999u;
static uint32_t g_threads_max = 4194304u;
static uint32_t g_root_maxkeys = 1000000u;
static volatile uint32_t g_boot_id_lock;
static uint32_t g_boot_id_ready;
static char g_boot_id[37];

static char proc_hex_digit(uint8_t value) {
    return value < 10u ? (char)('0' + value) : (char)('a' + value - 10u);
}

static const char *proc_boot_id(void) {
    static const uint8_t groups[5] = {4u, 2u, 2u, 2u, 6u};
    uint8_t bytes[16];
    uint32_t source = 0;
    uint32_t destination = 0;

    if (__atomic_load_n(&g_boot_id_ready, __ATOMIC_ACQUIRE)) return g_boot_id;
    while (__sync_lock_test_and_set(&g_boot_id_lock, 1u)) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause" ::: "memory");
#elif defined(__aarch64__)
        __asm__ __volatile__("yield" ::: "memory");
#endif
    }
    if (!g_boot_id_ready) {
        edge_random_fill(bytes, sizeof(bytes));
        bytes[6] = (uint8_t)((bytes[6] & 0x0fu) | 0x40u);
        bytes[8] = (uint8_t)((bytes[8] & 0x3fu) | 0x80u);
        for (uint32_t group = 0; group < 5u; ++group) {
            if (group) g_boot_id[destination++] = '-';
            for (uint32_t index = 0; index < groups[group]; ++index) {
                uint8_t byte = bytes[source++];
                g_boot_id[destination++] = proc_hex_digit(byte >> 4);
                g_boot_id[destination++] = proc_hex_digit(byte & 0x0fu);
            }
        }
        g_boot_id[destination] = 0;
        __atomic_store_n(&g_boot_id_ready, 1u, __ATOMIC_RELEASE);
    }
    __sync_lock_release(&g_boot_id_lock);
    return g_boot_id;
}

int proc_parse_s32(const void *buffer, uint32_t length,
                   int32_t minimum, int32_t maximum, int32_t *value_out) {
    const char *text = (const char *)buffer;
    uint32_t index = 0;
    uint32_t magnitude = 0;
    uint32_t digits = 0;
    int negative = 0;
    int64_t value;

    if (!buffer || !length || !value_out || minimum > maximum) return -1;
    while (index < length && (text[index] == ' ' || text[index] == '\t'))
        ++index;
    if (index < length && (text[index] == '-' || text[index] == '+')) {
        negative = text[index] == '-';
        ++index;
    }
    while (index < length && text[index] >= '0' && text[index] <= '9') {
        if (magnitude > 214748364u) return -1;
        magnitude = magnitude * 10u + (uint32_t)(text[index] - '0');
        ++digits;
        ++index;
    }
    if (!digits) return -1;
    while (index < length) {
        if (text[index] != 0 && text[index] != '\n' &&
            text[index] != ' ' && text[index] != '\t')
            return -1;
        ++index;
    }
    value = negative ? -(int64_t)magnitude : (int64_t)magnitude;
    if (value < minimum || value > maximum) return -1;
    *value_out = (int32_t)value;
    return 0;
}

uint32_t proc_sysctl_read(proc_sysctl_id_t id) {
    return id == PROC_SYSCTL_OVERFLOWGID ? g_overflowgid : g_overflowuid;
}

uint64_t proc_sysctl_nr_open_limit(void) {
    uint64_t configured = __atomic_load_n(&g_nr_open, __ATOMIC_RELAXED);
    uint64_t capacity = EDGE_RUNTIME_MAX_OPEN_FILES;

    return configured < capacity ? configured : capacity;
}

static int proc_render_u64(uint64_t value, char *buffer, uint32_t capacity) {
    char reversed[20];
    uint32_t digits = 0;
    uint32_t output = 0;

    do {
        reversed[digits++] = (char)('0' + value % 10u);
        value /= 10u;
    } while (value);
    if (digits + 2u > capacity) return -1;
    while (digits) buffer[output++] = reversed[--digits];
    buffer[output++] = '\n';
    buffer[output] = 0;
    return (int)output;
}

static int proc_parse_u64(const void *buffer, uint32_t length,
                          uint64_t *value_out) {
    const char *text = (const char *)buffer;
    uint64_t value = 0;
    uint32_t digits = 0;
    uint32_t index = 0;

    if (!buffer || !length || !value_out) return -1;
    while (index < length && (text[index] == ' ' || text[index] == '\t'))
        ++index;
    while (index < length && text[index] >= '0' && text[index] <= '9') {
        uint32_t digit = (uint32_t)(text[index] - '0');
        if (value > (UINT64_MAX - digit) / 10u) return -1;
        value = value * 10u + digit;
        ++digits;
        ++index;
    }
    if (!digits) return -1;
    while (index < length) {
        if (text[index] != '\n' && text[index] != ' ' && text[index] != '\t')
            return -1;
        ++index;
    }
    *value_out = value;
    return 0;
}

static int proc_parse_u32_pair(const void *buffer, uint32_t length,
                               uint32_t *first, uint32_t *second) {
    const char *text = (const char *)buffer;
    uint32_t values[2] = {0, 0};
    uint32_t index = 0;

    if (!buffer || !length || !first || !second) return -1;
    for (uint32_t value = 0; value < 2u; ++value) {
        uint32_t digits = 0;
        while (index < length &&
               (text[index] == ' ' || text[index] == '\t')) ++index;
        while (index < length && text[index] >= '0' && text[index] <= '9') {
            uint32_t digit = (uint32_t)(text[index] - '0');
            if (values[value] > (UINT32_MAX - digit) / 10u) return -1;
            values[value] = values[value] * 10u + digit;
            ++digits;
            ++index;
        }
        if (!digits) return -1;
    }
    while (index < length) {
        if (text[index] != '\n' && text[index] != ' ' && text[index] != '\t')
            return -1;
        ++index;
    }
    *first = values[0];
    *second = values[1];
    return 0;
}

int proc_sysctl_render_in_network_namespace(
    proc_sysctl_id_t id, uint32_t network_namespace,
    char *buffer, uint32_t capacity) {
    const char *value;
    uint32_t length = 0;

    if (!buffer || capacity < 2u) return -1;
    if (id == PROC_SYSCTL_FILE_MAX)
        return proc_render_u64(
            __atomic_load_n(&g_file_max, __ATOMIC_RELAXED),
            buffer, capacity);
    if (id == PROC_SYSCTL_NR_OPEN)
        return proc_render_u64(proc_sysctl_nr_open_limit(), buffer, capacity);
    if (id == PROC_SYSCTL_INOTIFY_MAX_QUEUED_EVENTS)
        return proc_render_u64(kernel_inotify_limit_get(
            KERNEL_INOTIFY_LIMIT_MAX_QUEUED_EVENTS), buffer, capacity);
    if (id == PROC_SYSCTL_INOTIFY_MAX_USER_INSTANCES)
        return proc_render_u64(kernel_inotify_limit_get(
            KERNEL_INOTIFY_LIMIT_MAX_USER_INSTANCES), buffer, capacity);
    if (id == PROC_SYSCTL_INOTIFY_MAX_USER_WATCHES)
        return proc_render_u64(kernel_inotify_limit_get(
            KERNEL_INOTIFY_LIMIT_MAX_USER_WATCHES), buffer, capacity);
    if (id == PROC_SYSCTL_IP_FORWARD) {
        int enabled;

        if (edge_net_namespace_ipv4_forwarding_get(
                network_namespace, &enabled) != EDGE_NET_OK)
            return -1;
        return proc_render_u64((uint32_t)enabled, buffer, capacity);
    }
    if (id == PROC_SYSCTL_BRIDGE_NF_CALL_IPTABLES ||
        id == PROC_SYSCTL_BRIDGE_NF_CALL_IP6TABLES ||
        id == PROC_SYSCTL_BRIDGE_NF_CALL_ARPTABLES) {
        uint32_t family = id == PROC_SYSCTL_BRIDGE_NF_CALL_IPTABLES ? 0u :
            id == PROC_SYSCTL_BRIDGE_NF_CALL_IP6TABLES ? 1u : 2u;
        int enabled;

        if (edge_net_namespace_bridge_filter_get(
                network_namespace, family, &enabled) != EDGE_NET_OK)
            return -1;
        return proc_render_u64((uint32_t)enabled, buffer, capacity);
    }
    if (id == PROC_SYSCTL_THREADS_MAX)
        return proc_render_u64(
            __atomic_load_n(&g_threads_max, __ATOMIC_RELAXED),
            buffer, capacity);
    if (id == PROC_SYSCTL_ROOT_MAXKEYS)
        return proc_render_u64(
            __atomic_load_n(&g_root_maxkeys, __ATOMIC_RELAXED),
            buffer, capacity);
    if (id == PROC_SYSCTL_IP_LOCAL_PORT_RANGE) {
        int first_length = proc_render_u64(
            __atomic_load_n(&g_ip_local_port_low, __ATOMIC_RELAXED),
            buffer, capacity);
        int second_length;
        if (first_length < 1) return -1;
        buffer[first_length - 1] = '\t';
        second_length = proc_render_u64(
            __atomic_load_n(&g_ip_local_port_high, __ATOMIC_RELAXED),
            buffer + first_length, capacity - (uint32_t)first_length);
        return second_length < 0 ? -1 : first_length + second_length;
    }
    if (id == PROC_SYSCTL_HOSTNAME)
        value = kernel_current_hostname();
    else if (id == PROC_SYSCTL_DOMAINNAME)
        value = kernel_current_domainname();
    else if (id == PROC_SYSCTL_BOOT_ID)
        value = proc_boot_id();
    else if (id == PROC_SYSCTL_OSTYPE)
        value = "Linux";
    else if (id == PROC_SYSCTL_OSRELEASE)
        value = CONFIG_LINUX_ABI_RELEASE;
    else if (id == PROC_SYSCTL_VERSION)
        value = EDGEOS_LINUX_ABI_VERSION;
    else
        return -1;
    if (!value) value = "";
    while (value[length]) {
        if (length + 2u > capacity) return -1;
        buffer[length] = value[length];
        ++length;
    }
    buffer[length++] = '\n';
    buffer[length] = 0;
    return (int)length;
}

int proc_sysctl_render(
    proc_sysctl_id_t id, char *buffer, uint32_t capacity) {
    return proc_sysctl_render_in_network_namespace(
        id, 0u, buffer, capacity);
}

int proc_sysctl_write_in_network_namespace(
    proc_sysctl_id_t id, uint32_t network_namespace,
    const void *buffer, uint32_t length) {
    const char *text = (const char *)buffer;
    uint32_t value = 0;
    uint32_t digits = 0;
    uint32_t index = 0;

    if (!buffer || length == 0) return -1;
    if (id == PROC_SYSCTL_BOOT_ID || id == PROC_SYSCTL_OSTYPE ||
        id == PROC_SYSCTL_OSRELEASE || id == PROC_SYSCTL_VERSION)
        return -1;
    if (id == PROC_SYSCTL_FILE_MAX) {
        uint64_t file_max;
        if (proc_parse_u64(buffer, length, &file_max) < 0) return -1;
        __atomic_store_n(&g_file_max, file_max, __ATOMIC_RELAXED);
        return (int)length;
    }
    if (id == PROC_SYSCTL_NR_OPEN) {
        uint64_t nr_open;
        uint64_t capacity = EDGE_RUNTIME_MAX_OPEN_FILES;

        if (proc_parse_u64(buffer, length, &nr_open) < 0 ||
            nr_open < 64u || nr_open > capacity)
            return -1;
        __atomic_store_n(&g_nr_open, nr_open, __ATOMIC_RELAXED);
        return (int)length;
    }
    if (id == PROC_SYSCTL_INOTIFY_MAX_QUEUED_EVENTS ||
        id == PROC_SYSCTL_INOTIFY_MAX_USER_INSTANCES ||
        id == PROC_SYSCTL_INOTIFY_MAX_USER_WATCHES) {
        uint64_t parsed;
        kernel_inotify_limit_t limit =
            id == PROC_SYSCTL_INOTIFY_MAX_QUEUED_EVENTS ?
                KERNEL_INOTIFY_LIMIT_MAX_QUEUED_EVENTS :
            id == PROC_SYSCTL_INOTIFY_MAX_USER_INSTANCES ?
                KERNEL_INOTIFY_LIMIT_MAX_USER_INSTANCES :
                KERNEL_INOTIFY_LIMIT_MAX_USER_WATCHES;

        if (proc_parse_u64(buffer, length, &parsed) < 0 ||
            parsed > UINT32_MAX ||
            kernel_inotify_limit_set(limit, (uint32_t)parsed) < 0)
            return -1;
        return (int)length;
    }
    if (id == PROC_SYSCTL_IP_LOCAL_PORT_RANGE) {
        uint32_t low;
        uint32_t high;
        if (proc_parse_u32_pair(buffer, length, &low, &high) < 0 ||
            low < 1024u || high > 65535u || low >= high)
            return -1;
        __atomic_store_n(&g_ip_local_port_low, low, __ATOMIC_RELAXED);
        __atomic_store_n(&g_ip_local_port_high, high, __ATOMIC_RELAXED);
        return (int)length;
    }
    if (id == PROC_SYSCTL_IP_FORWARD ||
        id == PROC_SYSCTL_BRIDGE_NF_CALL_IPTABLES ||
        id == PROC_SYSCTL_BRIDGE_NF_CALL_IP6TABLES ||
        id == PROC_SYSCTL_BRIDGE_NF_CALL_ARPTABLES ||
        id == PROC_SYSCTL_THREADS_MAX ||
        id == PROC_SYSCTL_ROOT_MAXKEYS) {
        uint64_t parsed;
        if (proc_parse_u64(buffer, length, &parsed) < 0 ||
            parsed > UINT32_MAX ||
            ((id == PROC_SYSCTL_IP_FORWARD ||
              id == PROC_SYSCTL_BRIDGE_NF_CALL_IPTABLES ||
              id == PROC_SYSCTL_BRIDGE_NF_CALL_IP6TABLES ||
              id == PROC_SYSCTL_BRIDGE_NF_CALL_ARPTABLES) && parsed > 1u) ||
            (id != PROC_SYSCTL_IP_FORWARD &&
             id != PROC_SYSCTL_BRIDGE_NF_CALL_IPTABLES &&
             id != PROC_SYSCTL_BRIDGE_NF_CALL_IP6TABLES &&
             id != PROC_SYSCTL_BRIDGE_NF_CALL_ARPTABLES && parsed == 0u))
            return -1;
        if (id == PROC_SYSCTL_IP_FORWARD) {
            if (edge_net_namespace_ipv4_forwarding_set(
                    network_namespace, (int)parsed) != EDGE_NET_OK)
                return -1;
        } else if (id == PROC_SYSCTL_BRIDGE_NF_CALL_IPTABLES ||
                   id == PROC_SYSCTL_BRIDGE_NF_CALL_IP6TABLES ||
                   id == PROC_SYSCTL_BRIDGE_NF_CALL_ARPTABLES) {
            uint32_t family =
                id == PROC_SYSCTL_BRIDGE_NF_CALL_IPTABLES ? 0u :
                id == PROC_SYSCTL_BRIDGE_NF_CALL_IP6TABLES ? 1u : 2u;

            if (edge_net_namespace_bridge_filter_set(
                    network_namespace, family, (int)parsed) != EDGE_NET_OK)
                return -1;
        } else if (id == PROC_SYSCTL_THREADS_MAX)
            __atomic_store_n(&g_threads_max, (uint32_t)parsed,
                             __ATOMIC_RELAXED);
        else
            __atomic_store_n(&g_root_maxkeys, (uint32_t)parsed,
                             __ATOMIC_RELAXED);
        return (int)length;
    }
    if (id == PROC_SYSCTL_HOSTNAME || id == PROC_SYSCTL_DOMAINNAME) {
        uint32_t value_length = length;
        int result;

        if (text[value_length - 1u] == '\n') --value_length;
        if (value_length > 64u) return -1;
        for (uint32_t i = 0; i < value_length; ++i)
            if (text[i] == 0 || text[i] == '\n') return -1;
        result = id == PROC_SYSCTL_HOSTNAME ?
            kernel_current_set_hostname(text, value_length) :
            kernel_current_set_domainname(text, value_length);
        return result < 0 ? -1 : (int)length;
    }
    while (index < length && (text[index] == ' ' || text[index] == '\t'))
        ++index;
    for (; index < length; ++index) {
        char byte = text[index];
        if (byte == '\n' || byte == ' ' || byte == '\t') break;
        if (byte < '0' || byte > '9' || value > 6553u) return -1;
        value = value * 10u + (uint32_t)(byte - '0');
        ++digits;
    }
    if (!digits || value > 65535u) return -1;
    while (index < length) {
        if (text[index] != '\n' && text[index] != ' ' && text[index] != '\t')
            return -1;
        ++index;
    }
    if (id == PROC_SYSCTL_OVERFLOWGID) g_overflowgid = value;
    else if (id == PROC_SYSCTL_OVERFLOWUID) g_overflowuid = value;
    else return -1;
    return (int)length;
}

int proc_sysctl_write(
    proc_sysctl_id_t id, const void *buffer, uint32_t length) {
    return proc_sysctl_write_in_network_namespace(
        id, 0u, buffer, length);
}
