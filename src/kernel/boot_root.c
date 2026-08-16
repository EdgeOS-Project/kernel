/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent root filesystem boot policy.
 * Copyright (c) EdgeOS Contributors.
 *
 * Linux-visible root selection belongs here rather than in an architecture
 * entry point.  Architecture code may discover block devices, but it must not
 * invent a different interpretation of root=, rootfstype=, or rootflags=.
 */

#include "kernel/boot_root.h"

#include <stddef.h>
#include <stdint.h>

#include "kernel/boot_command_line.h"
#include "stdio.h"
#include "string.h"
#include "sys/boottime.h"
#include "vfs/vfs.h"

#define EXT_SUPERBLOCK_OFFSET 1024u
#define EXT_SUPERBLOCK_BYTES  136u
#define EXT_MAGIC_OFFSET      56u
#define EXT_UUID_OFFSET       104u
#define EXT_LABEL_OFFSET      120u
#define EXT_LABEL_BYTES       16u

static int boot_root_text_equal(const char *left, const char *right) {
    if (!left || !right) return 0;
    while (*left && *right && *left == *right) {
        ++left;
        ++right;
    }
    return *left == 0 && *right == 0;
}

static int boot_root_prefix_equal(const char *text, const char *prefix) {
    if (!text || !prefix) return 0;
    while (*prefix && *text == *prefix) {
        ++text;
        ++prefix;
    }
    return *prefix == 0;
}

static int boot_root_contains(const char *text, char value) {
    if (!text) return 0;
    while (*text) {
        if (*text++ == value) return 1;
    }
    return 0;
}

static int boot_root_copy(char *output, size_t capacity, const char *input) {
    size_t length = 0;

    if (!output || !capacity || !input) return -1;
    while (input[length]) {
        if (length + 1u >= capacity) {
            output[0] = 0;
            return -1;
        }
        output[length] = input[length];
        ++length;
    }
    output[length] = 0;
    return 0;
}

static int boot_root_parse_u32(const char *text, uint32_t *value) {
    uint32_t output = 0;

    if (!text || !text[0] || !value) return -1;
    while (*text) {
        uint32_t digit;

        if (*text < '0' || *text > '9') return -1;
        digit = (uint32_t)(*text++ - '0');
        if (output > (UINT32_MAX - digit) / 10u) return -1;
        output = output * 10u + digit;
    }
    *value = output;
    return 0;
}

static int boot_root_flag_equal(const char *start, size_t length,
                                const char *expected) {
    size_t index = 0;

    while (index < length && expected[index] &&
           start[index] == expected[index])
        ++index;
    return index == length && expected[index] == 0;
}

static int boot_root_apply_flag(const char *start, size_t length,
                                uint32_t *mount_flags) {
    uint32_t set = 0;
    uint32_t clear = 0;

    if (!start || !length || !mount_flags) return -1;
    if (boot_root_flag_equal(start, length, "ro"))
        set = VFS_MOUNT_READONLY;
    else if (boot_root_flag_equal(start, length, "rw"))
        clear = VFS_MOUNT_READONLY;
    else if (boot_root_flag_equal(start, length, "nosuid"))
        set = VFS_MOUNT_NOSUID;
    else if (boot_root_flag_equal(start, length, "suid"))
        clear = VFS_MOUNT_NOSUID;
    else if (boot_root_flag_equal(start, length, "nodev"))
        set = VFS_MOUNT_NODEV;
    else if (boot_root_flag_equal(start, length, "dev"))
        clear = VFS_MOUNT_NODEV;
    else if (boot_root_flag_equal(start, length, "noexec"))
        set = VFS_MOUNT_NOEXEC;
    else if (boot_root_flag_equal(start, length, "exec"))
        clear = VFS_MOUNT_NOEXEC;
    else if (boot_root_flag_equal(start, length, "sync"))
        set = VFS_MOUNT_SYNCHRONOUS;
    else if (boot_root_flag_equal(start, length, "async"))
        clear = VFS_MOUNT_SYNCHRONOUS;
    else if (boot_root_flag_equal(start, length, "dirsync"))
        set = VFS_MOUNT_DIRSYNC;
    else if (boot_root_flag_equal(start, length, "nodirsync"))
        clear = VFS_MOUNT_DIRSYNC;
    else if (boot_root_flag_equal(start, length, "nosymfollow"))
        set = VFS_MOUNT_NOSYMFOLLOW;
    else if (boot_root_flag_equal(start, length, "symfollow"))
        clear = VFS_MOUNT_NOSYMFOLLOW;
    else if (boot_root_flag_equal(start, length, "noatime"))
        set = VFS_MOUNT_NOATIME;
    else if (boot_root_flag_equal(start, length, "atime"))
        clear = VFS_MOUNT_NOATIME | VFS_MOUNT_RELATIME |
                VFS_MOUNT_STRICTATIME;
    else if (boot_root_flag_equal(start, length, "nodiratime"))
        set = VFS_MOUNT_NODIRATIME;
    else if (boot_root_flag_equal(start, length, "diratime"))
        clear = VFS_MOUNT_NODIRATIME;
    else if (boot_root_flag_equal(start, length, "relatime")) {
        set = VFS_MOUNT_RELATIME;
        clear = VFS_MOUNT_STRICTATIME;
    } else if (boot_root_flag_equal(start, length, "norelatime"))
        clear = VFS_MOUNT_RELATIME;
    else if (boot_root_flag_equal(start, length, "strictatime")) {
        set = VFS_MOUNT_STRICTATIME;
        clear = VFS_MOUNT_RELATIME;
    } else if (boot_root_flag_equal(start, length, "nostrictatime"))
        clear = VFS_MOUNT_STRICTATIME;
    else if (boot_root_flag_equal(start, length, "lazytime"))
        set = VFS_MOUNT_LAZYTIME;
    else if (boot_root_flag_equal(start, length, "nolazytime"))
        clear = VFS_MOUNT_LAZYTIME;
    else if (boot_root_flag_equal(start, length, "acl") ||
             boot_root_flag_equal(start, length, "posixacl"))
        set = VFS_MOUNT_POSIXACL;
    else if (boot_root_flag_equal(start, length, "noacl"))
        clear = VFS_MOUNT_POSIXACL;
    else
        return -1;

    *mount_flags = (*mount_flags & ~clear) | set;
    return 0;
}

static int boot_root_parse_flags(const char *flags, uint32_t *mount_flags) {
    const char *cursor = flags;

    if (!flags || !mount_flags) return -1;
    while (*cursor) {
        const char *start = cursor;
        size_t length;

        while (*cursor && *cursor != ',') ++cursor;
        length = (size_t)(cursor - start);
        if (!length || boot_root_apply_flag(start, length, mount_flags) < 0)
            return -1;
        if (*cursor == ',') ++cursor;
    }
    return 0;
}

int kernel_boot_root_policy_load(kernel_boot_root_policy_t *policy) {
    char numeric[32];
    int result;
    int ro_order;
    int rw_order;

    if (!policy) return -1;
    memset(policy, 0, sizeof(*policy));
    policy->mount_flags = VFS_MOUNT_READONLY;

    result = kernel_boot_option_get(
        "root", policy->device_spec, sizeof(policy->device_spec));
    if (result < 0 || (result > 0 && !policy->device_spec[0])) return -1;
    policy->device_explicit = result > 0;

    result = kernel_boot_option_get(
        "rootfstype", policy->filesystem_types,
        sizeof(policy->filesystem_types));
    if (result < 0 || (result > 0 && !policy->filesystem_types[0]))
        return -1;
    if (result == 0 &&
        boot_root_copy(policy->filesystem_types,
                       sizeof(policy->filesystem_types), "ext4,ext2") < 0)
        return -1;

    result = kernel_boot_option_get(
        "rootflags", policy->filesystem_flags,
        sizeof(policy->filesystem_flags));
    if (result < 0) return -1;
    if (result > 0 &&
        boot_root_parse_flags(
            policy->filesystem_flags, &policy->mount_flags) < 0)
        return -1;

    ro_order = kernel_boot_option_last_ordinal("ro");
    rw_order = kernel_boot_option_last_ordinal("rw");
    if (ro_order < 0 || rw_order < 0) return -1;
    if (ro_order || rw_order) {
        if (rw_order > ro_order)
            policy->mount_flags &= ~VFS_MOUNT_READONLY;
        else
            policy->mount_flags |= VFS_MOUNT_READONLY;
    }

    result = kernel_boot_option_get("rootdelay", numeric, sizeof(numeric));
    if (result < 0 ||
        (result > 0 &&
         boot_root_parse_u32(numeric, &policy->delay_seconds) < 0))
        return -1;

    result = kernel_boot_option_get("rootwait", numeric, sizeof(numeric));
    if (result < 0) return -1;
    if (result > 0) {
        policy->wait_for_device = 1;
        if (!numeric[0])
            policy->wait_forever = 1;
        else if (boot_root_parse_u32(numeric, &policy->wait_seconds) < 0)
            return -1;
    }
    return 0;
}

static int boot_root_hex_value(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static int boot_root_parse_uuid(const char *text, uint8_t uuid[16]) {
    uint32_t output = 0;
    int high = -1;

    if (!text || !uuid) return -1;
    while (*text) {
        int value;

        if (*text == '-') {
            ++text;
            continue;
        }
        value = boot_root_hex_value(*text++);
        if (value < 0) return -1;
        if (high < 0) {
            high = value;
            continue;
        }
        if (output >= 16u) return -1;
        uuid[output++] = (uint8_t)((high << 4) | value);
        high = -1;
    }
    return output == 16u && high < 0 ? 0 : -1;
}

static int boot_root_ext_identity(block_device_t *device,
                                  uint8_t uuid[16],
                                  char label[EXT_LABEL_BYTES + 1u]) {
    uint8_t superblock[EXT_SUPERBLOCK_BYTES];

    if (!device ||
        block_read_bytes(device, EXT_SUPERBLOCK_OFFSET, superblock,
                         sizeof(superblock)) != (int64_t)sizeof(superblock))
        return -1;
    if (superblock[EXT_MAGIC_OFFSET] != 0x53u ||
        superblock[EXT_MAGIC_OFFSET + 1u] != 0xefu)
        return -1;
    if (uuid)
        memcpy(uuid, superblock + EXT_UUID_OFFSET, 16u);
    if (label) {
        uint32_t length = 0;

        while (length < EXT_LABEL_BYTES &&
               superblock[EXT_LABEL_OFFSET + length])
            ++length;
        while (length > 0u &&
               superblock[EXT_LABEL_OFFSET + length - 1u] == ' ')
            --length;
        memcpy(label, superblock + EXT_LABEL_OFFSET, length);
        label[length] = 0;
    }
    return 0;
}

static block_device_t *boot_root_find_uuid(const char *text) {
    uint8_t wanted[16];

    if (boot_root_parse_uuid(text, wanted) < 0) return 0;
    for (int index = 0; index < block_count(); ++index) {
        block_device_t *device = block_get(index);
        uint8_t current[16];

        if (boot_root_ext_identity(device, current, 0) == 0 &&
            memcmp(current, wanted, sizeof(current)) == 0)
            return device;
    }
    return 0;
}

static block_device_t *boot_root_find_label(const char *text) {
    if (!text || !text[0]) return 0;
    for (int index = 0; index < block_count(); ++index) {
        block_device_t *device = block_get(index);
        char current[EXT_LABEL_BYTES + 1u];

        if (boot_root_ext_identity(device, 0, current) == 0 &&
            boot_root_text_equal(current, text))
            return device;
    }
    return 0;
}

static int boot_root_parse_major_minor(const char *text, uint32_t *major,
                                      uint32_t *minor) {
    char major_text[16];
    char minor_text[16];
    size_t split = 0;
    size_t end;

    if (!text || !major || !minor) return -1;
    while (text[split] && text[split] != ':') ++split;
    if (!text[split] || !split || split >= sizeof(major_text))
        return -1;
    end = split + 1u;
    while (text[end]) ++end;
    if (end == split + 1u ||
        end - split >= sizeof(minor_text))
        return -1;
    memcpy(major_text, text, split);
    major_text[split] = 0;
    memcpy(minor_text, text + split + 1u, end - split - 1u);
    minor_text[end - split - 1u] = 0;
    if (boot_root_parse_u32(major_text, major) < 0 ||
        boot_root_parse_u32(minor_text, minor) < 0)
        return -1;
    return 0;
}

static uint64_t boot_root_linux_device_number(uint32_t major,
                                              uint32_t minor) {
    return ((uint64_t)(major & 0xfffu) << 8) |
           (uint64_t)(minor & 0xffu) |
           ((uint64_t)(major & ~0xfffu) << 32) |
           ((uint64_t)(minor & ~0xffu) << 12);
}

static int boot_root_mbr_partuuid(block_device_t *device,
                                  char output[12]) {
    block_device_t *parent;
    char parent_name[BLOCK_NAME_MAX];
    uint8_t signature[4];
    uint32_t value;
    int partition;
    static const char hex[] = "0123456789abcdef";

    if (!device ||
        block_partition_parent_name(
            device, parent_name, sizeof(parent_name)) < 0)
        return -1;
    parent = block_find(parent_name);
    partition = block_partition_number(device);
    if (!parent || partition <= 0 || partition > 255 ||
        block_read_bytes(parent, 440u, signature, sizeof(signature)) !=
            (int64_t)sizeof(signature))
        return -1;
    value = (uint32_t)signature[0] |
            ((uint32_t)signature[1] << 8) |
            ((uint32_t)signature[2] << 16) |
            ((uint32_t)signature[3] << 24);
    for (uint32_t index = 0; index < 8u; ++index)
        output[index] = hex[(value >> ((7u - index) * 4u)) & 0xfu];
    output[8] = '-';
    output[9] = hex[((uint32_t)partition >> 4) & 0xfu];
    output[10] = hex[(uint32_t)partition & 0xfu];
    output[11] = 0;
    return 0;
}

static int boot_root_case_equal(const char *left, const char *right) {
    if (!left || !right) return 0;
    while (*left && *right) {
        char a = *left++;
        char b = *right++;

        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
        if (a != b) return 0;
    }
    return *left == 0 && *right == 0;
}

static block_device_t *boot_root_find_partuuid(const char *text) {
    if (!text || !text[0]) return 0;
    for (int index = 0; index < block_count(); ++index) {
        block_device_t *device = block_get(index);
        char current[12];

        if (boot_root_mbr_partuuid(device, current) == 0 &&
            boot_root_case_equal(current, text))
            return device;
    }
    return 0;
}

block_device_t *kernel_boot_root_resolve_device(const char *specification) {
    uint32_t major;
    uint32_t minor;

    if (!specification || !specification[0]) return 0;
    if (boot_root_prefix_equal(specification, "/dev/"))
        return block_find(specification + 5u);
    if (boot_root_prefix_equal(specification, "UUID="))
        return boot_root_find_uuid(specification + 5u);
    if (boot_root_prefix_equal(specification, "LABEL="))
        return boot_root_find_label(specification + 6u);
    if (boot_root_prefix_equal(specification, "PARTUUID="))
        return boot_root_find_partuuid(specification + 9u);
    if (boot_root_parse_major_minor(
            specification, &major, &minor) == 0)
        return block_find_linux_device(
            boot_root_linux_device_number(major, minor));
    if (boot_root_contains(specification, '/')) return 0;
    return block_find(specification);
}

static int boot_root_filesystem_next(const char *list, size_t *offset,
                                     char *filesystem, size_t capacity) {
    size_t input;
    size_t output = 0;

    if (!list || !offset || !filesystem || capacity < 2u) return -1;
    input = *offset;
    while (list[input] == ',') ++input;
    if (!list[input]) {
        filesystem[0] = 0;
        *offset = input;
        return 0;
    }
    while (list[input] && list[input] != ',') {
        if (output + 1u >= capacity) return -1;
        filesystem[output++] = list[input++];
    }
    filesystem[output] = 0;
    *offset = input;
    return output ? 1 : -1;
}

static int boot_root_device_has_ext_magic(block_device_t *device) {
    uint8_t magic[2];

    return device &&
           block_read_bytes(device,
                            EXT_SUPERBLOCK_OFFSET + EXT_MAGIC_OFFSET,
                            magic, sizeof(magic)) ==
               (int64_t)sizeof(magic) &&
           magic[0] == 0x53u && magic[1] == 0xefu;
}

static int boot_root_try_device(
    block_device_t *device, const kernel_boot_root_policy_t *policy,
    kernel_boot_root_result_t *result) {
    size_t offset = 0;
    char filesystem[32];
    int next;

    if (!device || !policy || !result) return -1;
    while ((next = boot_root_filesystem_next(
                policy->filesystem_types, &offset, filesystem,
                sizeof(filesystem))) > 0) {
        if ((boot_root_text_equal(filesystem, "ext4") ||
             boot_root_text_equal(filesystem, "ext2")) &&
            !boot_root_device_has_ext_magic(device))
            continue;
        printf("[fs] trying %s root on /dev/%s\n",
               filesystem, device->name);
        if (vfs_mount_blockdev(device, "/", filesystem) == 0) {
            if (vfs_remount("/", policy->mount_flags) < 0) {
                printf("[fs] failed to apply root mount flags\n");
                return -1;
            }
            memset(result, 0, sizeof(*result));
            result->device = device;
            result->mount_flags = policy->mount_flags;
            result->device_explicit = policy->device_explicit;
            if (boot_root_copy(result->filesystem_type,
                               sizeof(result->filesystem_type),
                               filesystem) < 0)
                return -1;
            return 0;
        }
        if (policy->filesystem_types[offset] == ',') ++offset;
    }
    return next < 0 ? -1 : 1;
}

static void boot_root_delay_until(uint64_t deadline) {
    while (boottime_monotonic_us() < deadline)
        __asm__ __volatile__("" ::: "memory");
}

static block_device_t *boot_root_wait_for_explicit_device(
    const kernel_boot_root_policy_t *policy) {
    uint64_t deadline = 0;
    block_device_t *device;

    if (!policy || !policy->device_explicit) return 0;
    device = kernel_boot_root_resolve_device(policy->device_spec);
    if (device || !policy->wait_for_device) return device;
    if (!policy->wait_forever) {
        uint64_t now = boottime_monotonic_us();
        uint64_t interval =
            (uint64_t)policy->wait_seconds * 1000000u;

        deadline = now > UINT64_MAX - interval ?
            UINT64_MAX : now + interval;
    }
    printf("[fs] waiting for root device %s\n", policy->device_spec);
    for (;;) {
        device = kernel_boot_root_resolve_device(policy->device_spec);
        if (device) return device;
        if (!policy->wait_forever &&
            boottime_monotonic_us() >= deadline)
            return 0;
        {
            uint64_t now = boottime_monotonic_us();
            uint64_t poll_deadline =
                now > UINT64_MAX - 1000u ? UINT64_MAX : now + 1000u;
            if (!policy->wait_forever && poll_deadline > deadline)
                poll_deadline = deadline;
            boot_root_delay_until(poll_deadline);
        }
    }
}

static int boot_root_already_tried(block_device_t *device,
                                   block_device_t **tried,
                                   uint32_t tried_count) {
    for (uint32_t index = 0; index < tried_count; ++index)
        if (tried[index] == device) return 1;
    return 0;
}

int kernel_boot_root_mount(kernel_boot_root_result_t *result) {
    static const char *const preferred[] = {
        "sda1", "sda", "vda1", "vda", "ram0", "hda1", "hda"
    };
    block_device_t *tried[BLOCK_MAX_DEVICES];
    uint32_t tried_count = 0;
    kernel_boot_root_policy_t policy;
    int status;

    if (!result || kernel_boot_root_policy_load(&policy) < 0) {
        printf("[fs] invalid root filesystem command line\n");
        return -1;
    }
    memset(result, 0, sizeof(*result));
    result->device_explicit = policy.device_explicit;
    if (policy.delay_seconds) {
        uint64_t now = boottime_monotonic_us();
        uint64_t interval =
            (uint64_t)policy.delay_seconds * 1000000u;
        uint64_t deadline = now > UINT64_MAX - interval ?
            UINT64_MAX : now + interval;

        printf("[fs] delaying root mount for %u seconds\n",
               policy.delay_seconds);
        boot_root_delay_until(deadline);
    }

    if (policy.device_explicit) {
        block_device_t *device =
            boot_root_wait_for_explicit_device(&policy);

        if (!device) {
            printf("[fs] requested root device not found: %s\n",
                   policy.device_spec);
            return -1;
        }
        status = boot_root_try_device(device, &policy, result);
        if (status != 0)
            printf("[fs] requested root filesystem could not be mounted\n");
        return status == 0 ? 0 : -1;
    }

    for (uint32_t index = 0;
         index < sizeof(preferred) / sizeof(preferred[0]); ++index) {
        block_device_t *device = block_find(preferred[index]);

        if (!device || boot_root_already_tried(device, tried, tried_count))
            continue;
        if (tried_count < BLOCK_MAX_DEVICES)
            tried[tried_count++] = device;
        if (boot_root_try_device(device, &policy, result) == 0)
            return 0;
    }
    for (int index = 0; index < block_count(); ++index) {
        block_device_t *device = block_get(index);

        if (!device || boot_root_already_tried(device, tried, tried_count))
            continue;
        if (tried_count < BLOCK_MAX_DEVICES)
            tried[tried_count++] = device;
        if (boot_root_try_device(device, &policy, result) == 0)
            return 0;
    }
    printf("[fs] no usable root filesystem discovered\n");
    return -1;
}
