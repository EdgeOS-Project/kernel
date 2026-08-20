/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux credential transition helpers.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_CREDENTIALS_H
#define EDGEOS_KERNEL_CREDENTIALS_H

#include <stdint.h>

/* Linux capabilities are numbered through CAP_CHECKPOINT_RESTORE (40). */
#define EDGE_LINUX_CAP_CHOWN 0u
#define EDGE_LINUX_CAP_DAC_OVERRIDE 1u
#define EDGE_LINUX_CAP_DAC_READ_SEARCH 2u
#define EDGE_LINUX_CAP_FOWNER 3u
#define EDGE_LINUX_CAP_FSETID 4u
#define EDGE_LINUX_CAP_KILL 5u
#define EDGE_LINUX_CAP_SETGID 6u
#define EDGE_LINUX_CAP_SETUID 7u
#define EDGE_LINUX_CAP_SETPCAP 8u
#define EDGE_LINUX_CAP_LINUX_IMMUTABLE 9u
#define EDGE_LINUX_CAP_NET_ADMIN 12u
#define EDGE_LINUX_CAP_IPC_OWNER 15u
#define EDGE_LINUX_CAP_SYS_RAWIO 17u
#define EDGE_LINUX_CAP_SYS_CHROOT 18u
#define EDGE_LINUX_CAP_SYS_PTRACE 19u
#define EDGE_LINUX_CAP_SYS_PACCT 20u
#define EDGE_LINUX_CAP_SYS_ADMIN 21u
#define EDGE_LINUX_CAP_SYS_BOOT 22u
#define EDGE_LINUX_CAP_SYS_NICE 23u
#define EDGE_LINUX_CAP_SYS_RESOURCE 24u
#define EDGE_LINUX_CAP_SYS_TIME 25u
#define EDGE_LINUX_CAP_SYS_TTY_CONFIG 26u
#define EDGE_LINUX_CAP_SYS_MODULE 16u
#define EDGE_LINUX_CAP_MKNOD 27u
#define EDGE_LINUX_CAP_SETFCAP 31u
#define EDGE_LINUX_CAP_MAC_OVERRIDE 32u
#define EDGE_LINUX_CAP_SYSLOG 34u
#define EDGE_LINUX_CAP_WAKE_ALARM 35u
#define EDGE_LINUX_CAP_PERFMON 38u
#define EDGE_LINUX_CAP_LAST_CAP 40u
#define EDGE_LINUX_CAP_FULL_SET ((1ULL << (EDGE_LINUX_CAP_LAST_CAP + 1u)) - 1ULL)

#define EDGE_LINUX_SECBIT_NOROOT 0x01u
#define EDGE_LINUX_SECBIT_NOROOT_LOCKED 0x02u
#define EDGE_LINUX_SECBIT_NO_SETUID_FIXUP 0x04u
#define EDGE_LINUX_SECBIT_NO_SETUID_FIXUP_LOCKED 0x08u
#define EDGE_LINUX_SECBIT_KEEP_CAPS 0x10u
#define EDGE_LINUX_SECBIT_KEEP_CAPS_LOCKED 0x20u
#define EDGE_LINUX_SECBIT_NO_CAP_AMBIENT_RAISE 0x40u
#define EDGE_LINUX_SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED 0x80u
#define EDGE_LINUX_SECUREBITS_VALID_MASK 0xffu

#define EDGE_LINUX_PR_GET_KEEPCAPS 7u
#define EDGE_LINUX_PR_SET_KEEPCAPS 8u
#define EDGE_LINUX_PR_CAPBSET_READ 23u
#define EDGE_LINUX_PR_CAPBSET_DROP 24u
#define EDGE_LINUX_PR_GET_SECUREBITS 27u
#define EDGE_LINUX_PR_SET_SECUREBITS 28u
#define EDGE_LINUX_PR_CAP_AMBIENT 47u
#define EDGE_LINUX_PR_CAP_AMBIENT_IS_SET 1u
#define EDGE_LINUX_PR_CAP_AMBIENT_RAISE 2u
#define EDGE_LINUX_PR_CAP_AMBIENT_LOWER 3u
#define EDGE_LINUX_PR_CAP_AMBIENT_CLEAR_ALL 4u

typedef struct linux_capability_state {
    uint64_t permitted;
    uint64_t effective;
    uint64_t inheritable;
    uint64_t bounding;
    uint64_t ambient;
    uint32_t securebits;
} linux_capability_state_t;

typedef struct linux_credential_state {
    uint32_t uid;
    uint32_t euid;
    uint32_t suid;
    uint32_t fsuid;
    uint32_t gid;
    uint32_t egid;
    uint32_t sgid;
    uint32_t fsgid;
    linux_capability_state_t capabilities;
} linux_credential_state_t;

enum {
    LINUX_CAP_PRCTL_OK = 0,
    LINUX_CAP_PRCTL_UNHANDLED = 1,
    LINUX_CAP_PRCTL_INVALID = -1,
    LINUX_CAP_PRCTL_PERMISSION = -2,
};

enum {
    LINUX_CREDENTIAL_OK = 0,
    LINUX_CREDENTIAL_INVALID = -1,
    LINUX_CREDENTIAL_PERMISSION = -2,
};

/*
 * Apply Linux setreuid(2)/setregid(2) rules to one real/effective/saved ID
 * tuple. UINT32_MAX represents the ABI value -1 (leave unchanged).
 */
int linux_credentials_setreid(uint32_t *real_id, uint32_t *effective_id,
                              uint32_t *saved_id, uint32_t *filesystem_id,
                              uint32_t requested_real,
                              uint32_t requested_effective,
                              int privileged);

int linux_credentials_setuid(linux_credential_state_t *credentials,
                             uint32_t uid);
int linux_credentials_setgid(linux_credential_state_t *credentials,
                             uint32_t gid);
int linux_credentials_setreuid(linux_credential_state_t *credentials,
                               uint32_t ruid, uint32_t euid);
int linux_credentials_setregid(linux_credential_state_t *credentials,
                               uint32_t rgid, uint32_t egid);
int linux_credentials_setresuid(linux_credential_state_t *credentials,
                                uint32_t ruid, uint32_t euid,
                                uint32_t suid);
int linux_credentials_setresgid(linux_credential_state_t *credentials,
                                uint32_t rgid, uint32_t egid,
                                uint32_t sgid);
uint32_t linux_credentials_setfsuid(linux_credential_state_t *credentials,
                                    uint32_t fsuid);
uint32_t linux_credentials_setfsgid(linux_credential_state_t *credentials,
                                    uint32_t fsgid);

void linux_capabilities_init_root(linux_capability_state_t *state);
void linux_capabilities_copy(linux_capability_state_t *destination,
                             const linux_capability_state_t *source);
void linux_capabilities_apply_uid_transition(
    linux_capability_state_t *state,
    uint32_t old_real, uint32_t old_effective, uint32_t old_saved,
    uint32_t new_real, uint32_t new_effective, uint32_t new_saved);
void linux_capabilities_apply_fsuid_transition(
    linux_capability_state_t *state, uint32_t old_fsuid,
    uint32_t new_fsuid);
int linux_capabilities_prctl(linux_capability_state_t *state,
                             uint32_t option, uint64_t argument2,
                             uint64_t argument3, uint64_t argument4,
                             uint64_t argument5, int can_setpcap,
                             int64_t *result);

#endif
