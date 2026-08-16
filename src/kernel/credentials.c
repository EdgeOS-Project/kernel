/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux credential transition helpers.
 * Copyright (c) EdgeOS Contributors.
 */

#include "kernel/credentials.h"
#include "kernel/process_runtime.h"

static uint64_t linux_capability_mask(uint64_t value) {
    return value & EDGE_LINUX_CAP_FULL_SET;
}

void linux_capabilities_init_root(linux_capability_state_t *state) {
    if (!state) return;
    state->permitted = EDGE_LINUX_CAP_FULL_SET;
    state->effective = EDGE_LINUX_CAP_FULL_SET;
    state->inheritable = 0;
    state->bounding = EDGE_LINUX_CAP_FULL_SET;
    state->ambient = 0;
    state->securebits = 0;
}

void linux_capabilities_copy(linux_capability_state_t *destination,
                             const linux_capability_state_t *source) {
    if (!destination || !source) return;
    *destination = *source;
    destination->permitted = linux_capability_mask(destination->permitted);
    destination->effective &= destination->permitted;
    destination->inheritable = linux_capability_mask(destination->inheritable);
    destination->bounding = linux_capability_mask(destination->bounding);
    destination->ambient &= destination->permitted & destination->inheritable;
    destination->securebits &= EDGE_LINUX_SECUREBITS_VALID_MASK;
}

void linux_capabilities_apply_uid_transition(
    linux_capability_state_t *state,
    uint32_t old_real, uint32_t old_effective, uint32_t old_saved,
    uint32_t new_real, uint32_t new_effective, uint32_t new_saved) {
    int old_had_root;
    int new_has_no_root;

    if (!state) return;
    state->permitted = linux_capability_mask(state->permitted);
    state->inheritable = linux_capability_mask(state->inheritable);
    state->bounding = linux_capability_mask(state->bounding);
    if (state->securebits & EDGE_LINUX_SECBIT_NO_SETUID_FIXUP) {
        state->effective &= state->permitted;
        state->ambient &= state->permitted & state->inheritable;
        return;
    }

    old_had_root = old_real == 0 || old_effective == 0 || old_saved == 0;
    new_has_no_root = new_real != 0 && new_effective != 0 && new_saved != 0;
    if (old_had_root && new_has_no_root) {
        if (!(state->securebits & EDGE_LINUX_SECBIT_KEEP_CAPS))
            state->permitted = 0;
        state->effective = 0;
        state->ambient = 0;
    } else if (old_effective == 0 && new_effective != 0) {
        state->effective = 0;
        state->ambient = 0;
    } else if (old_effective != 0 && new_effective == 0 &&
               !(state->securebits & EDGE_LINUX_SECBIT_NOROOT)) {
        state->effective = state->permitted;
    } else {
        state->effective &= state->permitted;
    }
    state->ambient &= state->permitted & state->inheritable;
}

void linux_capabilities_apply_fsuid_transition(
    linux_capability_state_t *state, uint32_t old_fsuid,
    uint32_t new_fsuid) {
    const uint64_t filesystem_capabilities =
        (1ULL << EDGE_LINUX_CAP_CHOWN) |
        (1ULL << EDGE_LINUX_CAP_DAC_OVERRIDE) |
        (1ULL << EDGE_LINUX_CAP_DAC_READ_SEARCH) |
        (1ULL << EDGE_LINUX_CAP_FOWNER) |
        (1ULL << EDGE_LINUX_CAP_FSETID) |
        (1ULL << EDGE_LINUX_CAP_LINUX_IMMUTABLE) |
        (1ULL << EDGE_LINUX_CAP_MKNOD) |
        (1ULL << EDGE_LINUX_CAP_MAC_OVERRIDE);
    if (!state || old_fsuid == new_fsuid ||
        (state->securebits & EDGE_LINUX_SECBIT_NO_SETUID_FIXUP))
        return;
    if (old_fsuid == 0 && new_fsuid != 0) {
        state->effective &= ~filesystem_capabilities;
    } else if (old_fsuid != 0 && new_fsuid == 0) {
        state->effective |= state->permitted & filesystem_capabilities;
    }
    state->effective &= state->permitted;
    state->ambient &= state->permitted & state->inheritable;
}

static int linux_securebits_change_allowed(uint32_t current,
                                           uint32_t requested) {
    static const uint32_t value_bits[] = {
        EDGE_LINUX_SECBIT_NOROOT,
        EDGE_LINUX_SECBIT_NO_SETUID_FIXUP,
        EDGE_LINUX_SECBIT_KEEP_CAPS,
        EDGE_LINUX_SECBIT_NO_CAP_AMBIENT_RAISE,
    };
    static const uint32_t lock_bits[] = {
        EDGE_LINUX_SECBIT_NOROOT_LOCKED,
        EDGE_LINUX_SECBIT_NO_SETUID_FIXUP_LOCKED,
        EDGE_LINUX_SECBIT_KEEP_CAPS_LOCKED,
        EDGE_LINUX_SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED,
    };
    uint32_t index;

    for (index = 0; index < sizeof(value_bits) / sizeof(value_bits[0]); ++index) {
        if (!(current & lock_bits[index])) continue;
        if (!(requested & lock_bits[index]) ||
            ((current ^ requested) & value_bits[index]))
            return 0;
    }
    return 1;
}

int linux_capabilities_prctl(linux_capability_state_t *state,
                             uint32_t option, uint64_t argument2,
                             uint64_t argument3, uint64_t argument4,
                             uint64_t argument5, int can_setpcap,
                             int64_t *result) {
    uint64_t bit;
    uint32_t requested;

    if (!state || !result) return LINUX_CAP_PRCTL_INVALID;
    *result = 0;
    switch (option) {
        case EDGE_LINUX_PR_GET_KEEPCAPS:
            /* The Linux kernel does not consume the variadic tail here. */
            *result = (state->securebits & EDGE_LINUX_SECBIT_KEEP_CAPS) ? 1 : 0;
            return LINUX_CAP_PRCTL_OK;
        case EDGE_LINUX_PR_SET_KEEPCAPS:
            /* Linux consumes only arg2; variadic libc leaves tail registers. */
            if (argument2 > 1)
                return LINUX_CAP_PRCTL_INVALID;
            requested = state->securebits;
            if (argument2) requested |= EDGE_LINUX_SECBIT_KEEP_CAPS;
            else requested &= ~EDGE_LINUX_SECBIT_KEEP_CAPS;
            if (!linux_securebits_change_allowed(state->securebits, requested))
                return LINUX_CAP_PRCTL_PERMISSION;
            state->securebits = requested;
            return LINUX_CAP_PRCTL_OK;
        case EDGE_LINUX_PR_CAPBSET_READ:
            /* Linux consumes only the capability number for this command. */
            if (argument2 > EDGE_LINUX_CAP_LAST_CAP)
                return LINUX_CAP_PRCTL_INVALID;
            *result = (int64_t)((state->bounding >> argument2) & 1u);
            return LINUX_CAP_PRCTL_OK;
        case EDGE_LINUX_PR_CAPBSET_DROP:
            /* Variadic callers are not required to clear unused registers. */
            if (argument2 > EDGE_LINUX_CAP_LAST_CAP)
                return LINUX_CAP_PRCTL_INVALID;
            if (!can_setpcap) return LINUX_CAP_PRCTL_PERMISSION;
            state->bounding &= ~(1ULL << argument2);
            return LINUX_CAP_PRCTL_OK;
        case EDGE_LINUX_PR_GET_SECUREBITS:
            /* Callers commonly omit all variadic arguments for this query. */
            *result = state->securebits;
            return LINUX_CAP_PRCTL_OK;
        case EDGE_LINUX_PR_SET_SECUREBITS:
            /*
             * Linux consumes only arg2 for PR_SET_SECUREBITS.  The prctl ABI
             * does not require callers to clear the remaining argument
             * registers, and libc callers may leave arbitrary values there.
             */
            if (argument2 & ~EDGE_LINUX_SECUREBITS_VALID_MASK)
                return LINUX_CAP_PRCTL_INVALID;
            if (!can_setpcap) return LINUX_CAP_PRCTL_PERMISSION;
            requested = (uint32_t)argument2;
            if (!linux_securebits_change_allowed(state->securebits, requested))
                return LINUX_CAP_PRCTL_PERMISSION;
            state->securebits = requested;
            return LINUX_CAP_PRCTL_OK;
        case EDGE_LINUX_PR_CAP_AMBIENT:
            if (argument4 || argument5)
                return LINUX_CAP_PRCTL_INVALID;
            if (argument2 == EDGE_LINUX_PR_CAP_AMBIENT_CLEAR_ALL) {
                if (argument3) return LINUX_CAP_PRCTL_INVALID;
                state->ambient = 0;
                return LINUX_CAP_PRCTL_OK;
            }
            if (argument3 > EDGE_LINUX_CAP_LAST_CAP)
                return LINUX_CAP_PRCTL_INVALID;
            bit = 1ULL << argument3;
            if (argument2 == EDGE_LINUX_PR_CAP_AMBIENT_IS_SET) {
                *result = (state->ambient & bit) ? 1 : 0;
                return LINUX_CAP_PRCTL_OK;
            }
            if (argument2 == EDGE_LINUX_PR_CAP_AMBIENT_LOWER) {
                state->ambient &= ~bit;
                return LINUX_CAP_PRCTL_OK;
            }
            if (argument2 != EDGE_LINUX_PR_CAP_AMBIENT_RAISE)
                return LINUX_CAP_PRCTL_INVALID;
            if ((state->securebits & EDGE_LINUX_SECBIT_NO_CAP_AMBIENT_RAISE) ||
                !(state->permitted & bit) || !(state->inheritable & bit))
                return LINUX_CAP_PRCTL_PERMISSION;
            state->ambient |= bit;
            return LINUX_CAP_PRCTL_OK;
        default:
            return LINUX_CAP_PRCTL_UNHANDLED;
    }
}

int linux_credentials_setreid(uint32_t *real_id, uint32_t *effective_id,
                              uint32_t *saved_id, uint32_t *filesystem_id,
                              uint32_t requested_real,
                              uint32_t requested_effective,
                              int privileged) {
    uint32_t old_real;
    uint32_t old_effective;
    uint32_t old_saved;
    uint32_t new_real;
    uint32_t new_effective;
    uint32_t new_saved;

    if (!real_id || !effective_id || !saved_id || !filesystem_id) return -1;
    old_real = *real_id;
    old_effective = *effective_id;
    old_saved = *saved_id;

    if (!privileged) {
        if (requested_real != UINT32_MAX && requested_real != old_real &&
            requested_real != old_effective)
            return -1;
        if (requested_effective != UINT32_MAX &&
            requested_effective != old_real &&
            requested_effective != old_effective &&
            requested_effective != old_saved)
            return -1;
    }

    new_real = requested_real == UINT32_MAX ? old_real : requested_real;
    new_effective = requested_effective == UINT32_MAX ?
                    old_effective : requested_effective;
    new_saved = old_saved;
    if (requested_real != UINT32_MAX ||
        (requested_effective != UINT32_MAX &&
         requested_effective != old_real))
        new_saved = new_effective;

    *real_id = new_real;
    *effective_id = new_effective;
    *saved_id = new_saved;
    if (requested_effective != UINT32_MAX)
        *filesystem_id = new_effective;
    return 0;
}

static int linux_credentials_has_capability(
    const linux_credential_state_t *credentials, uint32_t capability) {
    return credentials && capability <= EDGE_LINUX_CAP_LAST_CAP &&
           (credentials->capabilities.effective &
            (1ULL << capability)) != 0;
}

static void linux_credentials_finish_uid_transition(
    linux_credential_state_t *credentials, uint32_t old_uid,
    uint32_t old_euid, uint32_t old_suid) {
    linux_capabilities_apply_uid_transition(
        &credentials->capabilities, old_uid, old_euid, old_suid,
        credentials->uid, credentials->euid, credentials->suid);
}

int linux_credentials_setuid(linux_credential_state_t *credentials,
                             uint32_t uid) {
    uint32_t old_uid;
    uint32_t old_euid;
    uint32_t old_suid;
    if (!credentials || uid == UINT32_MAX)
        return LINUX_CREDENTIAL_INVALID;
    old_uid = credentials->uid;
    old_euid = credentials->euid;
    old_suid = credentials->suid;
    if (linux_credentials_has_capability(credentials,
                                         EDGE_LINUX_CAP_SETUID)) {
        credentials->uid = uid;
        credentials->euid = uid;
        credentials->suid = uid;
    } else {
        if (uid != credentials->uid && uid != credentials->suid)
            return LINUX_CREDENTIAL_PERMISSION;
        credentials->euid = uid;
    }
    credentials->fsuid = credentials->euid;
    linux_credentials_finish_uid_transition(credentials, old_uid, old_euid,
                                            old_suid);
    return LINUX_CREDENTIAL_OK;
}

int linux_credentials_setgid(linux_credential_state_t *credentials,
                             uint32_t gid) {
    if (!credentials || gid == UINT32_MAX)
        return LINUX_CREDENTIAL_INVALID;
    if (linux_credentials_has_capability(credentials,
                                         EDGE_LINUX_CAP_SETGID)) {
        credentials->gid = gid;
        credentials->egid = gid;
        credentials->sgid = gid;
    } else {
        if (gid != credentials->gid && gid != credentials->sgid)
            return LINUX_CREDENTIAL_PERMISSION;
        credentials->egid = gid;
    }
    credentials->fsgid = credentials->egid;
    return LINUX_CREDENTIAL_OK;
}

int linux_credentials_setreuid(linux_credential_state_t *credentials,
                               uint32_t ruid, uint32_t euid) {
    uint32_t old_uid;
    uint32_t old_euid;
    uint32_t old_suid;
    int result;
    if (!credentials) return LINUX_CREDENTIAL_INVALID;
    old_uid = credentials->uid;
    old_euid = credentials->euid;
    old_suid = credentials->suid;
    result = linux_credentials_setreid(
        &credentials->uid, &credentials->euid, &credentials->suid,
        &credentials->fsuid, ruid, euid,
        linux_credentials_has_capability(credentials,
                                         EDGE_LINUX_CAP_SETUID));
    if (result < 0) return LINUX_CREDENTIAL_PERMISSION;
    linux_credentials_finish_uid_transition(credentials, old_uid, old_euid,
                                            old_suid);
    return LINUX_CREDENTIAL_OK;
}

int linux_credentials_setregid(linux_credential_state_t *credentials,
                               uint32_t rgid, uint32_t egid) {
    if (!credentials) return LINUX_CREDENTIAL_INVALID;
    return linux_credentials_setreid(
               &credentials->gid, &credentials->egid, &credentials->sgid,
               &credentials->fsgid, rgid, egid,
               linux_credentials_has_capability(
                   credentials, EDGE_LINUX_CAP_SETGID)) < 0 ?
        LINUX_CREDENTIAL_PERMISSION : LINUX_CREDENTIAL_OK;
}

static int linux_credentials_res_ids_allowed(
    uint32_t requested_real, uint32_t requested_effective,
    uint32_t requested_saved, uint32_t real_id, uint32_t effective_id,
    uint32_t saved_id, int privileged) {
    const uint32_t requested[3] = {
        requested_real, requested_effective, requested_saved,
    };
    uint32_t index;
    if (privileged) return 1;
    for (index = 0; index < 3u; ++index) {
        uint32_t id = requested[index];
        if (id == UINT32_MAX) continue;
        if (id != real_id && id != effective_id && id != saved_id)
            return 0;
    }
    return 1;
}

int linux_credentials_setresuid(linux_credential_state_t *credentials,
                                uint32_t ruid, uint32_t euid,
                                uint32_t suid) {
    uint32_t old_uid;
    uint32_t old_euid;
    uint32_t old_suid;
    if (!credentials) return LINUX_CREDENTIAL_INVALID;
    old_uid = credentials->uid;
    old_euid = credentials->euid;
    old_suid = credentials->suid;
    if (!linux_credentials_res_ids_allowed(
            ruid, euid, suid, old_uid, old_euid, old_suid,
            linux_credentials_has_capability(credentials,
                                             EDGE_LINUX_CAP_SETUID)))
        return LINUX_CREDENTIAL_PERMISSION;
    if (ruid != UINT32_MAX) credentials->uid = ruid;
    if (euid != UINT32_MAX) {
        credentials->euid = euid;
        credentials->fsuid = euid;
    }
    if (suid != UINT32_MAX) credentials->suid = suid;
    linux_credentials_finish_uid_transition(credentials, old_uid, old_euid,
                                            old_suid);
    return LINUX_CREDENTIAL_OK;
}

int linux_credentials_setresgid(linux_credential_state_t *credentials,
                                uint32_t rgid, uint32_t egid,
                                uint32_t sgid) {
    if (!credentials) return LINUX_CREDENTIAL_INVALID;
    if (!linux_credentials_res_ids_allowed(
            rgid, egid, sgid, credentials->gid, credentials->egid,
            credentials->sgid,
            linux_credentials_has_capability(credentials,
                                             EDGE_LINUX_CAP_SETGID)))
        return LINUX_CREDENTIAL_PERMISSION;
    if (rgid != UINT32_MAX) credentials->gid = rgid;
    if (egid != UINT32_MAX) {
        credentials->egid = egid;
        credentials->fsgid = egid;
    }
    if (sgid != UINT32_MAX) credentials->sgid = sgid;
    return LINUX_CREDENTIAL_OK;
}

uint32_t linux_credentials_setfsuid(linux_credential_state_t *credentials,
                                    uint32_t fsuid) {
    uint32_t previous;
    if (!credentials) return UINT32_MAX;
    previous = credentials->fsuid;
    if (fsuid == UINT32_MAX) return previous;
    if (linux_credentials_has_capability(credentials,
                                         EDGE_LINUX_CAP_SETUID) ||
        fsuid == credentials->uid || fsuid == credentials->euid ||
        fsuid == credentials->suid || fsuid == credentials->fsuid) {
        credentials->fsuid = fsuid;
        linux_capabilities_apply_fsuid_transition(
            &credentials->capabilities, previous, fsuid);
    }
    return previous;
}

uint32_t linux_credentials_setfsgid(linux_credential_state_t *credentials,
                                    uint32_t fsgid) {
    uint32_t previous;
    if (!credentials) return UINT32_MAX;
    previous = credentials->fsgid;
    if (fsgid == UINT32_MAX) return previous;
    if (linux_credentials_has_capability(credentials,
                                         EDGE_LINUX_CAP_SETGID) ||
        fsgid == credentials->gid || fsgid == credentials->egid ||
        fsgid == credentials->sgid || fsgid == credentials->fsgid)
        credentials->fsgid = fsgid;
    return previous;
}

int kernel_process_credentials_get(
    int32_t tid, linux_credential_state_t *credentials) {
    kernel_proc_task_view_t view;
    if (!credentials || tid <= 0) return -1;
    if (kernel_proc_task_view_get(tid, &view) < 0 ||
        view.state == KERNEL_PROC_TASK_ZOMBIE)
        return -1;
    credentials->uid = view.uid;
    credentials->euid = view.euid;
    credentials->suid = view.suid;
    credentials->fsuid = view.fsuid;
    credentials->gid = view.gid;
    credentials->egid = view.egid;
    credentials->sgid = view.sgid;
    credentials->fsgid = view.fsgid;
    linux_capabilities_copy(&credentials->capabilities,
                            &view.capabilities);
    return 0;
}

int kernel_process_capabilities_get(int32_t tid,
                                    linux_capability_state_t *capabilities) {
    linux_credential_state_t credentials;
    if (!capabilities ||
        kernel_process_credentials_get(tid, &credentials) < 0)
        return -1;
    linux_capabilities_copy(capabilities, &credentials.capabilities);
    return 0;
}

int kernel_current_credentials_get(linux_credential_state_t *credentials) {
    kernel_linux_identity_t identity;
    if (!credentials || kernel_current_linux_identity(&identity) < 0)
        return -1;
    return kernel_process_credentials_get(identity.global_tid, credentials);
}

int kernel_current_credentials_set(
    const linux_credential_state_t *credentials) {
    linux_credential_state_t current;
    int clear_parent_death_signal;

    if (!credentials || kernel_current_credentials_get(&current) < 0)
        return -1;
    clear_parent_death_signal =
        current.euid != credentials->euid ||
        current.egid != credentials->egid ||
        current.fsuid != credentials->fsuid ||
        current.fsgid != credentials->fsgid;
    return kernel_arch_current_credentials_commit(
        credentials, clear_parent_death_signal);
}

int kernel_current_capabilities_set(
    const linux_capability_state_t *capabilities) {
    linux_credential_state_t credentials;
    if (!capabilities || kernel_current_credentials_get(&credentials) < 0)
        return -1;
    linux_capabilities_copy(&credentials.capabilities, capabilities);
    return kernel_current_credentials_set(&credentials);
}
