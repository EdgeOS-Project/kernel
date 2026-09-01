/* SPDX-License-Identifier: BSD-2-Clause */
/* Concurrency Kit pointer primitives required by the FreeBSD queue API. */

#ifndef EDGEOS_COMPAT_FREEBSD_CK_PR_H
#define EDGEOS_COMPAT_FREEBSD_CK_PR_H

static inline void *
ck_pr_load_ptr(const void *target)
{
    return __atomic_load_n((void *const *)target, __ATOMIC_ACQUIRE);
}

static inline void
ck_pr_store_ptr(void *target, const void *value)
{
    __atomic_store_n((void **)target, (void *)value, __ATOMIC_RELEASE);
}

static inline void
ck_pr_fence_store(void)
{
    __atomic_thread_fence(__ATOMIC_RELEASE);
}

#endif
