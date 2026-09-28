/* SPDX-License-Identifier: MPL-2.0 */
/* Shared kernel-worker services for the EdgeOS BSD Driver Bridge. */

#ifndef EDGEOS_COMPAT_FREEBSD_KTHREAD_H
#define EDGEOS_COMPAT_FREEBSD_KTHREAD_H

#include <stdint.h>

struct thread;
struct mtx;

int bsd_kthread_runtime_initialize(void);
int bsd_kthread_runtime_is_initialized(void);
void bsd_kthread_pump(void);

void *bsd_kthread_current_token(void);
struct thread *bsd_kthread_current_public(void);
uint32_t bsd_kthread_current_cpu_id(void);
struct thread *bsd_kthread_public_context_enter(struct thread *thread);
void bsd_kthread_public_context_leave(struct thread *previous);
void bsd_kthread_critical_enter(void);
void bsd_kthread_critical_exit(void);
void bsd_kthread_sleeping_forbid(void);
void bsd_kthread_sleeping_allow(void);
int bsd_kthread_token_valid(void *token);
int bsd_kthread_token_can_block(void *token);
void bsd_kthread_token_prepare_block(void *token);
void bsd_kthread_token_block_current(void *token);
void bsd_kthread_token_make_runnable(void *token);
int bsd_kthread_join(struct thread *thread);

int bsd_kthread_sleep(const void *channel, struct mtx *mutex,
    int priority, int timeout_ticks);
uint64_t bsd_kthread_wakeup_generation(const void *channel);
int bsd_kthread_sleep_generation(const void *channel,
    uint64_t generation, int timeout_ticks);
void bsd_kthread_wakeup(const void *channel, int one);

#endif
