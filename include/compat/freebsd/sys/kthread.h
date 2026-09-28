/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * FreeBSD kernel-thread interface adapted to the EdgeOS shared worker
 * runtime. Driver source files can include this header unchanged.
 */

#ifndef _SYS_KTHREAD_H_
#define _SYS_KTHREAD_H_

#include <stddef.h>

#include <sys/cdefs.h>
#include <stdint.h>
#include "signal.h"
#ifdef BSD_BRIDGE_HOST_TEST
#include "../vm/vm_map.h"
#else
#include <vm/vm_map.h>
#endif

struct ucred {
	uint32_t cr_uid;
	uint32_t cr_ruid;
	uint32_t cr_svuid;
	uint32_t cr_gid;
	uint32_t cr_rgid;
	uint32_t cr_svgid;
	uint32_t cr_groups[16];
	int cr_ngroups;
	volatile uint32_t cr_ref;
};

struct trapframe;
struct pcb;
struct filedesc;
struct file;

struct syscall_args {
    int code;
    uintptr_t args[8];
};

#ifndef RFSTOPPED
#define RFSTOPPED (1 << 17)
#endif

#define TDP_EFIRT 0x00000001u
#define TDP_ITHREAD 0x00000002u
#define TDP_KTHREAD 0x00000004u
#define TDP_NOFAULTING 0x00000080u

#define P_WEXIT 0x00000001u

#ifndef THREAD0_TID
#define THREAD0_TID 100000
#endif

struct thread {
	uintptr_t td_edgeos_cookie;
	struct proc *td_proc;
	void *td_cdevpriv;
	void (*td_cdevpriv_dtr)(void *);
	volatile uint32_t td_lock;
	int td_priority;
	int td_tid;
	char td_name[32];
	int td_bound_cpu;
	int td_oncpu;
	int td_saved_cpu;
	int td_pin_saved_bound_cpu;
	unsigned int td_pinned;
	uint64_t td_affinity_mask;
	int td_critnest;
	int td_inhibitors;
	int td_no_sleeping;
	int td_ng_outbound;
	uint32_t td_pflags;
	sigset_t td_siglist;
	sigset_t td_sigmask;
	volatile uint32_t td_ast;
	volatile uint8_t td_owepreempt;
	void *td_lkpi_task;
	struct trapframe *td_intr_frame;
	struct pcb *td_pcb;
	uint8_t td_pcb_storage[4096] __attribute__((aligned(16)));
	unsigned int td_intr_nesting_level;
	uint32_t td_fpu_depth;
	uint8_t td_fpu_save[528] __attribute__((aligned(16)));
	uintptr_t td_retval[2];
	struct syscall_args td_sa;
	struct file *td_fpop;
	struct ucred *td_ucred;
	struct thread *td_proc_next;
};

int linux_alloc_current_noop(struct thread *thread, int flags);
extern int (*lkpi_alloc_current)(struct thread *thread, int flags);

enum {
	TDA_AST = 0,
	TDA_SCHED = 7,
};

#define TDAI(value) (1u << (value))
#define td_ast_pending(thread, value) (((thread)->td_ast & TDAI(value)) != 0)

struct proc {
	struct thread *p_edgeos_thread;
	uintptr_t p_edgeos_cookie;
	struct vmspace p_edgeos_vmspace;
	struct vmspace *p_vmspace;
	struct ucred p_ucred_storage;
	struct ucred *p_ucred;
	struct filedesc *p_fd;
	int p_pid;
	int p_pgid;
	volatile uint32_t p_lock;
	uint32_t p_flag;
	uint32_t p_flag2;
	sigset_t p_siglist;
	volatile uint32_t p_pending_signals;
	char p_comm[32];
};

struct kproc_desc {
	const char	*arg0;
	void		(*func)(void);
	struct proc	**global_procpp;
};

struct kthread_desc {
	const char	*arg0;
	void		(*func)(void);
	struct thread	**global_threadpp;
};

int	kproc_create(void (*)(void *), void *, struct proc **,
	    int flags, int pages, const char *, ...) __printflike(6, 7);
void	kproc_exit(int) __dead2;
int	kproc_resume(struct proc *);
void	kproc_shutdown(void *, int);
void	kproc_start(const void *);
int	kproc_suspend(struct proc *, int);
void	kproc_suspend_check(struct proc *);

int	kproc_kthread_add(void (*)(void *), void *, struct proc **,
	    struct thread **, int flags, int pages, const char *,
	    const char *, ...) __printflike(8, 9);
int	kthread_add(void (*)(void *), void *, struct proc *, struct thread **,
	    int flags, int pages, const char *, ...) __printflike(7, 8);
void	kthread_exit(void) __dead2;
int	kthread_resume(struct thread *);
void	kthread_shutdown(void *, int);
void	kthread_start(const void *);
int	kthread_suspend(struct thread *, int);
void	kthread_suspend_check(void);

void bsd_kthread_stack_usage(size_t *, size_t *);

#ifndef curthread
#define curthread bsd_kthread_current_public()
#endif

#endif
