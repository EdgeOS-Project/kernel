/* SPDX-License-Identifier: MPL-2.0 */

#ifndef _VM_VM_PAGEOUT_H_
#define _VM_VM_PAGEOUT_H_

#define PQ_INACTIVE 0
#define PQ_ACTIVE 1

unsigned int vm_free_count(void);

struct proc;
#define pageproc ((struct proc *)0)

#endif
