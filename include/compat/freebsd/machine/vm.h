/* SPDX-License-Identifier: MPL-2.0 */
/* Shared memory-attribute identifiers for the BSD driver bridge. */

#ifndef _MACHINE_VM_H_
#define _MACHINE_VM_H_

#define VM_MEMATTR_UNCACHEABLE 0
#define VM_MEMATTR_WRITE_COMBINING 1
#define VM_MEMATTR_WRITE_THROUGH 2
#define VM_MEMATTR_WRITE_PROTECTED 3
#define VM_MEMATTR_WRITE_BACK 4
#define VM_MEMATTR_WEAK_UNCACHEABLE 5
#define VM_MEMATTR_DEVICE 6
#define VM_MEMATTR_DEVICE_NP 7
#define VM_MEMATTR_TAGGED 8
#define VM_MEMATTR_END 9

#define VM_MEMATTR_DEFAULT VM_MEMATTR_WRITE_BACK

#endif
