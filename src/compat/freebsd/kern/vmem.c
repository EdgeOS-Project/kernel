/* SPDX-License-Identifier: MPL-2.0 */
/* Linear address-space allocator used by imported FreeBSD drivers. */

#include <sys/errno.h>
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/sys/malloc.h"
#include "compat/freebsd/sys/mutex.h"
#include <sys/vmem.h>

struct bsd_vmem_extent {
    vmem_addr_t start;
    vmem_size_t size;
    struct bsd_vmem_extent *next;
};

struct bsd_vmem_imported_span {
    vmem_addr_t start;
    vmem_size_t size;
    struct bsd_vmem_imported_span *next;
};

struct vmem {
    const char *name;
    vmem_size_t quantum;
    vmem_size_t limit;
    vmem_size_t total;
    vmem_addr_t next_fit;
    vmem_import_t *importfn;
    vmem_release_t *releasefn;
    vmem_reclaim_t *reclaimfn;
    void *import_arg;
    vmem_size_t import_quantum;
    struct bsd_vmem_extent *free_extents;
    struct bsd_vmem_imported_span *imported_spans;
    struct mtx lock;
    int heap_owned;
};

static vmem_size_t
bsd_vmem_round_up(vmem_size_t value, vmem_size_t quantum)
{
    vmem_size_t remainder;

    if (quantum <= 1)
        return value;
    remainder = value % quantum;
    if (remainder == 0)
        return value;
    if (value > VMEM_ADDR_MAX - (quantum - remainder))
        return 0;
    return value + quantum - remainder;
}

static int
bsd_vmem_insert_locked(vmem_t *vm, vmem_addr_t address, vmem_size_t size,
    int flags)
{
    struct bsd_vmem_extent **cursor;
    struct bsd_vmem_extent *extent;

    if (size == 0 || address > VMEM_ADDR_MAX - (size - 1))
        return EINVAL;
    extent = malloc(sizeof(*extent), M_TEMP,
        (flags & M_NOWAIT) ? M_NOWAIT : M_WAITOK);
    if (!extent)
        return ENOMEM;
    extent->start = address;
    extent->size = size;
    extent->next = NULL;

    cursor = &vm->free_extents;
    while (*cursor && (*cursor)->start < address)
        cursor = &(*cursor)->next;
    if (*cursor && address + size > (*cursor)->start) {
        free(extent, M_TEMP);
        return EEXIST;
    }
    if (cursor != &vm->free_extents) {
        struct bsd_vmem_extent *previous = vm->free_extents;

        while (previous->next != *cursor)
            previous = previous->next;
        if (previous->start + previous->size > address) {
            free(extent, M_TEMP);
            return EEXIST;
        }
        if (previous->start + previous->size == address) {
            previous->size += size;
            if (*cursor && previous->start + previous->size ==
                (*cursor)->start) {
                struct bsd_vmem_extent *merged = *cursor;

                previous->size += merged->size;
                previous->next = merged->next;
                free(merged, M_TEMP);
            }
            return 0;
        }
    }
    if (*cursor && address + size == (*cursor)->start) {
        (*cursor)->start = address;
        (*cursor)->size += size;
        free(extent, M_TEMP);
        return 0;
    }
    extent->next = *cursor;
    *cursor = extent;
    return 0;
}

vmem_t *
vmem_init(vmem_t *vm, const char *name, vmem_addr_t base,
    vmem_size_t size, vmem_size_t quantum, vmem_size_t qcache_max, int flags)
{
    (void)qcache_max;
    if (!vm || quantum == 0)
        return NULL;
    bsd_memset(vm, 0, sizeof(*vm));
    vm->name = name;
    vm->quantum = quantum;
    vm->limit = VMEM_ADDR_MAX;
    mtx_init(&vm->lock, name ? name : "vmem", NULL, MTX_DEF);
    if (size != 0) {
        mtx_lock(&vm->lock);
        if (bsd_vmem_insert_locked(vm, base, size, flags) != 0) {
            mtx_unlock(&vm->lock);
            mtx_destroy(&vm->lock);
            return NULL;
        }
        vm->total = size;
        mtx_unlock(&vm->lock);
    }
    return vm;
}

vmem_t *
vmem_create(const char *name, vmem_addr_t base, vmem_size_t size,
    vmem_size_t quantum, vmem_size_t qcache_max, int flags)
{
    vmem_t *vm;

    vm = malloc(sizeof(*vm), M_TEMP,
        (flags & M_NOWAIT) ? M_NOWAIT : M_WAITOK);
    if (!vm)
        return NULL;
    if (!vmem_init(vm, name, base, size, quantum, qcache_max, flags)) {
        free(vm, M_TEMP);
        return NULL;
    }
    vm->heap_owned = 1;
    return vm;
}

void
vmem_destroy(vmem_t *vm)
{
    struct bsd_vmem_extent *extent;
    struct bsd_vmem_imported_span *imported;
    vmem_release_t *releasefn;
    void *import_arg;
    int heap_owned;

    if (!vm)
        return;
    mtx_lock(&vm->lock);
    extent = vm->free_extents;
    vm->free_extents = NULL;
    imported = vm->imported_spans;
    vm->imported_spans = NULL;
    releasefn = vm->releasefn;
    import_arg = vm->import_arg;
    heap_owned = vm->heap_owned;
    mtx_unlock(&vm->lock);
    while (extent) {
        struct bsd_vmem_extent *next = extent->next;

        free(extent, M_TEMP);
        extent = next;
    }
    while (imported) {
        struct bsd_vmem_imported_span *next = imported->next;

        if (releasefn)
            releasefn(import_arg, imported->start, imported->size);
        free(imported, M_TEMP);
        imported = next;
    }
    mtx_destroy(&vm->lock);
    if (heap_owned)
        free(vm, M_TEMP);
}

void
vmem_set_import(vmem_t *vm, vmem_import_t *importfn,
    vmem_release_t *releasefn, void *argument, vmem_size_t import_quantum)
{
    if (!vm)
        return;
    mtx_lock(&vm->lock);
    vm->importfn = importfn;
    vm->releasefn = releasefn;
    vm->import_arg = argument;
    vm->import_quantum = import_quantum;
    mtx_unlock(&vm->lock);
}

void
vmem_set_limit(vmem_t *vm, vmem_size_t limit)
{
    if (!vm)
        return;
    mtx_lock(&vm->lock);
    vm->limit = limit;
    mtx_unlock(&vm->lock);
}

void
vmem_set_reclaim(vmem_t *vm, vmem_reclaim_t *reclaimfn)
{
    if (!vm)
        return;
    mtx_lock(&vm->lock);
    vm->reclaimfn = reclaimfn;
    mtx_unlock(&vm->lock);
}

static int
bsd_vmem_candidate(const struct bsd_vmem_extent *extent, vmem_size_t size,
    vmem_size_t align, vmem_size_t phase, vmem_size_t nocross,
    vmem_addr_t minaddr, vmem_addr_t maxaddr, vmem_addr_t *candidate)
{
    vmem_addr_t address = extent->start > minaddr ?
        extent->start : minaddr;
    vmem_addr_t end = extent->start + extent->size;
    vmem_size_t remainder;

    if (align == 0)
        align = 1;
    remainder = (address - phase) % align;
    if (remainder != 0) {
        if (address > VMEM_ADDR_MAX - (align - remainder))
            return ENOSPC;
        address += align - remainder;
    }
    if (nocross != 0 && size != 0 &&
        address / nocross != (address + size - 1) / nocross) {
        address = bsd_vmem_round_up(address, nocross);
        remainder = (address - phase) % align;
        if (remainder != 0)
            address += align - remainder;
    }
    if (size == 0 || address > maxaddr || address > VMEM_ADDR_MAX - size ||
        address + size > end)
        return ENOSPC;
    *candidate = address;
    return 0;
}

int
vmem_xalloc(vmem_t *vm, vmem_size_t size, vmem_size_t align,
    vmem_size_t phase, vmem_size_t nocross, vmem_addr_t minaddr,
    vmem_addr_t maxaddr, int flags, vmem_addr_t *addrp)
{
    struct bsd_vmem_extent *best;
    vmem_addr_t best_address;
    vmem_size_t best_waste;
    struct bsd_vmem_extent **cursor;
    int reclaimed = 0;
    int imported = 0;

    if (!vm || !addrp || size == 0 || (align != 0 && phase >= align))
        return EINVAL;
    size = bsd_vmem_round_up(size, vm->quantum);
    if (size == 0)
        return EINVAL;

retry:
    best = NULL;
    best_address = 0;
    best_waste = VMEM_ADDR_MAX;
    mtx_lock(&vm->lock);
    for (int pass = 0; pass < ((flags & M_NEXTFIT) ? 2 : 1); ++pass) {
        vmem_addr_t pass_min = minaddr;
        vmem_addr_t pass_max = maxaddr;

        if ((flags & M_NEXTFIT) != 0) {
            if (pass == 0) {
                if (vm->next_fit > pass_min)
                    pass_min = vm->next_fit;
            } else {
                if (vm->next_fit == 0)
                    break;
                if (pass_max >= vm->next_fit)
                    pass_max = vm->next_fit - 1u;
            }
            if (pass_min > pass_max)
                continue;
        }
        for (cursor = &vm->free_extents; *cursor;
            cursor = &(*cursor)->next) {
            vmem_addr_t address;
            vmem_size_t waste;

            if (bsd_vmem_candidate(*cursor, size, align, phase, nocross,
                pass_min, pass_max, &address) != 0)
                continue;
            waste = (*cursor)->size - size;
            if (!best || !(flags & M_BESTFIT) || waste < best_waste) {
                best = *cursor;
                best_address = address;
                best_waste = waste;
                if (!(flags & M_BESTFIT))
                    break;
            }
        }
        if (best)
            break;
    }
    if (!best) {
        vmem_reclaim_t *reclaimfn = vm->reclaimfn;
        vmem_import_t *importfn = vm->importfn;
        vmem_release_t *releasefn = vm->releasefn;
        void *import_arg = vm->import_arg;
        vmem_size_t import_size = size > vm->import_quantum ?
            size : vm->import_quantum;

        mtx_unlock(&vm->lock);
        if (!reclaimed && reclaimfn) {
            reclaimed = 1;
            reclaimfn(vm, flags);
            goto retry;
        }
        if (!imported && importfn) {
            struct bsd_vmem_imported_span *span;
            vmem_addr_t imported_address;
            int error;

            imported = 1;
            import_size = bsd_vmem_round_up(import_size, vm->quantum);
            if (import_size == 0)
                return EINVAL;
            error = importfn(import_arg, import_size, flags,
                &imported_address);
            if (error != 0)
                return error;
            span = malloc(sizeof(*span), M_TEMP,
                (flags & M_NOWAIT) ? M_NOWAIT : M_WAITOK);
            if (!span) {
                if (releasefn)
                    releasefn(import_arg, imported_address, import_size);
                return ENOMEM;
            }
            error = vmem_add(vm, imported_address, import_size, flags);
            if (error != 0) {
                if (releasefn)
                    releasefn(import_arg, imported_address, import_size);
                free(span, M_TEMP);
                return error;
            }
            span->start = imported_address;
            span->size = import_size;
            mtx_lock(&vm->lock);
            span->next = vm->imported_spans;
            vm->imported_spans = span;
            mtx_unlock(&vm->lock);
            goto retry;
        }
        return ENOSPC;
    }

    cursor = &vm->free_extents;
    while (*cursor != best)
        cursor = &(*cursor)->next;
    if (best_address != best->start &&
        best_address + size != best->start + best->size) {
        struct bsd_vmem_extent *suffix = malloc(sizeof(*suffix), M_TEMP,
            (flags & M_NOWAIT) ? M_NOWAIT : M_WAITOK);

        if (!suffix) {
            mtx_unlock(&vm->lock);
            return ENOMEM;
        }
        suffix->start = best_address + size;
        suffix->size = best->start + best->size - suffix->start;
        suffix->next = best->next;
        best->size = best_address - best->start;
        best->next = suffix;
    } else if (best_address == best->start) {
        best->start += size;
        best->size -= size;
        if (best->size == 0) {
            *cursor = best->next;
            free(best, M_TEMP);
        }
    } else {
        best->size -= size;
    }
    vm->next_fit = best_address + size;
    *addrp = best_address;
    mtx_unlock(&vm->lock);
    return 0;
}

int
vmem_alloc(vmem_t *vm, vmem_size_t size, int flags, vmem_addr_t *addrp)
{
    return vmem_xalloc(vm, size, vm ? vm->quantum : 1, 0, 0,
        VMEM_ADDR_MIN, VMEM_ADDR_MAX, flags, addrp);
}

void
vmem_xfree(vmem_t *vm, vmem_addr_t address, vmem_size_t size)
{
    int error;

    if (!vm || size == 0)
        return;
    size = bsd_vmem_round_up(size, vm->quantum);
    if (size == 0)
        bsd_panic("vmem_xfree size overflow");
    mtx_lock(&vm->lock);
    error = bsd_vmem_insert_locked(vm, address, size, M_WAITOK);
    mtx_unlock(&vm->lock);
    if (error != 0)
        bsd_panic("vmem_xfree invalid extent");
}

void
vmem_free(vmem_t *vm, vmem_addr_t address, vmem_size_t size)
{
    vmem_xfree(vm, address, size);
}

int
vmem_add(vmem_t *vm, vmem_addr_t address, vmem_size_t size, int flags)
{
    int error;

    if (!vm || size == 0)
        return EINVAL;
    mtx_lock(&vm->lock);
    if (size > vm->limit || vm->total > vm->limit - size) {
        mtx_unlock(&vm->lock);
        return ENOSPC;
    }
    error = bsd_vmem_insert_locked(vm, address, size, flags);
    if (error == 0)
        vm->total += size;
    mtx_unlock(&vm->lock);
    return error;
}

vmem_size_t
vmem_roundup_size(vmem_t *vm, vmem_size_t size)
{
    return vm ? bsd_vmem_round_up(size, vm->quantum) : 0;
}

vmem_size_t
vmem_size(vmem_t *vm, int typemask)
{
    struct bsd_vmem_extent *extent;
    vmem_size_t free_size = 0;
    vmem_size_t maximum = 0;
    vmem_size_t result;

    if (!vm)
        return 0;
    mtx_lock(&vm->lock);
    for (extent = vm->free_extents; extent; extent = extent->next) {
        free_size += extent->size;
        if (extent->size > maximum)
            maximum = extent->size;
    }
    if (typemask & VMEM_MAXFREE)
        result = maximum;
    else if ((typemask & VMEM_ALLOC) && !(typemask & VMEM_FREE))
        result = vm->total - free_size;
    else if ((typemask & VMEM_FREE) && !(typemask & VMEM_ALLOC))
        result = free_size;
    else
        result = vm->total;
    mtx_unlock(&vm->lock);
    return result;
}

void
vmem_whatis(vmem_addr_t address, int (*print)(const char *, ...))
{
    if (print)
        print("vmem address %#jx\n", (uintmax_t)address);
}

void
vmem_print(vmem_addr_t address, const char *prefix,
    int (*print)(const char *, ...))
{
    vmem_t *vm = (vmem_t *)(uintptr_t)address;

    if (print && vm)
        print("%s%s total=%ju free=%ju\n", prefix ? prefix : "",
            vm->name ? vm->name : "vmem", (uintmax_t)vm->total,
            (uintmax_t)vmem_size(vm, VMEM_FREE));
}

void
vmem_printall(const char *prefix, int (*print)(const char *, ...))
{
    if (print)
        print("%svmem registry active\n", prefix ? prefix : "");
}

void
vmem_startup(void)
{
}
