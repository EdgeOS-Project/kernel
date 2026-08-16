/* SPDX-License-Identifier: MPL-2.0 */
/*
 * ACPICA operating-system services backed by the shared BSD Driver Bridge.
 *
 * The imported ACPICA core remains unmodified. This file is the narrow
 * platform boundary for allocation, synchronization, scheduling, firmware
 * table mapping, PCI configuration, I/O, and interrupt delivery.
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <contrib/dev/acpica/include/acpi.h>

#include "compat/freebsd/edgeos/acpi_tables.h"
#include "compat/freebsd/edgeos/interrupt.h"
#include "compat/freebsd/edgeos/kthread.h"
#include "compat/freebsd/edgeos/malloc.h"
#include "compat/freebsd/edgeos/pci.h"
#include "compat/freebsd/edgeos/sleep.h"
#include "compat/freebsd/edgeos/systm.h"
#include "compat/freebsd/edgeos/taskqueue.h"
#include "sys/boottime.h"
#include "sys/spinlock.h"

#if defined(__x86_64__)
#include "sys/mmio.h"
#define BSD_ACPICA_X86_IRQ_BASE 0x20u
#endif

#define BSD_ACPICA_TASK_COUNT 64u
#define BSD_ACPICA_INTERRUPT_COUNT 8u

typedef struct bsd_acpica_semaphore {
    volatile unsigned int guard;
    uint32_t maximum;
    uint32_t units;
    uint32_t waiters;
    uint8_t deleting;
} bsd_acpica_semaphore_t;

typedef struct bsd_acpica_task {
    struct task task;
    ACPI_OSD_EXEC_CALLBACK callback;
    void *context;
    volatile uint8_t active;
} bsd_acpica_task_t;

typedef struct bsd_acpica_interrupt {
    ACPI_OSD_HANDLER handler;
    void *context;
    void *backend_cookie;
    uint32_t interrupt;
    uint8_t active;
} bsd_acpica_interrupt_t;

static bsd_acpica_task_t g_acpica_tasks[BSD_ACPICA_TASK_COUNT];
static bsd_acpica_interrupt_t
    g_acpica_interrupts[BSD_ACPICA_INTERRUPT_COUNT];
static volatile unsigned int g_acpica_task_guard;
static volatile unsigned int g_acpica_interrupt_guard;
static volatile uint32_t g_acpica_active_tasks;

static void
acpica_relax(void)
{
#if defined(__x86_64__)
    __asm__ __volatile__("pause");
#elif defined(__aarch64__)
    __asm__ __volatile__("yield");
#endif
}

static void
acpica_guard_lock(volatile unsigned int *guard)
{
    while (__atomic_test_and_set(guard, __ATOMIC_ACQUIRE))
        acpica_relax();
}

static void
acpica_guard_unlock(volatile unsigned int *guard)
{
    __atomic_clear(guard, __ATOMIC_RELEASE);
}

static int
acpica_width_valid(UINT32 width)
{
    return width == 8 || width == 16 || width == 32 || width == 64;
}

ACPI_STATUS
AcpiOsInitialize(void)
{
    return AE_OK;
}

ACPI_STATUS
AcpiOsTerminate(void)
{
    AcpiOsWaitEventsComplete();
    return AE_OK;
}

ACPI_PHYSICAL_ADDRESS
AcpiOsGetRootPointer(void)
{
    return (ACPI_PHYSICAL_ADDRESS)bsd_acpi_tables_rsdp_address();
}

ACPI_STATUS
AcpiOsPredefinedOverride(const ACPI_PREDEFINED_NAMES *initial,
    ACPI_STRING *replacement)
{
    if (!initial || !replacement)
        return AE_BAD_PARAMETER;
    *replacement = 0;
    return AE_OK;
}

ACPI_STATUS
AcpiOsTableOverride(ACPI_TABLE_HEADER *existing,
    ACPI_TABLE_HEADER **replacement)
{
    if (!existing || !replacement)
        return AE_BAD_PARAMETER;
    *replacement = 0;
    return AE_OK;
}

ACPI_STATUS
AcpiOsPhysicalTableOverride(ACPI_TABLE_HEADER *existing,
    ACPI_PHYSICAL_ADDRESS *replacement, UINT32 *replacement_length)
{
    if (!existing || !replacement || !replacement_length)
        return AE_BAD_PARAMETER;
    *replacement = 0;
    *replacement_length = 0;
    return AE_SUPPORT;
}

void *
AcpiOsAllocate(ACPI_SIZE size)
{
    return bsd_malloc((size_t)size, M_DEVBUF, M_NOWAIT);
}

void
AcpiOsFree(void *memory)
{
    bsd_free(memory, M_DEVBUF);
}

void *
AcpiOsMapMemory(ACPI_PHYSICAL_ADDRESS physical, ACPI_SIZE length)
{
    if (length == 0 || physical > UINT64_MAX - ((uint64_t)length - 1u))
        return 0;
#if defined(__x86_64__)
    if (!edge_mmio_phys_range_mapped((uint64_t)physical, (uint64_t)length))
        return 0;
    return (void *)edge_mmio_low_alias((uint64_t)physical);
#else
    return (void *)(uintptr_t)physical;
#endif
}

void
AcpiOsUnmapMemory(void *logical, ACPI_SIZE length)
{
    (void)logical;
    (void)length;
}

ACPI_STATUS
AcpiOsReadMemory(ACPI_PHYSICAL_ADDRESS physical, UINT64 *value, UINT32 width)
{
    volatile void *mapped;

    if (!value || !acpica_width_valid(width))
        return AE_BAD_PARAMETER;
    mapped = AcpiOsMapMemory(physical, width / 8u);
    if (!mapped)
        return AE_BAD_ADDRESS;
    if (width == 8)
        *value = *(volatile uint8_t *)mapped;
    else if (width == 16)
        *value = *(volatile uint16_t *)mapped;
    else if (width == 32)
        *value = *(volatile uint32_t *)mapped;
    else
        *value = *(volatile uint64_t *)mapped;
    return AE_OK;
}

ACPI_STATUS
AcpiOsWriteMemory(ACPI_PHYSICAL_ADDRESS physical, UINT64 value, UINT32 width)
{
    volatile void *mapped;

    if (!acpica_width_valid(width))
        return AE_BAD_PARAMETER;
    mapped = AcpiOsMapMemory(physical, width / 8u);
    if (!mapped)
        return AE_BAD_ADDRESS;
    if (width == 8)
        *(volatile uint8_t *)mapped = (uint8_t)value;
    else if (width == 16)
        *(volatile uint16_t *)mapped = (uint16_t)value;
    else if (width == 32)
        *(volatile uint32_t *)mapped = (uint32_t)value;
    else
        *(volatile uint64_t *)mapped = value;
    return AE_OK;
}

ACPI_STATUS
AcpiOsCreateLock(ACPI_SPINLOCK *handle)
{
    spinlock_t *lock;

    if (!handle)
        return AE_BAD_PARAMETER;
    lock = bsd_malloc(sizeof(*lock), M_DEVBUF, M_NOWAIT | M_ZERO);
    if (!lock)
        return AE_NO_MEMORY;
    spinlock_init(lock);
    *handle = lock;
    return AE_OK;
}

void
AcpiOsDeleteLock(ACPI_SPINLOCK handle)
{
    bsd_free(handle, M_DEVBUF);
}

ACPI_CPU_FLAGS
AcpiOsAcquireLock(ACPI_SPINLOCK handle)
{
    if (!handle)
        return 0;
    return (ACPI_CPU_FLAGS)spin_lock_irqsave((spinlock_t *)handle);
}

void
AcpiOsReleaseLock(ACPI_SPINLOCK handle, ACPI_CPU_FLAGS flags)
{
    if (handle)
        spin_unlock_irqrestore((spinlock_t *)handle, (uint64_t)flags);
}

ACPI_STATUS
AcpiOsCreateSemaphore(UINT32 maximum, UINT32 initial,
    ACPI_SEMAPHORE *handle)
{
    bsd_acpica_semaphore_t *semaphore;

    if (!handle || maximum == 0 || initial > maximum)
        return AE_BAD_PARAMETER;
    semaphore = bsd_malloc(sizeof(*semaphore), M_DEVBUF,
        M_NOWAIT | M_ZERO);
    if (!semaphore)
        return AE_NO_MEMORY;
    semaphore->maximum = maximum;
    semaphore->units = initial;
    *handle = semaphore;
    return AE_OK;
}

ACPI_STATUS
AcpiOsDeleteSemaphore(ACPI_SEMAPHORE handle)
{
    bsd_acpica_semaphore_t *semaphore = handle;

    if (!semaphore)
        return AE_BAD_PARAMETER;
    acpica_guard_lock(&semaphore->guard);
    semaphore->deleting = 1;
    acpica_guard_unlock(&semaphore->guard);
    bsd_kthread_wakeup(semaphore, 0);
    while (__atomic_load_n(&semaphore->waiters, __ATOMIC_ACQUIRE) != 0)
        bsd_delay(50);
    bsd_free(semaphore, M_DEVBUF);
    return AE_OK;
}

ACPI_STATUS
AcpiOsWaitSemaphore(ACPI_SEMAPHORE handle, UINT32 units, UINT16 timeout)
{
    bsd_acpica_semaphore_t *semaphore = handle;
    uint64_t deadline = UINT64_MAX;

    if (!semaphore || units == 0)
        return AE_BAD_PARAMETER;
    if (semaphore->maximum != ACPI_NO_UNIT_LIMIT &&
        units > semaphore->maximum)
        return AE_LIMIT;
    if (timeout != ACPI_WAIT_FOREVER) {
        uint64_t now = boottime_monotonic_us();
        uint64_t duration = (uint64_t)timeout * 1000u;

        deadline = duration > UINT64_MAX - now ? UINT64_MAX :
            now + duration;
    }
    for (;;) {
        uint64_t generation = bsd_kthread_wakeup_generation(semaphore);
        uint64_t now;
        int timeout_ticks;

        acpica_guard_lock(&semaphore->guard);
        if (semaphore->deleting) {
            acpica_guard_unlock(&semaphore->guard);
            return AE_ERROR;
        }
        if (semaphore->units >= units) {
            semaphore->units -= units;
            acpica_guard_unlock(&semaphore->guard);
            return AE_OK;
        }
        if (timeout == ACPI_DO_NOT_WAIT) {
            acpica_guard_unlock(&semaphore->guard);
            return AE_TIME;
        }
        semaphore->waiters++;
        acpica_guard_unlock(&semaphore->guard);

        now = boottime_monotonic_us();
        if (deadline != UINT64_MAX && now >= deadline) {
            __atomic_sub_fetch(&semaphore->waiters, 1, __ATOMIC_ACQ_REL);
            return AE_TIME;
        }
        if (deadline == UINT64_MAX) {
            timeout_ticks = 0;
        } else {
            uint64_t remaining = deadline - now;

            timeout_ticks = (int)((remaining + 999u) / 1000u);
            if (timeout_ticks < 1)
                timeout_ticks = 1;
        }
        (void)bsd_kthread_sleep_generation(semaphore, generation,
            timeout_ticks);
        __atomic_sub_fetch(&semaphore->waiters, 1, __ATOMIC_ACQ_REL);
    }
}

ACPI_STATUS
AcpiOsSignalSemaphore(ACPI_SEMAPHORE handle, UINT32 units)
{
    bsd_acpica_semaphore_t *semaphore = handle;

    if (!semaphore || units == 0)
        return AE_BAD_PARAMETER;
    acpica_guard_lock(&semaphore->guard);
    if (semaphore->deleting) {
        acpica_guard_unlock(&semaphore->guard);
        return AE_ERROR;
    }
    if (semaphore->maximum != ACPI_NO_UNIT_LIMIT &&
        (units > semaphore->maximum ||
        semaphore->units > semaphore->maximum - units)) {
        acpica_guard_unlock(&semaphore->guard);
        return AE_LIMIT;
    }
    semaphore->units += units;
    acpica_guard_unlock(&semaphore->guard);
    bsd_kthread_wakeup(semaphore, 0);
    return AE_OK;
}

ACPI_STATUS
AcpiOsCreateMutex(ACPI_MUTEX *handle)
{
    return AcpiOsCreateSemaphore(1, 1, (ACPI_SEMAPHORE *)handle);
}

void
AcpiOsDeleteMutex(ACPI_MUTEX handle)
{
    (void)AcpiOsDeleteSemaphore((ACPI_SEMAPHORE)handle);
}

ACPI_STATUS
AcpiOsAcquireMutex(ACPI_MUTEX handle, UINT16 timeout)
{
    return AcpiOsWaitSemaphore((ACPI_SEMAPHORE)handle, 1, timeout);
}

void
AcpiOsReleaseMutex(ACPI_MUTEX handle)
{
    (void)AcpiOsSignalSemaphore((ACPI_SEMAPHORE)handle, 1);
}

static void
acpica_task_execute(void *opaque_task, int pending)
{
    bsd_acpica_task_t *task = opaque_task;
    ACPI_OSD_EXEC_CALLBACK callback = task->callback;
    void *context = task->context;

    (void)pending;
    callback(context);
    task->callback = 0;
    task->context = 0;
    __atomic_store_n(&task->active, 0, __ATOMIC_RELEASE);
    __atomic_sub_fetch(&g_acpica_active_tasks, 1, __ATOMIC_ACQ_REL);
    bsd_kthread_wakeup((const void *)(uintptr_t)&g_acpica_active_tasks, 0);
}

ACPI_STATUS
AcpiOsExecute(ACPI_EXECUTE_TYPE type, ACPI_OSD_EXEC_CALLBACK callback,
    void *context)
{
    bsd_acpica_task_t *selected = 0;

    if (!callback || type > OSL_EC_BURST_HANDLER ||
        !bsd_taskqueue_runtime_is_initialized())
        return AE_BAD_PARAMETER;
    acpica_guard_lock(&g_acpica_task_guard);
    for (uint32_t index = 0; index < BSD_ACPICA_TASK_COUNT; ++index) {
        if (!__atomic_load_n(&g_acpica_tasks[index].active,
            __ATOMIC_ACQUIRE)) {
            selected = &g_acpica_tasks[index];
            __atomic_store_n(&selected->active, 1, __ATOMIC_RELEASE);
            break;
        }
    }
    acpica_guard_unlock(&g_acpica_task_guard);
    if (!selected)
        return AE_LIMIT;
    selected->callback = callback;
    selected->context = context;
    bsd_taskqueue_task_init(&selected->task, 0, acpica_task_execute,
        selected);
    __atomic_add_fetch(&g_acpica_active_tasks, 1, __ATOMIC_ACQ_REL);
    if (bsd_taskqueue_task_schedule(&selected->task) != 0) {
        __atomic_sub_fetch(&g_acpica_active_tasks, 1, __ATOMIC_ACQ_REL);
        __atomic_store_n(&selected->active, 0, __ATOMIC_RELEASE);
        return AE_ERROR;
    }
    return AE_OK;
}

void
AcpiOsWaitEventsComplete(void)
{
    while (__atomic_load_n(&g_acpica_active_tasks, __ATOMIC_ACQUIRE) != 0) {
        uint64_t generation =
            bsd_kthread_wakeup_generation(
                (const void *)(uintptr_t)&g_acpica_active_tasks);

        if (__atomic_load_n(&g_acpica_active_tasks,
            __ATOMIC_ACQUIRE) != 0) {
            (void)bsd_kthread_sleep_generation(
                (const void *)(uintptr_t)&g_acpica_active_tasks,
                generation, 1);
        }
    }
}

ACPI_THREAD_ID
AcpiOsGetThreadId(void)
{
    uintptr_t token = (uintptr_t)bsd_kthread_current_token();

    return token ? (ACPI_THREAD_ID)token : (ACPI_THREAD_ID)1;
}

void
AcpiOsSleep(UINT64 milliseconds)
{
    uint64_t ticks64;

    if (!milliseconds)
        return;
    ticks64 = milliseconds;
    if (ticks64 > INT32_MAX)
        ticks64 = INT32_MAX;
    if (bsd_kthread_current_token())
        (void)bsd_pause("acpislp", (int)ticks64);
    else {
        while (milliseconds != 0) {
            UINT32 step = milliseconds > UINT32_MAX / 1000u ?
                UINT32_MAX : (UINT32)(milliseconds * 1000u);

            bsd_delay(step);
            milliseconds -= step / 1000u;
        }
    }
}

void
AcpiOsStall(UINT32 microseconds)
{
    bsd_delay(microseconds);
}

UINT64
AcpiOsGetTimer(void)
{
    return boottime_monotonic_us() * 10u;
}

static void
acpica_interrupt_dispatch(void *opaque_record)
{
    bsd_acpica_interrupt_t *record = opaque_record;

    if (record && record->active && record->handler)
        (void)record->handler(record->context);
}

ACPI_STATUS
AcpiOsInstallInterruptHandler(UINT32 interrupt, ACPI_OSD_HANDLER handler,
    void *context)
{
    bsd_acpica_interrupt_t *record = 0;
    uint32_t platform_interrupt = interrupt;

    if (!handler)
        return AE_BAD_PARAMETER;
#if defined(__x86_64__)
    if (interrupt >= 224u)
        return AE_BAD_PARAMETER;
    platform_interrupt = BSD_ACPICA_X86_IRQ_BASE + interrupt;
#endif
    acpica_guard_lock(&g_acpica_interrupt_guard);
    for (uint32_t index = 0; index < BSD_ACPICA_INTERRUPT_COUNT; ++index) {
        if (g_acpica_interrupts[index].active &&
            g_acpica_interrupts[index].handler == handler) {
            acpica_guard_unlock(&g_acpica_interrupt_guard);
            return AE_ALREADY_EXISTS;
        }
        if (!record && !g_acpica_interrupts[index].active)
            record = &g_acpica_interrupts[index];
    }
    if (!record) {
        acpica_guard_unlock(&g_acpica_interrupt_guard);
        return AE_LIMIT;
    }
    record->handler = handler;
    record->context = context;
    record->interrupt = platform_interrupt;
    record->active = 1;
    acpica_guard_unlock(&g_acpica_interrupt_guard);
    if (bsd_interrupt_register_raw(platform_interrupt, 0,
        acpica_interrupt_dispatch, record, &record->backend_cookie) != 0) {
        record->active = 0;
        record->handler = 0;
        record->context = 0;
        return AE_ERROR;
    }
    return AE_OK;
}

ACPI_STATUS
AcpiOsRemoveInterruptHandler(UINT32 interrupt, ACPI_OSD_HANDLER handler)
{
    bsd_acpica_interrupt_t *record = 0;
    uint32_t platform_interrupt = interrupt;

#if defined(__x86_64__)
    platform_interrupt = BSD_ACPICA_X86_IRQ_BASE + interrupt;
#endif
    acpica_guard_lock(&g_acpica_interrupt_guard);
    for (uint32_t index = 0; index < BSD_ACPICA_INTERRUPT_COUNT; ++index) {
        if (g_acpica_interrupts[index].active &&
            g_acpica_interrupts[index].interrupt == platform_interrupt &&
            g_acpica_interrupts[index].handler == handler) {
            record = &g_acpica_interrupts[index];
            record->active = 0;
            break;
        }
    }
    acpica_guard_unlock(&g_acpica_interrupt_guard);
    if (!record)
        return AE_NOT_EXIST;
    if (bsd_interrupt_unregister_raw(record->backend_cookie) != 0) {
        record->active = 1;
        return AE_ERROR;
    }
    record->handler = 0;
    record->context = 0;
    record->backend_cookie = 0;
    return AE_OK;
}

ACPI_STATUS
AcpiOsReadPort(ACPI_IO_ADDRESS address, UINT32 *value, UINT32 width)
{
    if (!value || address > UINT16_MAX ||
        (width != 8 && width != 16 && width != 32))
        return AE_BAD_PARAMETER;
#if defined(__x86_64__)
    if (width == 8) {
        uint8_t result;
        __asm__ __volatile__("inb %1, %0" : "=a"(result) :
            "Nd"((uint16_t)address));
        *value = result;
    } else if (width == 16) {
        uint16_t result;
        __asm__ __volatile__("inw %1, %0" : "=a"(result) :
            "Nd"((uint16_t)address));
        *value = result;
    } else {
        __asm__ __volatile__("inl %1, %0" : "=a"(*value) :
            "Nd"((uint16_t)address));
    }
    return AE_OK;
#else
    return AE_SUPPORT;
#endif
}

ACPI_STATUS
AcpiOsWritePort(ACPI_IO_ADDRESS address, UINT32 value, UINT32 width)
{
    if (address > UINT16_MAX ||
        (width != 8 && width != 16 && width != 32))
        return AE_BAD_PARAMETER;
#if defined(__x86_64__)
    if (width == 8)
        __asm__ __volatile__("outb %0, %1" : :
            "a"((uint8_t)value), "Nd"((uint16_t)address));
    else if (width == 16)
        __asm__ __volatile__("outw %0, %1" : :
            "a"((uint16_t)value), "Nd"((uint16_t)address));
    else
        __asm__ __volatile__("outl %0, %1" : :
            "a"(value), "Nd"((uint16_t)address));
    return AE_OK;
#else
    return AE_SUPPORT;
#endif
}

ACPI_STATUS
AcpiOsReadPciConfiguration(ACPI_PCI_ID *pci_id, UINT32 reg,
    UINT64 *value, UINT32 width)
{
    bsd_pci_location_t location;
    uint32_t result;

    if (!pci_id || !value || reg > UINT16_MAX ||
        (width != 8 && width != 16 && width != 32))
        return AE_BAD_PARAMETER;
    location.domain = pci_id->Segment;
    location.bus = (uint8_t)pci_id->Bus;
    location.slot = (uint8_t)pci_id->Device;
    location.function = (uint8_t)pci_id->Function;
    if (bsd_pci_read_config_at(&location, (uint16_t)reg, width / 8u,
        &result) != 0)
        return AE_NOT_EXIST;
    *value = result;
    return AE_OK;
}

ACPI_STATUS
AcpiOsWritePciConfiguration(ACPI_PCI_ID *pci_id, UINT32 reg,
    UINT64 value, UINT32 width)
{
    bsd_pci_location_t location;

    if (!pci_id || reg > UINT16_MAX || value > UINT32_MAX ||
        (width != 8 && width != 16 && width != 32))
        return AE_BAD_PARAMETER;
    location.domain = pci_id->Segment;
    location.bus = (uint8_t)pci_id->Bus;
    location.slot = (uint8_t)pci_id->Device;
    location.function = (uint8_t)pci_id->Function;
    return bsd_pci_write_config_at(&location, (uint16_t)reg, width / 8u,
        (uint32_t)value) == 0 ? AE_OK : AE_NOT_EXIST;
}

ACPI_STATUS
AcpiOsSignal(UINT32 function, void *information)
{
    if (function == ACPI_SIGNAL_FATAL) {
        ACPI_SIGNAL_FATAL_INFO *fatal = information;

        if (fatal) {
            bsd_printf("[acpica] fatal type=0x%x code=0x%x argument=0x%x\n",
                fatal->Type, fatal->Code, fatal->Argument);
        }
        return AE_OK;
    }
    if (function == ACPI_SIGNAL_BREAKPOINT) {
        if (information)
            bsd_printf("[acpica] breakpoint: %s\n", (char *)information);
        return AE_OK;
    }
    return AE_BAD_PARAMETER;
}

ACPI_STATUS
AcpiOsEnterSleep(UINT8 sleep_state, UINT32 register_a, UINT32 register_b)
{
    (void)sleep_state;
    (void)register_a;
    (void)register_b;
    return AE_OK;
}

void
AcpiOsVprintf(const char *format, va_list arguments)
{
    (void)bsd_vprintf(format, arguments);
}

void
AcpiOsPrintf(const char *format, ...)
{
    va_list arguments;

    va_start(arguments, format);
    AcpiOsVprintf(format, arguments);
    va_end(arguments);
}

int
bsd_acpi_acquire_global_lock(volatile uint32_t *lock)
{
    uint32_t old_value;
    uint32_t new_value;

    do {
        old_value = __atomic_load_n(lock, __ATOMIC_ACQUIRE);
        new_value = (old_value & ~UINT32_C(1)) | UINT32_C(2);
        if ((old_value & UINT32_C(2)) != 0)
            new_value |= UINT32_C(1);
    } while (!__atomic_compare_exchange_n(lock, &old_value, new_value, 0,
        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
    return (new_value & UINT32_C(1)) == 0;
}

int
bsd_acpi_release_global_lock(volatile uint32_t *lock)
{
    uint32_t old_value;
    uint32_t new_value;

    do {
        old_value = __atomic_load_n(lock, __ATOMIC_ACQUIRE);
        new_value = old_value & ~(UINT32_C(1) | UINT32_C(2));
    } while (!__atomic_compare_exchange_n(lock, &old_value, new_value, 0,
        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
    return (old_value & UINT32_C(1)) != 0;
}
