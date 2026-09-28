/* SPDX-License-Identifier: MPL-2.0 */
/* Shared interrupt contract for the EdgeOS BSD Driver Bridge. */

#ifndef EDGEOS_COMPAT_FREEBSD_INTERRUPT_H
#define EDGEOS_COMPAT_FREEBSD_INTERRUPT_H

#include <stdint.h>

#include "newbus.h"
#include "../sys/rman.h"

#define FILTER_STRAY 0x01
#define FILTER_HANDLED 0x02
#define FILTER_SCHEDULE_THREAD 0x04

#define INTR_TYPE_TTY 1
#define INTR_TYPE_BIO 2
#define INTR_TYPE_NET 4
#define INTR_TYPE_CAM 8
#define INTR_TYPE_MISC 16
#define INTR_TYPE_CLK 32
#define INTR_TYPE_AV 64
#define INTR_EXCL 256
#define INTR_MPSAFE 512
#define INTR_ENTROPY 1024
#define INTR_SLEEPABLE 2048

typedef int driver_filter_t(void *);
typedef void driver_intr_t(void *);

typedef void (*bsd_interrupt_backend_callback_t)(void *argument);

typedef struct {
    int (*register_interrupt)(void *context, uint32_t interrupt,
        uint32_t flags, uint32_t interrupt_flags,
        bsd_interrupt_backend_callback_t callback, void *argument,
        void **backend_cookie);
    int (*unregister_interrupt)(void *context, void *backend_cookie);
    int (*mask_interrupt)(void *context, void *backend_cookie);
    int (*unmask_interrupt)(void *context, void *backend_cookie);
    int (*schedule_handler)(void *context, driver_intr_t *handler,
        void *argument);
    void *context;
} bsd_interrupt_backend_ops_t;

int bsd_interrupt_initialize(const bsd_interrupt_backend_ops_t *operations);
int bsd_interrupt_is_initialized(void);
int bsd_interrupt_ensure_initialized(void);
int bsd_interrupt_register_raw(uint32_t interrupt, uint32_t flags,
    bsd_interrupt_backend_callback_t callback, void *argument,
    void **backend_cookie);
int bsd_interrupt_unregister_raw(void *backend_cookie);
int bsd_intrng_resource_is_mapped(const struct resource *resource);
int bsd_intrng_suspend_irq(device_t device, struct resource *resource);
int bsd_intrng_resume_irq(device_t device, struct resource *resource);
int bsd_intrng_drain_irq(unsigned int irq);
int intr_activate_irq(device_t device, struct resource *resource);
int intr_deactivate_irq(device_t device, struct resource *resource);
int intr_setup_irq(device_t device, struct resource *resource,
    driver_filter_t filter, driver_intr_t handler, void *argument,
    int flags, void **cookie);
int intr_teardown_irq(device_t device, struct resource *resource,
    void *cookie);

int bus_setup_intr(device_t device, struct resource *resource, int flags,
    driver_filter_t *filter, driver_intr_t *handler, void *argument,
    void **cookie);
int bus_teardown_intr(device_t device, struct resource *resource,
    void *cookie);
int bsd_interrupt_setup_direct(device_t device, struct resource *resource,
    int flags, driver_filter_t *filter, driver_intr_t *handler,
    void *argument, void **cookie);
int bsd_interrupt_teardown_direct(device_t device,
    struct resource *resource, void *cookie);
int bsd_bus_setup_intr_from_parent(device_t child,
    struct resource *resource, int flags, driver_filter_t *filter,
    driver_intr_t *handler, void *argument, void **cookie);
int bsd_bus_teardown_intr_to_parent(device_t child,
    struct resource *resource, void *cookie);
int bus_suspend_intr(device_t device, struct resource *resource);
int bus_resume_intr(device_t device, struct resource *resource);
int bus_generic_teardown_intr(device_t bus, device_t child,
    struct resource *resource, void *cookie);
int bus_generic_suspend_intr(device_t bus, device_t child,
    struct resource *resource);
int bus_generic_resume_intr(device_t bus, device_t child,
    struct resource *resource);

#endif
