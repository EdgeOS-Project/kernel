/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding compile probe for BSD bridge static lifecycle sections. */

#include "compat/freebsd/sys/module.h"

static int
target_module_event(module_t module, int event, void *argument)
{
    (void)module;
    (void)event;
    (void)argument;
    return 0;
}

static moduledata_t target_module_data = {
    "target_compile",
    target_module_event,
    0,
};

DECLARE_MODULE(target_compile, target_module_data, SI_SUB_DRIVERS,
    SI_ORDER_MIDDLE);
MODULE_VERSION(target_compile, 1);

static void
target_module_cleanup(const void *argument)
{
    (void)argument;
}

C_SYSUNINIT(target_compile_cleanup, SI_SUB_DRIVERS, SI_ORDER_MIDDLE,
    target_module_cleanup, 0);
