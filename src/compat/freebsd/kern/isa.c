/* SPDX-License-Identifier: MPL-2.0 */
/* ISA autoconfiguration and platform attachment for the imported stack. */

#include "compat/freebsd/edgeos/isa.h"
#include "compat/freebsd/edgeos/newbus.h"
#include "compat/freebsd/sys/systm.h"
#include <sys/kbio.h>
#include <dev/kbd/kbdreg.h>
#include <isa/isavar.h>
#include <isa/isa_common.h>

device_t isa_bus_device;

#define BSD_ISA_ENXIO 6
#define BSD_ISA_EEXIST 17

#if defined(__aarch64__) || defined(EDGEOS_BSD_ARM64)
char *
pnp_eisaformat(uint32_t identifier)
{
    static char formatted[8];
    static const char hexadecimal[] = "0123456789abcdef";

    formatted[0] = (char)('@' + ((identifier & 0x7cu) >> 2));
    formatted[1] = (char)('@' + ((identifier & 0x03u) << 3) +
        ((identifier >> 13) & 0x07u));
    formatted[2] = (char)('@' + ((identifier >> 8) & 0x1fu));
    formatted[3] = hexadecimal[(identifier >> 20) & 0x0fu];
    formatted[4] = hexadecimal[(identifier >> 16) & 0x0fu];
    formatted[5] = hexadecimal[(identifier >> 28) & 0x0fu];
    formatted[6] = hexadecimal[(identifier >> 24) & 0x0fu];
    formatted[7] = '\0';
    return formatted;
}
#endif

static int
bsd_isa_i8042_keyboard_ready(device_t controller)
{
    device_t keyboard_child;
    keyboard_t *keyboard;
    int keyboard_index;
    int required_flags =
        KB_VALID | KB_PROBED | KB_INITIALIZED | KB_REGISTERED;

    if (!controller)
        return BSD_ISA_ENXIO;
    keyboard_child = device_find_child(controller, "atkbd", 0);
    if (!keyboard_child || !device_is_attached(keyboard_child))
        return BSD_ISA_ENXIO;
    keyboard_index = kbd_find_keyboard("atkbd", 0);
    keyboard = kbd_get_keyboard(keyboard_index);
    if (!keyboard ||
        (keyboard->kb_flags & required_flags) != required_flags)
        return BSD_ISA_ENXIO;
    return 0;
}

static int
bsd_isa_set_i8042_hints(void)
{
    static const struct {
        const char *name;
        const char *value;
    } hints[] = {
        { "hint.atkbdc.0.at", "isa" },
        { "hint.atkbdc.0.port", "0x060" },
        { "hint.atkbd.0.at", "atkbdc" },
        { "hint.atkbd.0.irq", "1" },
        { "hint.psm.0.at", "atkbdc" },
        { "hint.psm.0.irq", "12" },
    };

    for (size_t index = 0; index < nitems(hints); ++index) {
        if (kern_setenv(hints[index].name, hints[index].value) != 0)
            return BSD_ISA_ENXIO;
    }
    return 0;
}

int
bsd_isa_i8042_attach(device_t root)
{
#if defined(__x86_64__)
    device_t atkbdc;
    device_t bus;
    devclass_t atkbdc_class;
    devclass_t root_class;
    int error;

    if (!root)
        return BSD_ISA_ENXIO;
    atkbdc_class = devclass_find("atkbdc");
    atkbdc = atkbdc_class ?
        devclass_get_device(atkbdc_class, 0) : 0;
    if (atkbdc && device_is_attached(atkbdc))
        return bsd_isa_i8042_keyboard_ready(atkbdc);
    error = bsd_isa_set_i8042_hints();
    if (error != 0)
        return error;
    root_class = devclass_find(device_get_name(root));
    if (!root_class)
        return BSD_ISA_ENXIO;
    error = devclass_add_driver(root_class, &isa_driver, 0, 0);
    if (error != 0 && error != BSD_ISA_EEXIST)
        return error;
    bus = device_find_child(root, "isa", 0);
    if (!bus)
        bus = device_add_child(root, "isa", 0);
    if (!bus)
        return BSD_ISA_ENXIO;
    if (!device_is_attached(bus) &&
        device_probe_and_attach(bus) != 0)
        return BSD_ISA_ENXIO;
    isa_probe_children(bus);
    atkbdc = device_find_child(bus, "atkbdc", 0);
    if (!atkbdc || !device_is_attached(atkbdc))
        return BSD_ISA_ENXIO;
    return bsd_isa_i8042_keyboard_ready(atkbdc);
#else
    (void)root;
    return BSD_ISA_ENXIO;
#endif
}
