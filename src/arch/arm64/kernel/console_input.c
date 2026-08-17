/* SPDX-License-Identifier: MPL-2.0 */
/* ARM64 console input adapter backed by virtio-input and PL011 serial. */

#include "drivers/virtio_input_mmio.h"
#include "serial_console.h"

char kb_getchar(void) {
    for (;;) {
        int ch = virtio_input_getchar();
        if (ch >= 0) return (char)ch;
        ch = serial_console_pollchar();
        if (ch >= 0) return (char)ch;
        __asm__ __volatile__("wfe");
    }
}
