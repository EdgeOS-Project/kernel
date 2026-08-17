/* SPDX-License-Identifier: MPL-2.0 */
/* Generated Linux-compatible vDSO image selected by the kernel architecture. */

#include <stdint.h>

const uint8_t edge_linux_vdso_image[8192] = {
#if defined(__aarch64__)
#include "linux-vdso-arm64-image.inc"
#elif defined(__x86_64__)
#include "linux-vdso-x86_64-image.inc"
#else
#error Unsupported vDSO architecture
#endif
};

const uint64_t edge_linux_vdso_image_size = sizeof(edge_linux_vdso_image);
