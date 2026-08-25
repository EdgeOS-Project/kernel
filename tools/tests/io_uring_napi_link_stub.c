/* SPDX-License-Identifier: MPL-2.0 */
/* Link adapter for network-only host tests. */

#include <stdint.h>

int kernel_io_uring_napi_id_register(uint32_t napi_id) {
    (void)napi_id;
    return 0;
}

void kernel_io_uring_napi_id_unregister(uint32_t napi_id) {
    (void)napi_id;
}
