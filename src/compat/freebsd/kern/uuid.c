/* SPDX-License-Identifier: MPL-2.0 */
/* Shared UUID comparison support for imported BSD drivers. */

#include <sys/uuid.h>

#include "compat/freebsd/edgeos/systm.h"

int
uuidcmp(const struct uuid *left, const struct uuid *right)
{
    return bsd_memcmp(left, right, sizeof(*left));
}
