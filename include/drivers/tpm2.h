/* SPDX-License-Identifier: MPL-2.0 */
/*
 * EdgeOS TPM 2.0 driver interface.
 *
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_DRIVERS_TPM2_H
#define EDGEOS_DRIVERS_TPM2_H

void tpm2_init(void);
int tpm2_available(void);

#endif
