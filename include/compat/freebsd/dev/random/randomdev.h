/* SPDX-License-Identifier: BSD-2-Clause */
/* FreeBSD random-source registration contract for the BSD bridge. */

#ifndef SYS_DEV_RANDOM_RANDOMDEV_H_INCLUDED
#define SYS_DEV_RANDOM_RANDOMDEV_H_INCLUDED

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../../sys/random.h"

typedef unsigned int random_source_read_t(void *, unsigned int);

struct random_source {
    const char *rs_ident;
    enum random_entropy_source rs_source;
    random_source_read_t *rs_read;
    int rs_min_entropy;
};

void random_source_register(const struct random_source *source);
void random_source_deregister(const struct random_source *source);

extern bool random_bypass_before_seeding;
extern bool read_random_bypassed_before_seeding;
extern bool arc4random_bypassed_before_seeding;
extern bool random_bypass_disable_warnings;

#endif
