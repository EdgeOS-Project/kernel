/* SPDX-License-Identifier: BSD-2-Clause */
/* Socket option transfer interface used by imported protocol stacks. */

#ifndef _SYS_SOCKOPT_H_
#define _SYS_SOCKOPT_H_

#include <stddef.h>

struct cap_rights;
struct thread;

enum sopt_dir {
    SOPT_GET,
    SOPT_SET,
};

struct sockopt {
    enum sopt_dir sopt_dir;
    int sopt_level;
    int sopt_name;
    void *sopt_val;
    size_t sopt_valsize;
    const struct cap_rights *sopt_rights;
    struct thread *sopt_td;
};

int sooptcopyin(struct sockopt *, void *, size_t, size_t);
int sooptcopyout(struct sockopt *, const void *, size_t);

#endif
