/* SPDX-License-Identifier: BSD-2-Clause */
/* FreeBSD kernel signal-set ABI used by imported driver frameworks. */

#ifndef _SYS_SIGNAL_H_
#define _SYS_SIGNAL_H_

#include <stdint.h>

#ifndef _SYS__SIGSET_H_
#define _SYS__SIGSET_H_
#define _SIG_WORDS 4
#define _SIG_MAXSIG 128
#define _SIG_IDX(signal) ((signal) - 1)
#define _SIG_WORD(signal) (_SIG_IDX(signal) >> 5)
#define _SIG_BIT(signal) (UINT32_C(1) << (_SIG_IDX(signal) & 31))
#define _SIG_VALID(signal) ((signal) > 0 && (signal) <= _SIG_MAXSIG)
typedef struct __sigset {
    uint32_t __bits[_SIG_WORDS];
} __sigset_t;
#endif

#ifndef _SIGSET_T_DECLARED
#define _SIGSET_T_DECLARED
typedef __sigset_t sigset_t;
#endif

#define SIGKILL 9
#define SIGIO 23

#define SIGEMPTYSET(set) do { \
    for (unsigned int _signal_word = 0; _signal_word < _SIG_WORDS; \
        ++_signal_word) \
        (set).__bits[_signal_word] = 0; \
} while (0)
#define SIGSETOR(left, right) do { \
    for (unsigned int _signal_word = 0; _signal_word < _SIG_WORDS; \
        ++_signal_word) \
        (left).__bits[_signal_word] |= (right).__bits[_signal_word]; \
} while (0)
#define SIGSETNAND(left, right) do { \
    for (unsigned int _signal_word = 0; _signal_word < _SIG_WORDS; \
        ++_signal_word) \
        (left).__bits[_signal_word] &= ~(right).__bits[_signal_word]; \
} while (0)
#define SIGADDSET(set, signal) do { \
    int _signal_value = (signal); \
    if (_SIG_VALID(_signal_value)) \
        (set).__bits[_SIG_WORD(_signal_value)] |= _SIG_BIT(_signal_value); \
} while (0)
#define SIGISMEMBER(set, signal) \
    (_SIG_VALID(signal) && (((set).__bits[_SIG_WORD(signal)] & \
        _SIG_BIT(signal)) != 0))
#define SIGISEMPTY(set) \
    (((set).__bits[0] | (set).__bits[1] | (set).__bits[2] | \
        (set).__bits[3]) == 0)

#endif
