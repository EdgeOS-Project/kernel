/* SPDX-License-Identifier: MPL-2.0 */
/* Memory-state hooks for imported drivers. */

#ifndef _SYS_MSAN_H_
#define _SYS_MSAN_H_

#define KMSAN_STATE_INITED 0
#define kmsan_mark(data, length, state) do {                             \
    (void)(data);                                                       \
    (void)(length);                                                     \
    (void)(state);                                                      \
} while (0)
#define kmsan_mark_mbuf(mbuf, state) do {                               \
    (void)(mbuf);                                                       \
    (void)(state);                                                      \
} while (0)
#define kmsan_mark_bio(bio, state) \
    do {                            \
        (void)(bio);                \
        (void)(state);              \
    } while (0)

#ifndef KMSAN
#define kmsan_bus_dmamap_sync(memory, operation) do {                  \
    (void)sizeof(operation);                                           \
} while (0)
#endif

#endif
