/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture selector for imported FreeBSD segment definitions. */

#if defined(__x86_64__)
#include <amd64/include/segments.h>
#undef GCODE_SEL
#define GCODE_SEL 1
#undef GDATA_SEL
#define GDATA_SEL 2
#undef GPROC0_SEL
#define GPROC0_SEL 5
#else
#error "FreeBSD x86 segment definitions require x86_64"
#endif
