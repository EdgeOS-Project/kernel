/* SPDX-License-Identifier: MPL-2.0 */
/* Poll event values used by imported character-device drivers. */

#ifndef _SYS_POLL_H_
#define _SYS_POLL_H_

#define POLLIN 0x0001
#define POLLPRI 0x0002
#define POLLOUT 0x0004
#define POLLERR 0x0008
#define POLLHUP 0x0010
#define POLLNVAL 0x0020
#define POLLRDNORM 0x0040
#define POLLWRNORM POLLOUT

#endif
