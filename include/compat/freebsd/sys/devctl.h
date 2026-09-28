/* SPDX-License-Identifier: MPL-2.0 */
/* FreeBSD device-event interface mapped to EdgeOS device notifications. */

#ifndef _SYS_DEVCTL_H_
#define _SYS_DEVCTL_H_

#include <stdbool.h>

bool devctl_process_running(void);
void devctl_notify(const char *system, const char *subsystem,
    const char *type, const char *data);
struct sbuf;
void devctl_safe_quote_sb(struct sbuf *buffer, const char *source);
typedef void send_event_f(const char *system, const char *subsystem,
    const char *type, const char *data);
void devctl_set_notify_hook(send_event_f *hook);
void devctl_unset_notify_hook(void);

#endif
