/* SPDX-License-Identifier: MPL-2.0 */
/* LED interface exposed by the EdgeOS FreeBSD driver bridge. */

#ifndef _DEV_LED_H
#define _DEV_LED_H

struct cdev;

typedef void led_t(void *, int);

struct cdev *led_create_state(led_t *, void *, const char *, int);
struct cdev *led_create(led_t *, void *, const char *);
void led_destroy(struct cdev *);
int led_set(const char *, const char *);

#endif
