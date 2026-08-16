#ifndef SYS_BOOTTIME_H
#define SYS_BOOTTIME_H

#include <stdint.h>

void boottime_init(void);
void boottime_timer_tick(uint32_t hz);
int boottime_refine_tsc(uint64_t hz);
uint64_t boottime_clocksource_hz(void);
const char *boottime_clocksource_name(void);
uint32_t boottime_now_us(void);
uint64_t boottime_monotonic_us(void);
uint64_t boottime_realtime_us(void);
int boottime_set_realtime_us(uint64_t realtime_us);

#endif
