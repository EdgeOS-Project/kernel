/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_ARM64_LATENCY_DIAG_H
#define EDGEOS_ARM64_LATENCY_DIAG_H
#include <stdint.h>
#define ARM64_LATENCY_CPUS 16u
#define ARM64_LATENCY_METRICS 4u
#define ARM64_LATENCY_RING 32u
enum { ARM64_LATENCY_USER_ACQUIRE, ARM64_LATENCY_KERNEL_ACQUIRE,
       ARM64_LATENCY_OWNER_HOLD, ARM64_LATENCY_WAKE_RUN };
typedef struct {
    uint64_t count, total_us, maximum_us, histogram[8];
} arm64_latency_metric_t;
typedef struct {
    uint64_t sequence, metric, pid, cause, start_us, end_us, caller;
} arm64_latency_event_t;
typedef struct {
    uint64_t sequence, owner_start_us, owner_pid, owner_caller, owner_syscall;
    uint64_t events;
    uint64_t ring_overwrites, event_wraps, window_overruns, counter_saturations;
    arm64_latency_metric_t metrics[ARM64_LATENCY_METRICS];
    arm64_latency_event_t maximum[ARM64_LATENCY_METRICS];
    arm64_latency_event_t ring[ARM64_LATENCY_RING];
} arm64_latency_cpu_t;
typedef struct {
    /* Clock domain 1: boottime_monotonic_us; all duration/timestamp fields are us. */
    uint64_t version, enabled, start_us, stop_us, threshold_us;
    uint64_t clock_domain, time_unit_ns;
    arm64_latency_cpu_t cpus[ARM64_LATENCY_CPUS];
} arm64_latency_diag_t;
static inline uint64_t arm64_latency_add(uint64_t a,uint64_t b) {
    return b>UINT64_MAX-a?UINT64_MAX:a+b;
}
static inline int arm64_latency_active(const arm64_latency_diag_t *d,uint64_t now) {
    return d->enabled && now>=d->start_us && now<d->stop_us;
}
/* The caller masks local IRQs; each CPU owns its row without a global lock. */
static inline void arm64_latency_record(arm64_latency_diag_t *d,uint32_t cpu,
        uint32_t metric,uint64_t pid,uint64_t cause,uint64_t begin,uint64_t end,
        uint64_t caller) {
    static const uint64_t limits[7]={10,100,1000,5000,10000,20000,100000};
    if(!d->enabled || cpu>=ARM64_LATENCY_CPUS || metric>=ARM64_LATENCY_METRICS ||
       !begin || begin<d->start_us || begin>=d->stop_us || end<begin)return;
    arm64_latency_cpu_t *c=&d->cpus[cpu];
    arm64_latency_metric_t *m=&c->metrics[metric];
    uint64_t duration=end-begin;
    int new_maximum=duration>m->maximum_us;
    unsigned bucket=0;
    __atomic_add_fetch(&c->sequence,1,__ATOMIC_ACQ_REL);
    if(m->count==UINT64_MAX || duration>UINT64_MAX-m->total_us)
        c->counter_saturations=arm64_latency_add(c->counter_saturations,1);
    if(end>d->stop_us)c->window_overruns=arm64_latency_add(c->window_overruns,1);
    m->count=arm64_latency_add(m->count,1);
    m->total_us=arm64_latency_add(m->total_us,duration);
    if(new_maximum)m->maximum_us=duration;
    while(bucket<7 && duration>=limits[bucket])++bucket;
    m->histogram[bucket]=arm64_latency_add(m->histogram[bucket],1);
    if(new_maximum) {
        arm64_latency_event_t *e=&c->maximum[metric];
        e->sequence=0;e->metric=metric;e->pid=pid;e->cause=cause;
        e->start_us=begin;e->end_us=end;e->caller=caller;
        __atomic_store_n(&e->sequence,m->count,__ATOMIC_RELEASE);
    }
    if(duration>=d->threshold_us) {
        arm64_latency_event_t *e=&c->ring[c->events%ARM64_LATENCY_RING];
        if(c->events>=ARM64_LATENCY_RING)
            c->ring_overwrites=arm64_latency_add(c->ring_overwrites,1);
        e->sequence=0;e->metric=metric;e->pid=pid;e->cause=cause;
        e->start_us=begin;e->end_us=end;e->caller=caller;
        ++c->events;
        if(!c->events){c->events=1;c->event_wraps=arm64_latency_add(c->event_wraps,1);}
        __atomic_store_n(&e->sequence,c->events,__ATOMIC_RELEASE);
    }
    __atomic_add_fetch(&c->sequence,1,__ATOMIC_RELEASE);
}
#endif
