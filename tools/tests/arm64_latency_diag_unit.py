#!/usr/bin/env python3
"""Test production ARM owner diagnostics and wake classification using host shims."""
import argparse
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]

def function(source, signature):
    start=source.index(signature); opening=source.index('{',start); depth=1; end=opening+1
    while depth:
        depth+=(source[end]=='{')-(source[end]=='}');end+=1
    return source[start:end]

PRELUDE=r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "arch/arm64/latency_diag.h"
#include "kernel/boot_command_line.h"
#define EDGE_SMP_MAX_CPUS 4
typedef struct { uint64_t kernel_execution_irq_flags; unsigned kernel_execution_depth;
    unsigned kernel_execution_waiting, kernel_execution_suspended,
        kernel_execution_scheduler_handoffs; } arm64_scheduler_cpu_runtime_t;
typedef struct { uint64_t hardware_id; } edge_cpu_topology_t;
static arm64_scheduler_cpu_runtime_t g_arm64_scheduler_cpus[4];
static uint64_t g_kernel_execution_owner_hardware_plus_one, now=1000, flags_state;
static unsigned cpu, clocks, irq_masks, notifications;
static uint64_t g_scheduler_cpu_wait_us[4];
static uint64_t boottime_monotonic_us(void){++clocks;return now;}
static uint32_t edgeos_arm64_smp_current_cpu(void){return cpu;}
static uint64_t edgeos_arm64_smp_current_hardware_id(void){return cpu;}
static int kernel_current_pid(void){return 100+(int)cpu;}
static arm64_scheduler_cpu_runtime_t *arm64_scheduler_cpu_local(void){return &g_arm64_scheduler_cpus[cpu];}
static uint64_t arm64_latency_irq_save(void){++irq_masks;uint64_t old=flags_state;flags_state=1;return old;}
static void arm64_latency_irq_restore(uint64_t f){flags_state=f;}
static void simulate_wait(void);
'''
TEST=r'''
static void simulate_wait(void) {
    unsigned waiting_cpu=cpu;
    cpu=(unsigned)g_kernel_execution_owner_hardware_plus_one-1;
    assert(cpu<4 && cpu!=waiting_cpu);
    now+=5000;edgeos_arm64_kernel_execution_exit();cpu=waiting_cpu;
}
enum { KERNEL_TASK_UNUSED=0,KERNEL_TASK_RUNNING=2,KERNEL_TASK_RUNNABLE=3,
       KERNEL_TASK_WAITING=4,KERNEL_TASK_WAITING_EPOLL=14,KERNEL_TASK_STOPPED=38 };
typedef unsigned arm64_task_state_t;
typedef struct { unsigned state,latency_wake_cause,pid,cgroup_id;
    uint64_t scheduler_wait_start_us,scheduler_wait_us; } kernel_task_t;
static void task_scheduler_counter_add(uint64_t *p,uint64_t n){*p+=n;}
static void cgroupfs_cpu_note_pressure(unsigned c,uint64_t n,uint64_t w,unsigned x){(void)c;(void)n;(void)w;(void)x;}
'''
MAIN=r'''
int main(void) {
    kernel_boot_command_line_set("");arm64_latency_init();
    edgeos_arm64_kernel_execution_enter();edgeos_arm64_kernel_execution_exit();
    assert(!irq_masks && !g_arm64_latency_diag.enabled);
    assert(kernel_execution_owner_claim(0,1));
    assert(g_kernel_execution_owner_hardware_plus_one==1);
    kernel_execution_owner_release(0,1);
    assert(!g_kernel_execution_owner_hardware_plus_one);
    g_arm64_scheduler_cpus[1].kernel_execution_waiting=1;
    assert(kernel_execution_owner_claim(2,3));
    kernel_execution_owner_release(2,3);
    g_arm64_scheduler_cpus[1].kernel_execution_waiting=0;
    cpu=0;
    kernel_boot_command_line_set("edgeos.arm64_latency_diag=1 edgeos.arm64_latency_duration_ms=1000");
    arm64_latency_init();assert(g_arm64_latency_diag.clock_domain==1 && g_arm64_latency_diag.time_unit_ns==1000);
    edgeos_arm64_kernel_execution_enter();now=2000;
    edgeos_arm64_kernel_execution_enter();assert(!edgeos_arm64_kernel_execution_try_enter());
    edgeos_arm64_kernel_execution_profile_syscall(221);
    assert(g_arm64_latency_diag.cpus[0].metrics[1].count==1);
    assert(g_arm64_latency_diag.cpus[0].owner_start_us==1000);
    now=4000;edgeos_arm64_kernel_execution_exit();edgeos_arm64_kernel_execution_exit();
    assert(g_arm64_latency_diag.cpus[0].metrics[2].count==1);
    assert(g_arm64_latency_diag.cpus[0].metrics[2].total_us==3000);
    assert(g_arm64_latency_diag.cpus[0].maximum[2].cause==(221u<<8));
    now=5000;edgeos_arm64_kernel_execution_enter();cpu=1;
    edgeos_arm64_kernel_execution_enter();
    assert(g_kernel_execution_owner_hardware_plus_one==2);
    assert(!notifications && !g_arm64_scheduler_cpus[1].kernel_execution_waiting);
    assert(g_arm64_latency_diag.cpus[1].metrics[1].total_us==5000);
    edgeos_arm64_kernel_execution_exit();
    kernel_task_t t={.state=KERNEL_TASK_WAITING_EPOLL,.pid=123};
    now=11000;transition(&t,KERNEL_TASK_RUNNABLE);now=18000;transition(&t,KERNEL_TASK_RUNNING);
    assert(g_arm64_latency_diag.cpus[1].metrics[3].count==1 && g_arm64_latency_diag.cpus[1].metrics[3].total_us==7000);
    now=19000;transition(&t,KERNEL_TASK_RUNNABLE);now=21000;transition(&t,KERNEL_TASK_RUNNING);
    assert(g_arm64_latency_diag.cpus[1].metrics[3].count==1);
    arm64_latency_diag_t *d=&g_arm64_latency_diag;memset(d,0,sizeof(*d));
    d->enabled=1;d->start_us=1;d->stop_us=100;d->threshold_us=0;
    for(unsigned i=0;i<40;++i)arm64_latency_record(d,0,0,1,0,1,101,0);
    assert(d->cpus[0].ring_overwrites==8 && d->cpus[0].window_overruns==40);
    d->cpus[0].events=UINT64_MAX;arm64_latency_record(d,0,0,1,0,1,2,0);
    assert(d->cpus[0].event_wraps==1 && d->cpus[0].events==1);
    d->cpus[0].metrics[0].total_us=UINT64_MAX;arm64_latency_record(d,0,0,1,0,1,2,0);
    assert(d->cpus[0].counter_saturations==1);
    assert(d->cpus[0].maximum[0].end_us-d->cpus[0].maximum[0].start_us==100);
    uint64_t count=d->cpus[0].metrics[0].count;arm64_latency_record(d,0,0,1,0,100,102,0);
    assert(d->cpus[0].metrics[0].count==count);
    puts("ARM latency diagnostic/runnable owner acquisition/wake classification PASS");
    return 0;
}
'''

def main():
    p=argparse.ArgumentParser();p.add_argument('--output-dir',type=Path,required=True);a=p.parse_args()
    s=(ROOT/'src/arch/arm64/kernel/bootstrap_runtime.c').read_text()
    names=['static uint64_t arm64_latency_begin(', 'static void arm64_latency_acquired(',
           'static void arm64_latency_released(', 'static uint64_t arm64_latency_option_ms(',
           'static void arm64_latency_init(',
           'void edgeos_arm64_kernel_execution_profile_syscall(',
           'static int kernel_execution_owner_claim(',
           'static void kernel_execution_wait_for_owner_change(',
           'static void kernel_execution_owner_wait(',
           'static void kernel_execution_owner_release(',
           'void edgeos_arm64_kernel_execution_enter(void)',
           'int edgeos_arm64_kernel_execution_try_enter(void)',
           'void edgeos_arm64_kernel_execution_exit(void)']
    production='arm64_latency_diag_t g_arm64_latency_diag;\n'+'\n'.join(function(s,n) for n in names)
    grant_wait=function(s,'static void kernel_execution_wait_for_owner_change(')
    production=production.replace(
        grant_wait,
        'static void kernel_execution_wait_for_owner_change('
        'volatile uint64_t *owner, uint64_t observed_owner) {'
        ' while (*owner == observed_owner) simulate_wait(); }')
    production=production.replace('__asm__ __volatile__("mrs %0, daif" : "=r"(flags));','flags=flags_state;')
    production=production.replace('__asm__ __volatile__("msr daif, %0" :: "r"(flags) : "memory");','flags_state=flags;')
    production=production.replace('__asm__ __volatile__("dsb ishst" ::: "memory");','__atomic_thread_fence(__ATOMIC_SEQ_CST);')
    production=production.replace('__asm__ __volatile__("sev" ::: "memory");','++notifications;')
    production=production.replace('__asm__ __volatile__("yield" ::: "memory");','(void)0;')
    production=production.replace('__asm__ __volatile__("wfe" ::: "memory");','simulate_wait();')
    production=production.replace('__asm__ __volatile__(\n            "msr daifclr, #2\\n\\twfi\\n\\tmsr daifset, #2"\n            ::: "memory");','simulate_wait();')
    transition=function(s,'static void task_state_set(kernel_task_t *task,\n                           arm64_task_state_t state) {')
    transition=transition[transition.index('    previous = task->state;'):transition.index('    if (!g_tasks)')]
    code=PRELUDE+production+TEST+'\nstatic void transition(kernel_task_t *task,arm64_task_state_t state){arm64_task_state_t previous;uint64_t now_us;\n'+transition+'task->state=state;\n}\n'+MAIN
    a.output_dir.mkdir(parents=True,exist_ok=True)
    source=a.output_dir/'unit.c';source.write_text(code)
    binary=a.output_dir/'arm64_latency_diag_unit'
    subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-iquote',str(ROOT/'include'),str(source),str(ROOT/'src/kernel/boot_command_line.c'),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True)

if __name__=='__main__':main()
