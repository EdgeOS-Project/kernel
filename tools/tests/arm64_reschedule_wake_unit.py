#!/usr/bin/env python3
"""Exercise the production SGI branch and runtime release with host IRQ shims."""
import argparse
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def function(source, signature):
    start = source.index(signature)
    opening = source.index('{', start)
    depth, end = 1, opening + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


PRELUDE = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#define EDGE_SMP_MAX_CPUS 4u
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL: %s\n", #x); exit(1); } } while (0)
typedef struct { uint64_t spsr; } frame_t;
typedef struct {
    uint64_t kernel_execution_irq_flags;
    unsigned kernel_execution_depth, kernel_execution_scheduler_handoffs;
    unsigned kernel_execution_waiting, kernel_execution_suspended;
} arm64_scheduler_cpu_runtime_t;
static arm64_scheduler_cpu_runtime_t g_arm64_scheduler_cpus[4];
static uint64_t g_kernel_execution_owner_hardware_plus_one;
static unsigned cpu, active, completions, acknowledgements, wake_events;
static unsigned blocking_entries, preemptions;
static arm64_scheduler_cpu_runtime_t *arm64_scheduler_cpu_local(void) { return &g_arm64_scheduler_cpus[cpu]; }
static uint32_t edgeos_arm64_smp_current_cpu(void) { return cpu; }
static uint64_t edgeos_arm64_smp_current_hardware_id(void) { return cpu; }
static uint32_t edge_smp_present_count(void) { return 4; }
static void edge_smp_handle_reschedule(uint32_t target) { CHECK(target == cpu); }
static void edgeos_arm64_smp_reschedule_acknowledge(void) { ++acknowledgements; }
static void arm64_latency_released(uint32_t cause) { (void)cause; }
static void kernel_execution_profile_released(uint32_t logical_cpu) { (void)logical_cpu; }
static void kernel_execution_owner_release(uint32_t logical_cpu, uint64_t owner) {
    CHECK(logical_cpu == cpu && owner == cpu + 1);
    g_kernel_execution_owner_hardware_plus_one=0;
    ++wake_events;
}
static void arm64_irq_complete(uint64_t iar) { CHECK(iar == 1 && active); active=0; ++completions; }
static int edgeos_arm64_kernel_execution_waiting(void) { return arm64_scheduler_cpu_local()->kernel_execution_waiting; }
static int edgeos_arm64_kernel_execution_try_enter(void) {
    if (g_kernel_execution_owner_hardware_plus_one || edgeos_arm64_kernel_execution_waiting()) return 0;
    g_kernel_execution_owner_hardware_plus_one=cpu+1;
    arm64_scheduler_cpu_local()->kernel_execution_depth=1;
    return 1;
}
'''

ENTER = r'''
static void edgeos_arm64_kernel_execution_enter_from_user(void) {
    unsigned target=cpu;
    unsigned owner=(unsigned)g_kernel_execution_owner_hardware_plus_one-1;
    CHECK(!active); CHECK(owner < 4 && owner != target);
    ++blocking_entries;
    g_arm64_scheduler_cpus[target].kernel_execution_waiting=1;
    cpu=owner;
    edgeos_arm64_kernel_execution_exit();
    cpu=target;
    CHECK(wake_events == 1);
    CHECK(!g_kernel_execution_owner_hardware_plus_one);
    g_kernel_execution_owner_hardware_plus_one=cpu+1;
    g_arm64_scheduler_cpus[cpu].kernel_execution_waiting=0;
    g_arm64_scheduler_cpus[cpu].kernel_execution_depth=1;
}
'''

TESTS = r'''
static void reset(int busy) {
    for (unsigned i=0;i<4;++i) g_arm64_scheduler_cpus[i]=(arm64_scheduler_cpu_runtime_t){0};
    cpu=1; active=1; completions=acknowledgements=wake_events=blocking_entries=preemptions=0;
    g_kernel_execution_owner_hardware_plus_one=busy?1:0;
    if(busy)g_arm64_scheduler_cpus[0].kernel_execution_depth=1;
}
int main(void) {
    frame_t user={0}, kernel={5};
    unsigned peer=4;
    reset(0);
    g_arm64_scheduler_cpus[0].kernel_execution_waiting=1;
    g_arm64_scheduler_cpus[2].kernel_execution_waiting=1;
    CHECK(kernel_execution_peer_waiting(1, &peer) && peer == 2);
    CHECK(kernel_execution_peer_waiting(3, &peer) && peer == 0);
    reset(1); dispatch(&user);
    CHECK(blocking_entries == 1 && wake_events == 1 && preemptions == 1);
    CHECK(!active && completions == 1 && acknowledgements == 1);
    CHECK(g_kernel_execution_owner_hardware_plus_one == 2);
    reset(0); dispatch(&user);
    CHECK(!blocking_entries && !wake_events && preemptions == 1);
    CHECK(!active && completions == 1);
    reset(1); dispatch(&kernel);
    CHECK(!blocking_entries && !preemptions && !active && completions == 1);
    reset(1); dispatch(NULL);
    CHECK(!blocking_entries && !preemptions && !active && completions == 1);
    reset(1); g_arm64_scheduler_cpus[1].kernel_execution_waiting=1; dispatch(&user);
    CHECK(!blocking_entries && !preemptions && !active && completions == 1);
    puts("ARM reschedule wake PASS"); return 0;
}
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    review = ROOT / '.repair-review/desktop-kernel-fixes-20260910/sgi-wake'
    review.mkdir(parents=True, exist_ok=True)
    irq = (ROOT / 'src/arch/arm64/kernel/interrupt.c').read_text()
    runtime = (ROOT / 'src/arch/arm64/kernel/bootstrap_runtime.c').read_text()
    branch = irq.split('} else if (intid == ARM64_RESCHEDULE_SGI) {', 1)[1].split('} else if (intid == ARM64_CALL_SGI)', 1)[0]
    branch = branch.replace('__asm__ __volatile__("dmb ish" ::: "memory");', '__atomic_thread_fence(__ATOMIC_SEQ_CST);')
    release = function(runtime, 'static int kernel_execution_peer_waiting(') + '\n' + function(runtime, 'void edgeos_arm64_kernel_execution_exit(void)')
    release = release.replace('__asm__ __volatile__("dsb ishst" ::: "memory");', '__atomic_thread_fence(__ATOMIC_SEQ_CST);')
    release = release.replace('__asm__ __volatile__("sev" ::: "memory");', '++wake_events;')
    release = release.replace('__asm__ __volatile__("msr daif, %0" :: "r"(flags) : "memory");', '(void)flags;')
    old = 'edgeos_arm64_smp_reschedule_acknowledge(); execution_locked = edgeos_arm64_kernel_execution_try_enter();'
    for name, body in [('fixed', branch), ('negative', old)]:
        source = PRELUDE + release + ENTER + '\nstatic void dispatch(frame_t *frame) {\n uint64_t iar=1; int execution_locked=0, irq_completed=0;\n' + body + '\n if (!irq_completed) arm64_irq_complete(iar);\n if (execution_locked && frame && !(frame->spsr & 15)) ++preemptions;\n}\n' + TESTS
        path = review / f'{name}.c'
        path.write_text(source)
        binary = output / f'arm64_sgi_{name}'
        subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', str(path), '-o', str(binary)], check=True)
        result = subprocess.run([str(binary)], capture_output=True, text=True)
        (output / f'{name}.log').write_text(result.stdout + result.stderr)
        if name == 'fixed':
            if result.returncode: raise RuntimeError(result.stderr)
            print(result.stdout.strip())
        else:
            if result.returncode != 1 or 'blocking_entries == 1' not in result.stderr:
                raise RuntimeError('Old SGI branch did not fail the busy-owner regression check')
            print('Old SGI branch negative control: expected failure PASS')


if __name__ == '__main__':
    main()
