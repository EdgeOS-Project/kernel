#!/usr/bin/env python3
"""Exercise production timer rearm/idle/rseq code with host register shims."""
import argparse
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
COMMON = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include "kernel/timer_alarm.h"
#include "kernel/timer_policy.h"
#include "kernel/deferred_work.h"
#define EDGE_SMP_MAX_CPUS 4u
static uint32_t test_cpu;
static uint64_t test_now, test_global_deadline;
static int test_irq_masked;
uint64_t boottime_monotonic_us(void) { return test_now; }
uint64_t kernel_display_deadline(void) { return test_global_deadline; }
static uint64_t irq_save(void) {
    uint64_t old = test_irq_masked;
    test_irq_masked = 1;
    return old;
}
static void irq_restore(uint64_t flags) { test_irq_masked = (int)flags; }
'''

APIC_SHIM = r'''
#include "drivers/apic.h"
static uint32_t registers[4][256];
static uint32_t write_counts[4][256];
static uint64_t clocksource_hz = 1000000000u;
static uint32_t x86_smp_current_cpu_id(void) { return test_cpu; }
static uint64_t boottime_clocksource_hz(void) { return clocksource_hz; }
static uint64_t apic_timer_irq_save(void) { return irq_save(); }
static void apic_timer_irq_restore(uint64_t flags) { irq_restore(flags); }
static void lapic_write(uint32_t reg, uint32_t value) {
    assert(test_irq_masked);
    registers[test_cpu][reg / 4u] = value;
    write_counts[test_cpu][reg / 4u]++;
    if (reg == APIC_REG_TIMER_INITIAL)
        registers[test_cpu][APIC_REG_TIMER_CURRENT / 4u] = value;
}
static uint32_t lapic_read(uint32_t reg) {
    return registers[test_cpu][reg / 4u];
}
static void apic_delay_us(uint64_t delay) {
    test_now += delay;
    registers[test_cpu][APIC_REG_TIMER_CURRENT / 4u] -= (uint32_t)(delay * 100u);
}
'''

APIC_TEST = r'''
int main(void) {
    g_lapic = registers[0];
    assert(apic_timer_init_alarms() == 0);
    assert(!test_irq_masked && test_now == 10000u);
    assert(lapic_read(APIC_REG_LVT_TIMER) & APIC_LVT_MASKED);
    kernel_arch_display_deadline_request(15000u);
    assert(lapic_read(APIC_REG_LVT_TIMER) == APIC_TIMER_VECTOR);
    assert(lapic_read(APIC_REG_TIMER_INITIAL) == 500000u);
    {
        uint32_t initial_writes =
            write_counts[0][APIC_REG_TIMER_INITIAL / 4u];
        uint32_t lvt_writes = write_counts[0][APIC_REG_LVT_TIMER / 4u];
        kernel_arch_display_deadline_request(16000u);
        assert(write_counts[0][APIC_REG_TIMER_INITIAL / 4u] ==
               initial_writes);
        assert(write_counts[0][APIC_REG_LVT_TIMER / 4u] == lvt_writes);
    }
    assert(apic_timer_arm_oneshot_us(5u) == 0);
    assert(lapic_read(APIC_REG_TIMER_INITIAL) == 500u);
    test_now = 10002u;
    apic_timer_cancel_oneshot();
    assert(lapic_read(APIC_REG_TIMER_INITIAL) == 499800u);
    assert(!g_apic_alarms[0].periodic_enabled);
    test_now = 15000u; test_irq_masked = 1;
    assert(apic_timer_interrupt() == KERNEL_TIMER_ALARM_DISPLAY);
    assert(lapic_read(APIC_REG_LVT_TIMER) & APIC_LVT_MASKED);
    test_irq_masked = 0;
    test_cpu = 1u;
    assert(apic_timer_init(100u) == 0);
    assert(g_apic_alarms[1].periodic_deadline_us == 35000u);
    kernel_arch_display_deadline_request(27000u);
    apic_timer_pause_periodic();
    assert(lapic_read(APIC_REG_LVT_TIMER) == APIC_TIMER_VECTOR);
    assert(lapic_read(APIC_REG_TIMER_INITIAL) == 200000u);
    test_now = 27000u; test_irq_masked = 1;
    assert(apic_timer_interrupt() == KERNEL_TIMER_ALARM_DISPLAY);
    assert(lapic_read(APIC_REG_LVT_TIMER) & APIC_LVT_MASKED);
    test_irq_masked = 0; test_now = 28000u;
    apic_timer_resume_periodic();
    assert(lapic_read(APIC_REG_TIMER_INITIAL) == 700000u);
    kernel_arch_display_deadline_request(35000u);
    assert(apic_timer_arm_oneshot_us(7000u) == 0);
    test_now = 35000u; test_irq_masked = 1;
    assert(apic_timer_interrupt() == (KERNEL_TIMER_ALARM_PERIODIC |
        KERNEL_TIMER_ALARM_DISPLAY | KERNEL_TIMER_ALARM_RSEQ));
    assert(g_apic_alarms[1].periodic_deadline_us == 45000u);
    test_irq_masked = 0;
    test_cpu = 2u; clocksource_hz = 0u;
    assert(apic_timer_init(100u) == 0);
    assert(lapic_read(APIC_REG_LVT_TIMER) & APIC_LVT_TIMER_PERIODIC);
    assert(apic_timer_arm_oneshot_us(5u) == -1);
    apic_timer_pause_periodic();
    assert(lapic_read(APIC_REG_LVT_TIMER) & APIC_LVT_MASKED);
    apic_timer_resume_periodic();
    assert(lapic_read(APIC_REG_LVT_TIMER) & APIC_LVT_TIMER_PERIODIC);
    assert(apic_timer_interrupt() == KERNEL_TIMER_ALARM_PERIODIC);
    test_cpu = 1u;
    kernel_arch_wait_deadline_request(test_now + 10u);
    assert(g_apic_alarms[test_cpu].wait_deadline_us == test_now + 10u);
    test_now += 10u; test_irq_masked = 1;
    assert(apic_timer_interrupt() & KERNEL_TIMER_ALARM_WAIT);
    puts("timer_alarm_arch_unit: x86 APIC PASS");
    return 0;
}
'''

ARM_SHIM = r'''
static uint64_t test_compare[4], test_control[4];
static uint32_t edgeos_arm64_smp_current_cpu(void) { return test_cpu; }
static uint32_t edge_smp_present_count(void) { return 4u; }
static uint64_t arm64_timer_irq_save(void) { return irq_save(); }
static void arm64_timer_irq_restore(uint64_t flags) { irq_restore(flags); }
'''

ARM_TEST = r'''
int main(void) {
    arm64_timer_enable();
    assert(!test_irq_masked && test_compare[0] == 10000u);
    test_now = 1000u;
    kernel_arch_display_deadline_request(4000u);
    kernel_arch_display_deadline_request(2000u);
    kernel_arch_display_deadline_request(6000u);
    assert(test_compare[0] == 2000u);
    assert(edgeos_arm64_timer_arm_rseq_slice(5u) == 0);
    assert(test_compare[0] == 1005u);
    test_now = 1005u;
    assert(arm64_timer_interrupt() == KERNEL_TIMER_ALARM_RSEQ);
    assert(test_compare[0] == 2000u);
    assert(g_arm64_alarms[0].periodic_deadline_us == 10000u);
    test_now = 2000u;
    assert(arm64_timer_interrupt() == KERNEL_TIMER_ALARM_DISPLAY);
    assert(test_compare[0] == 10000u);
    kernel_arch_display_deadline_request(3500u);
    assert(edgeos_arm64_timer_arm_rseq_slice(5u) == 0);
    edgeos_arm64_timer_cancel_rseq_slice();
    assert(test_compare[0] == 3500u);
    test_cpu = 1u; test_now = 5000u;
    arm64_timer_enable();
    assert(test_compare[1] == 17500u);
    kernel_arch_display_deadline_request(6000u);
    edgeos_arm64_timer_enter_idle();
    assert(!g_arm64_alarms[1].periodic_enabled);
    assert(test_control[1] == 1u && test_compare[1] == 6000u);
    test_now = 6000u;
    assert(arm64_timer_interrupt() == KERNEL_TIMER_ALARM_DISPLAY);
    assert(test_control[1] == 3u);
    test_now = 7000u;
    edgeos_arm64_timer_leave_idle();
    assert(test_control[1] == 1u && test_compare[1] == 17500u);
    test_now = 7500u;
    edgeos_arm64_timer_leave_idle();
    assert(test_compare[1] == 17500u);
    g_kvm_slice_cpu_mask = 1u;
    edgeos_arm64_timer_enter_idle();
    assert(g_arm64_alarms[1].periodic_enabled && test_control[1] == 1u);
    g_kvm_slice_cpu_mask = 0u;
    edgeos_arm64_timer_enter_idle();
    assert(!g_arm64_alarms[1].periodic_enabled && test_control[1] == 3u);
    kernel_arch_wait_deadline_request(7600u);
    assert(test_compare[1] == 7600u && test_control[1] == 1u);
    test_now = 7600u; test_irq_masked = 1;
    assert(arm64_timer_interrupt() == KERNEL_TIMER_ALARM_WAIT);
    assert(!g_arm64_alarms[1].periodic_enabled);
    puts("timer_alarm_arch_unit: ARM CVAL PASS");
    return 0;
}
'''


def arm_register_shim(match):
    statement = match[0]
    for register, replacement in (
            ('cntvct_el0', 'counter = test_now;'),
            ('cntv_cval_el0', 'test_compare[cpu] = compare;'),
            ('cntv_ctl_el0', 'test_control[cpu] = control;'),
            ('cntfrq_el0', 'frequency = 1000000u;')):
        if register in statement:
            return replacement
    if 'cntkctl_el1' in statement:
        return 'cntkctl = 0u;' if 'mrs' in statement else '(void)cntkctl;'
    raise AssertionError('Unrecognized register operation: ' + statement)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', required=True, type=Path)
    output = parser.parse_args().output_dir.resolve()
    volume = Path('/Volumes/EdwardData')
    if not volume.is_mount() or not output.is_relative_to(volume / 'EdgeOS'):
        parser.error('output must be on mounted /Volumes/EdwardData/EdgeOS')
    output.mkdir(parents=True, exist_ok=True)
    source_output = ROOT / '.repair-review/desktop-kernel-fixes-20260910/highres-timer'
    source_output.mkdir(parents=True, exist_ok=True)
    apic = (ROOT / 'src/drivers/interrupt/apic.c').read_text()
    arm = (ROOT / 'src/arch/arm64/kernel/interrupt.c').read_text()
    apic_declarations = '\n'.join(line for line in apic.splitlines()
        if line.startswith(('static kernel_timer_alarm_t g_apic_', 'static uint64_t g_apic_timer_',
                            'static uint32_t g_apic_timer_', 'static uint8_t g_apic_timer_',
                            'static volatile uint32_t *g_lapic;')))
    apic_defines = '\n'.join(line for line in apic.splitlines()
        if line.startswith(('#define APIC_REG_TIMER_', '#define APIC_REG_LVT_TIMER',
                            '#define APIC_LVT_MASKED', '#define APIC_LVT_TIMER_PERIODIC')))
    apic_code = apic[apic.index('static void apic_timer_write_lvt('):apic.index('int apic_available(')]
    arm_declarations = '\n'.join(line for line in arm.splitlines()
        if line.startswith(('static kernel_timer_alarm_t g_arm64_', 'static uint64_t g_arm64_timer_',
                            'static uint8_t g_arm64_timer_', 'static volatile uint32_t g_kvm_slice_cpu_mask;')))
    broadcaster_start = arm.index('static uint32_t arm64_kvm_broadcaster_cpu(')
    broadcaster = arm[broadcaster_start:arm.index('\n}\n', broadcaster_start) + 3]
    arm_code = arm[arm.index('static void arm64_timer_rearm('):arm.index('void edgeos_arm64_exceptions_init(')]
    arm_code = re.sub(r'__asm__ __volatile__\(.*?\);', arm_register_shim, arm_code, flags=re.S)
    assert '__asm__' not in arm_code
    for name, source in (
            ('apic', COMMON + apic_defines + '\n' + apic_declarations + APIC_SHIM + apic_code + APIC_TEST),
            ('arm64', COMMON + arm_declarations + ARM_SHIM + broadcaster + arm_code + ARM_TEST)):
        path = source_output / ('timer_alarm_' + name + '_unit.c')
        binary = output / ('timer_alarm_' + name + '_unit')
        path.write_text(source)
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra',
                        '-Werror', '-iquote', str(ROOT / 'include'), str(path),
                        '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == '__main__':
    main()
