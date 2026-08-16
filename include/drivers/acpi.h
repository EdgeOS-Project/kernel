// SPDX-License-Identifier: MPL-2.0
/*
 * ACPI firmware table discovery for EdgeOS.
 *
 * Copyright (c) EdgeOS Contributors.
 *
 * ACPI is the firmware source of truth for modern x86 interrupt routing,
 * timers, power devices, batteries, lid/buttons, PCIe configuration windows,
 * and many platform devices.  Keep this layer table-driven and Linux-ABI
 * neutral: drivers may consume the discovered hardware topology, but userland
 * compatibility must be implemented through Linux-compatible kernel APIs.
 */

#ifndef EDGEOS_DRIVERS_ACPI_H
#define EDGEOS_DRIVERS_ACPI_H

#include <stdint.h>

struct acpi_table_info {
    char signature[5];
    uint64_t address;
    uint32_t length;
    uint8_t revision;
};

struct acpi_hpet_info {
    uint32_t event_timer_block_id;
    uint64_t address;
    uint8_t address_space_id;
    uint8_t hpet_number;
    uint16_t minimum_tick;
    uint8_t page_protection;
};

struct acpi_mcfg_window {
    uint64_t base_address;
    uint16_t segment;
    uint8_t start_bus;
    uint8_t end_bus;
};

struct acpi_ioapic_info {
    uint8_t id;
    uint32_t address;
    uint32_t global_irq_base;
};

struct acpi_irq_override_info {
    uint8_t bus;
    uint8_t source_irq;
    uint32_t global_irq;
    uint16_t flags;
};

#define EDGE_ACPI_CPU_ENABLED (1u << 0)
#define EDGE_ACPI_CPU_ONLINE_CAPABLE (1u << 1)

struct acpi_processor_info {
    uint32_t processor_uid;
    uint32_t apic_id;
    uint32_t flags;
    uint8_t x2apic;
};

#define EDGE_ACPI_BATTERY_TEXT_SIZE 33
#define EDGE_ACPI_BATTERY_VALUE_UNKNOWN UINT32_MAX
#define EDGE_ACPI_BATTERY_STATE_DISCHARGING 0x0001u
#define EDGE_ACPI_BATTERY_STATE_CHARGING 0x0002u
#define EDGE_ACPI_BATTERY_STATE_CRITICAL 0x0004u
#define EDGE_ACPI_BATTERY_ATTR_CAPACITY (1u << 0)
#define EDGE_ACPI_BATTERY_ATTR_TECHNOLOGY (1u << 1)
#define EDGE_ACPI_BATTERY_ATTR_SERIAL (1u << 2)
#define EDGE_ACPI_BATTERY_ATTR_CYCLE_COUNT (1u << 3)
#define EDGE_ACPI_BATTERY_ATTR_VOLTAGE_NOW (1u << 4)
#define EDGE_ACPI_BATTERY_ATTR_VOLTAGE_DESIGN (1u << 5)
#define EDGE_ACPI_BATTERY_ATTR_STORAGE (1u << 6)
#define EDGE_ACPI_BATTERY_ATTR_RATE (1u << 7)
#define EDGE_ACPI_BATTERY_ATTR_TIME_TO_EMPTY (1u << 8)

struct edge_acpi_battery_info {
    uint32_t present;
    uint32_t state;
    uint32_t units;
    uint32_t design_capacity;
    uint32_t full_capacity;
    uint32_t remaining_capacity;
    uint32_t rate;
    uint32_t voltage;
    uint32_t design_voltage;
    uint32_t cycle_count;
    int32_t capacity_percent;
    int32_t remaining_minutes;
    char model[EDGE_ACPI_BATTERY_TEXT_SIZE];
    char serial[EDGE_ACPI_BATTERY_TEXT_SIZE];
    char technology[EDGE_ACPI_BATTERY_TEXT_SIZE];
    char manufacturer[EDGE_ACPI_BATTERY_TEXT_SIZE];
};

void acpi_init(uint32_t boot_magic, void *boot_info);
int acpi_available(void);
uint64_t acpi_rsdp_address(void);
uint64_t acpi_rsdt_address(void);
uint64_t acpi_xsdt_address(void);
uint32_t acpi_table_count(void);
int acpi_get_table(uint32_t index, struct acpi_table_info *out);
uint64_t acpi_find_table(const char signature[4], uint32_t index);
uint32_t acpi_sysfs_table_count(void);
int acpi_sysfs_table_name(uint32_t index, char *out, uint32_t out_len);
int acpi_sysfs_table_size(const char *name, uint32_t *out_len);
int acpi_sysfs_table_read(const char *name, uint32_t offset, char *out,
                          uint32_t max);
uint64_t acpi_fadt_address(void);
uint64_t acpi_dsdt_address(void);
uint64_t acpi_facs_address(void);
uint32_t acpi_lapic_address(void);
uint32_t acpi_ioapic_count(void);
int acpi_get_ioapic(uint32_t index, struct acpi_ioapic_info *out);
uint32_t acpi_hpet_count(void);
int acpi_get_hpet(uint32_t index, struct acpi_hpet_info *out);
uint32_t acpi_local_apic_count(void);
uint32_t acpi_processor_count(void);
int acpi_get_processor(uint32_t index, struct acpi_processor_info *out);
uint32_t acpi_interrupt_override_count(void);
int acpi_get_interrupt_override(uint32_t index, struct acpi_irq_override_info *out);
uint32_t acpi_mcfg_count(void);
int acpi_get_mcfg(uint32_t index, struct acpi_mcfg_window *out);
uint32_t acpi_has_ac_adapter(void);
uint32_t acpi_has_battery(void);
int acpi_get_ac_adapter_online(int *online);
int acpi_get_battery_info(uint32_t unit,
                          struct edge_acpi_battery_info *information);
uint32_t acpi_battery_attribute_mask(
    const struct edge_acpi_battery_info *information);
uint32_t acpi_has_power_button(void);
uint32_t acpi_has_sleep_button(void);
uint32_t acpi_has_lid_switch(void);
uint32_t acpi_has_thermal_zone(void);
uint32_t acpi_pm_profile(void);
int acpi_platform_snapshot(char *buf, uint32_t max);
int acpi_poweroff(void);

#endif
