#ifndef GDT_H
#define GDT_H

#include <stdint.h>

void gdt_init(void);
void gdt_init_cpu(uint32_t logical_id);
void gdt_set_tss_rsp0(uint64_t rsp0);
uint64_t gdt_get_tss_rsp0(void);
void gdt_load_ldt(const uint64_t *entries, uint32_t entry_count);

#endif
