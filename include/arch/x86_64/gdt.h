#ifndef GDT_H
#define GDT_H

#include <stdint.h>

void gdt_init(void);
void gdt_init_cpu(uint32_t logical_id);
void gdt_set_tss_rsp0(uint64_t rsp0);
uint64_t gdt_get_tss_rsp0(void);
uint64_t *gdt_current_tss_descriptor(void);
void *gdt_current_tss(void);
uint64_t *gdt_current_base(void);
void gdt_load_ldt(const uint64_t *entries, uint32_t entry_count);
void gdt_load_tls(const uint64_t entries[3]);

#endif
