#include "drivers/usb_dma.h"
#include "drivers/usb_dma_layout.h"

#include "string.h"
#include "stdio.h"

/*
 * One xHCI controller may request up to 1023 page-sized scratchpads.  Reserve
 * enough low device-visible memory for two such 4 KiB-page controllers plus
 * their rings, contexts, mass-storage buffers, and retry headroom.
 */
#define USB_DMA_POOL_SIZE (16u * 1024u * 1024u)

/* Current kernel maps low memory directly enough that device-visible physical
 * addresses for static kernel memory are obtained by casting pointers. This is
 * the same assumption used by existing AHCI code paths.
 */
static uint8_t g_usb_dma_pool[USB_DMA_POOL_SIZE] __attribute__((aligned(4096)));
static uint32_t g_usb_dma_off;

void usb_dma_init(void) {
    g_usb_dma_off = 0;
    memset(g_usb_dma_pool, 0, sizeof(g_usb_dma_pool));
    printf("[usb][dma] pool %u KiB at %p\n", (uint32_t)(USB_DMA_POOL_SIZE / 1024u), g_usb_dma_pool);
}

static int usb_dma_alloc_internal(uint32_t size, uint32_t align,
                                  uint32_t boundary, usb_dma_block_t *out) {
    uint32_t off, next;
    uintptr_t base, current, aligned;
    if (!out || size == 0) return -1;
    if (align == 0) align = 16;
    base = (uintptr_t)g_usb_dma_pool;
    current = base + (uintptr_t)g_usb_dma_off;
    if (current < base ||
        usb_dma_layout_start(current, size, align, boundary, &aligned) < 0)
        return -1;
    if (aligned < base || aligned > UINT32_MAX ||
        aligned - base > UINT32_MAX)
        return -1;
    off = (uint32_t)(aligned - base);
    next = off + size;
    if (next < off || next > USB_DMA_POOL_SIZE) return -1;
    out->vaddr = &g_usb_dma_pool[off];
    out->paddr = (uint32_t)(uintptr_t)out->vaddr;
    out->size = size;
    g_usb_dma_off = next;
    return 0;
}

int usb_dma_alloc(uint32_t size, uint32_t align, usb_dma_block_t *out) {
    return usb_dma_alloc_internal(size, align, 0, out);
}

int usb_dma_alloc_zero(uint32_t size, uint32_t align, usb_dma_block_t *out) {
    if (usb_dma_alloc(size, align, out) < 0) return -1;
    memset(out->vaddr, 0, size);
    return 0;
}

int usb_dma_alloc_zero_boundary(uint32_t size, uint32_t align,
                                uint32_t boundary, usb_dma_block_t *out) {
    if (usb_dma_alloc_internal(size, align, boundary, out) < 0) return -1;
    memset(out->vaddr, 0, size);
    return 0;
}

uint32_t usb_dma_bytes_total(void) { return USB_DMA_POOL_SIZE; }
uint32_t usb_dma_bytes_used(void) { return g_usb_dma_off; }
