#ifndef EDGEOS_NOUVEAU_LEGACY_DRM_IRQ_COMPAT_H
#define EDGEOS_NOUVEAU_LEGACY_DRM_IRQ_COMPAT_H

#include <linux/vgaarb.h>

static inline int
edgeos_nouveau_vga_client_register(struct pci_dev *pdev, void *cookie,
    void (*irq_set_state)(void *, bool),
    unsigned int (*set_vga_decode)(void *, bool))
{
	return vga_client_register(pdev, NULL);
}

#define vga_client_register edgeos_nouveau_vga_client_register

#endif
