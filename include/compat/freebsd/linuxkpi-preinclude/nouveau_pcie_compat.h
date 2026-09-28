#ifndef EDGEOS_FREEBSD_LINUXKPI_NOUVEAU_PCIE_COMPAT_H
#define EDGEOS_FREEBSD_LINUXKPI_NOUVEAU_PCIE_COMPAT_H

#include <nvkm/subdev/pci.h>

static inline enum nvkm_pcie_speed
edgeos_nouveau_pcie_bus_cap(struct pci_dev *device,
    enum nvkm_pcie_speed device_cap)
{
	enum nvkm_pcie_speed bus_cap;

	switch (pcie_get_speed_cap(device)) {
	case PCIE_SPEED_5_0GT:
		bus_cap = NVKM_PCIE_SPEED_5_0;
		break;
	case PCIE_SPEED_8_0GT:
	case PCIE_SPEED_16_0GT:
	case PCIE_SPEED_32_0GT:
	case PCIE_SPEED_64_0GT:
		bus_cap = NVKM_PCIE_SPEED_8_0;
		break;
	default:
		bus_cap = NVKM_PCIE_SPEED_2_5;
		break;
	}
	return bus_cap < device_cap ? bus_cap : device_cap;
}

#undef min
#define min(_unused_bus_expression, _device_cap) \
	edgeos_nouveau_pcie_bus_cap(pci->pdev, (_device_cap))

#endif
