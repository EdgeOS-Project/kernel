/*-
 * SPDX-License-Identifier: MPL-2.0
 *
 * Raspberry Pi BCM2712 frontend for the FreeBSD SDHCI core.
 */

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/resource.h>
#include <sys/rman.h>
#include <sys/systm.h>

#include <machine/bus.h>
#include <machine/resource.h>

#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/openfirm.h>
#include <dev/clk/clk.h>
#include <dev/clk/clk_fixed.h>
#include <dev/mmc/bridge.h>
#include <dev/phy/phy.h>
#include <dev/sdhci/sdhci.h>
#include <dev/sdhci/sdhci_fdt.h>

#include "sdhci_if.h"

#define BCM2712_SDHCI_CFG_CONTROL 0x000
#define BCM2712_SDHCI_CFG_CARD_PRESENT_ENABLE (1u << 31)
#define BCM2712_SDHCI_CFG_CARD_ABSENT (1u << 30)
#define BCM2712_SDHCI_CFG_TUNING_CONTROL 0x1ac
#define BCM2712_SDHCI_CFG_TUNING_OVERRIDE (1u << 31)
#define BCM2712_SDHCI_CFG_LIMIT_50MHZ (1u << 0)

struct bcm2712_sdhci_softc {
	struct sdhci_fdt_softc	base;
	struct resource		*cfg_res;
	uint64_t		caps_mask;
	uint64_t		caps_value;
};

static bool
bcm2712_sdhci_read_u64(phandle_t node, const char *property,
    uint64_t *value)
{
	pcell_t cells[2];

	if (OF_getencprop(node, property, cells, sizeof(cells)) !=
	    sizeof(cells))
		return (false);
	*value = ((uint64_t)cells[0] << 32) | cells[1];
	return (true);
}

static int
bcm2712_sdhci_probe(device_t dev)
{
	struct bcm2712_sdhci_softc *sc;
	phandle_t node;

	if (!ofw_bus_status_okay(dev) ||
	    !ofw_bus_is_compatible(dev, "brcm,bcm2712-sdhci"))
		return (ENXIO);

	sc = device_get_softc(dev);
	node = ofw_bus_get_node(dev);
	(void)bcm2712_sdhci_read_u64(node, "sdhci-caps-mask",
	    &sc->caps_mask);
	(void)bcm2712_sdhci_read_u64(node, "sdhci-caps",
	    &sc->caps_value);
	device_set_desc(dev, "Broadcom BCM2712 SDHCI controller");
	return (BUS_PROBE_DEFAULT);
}

static void
bcm2712_sdhci_configure(device_t dev,
    struct bcm2712_sdhci_softc *sc)
{
	phandle_t node;
	uint32_t value;

	node = ofw_bus_get_node(dev);
	if (OF_hasprop(node, "sd-uhs-sdr50") ||
	    OF_hasprop(node, "sd-uhs-sdr104")) {
		value = bus_read_4(sc->cfg_res,
		    BCM2712_SDHCI_CFG_TUNING_CONTROL);
		value &= ~BCM2712_SDHCI_CFG_LIMIT_50MHZ;
		value |= BCM2712_SDHCI_CFG_TUNING_OVERRIDE;
		bus_write_4(sc->cfg_res,
		    BCM2712_SDHCI_CFG_TUNING_CONTROL, value);
	}

	if (OF_hasprop(node, "non-removable") ||
	    OF_hasprop(node, "broken-cd")) {
		value = bus_read_4(sc->cfg_res,
		    BCM2712_SDHCI_CFG_CONTROL);
		value &= ~BCM2712_SDHCI_CFG_CARD_ABSENT;
		value |= BCM2712_SDHCI_CFG_CARD_PRESENT_ENABLE;
		bus_write_4(sc->cfg_res, BCM2712_SDHCI_CFG_CONTROL, value);
	}
}

static int
bcm2712_sdhci_attach(device_t dev)
{
	struct bcm2712_sdhci_softc *sc;
	int error;
	int rid;

	sc = device_get_softc(dev);
	rid = 1;
	sc->cfg_res = bus_alloc_resource_any(dev, SYS_RES_MEMORY, &rid,
	    RF_ACTIVE);
	if (sc->cfg_res == NULL) {
		device_printf(dev, "cannot allocate configuration registers\n");
		return (ENXIO);
	}

	bcm2712_sdhci_configure(dev, sc);
	error = sdhci_fdt_attach(dev);
	if (error != 0) {
		bus_release_resource(dev, SYS_RES_MEMORY,
		    rman_get_rid(sc->cfg_res), sc->cfg_res);
		sc->cfg_res = NULL;
	}
	return (error);
}

static int
bcm2712_sdhci_detach(device_t dev)
{
	struct bcm2712_sdhci_softc *sc;
	int error;

	sc = device_get_softc(dev);
	error = sdhci_fdt_detach(dev);
	if (sc->cfg_res != NULL) {
		bus_release_resource(dev, SYS_RES_MEMORY,
		    rman_get_rid(sc->cfg_res), sc->cfg_res);
		sc->cfg_res = NULL;
	}
	return (error);
}

static uint32_t
bcm2712_sdhci_read_4(device_t dev, struct sdhci_slot *slot,
    bus_size_t offset)
{
	struct bcm2712_sdhci_softc *sc;
	uint32_t mask;
	uint32_t value;
	unsigned int shift;

	sc = device_get_softc(dev);
	value = bus_read_4(sc->base.mem_res[slot->num], offset);
	if (offset != SDHCI_CAPABILITIES &&
	    offset != SDHCI_CAPABILITIES2)
		return (value);

	shift = offset == SDHCI_CAPABILITIES ? 0 : 32;
	mask = (uint32_t)(sc->caps_mask >> shift);
	return ((value & ~mask) |
	    ((uint32_t)(sc->caps_value >> shift) & mask));
}

static device_method_t bcm2712_sdhci_methods[] = {
	DEVMETHOD(device_probe,		bcm2712_sdhci_probe),
	DEVMETHOD(device_attach,	bcm2712_sdhci_attach),
	DEVMETHOD(device_detach,	bcm2712_sdhci_detach),
	DEVMETHOD(sdhci_read_4,	bcm2712_sdhci_read_4),
	DEVMETHOD_END
};

extern driver_t sdhci_fdt_driver;

DEFINE_CLASS_1(sdhci_bcm2712, bcm2712_sdhci_driver,
    bcm2712_sdhci_methods, sizeof(struct bcm2712_sdhci_softc),
    sdhci_fdt_driver);
DRIVER_MODULE(sdhci_bcm2712, simplebus, bcm2712_sdhci_driver, NULL, NULL);
SDHCI_DEPEND(sdhci_bcm2712);
