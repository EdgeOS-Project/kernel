#ifndef EDGEOS_FREEBSD_LINUXKPI_NOUVEAU_NV04_INSTMEM_COMPAT_H
#define EDGEOS_FREEBSD_LINUXKPI_NOUVEAU_NV04_INSTMEM_COMPAT_H

#ifdef bus_space_vaddr
#undef bus_space_vaddr
#endif
#define bus_space_vaddr(_tag, _handle) ((void *)device->pri)

#endif
