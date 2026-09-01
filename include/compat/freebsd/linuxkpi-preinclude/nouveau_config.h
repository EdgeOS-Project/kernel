#ifndef EDGEOS_FREEBSD_LINUXKPI_NOUVEAU_CONFIG_H
#define EDGEOS_FREEBSD_LINUXKPI_NOUVEAU_CONFIG_H

#include <linux/wait.h>
#include <linux/dma-resv.h>
#include <linux/fb.h>
#include <linux/ioctl.h>
#include <linux/jiffies.h>
#include <linux/hrtimer.h>
#include <linux/iommu.h>
#include <linux/dma-mapping.h>
#include <linux/refcount.h>
#include <machine/_inttypes.h>
#include <sys/sysctl.h>

#ifndef _DRM_LEASE_H
#define _DRM_LEASE_H
#endif
#include <external/bsd/drm2/include/drm/drm_lease.h>

SYSCTL_DECL(_hw_nouveau);

#define fb_info linux_fb_info

#ifndef FBINFO_HWACCEL_DISABLED
#define FBINFO_HWACCEL_DISABLED 0x1000
#define FBINFO_HWACCEL_COPYAREA 0x2000
#define FBINFO_HWACCEL_FILLRECT 0x4000
#define FBINFO_HWACCEL_IMAGEBLIT 0x8000
#endif

#ifndef __KERNEL_RCSID
#define __KERNEL_RCSID(_n, _s)
#endif

#ifndef __UNVOLATILE
#define __UNVOLATILE(_pointer) ((void *)(uintptr_t)(_pointer))
#endif

#ifndef __UNCONST
#define __UNCONST(_pointer) ((void *)(uintptr_t)(const void *)(_pointer))
#endif

#ifndef LIST_HEAD_INIT
#define LIST_HEAD_INIT(_head) { &(_head), &(_head) }
#endif

#ifndef voidop
static inline void
edgeos_nouveau_voidop(void)
{
}
#define voidop edgeos_nouveau_voidop
#endif

#ifndef const_container_of
#define const_container_of(_pointer, _type, _member) \
	((const _type *)((const char *)(_pointer) - offsetof(_type, _member)))
#endif

#ifndef DRM_IRQ_ARGS
#define DRM_IRQ_ARGS int irq, void *arg
#endif

typedef wait_queue_head_t drm_waitqueue_t;

static inline struct dma_fence *
edgeos_dma_resv_get_excl(struct dma_resv *resv)
{
	struct dma_resv_iter cursor;
	struct dma_fence *fence;

	dma_resv_iter_begin(&cursor, resv, DMA_RESV_USAGE_WRITE);
	for (fence = dma_resv_iter_first(&cursor); fence != NULL;
	    fence = dma_resv_iter_next(&cursor)) {
		if (dma_resv_iter_usage(&cursor) == DMA_RESV_USAGE_WRITE)
			return fence;
	}
	return NULL;
}

static inline struct dma_fence *
edgeos_dma_resv_get_excl_rcu(struct dma_resv *resv)
{
	struct dma_fence *fence = NULL;

	if (dma_resv_get_singleton(resv, DMA_RESV_USAGE_WRITE, &fence) != 0)
		return NULL;
	return fence;
}

static inline int
edgeos_dma_resv_reserve_shared(struct dma_resv *resv, unsigned int count)
{
	return dma_resv_reserve_fences(resv, count);
}

static inline void
edgeos_dma_resv_add_excl_fence(struct dma_resv *resv,
    struct dma_fence *fence)
{
	dma_resv_add_fence(resv, fence, DMA_RESV_USAGE_WRITE);
}

static inline void
edgeos_dma_resv_add_shared_fence(struct dma_resv *resv,
    struct dma_fence *fence)
{
	dma_resv_add_fence(resv, fence, DMA_RESV_USAGE_READ);
}

#define dma_resv_get_excl edgeos_dma_resv_get_excl
#define dma_resv_get_excl_rcu edgeos_dma_resv_get_excl_rcu
#define dma_resv_reserve_shared edgeos_dma_resv_reserve_shared
#define dma_resv_add_excl_fence edgeos_dma_resv_add_excl_fence
#define dma_resv_add_shared_fence edgeos_dma_resv_add_shared_fence

static inline long
edgeos_dma_resv_wait_timeout_rcu(struct dma_resv *resv, bool write, bool intr,
    unsigned long timeout)
{
	return dma_resv_wait_timeout(resv, dma_resv_usage_rw(write), intr,
	    timeout);
}

#define dma_resv_wait_timeout_rcu edgeos_dma_resv_wait_timeout_rcu

#define spinlock mtx

struct address_space;
struct device;
struct device_link;
struct pci_dev;

#ifndef DL_FLAG_STATELESS
#define DL_FLAG_STATELESS 0
#endif

static inline struct device_link *
device_link_add(struct device *consumer, struct device *supplier, uint32_t flags)
{
	(void)consumer;
	(void)supplier;
	(void)flags;
	return NULL;
}

static inline int
vga_remove_vgacon(struct pci_dev *pdev)
{
	(void)pdev;
	return 0;
}

#ifndef in_atomic
#define in_atomic() 0
#endif

#ifndef in_dbg_master
#define in_dbg_master() 0
#endif

#ifndef irqs_disabled
#define irqs_disabled() 0
#endif

#ifndef swiotlb_nr_tbl
#define swiotlb_nr_tbl() 0
#endif

#ifndef pm_runtime_get
#define pm_runtime_get(_device) 0
#endif

#ifndef pm_runtime_put_sync
#define pm_runtime_put_sync(_device) 0
#endif

#ifndef trace_dma_fence_emit
#define trace_dma_fence_emit(_fence) do { (void)(_fence); } while (0)
#endif

#ifndef destroy_completion
#define destroy_completion(_completion) do { (void)(_completion); } while (0)
#endif

#ifndef schedule_hrtimeout
static inline int
schedule_hrtimeout(ktime_t *expires, enum hrtimer_mode mode)
{
	(void)mode;
	schedule_timeout(nsecs_to_jiffies(*expires));
	return 0;
}
#endif

#ifndef PCI_VENDOR_ID_NVIDIA
#define PCI_VENDOR_ID_NVIDIA 0x10de
#endif
#ifndef PCI_VENDOR_ID_NVIDIA_SGS
#define PCI_VENDOR_ID_NVIDIA_SGS 0x12d2
#endif

#ifndef linux_pci_enable_device
#define linux_pci_enable_device(_device) pci_enable_device(_device)
#endif
#ifndef linux_pci_disable_device
#define linux_pci_disable_device(_device) pci_disable_device(_device)
#endif
#ifndef pci_dev_dev
#define pci_dev_dev(_device) (&(_device)->dev)
#endif

#ifndef pci_enable_rom
#define pci_enable_rom(_device) 0
#endif
#ifndef pci_disable_rom
#define pci_disable_rom(_device) do { (void)(_device); } while (0)
#endif
#ifndef pci_map_rom
#define pci_map_rom(_device, _size) \
	vga_pci_map_bios(device_get_parent((_device)->dev.bsddev), (_size))
#endif
#ifndef pci_unmap_rom
#define pci_unmap_rom(_device, _rom) \
	vga_pci_unmap_bios(device_get_parent((_device)->dev.bsddev), (_rom))
#endif

#ifndef NVIF_IOCTL_V0_MAP_NETBSD
#define NVIF_IOCTL_V0_MAP_NETBSD 0x0d
#endif

#ifndef mmu_notifier_synchronize
#define mmu_notifier_synchronize() do { } while (0)
#endif

#ifndef dma_alloc_attrs
#define dma_alloc_attrs(_device, _size, _handle, _flags, _attributes) \
	dma_alloc_coherent((_device), (_size), (_handle), (_flags))
#endif
#ifndef dma_free_attrs
#define dma_free_attrs(_device, _size, _address, _handle, _attributes) \
	dma_free_coherent((_device), (_size), (_address), (_handle))
#endif

#ifndef IOMMU_READ
#define IOMMU_READ 0x1
#define IOMMU_WRITE 0x2
struct iommu_fwspec {
	u32 ids[1];
};

static inline struct iommu_fwspec *
dev_iommu_fwspec_get(struct device *device)
{
	(void)device;
	return NULL;
}

static inline int
iommu_map(struct iommu_domain *domain, unsigned long address,
    phys_addr_t physical, size_t size, int protection)
{
	(void)domain;
	(void)address;
	(void)physical;
	(void)size;
	(void)protection;
	return -ENODEV;
}

static inline size_t
iommu_unmap(struct iommu_domain *domain, unsigned long address, size_t size)
{
	(void)domain;
	(void)address;
	(void)size;
	return 0;
}
#endif

#ifndef refcount_dec_and_mutex_lock
#define refcount_dec_and_mutex_lock(_count, _mutex) \
	atomic_dec_and_mutex_lock((_count), (_mutex))
#endif

#ifndef kern_kldload
#define kern_kldload(_thread, _module, _file_id) ENOSYS
#endif

#ifndef __arraycount
#define __arraycount(_array) (sizeof(_array) / sizeof((_array)[0]))
#endif

#ifndef regulator_get_voltage
#define regulator_get_voltage(_regulator) (-ENODEV)
#endif
#ifndef regulator_set_voltage
#define regulator_set_voltage(_regulator, _minimum, _maximum) (-ENODEV)
#endif

#ifndef platform_set_drvdata
#define platform_set_drvdata(_device, _data) do { \
	(void)(_device); \
	(void)(_data); \
} while (0)
#endif

#ifndef strcspn
static inline size_t
strcspn(const char *string, const char *reject)
{
	const char *cursor;
	const char *match;

	for (cursor = string; *cursor != '\0'; cursor++) {
		for (match = reject; *match != '\0'; match++) {
			if (*cursor == *match)
				return (size_t)(cursor - string);
		}
	}
	return (size_t)(cursor - string);
}
#endif

#endif
