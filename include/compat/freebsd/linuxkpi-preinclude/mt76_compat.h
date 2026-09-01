#ifndef EDGEOS_FREEBSD_MT76_COMPAT_H
#define EDGEOS_FREEBSD_MT76_COMPAT_H

struct dentry;
struct device;
struct seq_file;

/* The imported FreeBSD module configuration enables only the PCI bus. */
#ifdef CONFIG_USB
#undef CONFIG_USB
#endif

#ifdef CONFIG_ACPI
#undef CONFIG_ACPI
#endif

#define page_pool_alloc_frag(pool, offset, size, gfp) \
    page_pool_dev_alloc_frag((pool), (offset), (size))

#ifndef IF_NAMESIZE
#define IF_NAMESIZE IFNAMSIZ
#endif

#define system_percpu_wq system_unbound_wq

#define IEEE80211_EML_CAP_EMLSR_PADDING_DELAY \
    IEEE80211_EML_CAP_EML_PADDING_DELAY
#define IEEE80211_EML_CAP_EMLSR_TRANSITION_DELAY \
    IEEE80211_EML_CAP_EML_TRANSITION_DELAY

static inline void
debugfs_create_devm_seqfile(struct device *device, const char *name,
    struct dentry *parent, int (*read_fn)(struct seq_file *, void *))
{
    (void)device;
    (void)name;
    (void)parent;
    (void)read_fn;
}

#endif
