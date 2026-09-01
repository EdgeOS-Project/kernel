#ifndef EDGEOS_FREEBSD_LINUXKPI_NOUVEAU_CLK_COMPAT_H
#define EDGEOS_FREEBSD_LINUXKPI_NOUVEAU_CLK_COMPAT_H

#include <linux/spinlock.h>

static spinlock_t edgeos_nouveau_clk_lock;

static inline void edgeos_nouveau_clk_lock_acquire(void)
{
	spin_lock(&edgeos_nouveau_clk_lock);
}

static inline void edgeos_nouveau_clk_lock_release(void)
{
	spin_unlock(&edgeos_nouveau_clk_lock);
}

static inline void edgeos_nouveau_clk_lock_init(void)
{
	spin_lock_init(&edgeos_nouveau_clk_lock);
}

static inline void edgeos_nouveau_clk_lock_destroy(void)
{
	spin_lock_destroy(&edgeos_nouveau_clk_lock);
}

#undef spin_lock
#undef spin_unlock
#undef spin_lock_init
#undef spin_lock_destroy
#define spin_lock(_lock) edgeos_nouveau_clk_lock_acquire()
#define spin_unlock(_lock) edgeos_nouveau_clk_lock_release()
#define spin_lock_init(_lock) edgeos_nouveau_clk_lock_init()
#define spin_lock_destroy(_lock) edgeos_nouveau_clk_lock_destroy()

#endif
