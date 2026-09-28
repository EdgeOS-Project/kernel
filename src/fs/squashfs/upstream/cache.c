/*
 * Copyright (c) 2012 Dave Vasilevsky <dave@vasilevsky.ca>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"

#if defined(EDGEOS_SQFS_HOST_TEST) && !defined(EDGEOS_SQFS_RUNTIME_TEST)

#include "cache.h"

#include "fs.h"

#include "sqfs_port.h"
#include "sqfs_port.h"

typedef struct sqfs_cache_internal {
	uint8_t *buf;

	sqfs_cache_dispose dispose;

	size_t size, count;
	size_t next; /* next block to evict */
} sqfs_cache_internal;

typedef struct {
	int valid;
	sqfs_cache_idx idx;
} sqfs_cache_entry_hdr;

sqfs_err sqfs_cache_init(sqfs_cache *cache, size_t size, size_t count,
			 sqfs_cache_dispose dispose) {

	sqfs_cache_internal *c = malloc(sizeof(sqfs_cache_internal));
	if (!c) {
		return SQFS_ERR;
	}

	c->size = size + sizeof(sqfs_cache_entry_hdr);
	c->count = count;
	c->dispose = dispose;
	c->next = 0;

	c->buf = calloc(count, c->size);

	if (c->buf) {
		*cache = c;
		return SQFS_OK;
	}

	sqfs_cache_destroy(&c);
	return SQFS_ERR;
}

static sqfs_cache_entry_hdr *sqfs_cache_entry_header(
						     sqfs_cache_internal* cache,
						     size_t i) {
	return (sqfs_cache_entry_hdr *)(cache->buf + i * cache->size);
}

static void* sqfs_cache_entry(sqfs_cache_internal* cache, size_t i) {
	return (void *)(sqfs_cache_entry_header(cache, i) + 1);
}

void sqfs_cache_destroy(sqfs_cache *cache) {
	if (cache && *cache) {
		sqfs_cache_internal *c = *cache;
		if (c->buf) {
			size_t i;
			for (i = 0; i < c->count; ++i) {
				sqfs_cache_entry_hdr *hdr =
					sqfs_cache_entry_header(c, i);
				if (hdr->valid) {
					c->dispose((void *)(hdr + 1));
				}
			}
		}
		free(c->buf);
		free(c);
		*cache = NULL;
	}
}

void *sqfs_cache_get(sqfs_cache *cache, sqfs_cache_idx idx) {
	size_t i;
	sqfs_cache_internal *c = *cache;
	sqfs_cache_entry_hdr *hdr;

	for (i = 0; i < c->count; ++i) {
		hdr = sqfs_cache_entry_header(c, i);
		/* Failed fills retain their key but must be retried as misses. */
		if (hdr->valid && hdr->idx == idx) {
			return sqfs_cache_entry(c, i);
		}
	}

	/* No existing entry; free one if necessary, allocate a new one. */
	i = (c->next++);
	c->next %= c->count;

	hdr = sqfs_cache_entry_header(c, i);
	if (hdr->valid) {
		/* evict */
		c->dispose((void *)(hdr + 1));
		hdr->valid = 0;
	}

	hdr->idx = idx;
	return (void *)(hdr + 1);
}

int sqfs_cache_entry_valid(const sqfs_cache *cache, const void *e) {
	sqfs_cache_entry_hdr *hdr = ((sqfs_cache_entry_hdr *)e) - 1;
	return hdr->valid;
}

void sqfs_cache_entry_mark_valid(sqfs_cache *cache, void *e) {
	sqfs_cache_entry_hdr *hdr = ((sqfs_cache_entry_hdr *)e) - 1;
	assert(hdr->valid == 0);
	hdr->valid = 1;
}

void sqfs_cache_put(const sqfs_cache *cache, const void *e) {
	// nada, we have no locking in single-threaded implementation.
}
#else

#include "cache.h"

#include "fs.h"

#include "kernel/process_runtime.h"
#include "sqfs_port.h"
#include <string.h>

typedef struct sqfs_cache_internal {
	uint8_t *buf;
	sqfs_cache_dispose dispose;
	size_t size, count;
	size_t next;
	uint32_t waiters;
	volatile uint32_t lock;
	volatile uint64_t available_sequence;
} sqfs_cache_internal;

typedef struct {
	volatile uint64_t sequence;
	sqfs_cache_idx idx;
	uintptr_t owner;
	uint32_t references;
	uint8_t valid;
	uint8_t pending;
} sqfs_cache_entry_hdr;

static void sqfs_cache_lock(sqfs_cache_internal *cache) {
	while (__atomic_exchange_n(&cache->lock, 1u, __ATOMIC_ACQUIRE)) {
		if (!kernel_runtime_yield()) {
			int released = kernel_runtime_contention_begin();

			while (__atomic_load_n(&cache->lock, __ATOMIC_ACQUIRE))
				kernel_runtime_contention_wait(&cache->lock, 1u);
			kernel_runtime_contention_end(released);
		}
	}
}

static void sqfs_cache_unlock(sqfs_cache_internal *cache) {
	__atomic_store_n(&cache->lock, 0u, __ATOMIC_RELEASE);
	kernel_runtime_contention_notify();
}

static void sqfs_cache_wait_sequence(sqfs_cache_internal *cache,
		volatile uint64_t *sequence, uint64_t observed) {
	int released;

	++cache->waiters;
	sqfs_cache_unlock(cache);
	if (kernel_runtime_wait_sequence(sequence, observed, UINT64_MAX) <= 0) {
		released = kernel_runtime_contention_begin();
		while (__atomic_load_n(sequence, __ATOMIC_ACQUIRE) == observed)
			kernel_runtime_contention_wait(
				(volatile uint32_t *)sequence, (uint32_t)observed);
		kernel_runtime_contention_end(released);
	}
	sqfs_cache_lock(cache);
	--cache->waiters;
	sqfs_cache_unlock(cache);
}

static sqfs_cache_entry_hdr *sqfs_cache_entry_header(
		sqfs_cache_internal *cache, size_t index) {
	return (sqfs_cache_entry_hdr *)(cache->buf + index * cache->size);
}

sqfs_err sqfs_cache_init(sqfs_cache *cache, size_t size, size_t count,
		sqfs_cache_dispose dispose) {
	sqfs_cache_internal *created;

	if (!cache || !count ||
		size > SIZE_MAX - sizeof(sqfs_cache_entry_hdr))
		return SQFS_ERR;
	created = calloc(1u, sizeof(*created));
	if (!created) return SQFS_ERR;
	created->size = size + sizeof(sqfs_cache_entry_hdr);
	created->count = count;
	created->dispose = dispose;
	if (count > SIZE_MAX / created->size) {
		free(created);
		return SQFS_ERR;
	}
	created->buf = calloc(count, created->size);
	if (!created->buf) {
		free(created);
		return SQFS_ERR;
	}
	*cache = created;
	return SQFS_OK;
}

void sqfs_cache_destroy(sqfs_cache *cache) {
	sqfs_cache_internal *current;

	if (!cache || !*cache) return;
	current = *cache;
	for (size_t index = 0; index < current->count; ++index) {
		sqfs_cache_entry_hdr *header =
			sqfs_cache_entry_header(current, index);

		if (header->valid && current->dispose)
			current->dispose((void *)(header + 1));
	}
	free(current->buf);
	free(current);
	*cache = NULL;
}

void *sqfs_cache_get(sqfs_cache *cache, sqfs_cache_idx idx) {
	sqfs_cache_internal *current = cache ? *cache : NULL;
	uintptr_t owner = kernel_current_context_token();

	if (!current) return NULL;
	for (;;) {
		sqfs_cache_entry_hdr *selected = NULL;
		volatile uint64_t *wait_sequence = NULL;
		uint64_t observed = 0u;

		sqfs_cache_lock(current);
		for (size_t index = 0; index < current->count; ++index) {
			sqfs_cache_entry_hdr *header =
				sqfs_cache_entry_header(current, index);

			if ((header->valid || header->pending) &&
				header->idx == idx) {
				selected = header;
				break;
			}
		}
		if (selected && selected->valid) {
			++selected->references;
			sqfs_cache_unlock(current);
			return (void *)(selected + 1);
		}
		if (selected && selected->pending && selected->owner == owner) {
			sqfs_cache_unlock(current);
			return (void *)(selected + 1);
		}
		if (selected && selected->pending) {
			wait_sequence = &selected->sequence;
			observed = __atomic_load_n(
				wait_sequence, __ATOMIC_ACQUIRE);
			sqfs_cache_wait_sequence(current, wait_sequence, observed);
			continue;
		}

		for (size_t count = 0; count < current->count; ++count) {
			size_t index = (current->next + count) % current->count;
			sqfs_cache_entry_hdr *header =
				sqfs_cache_entry_header(current, index);

			if (!header->pending && header->references == 0u) {
				selected = header;
				current->next = (index + 1u) % current->count;
				break;
			}
		}
		if (!selected) {
			wait_sequence = &current->available_sequence;
			observed = __atomic_load_n(
				wait_sequence, __ATOMIC_ACQUIRE);
			sqfs_cache_wait_sequence(current, wait_sequence, observed);
			continue;
		}
		if (selected->valid) {
			if (current->dispose)
				current->dispose((void *)(selected + 1));
		}
		memset((void *)(selected + 1), 0,
		       current->size - sizeof(*selected));
		selected->valid = 0u;
		selected->pending = 1u;
		selected->idx = idx;
		selected->owner = owner;
		selected->references = 1u;
		sqfs_cache_unlock(current);
		return (void *)(selected + 1);
	}
}

int sqfs_cache_entry_valid(const sqfs_cache *cache, const void *entry) {
	const sqfs_cache_entry_hdr *header;

	(void)cache;
	if (!entry) return 0;
	header = (const sqfs_cache_entry_hdr *)entry - 1;
	return __atomic_load_n(&header->valid, __ATOMIC_ACQUIRE) != 0u;
}

void sqfs_cache_entry_mark_valid(sqfs_cache *cache, void *entry) {
	sqfs_cache_internal *current = cache ? *cache : NULL;
	sqfs_cache_entry_hdr *header;
	int notify;

	if (!current || !entry) return;
	header = (sqfs_cache_entry_hdr *)entry - 1;
	sqfs_cache_lock(current);
	header->valid = 1u;
	header->pending = 0u;
	header->owner = 0u;
	__atomic_add_fetch(&header->sequence, 1u, __ATOMIC_RELEASE);
	notify = current->waiters != 0u;
	sqfs_cache_unlock(current);
	if (notify) kernel_runtime_notify_sequence(&header->sequence);
}

void sqfs_cache_put(const sqfs_cache *cache, const void *entry) {
	sqfs_cache_internal *current = cache ? *cache : NULL;
	sqfs_cache_entry_hdr *header;
	uintptr_t owner = kernel_current_context_token();
	int notify_entry = 0;
	int notify_available = 0;
	int has_waiters;

	if (!current || !entry) return;
	header = (sqfs_cache_entry_hdr *)entry - 1;
	sqfs_cache_lock(current);
	if (header->pending && (!header->owner || header->owner == owner)) {
		if (current->dispose)
			current->dispose((void *)(header + 1));
		memset((void *)(header + 1), 0,
		       current->size - sizeof(*header));
		header->pending = 0u;
		header->owner = 0u;
		header->references = 0u;
		__atomic_add_fetch(&header->sequence, 1u, __ATOMIC_RELEASE);
		notify_entry = 1;
		notify_available = 1;
	} else if (header->references) {
		--header->references;
		if (!header->references) notify_available = 1;
	}
	if (notify_available)
		__atomic_add_fetch(
			&current->available_sequence, 1u, __ATOMIC_RELEASE);
	has_waiters = current->waiters != 0u;
	sqfs_cache_unlock(current);
	if (notify_entry && has_waiters)
		kernel_runtime_notify_sequence(&header->sequence);
	if (notify_available && has_waiters)
		kernel_runtime_notify_sequence(&current->available_sequence);
}

#endif /* EDGEOS_SQFS_HOST_TEST */
