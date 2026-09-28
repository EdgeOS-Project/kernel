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
#include "file.h"

#include "fs.h"
#include "swap.h"
#include "table.h"

#include "sqfs_port.h"
#include <string.h>

#ifndef EDGEOS_SQFS_HOST_TEST
#include "kernel/task_scratch.h"
#endif

#ifndef EDGEOS_SQFS_HOST_TEST
#define SQFS_READ_CONTINUATION_MAGIC 0x53514652u

typedef struct {
	uint32_t magic;
	bool active;
	bool initialized;
	bool block_ready;
	sqfs *fs;
	uint32_t inode_number;
	sqfs_off_t start;
	sqfs_off_t requested;
	void *buffer;
	sqfs_off_t file_size;
	size_t block_size;
	sqfs_blocklist blocklist;
	size_t read_offset;
	sqfs_off_t remaining;
	sqfs_off_t done;
	size_t data_offset;
	size_t data_size;
	bool fragment;
	bool hole;
} sqfs_read_continuation;

static sqfs_read_continuation *sqfs_read_continuation_get(void) {
	return kernel_task_filesystem_scratch_acquire(
		sizeof(sqfs_read_continuation));
}

static void sqfs_read_continuation_clear(sqfs_read_continuation *state) {
	if (state)
		memset(state, 0, sizeof(*state));
}
#endif

sqfs_err sqfs_frag_entry(sqfs *fs, struct squashfs_fragment_entry *frag,
		uint32_t idx) {
	sqfs_err err = SQFS_OK;

	if (idx == SQUASHFS_INVALID_FRAG)
		return SQFS_ERR;

	err = sqfs_table_get(&fs->frag_table, fs, idx, frag);
	sqfs_swapin_fragment_entry(frag);
	return err;
}

sqfs_err sqfs_frag_block(sqfs *fs, sqfs_inode *inode,
		size_t *offset, size_t *size, sqfs_block **block) {
	struct squashfs_fragment_entry frag;
	sqfs_err err = SQFS_OK;

	if (!S_ISREG(inode->base.mode))
		return SQFS_ERR;

	err = sqfs_frag_entry(fs, &frag, inode->xtra.reg.frag_idx);
	if (err)
		return err;

	err = sqfs_data_cache(fs, &fs->frag_cache, frag.start_block,
		frag.size, block);
	if (err)
		return SQFS_ERR;

	*offset = inode->xtra.reg.frag_off;
	*size = inode->xtra.reg.file_size % fs->sb.block_size;
	return SQFS_OK;
}

size_t sqfs_blocklist_count(sqfs *fs, sqfs_inode *inode) {
	uint64_t size = inode->xtra.reg.file_size;
	size_t block = fs->sb.block_size;
	if (inode->xtra.reg.frag_idx == SQUASHFS_INVALID_FRAG) {
		return sqfs_divceil(size, block);
	} else {
		return (size_t)(size / block);
	}
}

void sqfs_blocklist_init(sqfs *fs, sqfs_inode *inode, sqfs_blocklist *bl) {
	bl->fs = fs;
	bl->remain = sqfs_blocklist_count(fs, inode);
	bl->cur = inode->next;
	bl->started = false;
	bl->pos = 0;
	bl->block = inode->xtra.reg.start_block;
	bl->input_size = 0;
}

sqfs_err sqfs_blocklist_next(sqfs_blocklist *bl) {
	sqfs_err err = SQFS_OK;
	bool compressed;
	sqfs_blocklist next;

	if (bl->remain == 0)
		return SQFS_ERR;
	next = *bl;
	--(next.remain);

	err = sqfs_md_read(next.fs, &next.cur, &next.header,
		sizeof(next.header));
	if (err)
		return err;
	sqfs_swapin32(&next.header);

	next.block += next.input_size;
	sqfs_data_header(next.header, &compressed, &next.input_size);

	if (next.started)
		next.pos += next.fs->sb.block_size;
	next.started = true;
	*bl = next;

	return SQFS_OK;
}

sqfs_err sqfs_read_range(sqfs *fs, sqfs_inode *inode, sqfs_off_t start,
		sqfs_off_t *size, void *buf) {
#ifdef EDGEOS_SQFS_HOST_TEST
	sqfs_err err = SQFS_OK;

	sqfs_off_t file_size;
	size_t block_size;
	sqfs_blocklist bl;

	size_t read_off;
	char *buf_orig;

	if (!S_ISREG(inode->base.mode))
		return SQFS_ERR;

	file_size = inode->xtra.reg.file_size;
	block_size = fs->sb.block_size;

	if (*size < 0 || start > file_size)
		return SQFS_ERR;
	if (start == file_size) {
		*size = 0;
		return SQFS_OK;
	}

	err = sqfs_blockidx_blocklist(fs, inode, &bl, start);
	if (err)
		return err;

	read_off = start % block_size;
	buf_orig = buf;
	while (*size > 0) {
		sqfs_block *block = NULL;
		size_t data_off, data_size;
		size_t take;

		bool fragment = (bl.remain == 0);
		if (fragment) { /* fragment */
			if (inode->xtra.reg.frag_idx == SQUASHFS_INVALID_FRAG)
				break;
			err = sqfs_frag_block(fs, inode, &data_off, &data_size, &block);
			if (err)
				return err;
		} else {
			if ((err = sqfs_blocklist_next(&bl)))
				return err;
			if (bl.pos + block_size <= start)
				continue;

			data_off = 0;
			if (bl.input_size == 0) { /* Hole! */
				data_size = (size_t)(file_size - bl.pos);
				if (data_size > block_size)
					data_size = block_size;
			} else {
				err = sqfs_data_cache(fs, &fs->data_cache, bl.block,
					bl.header, &block);
				if (err)
					return err;
				data_size = block->size;
			}
		}

		take = data_size - read_off;
		if (take > *size)
			take = (size_t)(*size);
		if (block) {
			memcpy(buf, (char*)block->data + data_off + read_off, take);
			sqfs_block_dispose(block);
		} else {
			memset(buf, 0, take);
		}
		read_off = 0;
		*size -= take;
		buf = (char*)buf + take;

		if (fragment)
			break;
	}

	*size = (char*)buf - buf_orig;
	return *size ? SQFS_OK : SQFS_ERR;
#else
	sqfs_read_continuation *state;
	sqfs_err err;
	sqfs_off_t requested;

	if (!S_ISREG(inode->base.mode) || !size)
		return SQFS_ERR;
	requested = *size;
	if (requested < 0 || start < 0 ||
		(uint64_t)start > inode->xtra.reg.file_size)
		return SQFS_ERR;
	if ((uint64_t)start == inode->xtra.reg.file_size) {
		*size = 0;
		return SQFS_OK;
	}

	state = sqfs_read_continuation_get();
	if (!state)
		return SQFS_ERR;
	if (state->magic != SQFS_READ_CONTINUATION_MAGIC || !state->active ||
		state->fs != fs || state->inode_number != inode->base.inode_number ||
		state->start != start || state->requested != requested ||
		state->buffer != buf) {
		sqfs_read_continuation_clear(state);
		state->magic = SQFS_READ_CONTINUATION_MAGIC;
		state->active = true;
		state->fs = fs;
		state->inode_number = inode->base.inode_number;
		state->start = start;
		state->requested = requested;
		state->buffer = buf;
		state->file_size = inode->xtra.reg.file_size;
		state->block_size = fs->sb.block_size;
		state->read_offset = start % state->block_size;
		state->remaining = requested;
	}

	if (!state->initialized) {
		err = sqfs_blockidx_blocklist(fs, inode, &state->blocklist, start);
		if (err) {
			sqfs_read_continuation_clear(state);
			return err;
		}
		state->initialized = true;
	}

	while (state->remaining > 0) {
		sqfs_block *block = NULL;
		size_t take;

		if (!state->block_ready) {
			state->fragment = state->blocklist.remain == 0;
			state->hole = false;
			if (state->fragment) {
				if (inode->xtra.reg.frag_idx == SQUASHFS_INVALID_FRAG)
					break;
				err = sqfs_frag_block(fs, inode, &state->data_offset,
					&state->data_size, &block);
				if (err) {
					sqfs_read_continuation_clear(state);
					return err;
				}
			} else {
				err = sqfs_blocklist_next(&state->blocklist);
				if (err) {
					sqfs_read_continuation_clear(state);
					return err;
				}
				if (state->blocklist.pos + state->block_size <=
					(uint64_t)start)
					continue;
				state->data_offset = 0;
				if (state->blocklist.input_size == 0) {
					state->data_size = (size_t)(state->file_size -
						state->blocklist.pos);
					if (state->data_size > state->block_size)
						state->data_size = state->block_size;
					state->hole = true;
				}
			}
			state->block_ready = true;
		}

		if (!state->fragment && !state->hole) {
			err = sqfs_data_cache(fs, &fs->data_cache,
				state->blocklist.block, state->blocklist.header, &block);
			if (err) {
				sqfs_read_continuation_clear(state);
				return err;
			}
			state->data_size = block->size;
		} else if (state->fragment && !block) {
			err = sqfs_frag_block(fs, inode, &state->data_offset,
				&state->data_size, &block);
			if (err) {
				sqfs_read_continuation_clear(state);
				return err;
			}
		}

		take = state->data_size - state->read_offset;
		if ((sqfs_off_t)take > state->remaining)
			take = (size_t)state->remaining;
		if (block) {
			memcpy((char *)state->buffer + state->done,
				(char *)block->data + state->data_offset +
				state->read_offset, take);
			sqfs_block_dispose(block);
		} else {
			memset((char *)state->buffer + state->done, 0, take);
		}
		state->read_offset = 0;
		state->remaining -= take;
		state->done += take;
		state->block_ready = false;
		if (state->fragment)
			break;
	}

	*size = state->done;
	err = state->done ? SQFS_OK : SQFS_ERR;
	sqfs_read_continuation_clear(state);
	return err;
#endif
}


/*
Reading block N otherwise scans N compressed block sizes from the inode.
Store the metadata cursor and compressed data offset for each block so
random access never rescans preceding block sizes after index creation.
*/

/* Is a file worth indexing? */
static bool sqfs_blockidx_indexable(sqfs *fs, sqfs_inode *inode) {
	size_t blocks = sqfs_blocklist_count(fs, inode);
	return blocks > 64u;
}

static void sqfs_blockidx_dispose(void *data) {
	free(*(sqfs_blockidx_entry**)data);
	*(sqfs_blockidx_entry**)data = NULL;
}

sqfs_err sqfs_blockidx_init(sqfs_cache *cache) {
	return sqfs_cache_init(cache, sizeof(sqfs_blockidx_entry**),
		SQUASHFS_META_SLOTS, &sqfs_blockidx_dispose);
}

sqfs_err sqfs_blockidx_add(sqfs *fs, sqfs_inode *inode,
		sqfs_blockidx_entry **out, sqfs_blockidx_entry **cachep) {
	size_t blocks;
	size_t count;
	sqfs_blockidx_entry *blockidx;
	sqfs_blocklist bl;

	*out = NULL;
	blocks = sqfs_blocklist_count(fs, inode);
	count = blocks;
	if (count > SIZE_MAX / sizeof(*blockidx)) return SQFS_ERR;
	blockidx = *cachep;
	if (!blockidx) {
		blockidx = malloc(count * sizeof(sqfs_blockidx_entry));
		if (!blockidx) return SQFS_ERR;
		*cachep = blockidx;
	}

	sqfs_blocklist_init(fs, inode, &bl);
	for (size_t block = 0; block < blocks; ++block) {
		blockidx[block].data_block = bl.block + bl.input_size;
		blockidx[block].cursor = bl.cur;
		if (sqfs_blocklist_next(&bl) != SQFS_OK) {
			free(blockidx);
			*cachep = NULL;
			return SQFS_ERR;
		}
	}

	*out = blockidx;
	return SQFS_OK;
}

sqfs_err sqfs_blockidx_blocklist(sqfs *fs, sqfs_inode *inode,
		sqfs_blocklist *bl, sqfs_off_t start) {
	size_t block, checkpoint;
	sqfs_blockidx_entry *blockidx, **bp;
	sqfs_cache_idx idx;

	sqfs_blocklist_init(fs, inode, bl);
	block = (size_t)(start / fs->sb.block_size);
	if (block >= bl->remain) { /* fragment or end of file */
		bl->remain = 0;
		return SQFS_OK;
	}

	checkpoint = block;
	if (checkpoint == 0u)
		return SQFS_OK;
	if (!sqfs_blockidx_indexable(fs, inode))
		return SQFS_OK;

	/* Get the index, creating it if necessary */
	idx = inode->base.inode_number + 1; /* zero means invalid index */
	bp = sqfs_cache_get(&fs->blockidx, idx);
	if (sqfs_cache_entry_valid(&fs->blockidx, bp)) {
		blockidx = *bp;
	} else {
		sqfs_err err = sqfs_blockidx_add(fs, inode, &blockidx, bp);
		if (err) {
			sqfs_cache_put(&fs->blockidx, bp);
			return err;
		}
		sqfs_cache_entry_mark_valid(&fs->blockidx, bp);
	}

	blockidx += checkpoint;
	bl->cur = blockidx->cursor;
	bl->remain -= checkpoint;
	bl->pos = (uint64_t)checkpoint * fs->sb.block_size;
	bl->block = blockidx->data_block;
	bl->input_size = 0u;
	bl->started = false;

	sqfs_cache_put(&fs->blockidx, bp);

	return SQFS_OK;
}
