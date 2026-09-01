/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2016-2018, Matthew Macy <mmacy@freebsd.org>
 * Copyright (c) 2026, EdgeOS contributors
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/systm.h>

#include <linux/debugfs.h>
#include <linux/dcache.h>

MALLOC_DEFINE(M_DFSINT, "debugfsint", "Linux debugfs internal");

enum debugfs_node_type {
	DEBUGFS_NODE_DIR,
	DEBUGFS_NODE_FILE,
	DEBUGFS_NODE_SYMLINK,
};

struct debugfs_node {
	struct dentry dn_dentry;
	struct debugfs_node *dn_parent;
	struct debugfs_node *dn_next;
	const struct file_operations *dn_fops;
	void *dn_data;
	char *dn_name;
	umode_t dn_mode;
	enum debugfs_node_type dn_type;
};

static struct debugfs_node *debugfs_nodes;
static volatile unsigned int debugfs_guard;

static void
debugfs_lock(void)
{
	while (__atomic_test_and_set(&debugfs_guard, __ATOMIC_ACQUIRE))
		;
}

static void
debugfs_unlock(void)
{
	__atomic_clear(&debugfs_guard, __ATOMIC_RELEASE);
}

static struct debugfs_node *
debugfs_node_from_dentry(struct dentry *dentry)
{
	if (dentry == NULL)
		return (NULL);
	return ((struct debugfs_node *)(void *)dentry->d_pfs_node);
}

static struct debugfs_node *
debugfs_find_locked(const char *name, struct debugfs_node *parent)
{
	struct debugfs_node *node;

	for (node = debugfs_nodes; node != NULL; node = node->dn_next) {
		if (node->dn_parent == parent && strcmp(node->dn_name, name) == 0)
			return (node);
	}
	return (NULL);
}

static char *
debugfs_copy_name(const char *name)
{
	char *copy;
	size_t length;

	length = strlen(name) + 1;
	copy = malloc(length, M_DFSINT, M_NOWAIT);
	if (copy != NULL)
		memcpy(copy, name, length);
	return (copy);
}

static struct dentry *
debugfs_create_node(const char *name, umode_t mode, struct dentry *parent,
	void *data, const struct file_operations *fops,
	enum debugfs_node_type type)
{
	struct debugfs_node *parent_node;
	struct debugfs_node *node;

	if (name == NULL || name[0] == '\0')
		return (NULL);
	parent_node = debugfs_node_from_dentry(parent);
	if (parent != NULL && parent_node == NULL)
		return (NULL);

	node = malloc(sizeof(*node), M_DFSINT, M_NOWAIT | M_ZERO);
	if (node == NULL)
		return (NULL);
	node->dn_name = debugfs_copy_name(name);
	if (node->dn_name == NULL) {
		free(node, M_DFSINT);
		return (NULL);
	}
	node->dn_parent = parent_node;
	node->dn_fops = fops;
	node->dn_data = data;
	node->dn_mode = mode;
	node->dn_type = type;
	node->dn_dentry.d_pfs_node = (struct pfs_node *)(void *)node;

	debugfs_lock();
	if (debugfs_find_locked(name, parent_node) != NULL) {
		debugfs_unlock();
		free(node->dn_name, M_DFSINT);
		free(node, M_DFSINT);
		return (NULL);
	}
	node->dn_next = debugfs_nodes;
	debugfs_nodes = node;
	debugfs_unlock();
	return (&node->dn_dentry);
}

struct dentry *
debugfs_create_file(const char *name, umode_t mode, struct dentry *parent,
	void *data, const struct file_operations *fops)
{
	return (debugfs_create_node(name, mode, parent, data, fops,
	    DEBUGFS_NODE_FILE));
}

struct dentry *
debugfs_create_file_size(const char *name, umode_t mode,
	struct dentry *parent, void *data, const struct file_operations *fops,
	loff_t file_size __unused)
{
	return (debugfs_create_file(name, mode, parent, data, fops));
}

struct dentry *
debugfs_create_file_unsafe(const char *name, umode_t mode,
	struct dentry *parent, void *data, const struct file_operations *fops)
{
	return (debugfs_create_file(name, mode, parent, data, fops));
}

struct dentry *
debugfs_create_mode_unsafe(const char *name, umode_t mode,
	struct dentry *parent, void *data, const struct file_operations *fops,
	const struct file_operations *fops_ro,
	const struct file_operations *fops_wo)
{
	const struct file_operations *selected;

	selected = fops;
	if ((mode & S_IRUGO) != 0 && (mode & S_IWUGO) == 0)
		selected = fops_ro;
	else if ((mode & S_IWUGO) != 0 && (mode & S_IRUGO) == 0)
		selected = fops_wo;
	return (debugfs_create_file(name, mode, parent, data, selected));
}

struct dentry *
debugfs_create_dir(const char *name, struct dentry *parent)
{
	return (debugfs_create_node(name, 0700, parent, NULL, NULL,
	    DEBUGFS_NODE_DIR));
}

struct dentry *
debugfs_create_symlink(const char *name, struct dentry *parent,
	const char *dest)
{
	char *target;
	struct dentry *dentry;

	if (dest == NULL)
		return (NULL);
	target = debugfs_copy_name(dest);
	if (target == NULL)
		return (NULL);
	dentry = debugfs_create_node(name, 0700, parent, target, NULL,
	    DEBUGFS_NODE_SYMLINK);
	if (dentry == NULL)
		free(target, M_DFSINT);
	return (dentry);
}

struct dentry *
debugfs_lookup(const char *name, struct dentry *parent)
{
	struct debugfs_node *node;
	struct debugfs_node *parent_node;

	if (name == NULL)
		return (NULL);
	parent_node = debugfs_node_from_dentry(parent);
	debugfs_lock();
	node = debugfs_find_locked(name, parent_node);
	debugfs_unlock();
	return (node != NULL ? &node->dn_dentry : NULL);
}

static void
debugfs_unlink_and_free_locked(struct debugfs_node *node)
{
	struct debugfs_node **link;

	for (link = &debugfs_nodes; *link != NULL; link = &(*link)->dn_next) {
		if (*link == node) {
			*link = node->dn_next;
			break;
		}
	}
	if (node->dn_type == DEBUGFS_NODE_SYMLINK)
		free(node->dn_data, M_DFSINT);
	free(node->dn_name, M_DFSINT);
	free(node, M_DFSINT);
}

static void
debugfs_remove_subtree_locked(struct debugfs_node *node)
{
	struct debugfs_node *child;

	do {
		child = NULL;
		for (child = debugfs_nodes; child != NULL; child = child->dn_next) {
			if (child->dn_parent == node)
				break;
		}
		if (child != NULL)
			debugfs_remove_subtree_locked(child);
	} while (child != NULL);
	debugfs_unlink_and_free_locked(node);
}

void
debugfs_remove(struct dentry *dentry)
{
	struct debugfs_node *node;

	node = debugfs_node_from_dentry(dentry);
	if (node == NULL)
		return;
	debugfs_lock();
	debugfs_unlink_and_free_locked(node);
	debugfs_unlock();
}

void
debugfs_remove_recursive(struct dentry *dentry)
{
	struct debugfs_node *node;

	node = debugfs_node_from_dentry(dentry);
	if (node == NULL)
		return;
	debugfs_lock();
	debugfs_remove_subtree_locked(node);
	debugfs_unlock();
}

#define DEBUGFS_CREATE_SCALAR(function, type)\
	void function(const char *name, umode_t mode, struct dentry *parent,\
	    type *value)\
	{\
		(void)debugfs_create_file(name, mode, parent, value, NULL);\
	}

DEBUGFS_CREATE_SCALAR(debugfs_create_bool, bool)
DEBUGFS_CREATE_SCALAR(debugfs_create_u8, uint8_t)
DEBUGFS_CREATE_SCALAR(debugfs_create_u16, uint16_t)
DEBUGFS_CREATE_SCALAR(debugfs_create_u32, uint32_t)
DEBUGFS_CREATE_SCALAR(debugfs_create_u64, uint64_t)
DEBUGFS_CREATE_SCALAR(debugfs_create_x8, uint8_t)
DEBUGFS_CREATE_SCALAR(debugfs_create_x16, uint16_t)
DEBUGFS_CREATE_SCALAR(debugfs_create_x32, uint32_t)
DEBUGFS_CREATE_SCALAR(debugfs_create_x64, uint64_t)
DEBUGFS_CREATE_SCALAR(debugfs_create_ulong, unsigned long)
DEBUGFS_CREATE_SCALAR(debugfs_create_atomic_t, atomic_t)
DEBUGFS_CREATE_SCALAR(debugfs_create_str, char *)

struct dentry *
debugfs_create_blob(const char *name, umode_t mode, struct dentry *parent,
	struct debugfs_blob_wrapper *value)
{
	return (debugfs_create_file(name, mode & 0444, parent, value, NULL));
}

MODULE_VERSION(lindebugfs, 1);
