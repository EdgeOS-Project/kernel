/*	$NetBSD: drm_sysfs.c,v 1.9 2021/12/19 12:30:31 riastradh Exp $	*/

/*-
 * Copyright (c) 2013 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Taylor R. Campbell.
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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: drm_sysfs.c,v 1.9 2021/12/19 12:30:31 riastradh Exp $");

#include <drm/drm_device.h>
#include <drm/drm_connector.h>
#include <drm/drm_file.h>
#include <drm/drm_sysfs.h>

#ifdef __FreeBSD__
#include <linux/device.h>
#include <linux/slab.h>
#endif

#include "../dist/drm/drm_internal.h"

#ifdef __FreeBSD__
struct class *drm_class;

static void
drm_sysfs_release(struct device *dev)
{
	kfree(dev);
}

int
drm_sysfs_init(void)
{
	drm_class = class_create("drm");
	return IS_ERR(drm_class) ? PTR_ERR(drm_class) : 0;
}

void
drm_sysfs_destroy(void)
{
	if (!IS_ERR_OR_NULL(drm_class))
		class_destroy(drm_class);
	drm_class = NULL;
}

struct device *
drm_sysfs_minor_alloc(struct drm_minor *minor)
{
	struct device *kdev;
	const char *name;

	kdev = kzalloc(sizeof(*kdev), GFP_KERNEL);
	if (kdev == NULL)
		return ERR_PTR(-ENOMEM);
	name = minor->type == DRM_MINOR_RENDER ? "renderD%d" : "card%d";
	kdev->class = drm_class;
	kdev->parent = minor->dev->dev;
	kdev->release = drm_sysfs_release;
	device_initialize(kdev);
	dev_set_drvdata(kdev, minor);
	if (dev_set_name(kdev, name, minor->index) != 0) {
		put_device(kdev);
		return ERR_PTR(-ENOMEM);
	}
	return kdev;
}

int
drm_class_device_register(struct device *dev)
{
	if (IS_ERR_OR_NULL(drm_class))
		return -ENOENT;
	dev->class = drm_class;
	return device_register(dev);
}

void
drm_class_device_unregister(struct device *dev)
{
	device_unregister(dev);
}
#endif

int
drm_sysfs_connector_add(struct drm_connector *connector)
{
	connector->kdev = connector->dev->dev; /* XXX */
	return 0;
}

void
drm_sysfs_connector_remove(struct drm_connector *connector)
{
}

void
drm_sysfs_hotplug_event(struct drm_device *dev)
{
}

void
drm_sysfs_connector_status_event(struct drm_connector *connector,
    struct drm_property *prop)
{
}
