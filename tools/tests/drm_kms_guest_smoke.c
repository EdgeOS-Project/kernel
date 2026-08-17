/*
 * Copyright (c) 2026 EdgeOS Contributors.
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Exercise the public Linux DRM/KMS dumb-buffer ABI from an unmodified
 * userspace process. This test intentionally uses only installed UAPI headers.
 */

#include <drm/drm.h>
#include <drm/drm_fourcc.h>
#include <drm/drm_mode.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define ARRAY_SIZE(values) (sizeof(values) / sizeof((values)[0]))
#define FLIP_COOKIE UINT64_C(0x454447454b4d5301)
#define ATOMIC_COOKIE UINT64_C(0x454447454b4d5302)
#define TEST_DRM_MODE_CONNECTED 1u

typedef struct {
    struct drm_mode_create_dumb create;
    struct drm_mode_map_dumb mapping;
    struct drm_mode_fb_cmd2 framebuffer;
    uint8_t *pixels;
} test_buffer_t;

static int report_errno(const char *operation) {
    fprintf(stderr, "FAIL: %s: %s\n", operation, strerror(errno));
    return -1;
}

static int drm_call(int fd, unsigned long command, void *argument,
                    const char *operation) {
    if (ioctl(fd, command, argument) == 0) return 0;
    return report_errno(operation);
}

static int create_buffer(int fd, const struct drm_mode_modeinfo *mode,
                         test_buffer_t *buffer, uint32_t color_a,
                         uint32_t color_b) {
    uint32_t row;

    memset(buffer, 0, sizeof(*buffer));
    buffer->create.width = mode->hdisplay;
    buffer->create.height = mode->vdisplay;
    buffer->create.bpp = 32;
    if (drm_call(fd, DRM_IOCTL_MODE_CREATE_DUMB, &buffer->create,
                 "DRM_IOCTL_MODE_CREATE_DUMB") < 0)
        return -1;

    buffer->mapping.handle = buffer->create.handle;
    if (drm_call(fd, DRM_IOCTL_MODE_MAP_DUMB, &buffer->mapping,
                 "DRM_IOCTL_MODE_MAP_DUMB") < 0)
        return -1;
    buffer->pixels = mmap(NULL, buffer->create.size, PROT_READ | PROT_WRITE,
                          MAP_SHARED, fd, (off_t)buffer->mapping.offset);
    if (buffer->pixels == MAP_FAILED) {
        buffer->pixels = NULL;
        return report_errno("mmap dumb buffer");
    }

    for (row = 0; row < mode->vdisplay; ++row) {
        uint32_t *line =
            (uint32_t *)(buffer->pixels + (uint64_t)row *
                         buffer->create.pitch);
        uint32_t color = row < mode->vdisplay / 2u ? color_a : color_b;
        for (uint32_t column = 0; column < mode->hdisplay; ++column)
            line[column] = color ^ ((column / 32u) & 1u ? 0x00101010u : 0u);
    }

    buffer->framebuffer.width = mode->hdisplay;
    buffer->framebuffer.height = mode->vdisplay;
    buffer->framebuffer.pixel_format = DRM_FORMAT_XRGB8888;
    buffer->framebuffer.handles[0] = buffer->create.handle;
    buffer->framebuffer.pitches[0] = buffer->create.pitch;
    if (drm_call(fd, DRM_IOCTL_MODE_ADDFB2, &buffer->framebuffer,
                 "DRM_IOCTL_MODE_ADDFB2") < 0)
        return -1;
    return 0;
}

static void destroy_buffer(int fd, test_buffer_t *buffer) {
    struct drm_mode_destroy_dumb destroy;

    if (buffer->framebuffer.fb_id)
        (void)ioctl(fd, DRM_IOCTL_MODE_RMFB, &buffer->framebuffer.fb_id);
    if (buffer->pixels)
        (void)munmap(buffer->pixels, buffer->create.size);
    if (!buffer->create.handle) return;
    memset(&destroy, 0, sizeof(destroy));
    destroy.handle = buffer->create.handle;
    (void)ioctl(fd, DRM_IOCTL_MODE_DESTROY_DUMB, &destroy);
}

static int get_display(int fd, uint32_t *crtc_id, uint32_t *connector_id,
                       struct drm_mode_modeinfo *mode) {
    struct drm_mode_card_res resources;
    struct drm_mode_get_connector connector;
    struct drm_mode_modeinfo modes[16];
    uint32_t framebuffer_ids[16];
    uint32_t crtc_ids[8];
    uint32_t connector_ids[8];
    uint32_t encoder_ids[8];
    uint32_t encoder_id = 0;
    uint32_t selected = 0;

    memset(&resources, 0, sizeof(resources));
    resources.fb_id_ptr = (uintptr_t)framebuffer_ids;
    resources.crtc_id_ptr = (uintptr_t)crtc_ids;
    resources.connector_id_ptr = (uintptr_t)connector_ids;
    resources.encoder_id_ptr = (uintptr_t)encoder_ids;
    resources.count_fbs = ARRAY_SIZE(framebuffer_ids);
    resources.count_crtcs = ARRAY_SIZE(crtc_ids);
    resources.count_connectors = ARRAY_SIZE(connector_ids);
    resources.count_encoders = ARRAY_SIZE(encoder_ids);
    if (drm_call(fd, DRM_IOCTL_MODE_GETRESOURCES, &resources,
                 "DRM_IOCTL_MODE_GETRESOURCES") < 0)
        return -1;
    if (resources.count_crtcs != 1 || resources.count_connectors != 1 ||
        resources.count_encoders != 1) {
        fprintf(stderr,
                "FAIL: unexpected resources: crtcs=%u connectors=%u "
                "encoders=%u\n",
                resources.count_crtcs, resources.count_connectors,
                resources.count_encoders);
        return -1;
    }

    memset(&connector, 0, sizeof(connector));
    connector.connector_id = connector_ids[0];
    connector.modes_ptr = (uintptr_t)modes;
    connector.encoders_ptr = (uintptr_t)&encoder_id;
    connector.count_modes = ARRAY_SIZE(modes);
    connector.count_encoders = 1;
    if (drm_call(fd, DRM_IOCTL_MODE_GETCONNECTOR, &connector,
                 "DRM_IOCTL_MODE_GETCONNECTOR") < 0)
        return -1;
    if (connector.connection != TEST_DRM_MODE_CONNECTED ||
        connector.count_modes == 0 ||
        connector.count_modes > ARRAY_SIZE(modes)) {
        fprintf(stderr, "FAIL: connector has no usable mode\n");
        return -1;
    }
    for (uint32_t index = 0; index < connector.count_modes; ++index)
        if (modes[index].type & DRM_MODE_TYPE_PREFERRED) {
            selected = index;
            break;
        }

    *crtc_id = crtc_ids[0];
    *connector_id = connector_ids[0];
    *mode = modes[selected];
    printf("MODE: %ux%u@%u\n", mode->hdisplay, mode->vdisplay,
           mode->vrefresh);
    return 0;
}

static uint32_t find_property(int fd, uint32_t object_id,
                              uint32_t object_type, const char *name) {
    struct drm_mode_obj_get_properties object;
    struct drm_mode_get_property property;
    uint32_t ids[16];
    uint64_t values[16];

    memset(&object, 0, sizeof(object));
    object.obj_id = object_id;
    object.obj_type = object_type;
    object.count_props = ARRAY_SIZE(ids);
    object.props_ptr = (uintptr_t)ids;
    object.prop_values_ptr = (uintptr_t)values;
    if (drm_call(fd, DRM_IOCTL_MODE_OBJ_GETPROPERTIES, &object,
                 "DRM_IOCTL_MODE_OBJ_GETPROPERTIES") < 0)
        return 0;
    if (object.count_props > ARRAY_SIZE(ids)) {
        fprintf(stderr, "FAIL: too many object properties\n");
        return 0;
    }
    for (uint32_t index = 0; index < object.count_props; ++index) {
        memset(&property, 0, sizeof(property));
        property.prop_id = ids[index];
        if (drm_call(fd, DRM_IOCTL_MODE_GETPROPERTY, &property,
                     "DRM_IOCTL_MODE_GETPROPERTY") < 0)
            return 0;
        if (strcmp(property.name, name) == 0)
            return ids[index];
    }
    fprintf(stderr, "FAIL: missing property %s on object %u\n",
            name, object_id);
    return 0;
}

static int read_flip_event(int fd, uint64_t cookie, uint32_t crtc_id) {
    struct drm_event_vblank event;
    struct pollfd poll_descriptor;

    poll_descriptor.fd = fd;
    poll_descriptor.events = POLLIN;
    poll_descriptor.revents = 0;
    if (poll(&poll_descriptor, 1, 2000) != 1 ||
        !(poll_descriptor.revents & POLLIN)) {
        fprintf(stderr, "FAIL: page-flip event did not become readable\n");
        return -1;
    }
    memset(&event, 0, sizeof(event));
    if (read(fd, &event, sizeof(event)) != (ssize_t)sizeof(event))
        return report_errno("read page-flip event");
    if (event.base.type != DRM_EVENT_FLIP_COMPLETE ||
        event.base.length != sizeof(event) ||
        event.user_data != cookie ||
        event.crtc_id != crtc_id) {
        fprintf(stderr, "FAIL: malformed page-flip event\n");
        return -1;
    }
    return 0;
}

static int test_atomic_modeset(int fd, uint32_t crtc_id,
                               uint32_t connector_id,
                               const struct drm_mode_modeinfo *mode,
                               uint32_t framebuffer_id) {
    struct drm_set_client_cap client_cap;
    struct drm_mode_get_plane_res plane_resources;
    struct drm_mode_create_blob create_blob;
    struct drm_mode_get_blob get_blob;
    struct drm_mode_destroy_blob destroy_blob;
    struct drm_mode_atomic atomic;
    struct drm_mode_modeinfo copied_mode;
    uint32_t plane_ids[4];
    uint32_t object_ids[3];
    uint32_t property_counts[3] = { 1u, 2u, 10u };
    uint32_t property_ids[13];
    uint64_t property_values[13];
    uint32_t plane_id;
    uint32_t cursor = 0;

    memset(&client_cap, 0, sizeof(client_cap));
    client_cap.capability = DRM_CLIENT_CAP_ATOMIC;
    client_cap.value = 1;
    if (drm_call(fd, DRM_IOCTL_SET_CLIENT_CAP, &client_cap,
                 "DRM_IOCTL_SET_CLIENT_CAP atomic") < 0)
        return -1;

    memset(&plane_resources, 0, sizeof(plane_resources));
    plane_resources.plane_id_ptr = (uintptr_t)plane_ids;
    plane_resources.count_planes = ARRAY_SIZE(plane_ids);
    if (drm_call(fd, DRM_IOCTL_MODE_GETPLANERESOURCES, &plane_resources,
                 "DRM_IOCTL_MODE_GETPLANERESOURCES") < 0)
        return -1;
    if (plane_resources.count_planes != 1) {
        fprintf(stderr, "FAIL: unexpected plane count %u\n",
                plane_resources.count_planes);
        return -1;
    }
    plane_id = plane_ids[0];

    object_ids[0] = connector_id;
    object_ids[1] = crtc_id;
    object_ids[2] = plane_id;
    property_ids[cursor] = find_property(
        fd, connector_id, DRM_MODE_OBJECT_CONNECTOR, "CRTC_ID");
    property_values[cursor++] = crtc_id;
    property_ids[cursor] = find_property(
        fd, crtc_id, DRM_MODE_OBJECT_CRTC, "MODE_ID");
    property_values[cursor++] = 0;
    property_ids[cursor] = find_property(
        fd, crtc_id, DRM_MODE_OBJECT_CRTC, "ACTIVE");
    property_values[cursor++] = 1;
    property_ids[cursor] = find_property(
        fd, plane_id, DRM_MODE_OBJECT_PLANE, "FB_ID");
    property_values[cursor++] = framebuffer_id;
    property_ids[cursor] = find_property(
        fd, plane_id, DRM_MODE_OBJECT_PLANE, "CRTC_ID");
    property_values[cursor++] = crtc_id;
    property_ids[cursor] = find_property(
        fd, plane_id, DRM_MODE_OBJECT_PLANE, "SRC_X");
    property_values[cursor++] = 0;
    property_ids[cursor] = find_property(
        fd, plane_id, DRM_MODE_OBJECT_PLANE, "SRC_Y");
    property_values[cursor++] = 0;
    property_ids[cursor] = find_property(
        fd, plane_id, DRM_MODE_OBJECT_PLANE, "SRC_W");
    property_values[cursor++] = (uint64_t)mode->hdisplay << 16;
    property_ids[cursor] = find_property(
        fd, plane_id, DRM_MODE_OBJECT_PLANE, "SRC_H");
    property_values[cursor++] = (uint64_t)mode->vdisplay << 16;
    property_ids[cursor] = find_property(
        fd, plane_id, DRM_MODE_OBJECT_PLANE, "CRTC_X");
    property_values[cursor++] = 0;
    property_ids[cursor] = find_property(
        fd, plane_id, DRM_MODE_OBJECT_PLANE, "CRTC_Y");
    property_values[cursor++] = 0;
    property_ids[cursor] = find_property(
        fd, plane_id, DRM_MODE_OBJECT_PLANE, "CRTC_W");
    property_values[cursor++] = mode->hdisplay;
    property_ids[cursor] = find_property(
        fd, plane_id, DRM_MODE_OBJECT_PLANE, "CRTC_H");
    property_values[cursor++] = mode->vdisplay;
    if (cursor != ARRAY_SIZE(property_ids)) return -1;
    for (cursor = 0; cursor < ARRAY_SIZE(property_ids); ++cursor)
        if (!property_ids[cursor]) return -1;

    memset(&create_blob, 0, sizeof(create_blob));
    create_blob.data = (uintptr_t)mode;
    create_blob.length = sizeof(*mode);
    if (drm_call(fd, DRM_IOCTL_MODE_CREATEPROPBLOB, &create_blob,
                 "DRM_IOCTL_MODE_CREATEPROPBLOB") < 0)
        return -1;
    property_values[1] = create_blob.blob_id;

    memset(&atomic, 0, sizeof(atomic));
    atomic.flags = DRM_MODE_ATOMIC_TEST_ONLY |
                   DRM_MODE_ATOMIC_ALLOW_MODESET;
    atomic.count_objs = ARRAY_SIZE(object_ids);
    atomic.objs_ptr = (uintptr_t)object_ids;
    atomic.count_props_ptr = (uintptr_t)property_counts;
    atomic.props_ptr = (uintptr_t)property_ids;
    atomic.prop_values_ptr = (uintptr_t)property_values;
    if (drm_call(fd, DRM_IOCTL_MODE_ATOMIC, &atomic,
                 "DRM_IOCTL_MODE_ATOMIC test-only") < 0)
        return -1;

    atomic.flags = DRM_MODE_ATOMIC_ALLOW_MODESET |
                   DRM_MODE_PAGE_FLIP_EVENT;
    atomic.user_data = ATOMIC_COOKIE;
    if (drm_call(fd, DRM_IOCTL_MODE_ATOMIC, &atomic,
                 "DRM_IOCTL_MODE_ATOMIC commit") < 0 ||
        read_flip_event(fd, ATOMIC_COOKIE, crtc_id) < 0)
        return -1;

    memset(&destroy_blob, 0, sizeof(destroy_blob));
    destroy_blob.blob_id = create_blob.blob_id;
    if (drm_call(fd, DRM_IOCTL_MODE_DESTROYPROPBLOB, &destroy_blob,
                 "DRM_IOCTL_MODE_DESTROYPROPBLOB") < 0)
        return -1;
    memset(&copied_mode, 0, sizeof(copied_mode));
    memset(&get_blob, 0, sizeof(get_blob));
    get_blob.blob_id = create_blob.blob_id;
    get_blob.length = sizeof(copied_mode);
    get_blob.data = (uintptr_t)&copied_mode;
    if (drm_call(fd, DRM_IOCTL_MODE_GETPROPBLOB, &get_blob,
                 "DRM_IOCTL_MODE_GETPROPBLOB retained") < 0 ||
        get_blob.length != sizeof(copied_mode) ||
        copied_mode.hdisplay != mode->hdisplay ||
        copied_mode.vdisplay != mode->vdisplay) {
        fprintf(stderr, "FAIL: committed mode blob was not retained\n");
        return -1;
    }
    return 0;
}

int main(void) {
    struct drm_version version;
    struct drm_mode_modeinfo mode;
    struct drm_mode_crtc crtc;
    struct drm_mode_crtc_page_flip flip;
    test_buffer_t buffers[2];
    uint32_t crtc_id;
    uint32_t connector_id;
    char driver_name[64];
    int fd;
    int result = EXIT_FAILURE;

    memset(buffers, 0, sizeof(buffers));
    fd = open("/dev/dri/card0", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        (void)report_errno("open /dev/dri/card0");
        return EXIT_FAILURE;
    }

    memset(&version, 0, sizeof(version));
    memset(driver_name, 0, sizeof(driver_name));
    version.name = driver_name;
    version.name_len = sizeof(driver_name) - 1u;
    if (drm_call(fd, DRM_IOCTL_VERSION, &version, "DRM_IOCTL_VERSION") < 0)
        goto out;
    if (strcmp(driver_name, "edgeos-kms") != 0 &&
        strcmp(driver_name, "virtio_gpu") != 0) {
        fprintf(stderr, "FAIL: unexpected driver name: %s\n", driver_name);
        goto out;
    }
    printf("DRIVER: %s %d.%d.%d\n", driver_name, version.version_major,
           version.version_minor, version.version_patchlevel);

    if (get_display(fd, &crtc_id, &connector_id, &mode) < 0)
        goto out;
    if (drm_call(fd, DRM_IOCTL_SET_MASTER, NULL,
                 "DRM_IOCTL_SET_MASTER") < 0)
        goto out;
    if (create_buffer(fd, &mode, &buffers[0], 0x002060d0u,
                      0x00102040u) < 0 ||
        create_buffer(fd, &mode, &buffers[1], 0x0020c060u,
                      0x00104020u) < 0)
        goto out;

    memset(&crtc, 0, sizeof(crtc));
    crtc.set_connectors_ptr = (uintptr_t)&connector_id;
    crtc.count_connectors = 1;
    crtc.crtc_id = crtc_id;
    crtc.fb_id = buffers[0].framebuffer.fb_id;
    crtc.mode_valid = 1;
    crtc.mode = mode;
    if (drm_call(fd, DRM_IOCTL_MODE_SETCRTC, &crtc,
                 "DRM_IOCTL_MODE_SETCRTC") < 0)
        goto out;

    memset(&flip, 0, sizeof(flip));
    flip.crtc_id = crtc_id;
    flip.fb_id = buffers[1].framebuffer.fb_id;
    flip.flags = DRM_MODE_PAGE_FLIP_EVENT;
    flip.user_data = FLIP_COOKIE;
    if (drm_call(fd, DRM_IOCTL_MODE_PAGE_FLIP, &flip,
                 "DRM_IOCTL_MODE_PAGE_FLIP") < 0)
        goto out;

    if (read_flip_event(fd, FLIP_COOKIE, crtc_id) < 0)
        goto out;
    if (test_atomic_modeset(fd, crtc_id, connector_id, &mode,
                            buffers[0].framebuffer.fb_id) < 0)
        goto out;

    printf("PASS: Linux DRM/KMS dumb-buffer, mmap, legacy and atomic "
           "modeset, properties, blobs, poll and page-flip events\n");
    result = EXIT_SUCCESS;

out:
    destroy_buffer(fd, &buffers[1]);
    destroy_buffer(fd, &buffers[0]);
    (void)ioctl(fd, DRM_IOCTL_DROP_MASTER, NULL);
    close(fd);
    return result;
}
