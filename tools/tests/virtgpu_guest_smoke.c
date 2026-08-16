/*
 * Copyright (c) 2026 EdgeOS Contributors.
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Exercise the public Linux virtgpu render ABI from an unmodified userspace
 * process. The test uses only installed DRM UAPI headers.
 */

#include <drm.h>
#include <virtgpu_drm.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define TEST_WIDTH 64u
#define TEST_HEIGHT 64u
#define TEST_STRIDE (TEST_WIDTH * 4u)
#define TEST_SIZE (TEST_STRIDE * TEST_HEIGHT)
#define TEST_TARGET_2D 2u
#define TEST_FORMAT_B8G8R8X8_UNORM 2u
#define TEST_BIND_RENDER_TARGET (1u << 1)
#define TEST_BIND_SAMPLER_VIEW (1u << 3)

static int report_errno(const char *operation) {
    fprintf(stderr, "FAIL: %s: %s\n", operation, strerror(errno));
    return -1;
}

static int drm_call(int fd, unsigned long command, void *argument,
                    const char *operation) {
    if (ioctl(fd, command, argument) == 0) return 0;
    return report_errno(operation);
}

static int get_parameter(int fd, uint64_t parameter, uint64_t *value) {
    struct drm_virtgpu_getparam request;

    memset(&request, 0, sizeof(request));
    request.param = parameter;
    request.value = (uintptr_t)value;
    return drm_call(fd, DRM_IOCTL_VIRTGPU_GETPARAM, &request,
                    "DRM_IOCTL_VIRTGPU_GETPARAM");
}

static int test_version(int fd) {
    struct drm_version version;
    char name[32];

    memset(&version, 0, sizeof(version));
    memset(name, 0, sizeof(name));
    version.name = name;
    version.name_len = sizeof(name);
    if (drm_call(fd, DRM_IOCTL_VERSION, &version,
                 "DRM_IOCTL_VERSION") < 0)
        return -1;
    if (version.name_len != strlen("virtio_gpu") ||
        strcmp(name, "virtio_gpu") != 0) {
        fprintf(stderr, "FAIL: unexpected DRM driver name '%s'\n", name);
        return -1;
    }
    return 0;
}

static int test_capabilities(int fd, uint32_t *capset_id) {
    uint64_t three_d = 0;
    uint64_t query_fix = 0;
    uint64_t context_init = 0;
    uint64_t capsets = 0;
    uint8_t capabilities[65536];
    struct drm_virtgpu_get_caps request;

    if (get_parameter(fd, VIRTGPU_PARAM_3D_FEATURES, &three_d) < 0 ||
        get_parameter(fd, VIRTGPU_PARAM_CAPSET_QUERY_FIX, &query_fix) < 0 ||
        get_parameter(fd, VIRTGPU_PARAM_CONTEXT_INIT, &context_init) < 0 ||
        get_parameter(fd, VIRTGPU_PARAM_SUPPORTED_CAPSET_IDs,
                      &capsets) < 0)
        return -1;
    if (!three_d || !query_fix || !context_init ||
        !(capsets & ((UINT64_C(1) << 1) | (UINT64_C(1) << 2)))) {
        fprintf(stderr,
                "FAIL: incomplete virtgpu parameters: 3d=%llu query=%llu "
                "context=%llu capsets=0x%llx\n",
                (unsigned long long)three_d,
                (unsigned long long)query_fix,
                (unsigned long long)context_init,
                (unsigned long long)capsets);
        return -1;
    }
    *capset_id = (capsets & (UINT64_C(1) << 2)) ? 2u : 1u;

    memset(capabilities, 0, sizeof(capabilities));
    memset(&request, 0, sizeof(request));
    request.cap_set_id = *capset_id;
    request.cap_set_ver = 0;
    request.addr = (uintptr_t)capabilities;
    request.size = sizeof(capabilities);
    if (drm_call(fd, DRM_IOCTL_VIRTGPU_GET_CAPS, &request,
                 "DRM_IOCTL_VIRTGPU_GET_CAPS") < 0)
        return -1;
    if (!capabilities[0] && !capabilities[1] &&
        !capabilities[2] && !capabilities[3]) {
        fprintf(stderr, "FAIL: virtgpu returned an empty capability set\n");
        return -1;
    }
    return 0;
}

static int initialize_context(int fd, uint32_t capset_id) {
    struct drm_virtgpu_context_set_param parameters[2];
    struct drm_virtgpu_context_init request;

    memset(parameters, 0, sizeof(parameters));
    parameters[0].param = VIRTGPU_CONTEXT_PARAM_CAPSET_ID;
    parameters[0].value = capset_id;
    parameters[1].param = VIRTGPU_CONTEXT_PARAM_NUM_RINGS;
    parameters[1].value = 1;
    memset(&request, 0, sizeof(request));
    request.num_params = 2;
    request.ctx_set_params = (uintptr_t)parameters;
    return drm_call(fd, DRM_IOCTL_VIRTGPU_CONTEXT_INIT, &request,
                    "DRM_IOCTL_VIRTGPU_CONTEXT_INIT");
}

static int exercise_resource(int fd) {
    struct drm_virtgpu_resource_create create;
    struct drm_virtgpu_resource_info information;
    struct drm_virtgpu_map mapping;
    struct drm_virtgpu_3d_transfer_to_host transfer_to;
    struct drm_virtgpu_3d_transfer_from_host transfer_from;
    struct drm_virtgpu_execbuffer execution;
    struct drm_virtgpu_3d_wait wait;
    struct drm_gem_close close_request;
    uint32_t command = 0;
    uint32_t handles[1];
    uint32_t *pixels;
    int result = -1;

    memset(&create, 0, sizeof(create));
    create.target = TEST_TARGET_2D;
    create.format = TEST_FORMAT_B8G8R8X8_UNORM;
    create.bind = TEST_BIND_RENDER_TARGET | TEST_BIND_SAMPLER_VIEW;
    create.width = TEST_WIDTH;
    create.height = TEST_HEIGHT;
    create.depth = 1;
    create.array_size = 1;
    create.size = TEST_SIZE;
    create.stride = TEST_STRIDE;
    if (drm_call(fd, DRM_IOCTL_VIRTGPU_RESOURCE_CREATE, &create,
                 "DRM_IOCTL_VIRTGPU_RESOURCE_CREATE") < 0)
        return -1;
    if (!create.bo_handle || !create.res_handle) {
        fprintf(stderr, "FAIL: virtgpu returned invalid resource handles\n");
        return -1;
    }

    memset(&information, 0, sizeof(information));
    information.bo_handle = create.bo_handle;
    if (drm_call(fd, DRM_IOCTL_VIRTGPU_RESOURCE_INFO, &information,
                 "DRM_IOCTL_VIRTGPU_RESOURCE_INFO") < 0)
        goto close_resource;
    if (information.res_handle != create.res_handle ||
        information.size != TEST_SIZE) {
        fprintf(stderr, "FAIL: inconsistent virtgpu resource information\n");
        goto close_resource;
    }

    memset(&mapping, 0, sizeof(mapping));
    mapping.handle = create.bo_handle;
    if (drm_call(fd, DRM_IOCTL_VIRTGPU_MAP, &mapping,
                 "DRM_IOCTL_VIRTGPU_MAP") < 0)
        goto close_resource;
    pixels = mmap(NULL, TEST_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED,
                  fd, (off_t)mapping.offset);
    if (pixels == MAP_FAILED) {
        pixels = NULL;
        report_errno("mmap virtgpu resource");
        goto close_resource;
    }
    for (uint32_t index = 0; index < TEST_WIDTH * TEST_HEIGHT; ++index)
        pixels[index] = UINT32_C(0xff204080) ^ index;

    memset(&transfer_to, 0, sizeof(transfer_to));
    transfer_to.bo_handle = create.bo_handle;
    transfer_to.box.w = TEST_WIDTH;
    transfer_to.box.h = TEST_HEIGHT;
    transfer_to.box.d = 1;
    transfer_to.stride = TEST_STRIDE;
    transfer_to.layer_stride = TEST_SIZE;
    if (drm_call(fd, DRM_IOCTL_VIRTGPU_TRANSFER_TO_HOST, &transfer_to,
                 "DRM_IOCTL_VIRTGPU_TRANSFER_TO_HOST") < 0)
        goto unmap_resource;

    handles[0] = create.bo_handle;
    memset(&execution, 0, sizeof(execution));
    execution.size = sizeof(command);
    execution.command = (uintptr_t)&command;
    execution.bo_handles = (uintptr_t)handles;
    execution.num_bo_handles = 1;
    execution.fence_fd = -1;
    if (drm_call(fd, DRM_IOCTL_VIRTGPU_EXECBUFFER, &execution,
                 "DRM_IOCTL_VIRTGPU_EXECBUFFER") < 0)
        goto unmap_resource;

    memset(&wait, 0, sizeof(wait));
    wait.handle = create.bo_handle;
    wait.flags = VIRTGPU_WAIT_NOWAIT;
    if (drm_call(fd, DRM_IOCTL_VIRTGPU_WAIT, &wait,
                 "DRM_IOCTL_VIRTGPU_WAIT") < 0)
        goto unmap_resource;

    memset(&transfer_from, 0, sizeof(transfer_from));
    transfer_from.bo_handle = create.bo_handle;
    transfer_from.box.w = TEST_WIDTH;
    transfer_from.box.h = TEST_HEIGHT;
    transfer_from.box.d = 1;
    transfer_from.stride = TEST_STRIDE;
    transfer_from.layer_stride = TEST_SIZE;
    if (drm_call(fd, DRM_IOCTL_VIRTGPU_TRANSFER_FROM_HOST,
                 &transfer_from,
                 "DRM_IOCTL_VIRTGPU_TRANSFER_FROM_HOST") < 0)
        goto unmap_resource;
    result = 0;

unmap_resource:
    (void)munmap(pixels, TEST_SIZE);
close_resource:
    memset(&close_request, 0, sizeof(close_request));
    close_request.handle = create.bo_handle;
    if (ioctl(fd, DRM_IOCTL_GEM_CLOSE, &close_request) < 0 && result == 0)
        result = report_errno("DRM_IOCTL_GEM_CLOSE");
    return result;
}

int main(void) {
    uint32_t capset_id = 0;
    int fd;
    int result = 1;

    fd = open("/dev/dri/renderD128", O_RDWR | O_CLOEXEC);
    if (fd < 0) return report_errno("open /dev/dri/renderD128") < 0;
    if (test_version(fd) < 0 ||
        test_capabilities(fd, &capset_id) < 0 ||
        initialize_context(fd, capset_id) < 0 ||
        exercise_resource(fd) < 0)
        goto out;
    puts("PASS: Linux virtgpu render context, capability, resource, mmap, "
         "transfer, submit and wait ABI");
    result = 0;
out:
    (void)close(fd);
    return result;
}
