/* SPDX-License-Identifier: MPL-2.0 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define DRM_IOCTL_VIRTGPU_EXECBUFFER 0xc0406442u
#define VIRTGPU_EXECBUF_FENCE_FD_OUT 0x02u

struct virtgpu_execbuffer {
    uint32_t flags;
    uint32_t size;
    uint64_t command;
    uint64_t bo_handles;
    uint32_t num_bo_handles;
    int32_t fence_fd;
    uint32_t ring_idx;
    uint32_t syncobj_stride;
    uint32_t num_in_syncobjs;
    uint32_t num_out_syncobjs;
    uint64_t in_syncobjs;
    uint64_t out_syncobjs;
};

int main(void)
{
    struct virtgpu_execbuffer execution;
    uint32_t command = 0;
    int descriptor;
    int duplicate;

    descriptor = open("/dev/dri/renderD128", O_RDWR | O_CLOEXEC);
    if (descriptor < 0) {
        fprintf(stderr, "open failed: %s\n", strerror(errno));
        return 1;
    }
    memset(&execution, 0, sizeof(execution));
    execution.command = (uintptr_t)&command;
    execution.size = sizeof(command);
    execution.flags = VIRTGPU_EXECBUF_FENCE_FD_OUT;
    execution.fence_fd = -1;
    if (ioctl(descriptor, DRM_IOCTL_VIRTGPU_EXECBUFFER, &execution) < 0) {
        fprintf(stderr, "execbuffer failed: %s\n", strerror(errno));
        close(descriptor);
        return 1;
    }
    printf("output_fence_fd=%d\n", execution.fence_fd);
    if (execution.fence_fd < 0) {
        close(descriptor);
        return 1;
    }
    duplicate = fcntl(execution.fence_fd, F_DUPFD_CLOEXEC, 3);
    printf("duplicate_fence_fd=%d errno=%d\n", duplicate, errno);
    if (duplicate >= 0)
        close(duplicate);
    close(execution.fence_fd);
    close(descriptor);
    return duplicate < 0;
}
