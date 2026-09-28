/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Copyright (c) EdgeOS Contributors.
 *
 * Small Linux userspace smoke test for the EdgeOS ALSA-compatible control and
 * PCM playback ABI.  This is intentionally independent of libasound so it can
 * run in tiny Alpine validation rootfs images.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define SNDRV_CTL_ELEM_IFACE_MIXER 2
#define SNDRV_CTL_ELEM_TYPE_BOOLEAN 1
#define SNDRV_CTL_ELEM_TYPE_INTEGER 2

#define IOC_NRBITS   8u
#define IOC_TYPEBITS 8u
#define IOC_SIZEBITS 14u
#define IOC_NRSHIFT  0u
#define IOC_TYPESHIFT (IOC_NRSHIFT + IOC_NRBITS)
#define IOC_SIZESHIFT (IOC_TYPESHIFT + IOC_TYPEBITS)
#define IOC_DIRSHIFT (IOC_SIZESHIFT + IOC_SIZEBITS)
#define IOC_WRITE 1u
#define IOC_READ  2u
#define EDGE_IOC(dir, type, nr, size) \
    (((dir) << IOC_DIRSHIFT) | ((uint32_t)(type) << IOC_TYPESHIFT) | \
     ((nr) << IOC_NRSHIFT) | ((uint32_t)(size) << IOC_SIZESHIFT))

struct edge_snd_ctl_elem_id {
    uint32_t numid;
    int32_t iface;
    uint32_t device;
    uint32_t subdevice;
    uint8_t name[44];
    uint32_t index;
};

struct edge_snd_ctl_elem_list {
    uint32_t offset;
    uint32_t space;
    uint32_t used;
    uint32_t count;
    uint64_t pids;
    uint8_t reserved[50];
};

struct edge_snd_ctl_elem_info {
    struct edge_snd_ctl_elem_id id;
    int32_t type;
    uint32_t access;
    uint32_t count;
    int32_t owner;
    uint8_t value[128];
    uint8_t reserved[64];
};

struct edge_snd_ctl_elem_value {
    struct edge_snd_ctl_elem_id id;
    uint32_t indirect;
    uint32_t pad;
    uint8_t value[1024];
    uint8_t reserved[128];
};

static int write_pcm_square(void) {
    int fd = open("/dev/snd/pcmC0D0p", O_WRONLY);
    int16_t frame[2];
    if (fd < 0) {
        perror("open pcm");
        return 1;
    }
    for (int i = 0; i < 2400; ++i) {
        int16_t s = ((i / 48) & 1) ? -12000 : 12000;
        frame[0] = s;
        frame[1] = s;
        if (write(fd, frame, sizeof(frame)) != (ssize_t)sizeof(frame)) {
            perror("write pcm");
            close(fd);
            return 1;
        }
    }
    close(fd);
    puts("pcm_write ok");
    return 0;
}

int main(void) {
    struct edge_snd_ctl_elem_id ids[4];
    struct edge_snd_ctl_elem_list list;
    int fd;
    uint32_t list_cmd = EDGE_IOC(IOC_READ | IOC_WRITE, 'U', 0x10, sizeof(list));
    uint32_t info_cmd = EDGE_IOC(IOC_READ | IOC_WRITE, 'U', 0x11, sizeof(struct edge_snd_ctl_elem_info));
    uint32_t read_cmd = EDGE_IOC(IOC_READ | IOC_WRITE, 'U', 0x12, sizeof(struct edge_snd_ctl_elem_value));
    uint32_t write_cmd = EDGE_IOC(IOC_READ | IOC_WRITE, 'U', 0x13, sizeof(struct edge_snd_ctl_elem_value));

    memset(ids, 0, sizeof(ids));
    memset(&list, 0, sizeof(list));
    list.space = 4;
    list.pids = (uint64_t)(uintptr_t)ids;

    fd = open("/dev/snd/controlC0", O_RDWR);
    if (fd < 0) {
        perror("open control");
        return 1;
    }
    if (ioctl(fd, list_cmd, &list) < 0) {
        perror("elem list");
        close(fd);
        return 1;
    }
    printf("elem_list used=%u count=%u\n", list.used, list.count);
    if (list.count < 2 || list.used < 2) {
        fprintf(stderr, "expected at least switch and volume controls\n");
        close(fd);
        return 1;
    }

    for (uint32_t i = 0; i < list.used; ++i) {
        struct edge_snd_ctl_elem_info info;
        struct edge_snd_ctl_elem_value val;
        memset(&info, 0, sizeof(info));
        info.id = ids[i];
        if (ioctl(fd, info_cmd, &info) < 0) {
            perror("elem info");
            close(fd);
            return 1;
        }
        printf("elem%u numid=%u iface=%d name=%s type=%d count=%u\n",
               i, ids[i].numid, ids[i].iface, ids[i].name, info.type, info.count);
        if (ids[i].iface != SNDRV_CTL_ELEM_IFACE_MIXER ||
            (info.type != SNDRV_CTL_ELEM_TYPE_BOOLEAN &&
             info.type != SNDRV_CTL_ELEM_TYPE_INTEGER)) {
            fprintf(stderr, "unexpected mixer control metadata\n");
            close(fd);
            return 1;
        }
        memset(&val, 0, sizeof(val));
        val.id = ids[i];
        if (ioctl(fd, read_cmd, &val) < 0) {
            perror("elem read");
            close(fd);
            return 1;
        }
        printf("elem%u value0=%ld value1=%ld\n", i,
               ((long *)val.value)[0], ((long *)val.value)[1]);
        if (strstr((const char *)ids[i].name, "Volume")) {
            ((long *)val.value)[0] = 80;
            ((long *)val.value)[1] = 80;
            if (ioctl(fd, write_cmd, &val) < 0) {
                perror("elem write volume");
                close(fd);
                return 1;
            }
        }
    }
    close(fd);
    return write_pcm_square();
}
