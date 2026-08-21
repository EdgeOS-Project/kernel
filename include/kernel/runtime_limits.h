/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */
#ifndef EDGEOS_KERNEL_RUNTIME_LIMITS_H
#define EDGEOS_KERNEL_RUNTIME_LIMITS_H

/* Linux-visible object capacities must not vary by CPU architecture. */
/*
 * Modern browsers routinely create several hundred live processes and
 * threads in addition to the desktop session.  A 384-task system-wide table
 * made Firefox fail clone(2) during ordinary navigation while the guest still
 * had ample memory.  Keep enough headroom for a browser, desktop services, and
 * build tools on both architectures; the ARM64 runtime allocates this table
 * from detected RAM rather than reserving it in the image.
 */
#define EDGE_RUNTIME_MAX_TASKS 1024
#define EDGE_RUNTIME_MAX_OPEN_FILES 1024u
/*
 * Firefox and Chromium can keep more than 128 pipes live while the desktop,
 * browser parent, and content processes overlap during startup.  Exhausting
 * this system-wide pool makes an otherwise healthy process fail pipe2(2) even
 * though its descriptor limit and physical memory still have headroom.
 * Match the shared task, descriptor, and socket scale on both architectures.
 */
#define EDGE_RUNTIME_MAX_PIPES 1024
/*
 * A Linux desktop can keep several hundred AF_UNIX endpoints live before a
 * lock screen starts another X server, D-Bus client set, and greeter.  Stream
 * connections consume two socket objects, so a 384-object system-wide table
 * made an otherwise healthy Debian XFCE session fail socket(2) with ENOMEM.
 * Keep this architecture-neutral limit above the normal desktop high-water
 * mark until socket metadata is moved to a dynamically growable slab.
 */
#define EDGE_RUNTIME_MAX_SOCKETS 1024
#define EDGE_RUNTIME_MAX_EVENTFDS 1024
#define EDGE_RUNTIME_MAX_TIMERFDS 128
#define EDGE_RUNTIME_MAX_SIGNALFDS 128
#define EDGE_RUNTIME_MAX_INOTIFY_INSTANCES 64
#define EDGE_RUNTIME_MAX_INOTIFY_WATCHES 512
#define EDGE_RUNTIME_INOTIFY_QUEUE_SIZE 512
#define EDGE_RUNTIME_INOTIFY_NAME_MAX 256
#define EDGE_RUNTIME_MAX_FANOTIFY_GROUPS 32
#define EDGE_RUNTIME_MAX_FANOTIFY_MARKS 512
#define EDGE_RUNTIME_FANOTIFY_EVENT_POOL 512
#define EDGE_RUNTIME_FANOTIFY_GROUP_QUEUE 64
#define EDGE_RUNTIME_MAX_USERFAULTFDS 64
#define EDGE_RUNTIME_MAX_USERFAULTFD_RANGES 256
#define EDGE_RUNTIME_USERFAULTFD_EVENT_POOL 256
#define EDGE_RUNTIME_MAX_PERF_EVENTS 128
#define EDGE_RUNTIME_MAX_BPF_OBJECTS 128
#define EDGE_RUNTIME_MAX_BPF_ATTACHMENTS 256
#define EDGE_RUNTIME_MAX_QUOTA_FILESYSTEMS 32u
#define EDGE_RUNTIME_MAX_QUOTA_ENTRIES 512u
#define EDGE_RUNTIME_SIGNAL_QUEUE_SIZE 1024
#define EDGE_RUNTIME_MAX_EPOLLS 128
#define EDGE_RUNTIME_MAX_EPOLL_WATCHES 256
#define EDGE_RUNTIME_SOCKET_BACKLOG 128
#define EDGE_RUNTIME_UNIX_SOCKET_BUFFER_SIZE (128u * 1024u)
#define EDGE_RUNTIME_UNIX_RECORD_QUEUE 128u
#define EDGE_RUNTIME_NETLINK_BUFFER_SIZE (32u * 1024u)
#define EDGE_RUNTIME_NETLINK_RECORD_QUEUE 128u
/*
 * Keep stream copy granularity architecture-neutral and aligned with the
 * Ethernet TCP payload size.  Smaller architecture-local chunks add extra
 * user-copy and transport queue operations to every large write.
 */
#define EDGE_RUNTIME_STREAM_COPY_CHUNK 1460u

#endif
