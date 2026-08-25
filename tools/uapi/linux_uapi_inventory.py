#!/usr/bin/env python3
"""Build a reproducible Linux UAPI symbol inventory for EdgeOS."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Iterable


REFERENCE_COMMIT = "a13c140cc289c0b7b3770bce5b3ad42ab35074aa"

EDGEOS_ASSESSMENTS = [
    {
        "domain": "key retention service",
        "status": "partial",
        "kconfig": ["KEYS"],
        "architectures": {
            "x86_64": "runtime-verified-partial",
            "aarch64": "runtime-verified-partial",
            "ia32": "runtime-verified-partial",
            "x32": "runtime-verified-partial",
        },
        "implemented": [
            "user, logon, big-key and keyring objects with descriptor-independent serial lifetime",
            "thread, process, session, user, user-session and persistent keyrings",
            "per-user-namespace named keyring isolation",
            "add, request, update, revoke, invalidate, search, read, link, unlink and move operations",
            "ownership, permissions, timeout, restriction and session-to-parent policy",
            "Linux capability discovery with zero-filled extension bytes",
            "key notification watches with removal records and notification-pipe lifetime",
            "namespace-tagged named keyrings and same-description key isolation",
            "raw finite-field key agreement through user-key payloads for standard groups through 8192 bits",
            "SP800-108 counter-mode SHA-224 and SHA-256 derivation with Linux output and other-info limits",
            "SP800-108 counter-mode SHA-1, SHA-384 and SHA-512 derivation when those digest algorithms are configured",
            "ia32 and x32 iovec and key-derivation parameter layouts",
        ],
        "missing": [
            "positive request-key construction authorization and successful instantiate, negate and reject operations",
            "nonstandard raw finite-field parameters above 8192 bits and asymmetric key operations",
        ],
        "runtime_tests": [
            "tools/tests/keyring_abi_probe.c",
            "tools/tests/keyring_dh_abi_probe.c",
            "tools/tests/keyring_runtime_unit.c",
            "tools/tests/ia32_keyctl_compat_uapi_probe.c",
            "tools/tests/x32_keyctl_compat_uapi_probe.c",
        ],
        "linux_oracle": {
            "status": "partial",
            "reference": REFERENCE_COMMIT,
            "scope": (
                "capability byte layout, session keyring creation, object add, "
                "search, read, update, revoke, links and named keyring "
                "user-namespace isolation, plus notification watch setup, "
                "delivery and removal records, plus raw finite-field results "
                "through 8192-bit parameters, "
                "size negotiation and SHA-1, SHA-224, SHA-256, "
                "SHA-384 or SHA-512 KDF output, "
                "plus ia32 and x32 boundary-checked iovec and KDF layouts"
            ),
        },
    },
    {
        "domain": "userfaultfd",
        "status": "partial",
        "kconfig": ["USERFAULTFD"],
        "architectures": {
            "x86_64": "runtime-verified-partial",
            "aarch64": "runtime-verified-partial",
            "ia32": "runtime-verified-partial",
            "x32": "runtime-verified-partial",
        },
        "implemented": [
            "API negotiation and thread-ID page-fault records",
            "exact fault addresses and signal-delivery mode without queued events",
            "missing-page registration, copy, zero-page, wake and unregister operations",
            "missing-page handling for shared memfd and tmpfs mappings",
            "write-protect registration, resident-page permission faults and wake behavior",
            "copy-and-write-protect mode and close-time permission restoration",
            "write-protecting unpopulated anonymous pages and asynchronous per-page write-fault resolution",
            "anonymous private page moves with strict destination and source-hole handling",
            "anonymous poisoned-page markers with persistent SIGBUS fault behavior",
            "registration cleanup across unmap, replacing fixed mappings and remap without event negotiation",
            "architecture-independent range, event and waiter state",
            "shared-memory minor faults with CONTINUE, DONTWAKE and write-protect completion modes",
            "fork events with inherited registrations and child userfaultfd descriptors",
            "remap, remove and unmap event records with Linux range layouts and blocking completion",
            "ia32 and x32 API negotiation, registration and unregistration with fixed-width ioctl layouts",
        ],
        "missing": [
            "hugetlb minor-fault behavior",
        ],
        "runtime_tests": [
            "tools/tests/userfaultfd_abi_probe.c",
            "tools/tests/compat_userfaultfd_uapi_probe.c",
            "tools/tests/userfaultfd_runtime_unit.c",
        ],
        "linux_oracle": {
            "status": "partial",
            "reference": REFERENCE_COMMIT,
            "scope": (
                "feature bits, range ioctl masks, anonymous and shared memfd "
                "missing-page copy and zero-page behavior, anonymous private "
                "page moves, poisoned-page markers and SIGBUS faults, mapping "
                "lifecycle cleanup, resident and unpopulated asynchronous write "
                "protection, write-protect event flags and wake behavior, plus "
                "ia32 and x32 page-boundary API, register and unregister layouts"
            ),
        },
    },
    {
        "domain": "io_uring",
        "status": "partial",
        "kconfig": ["IO_URING"],
        "architectures": {
            "x86_64": "runtime-verified",
            "aarch64": "runtime-verified",
            "ia32": "runtime-verified-partial",
            "x32": "runtime-verified-partial",
        },
        "implemented": [
            "setup and mapped submission/completion rings",
            "128-byte SQE and 32-byte CQE ring layouts with Linux opcode numbering through NOP128",
            "mixed 64/128-byte SQE and 16/32-byte CQE rings with double-slot accounting and wrap padding",
            "NOP, READ, WRITE, READV, WRITEV and FSYNC operations",
            "NOP result injection, descriptor and registered-buffer validation, task-work acceptance and CQE32 payloads",
            "probe and disabled-ring registration",
            "completion eventfd registration and notification",
            "single-shot and multishot poll completions with update operations",
            "relative, absolute, immediate-argument and multishot timeout requests",
            "completion-count timeouts",
            "timeout removal and user-data cancellation",
            "classic and extended temporary signal-mask enter arguments",
            "relative and absolute extended enter deadlines with minimum-wait batching",
            "completion-before-signal enter return ordering and CQ-capacity clamping",
            "kernel-allocated registered wait regions and indexed enter arguments",
            "OPENAT, OPENAT2, CLOSE, STATX and FALLOCATE through shared VFS handlers",
            "SEND, RECV, SENDMSG, RECVMSG and SHUTDOWN through shared socket handlers",
            "CONNECT and ACCEPT through shared socket handlers",
            "FADVISE, MADVISE, EPOLL_CTL and TEE through shared subsystem handlers",
            "RENAMEAT, UNLINKAT, MKDIRAT, SYMLINKAT and LINKAT through shared VFS handlers",
            "SOCKET, BIND and LISTEN through shared socket handlers",
            "FSETXATTR, SETXATTR, FGETXATTR, GETXATTR and FTRUNCATE through shared VFS handlers",
            "SYNC_FILE_RANGE through the shared bounded writeback policy",
            "FUTEX_WAKE through the shared futex2 handler",
            "fixed-file registration, sparse tables and retained descriptor lifetime",
            "fixed-file replacement, clearing and skip updates with partial progress",
            "submission-queue fixed-file updates through IORING_OP_FILES_UPDATE",
            "fixed-file installation with Linux close-on-exec policy",
            "FILES2 sparse registration, UPDATE2 layouts and resource tag completion events",
            "bounded fixed-buffer registration, sparse entries, updates, tags and range validation",
            "ia32 and x32 fixed-buffer registration and update iovec conversion",
            "ia32 and x32 setup, mapped SQ/CQ/SQE rings, NOP completion and compat READV iovec conversion",
            "bounded fixed-buffer user-page pinning with retained lifetime across unmap",
            "READ_FIXED and WRITE_FIXED through pinned pages for regular files, pipes, stream sockets, pseudo-terminals, physical terminals and memory character devices",
            "READV_FIXED and WRITEV_FIXED with pinned registered-buffer ranges for regular files and pipes",
            "bounded legacy provided-buffer groups with FIFO selection for READ, READV and RECV",
            "PROVIDE_BUFFERS and REMOVE_BUFFERS with Linux buffer IDs and CQE flags",
            "user-provided buffer-ring registration, status, unregistration and 16-bit head wrap",
            "retained user-provided buffer-ring pages with lifetime independent of the original mapping",
            "kernel-allocated mmap buffer rings with shared page lifetime",
            "kernel-allocated incremental buffer consumption with min-left thresholds and BUF_MORE completions",
            "user-provided incremental buffer consumption through retained ring pages",
            "buffer-ring selection for READ, READV and RECV with Linux CQE buffer IDs",
            "per-task registered-ring descriptors for enter and register operations",
            "timeout removal and update with retained clock selection",
            "per-ring monotonic or boottime enter clocks",
            "fixed-file automatic allocation range registration",
            "pipe creation with ordinary descriptors and explicit or automatic fixed-file slots",
            "architecture-correct O_DIRECT packet pipes with record truncation semantics",
            "O_NOTIFICATION_PIPE creation and watch-queue sizing through IORING_OP_PIPE",
            "splice with immediate offsets and ordinary or fixed input and output descriptors",
            "MSG_RING data delivery, CQE flag forwarding and buffered target-CQ overflow",
            "MSG_RING registered-file transfer with explicit or allocated target slots, CQE skipping and retained lifetime",
            "SEND_ZC and SENDMSG_ZC copy fallback for IPv4 and IPv6 sockets with Linux main and notification CQEs",
            "URING_CMD and URING_CMD128 dispatch for socket GETSOCKOPT, SETSOCKOPT, GETSOCKNAME and GETPEERNAME commands",
            "pending poll requests retain their open file descriptions across descriptor close and reuse",
            "EPOLL_WAIT with retained epoll objects, asynchronous completion and native x86_64 and AArch64 event layouts",
            "LINK_TIMEOUT cancellation races, target lifetime and paired completion results",
            "FUTEX_WAIT and FUTEX_WAITV asynchronous completion through the shared futex2 wait registry",
            "WAITID immediate and asynchronous child-state completion with retained submitter identity",
            "READ_MULTISHOT pipe reads with retained descriptions, legacy provided buffers, normal buffer rings and incremental partial-buffer lifetime",
            "blind linked capability queries for supported request, registration, setup, enter, SQE and feature flags",
            "synchronous and asynchronous cancellation by user data, file description, opcode or any request, including all-match counts",
            "disabled-ring restrictions for register operations, SQE opcodes and allowed or required SQE flags",
            "one-shot task restrictions inherited by newly created rings and forked tasks",
            "registered credential personalities with scoped SQE execution and submitter credential restoration",
            "fixed-buffer cloning from ordinary or registered source rings with ranges and destination replacement",
            "synchronous blind MSG_RING data delivery without a source ring",
            "DEFER_TASKRUN ring resizing with Linux-compatible old mapping lifetime and pending SQ/CQ preservation",
            "NAPI busy-poll configuration, state handback, static receive-context IDs and bounded enter polling",
            "scheduler-native enter suspension without an initial busy-poll window",
            "user-provided pinned parameter regions with writable-page validation, retained lifetime and registered wait arguments",
            "IORING_SETUP_NO_MMAP user-backed shared SQ/CQ storage and SQE storage with retained page lifetime",
            "dynamically sized fixed-buffer page lists with retained transfer after the original mapping is removed",
            "RECV_ZC for TCP sockets with nodev ZCRX areas, retained descriptions, CQE32 offsets, refill control and copy fallback",
            "SQPOLL setup, affinity validation, non-fixed descriptor feature reporting and SQ_WAKEUP or SQ_WAIT enter control",
        ],
        "missing": [
            "asynchronous worker execution",
            "pinned reads from device-specific character descriptors without kernel-buffer backends",
            "device-backed ZCRX registration and ZCRX import/export sharing",
            "remaining URING_CMD socket and device command consumers",
            "remaining ia32 and x32 semantic coverage across supported operations",
        ],
        "runtime_tests": [
            "tools/tests/io_uring_abi_probe.c",
            "tools/tests/io_uring_extended_entries_abi_probe.c",
            "tools/tests/io_uring_fixed_files_abi_probe.c",
            "tools/tests/io_uring_notification_pipe_abi_probe.c",
            "tools/tests/io_uring_fixed_buffer_pin_abi_probe.c",
            "tools/tests/io_uring_provided_buffers_abi_probe.c",
            "tools/tests/io_uring_pbuf_ring_abi_probe.c",
            "tools/tests/io_uring_registered_rings_abi_probe.c",
            "tools/tests/io_uring_timeout_update_abi_probe.c",
            "tools/tests/io_uring_poll_multishot_abi_probe.c",
            "tools/tests/io_uring_registration_abi_probe.c",
            "tools/tests/io_uring_send_zc_abi_probe.c",
            "tools/tests/io_uring_uring_cmd_abi_probe.c",
            "tools/tests/io_uring_epoll_wait_abi_probe.c",
            "tools/tests/io_uring_link_timeout_abi_probe.c",
            "tools/tests/io_uring_futex_wait_abi_probe.c",
            "tools/tests/io_uring_waitid_abi_probe.c",
            "tools/tests/io_uring_read_multishot_abi_probe.c",
            "tools/tests/io_uring_query_abi_probe.c",
            "tools/tests/io_uring_sync_cancel_abi_probe.c",
            "tools/tests/io_uring_restrictions_abi_probe.c",
            "tools/tests/io_uring_personality_abi_probe.c",
            "tools/tests/io_uring_clone_buffers_abi_probe.c",
            "tools/tests/io_uring_send_msg_ring_abi_probe.c",
            "tools/tests/io_uring_resize_abi_probe.c",
            "tools/tests/io_uring_napi_abi_probe.c",
            "tools/tests/io_uring_user_region_abi_probe.c",
            "tools/tests/io_uring_no_mmap_abi_probe.c",
            "tools/tests/io_uring_zcrx_abi_probe.c",
            "tools/tests/io_uring_sqpoll_abi_probe.c",
            "tools/tests/compat_io_uring_iovec_uapi_probe.c",
            "tools/tests/io_uring_runtime_unit.c",
        ],
        "linux_oracle": {
            "status": "partial",
            "reference": REFERENCE_COMMIT,
            "scope": (
                "setup, mmap, 128-byte SQE and 32-byte CQE layouts, NOP, "
                "NOP128, extended NOP flags, fixed and mixed SQE/CQE layouts, frozen opcode numbering, "
                "eventfd, poll, timeout, cancellation, "
                "openat, openat2, close, statx, fallocate, send, recv, "
                "sendmsg, recvmsg, shutdown, connect, accept, fadvise, "
                "madvise, epoll_ctl, tee, renameat, unlinkat, mkdirat, "
                "symlinkat, linkat, socket, bind, listen, fsetxattr, "
                "setxattr, fgetxattr, getxattr, ftruncate, sync_file_range, "
                "futex_wake, fixed-file registration, retained lifetime, register "
                "and submission-queue updates, extended resource layouts, tag "
                "completion events, fixed-file installation, frozen opcode "
                "extent, registered-ring "
                "descriptor lifetime, timeout update, finite and updated multishot "
                "timeouts, relative and absolute enter deadlines, minimum-wait "
                "batching, registered wait layouts and errors from the frozen "
                "source oracle, poll update, multishot poll, per-ring clock, "
                "fixed-file allocation range, operation probe, pipe creation "
                "and direct fixed-file allocation, notification-pipe creation "
                "and watch-queue sizing, plus packet-pipe record "
                "boundaries, short-read truncation and splice with ordinary "
                "or fixed input and output descriptors, plus MSG_RING data, "
                "flag forwarding, disabled targets and buffered CQ overflow, "
                "plus registered-file transfer with explicit and allocated "
                "slots, skipped target completions and retained lifetime after "
                "source-table removal, plus legacy and extended fixed-buffer "
                "registration, tagged updates, range errors and real pipe data "
                "through READ_FIXED and WRITE_FIXED, plus frozen-source "
                "fixed-buffer page pinning and READ_FIXED or WRITE_FIXED "
                "lifetime after the original mapping is removed, plus "
                "READV_FIXED and WRITEV_FIXED layouts with EdgeOS runtime data, "
                "plus legacy provided-buffer add, remove, empty-group, READ and "
                "single-iovec READV selection behavior with returned buffer IDs, "
                "plus user-provided buffer-ring registration, READ and READV "
                "selection, returned IDs, head status, user and kernel-allocated "
                "mmap ring lifetime, unregistration and "
                "legacy-versus-ring failed-I/O buffer consumption, plus "
                "incremental address and length updates, min-left retirement "
                "and BUF_MORE completions on kernel-allocated and user-provided rings, "
                "including buffer selection after the original user ring mapping is removed, "
                "plus SEND_ZC and SENDMSG_ZC copied sends, fixed-file and "
                "fixed-buffer validation, vectorized payloads, notification CQEs "
                "and report-usage results, plus EPOLL_WAIT validation, retained "
                "epoll lifetime, deferred completion and architecture-native "
                "epoll_event layouts, plus LINK_TIMEOUT target-first, "
                "timeout-first and unlinked-request completion behavior, plus "
                "FUTEX_WAIT and FUTEX_WAITV value validation, wake results, "
                "vector indexes and cancellation lifetime, plus READ_MULTISHOT "
                "pipe reads, provided-buffer IDs, incremental address and "
                "length updates, BUF_MORE lifetime, min-left retirement, "
                "ENOBUFS termination, "
                "cancellation and descriptor validation, plus frozen-source "
                "blind linked capability-query layouts, per-entry results and "
                "zero-filled extension bytes, plus synchronous and asynchronous "
                "cancel matching, all-match counts, target completions and "
                "reserved-field validation, plus disabled-ring restriction "
                "registration and register, opcode and SQE-flag enforcement, "
                "plus one-shot task restrictions, new-ring inheritance, fork "
                "inheritance and task-exit cleanup, "
                "plus credential-personality registration, use, restoration "
                "and invalidation, plus fixed-buffer cloning, range validation "
                "and destination replacement, plus synchronous blind MSG_RING "
                "data and CQE-flag delivery, plus DEFER_TASKRUN ring growth, "
                "old mapping lifetime, replacement mmap geometry, pending SQ "
                "and CQ preservation and shrink-overflow behavior, plus NAPI "
                "registration layouts, state handback, validation and disabled-"
                "configuration behavior from the frozen oracle, with enabled "
                "busy-poll state and enter behavior verified on EdgeOS, plus "
                "user-provided pinned parameter regions, handback, duplicate "
                "registration, mmap rejection and registered wait arguments, "
                "plus IORING_SETUP_NO_MMAP shared-ring and SQE user memory, "
                "page-alignment errors, direct NOP submission and CQE layout, "
                "plus URING_CMD and URING_CMD128 socket option and name "
                "commands with unsupported-command and layout validation, "
                "plus TCP RECV_ZC with nodev ZCRX registration, CQE32 data "
                "offsets, finite multishot completion, refill mmap and flush "
                "control, "
                "plus SQPOLL setup combinations, CPU affinity validation, "
                "non-fixed descriptor feature reporting, SQ_WAKEUP and "
                "SQ_WAIT completion control, "
                "plus ia32 and x32 fixed-buffer registration, setup and mapped "
                "ring layouts, NOP SQE/CQE completion and READV iovec boundary "
                "handling"
            ),
        },
    },
    {
        "domain": "bpf",
        "status": "partial",
        "kconfig": ["BPF_SYSCALL"],
        "architectures": {
            "x86_64": "runtime-verified-partial",
            "aarch64": "runtime-verified-partial",
            "ia32": "runtime-verified-partial",
            "x32": "runtime-verified-partial",
        },
        "implemented": [
            "array and hash map creation with descriptor-backed lifetime",
            "map lookup, update, delete and key iteration",
            "LRU hash maps with access-order eviction and lookup-and-delete operations",
            "queue and stack maps with push, peek, pop and full-map replacement semantics",
            "per-CPU array and hash maps with possible-CPU value layouts, padded value slots and explicit CPU access modes",
            "per-CPU LRU hash maps with shared eviction order and possible-CPU values",
            "no-common-LRU maps with rounded capacity and independent per-CPU eviction domains",
            "array-of-maps and hash-of-maps creation, template validation, element and batch operations and referenced-map lifetime",
            "map and program ID enumeration and descriptor reopening",
            "map information queries",
            "program information, translated instruction and SHA-256 tag queries",
            "bounded cgroup-device program verification and execution",
            "cgroup-device attachment, detachment and direct or effective queries",
            "hierarchical cgroup-device checks for device open and creation",
            "LPM trie maps with longest-prefix lookup and batch operations",
            "Bloom filter maps with Linux hash selection and peek semantics",
            "BTF object loading, information queries, ID enumeration and descriptor reopening",
            "BTF-backed map creation with retained BTF object lifetime",
            "cgroup link objects with descriptor lifetime, ID enumeration, information queries, program replacement, explicit detach and close-time detach",
            "kernel and user ring-buffer maps with mmap, poll and cgroup-device output execution",
            "cgroup array maps with retained cgroup lifetime, replacement and deletion semantics",
            "BPF filesystem mounting, object pinning, access-restricted reopening and unlink lifetime",
            "explicit map binding to program lifetime with program map-ID reporting",
            "runtime statistics enable descriptors with close-time disable semantics",
            "program test-run and unknown-command error ordering for the supported program family",
            "stack-trace map creation, build-ID value layouts, rounded bucket addressing and empty syscall operations",
            "CPU-map creation, CPU and queue validation, entry lifecycle, optional program descriptor rejection and Linux unsupported-operation behavior",
            "device-map and device-hash creation, network-interface validation, entry lifecycle, capacity, iteration and program descriptor behavior",
            "XSK-map creation, syscall lookup rejection, socket descriptor and family error behavior, deletion, key iteration and unsupported batch behavior",
            "socket-array and socket-hash creation, connected stream socket insertion, cookie lookup, close-time removal, replacement, deletion and key iteration semantics",
            "reuseport socket-array creation, bound TCP and UDP insertion, single-map membership, cookie lookup, replacement, deletion, close-time removal and key iteration semantics",
            "cgroup local-storage creation with BTF, cgroup FD lookup, insertion, replacement, deletion, reference lifetime and unsupported iteration semantics",
            "socket local-storage creation with BTF, socket FD and alias lookup, insertion, replacement, deletion, last-close removal and unsupported iteration semantics",
            "inode local-storage creation with BTF, inode identity shared across file descriptions, insertion, replacement, close-and-reopen persistence, deletion and unsupported iteration semantics",
            "instruction-array creation, offset update and zeroing behavior, lookup, iteration, freeze and unsupported delete and batch operations",
            "resizable-hash creation flag and size-hint validation, element operations, iteration, lookup-and-delete, batch operations and freeze behavior",
            "ia32 and x32 fixed-width map-create and map-element attribute layouts",
        ],
        "missing": [
            "remaining map types, socket-map and reuseport program attachment and redirect execution, reuseport disconnect-time removal, local-storage program helper access, socket clone propagation and diagnostic export, cgroup owner-removal cleanup, inode destruction cleanup, deprecated cgroup-storage attachment integration, stack-trace helper population, CPU-map packet redirect execution, device-map packet redirect execution and AF_XDP socket-backed XSK-map entries",
            "resizable-hash concurrent dynamic resizing and full Linux key and value size range",
            "remaining specialized map-family concurrency semantics, plus instruction-array verifier and jump-table integration",
            "additional attachment families and program types",
            "complete allow-override and multi-position attachment semantics",
            "complete BTF type-graph validation and program integration",
        ],
        "runtime_tests": [
            "tools/tests/bpf_abi_probe.c",
            "tools/tests/compat_bpf_uapi_probe.c",
            "tools/tests/bpf_cgroup_array_abi_probe.c",
            "tools/tests/bpf_cpumap_abi_probe.c",
            "tools/tests/bpf_devmap_abi_probe.c",
            "tools/tests/bpf_xskmap_abi_probe.c",
            "tools/tests/bpf_sockmap_abi_probe.c",
            "tools/tests/bpf_reuseport_array_abi_probe.c",
            "tools/tests/bpf_cgrp_storage_abi_probe.c",
            "tools/tests/bpf_sk_storage_abi_probe.c",
            "tools/tests/bpf_inode_storage_abi_probe.c",
            "tools/tests/bpf_insn_array_abi_probe.c",
            "tools/tests/bpf_rhash_abi_probe.c",
            "tools/tests/bpf_stack_trace_abi_probe.c",
            "tools/tests/bpf_runtime_unit.c",
        ],
        "linux_oracle": {
            "status": "partial",
            "reference": REFERENCE_COMMIT,
            "scope": (
                "array and hash maps, map element operations, object IDs, "
                "LRU hash creation, access-order eviction, element operations, "
                "queue and stack creation, push, peek, pop and replacement, "
                "per-CPU array, hash and LRU hash layouts, CPU selection, all-CPU updates, no-common-LRU eviction domains and map-in-map element and batch operations, "
                "descriptor reopening, map and program information, "
                "translated instructions, SHA-256 tags and cgroup-device "
                "program loading, attachment, detachment and query behavior, "
                "plus cgroup link object creation, replacement, information, "
                "ID enumeration and lifetime, kernel and user ring buffers, "
                "cgroup array descriptors and retained cgroup lifetime, "
                "BPF filesystem object pinning, explicit program-map binding, "
                "runtime statistics descriptors and supported program-test "
                "error behavior, stack-trace map creation, value-depth limits, "
                "rounded bucket addressing and empty map operations, CPU-map "
                "creation, qsize state, CPU bounds, program descriptor errors "
                "and unsupported operations, device-map and device-hash "
                "interface validation, lifecycle, capacity and iteration, "
                "XSK-map creation, syscall lookup rejection, socket "
                "descriptor and family errors, deletion, key iteration and "
                "unsupported batch behavior, "
                "socket-array and socket-hash creation, connected stream "
                "socket insertion, cookie lookup, close-time removal, "
                "replacement, deletion and key iteration, "
                "reuseport socket-array creation, bound TCP and UDP "
                "insertion, single-map membership, cookie lookup, "
                "replacement, deletion, close-time removal and iteration, "
                "cgroup local-storage BTF creation, cgroup FD lookup, "
                "insertion, replacement, deletion, reference lifetime and "
                "unsupported iteration, "
                "socket local-storage BTF creation, socket FD and alias "
                "lookup, insertion, replacement, deletion, last-close "
                "removal and unsupported iteration, "
                "inode local-storage BTF creation, shared inode identity "
                "across file descriptions, insertion, replacement, "
                "close-and-reopen persistence, deletion and unsupported "
                "iteration, "
                "instruction-array creation, offset updates, lookup, "
                "iteration, freeze and unsupported delete and batch behavior, "
                "resizable-hash creation flags, size hints, element and batch "
                "operations, iteration, lookup-and-delete and freeze behavior, "
                "plus ia32 "
                "and x32 page-boundary map-create, "
                "map-update and map-lookup attribute layouts"
            ),
        },
    },
]


def coverage_assessment(
        identifier: str, status: str, architectures: dict[str, str],
        *, kconfig: list[str] | None = None,
        runtime_tests: list[str] | None = None,
        oracle_status: str | None = None,
        oracle_scope: str | None = None) -> dict[str, object]:
    """Describe the evidence boundary for an extracted UAPI group."""
    assessment = {
        "id": identifier,
        "status": status,
        "kconfig": kconfig or [],
        "architectures": architectures,
        "runtime_tests": runtime_tests or [],
        "linux_oracle": {
            "status": oracle_status or
                      ("required" if status != "verified" else "verified"),
            "reference": REFERENCE_COMMIT,
        },
    }
    if oracle_scope:
        assessment["linux_oracle"]["scope"] = oracle_scope
    return assessment


NATIVE_ARCHITECTURES = {
    "x86_64": "partial",
    "aarch64": "partial",
    "ia32": "unimplemented",
    "x32": "unimplemented",
}

COMPAT_ARCHITECTURES = {
    "x86_64": "not-applicable",
    "aarch64": "not-applicable",
    "ia32": "runtime-verified-partial",
    "x32": "not-applicable",
}

X32_ARCHITECTURES = {
    "x86_64": "not-applicable",
    "aarch64": "not-applicable",
    "ia32": "not-applicable",
    "x32": "runtime-verified-partial",
}

SYSCALL_NATIVE_ARCHITECTURES = {
    "x86_64": "runtime-verified-partial",
    "aarch64": "runtime-verified-partial",
    "ia32": "not-applicable",
    "x32": "not-applicable",
}

COVERAGE_ASSESSMENTS = [
    coverage_assessment(
        "syscalls-native", "partial", SYSCALL_NATIVE_ARCHITECTURES,
        runtime_tests=[
            "tools/syscalls/linux_syscall_inventory.json",
            "tools/tests/validate_syscall_inventory.py",
            "tools/tests/arch_syscall_parity.py",
        ]),
    coverage_assessment(
        "syscalls-ia32", "partial", COMPAT_ARCHITECTURES,
        kconfig=["COMPAT_IA32"],
        runtime_tests=[
            "tools/tests/ia32_compat_uapi_probe.S",
            "tools/tests/ia32_runtime_uapi_probe.S",
            "tools/tests/ia32_common_uapi_probe.c",
            "tools/tests/ia32_fd_mm_uapi_probe.c",
            "tools/tests/ia32_largefile_uapi_probe.c",
            "tools/tests/ia32_legacy_id_stat_uapi_probe.c",
            "tools/tests/ia32_modern_uapi_probe.c",
            "tools/tests/ia32_numa_aio_quota_uapi_probe.c",
            "tools/tests/ia32_posix_mq_uapi_probe.c",
            "tools/tests/ia32_ptrace_uapi_probe.c",
            "tools/tests/ia32_resource_uapi_probe.c",
            "tools/tests/ia32_signal_ldt_uapi_probe.c",
            "tools/tests/ia32_socketcall_uapi_probe.c",
            "tools/tests/ia32_sysv_ipc_uapi_probe.c",
            "tools/tests/ia32_time_uapi_probe.c",
            "tools/tests/ia32_disabled_syscalls_uapi_probe.c",
            "tools/tests/ia32_keyctl_compat_uapi_probe.c",
            "tools/tests/compat_io_uring_iovec_uapi_probe.c",
            "tools/tests/compat_userfaultfd_uapi_probe.c",
            "tools/tests/compat_bpf_uapi_probe.c",
        ],
        oracle_status="partial",
        oracle_scope=(
            "ELF loading, int 0x80 entry, scalar and common calls, legacy and "
            "time64 structures, file and memory operations, socketcall, SysV "
            "IPC, POSIX message queues, signals, LDT and TLS, ptrace, NUMA, "
            "quota, AIO, keyctl, io_uring, userfaultfd and BPF compatibility "
            "layouts, architecture control "
            "and configuration-disabled slots"
        )),
    coverage_assessment(
        "syscalls-x32", "partial", X32_ARCHITECTURES,
        kconfig=["X86_X32_ABI"],
        runtime_tests=[
            "tools/tests/x32_scalar_abi_probe.c",
            "tools/tests/x32_iovec_abi_probe.c",
            "tools/tests/x32_socket_message_abi_probe.c",
            "tools/tests/x32_socket_control_abi_probe.c",
            "tools/tests/x32_mmsg_abi_probe.c",
            "tools/tests/x32_socket_option_abi_probe.c",
            "tools/tests/x32_robust_list_abi_probe.c",
            "tools/tests/x32_signal_registration_abi_probe.c",
            "tools/tests/x32_signal_info_abi_probe.c",
            "tools/tests/x32_keyctl_compat_uapi_probe.c",
            "tools/tests/x32_process_observation_abi_probe.c",
            "tools/tests/x32_time_abi_probe.c",
            "tools/tests/x32_basic_io_abi_probe.c",
            "tools/tests/x32_common_entry_abi_probe.c",
            "tools/tests/compat_io_uring_iovec_uapi_probe.c",
            "tools/tests/compat_userfaultfd_uapi_probe.c",
            "tools/tests/compat_bpf_uapi_probe.c",
        ],
        oracle_status="partial",
        oracle_scope=(
            "x32 syscall-number mask, scalar identity calls, scheduler yield, "
            "high-bit pointer rejection, descriptor creation and lifetime, "
            "x32 iovec conversion for vector, positioned and cross-process "
            "I/O, sendmsg and recvmsg compat-header conversion, x32 control "
            "message alignment, SCM_RIGHTS and SCM_CREDENTIALS delivery, "
            "sendmmsg and recvmmsg arrays with time64 timeout writeback, and "
            "old and time64 socket timeouts, scalar socket options and "
            "compat socket-filter programs, compat robust-list registration "
            "and query layouts, compat signal-action and alternate-stack "
            "registration, signal-mask and pending-set semantics, tagged "
            "compat siginfo conversion for queued process and thread "
            "signals, timed-wait delivery, and pidfd signal metadata, and "
            "compat waitid child information with native x32 wait4 and "
            "getrusage layouts, and "
            "native x32 64-bit time, interval-timer and timerfd layouts, and "
            "keyctl, io_uring, userfaultfd and BPF compat layouts, including "
            "native x32 KDF parameter layout, and "
            "basic file, path, offset, stat, pipe and UNIX socket I/O, and "
            "UTS data, CPU placement, affinity and random "
            "data queries, and "
            "Linux-designated common syscall entries including memory, "
            "resource limits, futex, poll and packed epoll layouts, and "
            "unassigned-number ENOSYS behavior"
        )),
    coverage_assessment(
        "ioctl-tty", "partial", NATIVE_ARCHITECTURES,
        runtime_tests=["tools/tests/tty_session_unit.c"]),
    coverage_assessment(
        "ioctl-input", "partial", NATIVE_ARCHITECTURES,
        runtime_tests=[
            "tools/tests/linux_input_unit.c",
            "tools/tests/file_description_runtime_unit.c",
        ],
        oracle_status="partial",
        oracle_scope=(
            "EVIOCGRAB owner, repeat-grab and non-owner release errors, plus "
            "EVIOCREVOKE post-revocation behavior"
        )),
    coverage_assessment("ioctl-graphics", "partial", NATIVE_ARCHITECTURES,
                        kconfig=["DRM"]),
    coverage_assessment("ioctl-media", "partial", NATIVE_ARCHITECTURES,
                        kconfig=["MEDIA_SUPPORT"]),
    coverage_assessment("ioctl-audio", "partial", NATIVE_ARCHITECTURES,
                        kconfig=["SOUND"]),
    coverage_assessment("ioctl-usb", "partial", NATIVE_ARCHITECTURES,
                        kconfig=["USB"]),
    coverage_assessment("ioctl-storage", "partial", NATIVE_ARCHITECTURES,
                        kconfig=["BLOCK"]),
    coverage_assessment("ioctl-network", "partial", NATIVE_ARCHITECTURES,
                        kconfig=["NET"]),
    coverage_assessment("ioctl-platform", "partial", NATIVE_ARCHITECTURES),
    coverage_assessment(
        "ioctl-events", "partial", NATIVE_ARCHITECTURES,
        kconfig=["PERF_EVENTS", "USERFAULTFD"],
        runtime_tests=[
            "tools/tests/perf_event_abi_probe.c",
            "tools/tests/perf_event_runtime_unit.c",
            "tools/tests/userfaultfd_abi_probe.c",
            "tools/tests/userfaultfd_runtime_unit.c",
        ]),
    coverage_assessment("socket-options", "partial", NATIVE_ARCHITECTURES,
                        kconfig=["NET"]),
    coverage_assessment(
        "io-uring", "partial", NATIVE_ARCHITECTURES,
        kconfig=["IO_URING"],
        runtime_tests=["tools/tests/io_uring_runtime_unit.c"]),
    coverage_assessment("netlink", "partial", NATIVE_ARCHITECTURES,
                        kconfig=["NET"]),
    coverage_assessment(
        "procfs", "partial", NATIVE_ARCHITECTURES,
        runtime_tests=["tools/tests/proc_task_unit.c"]),
    coverage_assessment(
        "sysfs", "partial", NATIVE_ARCHITECTURES,
        runtime_tests=["tools/tests/sysfs_uevent_abi_probe.c"]),
    coverage_assessment("cgroup-v2", "partial", NATIVE_ARCHITECTURES,
                        kconfig=["CGROUPS"]),
]

IOCTL_HEADERS = {
    "tty": ("include/uapi/asm-generic/ioctls.h", "include/uapi/linux/kd.h",
            "include/uapi/linux/tty.h", "include/uapi/linux/vt.h"),
    "input": ("include/uapi/linux/input.h", "include/uapi/linux/hiddev.h",
              "include/uapi/linux/hidraw.h", "include/uapi/linux/uhid.h"),
    "graphics": ("include/uapi/drm/drm.h", "include/uapi/drm/drm_mode.h",
                 "include/uapi/linux/fb.h"),
    "media": ("include/uapi/linux/videodev2.h",),
    "audio": ("include/uapi/sound/asound.h",),
    "usb": ("include/uapi/linux/usbdevice_fs.h",),
    "storage": ("include/uapi/linux/fs.h", "include/uapi/linux/loop.h",
                "include/uapi/linux/dm-ioctl.h", "include/uapi/linux/blkpg.h",
                "include/uapi/linux/cdrom.h", "include/uapi/linux/hdreg.h",
                "include/uapi/linux/nvme_ioctl.h"),
    "network": ("include/uapi/linux/if_tun.h", "include/uapi/linux/ethtool.h",
                "include/uapi/linux/rfkill.h"),
    "platform": ("include/uapi/linux/rtc.h", "include/uapi/linux/watchdog.h",
                 "include/uapi/linux/i2c-dev.h"),
    "events": ("include/uapi/linux/perf_event.h",
               "include/uapi/linux/userfaultfd.h"),
}

SOCKET_HEADERS = (
    "include/uapi/asm-generic/socket.h",
    "include/uapi/linux/in.h",
    "include/uapi/linux/in6.h",
    "include/uapi/linux/tcp.h",
    "include/uapi/linux/udp.h",
    "include/uapi/linux/if_packet.h",
    "include/uapi/linux/netlink.h",
    "include/uapi/linux/filter.h",
)

NETLINK_HEADERS = (
    "include/uapi/linux/rtnetlink.h",
    "include/uapi/linux/if_link.h",
    "include/uapi/linux/if_addr.h",
    "include/uapi/linux/neighbour.h",
    "include/uapi/linux/fib_rules.h",
    "include/uapi/linux/pkt_sched.h",
    "include/uapi/linux/netfilter/nf_tables.h",
    "include/uapi/linux/ethtool_netlink.h",
    "include/uapi/linux/sock_diag.h",
    "include/uapi/linux/inet_diag.h",
)

SOCKET_PREFIXES = ("SO_", "SCM_", "IP_", "IPV6_", "TCP_", "UDP_",
                   "PACKET_", "NETLINK_", "BPF_")
NETLINK_PREFIXES = ("RTM_", "RTN_", "RTA_", "IFLA_", "IFA_", "NDA_",
                    "FRA_", "TCA_", "NFT_", "ETHTOOL_", "SOCK_DIAG_",
                    "INET_DIAG_", "NLMSG_", "NLM_F_")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def logical_lines(text: str) -> Iterable[str]:
    pending = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        pending = f"{pending}{line}" if pending else line
        if pending.endswith("\\"):
            pending = pending[:-1] + " "
            continue
        yield pending
        pending = ""
    if pending:
        yield pending


def define_symbols(path: Path, prefixes: tuple[str, ...] | None = None,
                   require_ioctl: bool = False) -> list[dict[str, str]]:
    symbols: list[dict[str, str]] = []
    pattern = re.compile(r"^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\s+(.+)$")
    for line in logical_lines(path.read_text(encoding="utf-8", errors="replace")):
        match = pattern.match(line)
        if not match:
            continue
        name, expression = match.groups()
        if prefixes is not None and not name.startswith(prefixes):
            continue
        if require_ioctl and not re.search(r"\b_IO(?:R|W|WR)?\s*\(", expression):
            continue
        symbols.append({"name": name, "expression": expression.strip()})
    return symbols


def enum_symbols(path: Path, prefixes: tuple[str, ...]) -> list[dict[str, str]]:
    symbols: dict[str, dict[str, str]] = {}
    token = re.compile(r"^\s*([A-Z][A-Z0-9_]+)\s*(?:=\s*([^,]+))?,?\s*(?:/\*.*)?$")
    in_enum = False
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if re.search(r"\benum\b[^;]*\{", raw):
            in_enum = True
            continue
        if in_enum and "}" in raw:
            in_enum = False
            continue
        if not in_enum:
            continue
        match = token.match(raw)
        if not match or not match.group(1).startswith(prefixes):
            continue
        name = match.group(1)
        symbols[name] = {
            "name": name,
            "expression": (match.group(2) or "auto").strip(),
        }
    return sorted(symbols.values(), key=lambda item: item["name"])


def enum_sequence(path: Path, enum_name: str,
                  prefix: str) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    start = re.compile(rf"^\s*enum\s+{re.escape(enum_name)}\s*\{{")
    token = re.compile(
        rf"^\s*({re.escape(prefix)}[A-Z0-9_]+)"
        r"\s*(?:=\s*([^,]+))?,?\s*(?:/\*.*)?$"
    )
    in_enum = False
    value = -1
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not in_enum:
            in_enum = start.match(raw) is not None
            continue
        if "}" in raw:
            break
        match = token.match(raw)
        if not match:
            continue
        expression = match.group(2)
        if expression is None:
            value += 1
        else:
            value = int(expression.strip().rstrip("uUlL"), 0)
        entries.append({"name": match.group(1), "value": value})
    return entries


def syscall_table(path: Path, accepted_abis: set[str]) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split()
        if len(fields) < 3 or fields[1] not in accepted_abis:
            continue
        entries.append({"number": int(fields[0]), "name": fields[2],
                        "abi": fields[1]})
    return entries


def generic_syscalls(path: Path) -> list[dict[str, object]]:
    pattern = re.compile(
        r"^#define\s+__NR(?:3264)?_([A-Za-z0-9_]+)\s+([0-9]+)$"
    )
    entries = []
    for line in path.read_text(encoding="utf-8").splitlines():
        match = pattern.match(line)
        if match:
            entries.append({"name": match.group(1),
                            "number": int(match.group(2)), "abi": "common"})
    return entries


def git_output(tree: Path, *arguments: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(tree), *arguments], text=True
    ).strip()


def reference_version(tree: Path) -> str:
    values: dict[str, str] = {}
    pattern = re.compile(r"^(VERSION|PATCHLEVEL|SUBLEVEL|EXTRAVERSION)\s*=\s*(.*)$")
    for line in (tree / "Makefile").read_text(encoding="utf-8").splitlines():
        match = pattern.match(line)
        if match:
            values[match.group(1)] = match.group(2).strip()
    return (f"{values['VERSION']}.{values['PATCHLEVEL']}."
            f"{values['SUBLEVEL']}{values.get('EXTRAVERSION', '')}")


def symbol_domain(tree: Path, headers: Iterable[str], *,
                  prefixes: tuple[str, ...] | None = None,
                  require_ioctl: bool = False,
                  include_enums: bool = False,
                  assessment_id: str) -> dict[str, object]:
    items: list[dict[str, object]] = []
    sources: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for relative in headers:
        path = tree / relative
        if not path.exists():
            raise FileNotFoundError(relative)
        sources.append({"path": relative, "sha256": sha256(path)})
        symbols = define_symbols(path, prefixes, require_ioctl)
        if include_enums and prefixes is not None:
            symbols.extend(enum_symbols(path, prefixes))
        for symbol in symbols:
            key = (relative, symbol["name"])
            if key in seen:
                continue
            seen.add(key)
            items.append({
                "name": symbol["name"],
                "header": relative,
                "expression": symbol["expression"],
                "assessment": assessment_id,
                "status": "unreviewed",
            })
    items.sort(key=lambda item: (str(item["name"]), str(item["header"])))
    return {
        "sources": sources,
        "item_defaults": {
            "status": "unreviewed",
            "assessment": assessment_id,
            "kconfig": [],
            "architectures": ["x86_64", "aarch64", "ia32", "x32"],
            "runtime_tests": [],
            "linux_oracle": "required",
            "expected_errors": "reference-kernel",
        },
        "items": items,
    }


def build_inventory(tree: Path) -> dict[str, object]:
    commit = git_output(tree, "rev-parse", "HEAD")
    if commit != REFERENCE_COMMIT:
        raise ValueError(
            f"Linux reference commit is {commit}, expected {REFERENCE_COMMIT}"
        )
    x86_table = tree / "arch/x86/entry/syscalls/syscall_64.tbl"
    ia32_table = tree / "arch/x86/entry/syscalls/syscall_32.tbl"
    generic_table = tree / "scripts/syscall.tbl"
    syscall_sources = [x86_table, ia32_table, generic_table]
    syscall_architectures = {
        "x86_64": syscall_table(x86_table, {"common", "64"}),
        "x32": syscall_table(x86_table, {"common", "x32"}),
        "ia32": syscall_table(ia32_table, {"i386"}),
        "aarch64": syscall_table(
            generic_table,
            {"common", "64", "renameat", "rlimit", "memfd_secret"},
        ),
    }
    for architecture, entries in syscall_architectures.items():
        assessment = {
            "x86_64": "syscalls-native",
            "aarch64": "syscalls-native",
            "ia32": "syscalls-ia32",
            "x32": "syscalls-x32",
        }[architecture]
        for entry in entries:
            entry["assessment"] = assessment
            entry["status"] = "unreviewed"
    ioctl_groups = {
        name: symbol_domain(
            tree, headers, require_ioctl=True,
            assessment_id=f"ioctl-{name}")
        for name, headers in IOCTL_HEADERS.items()
    }
    io_uring_header = tree / "include/uapi/linux/io_uring.h"
    io_uring_domain = symbol_domain(
        tree, ("include/uapi/linux/io_uring.h",),
        prefixes=("IORING_", "IOSQE_"), include_enums=True,
        assessment_id="io-uring")
    io_uring_domain["opcodes"] = enum_sequence(
        io_uring_header, "io_uring_op", "IORING_OP_")
    return {
        "schema": 2,
        "reference": {
            "commit": commit,
            "version": reference_version(tree),
            "policy": "The commit hash, not a release nickname, is authoritative.",
        },
        "status_semantics": {
            "unreviewed": "Extracted from the frozen Linux UAPI but not audited in EdgeOS.",
            "unimplemented": "No EdgeOS implementation exists.",
            "partial": "Some operations exist, but Linux semantic parity is incomplete.",
            "configured-off": "Behavior must match Linux with the same Kconfig disabled.",
            "unsupported-subsystem": "EdgeOS has no backend and must not expose a fake device.",
            "verified": "Linux oracle and EdgeOS runtime evidence both pass.",
        },
        "scope": {
            "architectures": ["x86_64", "aarch64", "ia32", "x32"],
            "boundary": "complete UAPI for EdgeOS-supported subsystems",
            "default_status": "unreviewed",
        },
        "edgeos_assessments": EDGEOS_ASSESSMENTS,
        "coverage_assessments": COVERAGE_ASSESSMENTS,
        "domains": {
            "syscalls": {
                "sources": [
                    {"path": str(path.relative_to(tree)), "sha256": sha256(path)}
                    for path in syscall_sources
                ],
                "architecture_rules": {
                    "x86_64": {"abis": ["common", "64"]},
                    "x32": {
                        "abis": ["common", "x32"],
                        "syscall_number_or_mask": "0x40000000",
                    },
                    "ia32": {"abis": ["i386"]},
                    "aarch64": {
                        "abis": [
                            "common", "64", "renameat", "rlimit",
                            "memfd_secret",
                        ],
                    },
                },
                "architectures": syscall_architectures,
            },
            "ioctl": ioctl_groups,
            "socket_options": symbol_domain(
                tree, SOCKET_HEADERS, prefixes=SOCKET_PREFIXES,
                include_enums=True, assessment_id="socket-options"),
            "io_uring": io_uring_domain,
            "netlink": symbol_domain(
                tree, NETLINK_HEADERS, prefixes=NETLINK_PREFIXES,
                include_enums=True, assessment_id="netlink"),
            "virtual_filesystems": {
                "sources": [
                    "Documentation/filesystems/proc.rst",
                    "Documentation/admin-guide/cgroup-v2.rst",
                    "Documentation/ABI/stable and Documentation/ABI/testing",
                ],
                "status": "snapshot-required",
                "reason": "procfs, sysfs and cgroup paths are dynamic and need runtime snapshots.",
                "filesystems": [
                    {
                        "name": "procfs",
                        "assessment": "procfs",
                        "status": "partial",
                        "oracle": "runtime-snapshot",
                    },
                    {
                        "name": "sysfs",
                        "assessment": "sysfs",
                        "status": "partial",
                        "oracle": "runtime-snapshot",
                    },
                    {
                        "name": "cgroup-v2",
                        "assessment": "cgroup-v2",
                        "status": "partial",
                        "oracle": "runtime-snapshot",
                    },
                ],
            },
        },
    }


def write_inventory(document: dict[str, object], destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
