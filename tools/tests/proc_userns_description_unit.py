#!/usr/bin/env python3
"""Exercise proc namespace bindings with the production shared-description lifetime."""
import argparse
from pathlib import Path
import re
import subprocess

root = Path(__file__).resolve().parents[2]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--output", type=Path, required=True)
a = p.parse_args()
proc = (root / "src/fs/procfs.c").read_text()
ns = (root / "src/kernel/namespaces.c").read_text()
header = (root / "include/kernel/namespaces.h").read_text()

def function(source, name):
    m = re.search(r"^(?:static )?[\w *]+\b" + name + r"\([^;]*?\)\s*\{", source, re.M)
    assert m, name
    end, depth = m.end(), 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[m.start():end]

def structure(source, name):
    return re.search(r"typedef struct " + name + r" \{.*?\} " + name + r"_t;", source, re.S).group()

code = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define SYS_SPINLOCK_H
typedef struct { unsigned v; } spinlock_t;
static void spinlock_init(spinlock_t *p) { p->v=0; }
static uint64_t spin_lock_irqsave(spinlock_t *p) { (void)p; return 0; }
static void spin_unlock_irqrestore(spinlock_t *p,uint64_t f) { (void)p;(void)f; }
#define EDGE_USERNS_MAP_MAX 5
enum { EDGE_NS_POOL_CGROUP, EDGE_NS_POOL_IPC, EDGE_NS_POOL_NET,
       EDGE_NS_POOL_PID, EDGE_NS_POOL_TIME, EDGE_NS_POOL_USER, EDGE_NS_POOL_UTS };
#define EDGE_NAMESPACE_USER 8
#define PROC_PID_UID_MAP 1
#define PROC_PID_GID_MAP 2
#define PROC_PID_SETGROUPS 3
typedef struct { uint32_t fs_private[4]; } vfs_inode_t;
typedef struct { unsigned unused; } vfs_superblock_t;
typedef struct { uint32_t euid,egid,user_namespace_id; uint64_t effective_capabilities; } kernel_linux_identity_t;
typedef struct { uint32_t inside,outside,count; } edge_userns_extent_t;
typedef struct {
 uint32_t references,parent,owner_uid,owner_gid;
 uint8_t uid_map_written,gid_map_written,setgroups_allowed,uid_map_count,gid_map_count;
 edge_userns_extent_t uid_map[5],gid_map[5];
} edge_namespace_object_t;
static edge_namespace_object_t objects[8];
static unsigned allocations,freed;
static int fail_allocation,task_reaped;
static void *arch_vm_alloc_page(void) { if(fail_allocation)return NULL; ++allocations;return calloc(1,4096); }
static void arch_vm_free_page(void *p) { ++freed;free(p); }
static void namespace_lock(void) {}
static void namespace_unlock(void) {}
static edge_namespace_object_t *namespace_object(int pool,uint32_t id) {
 (void)pool;return id<8 && objects[id].references?&objects[id]:NULL;
}
static void namespace_release(int pool,uint32_t id) {
 (void)pool;assert(id<8 && objects[id].references);--objects[id].references;
}
static int edge_namespace_handle_retain(int kind,uint32_t id) {
 (void)kind;if(id>=8 || !objects[id].references)return -1;++objects[id].references;return 0;
}
static void edge_namespace_handle_release(int kind,uint32_t id) { (void)kind;namespace_release(0,id); }
static void vfs_mount_namespace_release(uint32_t id) { namespace_release(0,id); }
'''
code += structure(header, "edge_namespace_set") + "\n"
code += structure(header, "edge_userns_map_diagnostic") + "\n"
code += r'''
typedef struct { int32_t pid,tgid;edge_namespace_set_t *namespaces; } kernel_process_native_view_t;
static edge_namespace_set_t task_namespaces;
static kernel_linux_identity_t current={.euid=1000,.egid=1000,.user_namespace_id=0};
static int kernel_current_linux_identity(kernel_linux_identity_t *out) { *out=current;return 0; }
static uint64_t arch_process_task_lock(void) { return 0; }
static void arch_process_task_unlock(uint64_t lock) { (void)lock; }
static int edge_process_runtime_view(int32_t pid,kernel_process_native_view_t *out) {
 if(task_reaped || pid!=42)return -1;*out=(kernel_process_native_view_t){42,42,&task_namespaces};return 0;
}
static int edge_namespace_handle_acquire(const edge_namespace_set_t *set,int kind,uint32_t *id) {
 if(!set->owned || edge_namespace_handle_retain(kind,set->user)<0)return -1;*id=set->user;return 0;
}
'''
for name in ("namespace_set_prepare", "edge_namespaces_release", "edge_namespaces_release_runtime",
             "namespace_parse_u32", "edge_userns_map_opener_allowed", "edge_userns_write_map"):
    code += function(ns, name) + "\n"
code += structure(proc, "proc_userns_description") + "\n"
code += "static proc_userns_description_t *g_proc_userns_descriptions;\nstatic spinlock_t g_proc_userns_description_lock;\n"
for name in ("proc_userns_node", "proc_open_description", "proc_userns_description_acquire",
             "procfs_userns_description_release"):
    code += function(proc, name) + "\n"
code += '#define KERNEL_FILE_DESCRIPTION_CAPACITY 8u\n#define KERNEL_FILE_DESCRIPTION_HANDLE_SLOT_BITS 3u\n'
code += '#include "' + str(root / 'src/kernel/file_description_runtime.c') + '"\n'
code += r'''
static void detach(void *context,uint64_t identity) { (void)context;procfs_userns_description_release(identity); }
static void close_ref(uint32_t handle) {
 kernel_file_description_release_t r;
 assert(kernel_file_description_release_begin(kernel_file_description_handle_locator(handle),&r)==0);
 if(r.active)assert(kernel_file_description_release_finish(&r)==0);
}
static void new_task(unsigned ns) {
 namespace_set_prepare(&task_namespaces);task_namespaces.owned=1;task_namespaces.user=ns;
 objects[ns]=(edge_namespace_object_t){.references=1,.owner_uid=1000,.owner_gid=1000,.setgroups_allowed=1};
 task_reaped=0;
}
int main(void) {
 uint32_t h;uint64_t id;proc_userns_description_t saved;
 kernel_file_description_ops_t ops={.detach_description=detach};
 assert(kernel_file_description_runtime_initialize(&ops)==0);
 objects[0].references=1;
 new_task(1);
 assert(kernel_file_description_create(0,2,NULL,&h,&id)==0);
 vfs_inode_t inode={{PROC_PID_UID_MAP,42,0,0}};
 assert(proc_open_description(NULL,&inode,id,2)==0);
 assert(objects[1].references==2);
 for(unsigned i=0;i<3;++i) /* dup, fork copy, queued SCM_RIGHTS reference */
  assert(kernel_file_description_retain(kernel_file_description_handle_locator(h))==0);
 edge_namespaces_release_runtime(&task_namespaces);
 assert(task_namespaces.owned && task_namespaces.user==1 && objects[1].references==2);
 /* Opening an unreaped zombie still binds its credential user namespace. */
 uint32_t z;uint64_t zid;vfs_inode_t zombie={{PROC_PID_UID_MAP,42,0,0}};
 assert(kernel_file_description_create(0,2,NULL,&z,&zid)==0);
 assert(proc_open_description(NULL,&zombie,zid,2)==0);
 edge_namespaces_release(&task_namespaces);task_reaped=1;
 assert(objects[1].references==2);
 vfs_inode_t reaped={{PROC_PID_UID_MAP,42,0,0}};
 assert(proc_open_description(NULL,&reaped,zid+100,2)<0);
 new_task(2); /* The same PID now belongs to another namespace. */
 assert(proc_userns_description_acquire(&inode,&saved)==0 && saved.namespace_id==1);
 edge_namespace_set_t pinned={.user=saved.namespace_id};edge_userns_map_diagnostic_t d;
 assert(edge_userns_write_map(&pinned,0,"0 1000 1\n",9,1000,1000,0,&d)==9);
 assert(objects[1].uid_map_written && !objects[2].uid_map_written);
 edge_namespace_handle_release(EDGE_NAMESPACE_USER,saved.namespace_id);
 current.euid=0; /* A later privileged receiver cannot rewrite the opener snapshot. */
 assert(proc_userns_description_acquire(&inode,&saved)==0 && saved.opener.euid==1000);
 edge_namespace_handle_release(EDGE_NAMESPACE_USER,saved.namespace_id);
 assert(!edge_userns_map_opener_allowed(2,0,1001,0));
 assert(edge_userns_map_opener_allowed(2,0,1000,0));
 close_ref(h);close_ref(h);close_ref(h);
 assert(objects[1].references==2);
 close_ref(h);assert(objects[1].references==1);
 assert(proc_userns_description_acquire(&inode,&saved)<0);
 close_ref(z);assert(objects[1].references==0);
 assert(objects[0].references==1);
 uint32_t replacement;uint64_t replacement_id;
 assert(kernel_file_description_create(0,2,NULL,&replacement,&replacement_id)==0);
 assert(replacement_id!=id);
 assert(proc_userns_description_acquire(&inode,&saved)<0);
 fail_allocation=1;
 assert(proc_open_description(NULL,&reaped,replacement_id,2)<0);
 assert(objects[2].references==1 && objects[0].references==1);
 fail_allocation=0;
 assert(proc_open_description(NULL,&reaped,replacement_id,0x200000)==0);
 assert(!reaped.fs_private[2] && !reaped.fs_private[3]);
 close_ref(replacement);edge_namespaces_release(&task_namespaces);
 assert(objects[2].references==0 && !g_proc_userns_descriptions && allocations==freed);
 puts("PROC_USERNS_DESCRIPTION_PASS: exit, zombie open, reap, PID reuse, dup/fork/SCM, final close, stale identity, opener snapshot, allocation failure");
}
'''
a.output.parent.mkdir(parents=True, exist_ok=True)
subprocess.run(["clang", "-iquote", str(root / "include"), "-x", "c", "-", "-O1", "-g",
                "-fsanitize=address,undefined", "-o", str(a.output)], input=code, text=True, check=True)
subprocess.run([str(a.output)], check=True)
