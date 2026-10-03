#!/usr/bin/env python3
"""Exercise production proc mount ownership, rollback, and PID translation."""
import argparse, re, subprocess
from pathlib import Path
root = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', required=True)
args = parser.parse_args()
source = (root / 'src/fs/procfs.c').read_text()
def function(name):
    m = re.search(r'^(?:static )?[\w *]+\b' + name + r'\([^;]*?\)\s*\{', source, re.M)
    end, depth = m.end(), 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[m.start():end]
code = r'''
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#define EDGE_NAMESPACE_PID 4
#define PROC_ROOT 1
#define VFS_INODE_DIR 0x4000
#define VFS_SUPERBLOCK_DYNAMIC_LOOKUP 1
struct inode { unsigned ino; };
typedef struct { unsigned pid; } edge_namespace_set_t;
typedef struct { char fs_name[16],dev_name[16],mountpoint[4096]; struct inode root; void *ops,*fs_private; void (*retain)(void *); void (*release)(void *); unsigned runtime_flags; } vfs_superblock_t;
static unsigned nsrefs[3],allocations,frees,failalloc,failns,failmount;
static edge_namespace_set_t current;
static vfs_superblock_t mounts[4];
static unsigned count,g_proc_guard_armed,g_proc_ops;
static struct { uint64_t guard[4]; } g_proc_snapshot;
static void *arch_vm_alloc_page(void) { if(failalloc)return NULL; ++allocations;return calloc(1,4096); }
static void arch_vm_free_page(void *p) { ++frees;free(p); }
static int edge_namespace_handle_retain(int kind,unsigned id) { assert(kind==4);if(failns)return -1; ++nsrefs[id];return 0; }
static void edge_namespace_handle_release(int kind,unsigned id) { assert(kind==4 && nsrefs[id]);--nsrefs[id]; }
static edge_namespace_set_t *kernel_arch_current_namespace_set(void) { return &current; }
static void inode_set(struct inode *i,unsigned n,unsigned m) { (void)i;(void)n;(void)m; }
static int vfs_add_superblock(vfs_superblock_t *s) { if(failmount)return -1;mounts[count++]=*s;s->retain(s->fs_private);return 0; }
static int edge_pid_namespace_global_to_visible(unsigned ns,int32_t p,int32_t *out) { if(ns && p!=101)return -1;*out=ns?1:p;return 0; }
static int edge_pid_namespace_visible_to_global(unsigned ns,int32_t p,int32_t *out) { if(ns && p!=1)return -1;*out=ns?101:p;return 0; }
'''
code += re.search(r'typedef struct proc_mount_context \{.*?\} proc_mount_context_t;', source, re.S).group()
for name in ['proc_mount_retain','proc_mount_release','proc_mount_pid_namespace','proc_visible_pid_to_global','proc_global_pid_to_visible','proc_display_pid','procfs_mount']:
    code += '\n' + function(name)
code += r'''
int main(void) {
 int32_t p;
 failns=1;
 assert(procfs_mount("proc","/proc")==0 && nsrefs[0]==0);
 failns=0;
 current.pid=1;
 assert(proc_display_pid(&mounts[0],101)==101);
 assert(procfs_mount("proc","/child")==0 && nsrefs[1]==1);
 assert(proc_display_pid(&mounts[1],101)==1);
 assert(proc_display_pid(&mounts[1],99)==0);
 assert(proc_visible_pid_to_global(&mounts[1],1,&p)==0 && p==101);
 assert(proc_visible_pid_to_global(&mounts[0],101,&p)==0 && p==101);
 mounts[1].retain(mounts[1].fs_private);
 mounts[1].release(mounts[1].fs_private);
 assert(nsrefs[1]==1);
 mounts[1].release(mounts[1].fs_private);
 assert(nsrefs[1]==0 && proc_display_pid(&mounts[0],101)==101);
 failmount=1;assert(procfs_mount("proc","/fail")<0 && nsrefs[1]==0);failmount=0;
 failns=1;assert(procfs_mount("proc","/fail")<0);failns=0;
 failalloc=1;assert(procfs_mount("proc","/fail")<0);failalloc=0;
 mounts[0].release(mounts[0].fs_private);
 assert(!nsrefs[0] && allocations==frees);
 puts("PROC_MOUNT_OWNERSHIP_PASS");
}
'''
out=args.output
subprocess.run(['clang','-x','c','-','-O1','-g','-fsanitize=address,undefined','-o',out],input=code,text=True,check=True)
subprocess.run([out],check=True)
