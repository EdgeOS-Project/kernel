#!/usr/bin/env python3
"""Exercise real PID-map code across namespace exit, zombie, and slot reuse."""
import argparse
from pathlib import Path
import re
import subprocess

root = Path(__file__).resolve().parents[2]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--source", type=Path, default=root / "src/kernel/namespaces.c")
p.add_argument("--output", type=Path, required=True)
a = p.parse_args()
s = a.source.read_text()

def function(name):
    m = re.search(r"^(?:static )?[\w *]+\b" + name + r"\([^;]*?\)\s*\{", s, re.M)
    assert m, name
    end, depth = m.end(), 1
    while depth:
        depth += (s[end] == "{") - (s[end] == "}")
        end += 1
    return s[m.start():end]

code = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define EDGE_NAMESPACE_NESTING_MAX 32u
#define EDGE_RUNTIME_MAX_TASKS 4096u
#define EDGE_NS_POOL_PID 0
enum { EDGE_PID_MAPPING_EMPTY, EDGE_PID_MAPPING_LIVE, EDGE_PID_MAPPING_TOMBSTONE };
typedef struct { uint32_t pid; uint8_t owned; } edge_namespace_set_t;
typedef struct { uint32_t references, parent, next_pid; } edge_namespace_object_t;
static edge_namespace_object_t namespaces[4];
static void namespace_lock(void) {}
static void namespace_unlock(void) {}
static edge_namespace_object_t *namespace_object(int pool, uint32_t id) {
    (void)pool; return id < 4 && namespaces[id].references ? &namespaces[id] : NULL;
}
static void namespace_release(int pool, uint32_t id) {
    (void)pool; assert(id<4 && namespaces[id].references); --namespaces[id].references;
}
static edge_namespace_set_t create(void) {
    for(unsigned i=1;i<4;++i) if(!namespaces[i].references) {
        namespaces[i]=(edge_namespace_object_t){.references=1,.next_pid=1};
        return (edge_namespace_set_t){.pid=i,.owned=1};
    }
    assert(0); return (edge_namespace_set_t){0};
}
'''
for name in ("edge_pid_namespace_mapping", "edge_pid_task_mapping"):
    code += re.search(r"typedef struct " + name + r" \{.*?\} " + name + r"_t;", s, re.S).group() + "\n"
code += "static edge_pid_task_mapping_t g_pid_task_mappings[EDGE_RUNTIME_MAX_TASKS];\n"
for name in ("pid_mapping_hash", "pid_mapping_find_locked", "pid_mapping_allocate_locked",
             "pid_mapping_visible_locked", "edge_pid_namespace_task_attach",
             "edge_pid_namespace_task_detach", "edge_pid_namespace_global_to_visible",
             "edge_pid_namespace_visible_to_global"):
    code += function(name) + "\n"
code += r'''
int main(void) {
    int32_t visible=0, resolved=0;
    namespaces[0].references=1;
    edge_namespace_set_t old=create();
    assert(edge_pid_namespace_task_attach(&old,1572)==0);
    namespace_release(0,old.pid); /* Exit releases nsproxy; PID stays a zombie. */
    edge_namespace_set_t fresh=create();
    assert(edge_pid_namespace_task_attach(&fresh,1577)==0);
    assert(edge_pid_namespace_global_to_visible(fresh.pid,1577,&visible)==0);
    assert(visible==1);
    assert(edge_pid_namespace_visible_to_global(fresh.pid,visible,&resolved)==0);
    printf("SELF_ROUNDTRIP writer=1577 target=%d old_namespace=%u new_namespace=%u\n",
           resolved,old.pid,fresh.pid); fflush(stdout);
    assert(resolved==1577); /* /proc/self must never resolve the older zombie. */
    assert(old.pid!=fresh.pid);
    assert(edge_pid_namespace_global_to_visible(old.pid,1572,&visible)==0);
    edge_pid_namespace_task_detach(1572);
    assert(namespaces[old.pid].references==0);
    edge_namespace_set_t reused=create();
    assert(reused.pid==old.pid);
    assert(edge_pid_namespace_task_attach(&reused,1600)==0);
    assert(edge_pid_namespace_visible_to_global(reused.pid,1,&resolved)==0 && resolved==1600);
    assert(edge_pid_namespace_global_to_visible(reused.pid,1572,&visible)<0);
    namespace_release(0,fresh.pid); edge_pid_namespace_task_detach(1577);
    namespace_release(0,reused.pid); edge_pid_namespace_task_detach(1600);
    for(unsigned i=1;i<4;++i) assert(!namespaces[i].references);
    puts("PID_NAMESPACE_ZOMBIE_PASS");
}
'''
a.output.parent.mkdir(parents=True, exist_ok=True)
subprocess.run(["clang", "-x", "c", "-", "-O1", "-g", "-fsanitize=address,undefined",
                "-o", str(a.output)], input=code, text=True, check=True)
subprocess.run([str(a.output)], check=True)
