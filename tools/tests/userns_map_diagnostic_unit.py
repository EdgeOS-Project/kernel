#!/usr/bin/env python3
"""Verify map acceptance is unchanged and each rejected branch is identified."""
import argparse
from pathlib import Path
import re
import subprocess

root = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()

def function(text, name):
    match = re.search(r"^(?:static )?[\w *]+\b" + name + r"\([^;]*?\)\s*\{", text, re.M)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[match.start():end]

source = (root / "src/kernel/namespaces.c").read_text()
header = (root / "include/kernel/namespaces.h").read_text()
diagnostic = re.search(r"typedef struct edge_userns_map_diagnostic \{.*?\} edge_userns_map_diagnostic_t;", header, re.S).group()
code = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define EDGE_USERNS_MAP_MAX 5u
#define EDGE_NS_POOL_USER 0
typedef struct { uint32_t user; } edge_namespace_set_t;
typedef struct { uint32_t inside, outside, count; } edge_userns_extent_t;
typedef struct {
    uint32_t parent, owner_uid, owner_gid;
    uint8_t uid_map_written, gid_map_written, setgroups_allowed;
    uint8_t uid_map_count, gid_map_count;
    edge_userns_extent_t uid_map[5], gid_map[5];
} edge_namespace_object_t;
static edge_namespace_object_t object;
static void namespace_lock(void) {}
static void namespace_unlock(void) {}
static edge_namespace_object_t *namespace_object(int pool, uint32_t id) {
    (void)pool; return id == 1 ? &object : NULL;
}
'''
code += diagnostic + "\n"
code += function(source, "namespace_parse_u32") + "\n"
code += function(source, "edge_userns_write_map") + "\n"
code += r'''
static void reset(void) {
    memset(&object, 0, sizeof(object));
    object.owner_uid = object.owner_gid = 1000;
    object.setgroups_allowed = 1;
}
int main(void) {
    edge_namespace_set_t ns = {1};
    edge_userns_map_diagnostic_t d;
    const char *map = "0 1000 1\n";
    reset();
    assert(edge_userns_write_map(&ns,0,map,9,1000,1000,0,&d)==9);
    assert(!d.reason && object.uid_map_written && object.uid_map[0].outside==1000);
    assert(edge_userns_write_map(&ns,0,map,9,1000,1000,0,&d)==-1);
    assert(!strcmp(d.reason,"map-already-written") && d.uid_map_written);
    assert(d.namespace_id==1 && d.parent_id==0 && d.owner_uid==1000);
    reset();
    assert(edge_userns_write_map(&ns,0,map,9,1001,1000,0,&d)==-1);
    assert(!strcmp(d.reason,"owner-mismatch") && !object.uid_map_written);
    reset();
    assert(edge_userns_write_map(&ns,1,map,9,1000,1000,0,&d)==-1);
    assert(!strcmp(d.reason,"setgroups-allowed") && !object.gid_map_written);
    object.setgroups_allowed=0;
    assert(edge_userns_write_map(&ns,1,map,9,1000,1000,0,&d)==9);
    reset();
    assert(edge_userns_write_map(&ns,1,map,9,1000,1000,1,&d)==9);
    reset();
    assert(edge_userns_write_map(&ns,0,map,9,0,0,0,&d)==9);
    ns.user=99;
    assert(edge_userns_write_map(&ns,0,map,9,1000,1000,0,&d)==-1);
    assert(!strcmp(d.reason,"missing-namespace") && d.namespace_id==99);
    ns.user=1;
    const char *bad[]={"", "0 1000 0\n", "x 1000 1\n", "0 1000 2\n1 1002 1\n",
                       "0 1000 2\n2 1001 1\n", "4294967295 1000 2\n"};
    for (unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);++i) {
        reset();
        assert(edge_userns_write_map(&ns,0,bad[i],strlen(bad[i]),1000,1000,0,&d)==-1);
        assert(!strcmp(d.reason,"invalid-map") && !object.uid_map_written);
    }
    reset();
    assert(edge_userns_write_map(&ns,0,NULL,9,1000,1000,0,&d)==-1);
    assert(!strcmp(d.reason,"invalid-map"));
    puts("USERNS_MAP_DIAGNOSTIC_PASS: acceptance and rejection branches preserved");
}
'''
args.output.parent.mkdir(parents=True, exist_ok=True)
subprocess.run(["clang", "-x", "c", "-", "-O1", "-g", "-Wall", "-Wextra",
                "-fsanitize=address,undefined", "-o", str(args.output)],
               input=code, text=True, check=True)
subprocess.run([str(args.output)], check=True)
