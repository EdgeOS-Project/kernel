#!/usr/bin/env python3
"""Exercise actual credential assignment sites with distinct TID and TGID."""
import argparse
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def function(text, name):
    match = re.search(r'^(?:static )?[\w *]+\b' + name + r'\([^;]*?\)\s*\{', text, re.M)
    if not match:
        raise ValueError(name)
    end, depth = match.end(), 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[match.start():end]


p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--arm-source', type=Path, default=ROOT/'src/arch/arm64/kernel/bootstrap_runtime.c')
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
arm = a.arm_source.read_text()
x86 = (ROOT/'src/sys/syscall_parts/fd_tty_ipc.c').read_text()
helper = function((ROOT/'src/kernel/socket_unix_policy.c').read_text(), 'kernel_unix_socket_credential_pid')
assignments = re.findall(r'((?:socket->peer_pid|child->peer_pid|g_sockets\[sockets\[[01]\]\]\.peer_pid)\s*=\s*(?:kernel_unix_socket_credential_pid\([^;]+\)|current_task\(\)->pid|task->pid)\s*;)', arm)
scm = re.findall(r'((?:peer->recv_pid|record->pid)\s*=\s*kernel_unix_socket_credential_pid\([^;]+\)\s*;)', arm)
assert len(assignments) == 5, len(assignments)
assert len(scm) == 4, len(scm)
code = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#define LINUX_EINVAL 22
typedef struct { int32_t pid, tgid; uint32_t euid, egid; } task_t;
typedef task_t kernel_task_t;
typedef struct { int32_t peer_pid, recv_pid, pid, cred_pid, peer_cred_pid; uint32_t peer_uid, peer_gid, cred_uid, cred_gid, peer_cred_uid, peer_cred_gid; } kernel_socket_t;
typedef kernel_socket_t edge_socket_t;
typedef struct { int32_t process_id; uint32_t user_id, group_id; } kernel_socket_peer_credentials_t;
static task_t worker;
static task_t *current_task(void) { return &worker; }
'''
code += helper + '\n' + function(arm, 'arm64_socket_option_peer_credentials') + '\n'
for name in ['socket_set_cred_from_task', 'socket_set_peer_cred', 'socket_set_peer_cred_from_task']:
    code += function(x86, name) + '\n'
code += 'int main(void) {\n'
for tid, tgid, expected in [(1234,1229,1229),(1229,1229,1229),(42,0,42)]:
    for statement in assignments:
        lhs = statement.split('=',1)[0].strip()
        code += f'''{{
worker=(task_t){{.pid={tid},.tgid={tgid},.euid=1000,.egid=1000}};
kernel_task_t *task=&worker;
kernel_socket_t g_sockets[2]={{0}}, object={{0}};
kernel_socket_t *socket=&object,*child=&object;
int sockets[2]={{0,1}};
{statement}
assert({lhs}=={expected});
/* Stored peer credentials remain valid after the connecting thread exits. */
worker.pid=worker.tgid=0;
kernel_socket_peer_credentials_t cred={{0}};
assert(arm64_socket_option_peer_credentials(&{lhs.rsplit('.',1)[0] if '.peer_pid' in lhs else 'object'},&cred)==0);
assert(cred.process_id=={expected});
}}\n'''
    for statement in scm:
        lhs=statement.split('=',1)[0].strip()
        code += f'{{ worker=(task_t){{.pid={tid},.tgid={tgid}}}; kernel_task_t *task=&worker; kernel_socket_t object={{0}},*peer=&object,*record=&object; {statement} assert({lhs}=={expected}); }}\n'
    code += f'''{{ task_t t={{.pid={tid},.tgid={tgid},.euid=1000,.egid=1001}};
edge_socket_t creator={{0}},accepted={{0}};
socket_set_cred_from_task(&creator,&t); socket_set_peer_cred(&accepted,&creator);
assert(accepted.peer_cred_pid=={expected} && accepted.peer_cred_uid==1000 && accepted.peer_cred_gid==1001);
socket_set_peer_cred_from_task(&accepted,&t); assert(accepted.peer_cred_pid=={expected}); }}\n'''
code += 'puts("SOCKET_PEERCRED_TGID_PASS: ARM 5 peer sites, 4 SCM sites, x86 setters"); return 0; }\n'
a.output.parent.mkdir(parents=True,exist_ok=True)
subprocess.run(['clang','-x','c','-','-O1','-g','-fsanitize=address,undefined','-o',str(a.output)],input=code,text=True,check=True)
subprocess.run([str(a.output)],check=True)
