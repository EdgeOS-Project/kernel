#!/usr/bin/env python3
"""Test production exec de-threading with retained address-space owners."""
import argparse
import os
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--output-dir', type=Path, required=True)
parser.add_argument('--source', type=Path)
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
source = (args.source or root / 'src/sys/process.c').read_text()
start = source.index('int process_exec_de_thread_current(void) {')
end = source.index('\nint process_prepare_exec_current', start)
function = source[start:end]
header = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define PROC_MAX_TASKS 6
#define USER_AS_MAX_TASKS 2
#define TASK_UNUSED 0
#define TASK_RUNNING 1
#define TASK_ZOMBIE 2
typedef struct task {
 int pid,tgid,vm_owner_pid,state,ppid,parent_tid;
 uint8_t exit_signal;
 uint64_t signal_pending,signal_shared_pending;
 struct task *parent,*first_child,*sibling_next;
} task_t;
static task_t g_tasks[PROC_MAX_TASKS];
static task_t *running;
static int g_task_lock,g_task_pid_index,exits;
static task_t *process_current_task(void){return running;}
static int task_index(task_t *t){return t ? (int)(t-g_tasks) : -1;}
static int process_task_live(task_t *t){return t->state==TASK_RUNNING;}
static int process_tgid_of_task(task_t *t){return t->tgid?t->tgid:t->pid;}
static int process_vm_owner_pid_of_task_raw(const task_t *t){return t->vm_owner_pid>0?t->vm_owner_pid:t->pid;}
static task_t *task_find_by_pid(int pid){for(int i=0;i<PROC_MAX_TASKS;i++)if(g_tasks[i].state && g_tasks[i].pid==pid)return &g_tasks[i];return 0;}
static task_t *task_vm_owner_local(task_t *t){task_t *o=task_find_by_pid(process_vm_owner_pid_of_task_raw(t));return o?o:t;}
static void process_finish_task_exit(task_t *t,int code,const char *why,int notify){(void)code;(void)why;(void)notify;t->state=TASK_ZOMBIE;exits++;}
static void task_child_unlink(task_t *t){t->parent=0;}
static void task_child_link(task_t *parent,task_t *t){t->parent=parent;t->ppid=parent?parent->pid:0;}
static uint64_t spin_lock_irqsave(int *l){(void)l;return 0;}
static void spin_unlock_irqrestore(int *l,uint64_t f){(void)l;(void)f;}
static void edge_pid_index_remove(int *i,int pid,uint32_t slot){(void)i;(void)pid;(void)slot;}
static int edge_pid_index_insert(int *i,int pid,uint32_t slot){(void)i;(void)pid;(void)slot;return 0;}
static void reset(void){memset(g_tasks,0,sizeof(g_tasks));exits=0;}
static task_t *task(int slot,int pid,int group,int owner,int state){task_t *t=&g_tasks[slot];t->pid=pid;t->tgid=group;t->vm_owner_pid=owner;t->state=state;return t;}
'''
checks = r'''
int main(void){
 reset();
 task_t *owner=task(0,100,100,100,TASK_ZOMBIE);
 task_t *leader=task(2,200,200,100,TASK_RUNNING);
 running=task(3,201,200,100,TASK_RUNNING);
 assert(process_exec_de_thread_current()==0);
 assert(running->pid==200 && running->tgid==200);
 assert(task_vm_owner_local(running)==owner && running->vm_owner_pid==100);
 assert(leader->state==TASK_ZOMBIE && leader->vm_owner_pid==100);
 reset();
 owner=leader=task(0,100,100,100,TASK_RUNNING);
 running=task(3,101,100,100,TASK_RUNNING);
 task_t *external=task(4,150,150,100,TASK_RUNNING);
 assert(process_exec_de_thread_current()==0);
 assert(owner->pid==101 && running->pid==100);
 assert(task_vm_owner_local(running)==owner);
 assert(task_vm_owner_local(external)==owner && external->vm_owner_pid==101);
 reset();
 running=owner=task(0,101,100,101,TASK_RUNNING);
 leader=task(2,100,100,101,TASK_RUNNING);
 external=task(4,150,150,101,TASK_RUNNING);
 assert(process_exec_de_thread_current()==0);
 assert(running->pid==100 && running->vm_owner_pid==100);
 assert(task_vm_owner_local(external)==owner && external->vm_owner_pid==100);
 reset();
 running=task(3,201,200,999,TASK_RUNNING);
 leader=task(2,200,200,999,TASK_RUNNING);
 assert(process_exec_de_thread_current()<0 && exits==0);
 puts("Exec address-space owner tests: PASS");
}
'''
args.output_dir.mkdir(parents=True, exist_ok=True)
source_dir = root / '.repair-review/exec-vm-owner'
source_dir.mkdir(parents=True, exist_ok=True)
unit = source_dir / 'unit.c'
unit.write_text(header + function + checks)
executable = args.output_dir / 'exec-vm-owner-unit'
command = ['clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O1', '-g',
           '-fsanitize=address,undefined', str(unit), '-o', str(executable)]
subprocess.run(command, check=True)
subprocess.run([str(executable)], check=True)
