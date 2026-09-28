#ifndef SYS_USER_EXEC_H
#define SYS_USER_EXEC_H

#include <stdint.h>
#include "kernel/exec_payload.h"
#include "kernel/linux_task_abi.h"

#define USER_CS 0x1B
#define USER_DS 0x23
#define USER32_CS 0x4B
#define USER32_DS 0x53
#define KERNEL_CS 0x08
#define KERNEL_DS 0x10

typedef struct user_exec_image {
    uint64_t entry;
    uint64_t user_stack_top;
    uint64_t user_heap_base;
    uint64_t at_phdr;
    uint64_t at_phnum;
    uint64_t at_entry;
    uint64_t at_base;
    uint16_t at_phent;
    edge_linux_task_abi_t linux_abi;
    uint8_t secure_exec;
} user_exec_image_t;

void user_exec_set_kernel_rsp0(uint64_t rsp0);
int user_exec_run(const user_exec_image_t *img, int argc, char **argv, int envc, char **envp);
int user_exec_run_payload(const user_exec_image_t *img,
                          const linux_exec_payload_t *payload,
                          kernel_exec_payload_handle_t *payload_handle);

#endif
