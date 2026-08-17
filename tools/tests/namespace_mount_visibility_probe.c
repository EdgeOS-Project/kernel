/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux namespace regression test.
 * Copyright (c) EdgeOS Contributors.
 *
 * Bubblewrap and other application sandboxes create a child in several new
 * namespaces before constructing a private mount tree.  The child must retain
 * visibility of the parent's mount topology until it deliberately changes it.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHILD_STACK_SIZE (256u * 1024u)

struct child_test {
    const char *name;
    int flags;
};

static int verify_visible_mounts(void *opaque) {
    const struct child_test *test = opaque;
    struct stat root;
    struct stat usr;

    if (stat("/", &root) < 0) {
        fprintf(stderr, "%s: stat(/): %s\n", test->name, strerror(errno));
        return 10;
    }
    if (stat("/usr", &usr) < 0) {
        fprintf(stderr, "%s: stat(/usr): %s\n", test->name, strerror(errno));
        return 11;
    }
    if (!S_ISDIR(root.st_mode) || !S_ISDIR(usr.st_mode)) {
        fprintf(stderr, "%s: inherited mount points are not directories\n",
                test->name);
        return 12;
    }
    return 0;
}

static int verify_pivot_oldroot(void *opaque) {
    const struct child_test *test = opaque;
    static const char base[] = "/tmp/edgeos-pivot-root-probe";
    struct stat old_usr;

    if (mkdir(base, 0700) < 0 && errno != EEXIST) {
        fprintf(stderr, "%s: mkdir(%s): %s\n", test->name, base,
                strerror(errno));
        return 20;
    }
    if (mount("tmpfs", base, "tmpfs", MS_NODEV | MS_NOSUID, NULL) < 0) {
        fprintf(stderr, "%s: mount(tmpfs): %s\n", test->name,
                strerror(errno));
        return 21;
    }
    if (chdir(base) < 0 || mkdir("newroot", 0755) < 0 ||
        mkdir("oldroot", 0755) < 0) {
        fprintf(stderr, "%s: preparing pivot directories: %s\n", test->name,
                strerror(errno));
        return 22;
    }
    if (mount("newroot", "newroot", NULL, MS_BIND | MS_REC, NULL) < 0) {
        fprintf(stderr, "%s: bind mounting new root: %s\n", test->name,
                strerror(errno));
        return 23;
    }
    if (syscall(SYS_pivot_root, base, "oldroot") < 0) {
        fprintf(stderr, "%s: pivot_root: %s\n", test->name,
                strerror(errno));
        return 24;
    }
    if (chdir("/") < 0 || stat("/oldroot/usr", &old_usr) < 0) {
        fprintf(stderr, "%s: stat(/oldroot/usr): %s\n", test->name,
                strerror(errno));
        return 25;
    }
    if (!S_ISDIR(old_usr.st_mode)) {
        fprintf(stderr, "%s: /oldroot/usr is not a directory\n", test->name);
        return 26;
    }
    return 0;
}

static int run_clone_test(const struct child_test *test,
                          int (*entry)(void *)) {
    char *stack;
    pid_t pid;
    int status;

    stack = malloc(CHILD_STACK_SIZE);
    if (!stack) {
        fprintf(stderr, "%s: allocating child stack failed\n", test->name);
        return 1;
    }
    pid = clone(entry, stack + CHILD_STACK_SIZE,
                test->flags | SIGCHLD, (void *)test);
    if (pid < 0) {
        fprintf(stderr, "%s: clone: %s\n", test->name, strerror(errno));
        free(stack);
        return 1;
    }
    if (waitpid(pid, &status, 0) != pid) {
        fprintf(stderr, "%s: waitpid: %s\n", test->name, strerror(errno));
        free(stack);
        return 1;
    }
    free(stack);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "%s: child status=0x%x\n", test->name, status);
        return 1;
    }
    printf("PASS %s\n", test->name);
    return 0;
}

int main(void) {
    static const struct child_test tests[] = {
        {"clone-newns", CLONE_NEWNS},
        {"clone-newns-newpid", CLONE_NEWNS | CLONE_NEWPID},
        {"clone-bwrap-namespaces",
         CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWUTS |
             CLONE_NEWCGROUP | CLONE_NEWNET},
    };
    int failures = 0;

    for (size_t index = 0; index < sizeof(tests) / sizeof(tests[0]); ++index)
        failures += run_clone_test(&tests[index], verify_visible_mounts);
    {
        static const struct child_test pivot_test = {
            "pivot-oldroot-visible", CLONE_NEWNS
        };
        failures += run_clone_test(&pivot_test, verify_pivot_oldroot);
        (void)rmdir("/tmp/edgeos-pivot-root-probe");
    }

    if (failures) {
        fprintf(stderr, "NAMESPACE_MOUNT_VISIBILITY_FAIL failures=%d\n",
                failures);
        return 1;
    }
    puts("NAMESPACE_MOUNT_VISIBILITY_OK");
    return 0;
}
