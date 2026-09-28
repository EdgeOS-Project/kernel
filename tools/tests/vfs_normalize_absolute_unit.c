/* SPDX-License-Identifier: MPL-2.0 */
/* Test the production VFS normalizer without a running kernel. */
#include <assert.h>
#include <string.h>
#define STRING_H
#define EDGEOS_HOST_TEST 1
extern int puts(const char *text);
#ifndef VFS_TEST_SOURCE
#define VFS_TEST_SOURCE "../../src/vfs/vfs.c"
#endif
#include VFS_TEST_SOURCE
static unsigned snapshots;
static int snapshot_failure;
int kernel_current_fs_snapshot(char *cwd, uint32_t cwd_capacity,
                               char *root, uint32_t root_capacity) {
    ++snapshots;
    assert(cwd_capacity >= 16 && root_capacity >= 16);
    if (snapshot_failure) return -1;
    strcpy(cwd, "/home/user");
    strcpy(root, "/jail");
    return 0;
}
static void expect(const char *input, const char *expected, unsigned calls) {
    char output[VFS_PATH_MAX];
    snapshots = 0;
    normalize_path(input, output);
    assert(strcmp(output, expected) == 0);
    assert(snapshots == calls);
}
int main(void) {
    expect("/usr/bin/tool", "/usr/bin/tool", 0);
    expect("/usr//bin/./tool", "/usr/bin/tool", 0);
    /* Preserve the existing lexical spelling after parent components. */
    expect("/usr/bin/../share", "/usr//share", 0);
    expect("/../../a", "/a", 0);
    expect("//", "/", 0);
    expect("/", "/", 0);
    expect("../bin/./tool", "/home//bin/tool", 1);
    expect("", "/home/user", 1);
    expect(0, "/home/user", 1);
    snapshot_failure = 1;
    strcpy(g_cwd, "/fallback");
    expect("tool", "/fallback/tool", 1);
    expect("/usr/bin/tool", "/usr/bin/tool", 0);
    char long_path[VFS_PATH_MAX + 32], output[VFS_PATH_MAX];
    memset(long_path, 'a', sizeof(long_path));
    long_path[0] = '/';
    long_path[sizeof(long_path) - 1] = 0;
    snapshots = 0;
    normalize_path(long_path, output);
    assert(strlen(output) == VFS_PATH_MAX - 1 && !snapshots);
    puts("vfs_normalize_absolute_unit: PASS (absolute paths take zero filesystem snapshots)");
    return 0;
}
