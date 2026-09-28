/* SPDX-License-Identifier: MPL-2.0 */
/* Verify attribution through the real ext4 metadata regression paths. */
/* Select user-mode lock primitives before any included kernel header. */
#ifndef EDGEOS_HOST_TEST
#define EDGEOS_HOST_TEST 1
#endif
#define EDGE_VFS_PROFILE_IMPLEMENTATION
#define main ext4_metadata_test_main
#include "ext4_metadata_cache_unit.c"
#undef main
uint64_t arch_cpu_current_task(void) { return 7; }
#include "../../src/vfs/profile.c"
int main(void) {
    assert(vfs_profile_control("counts", 6) == 0);
    assert(ext4_metadata_test_main() == 0);
    assert(profile.rows[VFS_PROFILE_EXT4_LOOKUP].calls == 6);
    assert(profile.rows[VFS_PROFILE_EXT4_LOOKUP].hits >= 1);
    assert(profile.rows[VFS_PROFILE_EXT4_INODE_CACHE].calls >= 20000);
    assert(profile.rows[VFS_PROFILE_EXT4_BLOCK].calls >= 4);
    assert(profile.rows[VFS_PROFILE_EXT4_BLOCK].work ==
           profile.rows[VFS_PROFILE_EXT4_BLOCK].calls * 4096);
    assert(profile.rows[VFS_PROFILE_EXT4_BLOCK].hits ==
           profile.rows[VFS_PROFILE_EXT4_BLOCK].calls);
    assert(!profile.rows[VFS_PROFILE_EXT4_BLOCK].samples);
    assert(vfs_profile_control("stop", 4) == 0);
    puts("vfs_profile_ext4_unit: PASS");
    return 0;
}
