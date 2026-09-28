/* SPDX-License-Identifier: MPL-2.0 */
/* Verify on-disk ext4 block accounting across all three encodings. */
#include <assert.h>
#include "../../src/fs/ext4/ext4.c"

int main(void) {
    static ext4_fs_t fs;
    ext4_inode_t inode = {0};
    fs.block_size = 4096;
    inode.blocks_lo = UINT32_MAX - 7u;
    assert(ext4_inode_charge_blocks(&fs, &inode, 1u) < 0);
    assert(inode.blocks_lo == UINT32_MAX - 7u);
    fs.sb.feature_ro_compat = EXT4_RO_COMPAT_HUGE_FILE |
                              EXT4_RO_COMPAT_EXTRA_ISIZE;
    assert(ext4_feature_set_supported(&fs.sb));
    assert(ext4_inode_charge_blocks(&fs, &inode, 1u) == 0);
    assert(inode.blocks_lo == 0u);
    assert(ext4_inode_osd2_u16(&inode, 0u) == 1u);
    assert(ext4_inode_sectors(&fs, &inode) == (UINT64_C(1) << 32));
    assert(ext4_inode_release_sectors(&fs, &inode, 8u) == 0);
    assert(inode.blocks_lo == UINT32_MAX - 7u);
    assert(ext4_inode_osd2_u16(&inode, 0u) == 0u);
    inode.flags = EXT4_EXTENTS_FL | EXT4_HUGE_FILE_FL;
    inode.blocks_lo = 5;
    assert(ext4_inode_sectors(&fs, &inode) == 40u);
    assert(ext4_inode_charge_blocks(&fs, &inode, 1u) == 0);
    assert(ext4_inode_sectors(&fs, &inode) == 48u);
    assert(inode.flags == EXT4_EXTENTS_FL);
    assert(ext4_inode_set_sectors(&fs, &inode, UINT64_C(1) << 48) == 0);
    assert(inode.flags & EXT4_HUGE_FILE_FL);
    assert(ext4_inode_sectors(&fs, &inode) == (UINT64_C(1) << 48));
    assert(ext4_inode_set_sectors(&fs, &inode, (UINT64_C(1) << 48) + 1u) < 0);
    assert(ext4_inode_sectors(&fs, &inode) == (UINT64_C(1) << 48));
    assert(ext4_inode_release_sectors(&fs, &inode, UINT64_C(1) << 48) == 0);
    assert(ext4_inode_sectors(&fs, &inode) == 0u);
    assert(!(inode.flags & EXT4_HUGE_FILE_FL));
    fs.sb.feature_ro_compat |= EXT4_RO_COMPAT_METADATA_CSUM;
    assert(!ext4_feature_set_supported(&fs.sb));
    for (uint16_t depth = 1; depth <= EXT4_MAX_EXTENT_DEPTH; ++depth) {
        ext4_extent_header_t *root;
        ext4_extent_t *extent;
        assert(extent_init_inode(&inode) == 0);
        root = (ext4_extent_header_t *)inode.block;
        root->eh_depth = depth;
        assert(extent_map_insert_local(&inode, 0u, 123u) == 0);
        assert(root->eh_depth == 0u && root->eh_entries == 1u);
        extent = (ext4_extent_t *)((uint8_t *)root + sizeof(*root));
        assert(extent[0].ee_block == 0u);
        assert(extent_start_phys(&extent[0]) == 123u);
        assert(extent_actual_length(&extent[0]) == 1u);
        assert(extent_map_insert_local(&inode, 1u, 124u) == 0);
        assert(root->eh_entries == 1u);
        assert(extent_actual_length(&extent[0]) == 2u);
    }
    printf("ext4_inode_blocks_unit: PASS\n");
    return 0;
}
