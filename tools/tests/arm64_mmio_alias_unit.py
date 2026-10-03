#!/usr/bin/env python3
"""Verify production MMIO root aliases and protected virtual range bounds."""
import argparse
from pathlib import Path
import re
import subprocess

root = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', required=True)
args = parser.parse_args()
source = (root / 'src/arch/arm64/mm/mmu.c').read_text()
def function(name):
    match = re.search(r'^(?:static )?[\w *]+\b' + name + r'\([^;]*?\)\s*\{', source, re.M)
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[match.start():end]
code = '''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include "arch/arm64/mmio.h"
static uint64_t g_l0[512];
static int g_translation_tables_initialized;
static uint64_t current_el = 4;
static uint64_t arm64_mmio_exception_level(void) { return current_el; }
'''
code += function('edgeos_arm64_mmio_alias') + '\n' + function('arm64_install_mmio_aliases')
code += r'''
int main(void) {
 assert(edgeos_arm64_mmio_alias(0x9000000)==0x9000000);
 g_l0[0]=0x12345003;g_l0[1]=0xabcdef003;g_l0[3]=0x98765003;
 arm64_install_mmio_aliases();
 assert(g_l0[0x71]==g_l0[0] && g_l0[0x72]==g_l0[1]);
 assert(g_l0[0x74]==g_l0[0] && g_l0[0x75]==g_l0[1]);
 assert(g_l0[3]==0x98765003 && g_l0[0x70]==0 && g_l0[0x73]==0);
 g_translation_tables_initialized=1;
 current_el=8;assert(edgeos_arm64_mmio_alias(0x9000000)==0x9000000);
 current_el=4;
 assert(edgeos_arm64_mmio_alias(0xa003600)==EDGE_MMIO_LOW_ALIAS_BASE+0xa003600);
 assert(edgeos_arm64_mmio_alias(0x1000000000)==EDGE_MMIO_LOW_ALIAS_BASE+0x1000000000);
 assert(!edgeos_arm64_mmio_alias_overlaps(0x9000000,4096));
 assert(!edgeos_arm64_mmio_alias_overlaps(EDGE_MMIO_LOW_ALIAS_BASE-4096,4096));
 assert(edgeos_arm64_mmio_alias_overlaps(EDGE_MMIO_LOW_ALIAS_BASE-1,2));
 assert(edgeos_arm64_mmio_alias_overlaps(EDGE_MMIO_LOW_ALIAS_BASE,4096));
 assert(!edgeos_arm64_mmio_alias_overlaps(EDGE_MMIO_LOW_ALIAS_BASE+EDGE_MMIO_LOW_ALIAS_SIZE,1));
 assert(edgeos_arm64_mmio_alias_overlaps(EDGE_MMIO_UNCACHED_ALIAS_BASE,1));
 assert(edgeos_arm64_mmio_alias_overlaps(UINT64_MAX-1,4));
 assert(!edgeos_arm64_mmio_alias_overlaps(EDGE_MMIO_LOW_ALIAS_BASE,0));
 puts("ARM64_MMIO_ALIAS_PASS");
}
'''
subprocess.run(['clang','-D__aarch64__','-iquote',str(root/'include'),'-x','c','-','-O1','-g','-fsanitize=address,undefined','-o',args.output], input=code, text=True, check=True)
subprocess.run([args.output], check=True)
