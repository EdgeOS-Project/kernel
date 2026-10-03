#!/usr/bin/env python3
"""Check that an abandoned overlay lock wait retains no scratch reference."""
from pathlib import Path
import subprocess
import sys


root = Path(__file__).resolve().parents[2]
source = (root / "src/fs/overlayfs.c").read_text()
start = source.index("#define OVERLAY_SERIALIZED_BEGIN(")
end = source.index("\n\n#define OVERLAY_SERIALIZED_END", start)
macro = source[start:end]
program = r"""
#include <assert.h>
#include <setjmp.h>

typedef struct { int used; } overlay_state_t;
typedef struct { int used; } overlay_scratch_context_t;
static overlay_state_t state;
static overlay_scratch_context_t scratch;
static jmp_buf abandoned;
static int scratch_references;

static overlay_state_t *overlay_state(void *sb) {
    (void)sb;
    return &state;
}
static overlay_scratch_context_t *overlay_scratch_acquire(overlay_state_t *st) {
    (void)st;
    ++scratch_references;
    return &scratch;
}
static void overlay_operation_lock(overlay_state_t *st) {
    (void)st;
    longjmp(abandoned, 1);
}
static void overlay_operation_unlock(overlay_state_t *st) {
    (void)st;
}

MACRO

static int attempt(void) {
    OVERLAY_SERIALIZED_BEGIN(0, overlay);
    result = 0;
    return result;
}

int main(void) {
    if (setjmp(abandoned) == 0) (void)attempt();
    assert(scratch_references == 0);
    return 0;
}
""".replace("MACRO", macro)
output = Path(sys.argv[1])
output.mkdir(parents=True, exist_ok=True)
c_file = output / "overlayfs_yield_lifetime.c"
binary = output / "overlayfs_yield_lifetime"
c_file.write_text(program)
subprocess.run(["clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
                str(c_file), "-o", str(binary)], check=True)
subprocess.run([str(binary)], check=True)
print("overlayfs_yield_lifetime_unit: PASS")
