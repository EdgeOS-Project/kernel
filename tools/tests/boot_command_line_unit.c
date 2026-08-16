/* SPDX-License-Identifier: MPL-2.0 */
/* Shared boot command-line parser tests. */

#include <assert.h>

#include "kernel/boot_command_line.h"

static int text_equal(const char *left, const char *right) {
    while (*left && *right && *left == *right) {
        left++;
        right++;
    }
    return *left == 0 && *right == 0;
}

static void expect_value(const char *name, const char *expected) {
    char value[128];

    assert(kernel_boot_option_get(name, value, sizeof(value)) == 1);
    assert(text_equal(value, expected));
}

int main(void) {
    char small[4];
    char init_path[128];

    kernel_boot_command_line_set(
        "root=/dev/vda1 rw console=ttyAMA0,115200 "
        "init=\"/lib/systemd/systemd\" quiet=off "
        "label='EdgeOS rescue image' root=/dev/sda2 escaped=\"a\\\"b\\\\c\"");

    expect_value("root", "/dev/sda2");
    expect_value("console", "ttyAMA0,115200");
    expect_value("init", "/lib/systemd/systemd");
    expect_value("label", "EdgeOS rescue image");
    expect_value("escaped", "a\"b\\c");
    expect_value("rw", "");
    assert(kernel_boot_option_last_ordinal("root") == 7);
    assert(kernel_boot_option_last_ordinal("rw") == 2);
    assert(kernel_boot_option_last_ordinal("missing") == 0);
    assert(kernel_boot_option_last_ordinal("bad=name") == -1);
    assert(kernel_boot_option_present("rw") == 1);
    assert(kernel_boot_option_present("ro") == 0);
    assert(kernel_boot_option_get("missing", small, sizeof(small)) == 0);
    assert(kernel_boot_option_get("root", small, sizeof(small)) == -1);
    assert(kernel_boot_option_enabled("rw", 0) == 1);
    assert(kernel_boot_option_enabled("quiet", 1) == 0);
    assert(kernel_boot_option_enabled("missing", 1) == 1);
    assert(kernel_boot_option_get("bad=name", small, sizeof(small)) == -1);
    assert(kernel_boot_init_path(0, init_path, sizeof(init_path)) == 0);
    assert(text_equal(init_path, "/lib/systemd/systemd"));
    assert(kernel_boot_init_path(1, init_path, sizeof(init_path)) == 0);
    assert(text_equal(init_path, "/lib/systemd/systemd"));

    kernel_boot_command_line_set("feature=no feature=yes feature=off");
    assert(kernel_boot_option_last_ordinal("feature") == 3);
    assert(kernel_boot_option_enabled("feature", 1) == 0);
    assert(kernel_boot_init_path(0, init_path, sizeof(init_path)) == 0);
    assert(text_equal(init_path, "/sbin/init"));
    assert(kernel_boot_init_path(1, init_path, sizeof(init_path)) == 0);
    assert(text_equal(init_path, "/init"));

    kernel_boot_command_line_set("init=/sbin/init rdinit=/rescue/init");
    assert(kernel_boot_init_path(1, init_path, sizeof(init_path)) == 0);
    assert(text_equal(init_path, "/rescue/init"));

    kernel_boot_command_line_set("init=relative/path");
    assert(kernel_boot_init_path(0, init_path, sizeof(init_path)) == -1);

    kernel_boot_command_line_set(NULL);
    assert(text_equal(kernel_boot_command_line_get(), ""));
    return 0;
}
