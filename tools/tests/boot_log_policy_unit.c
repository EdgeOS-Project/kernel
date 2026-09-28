/* SPDX-License-Identifier: MPL-2.0 */
/* Shared boot log command-line policy tests. */

#include <assert.h>

#include "kernel/boot_command_line.h"
#include "kernel/boot_log_policy.h"

static int text_equal(const char *left, const char *right) {
    while (*left && *right && *left == *right) {
        ++left;
        ++right;
    }
    return *left == 0 && *right == 0;
}

int main(void) {
    kernel_boot_log_policy_t policy;

    kernel_boot_command_line_set("");
    assert(kernel_boot_log_policy_load(&policy) == 0);
    assert(policy.console_loglevel == 7);
    assert(policy.console_loglevel_explicit == 0);
    assert(policy.quiet == 0);
    assert(policy.file_enabled == 0);

    kernel_boot_command_line_set("quiet splash");
    assert(kernel_boot_log_policy_load(&policy) == 0);
    assert(policy.console_loglevel == 4);
    assert(policy.console_loglevel_explicit == 0);
    assert(policy.quiet == 1);

    kernel_boot_command_line_set("quiet loglevel=7");
    assert(kernel_boot_log_policy_load(&policy) == 0);
    assert(policy.console_loglevel == 7);
    assert(policy.console_loglevel_explicit == 1);
    assert(policy.quiet == 1);

    kernel_boot_command_line_set("loglevel=7 quiet");
    assert(kernel_boot_log_policy_load(&policy) == 0);
    assert(policy.console_loglevel == 4);
    assert(policy.console_loglevel_explicit == 1);
    assert(policy.quiet == 1);

    kernel_boot_command_line_set(
        "loglevel=8 logfile=/edgeos-boot.log");
    assert(kernel_boot_log_policy_load(&policy) == 0);
    assert(policy.console_loglevel == 8);
    assert(policy.console_loglevel_explicit == 1);
    assert(policy.file_enabled == 1);
    assert(text_equal(policy.file_path, "/edgeos-boot.log"));

    kernel_boot_command_line_set(
        "loglevel=4 logfile='/var/log/edgeos boot.log'");
    assert(kernel_boot_log_policy_load(&policy) == 0);
    assert(policy.console_loglevel == 4);
    assert(policy.file_enabled == 1);
    assert(text_equal(policy.file_path, "/var/log/edgeos boot.log"));

    kernel_boot_command_line_set("loglevel=9 logfile=relative.log");
    assert(kernel_boot_log_policy_load(&policy) == -1);
    assert(policy.console_loglevel == 7);
    assert(policy.file_enabled == 0);

    kernel_boot_command_line_set("quiet loglevel=9");
    assert(kernel_boot_log_policy_load(&policy) == -1);
    assert(policy.console_loglevel == 4);
    assert(policy.quiet == 1);

    assert(kernel_boot_log_path_valid("/edgeos.log") == 1);
    assert(kernel_boot_log_path_valid("/var/log/edgeos.log") == 1);
    assert(kernel_boot_log_path_valid("/") == 0);
    assert(kernel_boot_log_path_valid("edgeos.log") == 0);
    assert(kernel_boot_log_path_valid("/var//edgeos.log") == 0);
    assert(kernel_boot_log_path_valid("/var/../edgeos.log") == 0);
    assert(kernel_boot_log_path_valid("/var/./edgeos.log") == 0);
    return 0;
}
