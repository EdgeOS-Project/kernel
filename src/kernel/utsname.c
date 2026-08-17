/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-neutral Linux UTS namespace and uname semantics. */

#include "kernel/linux_utsname.h"
#include "kernel/namespace_runtime.h"
#include "kernel/process_runtime.h"

static void uts_field_set(char field[65], const char *value) {
    unsigned int index = 0;
    while (index < 64 && value && value[index]) {
        field[index] = value[index];
        ++index;
    }
    while (index < 65) field[index++] = 0;
}

void linux_utsname_fill(linux_utsname_t *uts, const char *hostname,
                        const char *release, const char *version,
                        const char *machine) {
    if (!uts) return;
    uts_field_set(uts->sysname, "Linux");
    /* An empty UTS nodename is valid after sethostname(NULL, 0). */
    uts_field_set(uts->nodename, hostname ? hostname : "edgeos");
    uts_field_set(uts->release, release);
    uts_field_set(uts->version, version);
    uts_field_set(uts->machine, machine);
    uts_field_set(uts->domainname, "localdomain");
}

const char *kernel_current_hostname(void) {
    edge_namespace_set_t *namespaces = kernel_arch_current_namespace_set();
    return namespaces ? edge_uts_hostname(namespaces) : "edgeos";
}

const char *kernel_current_domainname(void) {
    edge_namespace_set_t *namespaces = kernel_arch_current_namespace_set();
    return namespaces ? edge_uts_domainname(namespaces) : "localdomain";
}

int kernel_current_set_hostname(const char *name, uint32_t length) {
    edge_namespace_set_t *namespaces = kernel_arch_current_namespace_set();
    if (!namespaces || !name) return -1;
    return edge_uts_set_hostname(namespaces, name, length);
}

int kernel_current_set_domainname(const char *name, uint32_t length) {
    edge_namespace_set_t *namespaces = kernel_arch_current_namespace_set();
    if (!namespaces || !name) return -1;
    return edge_uts_set_domainname(namespaces, name, length);
}
