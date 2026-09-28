/* SPDX-License-Identifier: MPL-2.0 */
#define _GNU_SOURCE
/*
 * Copyright (c) EdgeOS Contributors.
 *
 * Runtime GTK/GObject class-layout validation for Linux ABI testing.  The test
 * intentionally uses dlsym instead of GTK development headers so one binary can
 * be copied into an unmodified Alpine desktop rootfs.
 */

#include <dlfcn.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef int (*gtk_init_check_fn)(int *argc, char ***argv);
typedef void *(*gtk_button_new_fn)(void);
typedef void (*gtk_widget_get_preferred_width_fn)(void *widget,
                                                   int *minimum_width,
                                                   int *natural_width);
typedef uintptr_t (*gtk_widget_get_type_fn)(void);
typedef uintptr_t (*gtk_derived_get_type_fn)(void);
typedef void *(*g_type_class_ref_fn)(uintptr_t type);
typedef const char *(*g_type_name_fn)(uintptr_t type);
typedef uintptr_t (*g_type_parent_fn)(uintptr_t type);

struct edge_g_type_query {
    uintptr_t type;
    const char *type_name;
    unsigned int class_size;
    unsigned int instance_size;
};

typedef void (*g_type_query_fn)(uintptr_t type, struct edge_g_type_query *query);

static void *required_symbol(void *handle, const char *name) {
    void *symbol = dlsym(handle, name);

    if (!symbol) {
        fprintf(stderr, "missing symbol %s: %s\n", name, dlerror());
        exit(2);
    }
    return symbol;
}

static void print_class_tail(const char *label, uintptr_t klass) {
    uintptr_t type = *(const uintptr_t *)klass;

    printf("%s class=%#" PRIxPTR " type=%#" PRIxPTR "\n",
           label, klass, type);
    for (uintptr_t offset = 0x2c0; offset < 0x300; offset += sizeof(uintptr_t)) {
        printf("%s[%#" PRIxPTR "]=%#" PRIxPTR "\n", label, offset,
               *(const uintptr_t *)(klass + offset));
    }
}

static void print_library_address(const char *label, uintptr_t address) {
    Dl_info info = {0};

    if (!address) {
        printf("%s address=0\n", label);
        return;
    }
    if (!dladdr((const void *)address, &info) || !info.dli_fbase) {
        printf("%s address=%#" PRIxPTR " object=?\n", label, address);
        return;
    }
    printf("%s address=%#" PRIxPTR " base=%p offset=%#" PRIxPTR " object=%s\n",
           label, address, info.dli_fbase,
           address - (uintptr_t)info.dli_fbase,
           info.dli_fname ? info.dli_fname : "?");
}

static void print_type_chain(uintptr_t type, g_type_parent_fn g_type_parent,
                             g_type_query_fn g_type_query) {
    while (type) {
        struct edge_g_type_query query = {0};

        g_type_query(type, &query);
        printf("query type=%#" PRIxPTR " name=%s class-size=%u instance-size=%u\n",
               query.type, query.type_name ? query.type_name : "?",
               query.class_size, query.instance_size);
        type = g_type_parent(type);
    }
}

int main(int argc, char **argv) {
    void *gtk;
    void *gobject;
    gtk_init_check_fn gtk_init_check;
    gtk_button_new_fn gtk_button_new;
    gtk_widget_get_preferred_width_fn gtk_widget_get_preferred_width;
    gtk_widget_get_type_fn gtk_widget_get_type;
    gtk_derived_get_type_fn gtk_container_get_type;
    gtk_derived_get_type_fn gtk_bin_get_type;
    gtk_derived_get_type_fn gtk_button_get_type;
    g_type_class_ref_fn g_type_class_ref;
    g_type_name_fn g_type_name;
    g_type_parent_fn g_type_parent;
    g_type_query_fn g_type_query;
    void *button;
    uintptr_t widget_type;
    uintptr_t widget_class;
    uintptr_t klass;
    uintptr_t type;
    int minimum_width = -1;
    int natural_width = -1;

    gtk = dlopen("libgtk-3.so.0", RTLD_NOW | RTLD_LOCAL);
    if (!gtk) {
        fprintf(stderr, "cannot load GTK: %s\n", dlerror());
        return 2;
    }
    gobject = dlopen("libgobject-2.0.so.0", RTLD_NOW | RTLD_LOCAL);
    if (!gobject) {
        fprintf(stderr, "cannot load GObject: %s\n", dlerror());
        return 2;
    }

    gtk_init_check = (gtk_init_check_fn)required_symbol(gtk, "gtk_init_check");
    gtk_button_new = (gtk_button_new_fn)required_symbol(gtk, "gtk_button_new");
    gtk_widget_get_preferred_width =
        (gtk_widget_get_preferred_width_fn)required_symbol(
            gtk, "gtk_widget_get_preferred_width");
    gtk_widget_get_type =
        (gtk_widget_get_type_fn)required_symbol(gtk, "gtk_widget_get_type");
    gtk_container_get_type =
        (gtk_derived_get_type_fn)required_symbol(gtk, "gtk_container_get_type");
    gtk_bin_get_type =
        (gtk_derived_get_type_fn)required_symbol(gtk, "gtk_bin_get_type");
    gtk_button_get_type =
        (gtk_derived_get_type_fn)required_symbol(gtk, "gtk_button_get_type");
    g_type_class_ref =
        (g_type_class_ref_fn)required_symbol(gobject, "g_type_class_ref");
    g_type_name = (g_type_name_fn)required_symbol(gobject, "g_type_name");
    g_type_parent =
        (g_type_parent_fn)required_symbol(gobject, "g_type_parent");
    g_type_query =
        (g_type_query_fn)required_symbol(gobject, "g_type_query");

    if (!gtk_init_check(&argc, &argv)) {
        fprintf(stderr, "gtk_init_check failed\n");
        return 3;
    }
    widget_type = gtk_widget_get_type();
    widget_class = (uintptr_t)g_type_class_ref(widget_type);
    if (!widget_class) {
        fprintf(stderr, "g_type_class_ref(GtkWidget) failed\n");
        return 4;
    }
    printf("base type=%#" PRIxPTR " name=%s\n",
           widget_type, g_type_name(widget_type));
    print_class_tail("GtkWidgetClass", widget_class);

    print_class_tail("GtkContainerClass",
                     (uintptr_t)g_type_class_ref(gtk_container_get_type()));
    print_library_address("GtkContainer.compute_expand",
                          *(const uintptr_t *)((uintptr_t)g_type_class_ref(
                              gtk_container_get_type()) + 0x2d8));
    print_library_address("GtkContainer.adjust_size_request",
                          *(const uintptr_t *)((uintptr_t)g_type_class_ref(
                              gtk_container_get_type()) + 0x2e0));
    print_library_address("GtkContainer.adjust_size_allocation",
                          *(const uintptr_t *)((uintptr_t)g_type_class_ref(
                              gtk_container_get_type()) + 0x2e8));
    print_class_tail("GtkBinClass",
                     (uintptr_t)g_type_class_ref(gtk_bin_get_type()));
    print_class_tail("GtkButtonClassBeforeNew",
                     (uintptr_t)g_type_class_ref(gtk_button_get_type()));

    button = gtk_button_new();
    if (!button) {
        fprintf(stderr, "gtk_button_new failed\n");
        return 5;
    }

    klass = *(const uintptr_t *)button;
    type = *(const uintptr_t *)klass;
    printf("object=%p class=%#" PRIxPTR " type=%#" PRIxPTR " name=%s\n",
           button, klass, type, g_type_name(type));
    print_type_chain(type, g_type_parent, g_type_query);
    print_class_tail("GtkButtonClass", klass);
    fflush(stdout);

    gtk_widget_get_preferred_width(button, &minimum_width, &natural_width);
    printf("preferred-width minimum=%d natural=%d\n",
           minimum_width, natural_width);
    return 0;
}
