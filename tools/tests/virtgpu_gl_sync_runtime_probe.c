/* SPDX-License-Identifier: MPL-2.0 */

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

typedef void *EGLDisplay;
typedef void *EGLConfig;
typedef void *EGLContext;
typedef void *EGLSurface;
typedef void *EGLSyncKHR;
typedef int32_t EGLint;
typedef uint32_t EGLBoolean;
typedef uint32_t EGLenum;
typedef intptr_t EGLAttrib;
typedef void *GLsync;
typedef uint32_t GLenum;
typedef uint32_t GLbitfield;
typedef uint64_t GLuint64;

#define EGL_NONE 0x3038
#define EGL_SURFACE_TYPE 0x3033
#define EGL_PBUFFER_BIT 0x0001
#define EGL_RENDERABLE_TYPE 0x3040
#define EGL_OPENGL_ES3_BIT 0x0040
#define EGL_CONTEXT_CLIENT_VERSION 0x3098
#define EGL_WIDTH 0x3057
#define EGL_HEIGHT 0x3056
#define EGL_OPENGL_ES_API 0x30a0
#define EGL_PLATFORM_SURFACELESS_MESA 0x31dd
#define EGL_SYNC_NATIVE_FENCE_ANDROID 0x3144
#define EGL_SYNC_NATIVE_FENCE_FD_ANDROID 0x3145
#define EGL_FOREVER_KHR UINT64_C(0xffffffffffffffff)
#define EGL_CONDITION_SATISFIED_KHR 0x30f6
#define GL_RENDERER 0x1f01
#define GL_VERSION 0x1f02
#define GL_SYNC_GPU_COMMANDS_COMPLETE 0x9117
#define GL_COLOR_BUFFER_BIT 0x00004000
#define GL_ALREADY_SIGNALED 0x911a
#define GL_CONDITION_SATISFIED 0x911c
#define GL_WAIT_FAILED 0x911d

static void *require_symbol(void *library, const char *name)
{
    void *symbol = dlsym(library, name);

    if (!symbol) {
        fprintf(stderr, "missing symbol: %s\n", name);
        exit(2);
    }
    return symbol;
}

#define LOAD(target, library, name) \
    do { *(void **)(&(target)) = require_symbol((library), (name)); } while (0)

int main(void)
{
    void *egl = dlopen("libEGL.so.1", RTLD_NOW | RTLD_LOCAL);
    void *gles = dlopen("libGLESv2.so.2", RTLD_NOW | RTLD_LOCAL);
    EGLDisplay (*get_platform_display)(EGLenum, void *, const EGLAttrib *);
    void *(*get_proc_address)(const char *);
    EGLBoolean (*initialize)(EGLDisplay, EGLint *, EGLint *);
    EGLBoolean (*bind_api)(EGLenum);
    EGLBoolean (*choose_config)(EGLDisplay, const EGLint *, EGLConfig *,
                               EGLint, EGLint *);
    EGLContext (*create_context)(EGLDisplay, EGLConfig, EGLContext,
                                 const EGLint *);
    EGLSurface (*create_pbuffer_surface)(EGLDisplay, EGLConfig,
                                        const EGLint *);
    EGLBoolean (*make_current)(EGLDisplay, EGLSurface, EGLSurface,
                              EGLContext);
    EGLint (*get_egl_error)(void);
    EGLSyncKHR (*create_sync)(EGLDisplay, EGLenum, const EGLint *);
    EGLint (*duplicate_native_fence)(EGLDisplay, EGLSyncKHR);
    EGLint (*client_wait_egl_sync)(EGLDisplay, EGLSyncKHR, EGLint, uint64_t);
    EGLBoolean (*destroy_sync)(EGLDisplay, EGLSyncKHR);
    const unsigned char *(*get_string)(GLenum);
    GLsync (*fence_sync)(GLenum, GLbitfield);
    GLenum (*client_wait_sync)(GLsync, GLbitfield, GLuint64);
    void (*finish)(void);
    void (*flush)(void);
    void (*clear_color)(float, float, float, float);
    void (*clear)(GLbitfield);
    GLenum (*get_error)(void);
    EGLDisplay display;
    EGLConfig config = NULL;
    EGLContext context;
    EGLSurface surface;
    EGLint major = 0;
    EGLint minor = 0;
    EGLint count = 0;
    GLsync sync;
    GLenum status;
    GLenum error;
    EGLSyncKHR native_sync;
    EGLSyncKHR imported_sync;
    EGLint native_fd;
    EGLint duplicate_fd;
    EGLint imported_status;
    int fd_flags;
    static const EGLint config_attributes[] = {
        EGL_SURFACE_TYPE, EGL_PBUFFER_BIT,
        EGL_RENDERABLE_TYPE, EGL_OPENGL_ES3_BIT,
        EGL_NONE
    };
    static const EGLint context_attributes[] = {
        EGL_CONTEXT_CLIENT_VERSION, 3,
        EGL_NONE
    };
    static const EGLint surface_attributes[] = {
        EGL_WIDTH, 16,
        EGL_HEIGHT, 16,
        EGL_NONE
    };

    if (!egl || !gles) {
        fprintf(stderr, "EGL or GLES library unavailable\n");
        return 2;
    }
    LOAD(get_platform_display, egl, "eglGetPlatformDisplay");
    LOAD(get_proc_address, egl, "eglGetProcAddress");
    LOAD(initialize, egl, "eglInitialize");
    LOAD(bind_api, egl, "eglBindAPI");
    LOAD(choose_config, egl, "eglChooseConfig");
    LOAD(create_context, egl, "eglCreateContext");
    LOAD(create_pbuffer_surface, egl, "eglCreatePbufferSurface");
    LOAD(make_current, egl, "eglMakeCurrent");
    LOAD(get_egl_error, egl, "eglGetError");
    *(void **)(&create_sync) = get_proc_address("eglCreateSyncKHR");
    *(void **)(&duplicate_native_fence) =
        get_proc_address("eglDupNativeFenceFDANDROID");
    *(void **)(&client_wait_egl_sync) =
        get_proc_address("eglClientWaitSyncKHR");
    *(void **)(&destroy_sync) = get_proc_address("eglDestroySyncKHR");
    if (!create_sync || !duplicate_native_fence ||
        !client_wait_egl_sync || !destroy_sync) {
        fprintf(stderr, "native fence EGL extension unavailable\n");
        return 2;
    }
    LOAD(get_string, gles, "glGetString");
    LOAD(fence_sync, gles, "glFenceSync");
    LOAD(client_wait_sync, gles, "glClientWaitSync");
    LOAD(finish, gles, "glFinish");
    LOAD(flush, gles, "glFlush");
    LOAD(clear_color, gles, "glClearColor");
    LOAD(clear, gles, "glClear");
    LOAD(get_error, gles, "glGetError");

    display = get_platform_display(EGL_PLATFORM_SURFACELESS_MESA, NULL, NULL);
    if (!display || !initialize(display, &major, &minor) ||
        !bind_api(EGL_OPENGL_ES_API) ||
        !choose_config(display, config_attributes, &config, 1, &count) ||
        count != 1) {
        fprintf(stderr, "EGL initialization failed\n");
        return 1;
    }
    context = create_context(display, config, NULL, context_attributes);
    surface = create_pbuffer_surface(display, config, surface_attributes);
    if (!context || !surface ||
        !make_current(display, surface, surface, context)) {
        fprintf(stderr, "EGL context creation failed\n");
        return 1;
    }

    sync = fence_sync(GL_SYNC_GPU_COMMANDS_COMPLETE, 0);
    finish();
    status = client_wait_sync(sync, 0, 0);
    error = get_error();
    printf("renderer=%s\n", get_string(GL_RENDERER));
    printf("version=%s\n", get_string(GL_VERSION));
    printf("sync_status=0x%x gl_error=0x%x egl=%d.%d\n",
           status, error, major, minor);
    if (!sync || error || status == GL_WAIT_FAILED ||
        (status != GL_ALREADY_SIGNALED && status != GL_CONDITION_SATISFIED))
        return 1;

    clear_color(0.1f, 0.3f, 0.7f, 1.0f);
    clear(GL_COLOR_BUFFER_BIT);
    native_sync = create_sync(
        display, EGL_SYNC_NATIVE_FENCE_ANDROID, NULL);
    flush();
    errno = 0;
    native_fd = duplicate_native_fence(display, native_sync);
    if (!native_sync || native_fd < 0) {
        fprintf(stderr,
                "native fence export failed fd=%d egl=0x%x errno=%d\n",
                native_fd, get_egl_error(), errno);
        return 1;
    }
    duplicate_fd = fcntl(native_fd, F_DUPFD_CLOEXEC, 0);
    fd_flags = duplicate_fd >= 0 ? fcntl(duplicate_fd, F_GETFD) : -1;
    printf("native_fd=%d duplicate_fd=%d fd_flags=0x%x\n",
           native_fd, duplicate_fd, fd_flags);
    close(native_fd);
    if (duplicate_fd < 0 || fd_flags < 0 || !(fd_flags & FD_CLOEXEC))
        return 1;
    {
        EGLint import_attributes[] = {
            EGL_SYNC_NATIVE_FENCE_FD_ANDROID, duplicate_fd,
            EGL_NONE
        };

        imported_sync = create_sync(
            display, EGL_SYNC_NATIVE_FENCE_ANDROID, import_attributes);
    }
    if (!imported_sync) {
        fprintf(stderr, "native fence import failed\n");
        close(duplicate_fd);
        return 1;
    }
    imported_status = client_wait_egl_sync(
        display, imported_sync, 0, EGL_FOREVER_KHR);
    printf("native_import_status=0x%x\n", imported_status);
    destroy_sync(display, imported_sync);
    destroy_sync(display, native_sync);
    if (imported_status != EGL_CONDITION_SATISFIED_KHR)
        return 1;
    puts("VIRTGPU_GL_SYNC_RUNTIME_PASS");
    return 0;
}
