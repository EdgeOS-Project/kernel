#pragma once

/* EdgeOS does not expose Linux framebuffer connector command-line options. */
#undef fb_get_options
#define fb_get_options(name, option) (-ENOENT)

