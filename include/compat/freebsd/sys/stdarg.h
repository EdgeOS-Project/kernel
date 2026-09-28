#ifndef EDGEOS_COMPAT_FREEBSD_SYS_STDARG_H
#define EDGEOS_COMPAT_FREEBSD_SYS_STDARG_H

typedef __builtin_va_list va_list;

#ifndef va_start
#define va_start(arguments, last) __builtin_va_start((arguments), (last))
#endif
#ifndef va_end
#define va_end(arguments) __builtin_va_end(arguments)
#endif
#ifndef va_arg
#define va_arg(arguments, type) __builtin_va_arg((arguments), type)
#endif
#ifndef va_copy
#define va_copy(destination, source) __builtin_va_copy((destination), (source))
#endif

#ifndef _VA_LIST_DECLARED
#define _VA_LIST_DECLARED
#endif

#endif
