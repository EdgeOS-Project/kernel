#ifndef TYPES_H
#define TYPES_H

#ifndef NULL
#define NULL 0
#endif

typedef unsigned char uint8;
typedef unsigned short uint16;
typedef unsigned int uint32;
typedef unsigned long long uint64;
typedef signed char sint8;
typedef signed short sint16;
typedef signed int sint32;
typedef uint8 byte;
typedef uint16 word;
typedef uint32 dword;
#ifndef __cplusplus
#if defined(__SIZE_TYPE__)
typedef __SIZE_TYPE__ size_t;
#else
typedef unsigned long size_t;
#endif
#endif
typedef enum {
    FALSE,
    TRUE
} BOOL;

#endif
