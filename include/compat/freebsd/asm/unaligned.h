/*
 * EdgeOS FreeBSD driver bridge unaligned access helpers.
 *
 * These helpers provide the LinuxKPI interface used by permissively licensed
 * FreeBSD drivers without requiring Linux implementation sources.
 */
#ifndef EDGEOS_FREEBSD_COMPAT_ASM_UNALIGNED_H
#define EDGEOS_FREEBSD_COMPAT_ASM_UNALIGNED_H

#include <sys/endian.h>
#include <sys/systm.h>
#include <sys/types.h>

static inline uint16_t
get_unaligned_le16(const void *pointer)
{
	uint16_t value;

	memcpy(&value, pointer, sizeof(value));
	return (le16toh(value));
}

static inline uint32_t
get_unaligned_le32(const void *pointer)
{
	uint32_t value;

	memcpy(&value, pointer, sizeof(value));
	return (le32toh(value));
}

static inline uint64_t
get_unaligned_le64(const void *pointer)
{
	uint64_t value;

	memcpy(&value, pointer, sizeof(value));
	return (le64toh(value));
}

static inline uint16_t
get_unaligned_be16(const void *pointer)
{
	uint16_t value;

	memcpy(&value, pointer, sizeof(value));
	return (be16toh(value));
}

static inline uint32_t
get_unaligned_be32(const void *pointer)
{
	uint32_t value;

	memcpy(&value, pointer, sizeof(value));
	return (be32toh(value));
}

static inline uint64_t
get_unaligned_be64(const void *pointer)
{
	uint64_t value;

	memcpy(&value, pointer, sizeof(value));
	return (be64toh(value));
}

static inline void
put_unaligned_le16(uint16_t value, void *pointer)
{
	value = htole16(value);
	memcpy(pointer, &value, sizeof(value));
}

static inline void
put_unaligned_le32(uint32_t value, void *pointer)
{
	value = htole32(value);
	memcpy(pointer, &value, sizeof(value));
}

static inline void
put_unaligned_le64(uint64_t value, void *pointer)
{
	value = htole64(value);
	memcpy(pointer, &value, sizeof(value));
}

static inline void
put_unaligned_be16(uint16_t value, void *pointer)
{
	value = htobe16(value);
	memcpy(pointer, &value, sizeof(value));
}

static inline void
put_unaligned_be32(uint32_t value, void *pointer)
{
	value = htobe32(value);
	memcpy(pointer, &value, sizeof(value));
}

static inline void
put_unaligned_be64(uint64_t value, void *pointer)
{
	value = htobe64(value);
	memcpy(pointer, &value, sizeof(value));
}

#endif
