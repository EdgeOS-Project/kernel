#ifndef EDGEOS_FREEBSD_LINUXKPI_NOUVEAU_IOCTL_COMPAT_H
#define EDGEOS_FREEBSD_LINUXKPI_NOUVEAU_IOCTL_COMPAT_H

#include <nvkm/core/object.h>

struct nvif_ioctl_map_netbsd_v0 {
	__u8 version;
	__u8 type;
	__u8 pad02[6];
	bus_space_tag_t tag;
	__u64 handle;
	__u64 length;
	__u8 data[];
};

static inline int
edgeos_nvkm_object_map(struct nvkm_object *object, void *arguments,
    u32 argument_size, enum nvkm_object_map *type, bus_space_tag_t *tag,
    u64 *address, u64 *size)
{
	(void)tag;
	return nvkm_object_map(object, arguments, argument_size, type, address,
	    size);
}

#define nvkm_object_map(_object, _arguments, _argument_size, _type, _tag, \
    _address, _size) \
	edgeos_nvkm_object_map((_object), (_arguments), (_argument_size), (_type), \
	    (_tag), (_address), (_size))

#endif
