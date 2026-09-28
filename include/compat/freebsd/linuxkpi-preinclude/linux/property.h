#ifndef _EDGEOS_LINUXKPI_PROPERTY_H_
#define _EDGEOS_LINUXKPI_PROPERTY_H_

#include <linux/device.h>
#include <linux/cleanup.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fwnode.h>

struct property_entry {
	const char *name;
	const void *data;
	size_t length;
	unsigned long scalar;
};

#define PROPERTY_ENTRY_STRING(_name, _value) \
	{ .name = (_name), .data = (_value) }
#define PROPERTY_ENTRY_U32_ARRAY(_name, _values) \
	{ .name = (_name), .data = (_values), .length = ARRAY_SIZE(_values) }
#define PROPERTY_ENTRY_U32(_name, _value) \
	{ .name = (_name), .scalar = (_value) }

static inline struct fwnode_handle *
dev_fwnode(const struct device *dev)
{
	return (dev != NULL ? dev->fwnode : NULL);
}

static inline struct fwnode_handle *
fwnode_handle_get(struct fwnode_handle *fwnode)
{
	return (fwnode);
}

static inline void
fwnode_handle_put(struct fwnode_handle *fwnode)
{
	(void)fwnode;
}

static inline struct fwnode_handle *
fwnode_create_software_node(const struct property_entry *properties,
    const struct fwnode_handle *parent)
{
	(void)properties;
	(void)parent;
	return (ERR_PTR(-ENODEV));
}

static inline void
fwnode_remove_software_node(struct fwnode_handle *fwnode)
{
	(void)fwnode;
}

static inline void
fw_devlink_purge_absent_suppliers(struct fwnode_handle *fwnode)
{
	(void)fwnode;
}

DEFINE_FREE(fwnode_handle, struct fwnode_handle *, fwnode_handle_put(_T))

static inline bool
fwnode_property_present(const struct fwnode_handle *fwnode, const char *property)
{
	(void)fwnode;
	(void)property;
	return (false);
}

static inline struct fwnode_handle *
fwnode_find_reference(const struct fwnode_handle *fwnode, const char *property,
    unsigned int index)
{
	(void)fwnode;
	(void)property;
	(void)index;
	return (ERR_PTR(-ENOENT));
}

static inline int
fwnode_property_read_string(const struct fwnode_handle *fwnode,
    const char *property, const char **value)
{
	(void)fwnode;
	(void)property;
	(void)value;
	return (-EINVAL);
}

#define EDGEOS_FWNODE_READ_ARRAY(_name, _type) \
static inline int \
fwnode_property_read_##_name##_array(const struct fwnode_handle *fwnode, \
    const char *property, _type *value, size_t count) \
{ \
	(void)fwnode; \
	(void)property; \
	(void)value; \
	(void)count; \
	return (-EINVAL); \
} \
static inline int \
fwnode_property_read_##_name(const struct fwnode_handle *fwnode, \
    const char *property, _type *value) \
{ \
	return (fwnode_property_read_##_name##_array(fwnode, property, value, 1)); \
} \
static inline int \
fwnode_property_count_##_name(const struct fwnode_handle *fwnode, \
    const char *property) \
{ \
	(void)fwnode; \
	(void)property; \
	return (-EINVAL); \
}

EDGEOS_FWNODE_READ_ARRAY(u8, u8)
EDGEOS_FWNODE_READ_ARRAY(u16, u16)
EDGEOS_FWNODE_READ_ARRAY(u32, u32)
EDGEOS_FWNODE_READ_ARRAY(u64, u64)

#undef EDGEOS_FWNODE_READ_ARRAY

static inline bool
fwnode_property_read_bool(const struct fwnode_handle *fwnode,
    const char *property)
{
	return (fwnode_property_present(fwnode, property));
}

static inline struct fwnode_handle *
device_get_named_child_node(const struct device *dev, const char *name)
{
	(void)dev;
	(void)name;
	return (NULL);
}

static inline struct fwnode_handle *
fwnode_get_named_child_node(const struct fwnode_handle *fwnode,
    const char *name)
{
	(void)fwnode;
	(void)name;
	return (NULL);
}

static inline struct fwnode_handle *
fwnode_get_next_child_node(const struct fwnode_handle *fwnode,
    struct fwnode_handle *child)
{
	(void)fwnode;
	(void)child;
	return (NULL);
}

static inline struct fwnode_handle *
device_get_next_child_node(const struct device *dev,
    struct fwnode_handle *child)
{
	return (fwnode_get_next_child_node(dev_fwnode(dev), child));
}

static inline unsigned int
fwnode_get_child_node_count(const struct fwnode_handle *fwnode)
{
	(void)fwnode;
	return (0);
}

static inline const char *
fwnode_get_name(const struct fwnode_handle *fwnode)
{
	(void)fwnode;
	return ("");
}

static inline struct fwnode_handle *
fwnode_graph_get_next_endpoint(const struct fwnode_handle *fwnode,
    struct fwnode_handle *endpoint)
{
	(void)fwnode;
	(void)endpoint;
	return (NULL);
}

static inline struct fwnode_handle *
fwnode_graph_get_remote_port_parent(const struct fwnode_handle *endpoint)
{
	(void)endpoint;
	return (NULL);
}

static inline int
fwnode_connection_find_matches(const struct fwnode_handle *fwnode,
    const char *connection, void **matches,
    void *(*match)(const struct fwnode_handle *, const char *, void *),
    void **data, unsigned int count)
{
	(void)fwnode;
	(void)connection;
	(void)matches;
	(void)match;
	(void)data;
	(void)count;
	return (0);
}

static inline void *
fwnode_connection_find_match(const struct fwnode_handle *fwnode,
    const char *connection, void *data,
    void *(*match)(const struct fwnode_handle *, const char *, void *))
{
	(void)fwnode;
	(void)connection;
	(void)data;
	(void)match;
	return (NULL);
}

#define fwnode_for_each_child_node(_parent, _child) \
	for ((_child) = fwnode_get_next_child_node((_parent), NULL); \
	    (_child) != NULL; \
	    (_child) = fwnode_get_next_child_node((_parent), (_child)))

#define device_for_each_child_node(_dev, _child) \
	fwnode_for_each_child_node(dev_fwnode(_dev), _child)
#define device_for_each_child_node_scoped(_dev, _child) \
	device_for_each_child_node((_dev), _child)

#define device_property_present(_dev, _property) \
	fwnode_property_present(dev_fwnode(_dev), (_property))
#define device_property_read_bool(_dev, _property) \
	fwnode_property_read_bool(dev_fwnode(_dev), (_property))
#define device_property_read_string(_dev, _property, _value) \
	fwnode_property_read_string(dev_fwnode(_dev), (_property), (_value))
#define device_property_read_u8(_dev, _property, _value) \
	fwnode_property_read_u8(dev_fwnode(_dev), (_property), (_value))
#define device_property_read_u16(_dev, _property, _value) \
	fwnode_property_read_u16(dev_fwnode(_dev), (_property), (_value))
#define device_property_read_u32(_dev, _property, _value) \
	fwnode_property_read_u32(dev_fwnode(_dev), (_property), (_value))
#define device_property_read_u64(_dev, _property, _value) \
	fwnode_property_read_u64(dev_fwnode(_dev), (_property), (_value))

#endif /* _EDGEOS_LINUXKPI_PROPERTY_H_ */
