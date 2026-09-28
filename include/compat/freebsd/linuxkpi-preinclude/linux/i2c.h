#ifndef _EDGEOS_LINUXKPI_I2C_H_
#define _EDGEOS_LINUXKPI_I2C_H_

#include_next <linux/i2c.h>
#include <linux/slab.h>

struct i2c_client {
	unsigned short addr;
	int irq;
	struct device dev;
	struct i2c_adapter *adapter;
	void *data;
};

struct i2c_device_id {
	char name[I2C_NAME_SIZE];
	kernel_ulong_t driver_data;
};

struct i2c_driver {
	struct device_driver driver;
	int (*probe)(struct i2c_client *);
	void (*remove)(struct i2c_client *);
	const struct i2c_device_id *id_table;
};

static inline struct i2c_client *
to_i2c_client(struct device *dev)
{
	return (container_of(dev, struct i2c_client, dev));
}

static inline void
i2c_set_clientdata(struct i2c_client *client, void *data)
{
	client->data = data;
	dev_set_drvdata(&client->dev, data);
}

static inline void *
i2c_get_clientdata(const struct i2c_client *client)
{
	return (client->data);
}

static inline const void *
i2c_get_match_data(const struct i2c_client *client)
{
	(void)client;
	return (NULL);
}

static inline int
i2c_smbus_read_byte_data(const struct i2c_client *client, u8 command)
{
	(void)client;
	(void)command;
	return (-EOPNOTSUPP);
}

static inline int
i2c_smbus_write_byte_data(const struct i2c_client *client, u8 command,
    u8 value)
{
	(void)client;
	(void)command;
	(void)value;
	return (-EOPNOTSUPP);
}

static inline int
i2c_smbus_read_i2c_block_data(const struct i2c_client *client, u8 command,
    u8 length, u8 *values)
{
	(void)client;
	(void)command;
	(void)length;
	(void)values;
	return (-EOPNOTSUPP);
}

static inline int
i2c_smbus_write_i2c_block_data(const struct i2c_client *client, u8 command,
    u8 length, const u8 *values)
{
	(void)client;
	(void)command;
	(void)length;
	(void)values;
	return (-EOPNOTSUPP);
}

static inline int
i2c_master_send(const struct i2c_client *client, const char *buffer, int count)
{
	(void)client;
	(void)buffer;
	(void)count;
	return (-EOPNOTSUPP);
}

static inline bool
i2c_check_functionality(struct i2c_adapter *adapter, u32 functionality)
{
	(void)adapter;
	(void)functionality;
	return (true);
}

static inline struct i2c_client *
i2c_new_dummy_device(struct i2c_adapter *adapter, u16 address)
{
	struct i2c_client *client;

	client = kzalloc(sizeof(*client), GFP_KERNEL);
	if (client == NULL)
		return (ERR_PTR(-ENOMEM));
	client->adapter = adapter;
	client->addr = address;
	return (client);
}

static inline void
i2c_unregister_device(struct i2c_client *client)
{
	kfree(client);
}

#ifndef I2C_FUNC_SMBUS_I2C_BLOCK
#define I2C_FUNC_SMBUS_I2C_BLOCK BIT(1)
#endif

#define module_i2c_driver(_driver) \
	static struct i2c_driver * const __used \
	edgeos_i2c_driver_##_driver = &(_driver)

#endif /* _EDGEOS_LINUXKPI_I2C_H_ */
