#ifndef _EDGEOS_LINUXKPI_INTEL_SCU_IPC_H_
#define _EDGEOS_LINUXKPI_INTEL_SCU_IPC_H_

#include <linux/device.h>

struct intel_scu_ipc_dev {
	struct device *dev;
};

static inline struct intel_scu_ipc_dev *
intel_scu_ipc_dev_get(void)
{
	return (ERR_PTR(-ENODEV));
}

static inline void
intel_scu_ipc_dev_put(struct intel_scu_ipc_dev *scu)
{
	(void)scu;
}

static inline struct intel_scu_ipc_dev *
devm_intel_scu_ipc_dev_get(struct device *dev)
{
	(void)dev;
	return (ERR_PTR(-ENODEV));
}

static inline int
intel_scu_ipc_dev_ioread8(struct intel_scu_ipc_dev *scu, u16 address,
    u8 *data)
{
	(void)scu;
	(void)address;
	(void)data;
	return (-EOPNOTSUPP);
}

static inline int
intel_scu_ipc_dev_iowrite8(struct intel_scu_ipc_dev *scu, u16 address,
    u8 data)
{
	(void)scu;
	(void)address;
	(void)data;
	return (-EOPNOTSUPP);
}

static inline int
intel_scu_ipc_dev_update(struct intel_scu_ipc_dev *scu, u16 address,
    u8 data, u8 mask)
{
	(void)scu;
	(void)address;
	(void)data;
	(void)mask;
	return (-EOPNOTSUPP);
}

static inline int
intel_scu_ipc_dev_command(struct intel_scu_ipc_dev *scu, int command,
    int subcommand, const void *input, size_t input_length,
    void *output, size_t output_length)
{
	(void)scu;
	(void)command;
	(void)subcommand;
	(void)input;
	(void)input_length;
	(void)output;
	(void)output_length;
	return (-EOPNOTSUPP);
}

#endif /* _EDGEOS_LINUXKPI_INTEL_SCU_IPC_H_ */
