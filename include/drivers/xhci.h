#ifndef DRIVERS_XHCI_H
#define DRIVERS_XHCI_H

#include <stdint.h>
#include "drivers/usb_dma.h"
#include "drivers/xhci_device_policy.h"
#include "kernel/input_device.h"

#define XHCI_MAX_TRACKED_SLOTS 32u

typedef struct {
    uint8_t used;
    uint8_t online;
    uint8_t slot_id;
    uint8_t port_id;
    uint8_t speed_id;
    uint8_t hid_ready;
    uint8_t hid_iface;
    uint8_t hid_ep_addr;
    uint8_t hid_ep_dci;
    uint8_t hid_interval;
    uint8_t hid_protocol;
    uint8_t hid_report_mode;
    uint16_t hid_report_descriptor_length;
    xhci_hid_pointer_layout_t hid_pointer_layout;
    uint8_t mass_ready;
    uint8_t uac_ready;
    uint8_t usbnet_ready;
    uint8_t usbnet_driver;
    uint16_t hid_max_packet;
    uint8_t mass_iface;
    uint8_t mass_bulk_in_addr;
    uint8_t mass_bulk_out_addr;
    uint8_t mass_bulk_in_dci;
    uint8_t mass_bulk_out_dci;
    uint8_t mass_in_enq;
    uint8_t mass_out_enq;
    uint8_t mass_in_ccs;
    uint8_t mass_out_ccs;
    uint16_t mass_bulk_in_mps;
    uint16_t mass_bulk_out_mps;
    uint8_t usbnet_iface;
    uint8_t usbnet_bulk_in_addr;
    uint8_t usbnet_bulk_out_addr;
    uint8_t usbnet_bulk_in_dci;
    uint8_t usbnet_bulk_out_dci;
    uint8_t usbnet_in_enq;
    uint8_t usbnet_out_enq;
    uint8_t usbnet_in_ccs;
    uint8_t usbnet_out_ccs;
    uint16_t usbnet_bulk_in_mps;
    uint16_t usbnet_bulk_out_mps;
    uint32_t mass_sector_size;
    uint32_t mass_sector_count;
    uint64_t mass_read_bytes;
    uint64_t mass_read_elapsed_us;
    uint64_t mass_next_report_bytes;
    uint32_t mass_read_commands;
    uint8_t uac_iface;
    uint8_t uac_alt;
    uint8_t uac_ep_addr;
    uint8_t uac_ep_dci;
    uint8_t uac_interval;
    uint8_t uac_enq;
    uint8_t uac_ccs;
    uint8_t uac_channels;
    uint8_t uac_subframe_size;
    uint16_t uac_max_packet;
    uint16_t uac_packet_bytes;
    uint32_t uac_rate;
    uint16_t max_packet0;
    uint16_t vendor_id;
    uint16_t product_id;
    uint16_t bcd_device;
    uint8_t device_class;
    uint8_t device_subclass;
    uint8_t device_protocol;
    uint8_t config_value;
    uint8_t interface_class;
    uint8_t interface_subclass;
    uint8_t interface_protocol;
    uint8_t interface_number;
    uint8_t ep0_ccs;
    uint8_t ep0_enq;
    uint8_t intr_ccs;
    uint8_t intr_enq;
    usb_dma_block_t input_ctx;
    usb_dma_block_t device_ctx;
    usb_dma_block_t ep0_ring;
    usb_dma_block_t ctrl_buf;
    usb_dma_block_t intr_ring;
    usb_dma_block_t intr_buf;
    usb_dma_block_t mass_in_ring;
    usb_dma_block_t mass_out_ring;
    usb_dma_block_t mass_cbw;
    usb_dma_block_t mass_csw;
    usb_dma_block_t mass_data;
    usb_dma_block_t usbnet_in_ring;
    usb_dma_block_t usbnet_out_ring;
    usb_dma_block_t usbnet_rx_buf;
    usb_dma_block_t usbnet_tx_buf;
    usb_dma_block_t uac_ring;
    usb_dma_block_t uac_data;
    uint64_t intr_pending_trb;
} xhci_slot_state_t;

typedef struct {
    int used;
    uint8_t bus, dev, fn;
    uint8_t irq_line;
    uint16_t vendor, device;
    uint64_t mmio_base;
    uint8_t cap_len;
    uint8_t max_ports;
    uint32_t ext_cap_off;
    volatile uint8_t *mmio;
    volatile uint8_t *op;
    volatile uint8_t *rt;
    volatile uint8_t *db;
    uint8_t max_slots;
    uint8_t cmd_ccs;
    uint8_t evt_ccs;
    uint8_t ctx_sz64;
    uint8_t cmd_enq;
    uint32_t cmd_ring_size;
    uint32_t evt_ring_size;
    uint32_t evt_deq;
    uint64_t cmd_wait_ptr;
    uint8_t cmd_wait_done;
    uint8_t cmd_wait_cc;
    uint8_t cmd_wait_slot;
    uint8_t cmd_wait_ep;
    uint64_t xfer_wait_ptr;
    uint64_t xfer_wait_alt_ptr1;
    uint64_t xfer_wait_alt_ptr2;
    uint8_t xfer_wait_done;
    uint8_t xfer_wait_cc;
    uint8_t xfer_wait_slot;
    uint8_t xfer_wait_ep;
    uint8_t enum_busy;
    uint16_t scratchpad_count;
    uint32_t page_size;
    usb_dma_block_t dcbaa;
    usb_dma_block_t scratchpad_array;
    usb_dma_block_t cmd_ring;
    usb_dma_block_t evt_ring;
    usb_dma_block_t erst;
    uint8_t port_to_slot[256];
    uint64_t port_retry_after_us[256];
    uint8_t port_failure_count[256];
    uint8_t port_disconnect_observations[256];
    xhci_slot_state_t slots[XHCI_MAX_TRACKED_SLOTS + 1u];
    input_device_description_t input_description[EDGE_INPUT_DEVICE_MAX];
    uint16_t port_poll_countdown;
    uint8_t port_change_pending;
    int running;
} xhci_controller_t;

int xhci_init_controller(xhci_controller_t *xc,
                         uint8_t bus, uint8_t dev, uint8_t fn,
                         uint16_t vendor, uint16_t device,
                         uint32_t bar0, uint32_t bar1, uint8_t irq_line);
void xhci_poll_controller(xhci_controller_t *xc);
void xhci_poll_controller_events(xhci_controller_t *xc);
void xhci_debug_dump(const xhci_controller_t *xc);
int xhci_storage_present(const xhci_controller_t *xc, uint8_t slot_id);
uint32_t xhci_storage_sector_size(const xhci_controller_t *xc, uint8_t slot_id);
uint32_t xhci_storage_sector_count(const xhci_controller_t *xc, uint8_t slot_id);
int xhci_storage_read(xhci_controller_t *xc, uint8_t slot_id, uint32_t lba, uint32_t count, void *out);
int xhci_storage_write(xhci_controller_t *xc, uint8_t slot_id, uint32_t lba, uint32_t count, const void *in);

#endif
