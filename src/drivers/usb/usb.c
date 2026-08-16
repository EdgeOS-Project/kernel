#include "drivers/usb.h"
#include "drivers/usb_handoff.h"
#include "drivers/ehci.h"
#include "drivers/ohci.h"
#include "drivers/uhci.h"
#include "drivers/xhci.h"
#include "drivers/usb_dma.h"
#include "drivers/pci.h"

#include "block/block.h"
#include "kernel/input_device.h"
#include "keyboard.h"
#include "stdio.h"
#include "string.h"
#include "sys/boottime.h"

#ifndef CONFIG_USB_UHCI
int uhci_init_controller(uhci_controller_t *uc,
                         uint8_t bus, uint8_t dev, uint8_t fn,
                         uint16_t vendor, uint16_t device,
                         uint32_t bar0, uint8_t irq_line) {
    (void)uc; (void)bus; (void)dev; (void)fn; (void)vendor; (void)device; (void)bar0; (void)irq_line;
    return -1;
}
void uhci_poll_controller(uhci_controller_t *uc) { (void)uc; }
void uhci_debug_dump(const uhci_controller_t *uc) { (void)uc; }
int uhci_alloc_qh(uhci_controller_t *uc, uint16_t *idx_out, uint32_t *phys_out, void **virt_out) {
    (void)uc; (void)idx_out; (void)phys_out; (void)virt_out; return -1;
}
int uhci_alloc_td(uhci_controller_t *uc, uint16_t *idx_out, uint32_t *phys_out, void **virt_out) {
    (void)uc; (void)idx_out; (void)phys_out; (void)virt_out; return -1;
}
uint32_t uhci_link_qh_ptr(uint32_t phys_qh) { (void)phys_qh; return 1u; }
uint32_t uhci_link_td_ptr(uint32_t phys_td) { (void)phys_td; return 1u; }
uint32_t uhci_link_term_ptr(void) { return 1u; }
int uhci_qh_set(uhci_controller_t *uc, uint16_t qh_idx, uint32_t link_ptr, uint32_t elem_ptr) {
    (void)uc; (void)qh_idx; (void)link_ptr; (void)elem_ptr; return -1;
}
int uhci_td_set(uhci_controller_t *uc, uint16_t td_idx, uint32_t link_ptr, uint32_t status, uint32_t token, uint32_t buffer) {
    (void)uc; (void)td_idx; (void)link_ptr; (void)status; (void)token; (void)buffer; return -1;
}
int uhci_append_async_qh(uhci_controller_t *uc, uint16_t qh_idx) {
    (void)uc; (void)qh_idx; return -1;
}
int uhci_port_connected(uhci_controller_t *uc, int port_index) {
    (void)uc; (void)port_index; return 0;
}
int uhci_port_reset_enable(uhci_controller_t *uc, int port_index, int *low_speed_out) {
    (void)uc; (void)port_index; (void)low_speed_out; return -1;
}
int uhci_control_transfer(uhci_controller_t *uc, int low_speed,
                          uint8_t addr, uint8_t bmRequestType, uint8_t bRequest,
                          uint16_t wValue, uint16_t wIndex, void *buf, uint16_t len,
                          int in_dir) {
    (void)uc; (void)low_speed; (void)addr; (void)bmRequestType; (void)bRequest;
    (void)wValue; (void)wIndex; (void)buf; (void)len; (void)in_dir; return -1;
}
int uhci_intr_queue_open(uhci_controller_t *uc, int low_speed,
                         uint8_t addr, uint8_t ep, uint16_t max_packet, uint8_t interval,
                         uhci_intr_queue_t *out_q) {
    (void)uc; (void)low_speed; (void)addr; (void)ep; (void)max_packet; (void)interval; (void)out_q;
    return -1;
}
int uhci_intr_queue_poll(uhci_controller_t *uc, uhci_intr_queue_t *q,
                         void *out, uint16_t out_len, uint16_t *actual_out) {
    (void)uc; (void)q; (void)out; (void)out_len; (void)actual_out; return -1;
}
#endif

#ifndef CONFIG_USB_EHCI
int ehci_init_controller(ehci_controller_t *ec,
                         uint8_t bus, uint8_t dev, uint8_t fn,
                         uint16_t vendor, uint16_t device,
                         uint32_t bar0, uint8_t irq_line) {
    (void)ec; (void)bus; (void)dev; (void)fn; (void)vendor; (void)device; (void)bar0; (void)irq_line;
    return -1;
}
void ehci_poll_controller(ehci_controller_t *ec) { (void)ec; }
void ehci_debug_dump(const ehci_controller_t *ec) { (void)ec; }
#endif

#ifndef CONFIG_USB_OHCI
int ohci_init_controller(ohci_controller_t *oc,
                         uint8_t bus, uint8_t dev, uint8_t fn,
                         uint16_t vendor, uint16_t device,
                         uint32_t bar0, uint8_t irq_line) {
    (void)oc; (void)bus; (void)dev; (void)fn; (void)vendor; (void)device; (void)bar0; (void)irq_line;
    return -1;
}
void ohci_poll_controller(ohci_controller_t *oc) { (void)oc; }
void ohci_debug_dump(const ohci_controller_t *oc) { (void)oc; }
#endif

#ifndef CONFIG_USB_XHCI
int xhci_init_controller(xhci_controller_t *xc,
                         uint8_t bus, uint8_t dev, uint8_t fn,
                         uint16_t vendor, uint16_t device,
                         uint32_t bar0, uint32_t bar1, uint8_t irq_line) {
    (void)xc; (void)bus; (void)dev; (void)fn; (void)vendor; (void)device; (void)bar0; (void)bar1; (void)irq_line;
    return -1;
}
void xhci_poll_controller(xhci_controller_t *xc) { (void)xc; }
void xhci_debug_dump(const xhci_controller_t *xc) { (void)xc; }
int xhci_storage_present(const xhci_controller_t *xc, uint8_t slot_id) {
    (void)xc; (void)slot_id; return 0;
}
uint32_t xhci_storage_sector_size(const xhci_controller_t *xc, uint8_t slot_id) {
    (void)xc; (void)slot_id; return 0;
}
uint32_t xhci_storage_sector_count(const xhci_controller_t *xc, uint8_t slot_id) {
    (void)xc; (void)slot_id; return 0;
}
int xhci_storage_read(xhci_controller_t *xc, uint8_t slot_id, uint32_t lba, uint32_t count, void *out) {
    (void)xc; (void)slot_id; (void)lba; (void)count; (void)out; return -1;
}
int xhci_storage_write(xhci_controller_t *xc, uint8_t slot_id, uint32_t lba, uint32_t count, const void *in) {
    (void)xc; (void)slot_id; (void)lba; (void)count; (void)in; return -1;
}
#endif

/* Minimal USB subsystem foundation:
 * - PCI host controller discovery (UHCI/OHCI/EHCI/XHCI)
 * - Poll hook for future controller state machines
 * - Shared mouse injection path into /dev/input/mice
 *
 * This does not yet implement transfer scheduling/enumeration/HID.
 */


#define USB_PCI_CLASS_SERIAL 0x0Cu
#define USB_PCI_SUBCLASS_USB 0x03u

#define USB_PROGIF_UHCI 0x00u
#define USB_PROGIF_OHCI 0x10u
#define USB_PROGIF_EHCI 0x20u
#define USB_PROGIF_XHCI 0x30u

#define USB_REQ_GET_DESCRIPTOR 6u
#define USB_REQ_SET_ADDRESS 5u
#define USB_REQ_SET_CONFIGURATION 9u
#define USB_REQ_SET_IDLE 10u
#define USB_REQ_GET_STATUS 0u
#define USB_REQ_CLEAR_FEATURE 1u
#define USB_REQ_SET_FEATURE 3u
#define USB_DT_DEVICE 1u
#define USB_DT_CONFIG 2u
#define USB_DT_HUB 0x29u
#define USB_CLASS_AUDIO 1u
#define USB_CLASS_HUB 9u
#define USB_CLASS_HID 3u
#define USB_CLASS_MASS_STORAGE 8u
#define USB_CLASS_VIDEO 0x0Eu
#define USB_CLASS_VENDOR 0xFFu
#define USB_PORT_FEAT_RESET 4u
#define USB_PORT_FEAT_POWER 8u
#define USB_PORT_FEAT_C_RESET 20u
#define USB_PORT_FEAT_C_CONNECTION 16u
#define USB_PORTSTAT_CONNECTION 0x0001u
#define USB_PORTSTAT_LOWSPEED 0x0200u
#define USB_MAX_ENUM_DEPTH 2

typedef struct {
    int used;
    uint8_t bus;
    uint8_t dev;
    uint8_t fn;
    uint8_t prog_if;
    uint8_t irq_line;
    uint16_t vendor;
    uint16_t device;
    uint32_t bar0;
    uint32_t bar1;
    int kind; /* 1=UHCI, 2=OHCI, 3=EHCI, 4=XHCI */
    int active;
    int reserved;
    ehci_controller_t ehci;
    ohci_controller_t ohci;
    uhci_controller_t uhci;
    xhci_controller_t xhci;
    int mouse_ready;
    int mouse_low_speed;
    uint8_t mouse_addr;
    uint8_t mouse_iface;
    uint8_t mouse_ep;
    uint8_t mouse_report_len;
    uhci_intr_queue_t mouse_q;
    int keyboard_ready;
    int keyboard_low_speed;
    uint8_t keyboard_addr;
    uint8_t keyboard_iface;
    uint8_t keyboard_ep;
    uint8_t keyboard_report_len;
    uhci_intr_queue_t keyboard_q;
    input_device_description_t input_description[EDGE_INPUT_DEVICE_MAX];
} usb_controller_t;

static usb_controller_t g_usb_ctrls[8];
static int g_usb_ctrl_count;
static int g_usb_have_mouse;
static uint32_t g_usb_poll_ticks;
static uint8_t g_usb_next_addr = 1;
static int g_usb_primary_kind; /* 0=none,1=UHCI,4=XHCI */
static int g_usb_initialized;
static int usb_enumerate_uhci_addr(usb_controller_t *ctrl, int low_speed, uint8_t addr, int depth);

static uint8_t usb_alloc_addr(void) {
    if (g_usb_next_addr < 1) g_usb_next_addr = 1;
    if (g_usb_next_addr >= 127) return 0;
    return g_usb_next_addr++;
}

typedef struct __attribute__((packed)) {
    uint8_t bLength;
    uint8_t bDescriptorType;
    uint16_t bcdUSB;
    uint8_t bDeviceClass;
    uint8_t bDeviceSubClass;
    uint8_t bDeviceProtocol;
    uint8_t bMaxPacketSize0;
    uint16_t idVendor;
    uint16_t idProduct;
    uint16_t bcdDevice;
    uint8_t iManufacturer;
    uint8_t iProduct;
    uint8_t iSerialNumber;
    uint8_t bNumConfigurations;
} usb_dev_desc_t;

typedef struct __attribute__((packed)) {
    uint8_t bLength;
    uint8_t bDescriptorType;
    uint16_t wTotalLength;
    uint8_t bNumInterfaces;
    uint8_t bConfigurationValue;
    uint8_t iConfiguration;
    uint8_t bmAttributes;
    uint8_t bMaxPower;
} usb_cfg_desc_t;

typedef struct __attribute__((packed)) {
    uint8_t bLength;
    uint8_t bDescriptorType;
    uint8_t bInterfaceNumber;
    uint8_t bAlternateSetting;
    uint8_t bNumEndpoints;
    uint8_t bInterfaceClass;
    uint8_t bInterfaceSubClass;
    uint8_t bInterfaceProtocol;
    uint8_t iInterface;
} usb_if_desc_t;

typedef struct __attribute__((packed)) {
    uint8_t bLength;
    uint8_t bDescriptorType;
    uint8_t bEndpointAddress;
    uint8_t bmAttributes;
    uint16_t wMaxPacketSize;
    uint8_t bInterval;
} usb_ep_desc_t;

static int usb_uhci_ctrl_get_desc(uhci_controller_t *hc, int low_speed, uint8_t addr,
                                  uint8_t dtype, uint8_t dindex, void *buf, uint16_t len) {
    return uhci_control_transfer(hc, low_speed, addr, 0x80u, USB_REQ_GET_DESCRIPTOR,
                                 (uint16_t)(((uint16_t)dtype << 8) | dindex), 0,
                                 buf, len, 1);
}

static int usb_uhci_ctrl_set_address(uhci_controller_t *hc, int low_speed, uint8_t old_addr, uint8_t new_addr) {
    return uhci_control_transfer(hc, low_speed, old_addr, 0x00u, USB_REQ_SET_ADDRESS,
                                 new_addr, 0, 0, 0, 0);
}

static int usb_uhci_ctrl_set_config(uhci_controller_t *hc, int low_speed, uint8_t addr, uint8_t cfgval) {
    return uhci_control_transfer(hc, low_speed, addr, 0x00u, USB_REQ_SET_CONFIGURATION,
                                 cfgval, 0, 0, 0, 0);
}

static int usb_uhci_hub_port_req(uhci_controller_t *hc, int low_speed, uint8_t hub_addr,
                                 uint8_t bRequest, uint16_t wValue, uint16_t wIndex,
                                 void *buf, uint16_t len, int in_dir) {
    uint8_t bm = in_dir ? 0xA3u : 0x23u; /* class | other(port), dir */
    return uhci_control_transfer(hc, low_speed, hub_addr, bm, bRequest, wValue, wIndex, buf, len, in_dir);
}

static int usb_uhci_hub_port_status(uhci_controller_t *hc, int low_speed, uint8_t hub_addr,
                                    uint8_t port, uint16_t *status, uint16_t *change) {
    uint8_t st[4];
    if (!status || !change) return -1;
    memset(st, 0, sizeof(st));
    if (usb_uhci_hub_port_req(hc, low_speed, hub_addr, USB_REQ_GET_STATUS, 0, port, st, sizeof(st), 1) < 0) return -1;
    *status = (uint16_t)st[0] | ((uint16_t)st[1] << 8);
    *change = (uint16_t)st[2] | ((uint16_t)st[3] << 8);
    return 0;
}

static void usb_enumerate_uhci_hub_children(usb_controller_t *ctrl, int hub_low_speed, uint8_t hub_addr,
                                            uint8_t ports, int depth) {
    uhci_controller_t *hc;
    if (!ctrl || depth > USB_MAX_ENUM_DEPTH || ports == 0) return;
    hc = &ctrl->uhci;
    for (uint8_t p = 1; p <= ports; ++p) {
        uint16_t st = 0, ch = 0;
        uint8_t addr = 0;
        int child_low_speed = 0;

        (void)usb_uhci_hub_port_req(hc, hub_low_speed, hub_addr, USB_REQ_SET_FEATURE, USB_PORT_FEAT_POWER, p, 0, 0, 0);
        for (volatile int d = 0; d < 200000; ++d) { (void)d; }

        if (usb_uhci_hub_port_status(hc, hub_low_speed, hub_addr, p, &st, &ch) < 0) continue;
        if ((st & USB_PORTSTAT_CONNECTION) == 0) continue;

        (void)usb_uhci_hub_port_req(hc, hub_low_speed, hub_addr, USB_REQ_SET_FEATURE, USB_PORT_FEAT_RESET, p, 0, 0, 0);
        for (volatile int d = 0; d < 300000; ++d) { (void)d; }
        (void)usb_uhci_hub_port_req(hc, hub_low_speed, hub_addr, USB_REQ_CLEAR_FEATURE, USB_PORT_FEAT_C_RESET, p, 0, 0, 0);
        (void)usb_uhci_hub_port_req(hc, hub_low_speed, hub_addr, USB_REQ_CLEAR_FEATURE, USB_PORT_FEAT_C_CONNECTION, p, 0, 0, 0);

        if (usb_uhci_hub_port_status(hc, hub_low_speed, hub_addr, p, &st, &ch) < 0) continue;
        child_low_speed = (st & USB_PORTSTAT_LOWSPEED) ? 1 : 0;
        addr = usb_alloc_addr();
        if (addr == 0) {
            printf("[usb][hub] no free USB addresses for downstream device on port %u\n", (uint32_t)p);
            continue;
        }

        /* Enumeration always starts at address 0 before SET_ADDRESS. */
        {
            usb_dev_desc_t dd;
            memset(&dd, 0, sizeof(dd));
            if (usb_uhci_ctrl_get_desc(hc, child_low_speed, 0, USB_DT_DEVICE, 0, &dd, 8) < 0) {
                printf("[usb][hub] port%u GET_DESCRIPTOR(device,8) failed\n", (uint32_t)p);
                continue;
            }
            if (usb_uhci_ctrl_set_address(hc, child_low_speed, 0, addr) < 0) {
                printf("[usb][hub] port%u SET_ADDRESS %u failed\n", (uint32_t)p, (uint32_t)addr);
                continue;
            }
            for (volatile int d = 0; d < 200000; ++d) { (void)d; }
        }

        printf("[usb][hub] downstream port%u addr=%u speed=%s\n",
               (uint32_t)p, (uint32_t)addr, child_low_speed ? "low" : "full");
        (void)usb_enumerate_uhci_addr(ctrl, child_low_speed, addr, depth + 1);
    }
}

static const char *usb_class_driver_state(uint8_t cls, uint8_t subcls, uint8_t proto, const char **name_out) {
    (void)proto;
    switch (cls) {
    case USB_CLASS_HID:
        *name_out = "USB HID";
        return "supported";
    case USB_CLASS_HUB:
        *name_out = "USB hub";
        return "supported";
    case USB_CLASS_AUDIO:
        *name_out = "USB Audio Class";
        return "missing";
    case USB_CLASS_MASS_STORAGE:
        *name_out = "USB Mass Storage";
#ifdef CONFIG_USB_STORAGE
        return "supported";
#else
        return "missing";
#endif
    case USB_CLASS_VIDEO:
        *name_out = "USB Video Class";
#ifdef CONFIG_USB_UVC
        if (subcls == 1u || subcls == 2u) return "partial";
#endif
        return "missing";
    case USB_CLASS_VENDOR:
        *name_out = "USB vendor-specific device";
        return "partial";
    default:
        *name_out = "USB interface";
        return "missing";
    }
}

static void usb_log_interface_coverage(const char *hc_name, uint8_t addr, const usb_if_desc_t *id) {
    const char *name;
    const char *state;
    if (!id) return;
    state = usb_class_driver_state(id->bInterfaceClass, id->bInterfaceSubClass, id->bInterfaceProtocol, &name);
    printf("[usb][drv] %s addr=%u iface=%u class=%u/%u/%u %s: %s\n",
           hc_name ? hc_name : "usb", (uint32_t)addr, (uint32_t)id->bInterfaceNumber,
           (uint32_t)id->bInterfaceClass, (uint32_t)id->bInterfaceSubClass,
           (uint32_t)id->bInterfaceProtocol, state, name);
}

static void usb_parse_cfg_for_classes(const char *hc_name, uint8_t addr, const uint8_t *buf, uint16_t len,
                                      int *has_boot_keyboard, int *has_boot_mouse, int *has_hub_iface) {
    uint16_t off = 0;
    if (has_boot_keyboard) *has_boot_keyboard = 0;
    if (has_boot_mouse) *has_boot_mouse = 0;
    if (has_hub_iface) *has_hub_iface = 0;
    while (off + 2 <= len) {
        uint8_t dlen = buf[off];
        uint8_t dtype = buf[off + 1];
        if (dlen < 2) break;
        if (off + dlen > len) break;
        if (dtype == 4 && dlen >= sizeof(usb_if_desc_t)) {
            const usb_if_desc_t *id = (const usb_if_desc_t *)(buf + off);
            usb_log_interface_coverage(hc_name, addr, id);
            if (id->bInterfaceClass == USB_CLASS_HUB) {
                if (has_hub_iface) *has_hub_iface = 1;
            }
            if (id->bInterfaceClass == USB_CLASS_HID &&
                id->bInterfaceSubClass == 1 && id->bInterfaceProtocol == 1) {
                if (has_boot_keyboard) *has_boot_keyboard = 1;
            }
            if (id->bInterfaceClass == USB_CLASS_HID &&
                id->bInterfaceSubClass == 1 && id->bInterfaceProtocol == 2) {
                if (has_boot_mouse) *has_boot_mouse = 1;
            }
        }
        off += dlen;
    }
}

static int usb_find_boot_hid_ep(const uint8_t *buf, uint16_t len, uint8_t protocol,
                                uint8_t *iface_out, uint8_t *ep_out,
                                uint16_t *maxpkt_out, uint8_t *interval_out) {
    uint16_t off = 0;
    int in_boot_if = 0;
    uint8_t cur_if = 0;
    if (!buf) return -1;
    while (off + 2 <= len) {
        uint8_t dlen = buf[off];
        uint8_t dtype = buf[off + 1];
        if (dlen < 2 || off + dlen > len) break;
        if (dtype == 4 && dlen >= sizeof(usb_if_desc_t)) {
            const usb_if_desc_t *id = (const usb_if_desc_t *)(buf + off);
            cur_if = id->bInterfaceNumber;
            in_boot_if = (id->bInterfaceClass == USB_CLASS_HID &&
                          id->bInterfaceSubClass == 1 &&
                          id->bInterfaceProtocol == protocol);
        } else if (dtype == 5 && dlen >= sizeof(usb_ep_desc_t) && in_boot_if) {
            const usb_ep_desc_t *ed = (const usb_ep_desc_t *)(buf + off);
            if ((ed->bEndpointAddress & 0x80u) && ((ed->bmAttributes & 0x03u) == 0x03u)) {
                if (iface_out) *iface_out = cur_if;
                if (ep_out) *ep_out = ed->bEndpointAddress;
                if (maxpkt_out) *maxpkt_out = (uint16_t)(ed->wMaxPacketSize & 0x07FFu);
                if (interval_out) *interval_out = ed->bInterval;
                return 0;
            }
        }
        off += dlen;
    }
    return -1;
}

static int usb_find_boot_keyboard_ep(const uint8_t *buf, uint16_t len,
                                     uint8_t *iface_out, uint8_t *ep_out,
                                     uint16_t *maxpkt_out, uint8_t *interval_out) {
    return usb_find_boot_hid_ep(buf, len, 1u, iface_out, ep_out, maxpkt_out, interval_out);
}

static int usb_find_boot_mouse_ep(const uint8_t *buf, uint16_t len,
                                  uint8_t *iface_out, uint8_t *ep_out,
                                  uint16_t *maxpkt_out, uint8_t *interval_out) {
    return usb_find_boot_hid_ep(buf, len, 2u, iface_out, ep_out, maxpkt_out, interval_out);
}

static int usb_uhci_ctrl_set_protocol_boot(uhci_controller_t *hc, int low_speed, uint8_t addr, uint8_t iface_num) {
    /* HID class SET_PROTOCOL, wValue=0 => boot protocol */
    return uhci_control_transfer(hc, low_speed, addr, 0x21u, 0x0Bu, 0u, iface_num, 0, 0, 0);
}

static int usb_uhci_ctrl_set_idle(uhci_controller_t *hc, int low_speed, uint8_t addr, uint8_t iface_num,
                                  uint8_t duration, uint8_t report_id) {
    uint16_t wValue = (uint16_t)(((uint16_t)duration << 8) | report_id);
    return uhci_control_transfer(hc, low_speed, addr, 0x21u, USB_REQ_SET_IDLE, wValue, iface_num, 0, 0, 0);
}

static int usb_enumerate_uhci_addr(usb_controller_t *ctrl, int low_speed, uint8_t addr, int depth) {
    uhci_controller_t *hc;
    usb_dev_desc_t dd;
    uint8_t cfg_hdr[9];
    uint8_t cfg_buf[256];
    uint8_t hub_desc[16];
    int has_boot_keyboard = 0;
    int has_boot_mouse = 0;
    int has_hub_iface = 0;
    uint8_t keyboard_iface = 0, keyboard_ep = 0, keyboard_interval = 10;
    uint8_t mouse_iface = 0, mouse_ep = 0, mouse_interval = 10, hub_ports = 0;
    uint16_t keyboard_maxpkt = 0;
    uint16_t mouse_maxpkt = 0;
    uint16_t total;

    if (!ctrl) return -1;
    hc = &ctrl->uhci;
    if (!hc || !hc->used || addr == 0) return -1;

    memset(&dd, 0, sizeof(dd));
    if (usb_uhci_ctrl_get_desc(hc, low_speed, addr, USB_DT_DEVICE, 0, &dd, sizeof(dd)) < 0) {
        printf("[usb][uhci] addr=%u GET_DESCRIPTOR(device,18) failed\n", (uint32_t)addr);
        return -1;
    }
    printf("[usb][uhci] dev addr=%u vid=%04x pid=%04x class=%u/%u/%u cfgs=%u ep0=%u\n",
           (uint32_t)addr, (uint32_t)dd.idVendor, (uint32_t)dd.idProduct,
           (uint32_t)dd.bDeviceClass, (uint32_t)dd.bDeviceSubClass, (uint32_t)dd.bDeviceProtocol,
           (uint32_t)dd.bNumConfigurations, (uint32_t)dd.bMaxPacketSize0);

    memset(cfg_hdr, 0, sizeof(cfg_hdr));
    if (usb_uhci_ctrl_get_desc(hc, low_speed, addr, USB_DT_CONFIG, 0, cfg_hdr, sizeof(cfg_hdr)) < 0) {
        printf("[usb][uhci] addr=%u GET_DESCRIPTOR(config hdr) failed\n", (uint32_t)addr);
        return 0;
    }
    total = (uint16_t)cfg_hdr[2] | ((uint16_t)cfg_hdr[3] << 8);
    if (total > sizeof(cfg_buf)) total = sizeof(cfg_buf);
    if (total < sizeof(cfg_hdr)) total = sizeof(cfg_hdr);
    memset(cfg_buf, 0, sizeof(cfg_buf));
    if (usb_uhci_ctrl_get_desc(hc, low_speed, addr, USB_DT_CONFIG, 0, cfg_buf, total) < 0) {
        printf("[usb][uhci] addr=%u GET_DESCRIPTOR(config %u) failed\n", (uint32_t)addr, (uint32_t)total);
        return 0;
    }
    usb_parse_cfg_for_classes("uhci", addr, cfg_buf, total, &has_boot_keyboard, &has_boot_mouse, &has_hub_iface);
    (void)usb_find_boot_keyboard_ep(cfg_buf, total, &keyboard_iface, &keyboard_ep, &keyboard_maxpkt, &keyboard_interval);
    (void)usb_find_boot_mouse_ep(cfg_buf, total, &mouse_iface, &mouse_ep, &mouse_maxpkt, &mouse_interval);
    printf("[usb][uhci] config total=%u boot-keyboard=%d boot-mouse=%d hub-iface=%d\n",
           (uint32_t)total, has_boot_keyboard, has_boot_mouse, has_hub_iface);

    /* Configure the device (use first configuration) */
    if (cfg_buf[5] != 0) {
        if (usb_uhci_ctrl_set_config(hc, low_speed, addr, cfg_buf[5]) == 0) {
            printf("[usb][uhci] SET_CONFIGURATION %u ok\n", (uint32_t)cfg_buf[5]);
        } else {
            printf("[usb][uhci] SET_CONFIGURATION %u failed\n", (uint32_t)cfg_buf[5]);
        }
    }

    if (dd.bDeviceClass == USB_CLASS_HUB || has_hub_iface) {
        memset(hub_desc, 0, sizeof(hub_desc));
        if (uhci_control_transfer(hc, low_speed, addr, 0xA0u, USB_REQ_GET_DESCRIPTOR,
                                  (uint16_t)(USB_DT_HUB << 8), 0, hub_desc, 8, 1) == 0) {
            hub_ports = hub_desc[2];
            printf("[usb][hub] hub descriptor: ports=%u characteristics=0x%02x%02x\n",
                   (uint32_t)hub_desc[2], (uint32_t)hub_desc[4], (uint32_t)hub_desc[3]);
            if (depth < USB_MAX_ENUM_DEPTH) {
                usb_enumerate_uhci_hub_children(ctrl, low_speed, addr, hub_ports, depth + 1);
            }
        } else {
            printf("[usb][hub] GET_DESCRIPTOR(hub) failed\n");
        }
    }
    if (has_boot_keyboard && !ctrl->keyboard_ready) {
        (void)usb_uhci_ctrl_set_protocol_boot(hc, low_speed, addr, keyboard_iface);
        (void)usb_uhci_ctrl_set_idle(hc, low_speed, addr, keyboard_iface, 0, 0);
        if (keyboard_maxpkt == 0) keyboard_maxpkt = 8;
        if (keyboard_maxpkt > 8) keyboard_maxpkt = 8;
        printf("[usb][hid] boot keyboard iface=%u ep=0x%02x maxpkt=%u interval=%u\n",
               (uint32_t)keyboard_iface, (uint32_t)keyboard_ep,
               (uint32_t)keyboard_maxpkt, (uint32_t)keyboard_interval);
        if (uhci_intr_queue_open(hc, low_speed, addr, keyboard_ep, keyboard_maxpkt,
                                 keyboard_interval, &ctrl->keyboard_q) == 0) {
            input_device_description_t *description =
                &ctrl->input_description[EDGE_INPUT_KEYBOARD];
            ctrl->keyboard_ready = 1;
            ctrl->keyboard_low_speed = low_speed;
            ctrl->keyboard_addr = addr;
            ctrl->keyboard_iface = keyboard_iface;
            ctrl->keyboard_ep = keyboard_ep;
            ctrl->keyboard_report_len = (uint8_t)keyboard_maxpkt;
            input_device_describe_keyboard(
                description, "USB HID Keyboard", "usb-uhci/input0",
                "usbhid", 0x03u, dd.idVendor, dd.idProduct,
                dd.bcdDevice);
            (void)input_device_register(EDGE_INPUT_KEYBOARD, description,
                                        &ctrl->keyboard_q);
            printf("[usb][hid] keyboard queue armed ep=0x%02x interval=%u maxpkt=%u\n",
                   (uint32_t)keyboard_ep, (uint32_t)keyboard_interval, (uint32_t)keyboard_maxpkt);
        }
    }
    if (has_boot_mouse && !ctrl->mouse_ready) {
        (void)usb_uhci_ctrl_set_protocol_boot(hc, low_speed, addr, mouse_iface);
        (void)usb_uhci_ctrl_set_idle(hc, low_speed, addr, mouse_iface, 0, 0);
        if (mouse_maxpkt == 0) mouse_maxpkt = 8;
        if (mouse_maxpkt > 8) mouse_maxpkt = 8;
        printf("[usb][hid] boot mouse iface=%u ep=0x%02x maxpkt=%u interval=%u\n",
               (uint32_t)mouse_iface, (uint32_t)mouse_ep, (uint32_t)mouse_maxpkt, (uint32_t)mouse_interval);
        if (uhci_intr_queue_open(hc, low_speed, addr, mouse_ep, mouse_maxpkt, mouse_interval, &ctrl->mouse_q) == 0) {
            input_device_description_t *description =
                &ctrl->input_description[EDGE_INPUT_POINTER];
            ctrl->mouse_ready = 1;
            ctrl->mouse_low_speed = low_speed;
            ctrl->mouse_addr = addr;
            ctrl->mouse_iface = mouse_iface;
            ctrl->mouse_ep = mouse_ep;
            ctrl->mouse_report_len = (uint8_t)mouse_maxpkt;
            input_device_describe_pointer(
                description, "USB HID Mouse", "usb-uhci/input1",
                "usbhid", 0x03u, dd.idVendor, dd.idProduct,
                dd.bcdDevice, 0);
            (void)input_device_register(EDGE_INPUT_POINTER, description,
                                        &ctrl->mouse_q);
            printf("[usb][hid] mouse queue armed ep=0x%02x interval=%u maxpkt=%u\n",
                   (uint32_t)mouse_ep, (uint32_t)mouse_interval, (uint32_t)mouse_maxpkt);
        }
    }
    return 0;
}

static void __attribute__((unused)) usb_enumerate_uhci_root_ports(usb_controller_t *ctrl) {
    uhci_controller_t *hc;
    int found = 0;
    if (!ctrl) return;
    hc = &ctrl->uhci;
    for (int port = 0; port < 2; ++port) {
        int low_speed = 0;
        uint8_t addr = 0;
        usb_dev_desc_t dd;
        if (!uhci_port_connected(hc, port)) continue;
        found = 1;
        if (uhci_port_reset_enable(hc, port, &low_speed) < 0) {
            printf("[usb][uhci] port%d reset/enable failed\n", port + 1);
            continue;
        }
        printf("[usb][uhci] root-port%d device connected speed=%s\n",
               port + 1, low_speed ? "low" : "full");

        addr = usb_alloc_addr();
        if (addr == 0) {
            printf("[usb][uhci] out of USB addresses on root-port%d\n", port + 1);
            continue;
        }
        memset(&dd, 0, sizeof(dd));
        if (usb_uhci_ctrl_get_desc(hc, low_speed, 0, USB_DT_DEVICE, 0, &dd, 8) < 0) {
            printf("[usb][uhci] root-port%d GET_DESCRIPTOR(device,8) failed\n", port + 1);
            continue;
        }
        if (usb_uhci_ctrl_set_address(hc, low_speed, 0, addr) < 0) {
            printf("[usb][uhci] root-port%d SET_ADDRESS %u failed\n", port + 1, (uint32_t)addr);
            continue;
        }
        for (volatile int d = 0; d < 200000; ++d) { (void)d; }
        (void)usb_enumerate_uhci_addr(ctrl, low_speed, addr, 0);
    }
    if (!found) printf("[usb][uhci] no device on root ports\n");
}

void usb_hid_process_boot_report(const uint8_t *report, uint16_t n) {
    uint8_t buttons;
    int8_t dx, dy, wheel = 0;
    int wheel_present = 0;
    if (!report || n < 3) return;
    /*
     * HID boot mouse protocol is fixed-format and has no report ID:
     * byte0=buttons, byte1=X, byte2=Y, optional byte3=wheel.  The previous
     * heuristic treated some 4-byte QEMU reports as report-ID-prefixed and
     * shifted the packet by one byte, so X saw movement as random button state
     * or no useful pointer motion.  Keep report-ID handling out of the boot
     * path; non-boot HID reports need a descriptor parser, not guessing here.
     */
    buttons = report[0] & 0x07u;
    dx = (int8_t)report[1];
    dy = (int8_t)report[2];
    if (n >= 4) {
        wheel = (int8_t)report[3];
        wheel_present = 1;
    }
    usb_hid_mouse_report_boot(dx, dy, wheel, buttons, wheel_present);
}

static uint8_t usb_hid_usage_to_set1(uint8_t usage) {
    static const uint8_t alpha[] = {
        SCAN_CODE_KEY_A, SCAN_CODE_KEY_B, SCAN_CODE_KEY_C, SCAN_CODE_KEY_D,
        SCAN_CODE_KEY_E, SCAN_CODE_KEY_F, SCAN_CODE_KEY_G, SCAN_CODE_KEY_H,
        SCAN_CODE_KEY_I, SCAN_CODE_KEY_J, SCAN_CODE_KEY_K, SCAN_CODE_KEY_L,
        SCAN_CODE_KEY_M, SCAN_CODE_KEY_N, SCAN_CODE_KEY_O, SCAN_CODE_KEY_P,
        SCAN_CODE_KEY_Q, SCAN_CODE_KEY_R, SCAN_CODE_KEY_S, SCAN_CODE_KEY_T,
        SCAN_CODE_KEY_U, SCAN_CODE_KEY_V, SCAN_CODE_KEY_W, SCAN_CODE_KEY_X,
        SCAN_CODE_KEY_Y, SCAN_CODE_KEY_Z
    };
    static const uint8_t digits[] = {
        SCAN_CODE_KEY_1, SCAN_CODE_KEY_2, SCAN_CODE_KEY_3, SCAN_CODE_KEY_4,
        SCAN_CODE_KEY_5, SCAN_CODE_KEY_6, SCAN_CODE_KEY_7, SCAN_CODE_KEY_8,
        SCAN_CODE_KEY_9, SCAN_CODE_KEY_0
    };
    if (usage >= 0x04u && usage <= 0x1Du) return alpha[usage - 0x04u];
    if (usage >= 0x1Eu && usage <= 0x27u) return digits[usage - 0x1Eu];
    if (usage >= 0x3Au && usage <= 0x43u) return (uint8_t)(SCAN_CODE_KEY_F1 + (usage - 0x3Au));
    switch (usage) {
    case 0x28: return SCAN_CODE_KEY_ENTER;
    case 0x29: return SCAN_CODE_KEY_ESC;
    case 0x2A: return SCAN_CODE_KEY_BACKSPACE;
    case 0x2B: return SCAN_CODE_KEY_TAB;
    case 0x2C: return SCAN_CODE_KEY_SPACE;
    case 0x2D: return SCAN_CODE_KEY_MINUS;
    case 0x2E: return SCAN_CODE_KEY_EQUAL;
    case 0x2F: return SCAN_CODE_KEY_SQUARE_OPEN_BRACKET;
    case 0x30: return SCAN_CODE_KEY_SQUARE_CLOSE_BRACKET;
    case 0x31: return SCAN_CODE_KEY_BACKSLASH;
    case 0x33: return SCAN_CODE_KEY_SEMICOLON;
    case 0x34: return SCAN_CODE_KEY_SINGLE_QUOTE;
    case 0x35: return SCAN_CODE_KEY_ACUTE;
    case 0x36: return SCAN_CODE_KEY_COMMA;
    case 0x37: return SCAN_CODE_KEY_DOT;
    case 0x38: return SCAN_CODE_KEY_FORESLHASH;
    case 0x39: return SCAN_CODE_KEY_CAPS_LOCK;
    case 0x4A: return SCAN_CODE_KEY_HOME;
    case 0x4B: return SCAN_CODE_KEY_PAGE_UP;
    case 0x4C: return SCAN_CODE_KEY_DELETE;
    case 0x4D: return SCAN_CODE_KEY_END;
    case 0x4E: return SCAN_CODE_KEY_PAGE_DOWN;
    case 0x4F: return SCAN_CODE_KEY_RIGHT;
    case 0x50: return SCAN_CODE_KEY_LEFT;
    case 0x51: return SCAN_CODE_KEY_DOWN;
    case 0x52: return SCAN_CODE_KEY_UP;
    default: return 0;
    }
}

static int usb_hid_usage_needs_set1_e0(uint8_t usage) {
    /*
     * USB HID boot keyboards report navigation keys as usages, while the
     * console decoder below expects the legacy set-1 extended sequence
     * E0 xx.  QEMU's usb-kbd is what the VMM exposes, so keep the conversion
     * here instead of teaching every tty/evdev consumer about USB usages.
     */
    return usage >= 0x4Au && usage <= 0x52u;
}

static void usb_hid_emit_usage_scancode(uint8_t usage, uint8_t sc, int pressed) {
    if (!sc) return;
    if (usb_hid_usage_needs_set1_e0(usage)) keyboard_emit_scancode(0xE0u);
    keyboard_emit_scancode(pressed ? sc : (uint8_t)(sc | 0x80u));
}

void usb_hid_process_boot_keyboard_report(const uint8_t *report, uint16_t n) {
    static uint8_t prev_mods;
    static uint8_t prev_keys[6];
    static uint32_t kbd_report_debug_budget = 0;
    uint8_t mods;
    uint8_t keys[6];
    if (!report || n < 8) return;
    mods = report[0];
    memcpy(keys, report + 2, sizeof(keys));
    if (kbd_report_debug_budget) {
        printf("[usb][hid-kbd] n=%u mods=0x%x keys=%02x %02x %02x %02x %02x %02x prev=%02x %02x %02x %02x %02x %02x\n",
               (uint32_t)n, (uint32_t)mods,
               (uint32_t)keys[0], (uint32_t)keys[1], (uint32_t)keys[2],
               (uint32_t)keys[3], (uint32_t)keys[4], (uint32_t)keys[5],
               (uint32_t)prev_keys[0], (uint32_t)prev_keys[1], (uint32_t)prev_keys[2],
               (uint32_t)prev_keys[3], (uint32_t)prev_keys[4], (uint32_t)prev_keys[5]);
        kbd_report_debug_budget--;
    }

    {
        static const uint8_t mod_scans[8] = {
            SCAN_CODE_KEY_LEFT_CTRL, SCAN_CODE_KEY_LEFT_SHIFT, SCAN_CODE_KEY_ALT, 0,
            SCAN_CODE_KEY_RIGHT_CTRL, SCAN_CODE_KEY_RIGHT_SHIFT, SCAN_CODE_KEY_ALT, 0
        };
        for (int i = 0; i < 8; ++i) {
            uint8_t mask = (uint8_t)(1u << i);
            uint8_t sc = mod_scans[i];
            if (!sc || ((mods ^ prev_mods) & mask) == 0) continue;
            keyboard_emit_scancode((mods & mask) ? sc : (uint8_t)(sc | 0x80u));
        }
    }

    for (int i = 0; i < 6; ++i) {
        uint8_t old_usage = prev_keys[i];
        uint8_t sc;
        int still_down = 0;
        if (!old_usage) continue;
        for (int j = 0; j < 6; ++j) {
            if (keys[j] == old_usage) {
                still_down = 1;
                break;
            }
        }
        if (!still_down) {
            sc = usb_hid_usage_to_set1(old_usage);
            usb_hid_emit_usage_scancode(old_usage, sc, 0);
        }
    }

    for (int i = 0; i < 6; ++i) {
        uint8_t usage = keys[i];
        uint8_t sc;
        int was_down = 0;
        if (!usage || usage == 1u) continue;
        for (int j = 0; j < 6; ++j) {
            if (prev_keys[j] == usage) {
                was_down = 1;
                break;
            }
        }
        if (!was_down) {
            sc = usb_hid_usage_to_set1(usage);
            usb_hid_emit_usage_scancode(usage, sc, 1);
        }
    }

    prev_mods = mods;
    memcpy(prev_keys, keys, sizeof(prev_keys));
}

static void __attribute__((unused)) usb_poll_mouse_queues(void) {
    uint8_t report[16];
    uint16_t n = 0;
    for (int i = 0; i < g_usb_ctrl_count; ++i) {
        usb_controller_t *c = &g_usb_ctrls[i];
        if (!c->used || c->kind != 1 || !c->mouse_ready) continue;
        if (uhci_intr_queue_poll(&c->uhci, &c->mouse_q, report, sizeof(report), &n) <= 0) continue;
        usb_hid_process_boot_report(report, n);
    }
}

static void __attribute__((unused)) usb_poll_keyboard_queues(void) {
    uint8_t report[8];
    uint16_t n = 0;
    for (int i = 0; i < g_usb_ctrl_count; ++i) {
        usb_controller_t *c = &g_usb_ctrls[i];
        if (!c->used || c->kind != 1 || !c->keyboard_ready) continue;
        if (uhci_intr_queue_poll(&c->uhci, &c->keyboard_q, report, sizeof(report), &n) <= 0) continue;
        usb_hid_process_boot_keyboard_report(report, n);
    }
}

static __attribute__((unused)) const char *usb_prog_if_name(uint8_t p) {
    switch (p) {
        case USB_PROGIF_UHCI: return "UHCI";
        case USB_PROGIF_OHCI: return "OHCI";
        case USB_PROGIF_EHCI: return "EHCI";
        case USB_PROGIF_XHCI: return "XHCI";
        default: return "USB?";
    }
}

static int usb_prog_if_kind(uint8_t p) {
    switch (p) {
        case USB_PROGIF_UHCI: return 1;
        case USB_PROGIF_OHCI: return 2;
        case USB_PROGIF_EHCI: return 3;
        case USB_PROGIF_XHCI: return 4;
        default: return 0;
    }
}

static uint32_t usb_pci_pick_io_bar(uint8_t bus, uint8_t dev, uint8_t fn) {
    for (uint8_t off = 0x10; off <= 0x24; off += 4) {
        uint32_t bar = pci_cfg_read32(bus, dev, fn, off);
        if ((bar & 1u) && (bar & ~0x3u)) return bar;
    }
    return 0;
}

static void usb_try_xhci_companion_handoff(const usb_controller_t *c) {
    uint32_t usb2_mask, usb3_mask;
    uint32_t usb2_before, usb3_before;
    if (!c || c->kind != 4) return;
    /* Intel-style optional routing registers:
     * 0xD4 USB2PRM (mask), 0xD0 XUSB2PR (route to xHCI)
     * 0xDC USB3PRM (mask), 0xD8 USB3_PSSEN (enable/route to xHCI)
     */
    usb2_mask = pci_cfg_read32(c->bus, c->dev, c->fn, 0xD4);
    usb3_mask = pci_cfg_read32(c->bus, c->dev, c->fn, 0xDC);
    usb2_before = pci_cfg_read32(c->bus, c->dev, c->fn, 0xD0);
    usb3_before = pci_cfg_read32(c->bus, c->dev, c->fn, 0xD8);

    if (usb2_mask != 0 && usb2_mask != 0xFFFFFFFFu) {
        pci_cfg_write32(c->bus, c->dev, c->fn, 0xD0, usb2_mask);
    }
    if (usb3_mask != 0 && usb3_mask != 0xFFFFFFFFu) {
        pci_cfg_write32(c->bus, c->dev, c->fn, 0xD8, usb3_mask);
    }

    if ((usb2_mask != 0 && usb2_mask != 0xFFFFFFFFu) ||
        (usb3_mask != 0 && usb3_mask != 0xFFFFFFFFu)) {
        printf("[usb][xhci] companion handoff usb2: 0x%x->0x%x (mask=0x%x) usb3: 0x%x->0x%x (mask=0x%x)\n",
               usb2_before, pci_cfg_read32(c->bus, c->dev, c->fn, 0xD0), usb2_mask,
               usb3_before, pci_cfg_read32(c->bus, c->dev, c->fn, 0xD8), usb3_mask);
    }
}

static int usb_activate_controller(usb_controller_t *c) {
    if (!c || !c->used) return 0;
    if (c->reserved) return 0;
    if (c->active) return 1;
    c->active = 1;
    if (c->kind == 4) {
#ifndef CONFIG_USB_XHCI
        printf("[usb][xhci] controller present but xHCI driver disabled by CONFIG_USB_XHCI\n");
        c->active = 0;
        return 0;
#else
        usb_try_xhci_companion_handoff(c);
        if (xhci_init_controller(&c->xhci, c->bus, c->dev, c->fn,
                                 c->vendor, c->device, c->bar0, c->bar1, c->irq_line) < 0) {
            printf("[usb][xhci] init failed for %u:%u.%u\n",
                   (uint32_t)c->bus, (uint32_t)c->dev, (uint32_t)c->fn);
            c->active = 0;
            return 0;
        }
        return 1;
#endif
    }
    if (c->kind == 1) {
#ifndef CONFIG_USB_UHCI
        printf("[usb][uhci] controller present but UHCI driver disabled by CONFIG_USB_UHCI\n");
        c->active = 0;
        return 0;
#else
        if (uhci_init_controller(&c->uhci, c->bus, c->dev, c->fn,
                                 c->vendor, c->device, c->bar0, c->irq_line) < 0) {
            printf("[usb][uhci] init failed for %u:%u.%u\n",
                   (uint32_t)c->bus, (uint32_t)c->dev, (uint32_t)c->fn);
            c->active = 0;
            return 0;
        }
        usb_enumerate_uhci_root_ports(c);
        return 1;
#endif
    }
    if (c->kind == 3) {
#ifndef CONFIG_USB_EHCI
        printf("[usb][ehci] controller present but EHCI driver disabled by CONFIG_USB_EHCI\n");
        c->active = 0;
        return 0;
#else
        if (ehci_init_controller(&c->ehci, c->bus, c->dev, c->fn,
                                 c->vendor, c->device, c->bar0, c->irq_line) < 0) {
            printf("[usb][ehci] init failed for %u:%u.%u\n",
                   (uint32_t)c->bus, (uint32_t)c->dev, (uint32_t)c->fn);
            c->active = 0;
            return 0;
        }
        printf("[usb][ehci] transfer scheduler not wired yet; companion/full driver handles HID/storage when present\n");
        return 1;
#endif
    }
    if (c->kind == 2) {
#ifndef CONFIG_USB_OHCI
        printf("[usb][ohci] controller present but OHCI driver disabled by CONFIG_USB_OHCI\n");
        c->active = 0;
        return 0;
#else
        if (ohci_init_controller(&c->ohci, c->bus, c->dev, c->fn,
                                 c->vendor, c->device, c->bar0, c->irq_line) < 0) {
            printf("[usb][ohci] init failed for %u:%u.%u\n",
                   (uint32_t)c->bus, (uint32_t)c->dev, (uint32_t)c->fn);
            c->active = 0;
            return 0;
        }
        printf("[usb][ohci] transfer scheduler not wired yet; UHCI/xHCI handle HID/storage when present\n");
        return 1;
#endif
    }
    c->active = 0;
    return 0;
}

static void usb_discover_boot_input(void) {
    const uint64_t timeout_us = 2000000u;
    uint64_t start_us;

    if (g_usb_primary_kind != 4 || input_device_count() >= 2u) return;

    /*
     * Root-hub connection state may become visible only after an xHCI
     * controller has returned from its start sequence.  Discover fixed boot
     * input before launching userspace so devtmpfs, udev, and Xorg observe a
     * stable device set.  This loop is bounded and runs with interrupts
     * enabled; command and transfer completions are therefore handled with
     * the same process-context rules as later hotplug work.
     */
    start_us = boottime_monotonic_us();
    do {
        for (int i = 0; i < g_usb_ctrl_count; ++i) {
            if (!g_usb_ctrls[i].used || !g_usb_ctrls[i].active ||
                g_usb_ctrls[i].kind != 4) continue;
            g_usb_ctrls[i].xhci.port_poll_countdown = 0;
            xhci_poll_controller(&g_usb_ctrls[i].xhci);
        }
        if (input_device_count() >= 2u) break;
        __asm__ __volatile__("sti; hlt" ::: "memory");
    } while (boottime_monotonic_us() - start_us < timeout_us);

    if (input_device_count() != 0u) {
        printf("[usb] boot input discovery registered %u device(s)\n",
               input_device_count());
    } else {
        for (int i = 0; i < g_usb_ctrl_count; ++i) {
            if (g_usb_ctrls[i].used && g_usb_ctrls[i].active &&
                g_usb_ctrls[i].kind == 4)
                xhci_debug_dump(&g_usb_ctrls[i].xhci);
        }
    }
}

static usb_handoff_location_t
usb_controller_location(const usb_controller_t *controller)
{
    return (usb_handoff_location_t){
        .domain = 0,
        .bus = controller->bus,
        .slot = controller->dev,
        .function = controller->fn,
    };
}

static void
usb_refresh_primary_kind(void)
{
    g_usb_primary_kind = 0;
    for (int index = 0; index < g_usb_ctrl_count; ++index) {
        if (g_usb_ctrls[index].used && g_usb_ctrls[index].active &&
            g_usb_ctrls[index].kind == 4) {
            g_usb_primary_kind = 4;
            return;
        }
    }
    for (int index = 0; index < g_usb_ctrl_count; ++index) {
        if (g_usb_ctrls[index].used && g_usb_ctrls[index].active &&
            g_usb_ctrls[index].kind == 1) {
            g_usb_primary_kind = 1;
            return;
        }
    }
}

static int
usb_native_handoff_prepare(void *opaque_controller)
{
    usb_controller_t *controller = opaque_controller;

    if (!controller || !controller->used)
        return 19;
    if (controller->active)
        return 16;
    controller->reserved = 1;
    return 0;
}

static int
usb_native_handoff_restore(void *opaque_controller)
{
    usb_controller_t *controller = opaque_controller;

    if (!controller || !controller->used)
        return 19;
    if (controller->active) {
        controller->reserved = 0;
        return 0;
    }
    controller->reserved = 0;
    if (!usb_activate_controller(controller))
        return 5;
    usb_refresh_primary_kind();
    if (controller->kind == 4)
        usb_discover_boot_input();
    return 0;
}

static void usb_register_controller(uint8_t bus, uint8_t dev, uint8_t fn) {
    usb_controller_t *c;
    usb_handoff_location_t location;
    int handoff_error;

    if (g_usb_ctrl_count >= (int)(sizeof(g_usb_ctrls) / sizeof(g_usb_ctrls[0]))) return;
    c = &g_usb_ctrls[g_usb_ctrl_count++];
    memset(c, 0, sizeof(*c));
    c->used = 1;
    c->bus = bus;
    c->dev = dev;
    c->fn = fn;
    c->vendor = pci_cfg_read16(bus, dev, fn, 0x00);
    c->device = pci_cfg_read16(bus, dev, fn, 0x02);
    c->prog_if = pci_cfg_read8(bus, dev, fn, 0x09);
    c->irq_line = pci_cfg_read8(bus, dev, fn, 0x3C);
    c->bar0 = pci_cfg_read32(bus, dev, fn, 0x10);
    c->bar1 = pci_cfg_read32(bus, dev, fn, 0x14);
    c->kind = usb_prog_if_kind(c->prog_if);
    location = usb_controller_location(c);
    c->reserved = usb_handoff_location_reserved(&location);
    handoff_error = usb_handoff_controller_register(
        &location, usb_native_handoff_prepare,
        usb_native_handoff_restore, c);
    if (handoff_error != 0) {
        printf("[usb] controller ownership registration failed for "
               "%u:%u.%u: %d\n",
               (uint32_t)bus, (uint32_t)dev, (uint32_t)fn,
               handoff_error);
    }
    if (c->kind == 1) {
        c->bar0 = usb_pci_pick_io_bar(bus, dev, fn);
        if (!c->reserved) {
            uint16_t cmd = pci_cfg_read16(bus, dev, fn, 0x04);
            cmd |= 0x0001u; /* I/O space */
            cmd |= 0x0004u; /* bus master */
            pci_cfg_write16(bus, dev, fn, 0x04, cmd);
        }
    } else if (!c->reserved &&
               (c->kind == 2 || c->kind == 3 || c->kind == 4)) {
        uint16_t cmd = pci_cfg_read16(bus, dev, fn, 0x04);
        cmd |= 0x0002u; /* memory space */
        cmd |= 0x0004u; /* bus master */
        pci_cfg_write16(bus, dev, fn, 0x04, cmd);
    }

    printf("[usb] controller %s at %u:%u.%u ven=%04x dev=%04x irq=%u bar0=0x%x\n",
           (c->kind == 4) ? "XHCI" : "LEGACY-USB",
           (uint32_t)bus, (uint32_t)dev, (uint32_t)fn,
           (uint32_t)c->vendor, (uint32_t)c->device,
           (uint32_t)c->irq_line, c->bar0);
    if (c->reserved)
        printf("[usb] controller %u:%u.%u reserved for BSD bridge\n",
               (uint32_t)bus, (uint32_t)dev, (uint32_t)fn);
}

static void usb_scan_pci(void) {
    for (uint16_t bus = 0; bus < 256; ++bus) {
        for (uint8_t dev = 0; dev < 32; ++dev) {
            for (uint8_t fn = 0; fn < 8; ++fn) {
                uint16_t ven = pci_cfg_read16((uint8_t)bus, dev, fn, 0x00);
                uint8_t cls, sub;
                if (ven == 0xFFFFu) {
                    if (fn == 0) break;
                    continue;
                }
                cls = pci_cfg_read8((uint8_t)bus, dev, fn, 0x0B);
                sub = pci_cfg_read8((uint8_t)bus, dev, fn, 0x0A);
                if (cls == USB_PCI_CLASS_SERIAL && sub == USB_PCI_SUBCLASS_USB) {
                    usb_register_controller((uint8_t)bus, dev, fn);
                }
                if (fn == 0) {
                    uint8_t hdr = pci_cfg_read8((uint8_t)bus, dev, fn, 0x0E);
                    if ((hdr & 0x80u) == 0) break;
                }
            }
        }
    }
}

void usb_init(void) {
    int have_xhci = 0;
    int xhci_ok = 0;
    int fallback_ok = 0;
    if (g_usb_initialized) return;
    g_usb_initialized = 1;
    g_usb_ctrl_count = 0;
    g_usb_have_mouse = 0;
    g_usb_poll_ticks = 0;
    g_usb_next_addr = 1;
    g_usb_primary_kind = 0;
    memset(g_usb_ctrls, 0, sizeof(g_usb_ctrls));
    usb_dma_init();
    usb_scan_pci();
    for (int i = 0; i < g_usb_ctrl_count; ++i) {
        if (g_usb_ctrls[i].used && !g_usb_ctrls[i].reserved &&
            g_usb_ctrls[i].kind == 4) {
            have_xhci = 1;
            printf("[usb] discovered xHCI controller at %u:%u.%u\n",
                   (uint32_t)g_usb_ctrls[i].bus, (uint32_t)g_usb_ctrls[i].dev, (uint32_t)g_usb_ctrls[i].fn);
        }
    }
    if (have_xhci) {
        for (int i = 0; i < g_usb_ctrl_count; ++i) {
            if (g_usb_ctrls[i].used && !g_usb_ctrls[i].reserved &&
                g_usb_ctrls[i].kind == 4) {
                if (usb_activate_controller(&g_usb_ctrls[i])) xhci_ok = 1;
            }
        }
        if (xhci_ok) {
            g_usb_primary_kind = 4;
            printf("[usb] using xHCI as primary controller\n");
            usb_discover_boot_input();
        } else {
            printf("[usb] xHCI init failed, using fallback controller\n");
        }
    } else {
        printf("[usb] xHCI not present, falling back to EHCI/UHCI/OHCI\n");
    }

    if (!xhci_ok) {
        /*
         * Bring up EHCI first for ownership handoff and high-speed root-hub
         * state, but do not treat it as a Linux-visible primary data path
         * until EHCI queue transfer support is wired into enumeration.
         * UHCI remains the only legacy controller with HID transfers today;
         * OHCI is still initialized so real hardware is quiesced and ports
         * are powered, but it must not create fake HID/storage success.
         */
        for (int pass = 0; pass < 3 && !fallback_ok; ++pass) {
            int want_kind = (pass == 0) ? 3 : ((pass == 1) ? 1 : 2);
            for (int i = 0; i < g_usb_ctrl_count; ++i) {
                if (!g_usb_ctrls[i].used || g_usb_ctrls[i].reserved ||
                    g_usb_ctrls[i].kind != want_kind) continue;
                if (usb_activate_controller(&g_usb_ctrls[i])) {
                    if (want_kind == 1) {
                        fallback_ok = 1;
                        g_usb_primary_kind = want_kind;
                        break;
                    }
                }
            }
        }
    } else if (!g_usb_have_mouse) {
        /* Compatibility fallback only when needed for HID in mixed environments. */
        for (int i = 0; i < g_usb_ctrl_count; ++i) {
            if (!g_usb_ctrls[i].used || g_usb_ctrls[i].reserved ||
                g_usb_ctrls[i].kind != 1) continue;
            if (usb_activate_controller(&g_usb_ctrls[i])) {
                fallback_ok = 1;
                printf("[usb] xHCI active but enabling UHCI compatibility fallback for HID\n");
            }
        }
    }

    if (g_usb_ctrl_count == 0) {
        printf("[usb] no PCI USB host controllers found\n");
    } else {
        if (g_usb_primary_kind == 4) {
            printf("[usb] found %d controller(s), primary=xHCI\n", g_usb_ctrl_count);
        } else if (g_usb_primary_kind == 1) {
            printf("[usb] using UHCI as primary controller\n");
        } else {
            printf("[usb] found %d controller(s), initialized non-primary legacy controller(s); no transfer-capable primary\n",
                   g_usb_ctrl_count);
        }
        (void)fallback_ok;
    }
}

#ifdef CONFIG_USB_STORAGE
typedef struct {
    int used;
    int ctrl_index;
    uint8_t slot_id;
} usb_storage_block_ctx_t;

static usb_storage_block_ctx_t g_usb_storage_ctx[4];

static int usb_storage_ctx_used(int ctrl_index, uint8_t slot_id) {
    for (uint32_t c = 0; c < sizeof(g_usb_storage_ctx) / sizeof(g_usb_storage_ctx[0]); ++c) {
        if (g_usb_storage_ctx[c].used &&
            g_usb_storage_ctx[c].ctrl_index == ctrl_index &&
            g_usb_storage_ctx[c].slot_id == slot_id) return 1;
    }
    return 0;
}

static int usb_storage_read_ops(block_device_t *dev, uint32_t lba, uint32_t count, void *out) {
    usb_storage_block_ctx_t *ctx = dev ? (usb_storage_block_ctx_t *)dev->ctx : 0;
    if (!ctx || !ctx->used || ctx->ctrl_index < 0 || ctx->ctrl_index >= g_usb_ctrl_count) return -1;
    if (g_usb_ctrls[ctx->ctrl_index].kind != 4) return -1;
    return xhci_storage_read(&g_usb_ctrls[ctx->ctrl_index].xhci, ctx->slot_id, dev->start_lba + lba, count, out);
}

static int usb_storage_write_ops(block_device_t *dev, uint32_t lba, uint32_t count, const void *in) {
    usb_storage_block_ctx_t *ctx = dev ? (usb_storage_block_ctx_t *)dev->ctx : 0;
    if (!ctx || !ctx->used || ctx->ctrl_index < 0 || ctx->ctrl_index >= g_usb_ctrl_count) return -1;
    if (g_usb_ctrls[ctx->ctrl_index].kind != 4) return -1;
    return xhci_storage_write(&g_usb_ctrls[ctx->ctrl_index].xhci, ctx->slot_id, dev->start_lba + lba, count, in);
}

int usb_storage_register_block_if_present(const char *name) {
    block_ops_t ops = {usb_storage_read_ops, usb_storage_write_ops};
    if (!name || block_find(name)) return -1;
    usb_init();
    for (int i = 0; i < g_usb_ctrl_count; ++i) {
        if (!g_usb_ctrls[i].used || !g_usb_ctrls[i].active || g_usb_ctrls[i].kind != 4) continue;
        for (uint8_t slot = 1; slot <= XHCI_MAX_TRACKED_SLOTS; ++slot) {
            if (!xhci_storage_present(&g_usb_ctrls[i].xhci, slot)) continue;
            if (usb_storage_ctx_used(i, slot)) continue;
            for (uint32_t c = 0; c < sizeof(g_usb_storage_ctx) / sizeof(g_usb_storage_ctx[0]); ++c) {
                if (g_usb_storage_ctx[c].used) continue;
                g_usb_storage_ctx[c].used = 1;
                g_usb_storage_ctx[c].ctrl_index = i;
                g_usb_storage_ctx[c].slot_id = slot;
                if (block_register(name,
                                   xhci_storage_sector_size(&g_usb_ctrls[i].xhci, slot),
                                   xhci_storage_sector_count(&g_usb_ctrls[i].xhci, slot),
                                   0, &g_usb_storage_ctx[c], ops) < 0) {
                    g_usb_storage_ctx[c].used = 0;
                    return -1;
                }
                printf("[usb-storage] registered /dev/%s from xHCI slot=%u sectors=%u sector_size=%u\n",
                       name, (uint32_t)slot,
                       xhci_storage_sector_count(&g_usb_ctrls[i].xhci, slot),
                       xhci_storage_sector_size(&g_usb_ctrls[i].xhci, slot));
                return 0;
            }
        }
    }
    return -1;
}
#else
int usb_storage_register_block_if_present(const char *name) {
    (void)name;
    return -1;
}
#endif

void usb_poll(void) {
    if (++g_usb_poll_ticks == 0) g_usb_poll_ticks = 1;
    for (int i = 0; i < g_usb_ctrl_count; ++i) {
        if (!g_usb_ctrls[i].used || !g_usb_ctrls[i].active) continue;
        if (g_usb_ctrls[i].kind == 1) uhci_poll_controller(&g_usb_ctrls[i].uhci);
        if (g_usb_ctrls[i].kind == 2) ohci_poll_controller(&g_usb_ctrls[i].ohci);
        if (g_usb_ctrls[i].kind == 3) ehci_poll_controller(&g_usb_ctrls[i].ehci);
        if (g_usb_ctrls[i].kind == 4) xhci_poll_controller(&g_usb_ctrls[i].xhci);
    }
    usb_poll_keyboard_queues();
    usb_poll_mouse_queues();
    (void)g_usb_have_mouse;
}

void usb_poll_irq(void) {
    if (++g_usb_poll_ticks == 0) g_usb_poll_ticks = 1;
    for (int i = 0; i < g_usb_ctrl_count; ++i) {
        if (!g_usb_ctrls[i].used || !g_usb_ctrls[i].active) continue;
        if (g_usb_ctrls[i].kind == 1)
            uhci_poll_controller(&g_usb_ctrls[i].uhci);
        if (g_usb_ctrls[i].kind == 2)
            ohci_poll_controller(&g_usb_ctrls[i].ohci);
        if (g_usb_ctrls[i].kind == 3)
            ehci_poll_controller(&g_usb_ctrls[i].ehci);
        if (g_usb_ctrls[i].kind == 4)
            xhci_poll_controller_events(&g_usb_ctrls[i].xhci);
    }
    usb_poll_keyboard_queues();
    usb_poll_mouse_queues();
}

int usb_present_mouse(void) {
    return g_usb_have_mouse;
}

static int usb_snap_append_char(char *buf, uint32_t max, uint32_t *off, char c) {
    if (!buf || !off || *off + 1u >= max) return -1;
    buf[(*off)++] = c;
    buf[*off] = 0;
    return 0;
}

static int usb_snap_append_lit(char *buf, uint32_t max, uint32_t *off, const char *s) {
    if (!s) return -1;
    while (*s) {
        if (usb_snap_append_char(buf, max, off, *s++) < 0) return -1;
    }
    return 0;
}

static int usb_snap_append_u32(char *buf, uint32_t max, uint32_t *off, uint32_t v) {
    char tmp[11];
    int n = 0;
    if (v == 0) return usb_snap_append_char(buf, max, off, '0');
    while (v && n < (int)sizeof(tmp)) {
        tmp[n++] = (char)('0' + (v % 10u));
        v /= 10u;
    }
    while (n > 0) {
        if (usb_snap_append_char(buf, max, off, tmp[--n]) < 0) return -1;
    }
    return 0;
}

static int usb_snap_append_hex(char *buf, uint32_t max, uint32_t *off, uint32_t v, uint32_t digits) {
    static const char hx[] = "0123456789abcdef";
    if (digits > 8) digits = 8;
    for (int i = (int)digits - 1; i >= 0; --i) {
        if (usb_snap_append_char(buf, max, off, hx[(v >> ((uint32_t)i * 4u)) & 0xFu]) < 0) return -1;
    }
    return 0;
}

static const char *usb_controller_kind_name(int kind) {
    if (kind == 1) return "uhci";
    if (kind == 2) return "ohci";
    if (kind == 3) return "ehci";
    if (kind == 4) return "xhci";
    return "unknown";
}

static const char *usb_hid_role(uint8_t proto) {
    if (proto == 1u) return "keyboard";
    if (proto == 2u) return "mouse";
    return "hid";
}

int usb_inventory_snapshot(char *buf, uint32_t max) {
    uint32_t off = 0;
    uint32_t online_slots = 0;

    if (!buf || max == 0) return -1;
    buf[0] = 0;
    if (usb_snap_append_lit(buf, max, &off, "usb: yes\ncontrollers: ") < 0) return -1;
    if (usb_snap_append_u32(buf, max, &off, (uint32_t)g_usb_ctrl_count) < 0) return -1;
    if (usb_snap_append_lit(buf, max, &off, "\nprimary: ") < 0) return -1;
    if (usb_snap_append_lit(buf, max, &off, usb_controller_kind_name(g_usb_primary_kind)) < 0) return -1;
    if (usb_snap_append_lit(buf, max, &off, "\nmouse_present: ") < 0) return -1;
    if (usb_snap_append_u32(buf, max, &off, g_usb_have_mouse ? 1u : 0u) < 0) return -1;
    if (usb_snap_append_lit(buf, max, &off, "\ndma_used: ") < 0) return -1;
    if (usb_snap_append_u32(buf, max, &off, usb_dma_bytes_used()) < 0) return -1;
    if (usb_snap_append_char(buf, max, &off, '/') < 0) return -1;
    if (usb_snap_append_u32(buf, max, &off, usb_dma_bytes_total()) < 0) return -1;
    if (usb_snap_append_char(buf, max, &off, '\n') < 0) return -1;

    for (int i = 0; i < g_usb_ctrl_count; ++i) {
        const usb_controller_t *c = &g_usb_ctrls[i];
        if (!c->used) continue;
        if (usb_snap_append_lit(buf, max, &off, "controller ") < 0) return -1;
        if (usb_snap_append_u32(buf, max, &off, (uint32_t)i) < 0) return -1;
        if (usb_snap_append_lit(buf, max, &off, " type ") < 0) return -1;
        if (usb_snap_append_lit(buf, max, &off, usb_controller_kind_name(c->kind)) < 0) return -1;
        if (usb_snap_append_lit(buf, max, &off, " bdf 0000:") < 0) return -1;
        if (usb_snap_append_hex(buf, max, &off, c->bus, 2) < 0) return -1;
        if (usb_snap_append_char(buf, max, &off, ':') < 0) return -1;
        if (usb_snap_append_hex(buf, max, &off, c->dev, 2) < 0) return -1;
        if (usb_snap_append_char(buf, max, &off, '.') < 0) return -1;
        if (usb_snap_append_u32(buf, max, &off, c->fn) < 0) return -1;
        if (usb_snap_append_lit(buf, max, &off, " vendor 0x") < 0) return -1;
        if (usb_snap_append_hex(buf, max, &off, c->vendor, 4) < 0) return -1;
        if (usb_snap_append_lit(buf, max, &off, " device 0x") < 0) return -1;
        if (usb_snap_append_hex(buf, max, &off, c->device, 4) < 0) return -1;
        if (usb_snap_append_lit(buf, max, &off, " irq ") < 0) return -1;
        if (usb_snap_append_u32(buf, max, &off, c->irq_line) < 0) return -1;
        if (usb_snap_append_lit(buf, max, &off, " active ") < 0) return -1;
        if (usb_snap_append_u32(buf, max, &off, c->active ? 1u : 0u) < 0) return -1;
        if (usb_snap_append_lit(buf, max, &off, " reserved ") < 0) return -1;
        if (usb_snap_append_u32(buf, max, &off, c->reserved ? 1u : 0u) < 0) return -1;
        if (usb_snap_append_char(buf, max, &off, '\n') < 0) return -1;

        if (c->kind == 4) {
            const xhci_controller_t *xc = &c->xhci;
            for (uint32_t slot_id = 1; slot_id <= XHCI_MAX_TRACKED_SLOTS; ++slot_id) {
                const xhci_slot_state_t *slot = &xc->slots[slot_id];
                if (!slot->used || !slot->online) continue;
                online_slots++;
                if (usb_snap_append_lit(buf, max, &off, "xhci-slot ") < 0) return -1;
                if (usb_snap_append_u32(buf, max, &off, slot->slot_id) < 0) return -1;
                if (usb_snap_append_lit(buf, max, &off, " port ") < 0) return -1;
                if (usb_snap_append_u32(buf, max, &off, slot->port_id) < 0) return -1;
                if (usb_snap_append_lit(buf, max, &off, " speed ") < 0) return -1;
                if (usb_snap_append_u32(buf, max, &off, slot->speed_id) < 0) return -1;
                if (usb_snap_append_lit(buf, max, &off, " vid 0x") < 0) return -1;
                if (usb_snap_append_hex(buf, max, &off, slot->vendor_id, 4) < 0) return -1;
                if (usb_snap_append_lit(buf, max, &off, " pid 0x") < 0) return -1;
                if (usb_snap_append_hex(buf, max, &off, slot->product_id, 4) < 0) return -1;
                if (usb_snap_append_lit(buf, max, &off, " devclass ") < 0) return -1;
                if (usb_snap_append_hex(buf, max, &off, slot->device_class, 2) < 0) return -1;
                if (usb_snap_append_char(buf, max, &off, '/') < 0) return -1;
                if (usb_snap_append_hex(buf, max, &off, slot->device_subclass, 2) < 0) return -1;
                if (usb_snap_append_char(buf, max, &off, '/') < 0) return -1;
                if (usb_snap_append_hex(buf, max, &off, slot->device_protocol, 2) < 0) return -1;
                if (usb_snap_append_lit(buf, max, &off, " iface ") < 0) return -1;
                if (usb_snap_append_u32(buf, max, &off, slot->interface_number) < 0) return -1;
                if (usb_snap_append_lit(buf, max, &off, " class ") < 0) return -1;
                if (usb_snap_append_hex(buf, max, &off, slot->interface_class, 2) < 0) return -1;
                if (usb_snap_append_char(buf, max, &off, '/') < 0) return -1;
                if (usb_snap_append_hex(buf, max, &off, slot->interface_subclass, 2) < 0) return -1;
                if (usb_snap_append_char(buf, max, &off, '/') < 0) return -1;
                if (usb_snap_append_hex(buf, max, &off, slot->interface_protocol, 2) < 0) return -1;
                if (usb_snap_append_lit(buf, max, &off, " hid ") < 0) return -1;
                if (usb_snap_append_u32(buf, max, &off, slot->hid_ready ? 1u : 0u) < 0) return -1;
                if (slot->hid_ready) {
                    if (usb_snap_append_lit(buf, max, &off, " role ") < 0) return -1;
                    if (usb_snap_append_lit(buf, max, &off, usb_hid_role(slot->hid_protocol)) < 0) return -1;
                    if (usb_snap_append_lit(buf, max, &off, " ep 0x") < 0) return -1;
                    if (usb_snap_append_hex(buf, max, &off, slot->hid_ep_addr, 2) < 0) return -1;
                    if (usb_snap_append_lit(buf, max, &off, " mps ") < 0) return -1;
                    if (usb_snap_append_u32(buf, max, &off, slot->hid_max_packet) < 0) return -1;
                    if (usb_snap_append_lit(buf, max, &off, " interval ") < 0) return -1;
                    if (usb_snap_append_u32(buf, max, &off, slot->hid_interval) < 0) return -1;
                }
                if (usb_snap_append_char(buf, max, &off, '\n') < 0) return -1;
            }
        } else if (c->kind == 1) {
            if (c->keyboard_ready) {
                if (usb_snap_append_lit(buf, max, &off, "uhci-hid keyboard addr ") < 0) return -1;
                if (usb_snap_append_u32(buf, max, &off, c->keyboard_addr) < 0) return -1;
                if (usb_snap_append_lit(buf, max, &off, " ep 0x") < 0) return -1;
                if (usb_snap_append_hex(buf, max, &off, c->keyboard_ep, 2) < 0) return -1;
                if (usb_snap_append_char(buf, max, &off, '\n') < 0) return -1;
            }
            if (c->mouse_ready) {
                if (usb_snap_append_lit(buf, max, &off, "uhci-hid mouse addr ") < 0) return -1;
                if (usb_snap_append_u32(buf, max, &off, c->mouse_addr) < 0) return -1;
                if (usb_snap_append_lit(buf, max, &off, " ep 0x") < 0) return -1;
                if (usb_snap_append_hex(buf, max, &off, c->mouse_ep, 2) < 0) return -1;
                if (usb_snap_append_char(buf, max, &off, '\n') < 0) return -1;
            }
        }
    }

    if (usb_snap_append_lit(buf, max, &off, "online_slots: ") < 0) return -1;
    if (usb_snap_append_u32(buf, max, &off, online_slots) < 0) return -1;
    if (usb_snap_append_char(buf, max, &off, '\n') < 0) return -1;
    return (int)off;
}

/* Future controller drivers (UHCI/EHCI/XHCI) should call this after parsing
 * HID boot mouse reports. Export kept local for now until first implementation. */
void usb_hid_mouse_report_boot(int8_t dx, int8_t dy, int8_t wheel, uint8_t buttons, int wheel_present) {
    usb_hid_mouse_report((int)dx, (int)dy, (int)wheel, buttons,
                         wheel_present);
}

void usb_hid_mouse_report(int dx, int dy, int wheel, uint8_t buttons,
                          int wheel_present) {
    keyboard_mouse_emit_packet_ex(dx, dy, wheel, buttons, wheel_present);
    g_usb_have_mouse = 1;
}
