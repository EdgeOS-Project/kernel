/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Copyright (c) EdgeOS Contributors.
 *
 * Original EdgeOS implementation of the Linux V4L2 discovery ABI for real USB
 * Video Class devices.  USB descriptor parsing follows the public USB Video
 * Class specification; Linux-visible ioctl numbers and structure layouts follow
 * Linux UAPI definitions.  Frame capture is not advertised until the xHCI
 * isochronous/bulk IN path is implemented.
 */

#include "dev/uvc.h"
#include "stdio.h"
#include "string.h"

#define EINVAL 22
#define ENODEV 19
#define ENOSYS 38

#define USB_DT_INTERFACE 4u
#define USB_DT_CS_INTERFACE 0x24u
#define USB_CLASS_VIDEO 0x0Eu
#define USB_VIDEO_SUBCLASS_CONTROL 1u
#define USB_VIDEO_SUBCLASS_STREAMING 2u
#define UVC_VS_FORMAT_UNCOMPRESSED 0x04u
#define UVC_VS_FRAME_UNCOMPRESSED 0x05u
#define UVC_VS_FORMAT_MJPEG 0x06u
#define UVC_VS_FRAME_MJPEG 0x07u

#define V4L2_BUF_TYPE_VIDEO_CAPTURE 1u
#define V4L2_FIELD_NONE 1u
#define V4L2_FRMSIZE_TYPE_DISCRETE 1u
#define V4L2_FRMIVAL_TYPE_DISCRETE 1u
#define V4L2_INPUT_TYPE_CAMERA 2u
#define V4L2_COLORSPACE_SRGB 8u
#define V4L2_COLORSPACE_JPEG 7u
#define V4L2_CAP_VIDEO_CAPTURE 0x00000001u
#define V4L2_CAP_DEVICE_CAPS 0x80000000u
#define V4L2_PIX_FMT_YUYV 0x56595559u
#define V4L2_PIX_FMT_MJPEG 0x47504A4Du

#define V4L2_IOC_NRBITS 8u
#define V4L2_IOC_TYPEBITS 8u
#define V4L2_IOC_NRSHIFT 0u
#define V4L2_IOC_TYPESHIFT (V4L2_IOC_NRSHIFT + V4L2_IOC_NRBITS)
#define V4L2_IOC_TYPE(cmd) (((cmd) >> V4L2_IOC_TYPESHIFT) & ((1u << V4L2_IOC_TYPEBITS) - 1u))
#define V4L2_IOC_NR(cmd) (((cmd) >> V4L2_IOC_NRSHIFT) & ((1u << V4L2_IOC_NRBITS) - 1u))

struct v4l2_capability_compat {
    uint8_t driver[16];
    uint8_t card[32];
    uint8_t bus_info[32];
    uint32_t version;
    uint32_t capabilities;
    uint32_t device_caps;
    uint32_t reserved[3];
};

struct v4l2_fmtdesc_compat {
    uint32_t index;
    uint32_t type;
    uint32_t flags;
    uint8_t description[32];
    uint32_t pixelformat;
    uint32_t mbus_code;
    uint32_t reserved[3];
};

struct v4l2_pix_format_compat {
    uint32_t width;
    uint32_t height;
    uint32_t pixelformat;
    uint32_t field;
    uint32_t bytesperline;
    uint32_t sizeimage;
    uint32_t colorspace;
    uint32_t priv;
    uint32_t flags;
    union {
        uint32_t ycbcr_enc;
        uint32_t hsv_enc;
    } enc;
    uint32_t quantization;
    uint32_t xfer_func;
};

struct v4l2_format_compat {
    uint32_t type;
    union {
        struct v4l2_pix_format_compat pix;
        uint8_t raw_data[200];
    } fmt;
};

struct v4l2_frmsizeenum_compat {
    uint32_t index;
    uint32_t pixel_format;
    uint32_t type;
    union {
        struct {
            uint32_t width;
            uint32_t height;
        } discrete;
        uint8_t raw_data[24];
    } u;
    uint32_t reserved[2];
};

struct v4l2_fract_compat {
    uint32_t numerator;
    uint32_t denominator;
};

struct v4l2_frmivalenum_compat {
    uint32_t index;
    uint32_t pixel_format;
    uint32_t width;
    uint32_t height;
    uint32_t type;
    union {
        struct v4l2_fract_compat discrete;
        uint8_t raw_data[24];
    } u;
    uint32_t reserved[2];
};

struct v4l2_input_compat {
    uint32_t index;
    uint8_t name[32];
    uint32_t type;
    uint32_t audioset;
    uint32_t tuner;
    uint64_t std;
    uint32_t status;
    uint32_t capabilities;
    uint32_t reserved[3];
};

struct edge_uvc_device {
    uint8_t present;
    uint8_t slot;
    uint8_t control_iface;
    uint8_t streaming_iface;
    uint16_t vendor;
    uint16_t product;
    uint16_t width;
    uint16_t height;
    uint32_t pixelformat;
    uint32_t frame_size;
    char bus[32];
};

static struct edge_uvc_device g_uvc0;

static uint16_t le16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int guid_is_yuy2(const uint8_t *p) {
    static const uint8_t yuy2[16] = {
        'Y', 'U', 'Y', '2', 0x00, 0x00, 0x10, 0x00,
        0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71
    };
    return p && memcmp(p, yuy2, sizeof(yuy2)) == 0;
}

static void uvc_fill_format(struct v4l2_pix_format_compat *pix) {
    uint32_t bytes_per_pixel;
    if (!pix) return;
    memset(pix, 0, sizeof(*pix));
    pix->width = g_uvc0.width;
    pix->height = g_uvc0.height;
    pix->pixelformat = g_uvc0.pixelformat;
    pix->field = V4L2_FIELD_NONE;
    bytes_per_pixel = (g_uvc0.pixelformat == V4L2_PIX_FMT_YUYV) ? 2u : 0u;
    pix->bytesperline = g_uvc0.width * bytes_per_pixel;
    pix->sizeimage = g_uvc0.frame_size ? g_uvc0.frame_size :
        (g_uvc0.width * g_uvc0.height * (bytes_per_pixel ? bytes_per_pixel : 2u));
    pix->colorspace = (g_uvc0.pixelformat == V4L2_PIX_FMT_MJPEG) ?
        V4L2_COLORSPACE_JPEG : V4L2_COLORSPACE_SRGB;
}

int uvc_available(void) {
#ifdef CONFIG_USB_UVC
    /*
     * A Linux-visible V4L2 camera must stream frames.  EdgeOS can currently
     * parse UVC descriptors, but xHCI isochronous/bulk video capture is not
     * wired into the V4L2 read/mmap/streaming ABI yet.  Do not publish
     * /dev/video0 from metadata-only discovery.
     */
    return 0;
#else
    return 0;
#endif
}

uint32_t uvc_inode(void) {
    return 0xD0000080u;
}

int uvc_path_kind(const char *path) {
    return path && strcmp(path, EDGE_UVC_PATH_VIDEO0) == 0 && uvc_available();
}

int uvc_register_from_usb_config(const char *bus, uint8_t slot, uint16_t vendor,
                                 uint16_t product, const uint8_t *cfg,
                                 uint16_t len) {
#ifdef CONFIG_USB_UVC
    uint16_t off = 0;
    uint8_t cur_stream = 0;
    uint8_t cur_format = 0;
    uint8_t control_iface = 0xffu;
    uint8_t streaming_iface = 0xffu;
    uint16_t width = 0;
    uint16_t height = 0;
    uint32_t pixelformat = 0;
    uint32_t frame_size = 0;
    if (!cfg || len < 9u) return -EINVAL;
    while (off + 2u <= len) {
        uint8_t dlen = cfg[off];
        uint8_t dtype = cfg[off + 1u];
        if (dlen < 2u || off + dlen > len) break;
        if (dtype == USB_DT_INTERFACE && dlen >= 9u) {
            uint8_t cls = cfg[off + 5u];
            uint8_t sub = cfg[off + 6u];
            cur_stream = (cls == USB_CLASS_VIDEO && sub == USB_VIDEO_SUBCLASS_STREAMING);
            cur_format = 0;
            if (cls == USB_CLASS_VIDEO && sub == USB_VIDEO_SUBCLASS_CONTROL) {
                control_iface = cfg[off + 2u];
            } else if (cur_stream) {
                streaming_iface = cfg[off + 2u];
            }
        } else if (dtype == USB_DT_CS_INTERFACE && dlen >= 3u && cur_stream) {
            uint8_t subtype = cfg[off + 2u];
            if (subtype == UVC_VS_FORMAT_UNCOMPRESSED && dlen >= 27u) {
                if (guid_is_yuy2(cfg + off + 5u)) cur_format = 1u;
                else cur_format = 0u;
            } else if (subtype == UVC_VS_FORMAT_MJPEG && dlen >= 11u) {
                cur_format = 2u;
            } else if ((subtype == UVC_VS_FRAME_UNCOMPRESSED ||
                        subtype == UVC_VS_FRAME_MJPEG) && dlen >= 21u &&
                       cur_format != 0u && width == 0 && height == 0) {
                width = le16(cfg + off + 5u);
                height = le16(cfg + off + 7u);
                frame_size = le32(cfg + off + 17u);
                pixelformat = (cur_format == 2u) ? V4L2_PIX_FMT_MJPEG : V4L2_PIX_FMT_YUYV;
            }
        }
        off += dlen;
    }
    if (control_iface == 0xffu || streaming_iface == 0xffu) return -ENODEV;
    if (width == 0 || height == 0 || pixelformat == 0) {
        printf("[uvc] slot=%u USB video interfaces found but no supported YUYV/MJPEG frame descriptor\n",
               (uint32_t)slot);
        return -ENODEV;
    }
    (void)bus;
    (void)frame_size;
    memset(&g_uvc0, 0, sizeof(g_uvc0));
    printf("[uvc] slot=%u vid=%04x pid=%04x ctrl-if=%u stream-if=%u %ux%u %s detected; capture path not implemented, not registering video0\n",
           (uint32_t)slot, (uint32_t)vendor, (uint32_t)product,
           (uint32_t)control_iface, (uint32_t)streaming_iface,
           (uint32_t)width, (uint32_t)height,
           pixelformat == V4L2_PIX_FMT_MJPEG ? "MJPEG" : "YUYV");
    return -ENOSYS;
#else
    (void)bus; (void)slot; (void)vendor; (void)product; (void)cfg; (void)len;
    return -ENODEV;
#endif
}

int uvc_read(const char *path, char *out, uint32_t max) {
    (void)out;
    (void)max;
    if (!uvc_path_kind(path)) return -ENODEV;
    return -ENOSYS;
}

int uvc_ioctl_type(uint32_t cmd) {
    return (int)V4L2_IOC_TYPE(cmd);
}

int uvc_ioctl_nr(uint32_t cmd) {
    return (int)V4L2_IOC_NR(cmd);
}

uint32_t uvc_ioctl_arg_size(uint32_t cmd) {
    if (uvc_ioctl_type(cmd) != 'V') return 0;
    switch (uvc_ioctl_nr(cmd)) {
    case 0: return sizeof(struct v4l2_capability_compat);
    case 2: return sizeof(struct v4l2_fmtdesc_compat);
    case 4:
    case 5:
    case 64: return sizeof(struct v4l2_format_compat);
    case 26: return sizeof(struct v4l2_input_compat);
    case 38:
    case 39: return sizeof(uint32_t);
    case 74: return sizeof(struct v4l2_frmsizeenum_compat);
    case 75: return sizeof(struct v4l2_frmivalenum_compat);
    default: return 0;
    }
}

int uvc_ioctl_kernel(const char *path, uint32_t cmd, void *arg) {
    if (!uvc_path_kind(path)) return -ENODEV;
    if (uvc_ioctl_type(cmd) != 'V') return -ENOSYS;
    switch (uvc_ioctl_nr(cmd)) {
    case 0: {
        struct v4l2_capability_compat *cap = (struct v4l2_capability_compat *)arg;
        if (!cap) return -EINVAL;
        memset(cap, 0, sizeof(*cap));
        strcpy((char *)cap->driver, "edge-uvc");
        strcpy((char *)cap->card, "USB Video Class");
        strcpy((char *)cap->bus_info, g_uvc0.bus);
        cap->version = 0x00020008u;
        cap->device_caps = V4L2_CAP_VIDEO_CAPTURE;
        cap->capabilities = cap->device_caps | V4L2_CAP_DEVICE_CAPS;
        return 0;
    }
    case 2: {
        struct v4l2_fmtdesc_compat *fmt = (struct v4l2_fmtdesc_compat *)arg;
        if (!fmt) return -EINVAL;
        if (fmt->index != 0 || fmt->type != V4L2_BUF_TYPE_VIDEO_CAPTURE) return -EINVAL;
        fmt->flags = 0;
        memset(fmt->description, 0, sizeof(fmt->description));
        strcpy((char *)fmt->description,
               g_uvc0.pixelformat == V4L2_PIX_FMT_MJPEG ? "Motion-JPEG" : "YUYV 4:2:2");
        fmt->pixelformat = g_uvc0.pixelformat;
        fmt->mbus_code = 0;
        memset(fmt->reserved, 0, sizeof(fmt->reserved));
        return 0;
    }
    case 4:
    case 5:
    case 64: {
        struct v4l2_format_compat *fmt = (struct v4l2_format_compat *)arg;
        if (!fmt) return -EINVAL;
        if (fmt->type != V4L2_BUF_TYPE_VIDEO_CAPTURE) return -EINVAL;
        uvc_fill_format(&fmt->fmt.pix);
        return 0;
    }
    case 26: {
        struct v4l2_input_compat *inp = (struct v4l2_input_compat *)arg;
        if (!inp) return -EINVAL;
        if (inp->index != 0) return -EINVAL;
        memset(inp, 0, sizeof(*inp));
        inp->index = 0;
        strcpy((char *)inp->name, "Camera 0");
        inp->type = V4L2_INPUT_TYPE_CAMERA;
        return 0;
    }
    case 38: {
        uint32_t *idx = (uint32_t *)arg;
        if (!idx) return -EINVAL;
        *idx = 0;
        return 0;
    }
    case 39: {
        uint32_t *idx = (uint32_t *)arg;
        if (!idx) return -EINVAL;
        return *idx == 0 ? 0 : -EINVAL;
    }
    case 74: {
        struct v4l2_frmsizeenum_compat *fsize = (struct v4l2_frmsizeenum_compat *)arg;
        if (!fsize) return -EINVAL;
        if (fsize->index != 0 || fsize->pixel_format != g_uvc0.pixelformat) return -EINVAL;
        fsize->type = V4L2_FRMSIZE_TYPE_DISCRETE;
        fsize->u.discrete.width = g_uvc0.width;
        fsize->u.discrete.height = g_uvc0.height;
        memset(fsize->reserved, 0, sizeof(fsize->reserved));
        return 0;
    }
    case 75: {
        struct v4l2_frmivalenum_compat *fival = (struct v4l2_frmivalenum_compat *)arg;
        if (!fival) return -EINVAL;
        if (fival->index != 0 || fival->pixel_format != g_uvc0.pixelformat ||
            fival->width != g_uvc0.width || fival->height != g_uvc0.height) {
            return -EINVAL;
        }
        fival->type = V4L2_FRMIVAL_TYPE_DISCRETE;
        fival->u.discrete.numerator = 1;
        fival->u.discrete.denominator = 30;
        memset(fival->reserved, 0, sizeof(fival->reserved));
        return 0;
    }
    default:
        return -ENOSYS;
    }
}
