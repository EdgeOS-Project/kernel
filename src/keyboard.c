#include "keyboard.h"
#include "arch/x86_64/pic.h"
#include "console.h"
#include "arch/x86_64/idt.h"
#include "arch/x86_64/io_ports.h"
#include "arch/x86_64/isr.h"
#include "serial_console.h"
#include "sys/syscall.h"
#include "sys/boottime.h"
#include "kernel/linux_time.h"
#include "kernel/boot_command_line.h"
#include "kernel/input_device.h"
#include "kernel/drm_runtime.h"
#include "drivers/usb.h"
#include "sys/spinlock.h"
#ifdef CONFIG_VIRTIO_INPUT
#include "drivers/virtio_input.h"
#endif
#include "types.h"
#include "string.h"

static BOOL g_caps_lock = FALSE;
static BOOL g_shift_pressed = FALSE;
static BOOL g_ctrl_pressed = FALSE;
static BOOL g_alt_pressed = FALSE;
volatile char g_ch = 0, g_scan_code = 0;
static int g_extended = 0;
static volatile int g_skip_irq_scancode = 0;
static volatile uint64_t g_keyboard_irq_count;
static volatile uint64_t g_keyboard_last_tsc;
static volatile uint32_t g_sigint_pending;
static int g_ps2_controller_present = 1;
static int g_ps2_keyboard_present;
static int g_ps2_keyboard_set2_mode;
static int g_ps2_keyboard_set2_break;
static int g_ps2_keyboard_set2_e0;
static input_device_description_t g_ps2_keyboard_description;
static uint32_t g_ps2_keyboard_debug_budget = 0;
static uint64_t g_ps2_fallback_poll_next_us;
static spinlock_t g_ps2_controller_lock;
#ifdef CONFIG_PS2_MOUSE
static int g_ps2_mouse_present;
static input_device_description_t g_ps2_mouse_description;
static int g_ps2_mouse_packet_size;
static uint8_t g_ps2_mouse_packet[4];
static uint8_t g_ps2_mouse_packet_index;
enum ps2_pointer_model {
    PS2_POINTER_GENERIC = 0,
    PS2_POINTER_INTELLIMOUSE,
    PS2_POINTER_SYNAPTICS,
    PS2_POINTER_ELANTECH
};
static enum ps2_pointer_model g_ps2_pointer_model;
#endif

#define KBD_BUF_SIZE 256
static char kbd_buf[KBD_BUF_SIZE];
static volatile int kbd_head;
static volatile int kbd_tail;

#define MOUSE_BUF_SIZE 1024
static uint8_t mouse_buf[MOUSE_BUF_SIZE];
static volatile int mouse_head;
static volatile int mouse_tail;
/*
 * Xorg/evdev reads fixed-size Linux struct input_event records.  A full XFCE
 * session can be slow during startup and pointer motion can queue hundreds of
 * REL_X/REL_Y/SYN records before the X input thread drains them.  Keep this
 * ring sized and maintained as whole records; byte-wise overflow corrupts the
 * stream alignment and makes later button clicks invisible to X.
 */
#define INPUT_EVENT_BUF_SIZE (EDGE_LINUX_INPUT_EVENT_SIZE * 8192u)
#define INPUT_EVENT_KEYBOARD 0
#define INPUT_EVENT_MOUSE 1
#define INPUT_EVENT_COUNT ((int)EDGE_INPUT_DEVICE_MAX)
static uint8_t input_event_buf[INPUT_EVENT_COUNT][INPUT_EVENT_BUF_SIZE];
static volatile int input_event_head[INPUT_EVENT_COUNT];
static volatile int input_event_tail[INPUT_EVENT_COUNT];
static volatile uint32_t input_event_sequence[INPUT_EVENT_COUNT];
static uint8_t g_mouse_buttons;
static int g_mouse_wheel_mode;
static int g_mouse_ext_prefix;
static uint32_t g_mouse_debug_budget = 0;
static uint32_t g_evdev_drop_debug_budget = 16;

static void keyboard_handle_scancode_ex(int scancode, int emit_linux_input);

static void keyboard_poll_external_input(void) {
    /*
     * PS/2 input is drained directly from the i8042 data port below, but USB
     * HID input arrives through the xHCI/UHCI event rings and is then
     * translated into the same keyboard ring by keyboard_emit_scancode(). Keep
     * this polling local to keyboard readers as well as the timer path so every
     * console implementation sees USB keyboards, including the older VFS tty
     * path used by fbcon login.
     */
#ifdef CONFIG_USB
    usb_poll();
#endif
#ifdef CONFIG_VIRTIO_INPUT
    virtio_input_poll();
#endif
}

#define LINUX_EV_SYN 0x00u
#define LINUX_EV_KEY 0x01u
#define LINUX_EV_REL 0x02u
#define LINUX_EV_MSC 0x04u
#define LINUX_SYN_REPORT 0u
#define LINUX_MSC_SCAN 0x04u
#define LINUX_KEY_HOME 102u
#define LINUX_KEY_UP 103u
#define LINUX_KEY_PAGEUP 104u
#define LINUX_KEY_LEFT 105u
#define LINUX_KEY_RIGHT 106u
#define LINUX_KEY_END 107u
#define LINUX_KEY_DOWN 108u
#define LINUX_KEY_PAGEDOWN 109u
#define LINUX_KEY_INSERT 110u
#define LINUX_KEY_DELETE 111u
#define LINUX_REL_X 0u
#define LINUX_REL_Y 1u
#define LINUX_REL_WHEEL 8u
#define LINUX_BTN_LEFT 0x110u
#define LINUX_BTN_RIGHT 0x111u
#define LINUX_BTN_MIDDLE 0x112u

typedef struct __attribute__((packed)) {
    int64_t tv_sec;
    int64_t tv_usec;
    uint16_t type;
    uint16_t code;
    int32_t value;
} edge_linux_input_event_t;

static void kbd_buf_push_char(char ch) {
    int next_head = (kbd_head + 1) % KBD_BUF_SIZE;
    if (next_head == kbd_tail) return;
    kbd_buf[kbd_head] = ch;
    kbd_head = next_head;
}

static void mouse_buf_push_byte(uint8_t b) {
    int next_head = (mouse_head + 1) % MOUSE_BUF_SIZE;
    if (next_head == mouse_tail) return;
    mouse_buf[mouse_head] = b;
    mouse_head = next_head;
}

static int input_event_buf_pending_locked(int event_id, int tail) {
    int n;
    if (event_id < 0 || event_id >= INPUT_EVENT_COUNT) return 0;
    if (tail < 0 || tail >= (int)INPUT_EVENT_BUF_SIZE) tail = input_event_head[event_id];
    n = input_event_head[event_id] - tail;
    if (n < 0) n += (int)INPUT_EVENT_BUF_SIZE;
    return n;
}

static int input_event_buf_cursor_valid_locked(int event_id, int tail) {
    int used;
    int pending;
    if (event_id < 0 || event_id >= INPUT_EVENT_COUNT) return 0;
    if (tail < 0 || tail >= (int)INPUT_EVENT_BUF_SIZE) return 0;
    /*
     * input_event_tail[event_id] is the oldest byte still retained in the
     * shared evdev ring.  Per-open fds keep their own cursor.  If a slow Xorg
     * input fd falls behind a wrap, the distance from its stale cursor to head
     * becomes larger than the retained window even when it remains aligned to
     * struct input_event.  Linux evdev never returns overwritten bytes as
     * input records; resync such cursors before userland can consume garbage
     * button/key events.
     */
    used = input_event_buf_pending_locked(event_id, input_event_tail[event_id]);
    pending = input_event_buf_pending_locked(event_id, tail);
    return pending <= used;
}

static int input_event_buf_free_locked(int event_id) {
    int used = input_event_buf_pending_locked(event_id, input_event_tail[event_id]);
    return ((int)INPUT_EVENT_BUF_SIZE - 1) - used;
}

static void input_event_buf_drop_record_locked(int event_id) {
    input_event_tail[event_id] = (input_event_tail[event_id] + (int)EDGE_LINUX_INPUT_EVENT_SIZE) %
                                 (int)INPUT_EVENT_BUF_SIZE;
}

static void input_event_buf_push_byte_locked(int event_id, uint8_t b) {
    int next_head;
    if (event_id < 0 || event_id >= INPUT_EVENT_COUNT) return;
    next_head = (input_event_head[event_id] + 1) % INPUT_EVENT_BUF_SIZE;
    if (next_head == input_event_tail[event_id]) input_event_buf_drop_record_locked(event_id);
    input_event_buf[event_id][input_event_head[event_id]] = b;
    input_event_head[event_id] = next_head;
}

static void input_event_push(int event_id, uint16_t type, uint16_t code, int32_t value) {
    edge_linux_input_event_t ev;
    uint64_t us = boottime_monotonic_us();
    unsigned long flags;
    ev.tv_sec = (int64_t)(us / 1000000ull);
    ev.tv_usec = (int64_t)(us % 1000000ull);
    ev.type = type;
    ev.code = code;
    ev.value = value;
    if (event_id >= 0)
        input_device_event_state_update((uint32_t)event_id, type, code,
                                        value);
    /*
     * Evdev readers must never observe a partially queued struct input_event.
     * Xorg/libinput poll the fd and then read fixed-size records; exposing the
     * first few bytes before the rest of the record is queued can make userland
     * consume and discard malformed input.  Queue the whole Linux ABI record as
     * one interrupt-protected unit.
     */
    __asm__ __volatile__("pushfq; popq %0; cli" : "=r"(flags) :: "memory");
    while (input_event_buf_free_locked(event_id) < (int)sizeof(ev)) {
        if (g_evdev_drop_debug_budget) {
            printf("[evdev] drop-old-record event%d head=%d tail=%d\n",
                   event_id, input_event_head[event_id], input_event_tail[event_id]);
            g_evdev_drop_debug_budget--;
        }
        input_event_buf_drop_record_locked(event_id);
    }
    for (uint32_t i = 0; i < sizeof(ev); ++i) {
        input_event_buf_push_byte_locked(event_id, ((const uint8_t *)&ev)[i]);
    }
    ++input_event_sequence[event_id];
    if (!input_event_sequence[event_id]) input_event_sequence[event_id] = 1u;
    __asm__ __volatile__("pushq %0; popfq" :: "r"(flags) : "memory");
    /*
     * Some virtual input devices emit empty synchronization frames while the
     * pointer is idle. Wake direct scanout only for a real input record so
     * those keepalives cannot defeat the idle refresh backoff.
     */
    if (type != LINUX_EV_SYN)
        edge_drm_scanout_activity();
}

void keyboard_emit_linux_input_event(int event_id, uint16_t type, uint16_t code, int32_t value) {
    input_event_push(event_id, type, code, value);
}

static void mouse_emit_linux_events(int dx, int dy, int wheel, uint8_t old_buttons, uint8_t new_buttons, int wheel_present) {
    if (dx != 0) input_event_push(INPUT_EVENT_MOUSE, LINUX_EV_REL, LINUX_REL_X, dx);
    if (dy != 0) input_event_push(INPUT_EVENT_MOUSE, LINUX_EV_REL, LINUX_REL_Y, dy);
    if (wheel_present && wheel != 0) input_event_push(INPUT_EVENT_MOUSE, LINUX_EV_REL, LINUX_REL_WHEEL, wheel);
    if ((old_buttons & 0x01u) != (new_buttons & 0x01u)) {
        input_event_push(INPUT_EVENT_MOUSE, LINUX_EV_KEY, LINUX_BTN_LEFT, (new_buttons & 0x01u) ? 1 : 0);
    }
    if ((old_buttons & 0x02u) != (new_buttons & 0x02u)) {
        input_event_push(INPUT_EVENT_MOUSE, LINUX_EV_KEY, LINUX_BTN_RIGHT, (new_buttons & 0x02u) ? 1 : 0);
    }
    if ((old_buttons & 0x04u) != (new_buttons & 0x04u)) {
        input_event_push(INPUT_EVENT_MOUSE, LINUX_EV_KEY, LINUX_BTN_MIDDLE, (new_buttons & 0x04u) ? 1 : 0);
    }
    if (dx != 0 || dy != 0 || (wheel_present && wheel != 0) || old_buttons != new_buttons) {
        input_event_push(INPUT_EVENT_MOUSE, LINUX_EV_SYN, LINUX_SYN_REPORT, 0);
    }
}

static void keyboard_emit_linux_event_from_scancode(int scancode) {
    static int evdev_extended;
    uint16_t code;
    uint32_t msc_scan;
    int value;
    int extended = 0;
    static uint32_t key_debug_budget = 0;
    if (scancode == 0) return;
    if (scancode == 0xE0) {
        evdev_extended = 1;
        return;
    }
    value = (scancode & 0x80) ? 0 : 1;
    code = (uint16_t)(scancode & 0x7F);
    if (code == 0) return;
    msc_scan = (uint32_t)code;
    if (evdev_extended) {
        extended = 1;
        msc_scan |= 0xE000u;
        switch (code) {
            case SCAN_CODE_KEY_HOME: code = LINUX_KEY_HOME; break;
            case SCAN_CODE_KEY_UP: code = LINUX_KEY_UP; break;
            case SCAN_CODE_KEY_PAGE_UP: code = LINUX_KEY_PAGEUP; break;
            case SCAN_CODE_KEY_LEFT: code = LINUX_KEY_LEFT; break;
            case SCAN_CODE_KEY_RIGHT: code = LINUX_KEY_RIGHT; break;
            case SCAN_CODE_KEY_END: code = LINUX_KEY_END; break;
            case SCAN_CODE_KEY_DOWN: code = LINUX_KEY_DOWN; break;
            case SCAN_CODE_KEY_PAGE_DOWN: code = LINUX_KEY_PAGEDOWN; break;
            case SCAN_CODE_KEY_INSERT: code = LINUX_KEY_INSERT; break;
            case SCAN_CODE_KEY_DELETE: code = LINUX_KEY_DELETE; break;
            default: break;
        }
        evdev_extended = 0;
    }
    /*
     * Linux HID/evdev devices commonly report the hardware scan value as an
     * EV_MSC/MSC_SCAN event immediately before the EV_KEY state change, then
     * terminate the packet with SYN_REPORT.  Xorg's evdev keyboard path can
     * build a key map from EVIOCGKEYCODE alone, but providing MSC_SCAN keeps
     * the observable stream aligned with Linux and avoids losing scan-code
     * context for extended keys.  For the common PC keyboard range, Linux
     * KEY_* values intentionally line up with set-1 scancodes for letters,
     * digits, Enter, Shift, Ctrl, Alt, and function keys.
     */
    input_event_push(INPUT_EVENT_KEYBOARD, LINUX_EV_MSC, LINUX_MSC_SCAN, (int32_t)msc_scan);
    input_event_push(INPUT_EVENT_KEYBOARD, LINUX_EV_KEY, code, value);
    input_event_push(INPUT_EVENT_KEYBOARD, LINUX_EV_SYN, LINUX_SYN_REPORT, 0);
    if (key_debug_budget) {
        printf("[kbd-evdev] sc=0x%x ext=%d msc=0x%x code=%u value=%d head=%d tail=%d\n",
               scancode & 0xff, extended, msc_scan, (uint32_t)code, value,
               input_event_head[INPUT_EVENT_KEYBOARD], input_event_tail[INPUT_EVENT_KEYBOARD]);
        key_debug_budget--;
    }
}

static void mouse_emit_ps2_packet(int dx, int dy, int wheel, uint8_t buttons, int wheel_present) {
    uint8_t b0 = 0x08u | (buttons & 0x07u);
    uint8_t b1, b2;
    if (dx > 127) dx = 127;
    if (dx < -127) dx = -127;
    if (dy > 127) dy = 127;
    if (dy < -127) dy = -127;
    if (dx < 0) b0 |= 0x10u;
    if (dy < 0) b0 |= 0x20u;
    b1 = (uint8_t)((int8_t)dx);
    b2 = (uint8_t)((int8_t)dy);
    mouse_buf_push_byte(b0);
    mouse_buf_push_byte(b1);
    mouse_buf_push_byte(b2);
    if (wheel_present) g_mouse_wheel_mode = 1;
    if (g_mouse_wheel_mode) {
        if (wheel > 127) wheel = 127;
        if (wheel < -127) wheel = -127;
        mouse_buf_push_byte((uint8_t)((int8_t)wheel));
    }
}

void keyboard_mouse_emit_packet(int dx, int dy, uint8_t buttons) {
    keyboard_mouse_emit_packet_ex(dx, dy, 0, buttons, 0);
}

void keyboard_mouse_emit_packet_ex(int dx, int dy, int wheel, uint8_t buttons, int wheel_present) {
    uint8_t old_buttons = g_mouse_buttons;
    uint8_t next_buttons = (uint8_t)(buttons & 0x07u);
    g_mouse_buttons = next_buttons;
    if ((old_buttons != next_buttons || wheel != 0) && g_mouse_debug_budget) {
        printf("[mouse] dx=%d dy=%d wheel=%d buttons=%u->%u\n",
               dx, dy, wheel, (uint32_t)old_buttons, (uint32_t)next_buttons);
        g_mouse_debug_budget--;
    }
    mouse_emit_ps2_packet(dx, dy, wheel, next_buttons, wheel_present);
    mouse_emit_linux_events(dx, dy, wheel, old_buttons, next_buttons, wheel_present);
}

void keyboard_mouse_emit_compat_packet_ex(int dx, int dy, int wheel,
                                          uint8_t buttons,
                                          int wheel_present) {
    uint8_t next_buttons = (uint8_t)(buttons & 0x07u);

    /*
     * Virtio input already supplies a complete evdev event frame.  Preserve
     * that frame byte-for-byte and update only the legacy /dev/input/mice
     * stream here.  Sending the same movement through
     * keyboard_mouse_emit_packet_ex() would duplicate EV_REL/button events
     * before SYN_REPORT and makes pointer acceleration device-dependent.
     */
    g_mouse_buttons = next_buttons;
    mouse_emit_ps2_packet(dx, dy, wheel, next_buttons, wheel_present);
}

static void mouse_emulate_from_scancode(int scancode) {
    int release = 0;
    if (scancode == 0xE0) {
        g_mouse_ext_prefix = 1;
        return;
    }
    if (scancode & 0x80) {
        release = 1;
        scancode &= 0x7F;
    }

    if (g_mouse_ext_prefix) {
        if (!release) {
            if (scancode == SCAN_CODE_KEY_UP) keyboard_mouse_emit_packet_ex(0, +8, 0, g_mouse_buttons, 0);
            else if (scancode == SCAN_CODE_KEY_DOWN) keyboard_mouse_emit_packet_ex(0, -8, 0, g_mouse_buttons, 0);
            else if (scancode == SCAN_CODE_KEY_LEFT) keyboard_mouse_emit_packet_ex(-8, 0, 0, g_mouse_buttons, 0);
            else if (scancode == SCAN_CODE_KEY_RIGHT) keyboard_mouse_emit_packet_ex(+8, 0, 0, g_mouse_buttons, 0);
        }
        g_mouse_ext_prefix = 0;
        return;
    }

    /* Keyboard-emulated mouse buttons: z=left, x=right, c=middle */
    if (scancode == SCAN_CODE_KEY_Z || scancode == SCAN_CODE_KEY_X || scancode == SCAN_CODE_KEY_C) {
        uint8_t mask = (scancode == SCAN_CODE_KEY_Z) ? 0x1u :
                       (scancode == SCAN_CODE_KEY_X) ? 0x2u : 0x4u;
        uint8_t next = release ? (uint8_t)(g_mouse_buttons & ~mask) : (uint8_t)(g_mouse_buttons | mask);
        if (next != g_mouse_buttons) {
            keyboard_mouse_emit_packet_ex(0, 0, 0, next, 0);
        }
    }
}

static inline uint64_t rdtsc64(void) {
    uint32_t lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

// see scan codes defined in keyboard.h for index
char g_scan_code_chars[128] = {
    0, 27, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', '\b',
    '\t', 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\r',
    0, 'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`', 0,
    '\\', 'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/', 0, '*', 0, ' ',
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, '-', 0, 0, 0, '+', 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0
};

static int get_scancode() {
    return inportb(KEYBOARD_DATA_PORT);
}
char alternate_chars(char ch);

static int keyboard_wait_input_empty(void) {
    for (int i = 0; i < 100000; ++i) {
        uint8_t st = inportb(KEYBOARD_STATUS_PORT);
        if (st == 0xFFu) {
            g_ps2_controller_present = 0;
            return -1;
        }
        if ((st & 0x02u) == 0) return 0;
        __asm__ __volatile__("pause");
    }
    return -1;
}

static int keyboard_wait_output_full(void) {
    for (int i = 0; i < 100000; ++i) {
        uint8_t st = inportb(KEYBOARD_STATUS_PORT);
        if (st == 0xFFu) {
            g_ps2_controller_present = 0;
            return -1;
        }
        if ((st & 0x01u) != 0) return 0;
        __asm__ __volatile__("pause");
    }
    return -1;
}

static void keyboard_controller_write_cmd(uint8_t cmd) {
    if (keyboard_wait_input_empty() == 0) outportb(KEYBOARD_COMMAND_PORT, cmd);
}

static void keyboard_controller_write_data(uint8_t data) {
    if (keyboard_wait_input_empty() == 0) outportb(KEYBOARD_DATA_PORT, data);
}

static int ps2_set2_to_set1(uint8_t code, int e0) {
    if (e0) {
        switch (code) {
            case 0x6cu: return SCAN_CODE_KEY_HOME;
            case 0x75u: return SCAN_CODE_KEY_UP;
            case 0x7du: return SCAN_CODE_KEY_PAGE_UP;
            case 0x6bu: return SCAN_CODE_KEY_LEFT;
            case 0x74u: return SCAN_CODE_KEY_RIGHT;
            case 0x69u: return SCAN_CODE_KEY_END;
            case 0x72u: return SCAN_CODE_KEY_DOWN;
            case 0x7au: return SCAN_CODE_KEY_PAGE_DOWN;
            case 0x70u: return SCAN_CODE_KEY_INSERT;
            case 0x71u: return SCAN_CODE_KEY_DELETE;
            case 0x14u: return SCAN_CODE_KEY_RIGHT_CTRL;
            default: return 0;
        }
    }

    switch (code) {
        case 0x76u: return SCAN_CODE_KEY_ESC;
        case 0x16u: return SCAN_CODE_KEY_1;
        case 0x1eu: return SCAN_CODE_KEY_2;
        case 0x26u: return SCAN_CODE_KEY_3;
        case 0x25u: return SCAN_CODE_KEY_4;
        case 0x2eu: return SCAN_CODE_KEY_5;
        case 0x36u: return SCAN_CODE_KEY_6;
        case 0x3du: return SCAN_CODE_KEY_7;
        case 0x3eu: return SCAN_CODE_KEY_8;
        case 0x46u: return SCAN_CODE_KEY_9;
        case 0x45u: return SCAN_CODE_KEY_0;
        case 0x4eu: return SCAN_CODE_KEY_MINUS;
        case 0x55u: return SCAN_CODE_KEY_EQUAL;
        case 0x66u: return SCAN_CODE_KEY_BACKSPACE;
        case 0x0du: return SCAN_CODE_KEY_TAB;
        case 0x15u: return SCAN_CODE_KEY_Q;
        case 0x1du: return SCAN_CODE_KEY_W;
        case 0x24u: return SCAN_CODE_KEY_E;
        case 0x2du: return SCAN_CODE_KEY_R;
        case 0x2cu: return SCAN_CODE_KEY_T;
        case 0x35u: return SCAN_CODE_KEY_Y;
        case 0x3cu: return SCAN_CODE_KEY_U;
        case 0x43u: return SCAN_CODE_KEY_I;
        case 0x44u: return SCAN_CODE_KEY_O;
        case 0x4du: return SCAN_CODE_KEY_P;
        case 0x54u: return SCAN_CODE_KEY_SQUARE_OPEN_BRACKET;
        case 0x5bu: return SCAN_CODE_KEY_SQUARE_CLOSE_BRACKET;
        case 0x5au: return SCAN_CODE_KEY_ENTER;
        case 0x14u: return SCAN_CODE_KEY_LEFT_CTRL;
        case 0x1cu: return SCAN_CODE_KEY_A;
        case 0x1bu: return SCAN_CODE_KEY_S;
        case 0x23u: return SCAN_CODE_KEY_D;
        case 0x2bu: return SCAN_CODE_KEY_F;
        case 0x34u: return SCAN_CODE_KEY_G;
        case 0x33u: return SCAN_CODE_KEY_H;
        case 0x3bu: return SCAN_CODE_KEY_J;
        case 0x42u: return SCAN_CODE_KEY_K;
        case 0x4bu: return SCAN_CODE_KEY_L;
        case 0x4cu: return SCAN_CODE_KEY_SEMICOLON;
        case 0x52u: return SCAN_CODE_KEY_SINGLE_QUOTE;
        case 0x0eu: return SCAN_CODE_KEY_ACUTE;
        case 0x12u: return SCAN_CODE_KEY_LEFT_SHIFT;
        case 0x5du: return SCAN_CODE_KEY_BACKSLASH;
        case 0x1au: return SCAN_CODE_KEY_Z;
        case 0x22u: return SCAN_CODE_KEY_X;
        case 0x21u: return SCAN_CODE_KEY_C;
        case 0x2au: return SCAN_CODE_KEY_V;
        case 0x32u: return SCAN_CODE_KEY_B;
        case 0x31u: return SCAN_CODE_KEY_N;
        case 0x3au: return SCAN_CODE_KEY_M;
        case 0x41u: return SCAN_CODE_KEY_COMMA;
        case 0x49u: return SCAN_CODE_KEY_DOT;
        case 0x4au: return SCAN_CODE_KEY_FORESLHASH;
        case 0x59u: return SCAN_CODE_KEY_RIGHT_SHIFT;
        case 0x7cu: return SCAN_CODE_KEY_ASTERISK;
        case 0x11u: return SCAN_CODE_KEY_ALT;
        case 0x29u: return SCAN_CODE_KEY_SPACE;
        case 0x58u: return SCAN_CODE_KEY_CAPS_LOCK;
        case 0x05u: return SCAN_CODE_KEY_F1;
        case 0x06u: return SCAN_CODE_KEY_F2;
        case 0x04u: return SCAN_CODE_KEY_F3;
        case 0x0cu: return SCAN_CODE_KEY_F4;
        case 0x03u: return SCAN_CODE_KEY_F5;
        case 0x0bu: return SCAN_CODE_KEY_F6;
        case 0x83u: return SCAN_CODE_KEY_F7;
        case 0x0au: return SCAN_CODE_KEY_F8;
        case 0x01u: return SCAN_CODE_KEY_F9;
        case 0x09u: return SCAN_CODE_KEY_F10;
        case 0x78u: return SCAN_CODE_KEY_F11;
        case 0x07u: return SCAN_CODE_KEY_F12;
        case 0x77u: return SCAN_CODE_KEY_NUM_LOCK;
        case 0x7eu: return SCAN_CODE_KEY_SCROLL_LOCK;
        default: return 0;
    }
}

static void ps2_keyboard_handle_byte(uint8_t data) {
    int translated;
    int release;
    int e0;

    if (data == 0xFAu || data == 0xFEu || data == 0xAAu) return;

    /*
     * If the i8042 translation bit is not honored, VMware and real PS/2
     * keyboards deliver set-2 bytes.  Linux's atkbd stack handles both
     * translated and raw controller modes; EdgeOS does the same at the
     * kernel input boundary and still exposes set-1-like console semantics and
     * Linux evdev KEY_* events to userspace.
     */
    if (!g_ps2_keyboard_set2_mode && data == 0xF0u) {
        g_ps2_keyboard_set2_mode = 1;
    }

    if (g_ps2_keyboard_set2_mode) {
        if (data == 0xE0u) {
            g_ps2_keyboard_set2_e0 = 1;
            return;
        }
        if (data == 0xF0u) {
            g_ps2_keyboard_set2_break = 1;
            return;
        }
        release = g_ps2_keyboard_set2_break;
        e0 = g_ps2_keyboard_set2_e0;
        g_ps2_keyboard_set2_break = 0;
        g_ps2_keyboard_set2_e0 = 0;
        translated = ps2_set2_to_set1(data, e0);
        if (!translated) return;
        if (e0) keyboard_handle_scancode_ex(0xE0, 1);
        if (release) translated |= 0x80;
    } else {
        translated = data;
    }

    if (g_ps2_keyboard_debug_budget) {
        printf("[ps2-kbd] raw=0x%x set2=%d sc=0x%x head=%d tail=%d\n",
               (uint32_t)data, g_ps2_keyboard_set2_mode,
               (uint32_t)translated, kbd_head, kbd_tail);
        g_ps2_keyboard_debug_budget--;
    }
    keyboard_handle_scancode_ex(translated, 1);
}

#ifdef CONFIG_PS2_MOUSE
static int ps2_read_data_timeout(uint8_t *out, int want_aux) {
    for (int i = 0; i < 100000; ++i) {
        uint8_t st = inportb(KEYBOARD_STATUS_PORT);
        if (st == 0xFFu) {
            g_ps2_controller_present = 0;
            return -1;
        }
        if (st & 0x01u) {
            uint8_t data = inportb(KEYBOARD_DATA_PORT);
            int is_aux = (st & 0x20u) != 0;
            if (want_aux < 0 || is_aux == want_aux) {
                *out = data;
                return 0;
            }
            if (!is_aux) ps2_keyboard_handle_byte(data);
        }
        __asm__ __volatile__("pause");
    }
    return -1;
}

static int ps2_mouse_write(uint8_t value) {
    uint8_t ack = 0;

    if (keyboard_wait_input_empty() < 0) return -1;
    outportb(KEYBOARD_COMMAND_PORT, 0xD4u);
    if (keyboard_wait_input_empty() < 0) return -1;
    outportb(KEYBOARD_DATA_PORT, value);
    if (ps2_read_data_timeout(&ack, 1) < 0) return -1;
    return (ack == 0xFAu) ? 0 : -1;
}

static int ps2_mouse_read_id(void) {
    uint8_t id = 0;

    if (ps2_mouse_write(0xF2u) < 0) return -1;
    if (ps2_read_data_timeout(&id, 1) < 0) return -1;
    return (int)id;
}

static int ps2_mouse_set_sample_rate(uint8_t rate) {
    if (ps2_mouse_write(0xF3u) < 0) return -1;
    return ps2_mouse_write(rate);
}

static int ps2_mouse_set_resolution(uint8_t resolution) {
    if (ps2_mouse_write(0xE8u) < 0) return -1;
    return ps2_mouse_write((uint8_t)(resolution & 0x03u));
}

static int ps2_mouse_set_scaling(uint8_t scale) {
    return ps2_mouse_write(scale == 2 ? 0xE7u : 0xE6u);
}

static int ps2_mouse_get_status(uint8_t status[3]) {
    if (ps2_mouse_write(0xE9u) < 0) return -1;
    for (int i = 0; i < 3; ++i) {
        if (ps2_read_data_timeout(&status[i], 1) < 0) return -1;
    }
    return 0;
}

static int ps2_mouse_ext_command(uint8_t command) {
    if (ps2_mouse_set_resolution((uint8_t)((command >> 6) & 0x03u)) < 0) return -1;
    if (ps2_mouse_set_resolution((uint8_t)((command >> 4) & 0x03u)) < 0) return -1;
    if (ps2_mouse_set_resolution((uint8_t)((command >> 2) & 0x03u)) < 0) return -1;
    if (ps2_mouse_set_resolution((uint8_t)(command & 0x03u)) < 0) return -1;
    return 0;
}

static int ps2_probe_synaptics(void) {
#ifdef CONFIG_TOUCHPAD_SYNAPTICS
    uint8_t st[3];
    int major;

    /*
     * Synaptics PS/2 touchpads tunnel extended queries through four
     * SET_RESOLUTION commands followed by GET_STATUS.  This mirrors FreeBSD
     * psm's probe order and must run before IntelliMouse sample-rate probing.
     */
    if (ps2_mouse_set_scaling(1) < 0) return 0;
    if (ps2_mouse_ext_command(0x00u) < 0) return 0; /* READ_IDENTITY */
    if (ps2_mouse_get_status(st) < 0) return 0;
    if (st[1] != 0x47u) return 0;
    major = st[2] & 0x0f;
    if (major < 4) return 0;

    if (ps2_mouse_ext_command(0x03u) < 0) return 0; /* READ_MODEL_ID */
    if (ps2_mouse_get_status(st) < 0) return 0;
    if (st[1] & 0x01u) return 0;

    g_ps2_pointer_model = PS2_POINTER_SYNAPTICS;
    printf("[ps2] Synaptics touchpad detected v%d.%u sensor=%u hw=%u geom=%u\n",
           major, (uint32_t)st[0], (uint32_t)(st[0] & 0x3fu),
           (uint32_t)((st[1] & 0xfeu) >> 1), (uint32_t)(st[2] & 0x0fu));
    return 1;
#else
    return 0;
#endif
}

static int ps2_elantech_cmd(uint8_t hwversion, uint8_t cmd, uint8_t resp[3]) {
    if (hwversion == 2) {
        if (ps2_mouse_set_scaling(1) < 0) return -1;
        if (ps2_mouse_ext_command(cmd) < 0) return -1;
    } else {
        if (ps2_mouse_write(0xF8u) < 0) return -1;
        if (ps2_mouse_write(cmd) < 0) return -1;
    }
    return ps2_mouse_get_status(resp);
}

static int ps2_probe_elantech(void) {
#ifdef CONFIG_TOUCHPAD_ELAN
    static const uint8_t ic_to_hw[16] = { 0, 0, 2, 0, 2, 3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4 };
    uint8_t resp[3];
    uint8_t ic;
    uint8_t hw;
    uint32_t fw;

    /*
     * ELAN/Elantech touchpads advertise a magic GET_STATUS triplet after
     * three SET_SCALING_1_1 commands.  Probe this before generic mouse
     * negotiation; otherwise some firmware stops accepting vendor commands.
     */
    if (ps2_mouse_set_scaling(1) < 0) return 0;
    if (ps2_mouse_set_scaling(1) < 0) return 0;
    if (ps2_mouse_set_scaling(1) < 0) return 0;
    if (ps2_mouse_get_status(resp) < 0) return 0;
    if (resp[0] != 0x3cu || resp[1] != 0x03u || (resp[2] < 0xc8u || resp[2] > 0xcfu)) return 0;

    if (ps2_elantech_cmd(2, 0x01u, resp) < 0) return 0; /* FW_VERSION */
    fw = ((uint32_t)resp[0] << 16) | ((uint32_t)resp[1] << 8) | resp[2];
    if (fw < 0x020030u || fw == 0x020600u) return 0; /* v1 hardware, unsupported by FreeBSD too */
    ic = resp[0] & 0x0fu;
    hw = ic_to_hw[ic];
    if (!hw) return 0;

    g_ps2_pointer_model = PS2_POINTER_ELANTECH;
    printf("[ps2] ELAN touchpad detected hw=%u fw=0x%x clickpad=%u crc=%u\n",
           (uint32_t)hw, fw, (uint32_t)((resp[1] & 0x10u) != 0),
           (uint32_t)((resp[1] & 0x40u) != 0));
    return 1;
#else
    return 0;
#endif
}

static void ps2_mouse_reset_packet(void) {
    g_ps2_mouse_packet_index = 0;
}

static void ps2_mouse_handle_packet(const uint8_t *p, int packet_size) {
    int dx = (int)(int8_t)p[1];
    int dy = -(int)(int8_t)p[2];
    int wheel = (packet_size >= 4) ? (int)(int8_t)p[3] : 0;
    uint8_t buttons = (uint8_t)(p[0] & 0x07u);

    keyboard_mouse_emit_packet_ex(dx, dy, wheel, buttons, packet_size >= 4);
}

static void ps2_mouse_handle_byte(uint8_t data) {
    if (!g_ps2_mouse_present) return;
    /*
     * Standard PS/2 relative packets always set bit 3 in the first byte.
     * Resynchronize on packet headers so a missed IRQ12 or interleaved byte
     * does not corrupt the Linux /dev/input stream until the next reboot.
     */
    if (g_ps2_mouse_packet_index == 0 && (data & 0x08u) == 0) return;
    g_ps2_mouse_packet[g_ps2_mouse_packet_index++] = data;
    if (g_ps2_mouse_packet_index >= (uint8_t)g_ps2_mouse_packet_size) {
        ps2_mouse_handle_packet(g_ps2_mouse_packet, g_ps2_mouse_packet_size);
        ps2_mouse_reset_packet();
    }
}

static void ps2_mouse_init(void) {
    uint8_t cfg = 0;
    uint8_t bat = 0;
    uint8_t reset_id = 0;
    int id;

    g_ps2_mouse_present = 0;
    g_ps2_mouse_packet_size = 3;
    g_ps2_pointer_model = PS2_POINTER_GENERIC;
    ps2_mouse_reset_packet();
    if (!g_ps2_controller_present) return;

    keyboard_controller_write_cmd(0xA8u); /* enable second PS/2 port */
    keyboard_controller_write_cmd(0x20u);
    if (keyboard_wait_output_full() == 0) {
        cfg = inportb(KEYBOARD_DATA_PORT);
        cfg = (uint8_t)((cfg | 0x02u) & ~0x20u); /* IRQ12 on, AUX clock enabled */
        keyboard_controller_write_cmd(0x60u);
        keyboard_controller_write_data(cfg);
    }

    if (ps2_mouse_write(0xFFu) < 0) {
        printf("[ps2] mouse not present\n");
        return;
    }
    (void)ps2_read_data_timeout(&bat, 1);
    (void)ps2_read_data_timeout(&reset_id, 1);
    if (ps2_mouse_write(0xF6u) < 0) return; /* defaults before capability negotiation */

    if (!ps2_probe_synaptics()) {
        (void)ps2_probe_elantech();
    }

    /*
     * The 200/100/80 sample-rate sequence is the standard PS/2 IntelliMouse
     * negotiation used by real controllers and QEMU.  If unsupported, the
     * device remains a three-byte relative mouse and still works.
     */
    (void)ps2_mouse_set_sample_rate(200);
    (void)ps2_mouse_set_sample_rate(100);
    (void)ps2_mouse_set_sample_rate(80);
    id = ps2_mouse_read_id();
    g_ps2_mouse_packet_size = (id == 3 || id == 4) ? 4 : 3;
    if (g_ps2_pointer_model == PS2_POINTER_GENERIC && (id == 3 || id == 4)) {
        g_ps2_pointer_model = PS2_POINTER_INTELLIMOUSE;
    }

    if (ps2_mouse_write(0xF4u) < 0) return; /* stream reporting */
    g_ps2_mouse_present = 1;
    pic8259_unmask_irq(12);
    printf("[ps2] mouse ready id=%d packet=%d model=%s irq=12\n",
           id, g_ps2_mouse_packet_size, keyboard_mouse_device_name());
}
#endif

static void keyboard_controller_enable(void) {
    uint8_t cfg = 0;
    uint8_t keyboard_ack = 0;
    int have_cfg = 0;

    if (inportb(KEYBOARD_STATUS_PORT) == 0xFFu) {
        g_ps2_controller_present = 0;
        return;
    }

    /*
     * Linux userspace and EdgeOS' evdev path consume set-1 compatible
     * scancodes.  Some firmware and hypervisors, including VMware's virtual
     * PS/2 keyboard, leave the controller translation bit clear; in that state
     * the keyboard sends set-2 bytes and the console/Xorg see no useful keys.
     * Own the i8042 config here: enable IRQ1, enable the first port, and force
     * XLATE so the controller translates the keyboard stream to set 1.
     *
     * Avoid full controller reset/self-test during boot because firmware may
     * already have initialized the device and heavy reset sequences can break
     * USB legacy handoff on some virtual machines.
     */
    keyboard_controller_write_cmd(0xAE); /* enable first PS/2 port */

    keyboard_controller_write_cmd(0x20); /* read controller config byte */
    if (keyboard_wait_output_full() == 0) {
        cfg = inportb(KEYBOARD_DATA_PORT);
        have_cfg = 1;
        cfg = (uint8_t)((cfg | 0x41u) & ~0x10u); /* IRQ1 + XLATE on, port 1 enabled */
        keyboard_controller_write_cmd(0x60);
        keyboard_controller_write_data(cfg);
        keyboard_controller_write_cmd(0x20);
        if (keyboard_wait_output_full() == 0) {
            cfg = inportb(KEYBOARD_DATA_PORT);
        }
        g_ps2_keyboard_set2_mode = (cfg & 0x40u) ? 0 : 1;
    }

    keyboard_controller_write_data(0xF4); /* enable keyboard scanning */
    if (keyboard_wait_output_full() == 0) {
        keyboard_ack = inportb(KEYBOARD_DATA_PORT);
        if (keyboard_ack == 0xFAu) g_ps2_keyboard_present = 1;
        if (keyboard_ack != 0xFAu && keyboard_ack != 0xFEu) {
            keyboard_handle_scancode_ex((int)keyboard_ack, 1);
        }
    }
    printf("[ps2] keyboard controller ready cfg=0x%x xlate=%d irq1=%d set2=%d keyboard=%d\n",
           (uint32_t)cfg, have_cfg ? ((cfg & 0x40u) ? 1 : 0) : -1,
           have_cfg ? ((cfg & 0x01u) ? 1 : 0) : -1,
           g_ps2_keyboard_set2_mode, g_ps2_keyboard_present);
}

static int decode_scancode_to_char(int scancode) {
    int ch = 0;

    if (scancode == 0 || scancode == 0xE0) {
        if (scancode == 0xE0) g_extended = 1;
        return 0;
    }

    if (scancode & 0x80) {
        int released = scancode & 0x7F;
        if (released == SCAN_CODE_KEY_LEFT_SHIFT || released == SCAN_CODE_KEY_RIGHT_SHIFT) {
            g_shift_pressed = FALSE;
        }
        if (released == SCAN_CODE_KEY_LEFT_CTRL || released == SCAN_CODE_KEY_RIGHT_CTRL) {
            g_ctrl_pressed = FALSE;
        }
        if (released == SCAN_CODE_KEY_ALT) {
            g_alt_pressed = FALSE;
        }
        g_extended = 0;
        return 0;
    }

    if (scancode == SCAN_CODE_KEY_LEFT_SHIFT || scancode == SCAN_CODE_KEY_RIGHT_SHIFT) {
        g_shift_pressed = TRUE;
        return 0;
    }
    if (scancode == SCAN_CODE_KEY_LEFT_CTRL || scancode == SCAN_CODE_KEY_RIGHT_CTRL) {
        g_ctrl_pressed = TRUE;
        return 0;
    }
    if (scancode == SCAN_CODE_KEY_ALT) {
        g_alt_pressed = TRUE;
        return 0;
    }
    if (scancode == SCAN_CODE_KEY_CAPS_LOCK) {
        g_caps_lock = !g_caps_lock;
        return 0;
    }
    /*
     * Linux text consoles accept Alt+Fn for fast VT switching, but once an X
     * server owns a graphics VT plain Alt+F2 is a desktop shortcut and must be
     * delivered to evdev/Xorg.  Require Ctrl+Alt+Fn while any VT is in graphics
     * mode so XFCE shortcuts are not stolen by the kernel console path.
     */
    if (g_alt_pressed && (!syscall_console_any_vt_in_graphics() || g_ctrl_pressed)) {
        int vt = 0;
        if (scancode == SCAN_CODE_KEY_F1) vt = 1;
        else if (scancode == SCAN_CODE_KEY_F2) vt = 2;
        else if (scancode == SCAN_CODE_KEY_F3) vt = 3;
        else if (scancode == SCAN_CODE_KEY_F4) vt = 4;
        else if (scancode == SCAN_CODE_KEY_F5) vt = 5;
        else if (scancode == SCAN_CODE_KEY_F6) vt = 6;
        else if (scancode == SCAN_CODE_KEY_F7) vt = 7;
        if (vt != 0) {
            syscall_console_activate_vt(vt);
            return 0;
        }
    }

    if (g_extended) {
        if (scancode == 0x48) ch = 0x80;
        else if (scancode == 0x50) ch = 0x81;
        else if (scancode == 0x4B) ch = 0x82;
        else if (scancode == 0x4D) ch = 0x83;
        g_extended = 0;
    } else if (scancode < 128) {
        ch = g_scan_code_chars[scancode];
        if (ch >= 'a' && ch <= 'z') {
            if (g_caps_lock != g_shift_pressed) ch -= 32;
        } else if (g_shift_pressed) {
            ch = alternate_chars((char)ch);
        }
        if (g_ctrl_pressed && ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z'))) {
            char lo = (ch >= 'A' && ch <= 'Z') ? (char)(ch - 'A' + 'a') : (char)ch;
            ch = (lo - 'a') + 1;
        }
    }

    return ch;
}

char alternate_chars(char ch) {
    switch(ch) {
        case '`': return '~';
        case '1': return '!';
        case '2': return '@';
        case '3': return '#';
        case '4': return '$';
        case '5': return '%';
        case '6': return '^';
        case '7': return '&';
        case '8': return '*';
        case '9': return '(';
        case '0': return ')';
        case '-': return '_';
        case '=': return '+';
        case '[': return '{';
        case ']': return '}';
        case '\\': return '|';
        case ';': return ':';
        case '\'': return '\"';
        case ',': return '<';
        case '.': return '>';
        case '/': return '?';
        default: return ch;
    }
}

static void keyboard_handle_scancode_ex(int scancode, int emit_linux_input) {
    int ch = 0;
    static uint32_t handle_debug_budget = 0;
    int any_graphics;

    if (scancode == 0) return;
    /*
     * Hardware scancode producers are the source of truth for evdev events.
     * VirtIO input already supplies Linux input event codes, so it uses the
     * console-only path below to avoid duplicate /dev/input/event0 records
     * while still feeding tty0/fbcon login prompts.
     */
    if (emit_linux_input) {
        keyboard_emit_linux_event_from_scancode(scancode);
        mouse_emulate_from_scancode(scancode);
    }
    if (g_skip_irq_scancode != 0 && scancode == g_skip_irq_scancode) {
        g_skip_irq_scancode = 0;
        return;
    }
    g_scan_code = scancode;
    g_keyboard_irq_count++;
    g_keyboard_last_tsc = rdtsc64();

    ch = decode_scancode_to_char(scancode);
    any_graphics = syscall_console_any_vt_in_graphics();
    if (handle_debug_budget > 0) {
        handle_debug_budget--;
        printf("[kbd-handle] sc=0x%x emit=%d ch=0x%x graphics=%d head=%d tail=%d shift=%d ctrl=%d alt=%d budget=%u\n",
               scancode & 0xff, emit_linux_input, ch & 0xff, any_graphics,
               kbd_head, kbd_tail, g_shift_pressed, g_ctrl_pressed,
               g_alt_pressed, (unsigned)handle_debug_budget);
    }

    /*
     * Xorg switches the owning VT into KD_GRAPHICS and reads keyboard input
     * from /dev/input/event*.  Keep emitting Linux input events above, but do
     * not also feed the same key stream into the text console getty.  Without
     * this split, QEMU/xHCI typing appears in the hidden tty login underneath
     * X instead of the focused X client.
     */
    if (any_graphics) return;

    // Push decoded input to tty buffer.
    if (ch != 0) {
        if (ch == 3) g_sigint_pending++;
        if (ch == 0x80 || ch == 0x81 || ch == 0x82 || ch == 0x83) {
            /* Linux tty-compatible arrows: ESC [ A/B/C/D */
            kbd_buf_push_char(27);
            kbd_buf_push_char('[');
            if (ch == 0x80) kbd_buf_push_char('A');
            else if (ch == 0x81) kbd_buf_push_char('B');
            else if (ch == 0x82) kbd_buf_push_char('D');
            else kbd_buf_push_char('C');
            g_ch = 27;
        } else {
            g_ch = (char)ch; // legacy global compatibility
            kbd_buf_push_char((char)ch);
        }
        syscall_console_keyboard_input_ready();
    }
}

void keyboard_emit_scancode(uint8_t scancode) {
    keyboard_handle_scancode_ex((int)scancode, 1);
}

void keyboard_emit_scancode_console_only(uint8_t scancode) {
    keyboard_handle_scancode_ex((int)scancode, 0);
}

static void keyboard_drain_controller_locked(void) {
    for (int i = 0; i < 32; ++i) {
        uint8_t st;
        uint8_t data;
        if (!g_ps2_controller_present) break;
        st = inportb(KEYBOARD_STATUS_PORT);
        if (st == 0xFFu) {
            /*
             * Keep an initialized i8042 controller recoverable after a
             * transient all-bits-set status read.  Runtime polling and IRQ
             * delivery may overlap firmware or hypervisor state changes; a
             * single anomalous read must not silence every later evdev event.
             */
            break;
        }
        if ((st & 0x01) == 0) break;
        data = (uint8_t)get_scancode();
#ifdef CONFIG_PS2_MOUSE
        if (st & 0x20u) {
            ps2_mouse_handle_byte(data);
        } else
#endif
        {
            ps2_keyboard_handle_byte(data);
        }
    }
}

void keyboard_poll_controller(void) {
    uint64_t now_us;
    uint64_t flags;

    if (!g_ps2_controller_present) return;
    now_us = boottime_monotonic_us();
    if (__atomic_load_n(&g_ps2_fallback_poll_next_us, __ATOMIC_RELAXED) &&
        now_us < __atomic_load_n(&g_ps2_fallback_poll_next_us,
                                 __ATOMIC_RELAXED))
        return;

    /*
     * IRQ1/IRQ12 are the normal i8042 delivery path.  Keep a bounded fallback
     * poll for firmware and hypervisors that occasionally lose an edge, but do
     * not read port 0x64 on every poll(2) readiness pass.  Port I/O exits a
     * hardware-accelerated guest and made an idle Xorg session perform several
     * thousand VM exits per second.
     */
    flags = spin_lock_irqsave(&g_ps2_controller_lock);
    if (g_ps2_fallback_poll_next_us &&
        now_us < g_ps2_fallback_poll_next_us) {
        spin_unlock_irqrestore(&g_ps2_controller_lock, flags);
        return;
    }
    g_ps2_fallback_poll_next_us = now_us + 10000u;
    keyboard_drain_controller_locked();
    spin_unlock_irqrestore(&g_ps2_controller_lock, flags);
}

void keyboard_handler(REGISTERS *r) {
    uint64_t flags;
    (void)r;

    /*
     * QEMU and real i8042 controllers may leave more than one scancode queued
     * for a single IRQ, especially when a key stream is injected quickly.  If
     * we read only one byte here, later bytes can sit in the controller until a
     * future IRQ or be overwritten by new input, which looks like laggy typing
     * and dropped characters in userspace.  Drain a bounded batch from the
     * output buffer each interrupt, matching the usual Linux-style IRQ bottom
     * half behavior without spinning forever on a noisy controller.
     */
    flags = spin_lock_irqsave(&g_ps2_controller_lock);
    keyboard_drain_controller_locked();
    spin_unlock_irqrestore(&g_ps2_controller_lock, flags);
}

#ifdef CONFIG_PS2_MOUSE
static void ps2_mouse_irq_handler(REGISTERS *r) {
    uint64_t flags;
    (void)r;
    flags = spin_lock_irqsave(&g_ps2_controller_lock);
    keyboard_drain_controller_locked();
    spin_unlock_irqrestore(&g_ps2_controller_lock, flags);
}
#endif



void keyboard_init() {
    g_caps_lock = FALSE;
    g_shift_pressed = FALSE;
    g_ctrl_pressed = FALSE;
    g_alt_pressed = FALSE;
    g_ch = 0;
    g_scan_code = 0;
    g_extended = 0;
    g_keyboard_irq_count = 0;
    g_keyboard_last_tsc = rdtsc64();
    g_sigint_pending = 0;
    g_ps2_controller_present = 1;
    g_ps2_keyboard_present = 0;
    g_ps2_keyboard_set2_mode = 0;
    g_ps2_keyboard_set2_break = 0;
    g_ps2_keyboard_set2_e0 = 0;
    g_ps2_keyboard_debug_budget = 0;
    g_ps2_fallback_poll_next_us = 0;
    spinlock_init(&g_ps2_controller_lock);
    kbd_head = 0;
    kbd_tail = 0;
    mouse_head = 0;
    mouse_tail = 0;
    for (int i = 0; i < INPUT_EVENT_COUNT; ++i) {
        input_event_head[i] = 0;
        input_event_tail[i] = 0;
        input_event_sequence[i] = 0;
    }
    g_mouse_buttons = 0;
    g_mouse_ext_prefix = 0;
    if (kernel_boot_option_enabled("bsd_bridge.i8042", 0)) {
        g_ps2_controller_present = 0;
#ifdef CONFIG_PS2_MOUSE
        g_ps2_mouse_present = 0;
#endif
        printf("[ps2] native controller reserved for BSD bridge\n");
        return;
    }
    keyboard_controller_enable();
    if (g_ps2_keyboard_present) {
        input_device_describe_keyboard(
            &g_ps2_keyboard_description, "AT Translated Set 2 keyboard",
            "isa0060/serio0/input0", "atkbd", 0x11u, 0u, 0u, 0u);
        (void)input_device_register(EDGE_INPUT_KEYBOARD,
                                    &g_ps2_keyboard_description,
                                    &g_ps2_keyboard_present);
    }
#ifdef CONFIG_PS2_MOUSE
    ps2_mouse_init();
    if (g_ps2_mouse_present) {
        input_device_describe_pointer(
            &g_ps2_mouse_description, keyboard_mouse_device_name(),
            "isa0060/serio1/input0", "psmouse", 0x11u, 0u, 0u, 0u, 0);
        (void)input_device_register(EDGE_INPUT_POINTER,
                                    &g_ps2_mouse_description,
                                    &g_ps2_mouse_present);
    }
#endif
    {
        uint64_t flags = spin_lock_irqsave(&g_ps2_controller_lock);
        keyboard_drain_controller_locked();
        spin_unlock_irqrestore(&g_ps2_controller_lock, flags);
    }
    isr_register_interrupt_handler(IRQ_BASE + 1, keyboard_handler);
#ifdef CONFIG_PS2_MOUSE
    if (g_ps2_mouse_present) isr_register_interrupt_handler(IRQ_BASE + 12, ps2_mouse_irq_handler);
#endif
}

// A blocking character read
char kb_getchar() {
    char c;

    while(g_ch <= 0) {
        __asm__ __volatile__("sti; hlt");
    }
    c = g_ch;
    g_ch = 0;
    g_scan_code = 0;
    return c;
}

char kb_get_scancode() {
    char code;

    while(g_scan_code <= 0) {
        __asm__ __volatile__("sti; hlt");
    }
    code = g_scan_code;
    g_ch = 0;
    g_scan_code = 0;
    return code;
}

int kb_read_event(char *ch, char *scan, int blocking) {
    while (g_scan_code == 0) {
        if (!blocking) return 0;
        __asm__ __volatile__("sti; hlt");
    }
    if (ch) *ch = g_ch;
    if (scan) *scan = g_scan_code;
    g_ch = 0;
    g_scan_code = 0;
    return 1;
}

int keyboard_getchar(void) {
    int ch;
    unsigned long flags;

    keyboard_poll_external_input();
    keyboard_poll_controller();

    // Critical section: disable interrupts while modifying tail
    __asm__ __volatile__("pushfq; popq %0; cli" : "=r"(flags) :: "memory");
    if (kbd_head == kbd_tail) {
        // Restore interrupts
        __asm__ __volatile__("pushq %0; popfq" :: "r"(flags) : "memory");
        return -1; 
    }

    ch = (unsigned char)kbd_buf[kbd_tail];
    kbd_tail = (kbd_tail + 1) % KBD_BUF_SIZE;

    __asm__ __volatile__("pushq %0; popfq" :: "r"(flags) : "memory");

    return ch;
}

int keyboard_pollchar(void) {
    return keyboard_getchar();
}

int keyboard_haschar(void) {
    int has;
    unsigned long flags;
    keyboard_poll_external_input();
    keyboard_poll_controller();
    __asm__ __volatile__("pushfq; popq %0; cli" : "=r"(flags) :: "memory");
    has = (kbd_head != kbd_tail) ? 1 : 0;
    __asm__ __volatile__("pushq %0; popfq" :: "r"(flags) : "memory");
    return has;
}

int keyboard_mouse_pending(void) {
    int n;
    unsigned long flags;
    keyboard_poll_controller();
    __asm__ __volatile__("pushfq; popq %0; cli" : "=r"(flags) :: "memory");
    n = mouse_head - mouse_tail;
    if (n < 0) n += MOUSE_BUF_SIZE;
    __asm__ __volatile__("pushq %0; popfq" :: "r"(flags) : "memory");
    return n;
}

int keyboard_mouse_read(char *out, uint32_t max, int blocking) {
    uint32_t n = 0;
    if (!out || max == 0) return 0;
    while (n < max) {
        int have;
        unsigned long flags;
        keyboard_poll_controller();
        __asm__ __volatile__("pushfq; popq %0; cli" : "=r"(flags) :: "memory");
        have = (mouse_head != mouse_tail);
        if (have) {
            out[n++] = (char)mouse_buf[mouse_tail];
            mouse_tail = (mouse_tail + 1) % MOUSE_BUF_SIZE;
        }
        __asm__ __volatile__("pushq %0; popfq" :: "r"(flags) : "memory");
        if (!have) {
            if (n > 0 || !blocking) break;
            __asm__ __volatile__("sti; hlt");
        }
    }
    return (int)n;
}

int keyboard_event_pending(int event_id) {
    keyboard_poll_external_input();
    return keyboard_event_pending_from(event_id, input_event_tail[event_id]);
}

int keyboard_event_cursor_init(int event_id) {
    int tail;
    unsigned long flags;
    if (event_id < 0 || event_id >= INPUT_EVENT_COUNT) return 0;
    __asm__ __volatile__("pushfq; popq %0; cli" : "=r"(flags) :: "memory");
    tail = input_event_head[event_id];
    __asm__ __volatile__("pushq %0; popfq" :: "r"(flags) : "memory");
    return tail;
}

uint32_t keyboard_event_sequence(int event_id) {
    uint32_t sequence;
    unsigned long flags;
    if (event_id < 0 || event_id >= INPUT_EVENT_COUNT) return 0;
    __asm__ __volatile__("pushfq; popq %0; cli" : "=r"(flags) :: "memory");
    sequence = input_event_sequence[event_id];
    __asm__ __volatile__("pushq %0; popfq" :: "r"(flags) : "memory");
    return sequence;
}

int keyboard_event_pending_from(int event_id, int tail) {
    int n;
    unsigned long flags;
    if (event_id < 0 || event_id >= INPUT_EVENT_COUNT) return 0;
    if (tail < 0 || tail >= (int)INPUT_EVENT_BUF_SIZE) tail = input_event_head[event_id];
    keyboard_poll_external_input();
    keyboard_poll_controller();
    __asm__ __volatile__("pushfq; popq %0; cli" : "=r"(flags) :: "memory");
    if (!input_event_buf_cursor_valid_locked(event_id, tail)) {
        n = 0;
    } else {
        n = input_event_buf_pending_locked(event_id, tail);
    }
    __asm__ __volatile__("pushq %0; popfq" :: "r"(flags) : "memory");
    return n;
}

int keyboard_event_read(int event_id, char *out, uint32_t max, int blocking) {
    return keyboard_event_read_from_clock(
        event_id, (int *)&input_event_tail[event_id], LINUX_CLOCK_REALTIME,
        out, max, blocking);
}

int keyboard_event_read_from(int event_id, int *tail, char *out, uint32_t max, int blocking) {
    return keyboard_event_read_from_clock(event_id, tail, LINUX_CLOCK_REALTIME,
                                          out, max, blocking);
}

int keyboard_event_read_from_clock(int event_id, int *tail, int clock_id,
                                   char *out, uint32_t max, int blocking) {
    uint32_t n = 0;
    static uint32_t read_debug_budget[INPUT_EVENT_COUNT];
    if (event_id < 0 || event_id >= INPUT_EVENT_COUNT) return 0;
    if (!tail || !out || max == 0) return 0;
    if (!linux_evdev_clock_supported(clock_id)) return 0;
    max -= max % EDGE_LINUX_INPUT_EVENT_SIZE;
    if (max == 0) return 0;
    while (n + EDGE_LINUX_INPUT_EVENT_SIZE <= max) {
        int pending;
        int local_tail;
        unsigned long flags;
        keyboard_poll_external_input();
        keyboard_poll_controller();
        __asm__ __volatile__("pushfq; popq %0; cli" : "=r"(flags) :: "memory");
        local_tail = *tail;
        if (local_tail < 0 || local_tail >= (int)INPUT_EVENT_BUF_SIZE) local_tail = input_event_head[event_id];
        if (!input_event_buf_cursor_valid_locked(event_id, local_tail)) {
            /*
             * The fd missed at least one retained-window wrap.  Use the
             * oldest still-valid record rather than the producer head so a
             * lagging but active desktop still receives fresh input after
             * recovery instead of waiting for a second event.
             */
            local_tail = input_event_tail[event_id];
            *tail = local_tail;
        }
        pending = input_event_buf_pending_locked(event_id, local_tail);
        if ((pending % (int)EDGE_LINUX_INPUT_EVENT_SIZE) != 0) {
            /*
             * A stale per-open tail may survive an old ring overflow.  Real
             * evdev never returns partial records, so resync to the current
             * producer head instead of feeding malformed records to Xorg.
             */
            local_tail = input_event_head[event_id];
            *tail = local_tail;
            pending = 0;
        }
        if (pending >= (int)EDGE_LINUX_INPUT_EVENT_SIZE) {
            uint32_t record_offset = n;
            for (uint32_t i = 0; i < EDGE_LINUX_INPUT_EVENT_SIZE; ++i) {
                out[n++] = (char)input_event_buf[event_id][local_tail];
                local_tail = (local_tail + 1) % INPUT_EVENT_BUF_SIZE;
            }
            if (clock_id != LINUX_CLOCK_MONOTONIC &&
                clock_id != LINUX_CLOCK_BOOTTIME) {
                edge_linux_input_event_t event;
                uint64_t monotonic_us;
                uint64_t realtime_us;
                uint64_t selected_us;
                memcpy(&event, out + record_offset, sizeof(event));
                monotonic_us = (uint64_t)event.tv_sec * 1000000u +
                               (uint64_t)event.tv_usec;
                realtime_us = monotonic_us + boottime_realtime_us() -
                              boottime_monotonic_us();
                selected_us = linux_evdev_timestamp_us(
                    clock_id, realtime_us, monotonic_us);
                event.tv_sec = (int64_t)(selected_us / 1000000u);
                event.tv_usec = (int64_t)(selected_us % 1000000u);
                memcpy(out + record_offset, &event, sizeof(event));
            }
            *tail = local_tail;
        }
        __asm__ __volatile__("pushq %0; popfq" :: "r"(flags) : "memory");
        if (pending < (int)EDGE_LINUX_INPUT_EVENT_SIZE) {
            if (n > 0 || !blocking) break;
            __asm__ __volatile__("sti; hlt");
        }
    }
    if (n > 0 && read_debug_budget[event_id]) {
        printf("[evdev-read] event%d bytes=%u tail=%d head=%d\n",
               event_id, n, tail ? *tail : -1, input_event_head[event_id]);
        read_debug_budget[event_id]--;
    }
    return (int)n;
}

int keyboard_mouse_event_pending(void) {
    return keyboard_event_pending(INPUT_EVENT_MOUSE);
}

int keyboard_mouse_event_read(char *out, uint32_t max, int blocking) {
    return keyboard_event_read(INPUT_EVENT_MOUSE, out, max, blocking);
}

uint8_t keyboard_mouse_buttons(void) {
    return g_mouse_buttons;
}

const char *keyboard_mouse_device_name(void) {
#ifdef CONFIG_PS2_MOUSE
    if (g_ps2_mouse_present || g_ps2_pointer_model != PS2_POINTER_GENERIC) {
        if (g_ps2_pointer_model == PS2_POINTER_SYNAPTICS) return "EdgeOS Synaptics PS/2 Touchpad";
        if (g_ps2_pointer_model == PS2_POINTER_ELANTECH) return "EdgeOS ELAN PS/2 Touchpad";
        if (g_ps2_pointer_model == PS2_POINTER_INTELLIMOUSE) return "EdgeOS PS/2 IntelliMouse";
        return "EdgeOS PS/2 Mouse";
    }
#endif
    return "EdgeOS xHCI mouse";
}

uint32_t keyboard_take_sigint_pending(void) {
    uint32_t v;
    unsigned long flags;
    __asm__ __volatile__("pushfq; popq %0; cli" : "=r"(flags) :: "memory");
    v = g_sigint_pending;
    g_sigint_pending = 0;
    __asm__ __volatile__("pushq %0; popfq" :: "r"(flags) : "memory");
    return v;
}

uint64_t keyboard_entropy_irq_count(void) {
    return g_keyboard_irq_count;
}

uint64_t keyboard_entropy_last_tsc(void) {
    return g_keyboard_last_tsc;
}
