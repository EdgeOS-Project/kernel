#include "serial_console.h"

#include "arch/x86_64/pic.h"
#include "arch/x86_64/io_ports.h"
#include "arch/x86_64/isr.h"
#include "stdio.h"
#include "sys/spinlock.h"
#include "types.h"

#define SERIAL_COM1_BASE 0x3F8u
#define SERIAL_REG_DATA 0u
#define SERIAL_REG_IER 1u
#define SERIAL_REG_FIFO 2u
#define SERIAL_REG_LCR 3u
#define SERIAL_REG_MCR 4u
#define SERIAL_REG_LSR 5u
#define SERIAL_REG_SCR 7u

#define SERIAL_LCR_DLAB 0x80u
#define SERIAL_LCR_8N1 0x03u
#define SERIAL_MCR_DTR 0x01u
#define SERIAL_MCR_RTS 0x02u
#define SERIAL_MCR_OUT2 0x08u
#define SERIAL_FIFO_ENABLE 0x01u
#define SERIAL_FIFO_CLEAR_RX 0x02u
#define SERIAL_FIFO_CLEAR_TX 0x04u
#define SERIAL_FIFO_TRIGGER_1 0x00u
#define SERIAL_LSR_DATA_READY 0x01u
#define SERIAL_LSR_OVERRUN_ERROR 0x02u
#define SERIAL_LSR_PARITY_ERROR 0x04u
#define SERIAL_LSR_FRAMING_ERROR 0x08u
#define SERIAL_LSR_BREAK_INTERRUPT 0x10u
#define SERIAL_LSR_THR_EMPTY 0x20u
#define SERIAL_LSR_RX_ERROR_MASK (SERIAL_LSR_OVERRUN_ERROR | SERIAL_LSR_PARITY_ERROR | SERIAL_LSR_FRAMING_ERROR | SERIAL_LSR_BREAK_INTERRUPT)
#define SERIAL_IER_RX_AVAILABLE 0x01u

#define SERIAL_RX_BUF_SIZE 8192
#define SERIAL_RX_LOG_BUDGET 16
#define SERIAL_TX_SPIN_LIMIT 64
#define SERIAL_RX_IDLE_SPIN_LIMIT 64

static int g_serial_ready;
static uint8 g_last_tx_was_cr;
static char g_serial_rx_buf[SERIAL_RX_BUF_SIZE];
static volatile int g_serial_rx_head;
static volatile int g_serial_rx_tail;
static spinlock_t g_serial_rx_lock;
static volatile uint32 g_serial_rx_drops;
static volatile uint32 g_serial_rx_high_water;
static volatile uint32 g_serial_rx_total;
static volatile uint32 g_serial_tx_total;
static volatile uint32 g_serial_tx_drops;
static volatile uint32 g_serial_rx_lsr_errors;
static volatile uint32 g_serial_rx_overruns;
static volatile uint32 g_serial_irq_count;
static uint32 g_serial_rx_logged_drops;
static uint32 g_serial_rx_logged_high_water;
static uint32 g_serial_rx_logged_lsr_errors;
static uint32 g_serial_rx_logged_overruns;
static uint32 g_serial_rx_log_budget;
static uint32 g_serial_rx_byte_trace_budget;

static int serial_proc_append(char *buf, unsigned int max, unsigned int *off, const char *s) {
    unsigned int p;
    if (!buf || !off || !s || max == 0) return -1;
    p = *off;
    if (p >= max) return -1;
    while (*s) {
        if (p + 1 >= max) return -1;
        buf[p++] = *s++;
    }
    buf[p] = 0;
    *off = p;
    return 0;
}

static int serial_proc_append_u32(char *buf, unsigned int max, unsigned int *off, uint32 v) {
    char tmp[16];
    int n = 0;
    if (v == 0) {
        tmp[n++] = '0';
    } else {
        while (v && n < (int)sizeof(tmp)) {
            tmp[n++] = (char)('0' + (v % 10u));
            v /= 10u;
        }
    }
    while (n > 0) {
        char c[2];
        c[0] = tmp[--n];
        c[1] = 0;
        if (serial_proc_append(buf, max, off, c) < 0) return -1;
    }
    return 0;
}

static uint16 serial_port(uint16 reg) {
    return (uint16)(SERIAL_COM1_BASE + reg);
}

static int serial_rx_count_locked(void) {
    if (g_serial_rx_head >= g_serial_rx_tail) {
        return g_serial_rx_head - g_serial_rx_tail;
    }
    return SERIAL_RX_BUF_SIZE - g_serial_rx_tail + g_serial_rx_head;
}

static void serial_rx_push_locked(char ch) {
    int next_head;

    next_head = (g_serial_rx_head + 1) % SERIAL_RX_BUF_SIZE;
    if (next_head != g_serial_rx_tail) {
        g_serial_rx_buf[g_serial_rx_head] = ch;
        g_serial_rx_head = next_head;
        g_serial_rx_total++;
        {
            uint32 count = (uint32)serial_rx_count_locked();
            if (count > g_serial_rx_high_water) g_serial_rx_high_water = count;
        }
    } else {
        /*
         * Linux's tty flip buffers tolerate pasted shell/config input far beyond
         * a hardware FIFO.  Dropping here corrupts the login shell command stream
         * and can leave scripted X11 bring-up waiting forever for a marker that
         * was truncated.  Keep a counter so the foreground read path can report
         * any remaining overruns without printing from IRQ context.
         */
        g_serial_rx_drops++;
    }
}

static void serial_rx_push(char ch) {
    uint64_t flags = spin_lock_irqsave(&g_serial_rx_lock);
    serial_rx_push_locked(ch);
    spin_unlock_irqrestore(&g_serial_rx_lock, flags);
}

static int serial_rx_pop(void) {
    uint64_t flags;
    int ch = -1;

    flags = spin_lock_irqsave(&g_serial_rx_lock);
    if (g_serial_rx_head != g_serial_rx_tail) {
        ch = (unsigned char)g_serial_rx_buf[g_serial_rx_tail];
        g_serial_rx_tail = (g_serial_rx_tail + 1) % SERIAL_RX_BUF_SIZE;
    }
    spin_unlock_irqrestore(&g_serial_rx_lock, flags);
    return ch;
}

static int serial_rx_pending(void) {
    uint64_t flags;
    int has;

    flags = spin_lock_irqsave(&g_serial_rx_lock);
    has = (g_serial_rx_head != g_serial_rx_tail) ? 1 : 0;
    spin_unlock_irqrestore(&g_serial_rx_lock, flags);
    return has;
}

static void serial_fill_rx(void) {
    uint64_t flags;
    int idle = 0;
    if (!g_serial_ready) return;
    /*
     * QEMU's PTY backend can present interactive input one byte at a time with
     * small gaps.  A single LSR check is too brittle for getty-style reads:
     * the kernel may consume 'r', miss the immediately following 'oot\n', and
     * then sleep/poll in a way that makes login look stuck.  Drain until the
     * UART has been idle for a short bounded window.
     */
    flags = spin_lock_irqsave(&g_serial_rx_lock);
    while (idle < SERIAL_RX_IDLE_SPIN_LIMIT) {
        uint8 lsr = inportb(serial_port(SERIAL_REG_LSR));
        if ((lsr & SERIAL_LSR_RX_ERROR_MASK) != 0) {
            g_serial_rx_lsr_errors++;
            if ((lsr & SERIAL_LSR_OVERRUN_ERROR) != 0) g_serial_rx_overruns++;
        }
        if ((lsr & SERIAL_LSR_DATA_READY) != 0) {
            char ch = (char)inportb(serial_port(SERIAL_REG_DATA));
            if (g_serial_rx_byte_trace_budget > 0) {
                printf("[serial][rx-byte] ch=0x%x total=%u\n",
                       (uint32)(uint8)ch, g_serial_rx_total + 1u);
                g_serial_rx_byte_trace_budget--;
            }
            serial_rx_push_locked(ch);
            idle = 0;
        } else {
            ++idle;
            __asm__ __volatile__("pause");
        }
    }
    spin_unlock_irqrestore(&g_serial_rx_lock, flags);
}

static int serial_probe_rx_once(void) {
    uint64_t flags;
    uint8 lsr;
    if (!g_serial_ready) return 0;
    if (serial_rx_pending()) return 1;
    /*
     * Readiness checks run from timer and poll/select paths where Linux would
     * normally rely on tty wait queues.  They only need to notice that input
     * exists, not wait for an inter-byte quiet window.  Keep this to one LSR
     * read so an idle serial console does not burn host CPU in QEMU's port I/O
     * path; the real read path still calls serial_fill_rx() and drains fully.
     */
    flags = spin_lock_irqsave(&g_serial_rx_lock);
    lsr = inportb(serial_port(SERIAL_REG_LSR));
    if ((lsr & SERIAL_LSR_RX_ERROR_MASK) != 0) {
        g_serial_rx_lsr_errors++;
        if ((lsr & SERIAL_LSR_OVERRUN_ERROR) != 0) g_serial_rx_overruns++;
    }
    if ((lsr & SERIAL_LSR_DATA_READY) != 0) {
        serial_rx_push_locked((char)inportb(serial_port(SERIAL_REG_DATA)));
    }
    spin_unlock_irqrestore(&g_serial_rx_lock, flags);
    return serial_rx_pending();
}

static void serial_irq_handler(REGISTERS *r) {
    (void)r;
    g_serial_irq_count++;
    /*
     * COM1 is still safe to poll, but QEMU and real 16550-compatible UARTs
     * signal receive availability through IRQ4.  Draining the FIFO from the
     * IRQ path prevents short login strings from stalling after the first few
     * bytes when the foreground console is waiting in a userspace read.
     */
    serial_fill_rx();
}

static void serial_write_hw(char ch) {
    int spins = 0;
    uint8 lsr;
    if (!g_serial_ready) return;
    /*
     * EdgeOS currently performs console echo/output synchronously.  While the
     * login shell echoes a pasted command, QEMU can continue feeding COM1 and a
     * 16550 FIFO can overrun before the next userspace read poll.  Linux avoids
     * this with interrupt-driven flip buffers; opportunistically drain RX before
     * blocking on TX so serial output cannot starve serial input.
     */
    lsr = inportb(serial_port(SERIAL_REG_LSR));
    if ((lsr & (SERIAL_LSR_DATA_READY | SERIAL_LSR_RX_ERROR_MASK)) != 0) {
        serial_fill_rx();
    }
    while ((lsr & SERIAL_LSR_THR_EMPTY) == 0) {
        /*
         * Console serial output is diagnostic I/O.  It must not be able to
         * stop Linux userspace when QEMU's PTY or a real UART cannot accept
         * more bytes.  Linux 8250 uses an interrupt-driven tty layer; EdgeOS
         * still polls, so keep a short grace period and account dropped bytes
         * instead of spinning in port I/O for whole scheduler ticks.
         */
        if (++spins >= SERIAL_TX_SPIN_LIMIT) {
            g_serial_tx_drops++;
            return;
        }
        __asm__ __volatile__("pause");
        lsr = inportb(serial_port(SERIAL_REG_LSR));
    }
    outportb(serial_port(SERIAL_REG_DATA), (uint8)ch);
}

static void serial_write_hw_emergency(char ch) {
    int spins = 0;
    uint8 lsr;
    if (!g_serial_ready) return;
    /*
     * Exception and panic paths must not enter the normal tty RX path.  The
     * normal serial writer opportunistically drains RX and takes the RX lock so
     * pasted serial commands are not lost, but doing that while already inside
     * an exception handler can recursively fault or deadlock diagnostics.  This
     * emergency writer only waits briefly for TX space and emits the byte.
     */
    lsr = inportb(serial_port(SERIAL_REG_LSR));
    while ((lsr & SERIAL_LSR_THR_EMPTY) == 0) {
        if (++spins >= SERIAL_TX_SPIN_LIMIT) {
            g_serial_tx_drops++;
            return;
        }
        __asm__ __volatile__("pause");
        lsr = inportb(serial_port(SERIAL_REG_LSR));
    }
    outportb(serial_port(SERIAL_REG_DATA), (uint8)ch);
}

void serial_console_init(void) {
    uint8 saved_scr;

    g_serial_ready = 0;
    g_last_tx_was_cr = 0;
    spinlock_init(&g_serial_rx_lock);
    g_serial_rx_head = 0;
    g_serial_rx_tail = 0;
    g_serial_rx_drops = 0;
    g_serial_rx_high_water = 0;
    g_serial_rx_total = 0;
    g_serial_tx_total = 0;
    g_serial_tx_drops = 0;
    g_serial_rx_lsr_errors = 0;
    g_serial_rx_overruns = 0;
    g_serial_irq_count = 0;
    g_serial_rx_logged_drops = 0;
    g_serial_rx_logged_high_water = 0;
    g_serial_rx_logged_lsr_errors = 0;
    g_serial_rx_logged_overruns = 0;
    g_serial_rx_log_budget = SERIAL_RX_LOG_BUDGET;
    g_serial_rx_byte_trace_budget = 0;

    outportb(serial_port(SERIAL_REG_IER), 0x00);
    outportb(serial_port(SERIAL_REG_LCR), SERIAL_LCR_DLAB);
    outportb(serial_port(SERIAL_REG_DATA), 0x01);
    outportb(serial_port(SERIAL_REG_IER), 0x00);
    outportb(serial_port(SERIAL_REG_LCR), SERIAL_LCR_8N1);
    /*
     * The serial tty is polled, not IRQ-driven. A high FIFO trigger can leave
     * short interactive inputs such as "root\n" pending below the trigger level
     * and make getty appear stuck after the first echoed byte. Linux 8250 uses
     * IRQs for higher trigger levels; keep EdgeOS polling conservative.
     */
    outportb(serial_port(SERIAL_REG_FIFO),
             SERIAL_FIFO_ENABLE | SERIAL_FIFO_CLEAR_RX | SERIAL_FIFO_CLEAR_TX | SERIAL_FIFO_TRIGGER_1);
    outportb(serial_port(SERIAL_REG_MCR), SERIAL_MCR_DTR | SERIAL_MCR_RTS | SERIAL_MCR_OUT2);

    saved_scr = inportb(serial_port(SERIAL_REG_SCR));
    outportb(serial_port(SERIAL_REG_SCR), 0x5A);
    if (inportb(serial_port(SERIAL_REG_SCR)) != 0x5A) {
        outportb(serial_port(SERIAL_REG_SCR), saved_scr);
        return;
    }
    outportb(serial_port(SERIAL_REG_SCR), 0xA5);
    if (inportb(serial_port(SERIAL_REG_SCR)) != 0xA5) {
        outportb(serial_port(SERIAL_REG_SCR), saved_scr);
        return;
    }
    outportb(serial_port(SERIAL_REG_SCR), saved_scr);

    g_serial_ready = 1;
    isr_register_interrupt_handler(IRQ_BASE + IRQ4_SERIAL_PORT1, serial_irq_handler);
    pic8259_unmask_irq(IRQ4_SERIAL_PORT1);
    outportb(serial_port(SERIAL_REG_IER), SERIAL_IER_RX_AVAILABLE);
    serial_fill_rx();
}

int serial_console_is_ready(void) {
    return g_serial_ready;
}

void serial_console_write_raw(char ch) {
    if (!g_serial_ready) return;
    if (ch == '\n' && !g_last_tx_was_cr) serial_write_hw('\r');
    serial_write_hw(ch);
    g_serial_tx_total++;
    g_last_tx_was_cr = (ch == '\r') ? 1u : 0u;
}

void serial_console_write_emergency(char ch) {
    if (!g_serial_ready) return;
    if (ch == '\n') serial_write_hw_emergency('\r');
    serial_write_hw_emergency(ch);
}

void serial_console_clear(void) {
    if (!g_serial_ready) return;
    serial_console_write_raw('\033');
    serial_console_write_raw('[');
    serial_console_write_raw('2');
    serial_console_write_raw('J');
    serial_console_write_raw('\033');
    serial_console_write_raw('[');
    serial_console_write_raw('H');
}

int serial_console_pollchar(void) {
    uint32 drops;
    uint32 high_water;
    uint32 total;
    uint32 lsr_errors;
    uint32 overruns;
    uint32 irqs;
    /*
     * Consume the tty flip/ring buffer first.  Linux does not re-poll the UART
     * hardware and wait for an inter-byte idle window for every byte already in
     * the line discipline path; it drains buffered input cheaply and only goes
     * back to the device when the software buffer is empty.  Doing the full
     * serial_fill_rx() spin per canonical byte makes large but ordinary serial
     * pastes, such as init scripts sent through the console while Xorg is busy,
     * take seconds to minutes and can starve GUI bring-up.
     *
     * Red flag: keep this generic to the serial tty.  Do not key behavior on
     * shells, Xorg, XFCE, rootfs files, or verifier markers; those are just
     * consumers of the Linux-compatible tty ABI.
     */
    if (!serial_rx_pending()) {
        serial_fill_rx();
    }
    drops = g_serial_rx_drops;
    high_water = g_serial_rx_high_water;
    total = g_serial_rx_total;
    lsr_errors = g_serial_rx_lsr_errors;
    overruns = g_serial_rx_overruns;
    irqs = g_serial_irq_count;
    if (g_serial_rx_log_budget > 0 &&
        (drops != g_serial_rx_logged_drops ||
         lsr_errors != g_serial_rx_logged_lsr_errors ||
         overruns != g_serial_rx_logged_overruns ||
         (high_water >= (SERIAL_RX_BUF_SIZE * 3u) / 4u &&
          high_water != g_serial_rx_logged_high_water))) {
        printf("[serial][rx] total=%u high=%u/%u drops=%u lsrerr=%u overrun=%u irq=%u\n",
               total, high_water, (uint32)SERIAL_RX_BUF_SIZE, drops, lsr_errors, overruns, irqs);
        g_serial_rx_logged_drops = drops;
        g_serial_rx_logged_high_water = high_water;
        g_serial_rx_logged_lsr_errors = lsr_errors;
        g_serial_rx_logged_overruns = overruns;
        g_serial_rx_log_budget--;
    }
    return serial_rx_pop();
}

int serial_console_haschar(void) {
    /*
     * Readiness checks can be hot from select/poll/tty wait paths.  If the
     * software ring already has input, report it immediately instead of taking
     * the expensive bounded UART drain again.  A one-shot hardware probe is
     * sufficient to recover from a missed UART edge; the interrupt and read
     * paths still drain a complete burst.
     */
    return serial_probe_rx_once();
}

int serial_console_probechar(void) {
    return serial_probe_rx_once();
}

int serial_console_buffered(void) {
    return serial_rx_pending();
}

void serial_console_inject_input(const char *s) {
    if (!s) return;
    while (*s) {
        serial_rx_push(*s++);
    }
}

int serial_console_proc_snapshot(char *buf, unsigned int max) {
    unsigned int off = 0;
    uint32 rx_total;
    uint32 tx_total;
    uint32 tx_drops;
    uint32 drops;
    uint32 high_water;
    uint32 lsr_errors;
    uint32 overruns;
    uint32 irqs;
    uint64_t flags;
    if (!buf || max == 0) return -1;
    buf[0] = 0;
    if (serial_proc_append(buf, max, &off, "serinfo:1.0 driver revision:\n") < 0) return -1;
    /*
     * Linux exposes /proc/tty/driver/serial as a diagnostic view of the UART
     * driver, not as a hardware probe API.  Report only the COM1-compatible
     * port EdgeOS actually initializes; if the scratch-register probe failed,
     * keep the line visibly unknown rather than pretending a live 16550 exists.
     */
    if (!g_serial_ready) {
        if (serial_proc_append(buf, max, &off, "0: uart:unknown port:000003F8 irq:4 tx:0 rx:0\n") < 0) return -1;
        return (int)off;
    }
    flags = spin_lock_irqsave(&g_serial_rx_lock);
    rx_total = g_serial_rx_total;
    tx_total = g_serial_tx_total;
    tx_drops = g_serial_tx_drops;
    drops = g_serial_rx_drops;
    high_water = g_serial_rx_high_water;
    lsr_errors = g_serial_rx_lsr_errors;
    overruns = g_serial_rx_overruns;
    irqs = g_serial_irq_count;
    spin_unlock_irqrestore(&g_serial_rx_lock, flags);
    if (serial_proc_append(buf, max, &off, "0: uart:16550A port:000003F8 irq:4 tx:") < 0) return -1;
    if (serial_proc_append_u32(buf, max, &off, tx_total) < 0) return -1;
    if (tx_drops) {
        if (serial_proc_append(buf, max, &off, " txdrop:") < 0) return -1;
        if (serial_proc_append_u32(buf, max, &off, tx_drops) < 0) return -1;
    }
    if (serial_proc_append(buf, max, &off, " rx:") < 0) return -1;
    if (serial_proc_append_u32(buf, max, &off, rx_total) < 0) return -1;
    if (drops) {
        if (serial_proc_append(buf, max, &off, " brk:0 oe:") < 0) return -1;
        if (serial_proc_append_u32(buf, max, &off, drops) < 0) return -1;
    }
    if (overruns || lsr_errors) {
        if (serial_proc_append(buf, max, &off, " fe:") < 0) return -1;
        if (serial_proc_append_u32(buf, max, &off, lsr_errors) < 0) return -1;
        if (serial_proc_append(buf, max, &off, " pe:0") < 0) return -1;
    }
    if (serial_proc_append(buf, max, &off, " RTS|DTR") < 0) return -1;
    if (serial_proc_append(buf, max, &off, " irq:") < 0) return -1;
    if (serial_proc_append_u32(buf, max, &off, irqs) < 0) return -1;
    if (serial_proc_append(buf, max, &off, " high:") < 0) return -1;
    if (serial_proc_append_u32(buf, max, &off, high_water) < 0) return -1;
    if (serial_proc_append(buf, max, &off, "\n") < 0) return -1;
    return (int)off;
}
