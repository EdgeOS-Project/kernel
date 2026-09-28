/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux i386 time32 and time64 UAPI probe. */

#include <stdint.h>

#define SYS_exit 1
#define SYS_write 4
#define SYS_open 5
#define SYS_close 6
#define SYS_unlink 10
#define SYS_time 13
#define SYS_alarm 27
#define SYS_utime 30
#define SYS_mkdir 39
#define SYS_uname 122
#define SYS_adjtimex 124
#define SYS_rt_sigtimedwait 177
#define SYS_gettimeofday 78
#define SYS_setitimer 104
#define SYS_getitimer 105
#define SYS_sched_rr_get_interval 161
#define SYS_nanosleep 162
#define SYS_futex 240
#define SYS_timer_create 259
#define SYS_timer_settime 260
#define SYS_timer_gettime 261
#define SYS_timer_delete 263
#define SYS_clock_gettime 265
#define SYS_clock_getres 266
#define SYS_clock_nanosleep 267
#define SYS_utimes 271
#define SYS_futimesat 299
#define SYS_pselect6 308
#define SYS_ppoll 309
#define SYS_utimensat 320
#define SYS_timerfd_create 322
#define SYS_timerfd_settime 325
#define SYS_timerfd_gettime 326
#define SYS_clock_gettime64 403
#define SYS_clock_adjtime64 405
#define SYS_clock_getres64 406
#define SYS_clock_nanosleep64 407
#define SYS_timer_gettime64 408
#define SYS_timer_settime64 409
#define SYS_timerfd_gettime64 410
#define SYS_timerfd_settime64 411
#define SYS_utimensat64 412
#define SYS_pselect6_time64 413
#define SYS_ppoll_time64 414
#define SYS_rt_sigtimedwait_time64 421
#define SYS_futex_time64 422
#define SYS_sched_rr_get_interval_time64 423

#define O_RDWR 2
#define O_CREAT 0100
#define O_TRUNC 01000
#define CLOCK_MONOTONIC 1
#define FUTEX_WAIT 0
#define EAGAIN 11
#define ENOSYS 38
#define AT_FDCWD (-100)

struct time32_pair {
    int32_t seconds;
    int32_t subsecond;
};

struct time64_pair {
    int64_t seconds;
    int64_t subsecond;
};

struct itimer32 {
    struct time32_pair interval;
    struct time32_pair value;
};

struct itimer64 {
    struct time64_pair interval;
    struct time64_pair value;
};

struct guarded_time32 {
    struct time32_pair value;
    uint32_t guard;
};

struct guarded_itimer32 {
    struct itimer32 value;
    uint32_t guard;
};

struct guarded_timex32 {
    uint32_t value[32];
    uint32_t guard;
};

struct guarded_timex64 {
    uint32_t value[52];
    uint32_t guard;
};

static const char test_path[] = "/tmp/ia32-time-uapi";
static const char pass_text[] = "IA32_TIME_UAPI_PROBE_PASS\n";
static const char fail_prefix[] = "IA32_TIME_UAPI_PROBE_FAIL ";
static const char newline[] = "\n";
static char uts_name[390];
static int running_on_edgeos;
static volatile uint32_t futex_word = 1;

void *memset(void *destination, int value, uint32_t size) {
    volatile uint8_t *bytes = (volatile uint8_t *)destination;

    for (uint32_t index = 0; index < size; ++index)
        bytes[index] = (uint8_t)value;
    return destination;
}

__attribute__((naked)) static long raw_call6(
        long number, long a0, long a1, long a2,
        long a3, long a4, long a5) {
    __asm__ volatile(
        "pushl %ebp\n"
        "pushl %edi\n"
        "pushl %esi\n"
        "pushl %ebx\n"
        "movl 20(%esp), %eax\n"
        "movl 24(%esp), %ebx\n"
        "movl 28(%esp), %ecx\n"
        "movl 32(%esp), %edx\n"
        "movl 36(%esp), %esi\n"
        "movl 40(%esp), %edi\n"
        "movl 44(%esp), %ebp\n"
        "int $0x80\n"
        "popl %ebx\n"
        "popl %esi\n"
        "popl %edi\n"
        "popl %ebp\n"
        "ret\n");
}

#define call6(number, a0, a1, a2, a3, a4, a5) \
    raw_call6((number), \
              (long)(uintptr_t)(a0), (long)(uintptr_t)(a1), \
              (long)(uintptr_t)(a2), (long)(uintptr_t)(a3), \
              (long)(uintptr_t)(a4), (long)(uintptr_t)(a5))

static uint32_t text_length(const char *text) {
    uint32_t length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    call6(SYS_write, 1, text, text_length(text), 0, 0, 0);
}

static void fail(const char *name) {
    print_text(fail_prefix);
    print_text(name);
    print_text(newline);
    call6(SYS_exit, 1, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}

static void print_result(long result) {
    char text[16];
    uint32_t length = 0;
    uint32_t value;
    if (result < 0) {
        text[length++] = '-';
        value = (uint32_t)(-result);
    } else {
        value = (uint32_t)result;
    }
    if (!value) {
        text[length++] = '0';
    } else {
        char reversed[10];
        uint32_t count = 0;
        while (value) {
            reversed[count++] = (char)('0' + value % 10u);
            value /= 10u;
        }
        while (count) text[length++] = reversed[--count];
    }
    text[length++] = '\n';
    call6(SYS_write, 1, text, length, 0, 0, 0);
}

static void require_routed(const char *name, long result) {
    if (result == -ENOSYS && running_on_edgeos) fail(name);
}

static int result_is_error(long result) {
    return (uint32_t)result >= (uint32_t)-4095;
}

__attribute__((noreturn)) void _start(void) {
    struct guarded_time32 time32 = {{0, 0}, 0x5a17c0deu};
    struct time64_pair time64 = {0, 0};
    struct guarded_itimer32 timer32 = {{{0, 0}, {0, 0}}, 0xcafe3210u};
    struct itimer64 timer64 = {{0, 0}, {0, 0}};
    struct guarded_timex32 timex32 = {{0}, 0xc10c32abu};
    struct guarded_timex64 timex64 = {{0}, 0xc10c64abu};
    struct time32_pair timeval32[2] = {{1, 0}, {1, 0}};
    struct time64_pair timespec64[2] = {{1, 0}, {1, 0}};
    int32_t seconds32 = 0;
    uint32_t seconds_guard = 0x51f00dadu;
    int32_t timezone[2] = {0, 0};
    int32_t timer_id = -1;
    long descriptor;
    long result;

    if (call6(SYS_uname, uts_name, 0, 0, 0, 0, 0) != 0)
        fail("uname");
    running_on_edgeos = uts_name[0] == 'E' && uts_name[1] == 'd' &&
                        uts_name[2] == 'g' && uts_name[3] == 'e' &&
                        uts_name[4] == 'O' && uts_name[5] == 'S';

    result = call6(SYS_time, &seconds32, 0, 0, 0, 0, 0);
    require_routed("time", result);
    if (result >= 0 && (seconds32 <= 0 || seconds_guard != 0x51f00dadu))
        fail("time-layout");
    result = call6(SYS_gettimeofday, &time32.value, timezone, 0, 0, 0, 0);
    require_routed("gettimeofday", result);
    if (result == 0 && (time32.value.seconds <= 0 ||
                        time32.guard != 0x5a17c0deu))
        fail("gettimeofday-layout");
    result = call6(SYS_alarm, 0, 0, 0, 0, 0, 0);
    require_routed("alarm", result);

    result = call6(SYS_adjtimex, timex32.value, 0, 0, 0, 0, 0);
    require_routed("adjtimex32", result);
    if (result >= 0 && (result > 5 || timex32.guard != 0xc10c32abu))
        fail("adjtimex32-layout");
    result = call6(SYS_clock_adjtime64, 0, timex64.value, 0, 0, 0, 0);
    require_routed("clock_adjtime64", result);
    if (result >= 0 && (result > 5 || timex64.guard != 0xc10c64abu))
        fail("clock_adjtime64-layout");

    result = call6(SYS_clock_gettime, CLOCK_MONOTONIC, &time32.value,
                   0, 0, 0, 0);
    if (result != 0 || time32.value.seconds < 0 ||
        time32.value.subsecond < 0 || time32.value.subsecond >= 1000000000 ||
        time32.guard != 0x5a17c0deu)
        fail("clock_gettime32");
    if (call6(SYS_clock_getres, CLOCK_MONOTONIC, &time32.value,
              0, 0, 0, 0) != 0 || time32.guard != 0x5a17c0deu)
        fail("clock_getres32");
    if (call6(SYS_clock_gettime64, CLOCK_MONOTONIC, &time64,
              0, 0, 0, 0) != 0 || time64.seconds < 0)
        fail("clock_gettime64");
    if (call6(SYS_clock_getres64, CLOCK_MONOTONIC, &time64,
              0, 0, 0, 0) != 0)
        fail("clock_getres64");

    time32.value.seconds = 0;
    time32.value.subsecond = 0;
    if (call6(SYS_nanosleep, &time32.value, &time32.value,
              0, 0, 0, 0) != 0 || time32.guard != 0x5a17c0deu)
        fail("nanosleep32");
    if (call6(SYS_clock_nanosleep, CLOCK_MONOTONIC, 0,
              &time32.value, &time32.value, 0, 0) != 0)
        fail("clock_nanosleep32");
    if (call6(SYS_clock_nanosleep64, CLOCK_MONOTONIC, 0,
              &time64, &time64, 0, 0) != 0)
        fail("clock_nanosleep64");

    if (call6(SYS_getitimer, 0, &timer32.value, 0, 0, 0, 0) != 0 ||
        timer32.guard != 0xcafe3210u)
        fail("getitimer32");
    if (call6(SYS_setitimer, 0, &timer32.value, &timer32.value,
              0, 0, 0) != 0 || timer32.guard != 0xcafe3210u)
        fail("setitimer32");

    result = call6(SYS_timer_create, CLOCK_MONOTONIC, 0, &timer_id,
                   0, 0, 0);
    require_routed("timer_create", result);
    if (result == 0) {
        if (call6(SYS_timer_gettime, timer_id, &timer32.value,
                  0, 0, 0, 0) != 0 || timer32.guard != 0xcafe3210u)
            fail("timer_gettime32");
        if (call6(SYS_timer_settime, timer_id, 0, &timer32.value,
                  &timer32.value, 0, 0) != 0 ||
            timer32.guard != 0xcafe3210u)
            fail("timer_settime32");
        if (call6(SYS_timer_gettime64, timer_id, &timer64,
                  0, 0, 0, 0) != 0)
            fail("timer_gettime64");
        if (call6(SYS_timer_settime64, timer_id, 0, &timer64,
                  &timer64, 0, 0) != 0)
            fail("timer_settime64");
        if (call6(SYS_timer_delete, timer_id, 0, 0, 0, 0, 0) != 0)
            fail("timer_delete");
    }

    descriptor = call6(SYS_timerfd_create, CLOCK_MONOTONIC, 0, 0, 0, 0, 0);
    require_routed("timerfd_create", descriptor);
    if (!result_is_error(descriptor)) {
        if (call6(SYS_timerfd_gettime, descriptor, &timer32.value,
                  0, 0, 0, 0) != 0 || timer32.guard != 0xcafe3210u)
            fail("timerfd_gettime32");
        if (call6(SYS_timerfd_settime, descriptor, 0, &timer32.value,
                  &timer32.value, 0, 0) != 0)
            fail("timerfd_settime32");
        if (call6(SYS_timerfd_gettime64, descriptor, &timer64,
                  0, 0, 0, 0) != 0)
            fail("timerfd_gettime64");
        if (call6(SYS_timerfd_settime64, descriptor, 0, &timer64,
                  &timer64, 0, 0) != 0)
            fail("timerfd_settime64");
        call6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    }

    if (call6(SYS_sched_rr_get_interval, 0, &time32.value,
              0, 0, 0, 0) != 0 || time32.guard != 0x5a17c0deu)
        fail("sched_rr32");
    if (call6(SYS_sched_rr_get_interval_time64, 0, &time64,
              0, 0, 0, 0) != 0)
        fail("sched_rr64");
    result = call6(SYS_futex, &futex_word, FUTEX_WAIT, 0,
                   &time32.value, 0, 0);
    if (result != -EAGAIN) fail("futex32");
    result = call6(SYS_futex_time64, &futex_word, FUTEX_WAIT, 0,
                   &time64, 0, 0);
    if (result != -EAGAIN) fail("futex64");

    time32.value.seconds = 0;
    time32.value.subsecond = 0;
    if (call6(SYS_ppoll, 0, 0, &time32.value, 0, 0, 0) != 0)
        fail("ppoll32");
    if (call6(SYS_ppoll_time64, 0, 0, &time64, 0, 0, 0) != 0)
        fail("ppoll64");
    if (call6(SYS_pselect6, 0, 0, 0, 0, &time32.value, 0) != 0)
        fail("pselect32");
    if (call6(SYS_pselect6_time64, 0, 0, 0, 0, &time64, 0) != 0)
        fail("pselect64");

    {
        uint32_t empty_signal_mask[2] = {0, 0};
        uint32_t signal_information[32] = {0};

        result = call6(SYS_rt_sigtimedwait, empty_signal_mask,
                       signal_information, &time32.value, 8, 0, 0);
        if (result != -EAGAIN) fail("rt_sigtimedwait32");
        result = call6(SYS_rt_sigtimedwait_time64, empty_signal_mask,
                       signal_information, &time64, 8, 0, 0);
        if (result != -EAGAIN) fail("rt_sigtimedwait64");
    }

    call6(SYS_unlink, test_path, 0, 0, 0, 0, 0);
    result = call6(SYS_mkdir, "/tmp", 01777, 0, 0, 0, 0);
    if (result != 0 && result != -17) fail("tmp-directory");
    descriptor = call6(SYS_open, test_path, O_CREAT | O_TRUNC | O_RDWR,
                       0600, 0, 0, 0);
    if (descriptor < 0) fail("timestamp-open");
    result = call6(SYS_utime, test_path, timeval32, 0, 0, 0, 0);
    if (result != 0) {
        print_result(result);
        fail("utime32");
    }
    if (call6(SYS_utimes, test_path, timeval32, 0, 0, 0, 0) != 0)
        fail("utimes32");
    if (call6(SYS_futimesat, AT_FDCWD, test_path, timeval32,
              0, 0, 0) != 0)
        fail("futimesat32");
    if (call6(SYS_utimensat, AT_FDCWD, test_path, &timer32.value,
              0, 0, 0) != 0)
        fail("utimensat32");
    if (call6(SYS_utimensat64, AT_FDCWD, test_path, timespec64,
              0, 0, 0) != 0)
        fail("utimensat64");
    call6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    call6(SYS_unlink, test_path, 0, 0, 0, 0, 0);

    print_text(pass_text);
    call6(SYS_exit, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
