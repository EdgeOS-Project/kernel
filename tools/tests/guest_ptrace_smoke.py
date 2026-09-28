#!/usr/bin/env python3
"""Runtime ptrace smoke test for unmodified Linux Python userspace."""

import ctypes
import os
import platform
import signal
import struct


PTRACE_TRACEME = 0
PTRACE_PEEKDATA = 2
PTRACE_POKEDATA = 5
PTRACE_CONT = 7
PTRACE_SINGLESTEP = 9
PTRACE_DETACH = 17
PTRACE_SYSCALL = 24
PTRACE_SETOPTIONS = 0x4200
PTRACE_GETEVENTMSG = 0x4201
PTRACE_GETSIGINFO = 0x4202
PTRACE_GETREGSET = 0x4204
PTRACE_SEIZE = 0x4206
PTRACE_INTERRUPT = 0x4207
PTRACE_LISTEN = 0x4208
PTRACE_GETSIGMASK = 0x420A
PTRACE_SETSIGMASK = 0x420B
PTRACE_GET_SYSCALL_INFO = 0x420e
PTRACE_GET_RSEQ_CONFIGURATION = 0x420F
PTRACE_EVENT_FORK = 1
PTRACE_EVENT_STOP = 128
PTRACE_O_TRACESYSGOOD = 0x00000001
PTRACE_O_TRACEFORK = 0x00000002
PTRACE_O_EXITKILL = 0x00100000
NT_PRSTATUS = 1


class IOVec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("length", ctypes.c_size_t)]


libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace.restype = ctypes.c_long


def ptrace(request, pid=0, address=0, data=0):
    ctypes.set_errno(0)
    result = libc.ptrace(
        ctypes.c_int(request), ctypes.c_int(pid),
        ctypes.c_void_p(address), ctypes.c_void_p(data)
    )
    error = ctypes.get_errno()
    if result == -1 and error:
        raise OSError(error, os.strerror(error))
    return result


def wait_stopped(pid, expected_signal, options=0):
    waited, status = os.waitpid(pid, options)
    assert waited == pid, (waited, pid)
    assert os.WIFSTOPPED(status), hex(status)
    assert os.WSTOPSIG(status) == expected_signal, hex(status)
    return status


def read_regset(pid):
    registers = ctypes.create_string_buffer(1024)
    vector = IOVec(ctypes.addressof(registers), len(registers))
    ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, ctypes.addressof(vector))
    assert 128 <= vector.length <= len(registers), vector.length
    return bytes(registers.raw[:vector.length])


def read_syscall_info(pid):
    information = ctypes.create_string_buffer(88)
    available = ptrace(
        PTRACE_GET_SYSCALL_INFO, pid, len(information),
        ctypes.addressof(information)
    )
    assert 24 <= available <= len(information), available
    raw = information.raw
    return {
        "available": available,
        "op": raw[0],
        "architecture": struct.unpack_from("<I", raw, 4)[0],
        "instruction_pointer": struct.unpack_from("<Q", raw, 8)[0],
        "stack_pointer": struct.unpack_from("<Q", raw, 16)[0],
        "number_or_result": struct.unpack_from("<q", raw, 24)[0],
        "is_error": raw[32],
    }


def test_signal_mask_and_rseq(pid):
    original = ctypes.c_ulong()
    ptrace(PTRACE_GETSIGMASK, pid, ctypes.sizeof(original),
           ctypes.addressof(original))

    requested = ctypes.c_ulong(
        original.value | (1 << (signal.SIGUSR1 - 1)) |
        (1 << (signal.SIGKILL - 1)) | (1 << (signal.SIGSTOP - 1))
    )
    ptrace(PTRACE_SETSIGMASK, pid, ctypes.sizeof(requested),
           ctypes.addressof(requested))
    observed = ctypes.c_ulong()
    ptrace(PTRACE_GETSIGMASK, pid, ctypes.sizeof(observed),
           ctypes.addressof(observed))
    assert observed.value & (1 << (signal.SIGUSR1 - 1)), hex(observed.value)
    assert not observed.value & (1 << (signal.SIGKILL - 1)), hex(observed.value)
    assert not observed.value & (1 << (signal.SIGSTOP - 1)), hex(observed.value)
    ptrace(PTRACE_SETSIGMASK, pid, ctypes.sizeof(original),
           ctypes.addressof(original))

    configuration = ctypes.create_string_buffer(24)
    ptrace(PTRACE_GET_RSEQ_CONFIGURATION, pid, len(configuration),
           ctypes.addressof(configuration))
    _, size, _, flags, padding = struct.unpack("<QIIII", configuration.raw)
    assert size in (0, 32), size
    assert flags == 0 and padding == 0, (flags, padding)


def test_syscall_information_and_phase_tracking():
    machine = platform.machine()
    if machine == "x86_64":
        chdir_number = 80
        audit_architecture = 0xC000003E
    elif machine in ("aarch64", "arm64"):
        chdir_number = 49
        audit_architecture = 0xC00000B7
    else:
        raise AssertionError(f"unsupported test architecture: {machine}")

    child = os.fork()
    if child == 0:
        empty_path = ctypes.create_string_buffer(b"")
        ptrace(PTRACE_TRACEME)
        os.kill(os.getpid(), signal.SIGSTOP)
        libc.syscall(
            ctypes.c_long(chdir_number),
            ctypes.c_void_p(ctypes.addressof(empty_path)),
            ctypes.c_ulong(0x1111111111111111),
            ctypes.c_ulong(0x2222222222222222),
            ctypes.c_ulong(0x3333333333333333),
            ctypes.c_ulong(0x4444444444444444),
            ctypes.c_ulong(0x5555555555555555),
        )
        os._exit(0)

    print("ptrace syscall-info: wait initial stop", flush=True)
    wait_stopped(child, signal.SIGSTOP)
    print("ptrace syscall-info: read initial info", flush=True)
    initial = read_syscall_info(child)
    assert initial["op"] == 0, initial
    assert initial["available"] == 24, initial
    print("ptrace syscall-info: set options", flush=True)
    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD)

    active_number = None
    observed_chdir = False
    print("ptrace syscall-info: resume first syscall", flush=True)
    ptrace(PTRACE_SYSCALL, child)
    stop_index = 0
    while True:
        print(f"ptrace syscall-info: wait stop {stop_index}", flush=True)
        waited, status = os.waitpid(child, 0)
        assert waited == child
        if os.WIFEXITED(status):
            assert os.WEXITSTATUS(status) == 0, hex(status)
            break
        assert os.WIFSTOPPED(status), hex(status)
        assert os.WSTOPSIG(status) == signal.SIGTRAP | 0x80, hex(status)
        print(f"ptrace syscall-info: read stop {stop_index}", flush=True)
        information = read_syscall_info(child)
        assert information["architecture"] == audit_architecture, information
        assert information["instruction_pointer"], information
        assert information["stack_pointer"], information
        if active_number is None:
            assert information["op"] == 1, information
            assert information["available"] == 80, information
            active_number = information["number_or_result"]
        else:
            assert information["op"] == 2, information
            assert information["available"] == 33, information
            if active_number == chdir_number:
                assert information["number_or_result"] == -2, information
                assert information["is_error"] == 1, information
                observed_chdir = True
            active_number = None
        print(f"ptrace syscall-info: resume stop {stop_index}", flush=True)
        ptrace(PTRACE_SYSCALL, child)
        stop_index += 1
    assert observed_chdir, "chdir syscall was not observed"


def test_traceme_memory_step_and_signal_suppression():
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        word = ctypes.c_long(0x0011223344556677)
        os.write(write_fd, f"{ctypes.addressof(word)}\n".encode())
        os.close(write_fd)
        ptrace(PTRACE_TRACEME)
        os.kill(os.getpid(), signal.SIGSTOP)
        if word.value != 0x0077665544332211:
            os._exit(20)
        os.kill(os.getpid(), signal.SIGUSR1)
        os._exit(0)

    os.close(write_fd)
    address = int(os.read(read_fd, 64).strip())
    os.close(read_fd)
    wait_stopped(child, signal.SIGSTOP)

    print("ptrace detail: read-regset", flush=True)
    registers = read_regset(child)
    assert any(registers), "all-zero general register set"
    print("ptrace detail: signal-mask-rseq", flush=True)
    test_signal_mask_and_rseq(child)
    print("ptrace detail: peek-poke", flush=True)
    assert ptrace(PTRACE_PEEKDATA, child, address) == 0x0011223344556677
    ptrace(PTRACE_POKEDATA, child, address, 0x0077665544332211)

    print("ptrace detail: single-step", flush=True)
    ptrace(PTRACE_SINGLESTEP, child)
    wait_stopped(child, signal.SIGTRAP)
    print("ptrace detail: signal-suppression", flush=True)
    ptrace(PTRACE_CONT, child)
    wait_stopped(child, signal.SIGUSR1)

    information = ctypes.create_string_buffer(128)
    ptrace(PTRACE_GETSIGINFO, child, 0, ctypes.addressof(information))
    delivered = int.from_bytes(information.raw[:4], "little", signed=True)
    assert delivered == signal.SIGUSR1, delivered

    # Resuming a signal-delivery stop with signal zero suppresses that signal.
    ptrace(PTRACE_CONT, child, 0, 0)
    waited, status = os.waitpid(child, 0)
    assert waited == child
    assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, hex(status)


def test_tracefork_event_and_wait_ownership():
    tracee = os.fork()
    if tracee == 0:
        ptrace(PTRACE_TRACEME)
        os.kill(os.getpid(), signal.SIGSTOP)
        child = os.fork()
        if child == 0:
            os._exit(42)
        waited, status = os.waitpid(child, 0)
        if waited != child or not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 42:
            os._exit(60)
        os._exit(0)

    wait_stopped(tracee, signal.SIGSTOP)
    ptrace(PTRACE_SETOPTIONS, tracee, 0, PTRACE_O_TRACEFORK)
    ptrace(PTRACE_CONT, tracee)
    status = wait_stopped(tracee, signal.SIGTRAP)
    assert status >> 16 == PTRACE_EVENT_FORK, hex(status)
    event_message = ctypes.c_ulong()
    ptrace(PTRACE_GETEVENTMSG, tracee, 0, ctypes.addressof(event_message))
    child = event_message.value
    assert child > 0 and child != tracee, child

    ptrace(PTRACE_CONT, tracee)
    status = wait_stopped(child, signal.SIGSTOP)
    assert status >> 16 == 0, hex(status)
    ptrace(PTRACE_CONT, child)

    terminal = {}
    while len(terminal) != 2:
        waited, status = os.waitpid(-1, 0)
        if os.WIFSTOPPED(status):
            ptrace(PTRACE_CONT, waited)
            continue
        terminal[waited] = status
    assert child in terminal and tracee in terminal, terminal
    assert (os.WIFEXITED(terminal[child]) and
            os.WEXITSTATUS(terminal[child]) == 42), hex(terminal[child])
    assert (os.WIFEXITED(terminal[tracee]) and
            os.WEXITSTATUS(terminal[tracee]) == 0), hex(terminal[tracee])


def test_seize_interrupt_and_detach():
    child = os.fork()
    if child == 0:
        while True:
            signal.pause()

    ptrace(PTRACE_SEIZE, child)
    ptrace(PTRACE_INTERRUPT, child)
    status = wait_stopped(child, signal.SIGTRAP)
    assert status >> 16 == PTRACE_EVENT_STOP, hex(status)
    assert any(read_regset(child)), "all-zero seized register set"
    ptrace(PTRACE_DETACH, child)
    os.kill(child, signal.SIGTERM)
    waited, status = os.waitpid(child, 0)
    assert waited == child
    assert (os.WIFSIGNALED(status) and
            os.WTERMSIG(status) == signal.SIGTERM), hex(status)


def test_seize_running_task_preserves_live_registers():
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        finished = False

        def finish(_signal, _frame):
            nonlocal finished
            finished = True

        signal.signal(signal.SIGUSR1, finish)
        os.write(write_fd, b"ready")
        accumulator = 0x12345678
        while not finished:
            accumulator = ((accumulator << 7) ^ (accumulator >> 3) ^
                           0x9E3779B9) & 0xFFFFFFFF
        os.write(write_fd, b"alive")
        os.close(write_fd)
        os._exit(0 if accumulator else 1)

    os.close(write_fd)
    assert os.read(read_fd, 5) == b"ready"
    ptrace(PTRACE_SEIZE, child)
    ptrace(PTRACE_INTERRUPT, child)
    status = wait_stopped(child, signal.SIGTRAP)
    assert status >> 16 == PTRACE_EVENT_STOP, hex(status)
    registers = read_regset(child)
    assert any(registers), "all-zero running-task register set"
    ptrace(PTRACE_DETACH, child)
    os.kill(child, signal.SIGUSR1)
    assert os.read(read_fd, 5) == b"alive"
    os.close(read_fd)
    waited, status = os.waitpid(child, 0)
    assert waited == child
    assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, hex(status)


def test_seize_group_stopped_tracee():
    child = os.fork()
    if child == 0:
        os.kill(os.getpid(), signal.SIGSTOP)
        signal.pause()

    wait_stopped(child, signal.SIGSTOP, os.WUNTRACED)
    ptrace(PTRACE_SEIZE, child)
    ptrace(PTRACE_INTERRUPT, child)
    status = wait_stopped(child, signal.SIGSTOP)
    assert status >> 16 == PTRACE_EVENT_STOP, hex(status)
    os.kill(child, signal.SIGCONT)
    ptrace(PTRACE_LISTEN, child)
    status = wait_stopped(child, signal.SIGTRAP)
    assert status >> 16 == PTRACE_EVENT_STOP, hex(status)
    ptrace(PTRACE_CONT, child)
    status = wait_stopped(child, signal.SIGCONT)
    assert status >> 16 == 0, hex(status)
    information = ctypes.create_string_buffer(128)
    ptrace(PTRACE_GETSIGINFO, child, 0, ctypes.addressof(information))
    delivered = int.from_bytes(information.raw[:4], "little", signed=True)
    assert delivered == signal.SIGCONT, delivered
    ptrace(PTRACE_CONT, child, 0, signal.SIGCONT)
    ptrace(PTRACE_INTERRUPT, child)
    status = wait_stopped(child, signal.SIGTRAP)
    assert status >> 16 == PTRACE_EVENT_STOP, hex(status)
    ptrace(PTRACE_DETACH, child)
    os.kill(child, signal.SIGTERM)
    waited, status = os.waitpid(child, 0)
    assert waited == child
    assert (os.WIFSIGNALED(status) and
            os.WTERMSIG(status) == signal.SIGTERM), hex(status)


def test_tracer_exit(exitkill):
    tracee = os.fork()
    if tracee == 0:
        while True:
            signal.pause()

    read_fd, write_fd = os.pipe()
    tracer = os.fork()
    if tracer == 0:
        os.close(read_fd)
        options = PTRACE_O_EXITKILL if exitkill else 0
        ptrace(PTRACE_SEIZE, tracee, 0, options)
        ptrace(PTRACE_INTERRUPT, tracee)
        wait_stopped(tracee, signal.SIGTRAP)
        os.write(write_fd, b"ready")
        os.close(write_fd)
        os._exit(0)

    os.close(write_fd)
    assert os.read(read_fd, 5) == b"ready"
    os.close(read_fd)
    waited, status = os.waitpid(tracer, 0)
    assert waited == tracer
    assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, hex(status)

    if exitkill:
        waited, status = os.waitpid(tracee, 0)
        assert waited == tracee
        assert (os.WIFSIGNALED(status) and
                os.WTERMSIG(status) == signal.SIGKILL), hex(status)
    else:
        os.kill(tracee, 0)
        os.kill(tracee, signal.SIGTERM)
        waited, status = os.waitpid(tracee, 0)
        assert waited == tracee
        assert (os.WIFSIGNALED(status) and
                os.WTERMSIG(status) == signal.SIGTERM), hex(status)


def main():
    signal.alarm(60)
    print("ptrace stage: syscall-info", flush=True)
    test_syscall_information_and_phase_tracking()
    print("ptrace stage: traceme-memory-step", flush=True)
    test_traceme_memory_step_and_signal_suppression()
    print("ptrace stage: tracefork", flush=True)
    test_tracefork_event_and_wait_ownership()
    print("ptrace stage: seize-interrupt", flush=True)
    test_seize_interrupt_and_detach()
    print("ptrace stage: seize-running-task", flush=True)
    test_seize_running_task_preserves_live_registers()
    print("ptrace stage: seize-group-stop", flush=True)
    test_seize_group_stopped_tracee()
    print("ptrace stage: tracer-exit-detach", flush=True)
    test_tracer_exit(False)
    print("ptrace stage: tracer-exit-exitkill", flush=True)
    test_tracer_exit(True)
    print("ptrace smoke: PASS")


if __name__ == "__main__":
    main()
