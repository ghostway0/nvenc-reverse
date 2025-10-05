import ctypes, os, struct, time, signal, threading

libc = ctypes.CDLL("/lib64/libc.so.6")

libc.memcpy.restype = ctypes.c_void_p
libc.memcpy.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]

libc.mprotect.restype = ctypes.c_int
libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]

libc.sigaction.restype = ctypes.c_int
libc.sigaction.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]

class RStructure(ctypes.Structure):
    def __repr__(self):
        field_strs = []
        for field_name, field_type in getattr(self, "_fields_", []):
            try:
                value = getattr(self, field_name)
                if isinstance(value, ctypes.Array):
                    value = list(value)
            except Exception:
                value = "<error>"
            field_strs.append(f"{field_name}={value!r}")
        fields_repr = ", ".join(field_strs)
        return f"{self.__class__.__name__}({fields_repr})"


def write(addr, value):
    libc.mprotect(addr & (~0xFFF), (len(value) + 0xFFF) & (~0xFFF), 0x7)
    orig = bytearray(len(value))
    libc.memcpy(ctypes.byref(ctypes.c_char.from_buffer(orig)), addr, len(value))
    libc.memcpy(addr, value, len(value))
    return bytes(orig)

def hook(addr, f):
    addr = ctypes.cast(addr, ctypes.c_void_p).value
    f = ctypes.cast(f, ctypes.c_void_p).value

    tramp = b"\x48\xb8" + struct.pack("<Q", f) + b"\xff\xe0"
    orig = write(addr, tramp)

    def round_trip(*args):
        write(addr, orig)
        origf = ctypes.CFUNCTYPE(ctypes.c_int, *[type(arg) for arg in args])(addr)
        r = origf(*args)
        write(addr, tramp)
        return r
    return round_trip

def unwind_from_rsp(rbp):
    trace = []
    while rbp:
        prev_rbp = ctypes.c_uint64.from_address(rbp).value
        ret_addr = ctypes.c_uint64.from_address(rbp + 8).value
        trace.append(ret_addr)
        if prev_rbp <= rbp:
            break
        rbp = prev_rbp
    return trace

class SigAction(RStructure):
    _fields_ = [
        ("sa_sigaction", ctypes.CFUNCTYPE(None, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)),
        ("sa_mask", ctypes.c_ulong),
        ("sa_flags", ctypes.c_int),
        ("sa_restorer", ctypes.c_void_p)
    ]

catch = []

def hook_mem(start, length):
    assert start & 0xFFF == 0
    assert length & 0xFFF == 0
    libc.mprotect(start, length, 0x0)
    catch.append((start, start + length))


def install_mem_hooks():
    print("Catching:", " ".join((f"{hex(start)}-{hex(end)}" for start, end in catch)))
    libc.sigaction(signal.SIGSEGV, ctypes.byref(SigAction(sa_sigaction=sigsegv_handler, sa_flags=0x4)), None)
    libc.sigaction(signal.SIGTRAP, ctypes.byref(SigAction(sa_sigaction=sigtrap_handler, sa_flags=0x4)), None)


def library_base(lib):
    return ctypes.c_uint64.from_address(lib._handle)


class SigSegvInfo(RStructure):
    _fields_ = [
        ("si_signo", ctypes.c_int),
        ("si_errno", ctypes.c_int),
        ("si_code", ctypes.c_int),
        ("__pad0", ctypes.c_int),
        ("si_addr", ctypes.c_void_p),
        ("si_addr_lsb", ctypes.c_short),
        ("_pad1", ctypes.c_short * 3),
        ("si_lower", ctypes.c_void_p),
        ("si_higher", ctypes.c_void_p),
        ("_pkey", ctypes.c_uint32),
    ]


class GRegs(RStructure):
    _fields_ = [
        ("r8", ctypes.c_size_t),
        ("r9", ctypes.c_size_t),
        ("r10", ctypes.c_size_t),
        ("r11", ctypes.c_size_t),
        ("r12", ctypes.c_size_t),
        ("r13", ctypes.c_size_t),
        ("r14", ctypes.c_size_t),
        ("r15", ctypes.c_size_t),
        ("rdi", ctypes.c_size_t),
        ("rsi", ctypes.c_size_t),
        ("rbp", ctypes.c_size_t),
        ("rbx", ctypes.c_size_t),
        ("rdx", ctypes.c_size_t),
        ("rax", ctypes.c_size_t),
        ("rcx", ctypes.c_size_t),
        ("rsp", ctypes.c_size_t),
        ("rip", ctypes.c_size_t),
        ("eflags", ctypes.c_size_t),
        ("csgsfs", ctypes.c_size_t),
        ("err", ctypes.c_size_t),
        ("trapno", ctypes.c_size_t),
        ("oldmask", ctypes.c_size_t),
        ("cr2", ctypes.c_size_t),
    ]


class MContext(RStructure):
    _fields_ = [
        ("gregs", GRegs),
        ("fpregs", ctypes.c_void_p),
        ("__reserved1", ctypes.c_ulonglong * 8),
    ]


class StackT(RStructure):
    _fields_ = [
        ("ss_sp", ctypes.c_void_p),
        ("ss_flags", ctypes.c_int),
        ("ss_size", ctypes.c_size_t),
    ]


class SigSet(RStructure):
    _fields_ = [("_val", ctypes.c_ulong * 16)]


class UContext(RStructure):
    _fields_ = [
        ("uc_flags", ctypes.c_ulong),
        ("uc_link", ctypes.POINTER('UContext')),
        ("uc_stack", StackT),
        ("uc_mcontext", MContext),
        ("uc_sigmask", SigSet),
        ("__fpregs_mem", ctypes.c_byte * 512),
        ("__ssp", ctypes.c_ulonglong * 4),
    ]

_last_fault_range = None
_fault_lock = threading.Lock()

@ctypes.CFUNCTYPE(None, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
def sigsegv_handler(signum, siginfo_p, ucontext_p):
    global _last_fault_range

    regs = UContext.from_address(ucontext_p).uc_mcontext.gregs
    fault_addr = regs.cr2
    if fault_addr is None:
        return

    for (start, end) in catch:
        if fault_addr >= start and fault_addr < end:
            break
    else:
        return

    print(hex(regs.rip - 0x5000000), hex(fault_addr), f"{hex(start)}-{hex(end)}")
    libc.mprotect(start, end - start, 0x3)

    regs.eflags = ctypes.c_size_t(regs.eflags | (1 << 8))
    with _fault_lock:
        _last_fault_range = (start, end)


@ctypes.CFUNCTYPE(None, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
def sigtrap_handler(signum, siginfo_p, ucontext_p):
    global _last_fault_range

    uc = UContext.from_address(ucontext_p)
    regs = uc.uc_mcontext.gregs

    regs.eflags = ctypes.c_size_t(regs.eflags & ~(1 << 8))

    with _fault_lock:
        if _last_fault_range is None:
            return

        start, end = _last_fault_range
        libc.mprotect(start, end - start, 0x0)
        _last_fault_range = None

