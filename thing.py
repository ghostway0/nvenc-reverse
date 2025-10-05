import ctypes, os, struct, time, signal, threading

libc = ctypes.CDLL("/lib64/libc.so.6")


libc.memcpy.restype = ctypes.c_void_p
libc.memcpy.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]

libc.mprotect.restype = ctypes.c_int
libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]

libc.sigaction.restype = ctypes.c_int
libc.sigaction.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]

def write(addr, value):
    libc.mprotect(addr & (~0xFFF), (len(value) + 0xFFF) & (~0xFFF), 0x7)
    orig = bytearray(len(value))
    libc.memcpy(ctypes.byref(ctypes.c_char.from_buffer(orig)), addr, len(value))
    libc.memcpy(addr, value, len(value))
    return bytes(orig)

def hook(addr, f):
    addr = ctypes.cast(addr, ctypes.c_void_p).value
    f = ctypes.cast(f, ctypes.c_void_p).value

    tramp = b"\x48\xb8" + struct.pack("<Q", f) + b"\xff\xe0" # movabs rax, f; jmp rax
    orig = write(addr, tramp)

    def round_trip(*args):
        write(addr, orig)
        origf = ctypes.CFUNCTYPE(ctypes.c_int, *[type(arg) for arg in args])(addr)
        r = origf(*args)
        write(addr, tramp)
        return r
    return round_trip

original = {}

class RStructure(ctypes.Structure):
    def __repr__(self):
        field_strs = []
        for field_name, field_type in getattr(self, "_fields_", []):
            try:
                value = getattr(self, field_name)
                # if it's a ctypes array, convert to list
                if isinstance(value, ctypes.Array):
                    value = list(value)
            except Exception:
                value = "<error>"
            field_strs.append(f"{field_name}={value!r}")
        fields_repr = ", ".join(field_strs)
        return f"{self.__class__.__name__}({fields_repr})"

class NVC36F_CTRL_CMD_GPFIFO_GET_WORK_SUBMIT_TOKEN_PARAMS(RStructure):
    _pack_ = 1
    _fields_ = [("workSubmitToken", ctypes.c_uint32)]

class NV_MEMORY_DESC_PARAMS(RStructure):
    _pack_ = 1
    _fields_ = [
        ("base", ctypes.c_uint64),
        ("size", ctypes.c_uint64),
        ("addressSpace", ctypes.c_uint32),
        ("cacheAttrib", ctypes.c_uint32),
    ]

class NV_CHANNEL_ALLOC_PARAMS(RStructure):
    _pack_ = 1
    _fields_ = [
        ("hObjectError", ctypes.c_uint32),
        ("hObjectBuffer", ctypes.c_uint32),
        ("gpFifoOffset", ctypes.c_uint64),
        ("gpFifoEntries", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("hContextShare", ctypes.c_uint32),
        ("hVASpace", ctypes.c_uint32),
        ("hUserdMemory", ctypes.c_uint32 * 8),
        ("userdOffset", ctypes.c_uint64 * 8),
        ("engineType", ctypes.c_uint32),
        ("cid", ctypes.c_uint32),
        ("subDeviceId", ctypes.c_uint32),
        ("hObjectEccError", ctypes.c_uint32),
        ("instanceMem", NV_MEMORY_DESC_PARAMS),
        ("userdMem", NV_MEMORY_DESC_PARAMS),
        ("ramfcMem", NV_MEMORY_DESC_PARAMS),
        ("mthdbufMem", NV_MEMORY_DESC_PARAMS),
        ("hPhysChannelGroup", ctypes.c_uint32),
        ("internalFlags", ctypes.c_uint32),
        ("errorNotifierMem", NV_MEMORY_DESC_PARAMS),
        ("eccErrorNotifierMem", NV_MEMORY_DESC_PARAMS),
        ("ProcessID", ctypes.c_uint32),
        ("SubProcessID", ctypes.c_uint32),
        ("encryptIv", ctypes.c_uint32 * 3),
        ("decryptIv", ctypes.c_uint32 * 3),
        ("hmacNonce", ctypes.c_uint32 * 8),
        ("tpcConfigID", ctypes.c_uint32),
        ("PADDING_0", ctypes.c_ubyte * 4),
    ]

NV_CHANNELGPFIFO_ALLOCATION_PARAMETERS = NV_CHANNEL_ALLOC_PARAMS

class NVOS21_PARAMETERS(RStructure):
    _pack_ = 1
    _fields_ = [
        ("hRoot", ctypes.c_uint32),
        ("hObjectParent", ctypes.c_uint32),
        ("hObjectNew", ctypes.c_uint32),
        ("hClass", ctypes.c_uint32),
        ("pAllocParms", ctypes.c_void_p),
        ("paramsSize", ctypes.c_uint32),
        ("status", ctypes.c_uint32),
    ]

fds = {}

@ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_int)
def hook_open(path, flags):
    r = original["open"](ctypes.c_void_p(path), ctypes.c_int(flags))
    s = ctypes.string_at(path, 256)
    fds[r] = s[:s.find(b"\0")]
    return r

@ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_int)
def hook_openat(dirfd, path, flags):
    print("open")
    r = original["openat"](ctypes.c_int(dirfd), ctypes.c_void_p(path), ctypes.c_int(flags))
    s = ctypes.string_at(path, 256)
    fds[r] = s[:s.find(b"\0")]
    return r


rm = {}
gpfifos = []

class NVOS46_PARAMETERS(RStructure):
    _fields_ = [
        ("hClient", ctypes.c_uint32),
        ("hDevice", ctypes.c_uint32),
        ("hDma", ctypes.c_uint32),
        ("hMemory", ctypes.c_uint32),
        ("offset", ctypes.c_uint64),
        ("length", ctypes.c_uint64),
        ("flags", ctypes.c_uint32),
        ("flags2", ctypes.c_uint32),
        ("kindOverride", ctypes.c_uint32),
        ("dmaOffset", ctypes.c_uint64),
        ("status", ctypes.c_uint32),
    ]

class NVOS54_PARAMETERS(RStructure):
    _pack_ = 1
    _fields_ = [
        ('hClient', ctypes.c_uint32),
        ('hObject', ctypes.c_uint32),
        ('cmd', ctypes.c_uint32),
        ('flags', ctypes.c_uint32),
        ('params', ctypes.POINTER(None)),
        ('paramsSize', ctypes.c_uint32),
        ('status', ctypes.c_uint32),
    ]

tokens = []

@ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p)
def hook_ioctl(fd, cmd, argp):
    token = struct.pack("I", 0xc36f0108)
    d, ty, nr, paramsz = (cmd >> 30) & 3, (cmd >> 8) & 0xff, cmd & 0xff, (cmd >> 16) & 0xfff
    argbuf = bytearray(ctypes.string_at(argp, paramsz))
    print(fds[fd], hex(nr))

    if token in bytes(argbuf):
        params = NVOS54_PARAMETERS.from_address(argp)
        # hparent = int.from_bytes(bytes(argbuf[4:8]), "little")
        gpfifos.append(params.hObject)
        r = original["ioctl"](ctypes.c_int(fd), ctypes.c_ulong(cmd), ctypes.c_void_p(argp))
        tokens.append(NVC36F_CTRL_CMD_GPFIFO_GET_WORK_SUBMIT_TOKEN_PARAMS.from_address(params.params).workSubmitToken)
        return r

    if nr == 0x2b:
        r = original["ioctl"](ctypes.c_int(fd), ctypes.c_ulong(cmd), ctypes.c_void_p(argp))
        params = NVOS21_PARAMETERS.from_buffer(argbuf)
        hparent = params.hObjectNew
        alloc_params = NV_CHANNELGPFIFO_ALLOCATION_PARAMETERS.from_buffer(
            bytearray(ctypes.string_at(params.pAllocParms, ctypes.sizeof(NV_CHANNELGPFIFO_ALLOCATION_PARAMETERS)))
        )
        rm[hparent] = alloc_params
        return r

    if fds[fd] == b"/dev/nvidiactl" and nr == 0x57:
        print(NVOS46_PARAMETERS.from_buffer(argbuf))
        r = original["ioctl"](ctypes.c_int(fd), ctypes.c_ulong(cmd), ctypes.c_void_p(argp))
        argbuf = bytearray(ctypes.string_at(argp, paramsz))
        print(NVOS46_PARAMETERS.from_buffer(argbuf))
        return r

    return original["ioctl"](ctypes.c_int(fd), ctypes.c_ulong(cmd), ctypes.c_void_p(argp))

# original["ioctl"] = hook(libc["ioctl"], hook_ioctl)
# original["open"] = hook(libc["open"], hook_open)
# original["openat"] = hook(libc["openat"], hook_openat)

class SigAction(RStructure):
    _fields_ = [
        ("sa_sigaction", ctypes.CFUNCTYPE(None, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)),
        ("sa_mask", ctypes.c_ulong),
        ("sa_flags", ctypes.c_int),
        ("sa_restorer", ctypes.c_void_p)
    ]

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

catch = []

def unwind_from_rsp(rbp):
    trace = []
    while rbp:
        prev_rbp = ctypes.c_uint64.from_address(rbp).value
        ret_addr = ctypes.c_uint64.from_address(rbp + 8).value
        trace.append(ret_addr)
        if prev_rbp <= rbp:  # prevent infinite loop
            break
        rbp = prev_rbp
    return trace

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

    # hardcoded base address..
    print(hex(regs.rip - 0x5000000), hex(fault_addr), f"{hex(start)}-{hex(end)}")
    libc.mprotect(start, end - start, 0x3)

    regs.eflags = ctypes.c_size_t(regs.eflags | (1 << 8)) # TF_MASK
    with _fault_lock:
        _last_fault_range = (start, end)

@ctypes.CFUNCTYPE(None, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
def sigtrap_handler(signum, siginfo_p, ucontext_p):
    global _last_fault_range

    uc = UContext.from_address(ucontext_p)
    regs = uc.uc_mcontext.gregs

    regs.eflags = ctypes.c_size_t(regs.eflags & ~(1 << 8)) # ~TF_MASK

    with _fault_lock:
        if _last_fault_range is None:
            return

        start, end = _last_fault_range
        libc.mprotect(start, end - start, 0x0)
        _last_fault_range = None

def hook_mem(start, length):
    assert start & 0xFFF == 0
    assert length & 0xFFF == 0
    libc.mprotect(start, length, 0x0)
    catch.append((start, start + length))

def install_mem_hooks():
    print("Catching:", " ".join((f"{hex(start)}-{hex(end)}" for start, end in catch)))
    libc.sigaction(signal.SIGSEGV, ctypes.byref(SigAction(sa_sigaction=sigsegv_handler, sa_flags=0x4)), None) # SA_SIGINFO
    libc.sigaction(signal.SIGTRAP, ctypes.byref(SigAction(sa_sigaction=sigtrap_handler, sa_flags=0x4)), None) # SA_SIGINFO

# hook_fifo = lambda g: hook_mem(rm[g].gpFifoOffset, rm[g].gpFifoOffset + rm[g].gpFifoEntries * 4)

def library_base(lib):
    return ctypes.c_uint64.from_address(lib._handle)

if __name__ == "__main__":
    CUhandle = ctypes.c_void_p
    libcuda = ctypes.CDLL("/lib64/libcuda.so")
    libcuda.cuInit(0)

    dev = CUhandle()
    ctx = CUhandle()

    libcuda.cuDeviceGet(ctypes.byref(dev), 0)
    libcuda.cuDevicePrimaryCtxRetain(ctypes.byref(ctx), dev)
    libcuda.cuCtxPushCurrent(ctx)

    hevc2.run()
