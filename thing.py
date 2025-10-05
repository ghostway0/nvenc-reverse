import ctypes, os, struct, time

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
def open(path, flags):
    r = original["open"](ctypes.c_void_p(path), ctypes.c_int(flags))
    s = ctypes.string_at(path, 256)
    fds[r] = s[:s.find(b"\0")]
    return r

@ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_int)
def openat(dirfd, path, flags):
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
def ioctl(fd, cmd, argp):
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

import hevc2

original["ioctl"] = hook(libc["ioctl"], ioctl)
original["open"] = hook(libc["open"], open)
original["openat"] = hook(libc["openat"], openat)

CUhandle = ctypes.c_void_p
libcuda = ctypes.CDLL("/lib64/libcuda.so")
libcuda.cuInit(0)

dev = CUhandle()
ctx = CUhandle()

libcuda.cuDeviceGet(ctypes.byref(dev), 0)
libcuda.cuDevicePrimaryCtxRetain(ctypes.byref(ctx), dev)
libcuda.cuCtxPushCurrent(ctx)

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
        ("_bounds_lower", ctypes.c_void_p),
        ("_bounds_upper", ctypes.c_void_p),
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

NGREG = 23

# greg_t is "long long" on x86_64
greg_t = ctypes.c_longlong

# typedef greg_t gregset_t[NGREG];
gregset_t = greg_t * NGREG

class MContext(ctypes.Structure):
    _fields_ = [
        ("gregs", gregset_t),
        ("fpregs", ctypes.c_void_p),                # fpregset_t is pointer
        ("__reserved1", ctypes.c_ulonglong * 8),    # reserved space
    ]

class StackT(ctypes.Structure):
    _fields_ = [
        ("ss_sp", ctypes.c_void_p),
        ("ss_flags", ctypes.c_int),
        ("ss_size", ctypes.c_size_t),
    ]

class SigSet(ctypes.Structure):
    _fields_ = [("_val", ctypes.c_ulong * 16)]     # 1024 bits

# ucontext_t
class UContext(ctypes.Structure):
    _fields_ = [
        ("uc_flags", ctypes.c_ulong),
        ("uc_link", ctypes.POINTER('UContext')),
        ("uc_stack", StackT),
        ("uc_mcontext", MContext),
        ("uc_sigmask", SigSet),
        ("__fpregs_mem", ctypes.c_byte * 512),
        ("__ssp", ctypes.c_ulonglong * 4),
    ]

REG_R8     = 0
REG_R9     = 1
REG_R10    = 2
REG_R11    = 3
REG_R12    = 4
REG_R13    = 5
REG_R14    = 6
REG_R15    = 7
REG_RDI    = 8
REG_RSI    = 9
REG_RBP    = 10
REG_RBX    = 11
REG_RDX    = 12
REG_RAX    = 13
REG_RCX    = 14
REG_RSP    = 15
REG_RIP    = 16
REG_EFL    = 17
REG_CSGSFS = 18
REG_ERR    = 19
REG_TRAPNO = 20
REG_OLDMASK= 21
REG_CR2    = 22


@ctypes.CFUNCTYPE(None, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
def sigsegv(signum, siginfo_p, ucontext_p):
    import builtins
    regs = UContext.from_address(ucontext_p).uc_mcontext.gregs
    print(list(hex(i) for i in unwind_from_rsp(regs[REG_RBP])))
    print(builtins.open("/proc/self/maps").read(), regs[REG_RIP])
    faulting_addr = SigSegvInfo.from_address(siginfo_p).si_addr
    if faulting_addr is None:
        os._exit(0)
        return

    for (start, end) in catch:
        if faulting_addr >= start and faulting_addr < end:
            break
    else:
        return

    print(faulting_addr, f"{hex(start)}-{hex(end)}")
    libc.mprotect(start, end - start, 0x3)

def hook_mem(start, end):
    assert start & 0xFFF == 0
    assert end & 0xFFF == 0
    libc.mprotect(start, end - start, 0x0)
    catch.append((start, end))

# hook_fifo = lambda g: hook_mem(rm[g].gpFifoOffset, rm[g].gpFifoOffset + rm[g].gpFifoEntries * 4)

libc.sigaction(11, ctypes.byref(SigAction(sa_sigaction=sigsegv, sa_flags=0x4)), None) # SA_SIGINFO

hevc2.run()
hevc2.run()
# print(tokens)
