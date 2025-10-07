import ctypes, os, struct, time, signal, threading, inspect

from utils import *

ioctl_map = {}
params_map = {}

import nv_gpu
for name, value in inspect.getmembers(nv_gpu):
    if not name.isupper():
        continue

    if "UVM" in name:
        dev = "/dev/nvidia-uvm"
    elif "NV_ESC_" in name:
        dev = "/dev/nvidiactl"
    elif "CTRL_CMD" in name:
        dev = "NV0000"
    elif "NV2080_CTRL_" in name:
        dev = "/dev/nvidia0"
    else:
        continue

    if isinstance(value, int):
        ioctl_map[(dev, int(value))] = name
    elif inspect.isclass(value) and name.endswith("_PARAMS") and issubclass(value, ctypes.Structure):
        params_map[name] = value

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
def _open(path, flags):
    r = original["open"](ctypes.c_void_p(path), ctypes.c_int(flags))
    s = ctypes.string_at(path, 256)
    fds[r] = s[:s.find(b"\0")]
    return r

@ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_int)
def _openat(dirfd, path, flags):
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
original = {}

libc = ctypes.CDLL("/lib64/libc.so.6")
@ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p)
def _ioctl(fd, cmd, argp):
    d, paramsz, ty, nr = (cmd >> 30) & 3, (cmd >> 16) & 0xfff, (cmd >> 8) & 0xff, cmd & 0xff
    ioctl_name = ioctl_map.get((fds[fd].decode(), nr))

    print(fds[fd], hex(nr), f"({ioctl_name})" if ioctl_name else "")
    print(" ".join(get_backtrace()))

    if ioctl_name and (ioctl_name + "_PARAMS") in params_map:
        params_type = params_map[ioctl_name + "_PARAMS"]
        params = params_type.from_address(argp)
        for field, _ in params_type._fields_:
            print(f"  {field} = {getattr(params, field)}")
        old_params = params

    if struct.pack("I", 0xc36f0108) in ctypes.string_at(argp, paramsz):
        params = NVOS54_PARAMETERS.from_address(argp)
        gpfifos.append(params.hObject)
        print(rm[params.hObject])
        r = original["ioctl"](ctypes.c_int(fd), ctypes.c_ulong(cmd), ctypes.c_void_p(argp))
        tokens.append(NVC36F_CTRL_CMD_GPFIFO_GET_WORK_SUBMIT_TOKEN_PARAMS.from_address(params.params).workSubmitToken)
        return r

    if nr == 0x2b:
        r = original["ioctl"](ctypes.c_int(fd), ctypes.c_ulong(cmd), ctypes.c_void_p(argp))
        params = NVOS21_PARAMETERS.from_address(argp)
        hparent = params.hObjectNew
        alloc_params = NV_CHANNELGPFIFO_ALLOCATION_PARAMETERS.from_buffer(
            bytearray(ctypes.string_at(params.pAllocParms, ctypes.sizeof(NV_CHANNELGPFIFO_ALLOCATION_PARAMETERS)))
        )
        rm[hparent] = alloc_params
        return r

    if nr == 0x2a:
        params = NVOS54_PARAMETERS.from_address(argp)
        print(f"{hex(params.cmd)}", f"({ioctl_map[('NV0000', params.cmd)]})" if ("NV0000", params.cmd) in ioctl_map else "")

    r = original["ioctl"](ctypes.c_int(fd), ctypes.c_ulong(cmd), ctypes.c_void_p(argp))
    if ioctl_name and (ioctl_name + "_PARAMS") in params_map:
        params_type = params_map[ioctl_name + "_PARAMS"]
        new_params = params_type.from_address(argp)
        for field, _ in params_type._fields_:
            new_value = getattr(new_params, field)
            if getattr(old_params, field) != new_value:
                print(f"(!){field} = {new_value}")
    return r

if __name__ == "__main__":
    import hevc2
    original["open"] = hook(hevc2.libc["open"], _open)
    original["openat"] = hook(hevc2.libc["openat"], _openat)

    CUhandle = ctypes.c_void_p
    libcuda = ctypes.CDLL("/lib64/libcuda.so")
    libcuda.cuInit(0)

    dev = CUhandle()
    ctx = CUhandle()

    libcuda.cuDeviceGet(ctypes.byref(dev), 0)
    libcuda.cuDevicePrimaryCtxRetain(ctypes.byref(ctx), dev)
    libcuda.cuCtxPushCurrent(ctx)

    original["ioctl"] = hook(hevc2.libc["ioctl"], _ioctl)
    hevc2.run()
