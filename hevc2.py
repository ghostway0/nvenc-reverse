import ctypes, time, threading, os
from typing import Optional
from queue import Queue

CUresult = ctypes.c_int
CUhandle = ctypes.c_void_p
CUvideodecoder = ctypes.c_void_p
CUvideoparser = ctypes.c_void_p
CUVIDEOFORMATEX = ctypes.c_void_p
CUvideotimestamp = ctypes.c_void_p

libnvcuvid = ctypes.CDLL("/lib64/libnvcuvid.so")
libcuda = ctypes.CDLL("/lib64/libcuda.so")
libc = ctypes.CDLL("/lib64/libc.so.6")

libc.backtrace.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_int]
libc.backtrace.restype = ctypes.c_int

libc.backtrace_symbols.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_int]
libc.backtrace_symbols.restype = ctypes.POINTER(ctypes.c_char_p)

def get_backtrace(max_frames=32):
    buffer = (ctypes.c_void_p * max_frames)()
    n = libc.backtrace(buffer, max_frames)

    symbols = libc.backtrace_symbols(buffer, n)
    result = []
    for i in range(n):
        result.append(symbols[i].decode("utf-8", errors="replace"))
    return result

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

class FrameRate(RStructure):
    _fields_ = [('numerator', ctypes.c_uint), ('denominator', ctypes.c_uint)]

class DisplayArea(RStructure):
    _fields_ = [('left', ctypes.c_int), ('top', ctypes.c_int), ('right', ctypes.c_int), ('bottom', ctypes.c_int)]

class RectShort(RStructure):
    _fields_ = [('left', ctypes.c_short), ('top', ctypes.c_short), ('right', ctypes.c_short), ('bottom', ctypes.c_short)]

class CUVIDEOFORMAT(RStructure):
    _fields_ = [
        ('codec', ctypes.c_int), ('frame_rate', FrameRate), ('progressive_sequence', ctypes.c_int),
        ('coded_width', ctypes.c_uint), ('coded_height', ctypes.c_uint), ('display_area', DisplayArea),
        ('chroma_format', ctypes.c_int), ('bitrate', ctypes.c_uint), ('reserved', ctypes.c_uint * 20)
    ]

class CUVIDDECODECREATEINFO(RStructure):
    _fields_ = [
        ('ulWidth', ctypes.c_ulong), ('ulHeight', ctypes.c_ulong), ('ulNumDecodeSurfaces', ctypes.c_ulong),
        ('CodecType', ctypes.c_int), ('ChromaFormat', ctypes.c_int), ('ulCreationFlags', ctypes.c_ulong),
        ('bitDepthMinus8', ctypes.c_ulong), ('ulIntraDecodeOnly', ctypes.c_ulong), ('ulMaxWidth', ctypes.c_ulong),
        ('ulMaxHeight', ctypes.c_ulong), ('Reserved1', ctypes.c_ulong), ('display_area', RectShort),
        ('OutputFormat', ctypes.c_int), ('DeinterlaceMode', ctypes.c_int), ('ulTargetWidth', ctypes.c_ulong),
        ('ulTargetHeight', ctypes.c_ulong), ('ulNumOutputSurfaces', ctypes.c_ulong), ('vidLock', ctypes.c_void_p),
        ('target_rect', RectShort), ('enableHistogram', ctypes.c_int), ('Reserved2', ctypes.c_ulong * 4)
    ]

class CUVIDPROCPARAMS(RStructure):
    _fields_ = [
        ('progressive_frame', ctypes.c_int), ('second_field', ctypes.c_int), ('top_field_first', ctypes.c_int),
        ('unpaired_field', ctypes.c_int), ('reserved_flags', ctypes.c_uint), ('reserved_zero', ctypes.c_uint),
        ('raw_input_dptr', ctypes.c_ulonglong), ('raw_input_pitch', ctypes.c_uint), ('raw_input_format', ctypes.c_uint),
        ('raw_output_dptr', ctypes.c_ulonglong), ('raw_output_pitch', ctypes.c_uint), ('Reserved1', ctypes.c_uint),
        ('output_stream', ctypes.c_void_p), ('Reserved', ctypes.c_uint * 46), ('Reserved2', ctypes.c_void_p * 2)
    ]

class CUVIDPICPARAMS(RStructure):
    _pack_ = 1
    _fields_ = [
        ('PicWidthInMbs', ctypes.c_int), ('FrameHeightInMbs', ctypes.c_int), ('CurrPicIdx', ctypes.c_int),
        ('field_pic_flag', ctypes.c_int), ('bottom_field_flag', ctypes.c_int), ('second_field', ctypes.c_int),
        ('nBitstreamDataLen', ctypes.c_uint), ('pBitstreamData', ctypes.c_void_p), ('nNumSlices', ctypes.c_uint),
        ('pSliceDataOffsets', ctypes.c_void_p), ('ref_pic_flag', ctypes.c_int), ('intra_pic_flag', ctypes.c_int),
        ('Reserved', ctypes.c_uint * 30), ('CodecSpecific', ctypes.c_uint * 1024)
    ]

class CUVIDPARSERDISPINFO(RStructure):
    _fields_ = [
        ('picture_index', ctypes.c_int), ('progressive_frame', ctypes.c_int), ('top_field_first', ctypes.c_int),
        ('repeat_first_field', ctypes.c_int), ('timestamp', ctypes.c_void_p)
    ]

class CUVIDSOURCEDATAPACKET(RStructure):
    _fields_ = [
        ('flags', ctypes.c_ulong), ('payload_size', ctypes.c_ulong),
        ('payload', ctypes.c_void_p), ('timestamp', CUvideotimestamp)
    ]

PFNVIDSEQUENCECALLBACK = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(CUVIDEOFORMAT))
PFNVIDDECODECALLBACK = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(CUVIDPICPARAMS))
PFNVIDDISPLAYCALLBACK = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(CUVIDPARSERDISPINFO))

class CUVIDPARSERPARAMS(RStructure):
    _fields_ = [
        ('CodecType', ctypes.c_int), ('ulMaxNumDecodeSurfaces', ctypes.c_uint), ('ulClockRate', ctypes.c_uint),
        ('ulErrorThreshold', ctypes.c_uint), ('ulMaxDisplayDelay', ctypes.c_uint), ('uReserved1', ctypes.c_uint * 5),
        ('pUserData', ctypes.c_void_p), ('pfnSequenceCallback', PFNVIDSEQUENCECALLBACK),
        ('pfnDecodePicture', PFNVIDDECODECALLBACK), ('pfnDisplayPicture', PFNVIDDISPLAYCALLBACK),
        ('pvReserved2', ctypes.c_void_p * 7), ('pExtVideoInfo', ctypes.POINTER(CUVIDEOFORMATEX))
    ]

libnvcuvid.cuvidCreateDecoder.argtypes = [ctypes.POINTER(CUvideodecoder), ctypes.POINTER(CUVIDDECODECREATEINFO)]
libnvcuvid.cuvidCreateDecoder.restype = CUresult
libnvcuvid.cuvidDestroyDecoder.argtypes = [CUvideodecoder]
libnvcuvid.cuvidDestroyDecoder.restype = CUresult
libnvcuvid.cuvidCreateVideoParser.argtypes = [ctypes.POINTER(CUvideoparser), ctypes.POINTER(CUVIDPARSERPARAMS)]
libnvcuvid.cuvidCreateVideoParser.restype = CUresult
libnvcuvid.cuvidDestroyVideoParser.argtypes = [CUvideoparser]
libnvcuvid.cuvidDestroyVideoParser.restype = CUresult
libnvcuvid.cuvidParseVideoData.argtypes = [CUvideoparser, ctypes.POINTER(CUVIDSOURCEDATAPACKET)]
libnvcuvid.cuvidParseVideoData.restype = CUresult
libnvcuvid.cuvidDecodePicture.argtypes = [CUvideodecoder, ctypes.POINTER(CUVIDPICPARAMS)]
libnvcuvid.cuvidDecodePicture.restype = CUresult
libnvcuvid.cuvidMapVideoFrame.argtypes = [CUvideodecoder, ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(CUVIDPROCPARAMS)]
libnvcuvid.cuvidMapVideoFrame.restype = CUresult
libnvcuvid.cuvidUnmapVideoFrame.argtypes = [CUvideodecoder, ctypes.c_void_p]
libnvcuvid.cuvidUnmapVideoFrame.restype = CUresult

CUDA_SUCCESS = 0
HEVC_CODEC = 8
CHROMA_420 = 1
SURFACE_FORMAT_NV12 = 0
DEINTERLACE_WEAVE = 0

class VideoContext:
    def __init__(self):
        self.decoder: Optional[CUvideodecoder] = None
        self.parser: Optional[CUvideoparser] = None
        self.width = 0
        self.height = 0
        self.frame_queue = Queue()
        self.surface_in_use = [False] * 16
        self.lock = threading.Lock()

class HEVCDecoder:
    def __init__(self, max_surfaces: int = 8):
        self.ctx = VideoContext()
        self.max_surfaces = max_surfaces
        self._setup_callbacks()

    def _setup_callbacks(self):
        @PFNVIDSEQUENCECALLBACK
        def sequence_cb(user_data, format_info):
            fmt = format_info.contents
            return 1 if self._create_decoder(fmt.coded_width, fmt.coded_height) else 0

        @PFNVIDDECODECALLBACK
        def decode_cb(user_data, pic_params):
            result = libnvcuvid.cuvidDecodePicture(self.ctx.decoder, pic_params)
            return 1 if result == CUDA_SUCCESS else 0

        @PFNVIDDISPLAYCALLBACK
        def display_cb(user_data, disp_info):
            disp = disp_info.contents
            if disp.picture_index < len(self.ctx.surface_in_use):
                self.ctx.surface_in_use[disp.picture_index] = True
            self.ctx.frame_queue.put(disp)
            os._exit(0)
            return 1

        self.callbacks = (sequence_cb, decode_cb, display_cb)

    def _create_decoder(self, width: int, height: int) -> bool:
        with self.ctx.lock:
            if self.ctx.decoder:
                libnvcuvid.cuvidDestroyDecoder(self.ctx.decoder)

            create_info = CUVIDDECODECREATEINFO(
                ulWidth=width, ulHeight=height, ulNumDecodeSurfaces=self.max_surfaces,
                CodecType=HEVC_CODEC, ChromaFormat=CHROMA_420, ulCreationFlags=0x4,
                OutputFormat=SURFACE_FORMAT_NV12, DeinterlaceMode=DEINTERLACE_WEAVE,
                ulTargetWidth=width, ulTargetHeight=height, ulNumOutputSurfaces=2,
                ulMaxWidth=width, ulMaxHeight=height,
                display_area=RectShort(right=width, bottom=height)
            )

            self.ctx.decoder = CUvideodecoder()
            result = libnvcuvid.cuvidCreateDecoder(ctypes.byref(self.ctx.decoder), ctypes.byref(create_info))
            print(hex(ctypes.c_uint64.from_address(libnvcuvid._handle).value))

            from thing import hook_mem, install_mem_hooks
            a = ctypes.c_uint64.from_address(self.ctx.decoder.value + 0x8).value
            b = ctypes.c_uint64.from_address(a + 0x23c4a8).value
            addr = ctypes.c_uint64.from_address(b + 0x270 * 0x6 + 0x198 + 0x60).value
            hook_mem(addr & (~0xFFF), 0x30000)
            install_mem_hooks()

            if result == CUDA_SUCCESS:
                self.ctx.width, self.ctx.height = width, height
                return True
            return False

    def create_parser(self) -> bool:
        if self.ctx.parser:
            libnvcuvid.cuvidDestroyVideoParser(self.ctx.parser)

        parser_params = CUVIDPARSERPARAMS(
            CodecType=HEVC_CODEC, ulMaxNumDecodeSurfaces=self.max_surfaces,
            pUserData=ctypes.cast(ctypes.pointer(ctypes.py_object(self)), ctypes.c_void_p),
            pfnSequenceCallback=self.callbacks[0], pfnDecodePicture=self.callbacks[1],
            pfnDisplayPicture=self.callbacks[2]
        )

        self.ctx.parser = CUvideoparser()
        result = libnvcuvid.cuvidCreateVideoParser(ctypes.byref(self.ctx.parser), ctypes.byref(parser_params))
        return result == CUDA_SUCCESS

    def parse_data(self, data: bytes) -> bool:
        if not self.ctx.parser:
            return False

        packet = CUVIDSOURCEDATAPACKET(
            flags=0x2, payload_size=len(data),
            payload=ctypes.cast(data, ctypes.c_void_p), timestamp=0
        )

        result = libnvcuvid.cuvidParseVideoData(self.ctx.parser, ctypes.byref(packet))
        return result == CUDA_SUCCESS

    def get_frame(self) -> Optional[tuple[ctypes.c_void_p, int, int]]:
        if self.ctx.frame_queue.empty():
            return None

        disp_info = self.ctx.frame_queue.get()
        mapped_frame = ctypes.c_void_p()
        pitch = ctypes.c_uint()

        proc_params = CUVIDPROCPARAMS(progressive_frame=1)
        result = libnvcuvid.cuvidMapVideoFrame(
            self.ctx.decoder, disp_info.picture_index, ctypes.byref(mapped_frame),
            ctypes.byref(pitch), ctypes.byref(proc_params)
        )

        if result == CUDA_SUCCESS:
            return mapped_frame, pitch.value, disp_info.picture_index
        return None

    def release_frame(self, mapped_frame: ctypes.c_void_p, pic_index: int):
        libnvcuvid.cuvidUnmapVideoFrame(self.ctx.decoder, mapped_frame)
        if pic_index < len(self.ctx.surface_in_use):
            self.ctx.surface_in_use[pic_index] = False

    def cleanup(self):
        with self.ctx.lock:
            if self.ctx.parser:
                libnvcuvid.cuvidDestroyVideoParser(self.ctx.parser)
                self.ctx.parser = None
            if self.ctx.decoder:
                libnvcuvid.cuvidDestroyDecoder(self.ctx.decoder)
                self.ctx.decoder = None

def run():
    decoder = HEVCDecoder()
    if decoder.create_parser():
        with open("video.h265", "rb") as f:
            print("start")
            decoder.parse_data(f.read())

        time.sleep(0.5)
        while True:
            frame_data = decoder.get_frame()
            if not frame_data:
                break

            mapped_ptr, pitch, pic_idx = frame_data
            decoder.release_frame(mapped_ptr, pic_idx)

    decoder.cleanup()

if __name__ == "__main__":
    CUhandle = ctypes.c_void_p
    libcuda = ctypes.CDLL("/lib64/libcuda.so")
    libcuda.cuInit(0)

    dev = CUhandle()
    ctx = CUhandle()

    libcuda.cuDeviceGet(ctypes.byref(dev), 0)
    libcuda.cuDevicePrimaryCtxRetain(ctypes.byref(ctx), dev)
    libcuda.cuCtxPushCurrent(ctx)
    run()
