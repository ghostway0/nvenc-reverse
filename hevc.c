#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cuda.h>
#include <nvcuvid.h>

#define CUDA_DRVAPI_CALL(call)                                  \
    do {                                                        \
        CUresult err = call;                                    \
        if (err != CUDA_SUCCESS) {                              \
            const char *errStr;                                 \
            cuGetErrorString(err, &errStr);                     \
            fprintf(stderr, "%s failed with %s\n", #call, errStr); \
            exit(1);                                            \
        }                                                       \
    } while (0)

typedef struct {
    CUvideodecoder decoder;
    CUvideoparser parser;
    unsigned int width;
    unsigned int height;
} VideoContext;

static int CUDAAPI HandleVideoSequence(void *pUserData, CUVIDEOFORMAT *pFormat) {
    VideoContext *ctx = (VideoContext *)pUserData;

    CUVIDDECODECREATEINFO createInfo = {0};
    createInfo.CodecType = cudaVideoCodec_HEVC;
    createInfo.ulWidth  = pFormat->coded_width;
    createInfo.ulHeight = pFormat->coded_height;
    createInfo.ulNumDecodeSurfaces = 8;
    createInfo.ChromaFormat = cudaVideoChromaFormat_420;
    createInfo.OutputFormat = cudaVideoSurfaceFormat_NV12;
    createInfo.DeinterlaceMode = cudaVideoDeinterlaceMode_Weave;
    createInfo.ulTargetWidth  = pFormat->coded_width;
    createInfo.ulTargetHeight = pFormat->coded_height;

    if (ctx->decoder) {
        cuvidDestroyDecoder(ctx->decoder);
        ctx->decoder = NULL;
    }

    CUDA_DRVAPI_CALL(cuvidCreateDecoder(&ctx->decoder, &createInfo));
    ctx->width = pFormat->coded_width;
    ctx->height = pFormat->coded_height;

    printf("Created decoder %p %ux%u\n", ctx->decoder, ctx->width, ctx->height);
    return 1;
}

static int CUDAAPI HandlePictureDecode(void *pUserData, CUVIDPICPARAMS *pPicParams) {
    VideoContext *ctx = (VideoContext *)pUserData;
    CUDA_DRVAPI_CALL(cuvidDecodePicture(ctx->decoder, pPicParams));
    return 1;
}

static int CUDAAPI HandlePictureDisplay(void *pUserData, CUVIDPARSERDISPINFO *pDispInfo) {
    VideoContext *ctx = (VideoContext *)pUserData;
    CUdeviceptr dptr = 0;
    unsigned int pitch = 0;
    CUVIDPROCPARAMS procParams = {0};

    // CUDA_DRVAPI_CALL(cuvidMapVideoFrame(ctx->decoder, pDispInfo->picture_index,
    //                                     &dptr, &pitch, &procParams));
    //
    // printf("Mapped frame %d, device ptr=%p, pitch=%u\n",
    //        pDispInfo->picture_index, (void*)(uintptr_t)dptr, pitch);

    // CUDA_DRVAPI_CALL(cuvidUnmapVideoFrame(ctx->decoder, dptr));
    return 1;
}

int main(void) {
    VideoContext ctx;
    memset(&ctx, 0, sizeof(ctx));

    // Init CUDA
    CUdevice dev;
    CUcontext cuCtx = NULL;
    CUDA_DRVAPI_CALL(cuInit(0));
    CUDA_DRVAPI_CALL(cuDeviceGet(&dev, 0));
    CUctxCreateParams ctxCreateParams = {};
    cuCtxCreate(&cuCtx, &ctxCreateParams, 0, dev);

    // Parser params
    CUVIDPARSERPARAMS parserParams = {0};
    parserParams.CodecType = cudaVideoCodec_HEVC;
    parserParams.ulMaxNumDecodeSurfaces = 8;
    parserParams.pUserData = &ctx;
    parserParams.pfnSequenceCallback = HandleVideoSequence;
    parserParams.pfnDecodePicture   = HandlePictureDecode;
    parserParams.pfnDisplayPicture  = HandlePictureDisplay;

    CUDA_DRVAPI_CALL(cuvidCreateVideoParser(&ctx.parser, &parserParams));

    // Read a sample H.265 file
    FILE *f = fopen("video.h265", "rb");
    if (!f) {
        perror("video.h265");
        return 1;
    }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);

    uint8_t *buffer = (uint8_t*)malloc(size);
    fread(buffer, 1, size, f);
    fclose(f);

    CUVIDSOURCEDATAPACKET pkt = {0};
    pkt.payload = buffer;
    pkt.payload_size = size;
    pkt.flags = CUVID_PKT_ENDOFSTREAM; // or 0

    CUDA_DRVAPI_CALL(cuvidParseVideoData(ctx.parser, &pkt));

    // Cleanup
    cuvidDestroyVideoParser(ctx.parser);
    if (ctx.decoder)
        cuvidDestroyDecoder(ctx.decoder);
    cuCtxDestroy(cuCtx);
    free(buffer);

    return 0;
}

