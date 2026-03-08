# -*- coding: utf-8 -*-
import os
import sys

from cffi import FFI
ffi = FFI()

USE_SHARED_BROTLI = os.environ.get("USE_SHARED_BROTLI")
if USE_SHARED_BROTLI != "1":
    libraries = ['libbrotli']
else:
    libraries = ['brotlienc', 'brotlidec']

    if 'win32' not in str(sys.platform).lower():
        libraries.append('stdc++')


ffi.set_source(
    "_brotlicffi",
    """#include <brotli/decode.h>
       #include <brotli/encode.h>
    """,
    libraries=libraries,
    include_dirs=["libbrotli/c", "libbrotli/c/include", "libbrotli/c/common"]
)

ffi.cdef("""
    /* common/types.h */
    typedef bool BROTLI_BOOL;
    #define BROTLI_TRUE ...
    #define BROTLI_FALSE ...

    /* dec/state.h */
    /* Allocating function pointer. Function MUST return 0 in the case of
       failure. Otherwise it MUST return a valid pointer to a memory region of
       at least size length. Neither items nor size are allowed to be 0.
       opaque argument is a pointer provided by client and could be used to
       bind function to specific object (memory pool). */
    typedef void* (*brotli_alloc_func)(void* opaque, size_t size);

    /* Deallocating function pointer. Function SHOULD be no-op in the case the
       address is 0. */
    typedef void (*brotli_free_func)(void* opaque, void* address);

    /* dec/decode.h */

    typedef enum {
      /* Decoding error, e.g. corrupt input or memory allocation problem */
      BROTLI_DECODER_RESULT_ERROR = 0,
      /* Decoding successfully completed */
      BROTLI_DECODER_RESULT_SUCCESS = 1,
      /* Partially done; should be called again with more input */
      BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT = 2,
      /* Partially done; should be called again with more output */
      BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT = 3
    } BrotliDecoderResult;

    typedef enum {...} BrotliDecoderErrorCode;
    typedef ... BrotliDecoderState;

    /* Creates the instance of BrotliDecoderState and initializes it.
       |alloc_func| and |free_func| MUST be both zero or both non-zero. In the
       case they are both zero, default memory allocators are used. |opaque| is
       passed to |alloc_func| and |free_func| when they are called. */
    BrotliDecoderState* BrotliDecoderCreateInstance(brotli_alloc_func,
                                                    brotli_free_func,
                                                    void *);

    /* Deinitializes and frees BrotliDecoderState instance. */
    void BrotliDecoderDestroyInstance(BrotliDecoderState* state);

    /* Decompresses the data. Supports partial input and output.

       Must be called with an allocated input buffer in |*next_in| and an
       allocated output buffer in |*next_out|. The values |*available_in| and
       |*available_out| must specify the allocated size in |*next_in| and
       |*next_out| respectively.

       After each call, |*available_in| will be decremented by the amount of
       input bytes consumed, and the |*next_in| pointer will be incremented by
       that amount. Similarly, |*available_out| will be decremented by the
       amount of output bytes written, and the |*next_out| pointer will be
       incremented by that amount. |total_out|, if it is not a null-pointer,
       will be set to the number of bytes decompressed since the last state
       initialization.

       Input is never overconsumed, so |next_in| and |available_in| could be
       passed to the next consumer after decoding is complete. */
    BrotliDecoderResult BrotliDecoderDecompressStream(BrotliDecoderState* s,
                                                      size_t* available_in,
                                                      const uint8_t** next_in,
                                                      size_t* available_out,
                                                      uint8_t** next_out,
                                                      size_t* total_out);

    /* Returns true, if decoder has some unconsumed output.
       Otherwise returns false. */
    BROTLI_BOOL BrotliDecoderHasMoreOutput(const BrotliDecoderState* s);

    /* Returns true, if decoder has already received some input bytes.
       Otherwise returns false. */
    BROTLI_BOOL BrotliDecoderIsUsed(const BrotliDecoderState* s);

    /* Returns true, if decoder is in a state where we reached the end of the
       input and produced all of the output; returns false otherwise. */
    BROTLI_BOOL BrotliDecoderIsFinished(const BrotliDecoderState* s);

    /* Returns detailed error code after BrotliDecompressStream returns
       BROTLI_DECODER_RESULT_ERROR. */
    BrotliDecoderErrorCode BrotliDecoderGetErrorCode(
                                                  const BrotliDecoderState* s);

    const char* BrotliDecoderErrorString(BrotliDecoderErrorCode c);

    /* enc/encode.h */
    typedef ... BrotliEncoderState;

    typedef enum BrotliEncoderParameter {
      BROTLI_PARAM_MODE = 0,
      /* Controls the compression-speed vs compression-density tradeoffs. The
         higher the quality, the slower the compression. Range is 0 to 11. */
      BROTLI_PARAM_QUALITY = 1,
      /* Base 2 logarithm of the sliding window size. Range is 10 to 24. */
      BROTLI_PARAM_LGWIN = 2,
      /* Base 2 logarithm of the maximum input block size. Range is 16 to 24.
         If set to 0, the value will be set based on the quality. */
      BROTLI_PARAM_LGBLOCK = 3
    } BrotliEncoderParameter;

    typedef enum BrotliEncoderMode {
      /* Default compression mode. The compressor does not know anything in
         advance about the properties of the input. */
      BROTLI_MODE_GENERIC = 0,
      /* Compression mode for UTF-8 format text input. */
      BROTLI_MODE_TEXT = 1,
      /* Compression mode used in WOFF 2.0. */
      BROTLI_MODE_FONT = 2
    } BrotliEncoderMode;

    int BROTLI_DEFAULT_QUALITY = 11;
    int BROTLI_DEFAULT_WINDOW = 22;
    #define BROTLI_DEFAULT_MODE ...

    typedef enum BrotliEncoderOperation {
      BROTLI_OPERATION_PROCESS = 0,
      /* Request output stream to flush. Performed when input stream is
         depleted and there is enough space in output stream. */
      BROTLI_OPERATION_FLUSH = 1,
      /* Request output stream to finish. Performed when input stream is
         depleted and there is enough space in output stream. */
      BROTLI_OPERATION_FINISH = 2
    } BrotliEncoderOperation;

    /* Creates the instance of BrotliEncoderState and initializes it.
       |alloc_func| and |free_func| MUST be both zero or both non-zero. In the
       case they are both zero, default memory allocators are used. |opaque| is
       passed to |alloc_func| and |free_func| when they are called. */
    BrotliEncoderState* BrotliEncoderCreateInstance(brotli_alloc_func,
                                                    brotli_free_func,
                                                    void *);

    /* Deinitializes and frees BrotliEncoderState instance. */
    void BrotliEncoderDestroyInstance(BrotliEncoderState* state);

    /* Compresses the data in |input_buffer| into |encoded_buffer|, and sets
       |*encoded_size| to the compressed length.
       BROTLI_DEFAULT_QUALITY, BROTLI_DEFAULT_WINDOW and BROTLI_DEFAULT_MODE
       should be used as |quality|, |lgwin| and |mode| if there are no specific
       requirements to encoder speed and compression ratio.
       If compression fails, |*encoded_size| is set to 0.
       If BrotliEncoderMaxCompressedSize(|input_size|) is not zero, then
       |*encoded_size| is never set to the bigger value.
       Returns false if there was an error and true otherwise. */
    BROTLI_BOOL BrotliEncoderCompress(int quality,
                                      int lgwin,
                                      BrotliEncoderMode mode,
                                      size_t input_size,
                                      const uint8_t* input_buffer,
                                      size_t* encoded_size,
                                      uint8_t* encoded_buffer);

    BROTLI_BOOL BrotliEncoderCompressStream(BrotliEncoderState* s,
                                            BrotliEncoderOperation op,
                                            size_t* available_in,
                                            const uint8_t** next_in,
                                            size_t* available_out,
                                            uint8_t** next_out,
                                            size_t* total_out);

    BROTLI_BOOL BrotliEncoderSetParameter(BrotliEncoderState* state,
                                          BrotliEncoderParameter p,
                                          uint32_t value);

    /* Check if encoder is in "finished" state, i.e. no more input is
       acceptable and no more output will be produced.
       Works only with BrotliEncoderCompressStream workflow.
       Returns 1 if stream is finished and 0 otherwise. */
    BROTLI_BOOL BrotliEncoderIsFinished(BrotliEncoderState* s);

    /* Check if encoder has more output bytes in internal buffer.
       Works only with BrotliEncoderCompressStream workflow.
       Returns 1 if has more output (in internal buffer) and 0 otherwise. */
    BROTLI_BOOL BrotliEncoderHasMoreOutput(BrotliEncoderState* s);
""")

if __name__ == '__main__':
    ffi.compile()
