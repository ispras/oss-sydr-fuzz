/* Derived from zlib fuzzers at http://github.com/google/oss-fuzz/tree/master/projects/zlib,
 * see ossfuzz.sh for full license text.
*/

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include "miniz.h"

#define CHECK_ERR(err, msg) { \
    if (err != MZ_OK) { \
        fprintf(stderr, "%s error: %d\n", msg, err); \
        exit(1); \
    } \
}

static const uint8_t *data;
static size_t dataLen;
static mz_alloc_func zalloc = NULL;
static mz_free_func zfree = NULL;

/* Test mz_deflate() with small buffers */
void test_mz_deflate(unsigned char *compr, size_t comprLen)
{
    mz_stream c_stream; /* compression stream */
    int err;
    unsigned long len = dataLen;

    c_stream.zalloc = zalloc;
    c_stream.zfree = zfree;
    c_stream.opaque = NULL;

    err = mz_deflateInit(&c_stream, MZ_DEFAULT_COMPRESSION);
    CHECK_ERR(err, "mz_deflateInit");

    c_stream.next_in = (unsigned char *)data;
    c_stream.next_out = compr;

    while (c_stream.total_in != len && c_stream.total_out < comprLen)
    {
        c_stream.avail_in = c_stream.avail_out = 1; /* force small buffers */
        err = mz_deflate(&c_stream, MZ_NO_FLUSH);
        CHECK_ERR(err, "mz_deflate small 1");
    }

    /* Finish the stream, still forcing small buffers: */
    for (;;)
    {
        c_stream.avail_out = 1;
        err = mz_deflate(&c_stream, MZ_FINISH);
        if (err == MZ_STREAM_END)
            break;
        CHECK_ERR(err, "mz_deflate small 2");
    }

    err = mz_deflateEnd(&c_stream);
    CHECK_ERR(err, "mz_deflateEnd");
}

/* Test mz_inflate() with small buffers */
void test_mz_inflate(unsigned char *compr, size_t comprLen, unsigned char *uncompr, size_t uncomprLen)
{
    int err;
    mz_stream d_stream; /* decompression stream */

    d_stream.zalloc = zalloc;
    d_stream.zfree = zfree;
    d_stream.opaque = NULL;

    d_stream.next_in = compr;
    d_stream.avail_in = 0;
    d_stream.next_out = uncompr;

    err = mz_inflateInit(&d_stream);
    CHECK_ERR(err, "mz_inflateInit");

    while (d_stream.total_out < uncomprLen && d_stream.total_in < comprLen)
    {
        d_stream.avail_in = d_stream.avail_out = 1; /* force small buffers */
        err = mz_inflate(&d_stream, MZ_NO_FLUSH);
        if (err == MZ_STREAM_END)
            break;
        CHECK_ERR(err, "mz_inflate");
    }

    err = mz_inflateEnd(&d_stream);
    CHECK_ERR(err, "mz_inflateEnd");

    if (memcmp(uncompr, data, dataLen))
    {
        fprintf(stderr, "bad mz_inflate\n");
        exit(1);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t size)
{
    size_t comprLen = mz_compressBound(size);
    size_t uncomprLen = size;
    uint8_t *compr, *uncompr;

    /* Discard inputs larger than 1Mb. */
    static size_t kMaxSize = 1024 * 1024;

    if (size < 1 || size > kMaxSize)
    return 0;

    data = d;
    dataLen = size;
    compr = calloc(1, comprLen);
    uncompr = calloc(1, uncomprLen);

    test_mz_deflate(compr, comprLen);
    test_mz_inflate(compr, comprLen, uncompr, uncomprLen);

    free(compr);
    free(uncompr);

    return 0;
}
