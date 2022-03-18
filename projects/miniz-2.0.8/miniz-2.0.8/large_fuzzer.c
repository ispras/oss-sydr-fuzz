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
static unsigned int diff;

/* Test mz_deflate() with large buffers and dynamic change of compression level */
void test_large_mz_deflate(unsigned char *compr, size_t comprLen,
                        unsigned char *uncompr, size_t uncomprLen)
{
    mz_stream c_stream; /* compression stream */
    int err;

    c_stream.zalloc = zalloc;
    c_stream.zfree = zfree;
    c_stream.opaque = NULL;

    err = mz_deflateInit(&c_stream, MZ_BEST_COMPRESSION);
    CHECK_ERR(err, "mz_deflateInit");

    c_stream.next_out = compr;
    c_stream.avail_out = (unsigned int)comprLen;

    /* At this point, uncompr is still mostly zeroes, so it should compress
    * very well:
    */
    c_stream.next_in = uncompr;
    c_stream.avail_in = (unsigned int)uncomprLen;
    err = mz_deflate(&c_stream, MZ_NO_FLUSH);
    CHECK_ERR(err, "mz_deflate large 1");

    if (c_stream.avail_in != 0)
    {
        fprintf(stderr, "mz_deflate not greedy\n");
        exit(1);
    }

    /* Feed in already compressed data: */
    c_stream.next_in = compr;
    diff = (unsigned int)(c_stream.next_out - compr);
    c_stream.avail_in = diff;

    mz_deflate(&c_stream, MZ_NO_FLUSH);
    err = mz_deflate(&c_stream, MZ_FINISH);

    if (err != MZ_STREAM_END)
    {
        fprintf(stderr, "mz_deflate large should report MZ_STREAM_END\n");
        exit(1);
    }
    err = mz_deflateEnd(&c_stream);
    CHECK_ERR(err, "mz_deflateEnd");
}

/* Test mz_inflate() with large buffers */
void test_large_mz_inflate(unsigned char *compr, size_t comprLen,
                        unsigned char *uncompr, size_t uncomprLen)
{
    int err;
    mz_stream d_stream; /* decompression stream */

    d_stream.zalloc = zalloc;
    d_stream.zfree = zfree;
    d_stream.opaque = NULL;

    d_stream.next_in = compr;
    d_stream.avail_in = (unsigned int)comprLen;

    err = mz_inflateInit(&d_stream);
    CHECK_ERR(err, "mz_inflateInit");

    for (;;)
    {
        d_stream.next_out = uncompr; /* discard the output */
        d_stream.avail_out = (unsigned int)uncomprLen;
        err = mz_inflate(&d_stream, MZ_NO_FLUSH);
        if (err == MZ_STREAM_END) break;

        CHECK_ERR(err, "large mz_inflate");
    }

    err = mz_inflateEnd(&d_stream);
    CHECK_ERR(err, "mz_inflateEnd");
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t size)
{
    size_t comprLen = 100 + 3 * size;
    size_t uncomprLen = comprLen;
    uint8_t *compr, *uncompr;

    /* Discard inputs larger than 512Kb. */
    static size_t kMaxSize = 512 * 1024;

    if (size < 1 || size > kMaxSize)
    return 0;

    data = d;
    dataLen = size;
    compr = calloc(1, comprLen);
    uncompr = calloc(1, uncomprLen);

    test_large_mz_deflate(compr, comprLen, uncompr, uncomprLen);
    test_large_mz_inflate(compr, comprLen, uncompr, uncomprLen);

    free(compr);
    free(uncompr);

    return 0;
}
