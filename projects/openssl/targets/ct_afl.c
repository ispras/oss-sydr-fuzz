/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 * Modifications copyright (C) 2021 ISP RAS
 *
 * Licensed under the Apache License 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

/*
 * Fuzz the SCT parser.
 */

#include <stdio.h>
#include <openssl/ct.h>
#include <openssl/err.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include "fuzzer.h"

__AFL_FUZZ_INIT();

int FuzzerInitialize(int *argc, char ***argv)
{
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    CRYPTO_free_ex_index(0, -1);
    ERR_clear_error();
    return 1;
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    const uint8_t **pp = &buf;
    unsigned char *der = NULL;
    STACK_OF(SCT) *scts = d2i_SCT_LIST(NULL, pp, len);
    if (scts != NULL) {
        BIO *bio = BIO_new(BIO_s_null());
        SCT_LIST_print(scts, bio, 4, "\n", NULL);
        BIO_free(bio);

        if (i2d_SCT_LIST(scts, &der)) {
            /* Silence unused result warning */
        }
        OPENSSL_free(der);

        SCT_LIST_free(scts);
    }
    ERR_clear_error();
    return 0;
}

void FuzzerCleanup(void)
{
}

int
main(int argc, char **argv)
{
    FuzzerInitialize(&argc, &argv);

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    uint8_t *data = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(1000))
    {
        size_t size = __AFL_FUZZ_TESTCASE_LEN;

        FuzzerTestOneInput(data, size);
    }

    FuzzerCleanup();

    return 0;
}
