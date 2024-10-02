
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

extern "C" {
#include "includes.h"

#include <sys/types.h>
#include "defines.h"
#include "digest.h"
#include "misc.h"
#include "ssherr.h"
#include "sshkey.h"


/* Digest algorithms */
// #define SSH_DIGEST_MD5    0
// #define SSH_DIGEST_SHA1   1
// #define SSH_DIGEST_SHA256 2 // default
// #define SSH_DIGEST_SHA384 3
// #define SSH_DIGEST_SHA512 4
// #define SSH_DIGEST_MAX    5

/* Fingerprint representation formats */
static const sshkey_fp_rep reps[] = {
    SSH_FP_DEFAULT,
    SSH_FP_HEX,
    SSH_FP_BASE64,
    SSH_FP_BUBBLEBABBLE,
    SSH_FP_RANDOMART
};

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    struct sshkey *k = NULL;
    if (sshkey_from_blob(data, size, &k) != 0) {
        return 0;
    }
    char *fp = NULL;
    fp = sshkey_fingerprint(k, 2, SSH_FP_DEFAULT);
    if (fp != NULL) free(fp);
    fp = sshkey_fingerprint(k, 2, SSH_FP_HEX);
    if (fp != NULL) free(fp);
    fp = sshkey_fingerprint(k, 2, SSH_FP_BASE64);
    if (fp != NULL) free(fp);
    fp = sshkey_fingerprint(k, 2, SSH_FP_BUBBLEBABBLE);
    if (fp != NULL) free(fp);
    fp = sshkey_fingerprint(k, 2, SSH_FP_RANDOMART);
    if (fp != NULL) free(fp);

    sshkey_free(k);
    return 0;
}

} // extern
