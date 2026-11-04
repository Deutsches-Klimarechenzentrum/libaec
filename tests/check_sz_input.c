#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "szlib.h"
#include "check_aec.h"

#define NPIXELS 1000

static int check_negative_params(void)
{
    /*
       SZ_com_t fields are signed. Negative values must be rejected
       before they are used to size the padding buffer.
     */
    SZ_com_t bad[] = {
        {0, 8, 8, -100},
        {0, 8, -2, 10},
        {0, -8, 8, 10},
    };
    unsigned char source[200];
    unsigned char dest[4096];

    printf("Checking negative SZ parameters ... ");

    memset(source, 0, sizeof(source));
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        size_t destLen = sizeof(dest);
        int status = SZ_BufftoBuffCompress(dest, &destLen,
                                           source, sizeof(source), &bad[i]);
        if (status != SZ_PARAM_ERROR) {
            printf("%s: compress %zu: expected SZ_PARAM_ERROR, got %i\n",
                   CHECK_FAIL, i, status);
            return 99;
        }
        destLen = sizeof(dest);
        status = SZ_BufftoBuffDecompress(dest, &destLen,
                                         source, sizeof(source), &bad[i]);
        if (status != SZ_PARAM_ERROR) {
            printf("%s: decompress %zu: expected SZ_PARAM_ERROR, got %i\n",
                   CHECK_FAIL, i, status);
            return 99;
        }
    }

    printf("%s\n", CHECK_PASS);
    return 0;
}

static int check_truncated_padded_scanlines(void)
{
    /*
       Scanlines that are not a multiple of the block size take the
       padding path in SZ_BufftoBuffDecompress. With truncated input
       destLen must only cover the decoded pixels, not the whole
       requested buffer.
     */
    SZ_com_t param = {SZ_MSB_OPTION_MASK | SZ_NN_OPTION_MASK, 8, 8, 10};
    unsigned char source[NPIXELS];
    unsigned char comp[2 * NPIXELS];
    unsigned char dest[NPIXELS];
    size_t compLen = sizeof(comp);
    size_t destLen;
    int status;

    printf("Checking SZ decompression of truncated padded scanlines ... ");

    for (size_t i = 0; i < NPIXELS; i++)
        source[i] = (unsigned char)(i * i / 7);

    status = SZ_BufftoBuffCompress(comp, &compLen,
                                   source, sizeof(source), &param);
    if (status != SZ_OK) {
        printf("%s: compress failed with %i\n", CHECK_FAIL, status);
        return 99;
    }

    destLen = sizeof(dest);
    status = SZ_BufftoBuffDecompress(dest, &destLen, comp, compLen, &param);
    if (status != SZ_OK || destLen != NPIXELS
        || memcmp(source, dest, NPIXELS) != 0) {
        printf("%s: full round trip failed\n", CHECK_FAIL);
        return 99;
    }

    destLen = sizeof(dest);
    status = SZ_BufftoBuffDecompress(dest, &destLen,
                                     comp, compLen / 2, &param);
    if (status != SZ_OK) {
        printf("%s: decompress failed with %i\n", CHECK_FAIL, status);
        return 99;
    }
    if (destLen >= NPIXELS || memcmp(source, dest, destLen) != 0) {
        printf("%s: destLen %zu doesn't match decoded data\n",
               CHECK_FAIL, destLen);
        return 99;
    }

    printf("%s\n", CHECK_PASS);
    return 0;
}

int main(void)
{
    int status = check_negative_params();
    if (status)
        return status;
    return check_truncated_padded_scanlines();
}
