#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "check_aec.h"

static int check_split_truncated_binary_part(void)
{
    /*
       A single split-coded block (ID 010, k = 1) followed by zeros.
       The input is long enough for the decoder's fast path, but the
       zero bits are read as one long fundamental sequence that
       consumes the input needed for the binary part. The decoder
       must report a data error instead of returning garbage.
     */
    unsigned char in[32] = {0x40};
    unsigned char out[8];
    struct aec_stream strm;
    int status;

    printf("Checking split block with exhausted binary part ... ");

    memset(&strm, 0, sizeof(strm));
    strm.bits_per_sample = 8;
    strm.block_size = 8;
    strm.rsi = 1;
    strm.flags = 0;
    strm.next_in = in;
    strm.avail_in = sizeof(in);
    strm.next_out = out;
    strm.avail_out = sizeof(out);

    status = aec_buffer_decode(&strm);
    if (status != AEC_DATA_ERROR) {
        printf("%s: expected AEC_DATA_ERROR, got %i\n", CHECK_FAIL, status);
        return 99;
    }

    printf("%s\n", CHECK_PASS);
    return 0;
}

static int check_se_huge_fs_small_output(void)
{
    /*
       A Second Extension block (ID 000, then 1) whose first
       fundamental sequence is longer than 2^31 zero bits. A one-byte
       output buffer forces the decoder's slow path. The FS length
       must not wrap to a negative table index; the decoder must
       report a data error instead of reading outside se_table.
     */
    const size_t zero_len = 1 << 20;
    const size_t zero_chunks = (1UL << 31) / 8 / zero_len;
    unsigned char head = 0x10;
    unsigned char tail = 0xff;
    unsigned char *zeros;
    unsigned char out[1];
    struct aec_stream strm;
    int status;

    printf("Checking second extension with huge fundamental sequence ... ");

    zeros = calloc(zero_len, 1);
    if (zeros == NULL) {
        fprintf(stderr, "Not enough memory.\n");
        return 99;
    }

    memset(&strm, 0, sizeof(strm));
    strm.bits_per_sample = 8;
    strm.block_size = 8;
    strm.rsi = 1;
    strm.flags = 0;

    if (aec_decode_init(&strm) != AEC_OK) {
        printf("%s: init failed\n", CHECK_FAIL);
        free(zeros);
        return 99;
    }

    strm.next_out = out;
    strm.avail_out = sizeof(out);
    strm.next_in = &head;
    strm.avail_in = 1;
    status = aec_decode(&strm, AEC_NO_FLUSH);

    for (size_t i = 0; i < zero_chunks && status == AEC_OK; i++) {
        strm.next_in = zeros;
        strm.avail_in = zero_len;
        status = aec_decode(&strm, AEC_NO_FLUSH);
    }

    if (status == AEC_OK) {
        strm.next_in = &tail;
        strm.avail_in = 1;
        status = aec_decode(&strm, AEC_NO_FLUSH);
    }

    aec_decode_end(&strm);
    free(zeros);

    if (status != AEC_DATA_ERROR) {
        printf("%s: expected AEC_DATA_ERROR, got %i\n", CHECK_FAIL, status);
        return 99;
    }

    printf("%s\n", CHECK_PASS);
    return 0;
}

int main(void)
{
    int status = check_split_truncated_binary_part();
    if (status)
        return status;
    return check_se_huge_fs_small_output();
}
