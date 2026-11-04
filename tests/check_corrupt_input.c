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

static void put_bits(unsigned char *buf, size_t *bitp,
                     unsigned int data, int n)
{
    while (n--) {
        if ((data >> n) & 1)
            buf[*bitp >> 3] |= 0x80 >> (*bitp & 7);
        (*bitp)++;
    }
}

static void put_fs(unsigned char *buf, size_t *bitp, unsigned int fs)
{
    *bitp += fs;
    put_bits(buf, bitp, 1, 1);
}

static int check_decode_after_error(void)
{
    /*
       A Second Extension block that decodes one pair of samples and
       then fails on an FS beyond the SE table, followed by valid
       blocks. The first call fails after part of the block has been
       written to rsi_buffer. Calling aec_decode() again must keep
       failing instead of decoding more blocks past the end of
       rsi_buffer.
     */
    unsigned char in[128];
    unsigned char out[1024];
    size_t bitp = 0;
    struct aec_stream strm;
    int status;

    printf("Checking decoding after data error ... ");

    memset(in, 0, sizeof(in));
    put_bits(in, &bitp, 1, 4);
    put_fs(in, &bitp, 0);
    put_fs(in, &bitp, 91);
    for (int b = 0; b < 8; b++) {
        put_bits(in, &bitp, 1, 4);
        for (int i = 0; i < 4; i++)
            put_fs(in, &bitp, 0);
    }

    memset(&strm, 0, sizeof(strm));
    strm.bits_per_sample = 8;
    strm.block_size = 8;
    strm.rsi = 1;
    strm.flags = 0;

    if (aec_decode_init(&strm) != AEC_OK) {
        printf("%s: init failed\n", CHECK_FAIL);
        return 99;
    }

    strm.next_in = in;
    strm.avail_in = sizeof(in);
    strm.next_out = out;
    strm.avail_out = sizeof(out);

    status = aec_decode(&strm, AEC_FLUSH);
    if (status == AEC_DATA_ERROR)
        status = aec_decode(&strm, AEC_FLUSH);
    aec_decode_end(&strm);

    if (status != AEC_DATA_ERROR) {
        printf("%s: expected AEC_DATA_ERROR, got %i\n", CHECK_FAIL, status);
        return 99;
    }

    printf("%s\n", CHECK_PASS);
    return 0;
}

static int check_decode_range_truncated(void)
{
    /*
       An uncompressed block ID without any sample data. The
       requested range can't be decoded, so aec_decode_range() must
       report a data error instead of returning uninitialized
       memory.
     */
    unsigned char in[1] = {0xe0};
    unsigned char out[64];
    size_t offsets[1] = {0};
    struct aec_stream strm;
    int status;

    printf("Checking range decoding of truncated input ... ");

    memset(&strm, 0, sizeof(strm));
    strm.bits_per_sample = 8;
    strm.block_size = 8;
    strm.rsi = 8;
    strm.flags = 0;
    strm.next_in = in;
    strm.avail_in = sizeof(in);

    if (aec_decode_init(&strm) != AEC_OK) {
        printf("%s: init failed\n", CHECK_FAIL);
        return 99;
    }

    strm.next_out = out;
    strm.avail_out = sizeof(out);
    status = aec_decode_range(&strm, offsets, 1, 0, sizeof(out));
    aec_decode_end(&strm);

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
    status = check_se_huge_fs_small_output();
    if (status)
        return status;
    status = check_decode_after_error();
    if (status)
        return status;
    return check_decode_range_truncated();
}
