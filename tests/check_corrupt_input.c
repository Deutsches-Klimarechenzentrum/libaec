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

int main(void)
{
    return check_split_truncated_binary_part();
}
