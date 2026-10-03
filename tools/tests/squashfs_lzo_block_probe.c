#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <lzo/lzo1x.h>

typedef int sqfs_err;
#define SQFS_OK 0
#define SQFS_ERR 1
#include "../../src/fs/squashfs/upstream/lzo_mit.c.inc"

int main(int argc, char **argv) {
    unsigned char input[131072];
    unsigned char edge_output[131072];
    unsigned char reference_output[131072];
    size_t edge_size = sizeof(edge_output);
    lzo_uint reference_size = sizeof(reference_output);
    FILE *stream;
    size_t input_size;
    int edge_result;
    int reference_result;

    if (argc != 2) return 2;
    stream = fopen(argv[1], "rb");
    if (!stream) return 2;
    input_size = fread(input, 1, sizeof(input), stream);
    if (ferror(stream) || !feof(stream)) {
        fclose(stream);
        return 2;
    }
    fclose(stream);
    edge_result = sqfs_decompressor_lzo(
        input, input_size, edge_output, &edge_size);
    reference_result = lzo1x_decompress_safe(
        input, input_size, reference_output, &reference_size, NULL);
    printf("edge_result=%d edge_size=%zu reference_result=%d reference_size=%lu\n",
           edge_result, edge_size, reference_result,
           (unsigned long)reference_size);
    if (reference_result != LZO_E_OK) return 3;
    if (edge_result != SQFS_OK || edge_size != reference_size ||
        memcmp(edge_output, reference_output, edge_size) != 0)
        return 1;
    return 0;
}
