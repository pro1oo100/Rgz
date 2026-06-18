#include "../src/cipher_api.h"
#include <string.h>
#include <stdlib.h>

static const AlgorithmInfo ATBASH_INFO = {
    "atbash",
    0   
};

const AlgorithmInfo* get_algorithm_info() {
    return &ATBASH_INFO;
}

size_t get_output_size(size_t input_size, int operation_type) {
    (void)operation_type;
    return input_size;
}

static int atbash_transform(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    (void)key; 

    if (input.size == 0) return 0;
    if (output->size < input.size) return 1;

    for (size_t i = 0; i < input.size; i++) {
        output->data[i] = (uint8_t)(255u - input.data[i]);
    }
    return 0;
}

int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    return atbash_transform(key, input, output);
}

int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    return atbash_transform(key, input, output);
}
