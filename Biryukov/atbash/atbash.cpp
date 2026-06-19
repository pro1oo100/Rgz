#include "atbash.h"
#include <cstring>
#include <cstdlib>
#include <fstream>

using namespace std;

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

    for (uint64_t i = 0; i < input.size; i++) {
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

int generateKey(ConstBuffer key, MutBuffer* output) {
    (void)key;
    if (output == nullptr) return 1;
    ifstream urandom("/dev/urandom", ios::binary);
    if (!urandom) return 1;
    urandom.read(reinterpret_cast<char*>(output->data), output->size);
    return 0;
}
