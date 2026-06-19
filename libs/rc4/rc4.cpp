#include "cipher_interface.h"
#include <cstring>
#include <cstdlib>
#include <fstream>

using namespace std;

static const AlgorithmInfo RC4_INFO = {
    "rc4",
    16
};

const AlgorithmInfo* get_algorithm_info() {
    return &RC4_INFO;
}

size_t get_output_size(size_t input_size, int operation_type) {
    (void)operation_type;
    return input_size;
}

static uint8_t s_box[256];
static uint8_t s_i;
static uint8_t s_j;

static void rc4_ksa(ConstBuffer key) {
    for (uint64_t idx = 0; idx < 256; idx++) {
        s_box[idx] = (uint8_t)idx;
    }

    uint8_t j = 0;
    for (uint64_t idx = 0; idx < 256; idx++) {
        j = (uint8_t)(j + s_box[idx] + key.data[idx % key.size]);
        uint8_t tmp = s_box[idx];
        s_box[idx] = s_box[j];
        s_box[j] = tmp;
    }

    s_i = 0;
    s_j = 0;
}

static uint8_t rc4_next_byte() {
    s_i = (uint8_t)(s_i + 1);
    s_j = (uint8_t)(s_j + s_box[s_i]);

    uint8_t tmp = s_box[s_i];
    s_box[s_i] = s_box[s_j];
    s_box[s_j] = tmp;

    uint8_t k = s_box[(uint8_t)(s_box[s_i] + s_box[s_j])];
    return k;
}

static int rc4_transform(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (key.size == 0 || key.size > 256) return 1;
    if (output->size < input.size) return 1;

    rc4_ksa(key);

    for (uint64_t idx = 0; idx < input.size; idx++) {
        output->data[idx] = input.data[idx] ^ rc4_next_byte();
    }

    memset(s_box, 0, sizeof(s_box));
    s_i = 0;
    s_j = 0;

    return 0;
}

int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    return rc4_transform(key, input, output);
}

int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    return rc4_transform(key, input, output);
}

int generateKey(ConstBuffer key, MutBuffer* output) {
    (void)key;
    if (output == nullptr) return 1;
    ifstream urandom("/dev/urandom", ios::binary);
    if (!urandom) return 1;
    urandom.read(reinterpret_cast<char*>(output->data), output->size);
    return 0;
}
