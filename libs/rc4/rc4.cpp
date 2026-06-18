#include "../src/cipher_api.h"
#include <string.h>
#include <stdlib.h>

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

struct Rc4State {
    uint8_t S[256];
    uint8_t i;
    uint8_t j;
};

static void rc4_ksa(Rc4State* state, ConstBuffer key) {
    for (uint32_t idx = 0; idx < 256; idx++) {
        state->S[idx] = (uint8_t)idx;
    }

    uint8_t j = 0;
    for (uint32_t idx = 0; idx < 256; idx++) {
        j = (uint8_t)(j + state->S[idx] + key.data[idx % key.size]);
        uint8_t tmp = state->S[idx];
        state->S[idx] = state->S[j];
        state->S[j] = tmp;
    }

    state->i = 0;
    state->j = 0;
}

static uint8_t rc4_next_byte(Rc4State* state) {
    state->i = (uint8_t)(state->i + 1);
    state->j = (uint8_t)(state->j + state->S[state->i]);

    uint8_t tmp = state->S[state->i];
    state->S[state->i] = state->S[state->j];
    state->S[state->j] = tmp;

    uint8_t k = state->S[(uint8_t)(state->S[state->i] + state->S[state->j])];
    return k;
}

static int rc4_transform(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (key.size == 0 || key.size > 256) return 1;
    if (output->size < input.size) return 1;

    Rc4State state;
    rc4_ksa(&state, key);

    for (size_t idx = 0; idx < input.size; idx++) {
        output->data[idx] = input.data[idx] ^ rc4_next_byte(&state);
    }

    memset(state.S, 0, sizeof(state.S));
    state.i = 0;
    state.j = 0;

    return 0;
}

int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    return rc4_transform(key, input, output);
}

int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    return rc4_transform(key, input, output);
}
