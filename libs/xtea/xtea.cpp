#include "cipher_interface.h"
#include <cstring>
#include <cstdlib>
#include <ctime>

static const uint32_t DELTA = 0x9E3779B9;

static void to_words(const uint8_t* bytes, uint32_t* words, int n) {
    for (int i = 0; i < n; i++)
        words[i] = bytes[4*i] | (bytes[4*i+1] << 8) | (bytes[4*i+2] << 16) | (bytes[4*i+3] << 24);
}

static void from_words(const uint32_t* words, uint8_t* bytes, int n) {
    for (int i = 0; i < n; i++) {
        bytes[4*i]   = words[i] & 0xFF;
        bytes[4*i+1] = (words[i] >> 8) & 0xFF;
        bytes[4*i+2] = (words[i] >> 16) & 0xFF;
        bytes[4*i+3] = (words[i] >> 24) & 0xFF;
    }
}

static void xtea_encrypt_block(uint32_t v[2], const uint32_t key[4]) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0;
    for (int i = 0; i < 32; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += DELTA;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
    }
    v[0] = v0;
    v[1] = v1;
}

static void xtea_decrypt_block(uint32_t v[2], const uint32_t key[4]) {
    uint32_t v0 = v[0], v1 = v[1], sum = DELTA * 32;
    for (int i = 0; i < 32; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
        sum -= DELTA;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }
    v[0] = v0;
    v[1] = v1;
}

extern "C" {

const char* cipher_name() { return "XTEA"; }
int key_size() { return 16; }
int nonce_size() { return 0; }

int encrypt(const uint8_t* in, size_t in_len, const uint8_t* key, const uint8_t* nonce, uint8_t* out) {
    uint32_t k[4];
    to_words(key, k, 4);

    int pad = 8 - (in_len % 8);
    size_t padded_len = in_len + pad;

    uint8_t* padded = new uint8_t[padded_len];
    memcpy(padded, in, in_len);
    memset(padded + in_len, pad, pad);

    for (size_t i = 0; i < padded_len; i += 8) {
        uint32_t block[2];
        to_words(padded + i, block, 2);
        xtea_encrypt_block(block, k);
        from_words(block, out + i, 2);
    }

    delete[] padded;
    return padded_len;
}

int decrypt(const uint8_t* in, size_t in_len, const uint8_t* key, const uint8_t* nonce, uint8_t* out) {
    uint32_t k[4];
    to_words(key, k, 4);

    for (size_t i = 0; i < in_len; i += 8) {
        uint32_t block[2];
        to_words(in + i, block, 2);
        xtea_decrypt_block(block, k);
        from_words(block, out + i, 2);
    }

    uint8_t pad = out[in_len - 1];
    if (pad >= 1 && pad <= 8) {
        bool ok = true;
        for (size_t i = in_len - pad; i < in_len; i++)
            if (out[i] != pad) ok = false;
        if (ok) return in_len - pad;
    }
    return in_len;
}

void generate_key(uint8_t* key) {
    srand(time(0));
    for (int i = 0; i < 16; i++)
        key[i] = rand() % 256;
}

}
