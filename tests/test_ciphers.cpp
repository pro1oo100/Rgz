#include <iostream>
#include <vector>
#include <string>
#include <cassert>
#include <cstring>
#include <dlfcn.h>

#include "cipher_api.h"

using namespace std;

using fn_get_info      = const AlgorithmInfo*(*)();
using fn_get_out_size  = size_t(*)(size_t, int);
using fn_crypt         = int(*)(ConstBuffer, ConstBuffer, MutBuffer*);

struct CipherLib {
    void*           handle;
    fn_get_info     get_info;
    fn_get_out_size get_output_size;
    fn_crypt        encrypt_fn;
    fn_crypt        decrypt_fn;
};

static CipherLib load(const string& base) {
    string path = "lib" + base + ".so";
    void* h = dlopen(path.c_str(), RTLD_LAZY);
    if (!h) { cerr << "dlopen failed: " << dlerror() << "\n"; exit(1); }
    CipherLib lib;
    lib.handle          = h;
    lib.get_info        = (fn_get_info)    dlsym(h, "get_algorithm_info");
    lib.get_output_size = (fn_get_out_size)dlsym(h, "get_output_size");
    lib.encrypt_fn      = (fn_crypt)       dlsym(h, "encrypt");
    lib.decrypt_fn      = (fn_crypt)       dlsym(h, "decrypt");
    return lib;
}

static bool round_trip(const CipherLib& lib,
                        const vector<uint8_t>& key,
                        const vector<uint8_t>& plaintext,
                        const string& label) {

    size_t enc_size = lib.get_output_size(plaintext.size(), 0);
    vector<uint8_t> ciphertext(enc_size);
    vector<uint8_t> recovered(lib.get_output_size(enc_size, 1));

    ConstBuffer k  = { key.data(),       key.size()       };
    ConstBuffer p  = { plaintext.data(),  plaintext.size() };
    MutBuffer   c  = { ciphertext.data(), ciphertext.size() };
    MutBuffer   r  = { recovered.data(),  recovered.size() };

    if (lib.encrypt_fn(k, p, &c) != 0) {
        cerr << "[FAIL] " << label << " — encrypt returned non-zero\n";
        return false;
    }
    ConstBuffer c_in = { ciphertext.data(), ciphertext.size() };
    if (lib.decrypt_fn(k, c_in, &r) != 0) {
        cerr << "[FAIL] " << label << " — decrypt returned non-zero\n";
        return false;
    }
    if (recovered != plaintext) {
        cerr << "[FAIL] " << label << " — round-trip mismatch\n";
        return false;
    }
    cerr << "[PASS] " << label << "\n";
    return true;
}

static bool known_answer(const CipherLib& lib,
                          const vector<uint8_t>& key,
                          const vector<uint8_t>& plaintext,
                          const vector<uint8_t>& expected,
                          const string& label) {

    size_t out_size = lib.get_output_size(plaintext.size(), 0);
    vector<uint8_t> ciphertext(out_size);
    ConstBuffer k = { key.data(), key.size() };
    ConstBuffer p = { plaintext.data(), plaintext.size() };
    MutBuffer   c = { ciphertext.data(), ciphertext.size() };

    if (lib.encrypt_fn(k, p, &c) != 0) {
        cerr << "[FAIL] " << label << " — encrypt returned non-zero\n";
        return false;
    }
    if (ciphertext != expected) {
        cerr << "[FAIL] " << label << " — output does not match expected\n";
        cerr << "  Got:      ";
        for (auto b : ciphertext) cerr << (int)b << " ";
        cerr << "\n  Expected: ";
        for (auto b : expected) cerr << (int)b << " ";
        cerr << "\n";
        return false;
    }
    cerr << "[PASS] " << label << "\n";
    return true;
}


static int test_atbash() {
    int failed = 0;
    CipherLib lib = load("atbash");
    vector<uint8_t> no_key;

    {
        vector<uint8_t> plain = { 'H', 'i' };
        vector<uint8_t> expected = { 183, 150 };
        if (!known_answer(lib, no_key, plain, expected, "Atbash KAT: 'Hi'")) failed++;
    }

    {
        vector<uint8_t> plain = { 0x00, 0x7F, 0x80, 0xFF, 0xAB, 0x01 };
        if (!round_trip(lib, no_key, plain, "Atbash round-trip: binary data")) failed++;
    }

    {
        string s = "Hello, World!";
        vector<uint8_t> plain(s.begin(), s.end());
        if (!round_trip(lib, no_key, plain, "Atbash round-trip: 'Hello, World!'")) failed++;
    }

    dlclose(lib.handle);
    return failed;
}

static int test_rc4() {
    int failed = 0;
    CipherLib lib = load("rc4");

    {
        vector<uint8_t> key  = { 0x4B, 0x65, 0x79 };
        vector<uint8_t> plain = { 0x50,0x6C,0x61,0x69,0x6E,0x74,0x65,0x78,0x74 };
        vector<uint8_t> expected = { 0xBB,0xF3,0x16,0xE8,0xD9,0x40,0xAF,0x0A,0xD3 };
        if (!known_answer(lib, key, plain, expected, "RC4 KAT: RFC vector 'Key'/'Plaintext'")) failed++;
    }

    {
        vector<uint8_t> key = {
            0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
            0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF
        };
        string s = "NSTU AVTF group AB-524";
        vector<uint8_t> plain(s.begin(), s.end());
        if (!round_trip(lib, key, plain, "RC4 round-trip: 'NSTU AVTF group AB-524'")) failed++;
    }

    {
        vector<uint8_t> key(16, 0x00);
        vector<uint8_t> plain = { 0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE };
        if (!round_trip(lib, key, plain, "RC4 round-trip: binary with zero key")) failed++;
    }

    dlclose(lib.handle);
    return failed;
}

int main() {
    int total_failed = 0;

    cerr << " Atbash tests \n";
    total_failed += test_atbash();

    cerr << "\n RC4 tests \n";
    total_failed += test_rc4();

    cerr << "\n";
    if (total_failed == 0) {
        cerr << "All tests passed.\n";
        return 0;
    } else {
        cerr << total_failed << " test(s) FAILED.\n";
        return 1;
    }
}
