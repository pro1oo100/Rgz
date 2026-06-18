#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <map>
#include <stdexcept>
#include <cstring>
#include <dlfcn.h>   

#include "cipher_api.h"

using namespace std;

using fn_get_info      = const AlgorithmInfo*(*)();
using fn_get_out_size  = size_t(*)(size_t, int);
using fn_crypt         = int(*)(ConstBuffer, ConstBuffer, MutBuffer*);

struct CipherLib {
    void*         handle;
    fn_get_info   get_info;
    fn_get_out_size get_output_size;
    fn_crypt      encrypt_fn;
    fn_crypt      decrypt_fn;
};

static const map<string, string> KNOWN_ALGORITHMS = {
    { "atbash", "atbash" },
    { "rc4",    "rc4"    },
};

static string lib_filename(const string& base) {
    return "lib" + base + ".so";
}

static CipherLib load_lib(const string& algo) {
    auto it = KNOWN_ALGORITHMS.find(algo);
    if (it == KNOWN_ALGORITHMS.end()) {
        throw runtime_error("Unknown algorithm: " + algo);
    }

    string path = lib_filename(it->second);
    void* handle = dlopen(path.c_str(), RTLD_LAZY);
    if (!handle) {
        throw runtime_error("Cannot load library " + path + ": " + dlerror());
    }

    CipherLib lib;
    lib.handle = handle;
    lib.get_info       = (fn_get_info)     dlsym(handle, "get_algorithm_info");
    lib.get_output_size = (fn_get_out_size) dlsym(handle, "get_output_size");
    lib.encrypt_fn     = (fn_crypt)        dlsym(handle, "encrypt");
    lib.decrypt_fn     = (fn_crypt)        dlsym(handle, "decrypt");

    if (!lib.get_info || !lib.get_output_size || !lib.encrypt_fn || !lib.decrypt_fn) {
        dlclose(handle);
        throw runtime_error("Library " + path + " is missing required symbols");
    }
    return lib;
}

static void unload_lib(CipherLib& lib) {
    if (lib.handle) {
        dlclose(lib.handle);
        lib.handle = nullptr;
    }
}

static vector<uint8_t> read_binary(const string& path) {
    if (path == "-") {
        ios::sync_with_stdio(false);
        return vector<uint8_t>(
            istreambuf_iterator<char>(cin),
            istreambuf_iterator<char>()
        );
    }
    ifstream f(path, ios::binary);
    if (!f) throw runtime_error("Cannot open file for reading: " + path);
    return vector<uint8_t>(
        istreambuf_iterator<char>(f),
        istreambuf_iterator<char>()
    );
}

static void write_binary(const string& path, const vector<uint8_t>& data) {
    if (path == "-") {
        cout.write(reinterpret_cast<const char*>(data.data()), data.size());
        cout.flush();
        return;
    }
    ofstream f(path, ios::binary);
    if (!f) throw runtime_error("Cannot open file for writing: " + path);
    f.write(reinterpret_cast<const char*>(data.data()), data.size());
}

static void secure_wipe(vector<uint8_t>& buf) {
    volatile uint8_t* p = buf.data();
    for (size_t i = 0; i < buf.size(); i++) p[i] = 0;
}

static vector<uint8_t> generate_key(size_t key_size) {
    if (key_size == 0) key_size = 16;  
    ifstream urandom("/dev/urandom", ios::binary);
    if (!urandom) throw runtime_error("Cannot open /dev/urandom");
    vector<uint8_t> key(key_size);
    urandom.read(reinterpret_cast<char*>(key.data()), key_size);
    return key;
}

struct Args {
    string algo;
    string mode;      
    string key_path;    
    string input_path;  
    string output_path; 
    string save_key_path;
    bool help = false;
    bool generate_key_inline = false;  
};

static void print_help(const char* prog) {
    cerr << "Usage: " << prog << " [OPTIONS]\n\n"
         << "Options:\n"
         << "  -a, --algorithm <name>      Cipher to use: ";
    for (auto& kv : KNOWN_ALGORITHMS) cerr << kv.first << " ";
    cerr << "\n"
         << "  -m, --mode <mode>           Mode: encrypt | decrypt | generate-key\n"
         << "  -k, --key <file|-|fd>       Key file (or - for stdin)\n"
         << "  -i, --input <file|->        Input file (or - for stdin) [default: -]\n"
         << "  -o, --output <file|->       Output file (or - for stdout) [default: -]\n"
	 << "      --generate-key          Generate a key, use it, save via --save-key\n"
         << "      --save-key <file|->     Where to write the generated key\n"
         << "  -h, --help                  Show this message\n\n"
         << "Examples:\n"
         << "  cryptum -a rc4 -m generate-key --save-key key.bin\n"
         << "  cryptum -a rc4 -m encrypt -k key.bin -i plain.txt -o cipher.bin\n"
         << "  cryptum -a atbash -m encrypt -i plain.txt -o cipher.bin\n"
         << "  cryptum -a rc4 -m decrypt -k key.bin -i cipher.bin -o plain.txt\n";
}

static Args parse_args(int argc, char* argv[]) {
    Args a;
    if (argc < 2) { a.help = true; return a; }

    for (int i = 1; i < argc; i++) {
        string arg = argv[i];

        auto next = [&]() -> string {
            if (i + 1 >= argc) throw runtime_error("Missing value for " + arg);
            return argv[++i];
        };

        if (arg == "-h" || arg == "--help") { a.help = true; }
        else if (arg == "-a" || arg == "--algorithm") a.algo = next();
        else if (arg == "-m" || arg == "--mode")      a.mode = next();
        else if (arg == "-k" || arg == "--key")       a.key_path = next();
        else if (arg == "-i" || arg == "--input")     a.input_path = next();
        else if (arg == "-o" || arg == "--output")    a.output_path = next();
        else if (arg == "--save-key")                 a.save_key_path = next();
        else if (arg == "--generate-key")             a.generate_key_inline = true;
        else throw runtime_error("Unknown argument: " + arg);
    }

    return a;
}

int main(int argc, char* argv[]) {
    ios::sync_with_stdio(false);

    Args args;
    try {
        args = parse_args(argc, argv);
    } catch (const exception& e) {
        cerr << "Argument error: " << e.what() << "\n";
        print_help(argv[0]);
        return 1;
    }

    if (args.help) {
        print_help(argv[0]);
        return 0;
    }

    if (args.algo.empty()) {
        cerr << "Error: --algorithm is required\n";
        print_help(argv[0]);
        return 1;
    }
    if (args.mode.empty()) {
        cerr << "Error: --mode is required\n";
        print_help(argv[0]);
        return 1;
    }

    if (args.input_path.empty())  args.input_path  = "-";
    if (args.output_path.empty()) args.output_path = "-";

    try {
        CipherLib lib = load_lib(args.algo);
        const AlgorithmInfo* info = lib.get_info();

        if (args.mode == "generate-key") {
            auto key = generate_key(info->key_size);
            string dst = args.save_key_path.empty() ? "-" : args.save_key_path;
            write_binary(dst, key);
            secure_wipe(key);
            unload_lib(lib);
            return 0;
        }

        if (args.mode != "encrypt" && args.mode != "decrypt") {
            throw runtime_error("Unknown mode: " + args.mode + ". Use encrypt, decrypt, or generate-key");
        }

        vector<uint8_t> key;
        if (args.generate_key_inline) {
            key = generate_key(info->key_size);
            if (!args.save_key_path.empty()) write_binary(args.save_key_path, key);
        } else {
            if (args.key_path.empty() && info->key_size != 0) {
                throw runtime_error("--key is required for algorithm " + args.algo);
            }
            if (!args.key_path.empty()) {
                key = read_binary(args.key_path);
            }
        }

        auto input = read_binary(args.input_path);

        int op = (args.mode == "encrypt") ? 0 : 1;
        size_t out_size = lib.get_output_size(input.size(), op);
        vector<uint8_t> output(out_size);

        ConstBuffer key_buf = { key.data(), key.size() };
        ConstBuffer in_buf  = { input.data(), input.size() };
        MutBuffer   out_buf = { output.data(), output.size() };

        int rc;
        if (args.mode == "encrypt") {
            rc = lib.encrypt_fn(key_buf, in_buf, &out_buf);
        } else {
            rc = lib.decrypt_fn(key_buf, in_buf, &out_buf);
        }

        if (rc != 0) throw runtime_error("Cipher operation failed with code " + to_string(rc));

        write_binary(args.output_path, output);

        secure_wipe(key);
        unload_lib(lib);

    } catch (const exception& e) {
        cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
