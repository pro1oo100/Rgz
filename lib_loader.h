#pragma once
#include "icipher.h"

#ifdef _WIN32
    #include <windows.h>
    using LibHandle = HMODULE;
#else
    #include <dlfcn.h>
    using LibHandle = void*;
#endif

using CreateCipherFN = ICipher* (*)();

class CipherLoader {
public:
    CipherLoader(const std::string& path) {
        #ifdef _WIN32
                handle_ = LoadLibraryA(path.c_str());
                if (!handle_) throw std::runtime_error("Не удалось загрузить " + path);
        #else
                handle_ = dlopen(path.c_str(), RTLD_NOW); // RTLD_NOW - разрешить все символы
                if (!handle_) throw std::runtime_error(dlerror());
        #endif
    }
private:
    LibHandle handle_ = nullptr;
    ICipher*  cipher_ = nullptr;
};