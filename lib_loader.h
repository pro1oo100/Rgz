#pragma once
#include "icipher.h"

#include <string>
#include <stdexcept>

#ifdef _WIN32
    #include <windows.h>
    using LibHandle = HMODULE;
#else
    #include <dlfcn.h>
    using LibHandle = void*;
#endif

using CreateCipherFN = ICipher* (*)();

// Загружает одну динамическую библиотеку-шифр в рантайме и достаёт из неё
// объект ICipher через экспортированную функцию createCipher().
class CipherLoader {
public:
    explicit CipherLoader(const std::string& path) {
        #ifdef _WIN32
            handle_ = LoadLibraryA(path.c_str());
            if (!handle_) throw std::runtime_error("Не удалось загрузить " + path);
            auto fn = reinterpret_cast<CreateCipherFN>(GetProcAddress(handle_, "createCipher"));
        #else
            handle_ = dlopen(path.c_str(), RTLD_NOW); // RTLD_NOW - разрешить все символы
            if (!handle_) throw std::runtime_error(dlerror());
            auto fn = reinterpret_cast<CreateCipherFN>(dlsym(handle_, "createCipher"));
        #endif
        if (!fn) throw std::runtime_error("Символ createCipher не найден в " + path);
        cipher_ = fn();
    }

    // Владеем библиотекой и объектом — копирование запрещаем.
    CipherLoader(const CipherLoader&) = delete;
    CipherLoader& operator=(const CipherLoader&) = delete;

    ICipher* get() const { return cipher_; }

    ~CipherLoader() {
        delete cipher_; // объект создан внутри библиотеки — удаляем до выгрузки
        #ifdef _WIN32
            if (handle_) FreeLibrary(handle_);
        #else
            if (handle_) dlclose(handle_);
        #endif
    }

private:
    LibHandle handle_ = nullptr;
    ICipher* cipher_ = nullptr;
};
