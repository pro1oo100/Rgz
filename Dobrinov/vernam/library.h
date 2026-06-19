#pragma once
#include "vernam_export.h"
#include "../icipher.h"
#include <string>
#include <fstream>

class VERNAM_EXPORT Vernam : public ICipher {
public:
    std::string encrypt(const std::string& text, const std::string& key) override;
    std::string decrypt(const std::string& text, const std::string& key) override;
    void encryptFile(const std::string& inputPath, const std::string& outputPath, const std::string& key) override;
    void decryptFile(const std::string& inputPath, const std::string& outputPath, const std::string& key) override;
};

extern "C" VERNAM_EXPORT ICipher* createCipher();