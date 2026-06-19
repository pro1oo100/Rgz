#pragma once
#include "playfair_export.h"
#include "../icipher.h"
#include <string>
#include <fstream>

class PLAYFAIR_EXPORT Playfair : public ICipher {
public:
    std::string encrypt(const std::string& text, const std::string& key) override;
    std::string decrypt(const std::string& text, const std::string& key) override;

    void encryptFile(const std::string& inputPath, const std::string& outputPath, const std::string& key) override;
    void decryptFile(const std::string& inputPath, const std::string& outputPath, const std::string& key) override;
};

extern "C" PLAYFAIR_EXPORT ICipher* createCipher();