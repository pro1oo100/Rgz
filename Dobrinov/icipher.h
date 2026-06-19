#pragma once
#include <string>

class ICipher {
public:
    virtual std::string encrypt(const std::string& text, const std::string& key) = 0;
    virtual std::string decrypt(const std::string& text, const std::string& key) = 0;

    virtual void encryptFile(const std::string& inputPath, const std::string& outputPath, const std::string& key) = 0;
    virtual void decryptFile(const std::string& inputPath, const std::string& outputPath, const std::string& key) = 0;

    virtual ~ICipher() = default;
};