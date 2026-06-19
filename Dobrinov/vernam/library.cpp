#include "library.h"

std::string Vernam::encrypt(const std::string& text, const std::string& key) { return ""; }
std::string Vernam::decrypt(const std::string& text, const std::string& key) { return ""; }
void Vernam::encryptFile(const std::string& inputPath, const std::string& outputPath, const std::string& key) {}
void Vernam::decryptFile(const std::string& inputPath, const std::string& outputPath, const std::string& key) {}

ICipher* createCipher() { return new Vernam(); }