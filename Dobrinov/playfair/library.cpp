#include "library.h"

std::string Playfair::encrypt(const std::string& text, const std::string& key) { return ""; }
std::string Playfair::decrypt(const std::string& text, const std::string& key) { return ""; }
void Playfair::encryptFile(const std::string& inputPath, const std::string& outputPath, const std::string& key) {}
void Playfair::decryptFile(const std::string& inputPath, const std::string& outputPath, const std::string& key) {}

ICipher* createCipher() { return new Playfair(); }