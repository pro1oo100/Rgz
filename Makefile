CXX      := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -Werror -Iinclude -Isrc
LDFLAGS  := -ldl

BUILD_DIR := build

SO_FLAGS  := -shared -fPIC

MAIN_BIN  := $(BUILD_DIR)/cryptum
TEST_BIN  := $(BUILD_DIR)/test_ciphers
ATBASH_SO := $(BUILD_DIR)/libatbash.so
RC4_SO    := $(BUILD_DIR)/librc4.so

.PHONY: all clean test install uninstall

all: $(BUILD_DIR) $(ATBASH_SO) $(RC4_SO) $(MAIN_BIN) $(TEST_BIN)

$(BUILD_DIR):
	 mkdir -p $(BUILD_DIR)

$(ATBASH_SO): libs/atbash/atbash.cpp src/cipher_api.h
	$(CXX) $(CXXFLAGS) $(SO_FLAGS) -o $@ $<

$(RC4_SO): libs/rc4/rc4.cpp src/cipher_api.h
	$(CXX) $(CXXFLAGS) $(SO_FLAGS) -o $@ $<

$(MAIN_BIN): src/main.cpp src/cipher_api.h $(ATBASH_SO) $(RC4_SO)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

$(TEST_BIN): tests/test_ciphers.cpp src/cipher_api.h
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

test: all
	@echo "Running cipher tests..."
	LD_LIBRARY_PATH=$(BUILD_DIR) $(TEST_BIN)

install: all
	install -m 755 $(MAIN_BIN) /usr/local/bin/cryptum
	install -m 755 $(ATBASH_SO) /usr/local/lib/libatbash.so
	install -m 755 $(RC4_SO) /usr/local/lib/librc4.so
	ldconfig

uninstall:
	rm -f /usr/local/bin/cryptum
	rm -f /usr/local/lib/libatbash.so
	rm -f /usr/local/lib/librc4.so
	ldconfig

clean:
	rm -rf $(BUILD_DIR)
