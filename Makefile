# Structor Plugin Makefile
# Usage:
#   make              - build the plugin
#   make install      - build and install to ~/.idapro/plugins
#   make clean        - remove build directory
#   make rebuild      - clean and build
#
# Variables:
#   IDA_SDK_DIR/IDASDK - path to IDA SDK (required, or set in environment)
#   BUILD_TYPE         - Release or Debug (default: Release)
#   INSTALL_DIR        - override install location (default: ~/.idapro/plugins)

BUILD_DIR     := build
BUILD_TYPE    ?= Release
INSTALL_DIR   ?= $(HOME)/.idapro/plugins
PLUGIN_NAME   := structor.dylib

# Support both IDA_SDK_DIR and IDASDK env vars
# Also handle case where SDK is in $IDASDK/src/ subdirectory
IDA_SDK_DIR   ?= $(IDASDK)
ifneq ($(wildcard $(IDA_SDK_DIR)/src/include/pro.h),)
    IDA_SDK_DIR := $(IDA_SDK_DIR)/src
endif

# Detect platform
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    PLUGIN_EXT := .dylib
else ifeq ($(UNAME_S),Linux)
    PLUGIN_EXT := .so
else
    PLUGIN_EXT := .dll
endif

CMAKE_FLAGS := -DCMAKE_BUILD_TYPE=$(BUILD_TYPE)

ifdef IDA_SDK_DIR
    CMAKE_FLAGS += -DIDA_SDK_DIR=$(IDA_SDK_DIR)
endif

.PHONY: all build configure clean rebuild install uninstall

all: build

configure:
	@mkdir -p $(BUILD_DIR)
	@cd $(BUILD_DIR) && cmake $(CMAKE_FLAGS) ..

build: configure
	@cmake --build $(BUILD_DIR) --parallel

clean:
	@rm -rf $(BUILD_DIR)

rebuild: clean build

install: build
	@mkdir -p $(INSTALL_DIR)
	@cp $(BUILD_DIR)/structor$(PLUGIN_EXT) $(INSTALL_DIR)/
	@echo "Installed to $(INSTALL_DIR)/structor$(PLUGIN_EXT)"

uninstall:
	@rm -f $(INSTALL_DIR)/structor$(PLUGIN_EXT)
	@echo "Removed $(INSTALL_DIR)/structor$(PLUGIN_EXT)"

# Debug build shortcut
debug:
	@$(MAKE) BUILD_TYPE=Debug build

# Show current configuration
info:
	@echo "BUILD_DIR:   $(BUILD_DIR)"
	@echo "BUILD_TYPE:  $(BUILD_TYPE)"
	@echo "INSTALL_DIR: $(INSTALL_DIR)"
	@echo "IDA_SDK_DIR: $(IDA_SDK_DIR)"
