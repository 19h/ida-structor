# Structor Plugin Makefile
# Usage:
#   make              - build the plugin
#   make install      - build, install, and codesign on macOS
#   make clean        - remove build directory
#   make rebuild      - clean and build
#
# Variables:
#   IDA_SDK_DIR/IDASDK - path to IDA SDK (required, or set in environment)
#   BUILD_TYPE         - Release or Debug (default: Release)
#   INSTALL_DIR        - override install location (default: ~/.idapro/plugins)
#   TEST_IDUMP         - idump executable path (default: idump)

BUILD_DIR     := build
BUILD_TYPE    ?= Release
BUILD_TESTS   ?= OFF
LIVE_TEST_HOOKS ?= OFF
INSTALL_DIR   ?= $(HOME)/.idapro/plugins
INSTALL_STAGE_DIR := $(BUILD_DIR)/install-stage
PLUGIN_NAME   := structor.dylib
TEST_IDUMP    ?= idump
PYTHON        ?= python3

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

CMAKE_FLAGS = -DCMAKE_BUILD_TYPE=$(BUILD_TYPE) \
	-DBUILD_TESTS=$(BUILD_TESTS) \
	-DSTRUCTOR_ENABLE_LIVE_TEST_HOOKS=$(LIVE_TEST_HOOKS)

ifdef IDA_SDK_DIR
    CMAKE_FLAGS += -DIDA_SDK_DIR=$(IDA_SDK_DIR)
endif

.PHONY: all build configure clean rebuild install uninstall test

all: build

configure:
	@mkdir -p $(BUILD_DIR)
	@cd $(BUILD_DIR) && cmake $(CMAKE_FLAGS) ..

build: configure
	@cmake --build $(BUILD_DIR) --parallel

test: BUILD_TESTS=ON
test: LIVE_TEST_HOOKS=ON
test: build
	@ctest --test-dir $(BUILD_DIR) --build-config $(BUILD_TYPE) --output-on-failure --no-tests=error -E '_live$$'
	@$(PYTHON) integration_tests/check_full_integrity_suite.py --repo-root "$(CURDIR)" --plugin "$(CURDIR)/$(BUILD_DIR)/structor$(PLUGIN_EXT)" --idump "$(TEST_IDUMP)"

clean:
	@rm -rf $(BUILD_DIR)

rebuild: clean build

install:
	@mkdir -p $(BUILD_DIR)
	@cd $(BUILD_DIR) && cmake $(CMAKE_FLAGS) \
		-DBUILD_TESTS=OFF \
		-DSTRUCTOR_ENABLE_LIVE_TEST_HOOKS=OFF ..
	@cmake --build $(BUILD_DIR) --parallel
	@rm -rf $(INSTALL_STAGE_DIR)
	@cmake --install $(BUILD_DIR) --config $(BUILD_TYPE) --component Runtime \
		--prefix "$(CURDIR)/$(INSTALL_STAGE_DIR)"
	@for marker in STRUCTOR_INTEGRATION_TESTING \
		STRUCTOR_TEST_PERSISTENCE_FAULT fault_global_tinfo_rollback \
		inspect_base_inference inspect_existing_type_matcher \
		inspect_array_layout inspect_type_application_identity \
		inspect_instruction_semantics_identity check_assignment_order_ctree \
		check_type_lattice_materialization \
		inspect_symbolic_query_status \
		inspect_memory_inference \
		inspect_type_model_evidence \
		inspect_constraint_sources \
		check_alias_flow_ctree \
		inspect_signature_mapping inspect_target_calling_convention; do \
		if strings "$(INSTALL_STAGE_DIR)/plugins/structor$(PLUGIN_EXT)" | \
			grep -F -- "$$marker" >/dev/null; then \
			echo "Production plugin contains live-test marker: $$marker"; \
			exit 1; \
		fi; \
	done
	@mkdir -p $(INSTALL_DIR)
	@cp -f $(INSTALL_STAGE_DIR)/plugins/structor$(PLUGIN_EXT) $(INSTALL_DIR)/
	@if [ "$(UNAME_S)" = "Darwin" ]; then \
		codesign -s - -f "$(INSTALL_DIR)/structor$(PLUGIN_EXT)"; \
		echo "Codesigned $(INSTALL_DIR)/structor$(PLUGIN_EXT)"; \
	fi
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
	@echo "BUILD_TESTS: $(BUILD_TESTS)"
	@echo "LIVE_HOOKS:  $(LIVE_TEST_HOOKS)"
	@echo "INSTALL_DIR: $(INSTALL_DIR)"
	@echo "IDA_SDK_DIR: $(IDA_SDK_DIR)"
