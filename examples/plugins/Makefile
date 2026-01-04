# Renef Plugin Build System
# Usage: make [all|install|clean]

# Renef SDK path
RENEF_SDK := ../../src/librenef/include

# Platform detection
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    PLUGIN_EXT := .dylib
    LDFLAGS := -dynamiclib
else ifeq ($(UNAME_S),Linux)
    PLUGIN_EXT := .so
    LDFLAGS := -shared
endif

# Plugin install directory
PLUGIN_DIR := $(HOME)/.config/renef/plugins

CC := gcc
CFLAGS := -fPIC -Wall -Wextra -I$(RENEF_SDK)

SRCS := $(wildcard *.c)
TARGETS := $(SRCS:.c=$(PLUGIN_EXT))

.PHONY: all clean install list

all: $(TARGETS)

%$(PLUGIN_EXT): %.c
	@echo "Building $@..."
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

install: $(TARGETS)
	@mkdir -p $(PLUGIN_DIR)
	@for plugin in $(TARGETS); do \
		echo "Installing $$plugin..."; \
		cp $$plugin $(PLUGIN_DIR)/; \
	done
	@echo "Installed $(words $(TARGETS)) plugin(s) to $(PLUGIN_DIR)"

clean:
	rm -f $(TARGETS)

list:
	@echo "Available plugins:"
	@for src in $(SRCS); do \
		echo "  - $${src%.c}"; \
	done
