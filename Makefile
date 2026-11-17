CC       ?= cc
CFLAGS   ?= -std=c11 -Wall -Wextra -Wpedantic -O2
CPPFLAGS += -D_DEFAULT_SOURCE
BIN      := bin

all: $(BIN)/portscan

$(BIN)/portscan: src/portscan.c | $(BIN)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ src/portscan.c

$(BIN):
	mkdir -p $@

test: all
	sh tests/run_tests.sh

clean:
	rm -rf $(BIN)

.PHONY: all test clean
