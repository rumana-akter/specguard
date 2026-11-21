CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Werror -O2
SRC = src/filter.c src/frame.c src/alarm.c

.PHONY: all test clean

all: build/test_runner

build/test_runner: $(SRC) tests/test_main.c
	mkdir -p build
	$(CC) $(CFLAGS) -Isrc -o $@ $^

test: build/test_runner
	./build/test_runner

clean:
	rm -rf build
