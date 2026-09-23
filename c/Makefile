CC ?= cc
CFLAGS ?= -std=c99 -O2 -Wall -Wextra -pedantic
SAN_FLAGS = -std=c99 -O1 -g -Wall -Wextra -pedantic \
	-fsanitize=address,undefined -fno-sanitize-recover=all

all: tests difftest

tests: tests.c fre.c sha256.c fre.h sha256.h
	$(CC) $(CFLAGS) -o $@ tests.c fre.c sha256.c

difftest: difftest.c fre.c sha256.c fre.h sha256.h
	$(CC) $(CFLAGS) -o $@ difftest.c fre.c sha256.c

test: tests
	./tests

tests_asan: tests.c fre.c sha256.c fre.h sha256.h
	$(CC) $(SAN_FLAGS) -o $@ tests.c fre.c sha256.c

difftest_asan: difftest.c fre.c sha256.c fre.h sha256.h
	$(CC) $(SAN_FLAGS) -o $@ difftest.c fre.c sha256.c

sanitize: tests_asan difftest_asan
	./tests_asan

clean:
	rm -f tests difftest tests_asan difftest_asan

.PHONY: all test sanitize clean