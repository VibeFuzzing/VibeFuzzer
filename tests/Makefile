CC ?= gcc
CFLAGS ?= -Wall -Wextra -std=c11 -g -I. -I../mutator
LDLIBS ?= -lcurl -lcjson

TARGETS = ollama_test mutator_test
OBJ = ollama_test.o ollama.o mutator_test.o mutator.o test_utils.o

all: $(TARGETS)

ollama_test: ollama_test.o ollama.o test_utils.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

mutator_test: mutator_test.o mutator.o ollama.o test_utils.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

ollama.o: ../mutator/ollama.c
	$(CC) $(CFLAGS) -c $< -o $@

ollama_test.o: ollama_test.c
	$(CC) $(CFLAGS) -c $< -o $@

mutator.o: ../mutator/mutator.c
	$(CC) $(CFLAGS) -c $< -o $@

test_utils.o: test_utils.c
	$(CC) $(CFLAGS) -c $< -o $@

mutator_test.o: mutator_test.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGETS) $(OBJ)
