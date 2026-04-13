CFLAGS = -fPIC -I$(AFL_PATH)/include -MMD
LDFLAGS = -shared
LDLIBS = -lcurl -lcjson
TARGET = libllmmutator.so
DEP = ollama.d mutator.d

.PHONY: all clean

all: $(TARGET)

clean:
	rm -f libllmmutator.so ollama.o mutator.o $(DEP)

libllmmutator.so: ollama.o mutator.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

-include $(DEP)

mutator.c: $(AFL_PATH)/include/afl-fuzz.h

$(AFL_PATH)/include/afl-fuzz.h:
	ifndef AFL_PATH
	$(error AFL_PATH isn't set. Please point this to the root of the AFL++ source tree)
	endif
