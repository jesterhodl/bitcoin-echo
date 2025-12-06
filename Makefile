# Bitcoin Echo — POSIX Makefile
# Build once. Build right. Stop.

CC      = cc
CFLAGS  = -std=c11 -Wall -Wextra -Wpedantic -O2 -Iinclude -pthread
LDFLAGS = -pthread
TARGET  = echo

# Source files (will be populated as implementation progresses)
SRCS    = src/main.c \
          src/platform/posix.c \
          src/crypto/sha256.c \
          src/crypto/ripemd160.c
OBJS    = $(SRCS:.c=.o)

# Test files
TEST_SHA256    = test/unit/test_sha256
TEST_RIPEMD160 = test/unit/test_ripemd160

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Test targets
$(TEST_SHA256): test/unit/test_sha256.c src/crypto/sha256.c
	$(CC) $(CFLAGS) -o $@ $^

$(TEST_RIPEMD160): test/unit/test_ripemd160.c src/crypto/ripemd160.c src/crypto/sha256.c
	$(CC) $(CFLAGS) -o $@ $^

test: $(TEST_SHA256) $(TEST_RIPEMD160)
	@echo "Running SHA-256 tests..."
	@./$(TEST_SHA256)
	@echo ""
	@echo "Running RIPEMD-160 tests..."
	@./$(TEST_RIPEMD160)

clean:
	rm -f $(TARGET) $(OBJS) $(TEST_SHA256) $(TEST_RIPEMD160)
	find src -name '*.o' -delete
