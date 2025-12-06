# Bitcoin Echo — POSIX Makefile
# Build once. Build right. Stop.

CC      = cc
CFLAGS  = -std=c11 -Wall -Wextra -Wpedantic -O2 -Iinclude
LDFLAGS =
TARGET  = echo

# Source files (will be populated as implementation progresses)
SRCS    = src/main.c
OBJS    = $(SRCS:.c=.o)

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET) $(OBJS)

test:
	@echo "No tests yet"
