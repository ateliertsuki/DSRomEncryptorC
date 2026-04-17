CC      := gcc
CFLAGS  := -std=c11 -Wall -Wextra -Wpedantic -O2
SRCDIR  := src
SRCS    := $(SRCDIR)/main.c            \
           $(SRCDIR)/blowfish.c        \
           $(SRCDIR)/key_transform.c   \
           $(SRCDIR)/crc16.c           \
           $(SRCDIR)/blowfish_locator.c
OBJS    := $(SRCS:.c=.o)

# Detect platform via uname -s; covers Linux, macOS, MSYS2, and MinGW.
UNAME := $(shell uname -s)

ifneq (,$(filter MINGW% MSYS%,$(UNAME)))
    # MSYS2 / MinGW-w64: produce a .exe and link kernel32 for GetModuleFileNameA
    EXE     := .exe
    LDFLAGS := -lkernel32
else ifeq ($(UNAME), Darwin)
    EXE     :=
    LDFLAGS :=
else
    # Linux / other POSIX
    EXE     :=
    LDFLAGS :=
endif

TARGET := dsromencryptor$(EXE)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(SRCDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -I$(SRCDIR) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)
