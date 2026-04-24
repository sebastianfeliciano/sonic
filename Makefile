# Packet processor (C) - requires libpcap
# macOS: libpcap is usually present with Xcode CLI tools
# Linux: sudo apt-get install libpcap-dev  (Debian/Ubuntu)

CC = gcc
CFLAGS = -O2 -Wall -Wextra
LDFLAGS = -lpcap -lm

TARGET = packet_processor

all: $(TARGET)


$(TARGET): packet_processor.c
	$(CC) $(CFLAGS) -o $(TARGET) packet_processor.c $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
