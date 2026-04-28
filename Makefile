CC := gcc
CFLAGS := -Wall -Wextra -Werror -O2
LDFLAGS := -lnetfilter_queue
TARGET := netfilter-test
SRC := main.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)
