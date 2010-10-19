SRC=sock.c

CC=gcc
RM=rm -f

CFLAGS = -g
CFLAGS+= -Wall -pipe -pthread

BIN=rsock

.PHONY: all
all: build
	
.PHONY: build
build: $(BIN)

.PHONY: rebuild
rebuild: | clean $(BIN)

.PHONY: clean
clean:
	$(RM) $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $@ --combine $<

.PHONY:
caps: $(BIN)
	setcap cap_net_raw=eip $^
