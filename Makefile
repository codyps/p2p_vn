SRC = sock.c routing.c dpg.c dpeer.c vnet.c

CC = gcc
RM = rm -f

CFLAGS = -ggdb
override CFLAGS+= -Wall -pipe -pthread -MMD -std=gnu99

BIN = L2O3

.PHONY: all
all: build

.PHONY: build
build: $(BIN)

.PHONY: rebuild
rebuild: | clean $(BIN)

.PHONY: clean
clean:
	$(RM) $(BIN) $(wildcard rsock-g*.tar) $(wildcard *.d)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^

.PHONY: archive
VER:=$(shell git rev-parse --verify --short HEAD 2>/dev/null)
archive:
	git archive --prefix='rsock-g$(VER)/' HEAD > rsock-g$(VER).tar

.PHONY: caps
caps: $(BIN)
	setcap cap_net_admin=eip $^

TCP_PORT=9999
TUN_NAME=tun0

tshark:
	/usr/sbin/tshark -i $(TUN) -x

S1_IP=192.168.18.1
S2_IP=192.168.18.2

.PHONY: slave1.test
slave1.test: $(BIN)
	./$(BIN) $(TCP_PORT) $(TUN_NAME) &
	/sbin/ifconfig $(TUN_NAME) $(S1_IP)/24

.PHONY: slave2.test
slave2.test: $(BIN)
	./$(BIN) slave1 $(TCP_PORT) $(TUN_NAME) &
	/sbin/ifconfig $(TUN_NAME) $(S2_IP)/24

#-include $(wildcard *.d)
