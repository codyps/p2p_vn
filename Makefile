SRC=sock.c

CC=gcc
RM=rm -f

CFLAGS = -ggdb
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
	$(RM) $(BIN) $(wildcard rsock-g*.tar)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $@ --combine $<


.PHONY: archive
VER:=$(shell git rev-parse --verify --short HEAD 2>/dev/null)
archive:
	git archive --prefix='rsock-g$(VER)/' HEAD > rsock-g$(VER).tar

.PHONY: caps
caps: $(BIN)
	setcap cap_net_raw=eip $^

S1_IP=192.168.18.1
S2_IP=192.168.18.2
S1_MAC=00:16:3E:7F:81:A2
S2_MAC=00:16:3E:07:97:82

.PHONY: slave1.net slave1.ip slave1.arp
slave1.net: | slave1.ip slave1.arp

slave1.ip:
	/sbin/ifconfig eth0:1 $(S1_IP) netmask 255.255.255.0 up
slave1.arp:
	/sbin/arp -s $(S2_IP) $(S2_MAC)

.PHONY: slave2.net slave2.ip slave2.arp
slave2.net: | slave2.ip slave2.arp

slave2.ip:
	/sbin/ifconfig eth0:1 $(S2_IP) netmask 255.255.255.0 up
slave2.arp:
	/sbin/arp -s $(S1_IP) $(S1_MAC)

