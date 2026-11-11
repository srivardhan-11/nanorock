CC      := gcc
CFLAGS  := -Wall -Wextra -Werror -std=gnu11 -Iinclude -g -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
LDFLAGS := -pie -Wl,-z,relro,-z,now
SRC     := $(wildcard src/*.c)
OBJ     := $(SRC:.c=.o)
BIN     := bin/nanorock

.PHONY: all clean test install rootfs

all: $(BIN)

$(BIN): $(OBJ)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJ)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

rootfs:
	bash scripts/setup-rootfs.sh ./rootfs

test: all
	bash tests/test_isolation.sh
	bash tests/test_milestone2.sh
	bash tests/test_cgroups.sh
	bash tests/test_security.sh
	bash tests/test_milestone5.sh
	bash tests/test_milestone6.sh
	bash tests/test_milestone7.sh
	bash tests/test_milestone8.sh
	bash tests/test_milestone9_10.sh

install: all
	install -Dm755 $(BIN) /usr/local/bin/nanorock

clean:
	rm -f $(OBJ) $(BIN)
	@rmdir bin 2>/dev/null || true
