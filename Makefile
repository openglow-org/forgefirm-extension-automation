# Copyright 2026 514 LLC d/b/a OpenGlow
# Written by Scott Wiederhold
# SPDX-License-Identifier: MIT
#
# org.openglow.automation. `make` builds the service for the machine: one
# ARMv7 hard-float binary linked against the C library alone (libc.so.6
# and libm.so.6), at bin/run. `make host` builds the same service for this
# computer, for the integration test, and `make test` builds and runs the
# unit tests. `make pack` lays out what the package ships - the manifest,
# the page, and the binary, and nothing of the source or its tests - in
# build/pkg and packs it with ffx (KEY=<file.priv> signs it). The kit's
# ffx.h comes from sdk/c.

CROSS  ?= arm-linux-gnueabihf-
CC     ?= cc
CFLAGS ?= -O2 -g0 -Wall -Wextra -Werror -std=gnu11 -D_FORTIFY_SOURCE=2 -fstack-protector-strong
INC     = -I src -I ../../sdk/c
LIBS    = -lpthread -lm
SRC     = src/main.c src/js.c src/rules.c src/web.c src/mqtt.c
HDR     = src/js.h src/rules.h src/web.h src/mqtt.h ../../sdk/c/ffx.h

all: bin/run

bin/run: $(SRC) $(HDR)
	@mkdir -p bin
	$(CROSS)gcc $(CFLAGS) $(INC) -o $@ $(SRC) $(LIBS)
	$(CROSS)strip $@

host: build/automation

build/automation: $(SRC) $(HDR)
	@mkdir -p build
	$(CC) $(CFLAGS) $(INC) -o $@ $(SRC) $(LIBS)

build/%_test: tests/%_test.c src/js.c src/rules.c src/web.c src/mqtt.c $(HDR)
	@mkdir -p build
	$(CC) $(CFLAGS) $(INC) -o $@ $< src/js.c src/rules.c src/web.c src/mqtt.c $(LIBS)

test: build/js_test build/rules_test build/mqtt_test
	./build/js_test
	./build/rules_test
	./build/mqtt_test

stage: bin/run manifest.json ui/index.html
	rm -rf build/pkg
	mkdir -p build/pkg/bin build/pkg/ui
	cp manifest.json build/pkg/
	cp ui/index.html build/pkg/ui/
	cp bin/run build/pkg/bin/

pack: stage
	python3 ../../tools/ffx pack build/pkg $(if $(KEY),--key $(KEY)) --out build/automation.ffx

clean:
	rm -rf bin build

.PHONY: all host test stage pack clean
