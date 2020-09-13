# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2020,2021 IBM Corp.

FUZZ=0
SANITIZE=1
COVERAGE=0
ASSERT=1
TRACE=1

CFLAGS = -std=gnu11 -g -ggdb -Wall -Wextra -Werror -MMD
LDLIBS = -lrt -lpthread

ifeq ($(FUZZ),1)
CC = afl-clang
CFLAGS += -DNTRACE
else
ifeq ($(SANITIZE),1)
CFLAGS += -fsanitize=undefined -fsanitize=address
LDFLAGS += -fsanitize=undefined -fsanitize=address
endif
endif

ifeq ($(COVERAGE),1)
CFLAGS += -O2
CFLAGS += -fprofile-arcs -ftest-coverage
LDFLAGS += -fprofile-arcs -ftest-coverage
else
CFLAGS += -flto -O2
LDFLAGS += -flto
endif

ifeq ($(ASSERT),0)
CFLAGS += -DNDEBUG
endif

ifeq ($(TRACE),0)
CFLAGS += -DNTRACE
endif

.PHONY: all
all: _all

include Makefile.libshmap
include Makefile.libshmapper
include Makefile.fuzz

.PHONY: _all
_all: $(SHMAP_SONAME) $(SHMAPPER_SONAME) shmapperd shmapperctl fuzz cscope

.PHONY: clean
clean: clean-$(SHMAP_SONAME) clean-$(SHMAPPER_SONAME) clean-shmapperd clean-shmapperctl clean-fuzz clean-cscope

shmapperd: LDLIBS += -lsystemd -lexpat
shmapperd: shmapperd.o introspect.o $(SHMAPPER_SONAME) $(SHMAP_SONAME)

.PHONY: clean-shmapperd
clean-shmapperd:
	$(RM) shmapperd.o shmapperd.d shmapperd introspect.o introspect.d
	$(RM) shmapperd.gcno shmapperd.gcda introspect.gcno introspect.gcda

shmapperctl: shmapperctl.o $(SHMAPPER_SONAME) $(SHMAP_SONAME)

.PHONY: clean-shmapperctl
clean-shmapperctl:
	$(RM) shmapperctl.o shmapperctl.d shmapperctl
	$(RM) shmapperctl.gcno shmapperctl.gcda

.PHONY: cscope
cscope: cscope.out

cscope.out: $(SHMAP_SRCS) $(SHMAPPER_SRCS) $(FUZZ_SRCS) shmapperd.c introspect.c shmapperctl.c
	cscope -b $^

.PHONY: clean-cscope
clean-cscope:
	$(RM) cscope.out

SPARSE=sparse -Wcast-from-as -Wcast-to-as
.PHONY: sparse
sparse: CC=$(SPARSE)
sparse: CFLAGS += -DSHMAPPER_SONAME='"$(SHMAPPER_SONAME)"' -DSHMAPPER_VERSION='"$(SHMAPPER_VERSION)"'
sparse: $(SHMAP_OBJS) $(SHMAPPER_OBJS) $(FUZZ_OBJS) shmapperd.o introspect.o shmapperctl.o
