# ==============================================================================
# RAPTOR-OS // MAKEFILE NATIF BSD POUR RAP (MOTEUR CLI)
# Architecture : OpenBSD 8.0 amd64 - Clang (cc)
# ==============================================================================

CC = cc
CFLAGS = -std=c99 -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_GNU_SOURCE=1 \
         -Wall -Wextra -O2 \
         -Iinclude -Isrc/cli -Isrc/engine -Isrc/core

LDFLAGS = -lm -pthread

SRCS = src/cli/rap_main.c \
       src/cli/rap_common.c \
       src/cli/cmd_status.c \
       src/cli/cmd_top.c \
       src/cli/cmd_hunt.c \
       src/cli/cmd_rx.c \
       src/cli/cmd_preload.c \
       src/cli/cmd_heur.c \
       src/cli/cmd_net.c \
       src/cli/cmd_sentry.c \
       src/cli/cmd_kill.c \
       src/cli/cmd_man.c \
       src/engine/sentry_engine.c \
       src/core/rap_oom.c \
       src/core/rap_blackbox.c \
       src/core/rap_reflex.c \
       src/cli/cmd_netop.c \
       src/cli/netop_engine.c \
       src/cli/netop_router.c \
       src/cli/netop_cmd_kill.c \
       src/cli/netop_cmd_ban.c \
       src/cli/netop_cmd_inspect.c \
       src/cli/netop_cmd_sort.c \
       src/cli/netop_cmd_filter.c

OBJS = $(SRCS:.c=.o)
TARGET = bin/rap

all: $(TARGET)
$(TARGET): $(OBJS)
	@mkdir -p bin
	$(CC) $(OBJS) $(LDFLAGS) -o $@

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)
