ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overriden by command line or environment
RTE_TARGET ?= $(notdir $(abspath $(dir $(firstword $(wildcard $(RTE_SDK)/*/.config)))))

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
LIB = libprotostack.a

# all source are stored in SRCS-y
SRCS-y += protostack.c

# for decode dir
VPATH += $(SRCDIR)/tcp
SRCS-y += tcp.c
VPATH += $(SRCDIR)/udp
SRCS-y += udp.c
VPATH += $(SRCDIR)/arp
SRCS-y += arp.c
VPATH += $(SRCDIR)/epoll
SRCS-y += epoll.c
VPATH += $(SRCDIR)/std
SRCS-y += std.c
VPATH += $(SRCDIR)/socket
SRCS-y += socket.c


# include path
CFLAGS += -I$(SRCDIR)
CFLAGS += -I$(SRCDIR)/tcp/
CFLAGS += -I$(SRCDIR)/udp/
CFLAGS += -I$(SRCDIR)/arp/
CFLAGS += -I$(SRCDIR)/std/
CFLAGS += -I$(SRCDIR)/epoll/
CFLAGS += -I$(SRCDIR)/socket/

# build flags
CFLAGS += -O3 -g

## LD LIB
LDLIBS += -L/usr/local/lib
LDLIBS += -lnuma 

include $(RTE_SDK)/mk/rte.extlib.mk
