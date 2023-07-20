ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overriden by command line or environment
# RTE_TARGET ?= x86_64-default-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = protostack

# all source are stored in SRCS-y


# for decode dir
VPATH += $(SRCDIR)/std
SRCS-y += std.c
VPATH += $(SRCDIR)/epoll
SRCS-y += epoll.c
VPATH += $(SRCDIR)/socket
SRCS-y += socket.c
VPATH += $(SRCDIR)/tcp
SRCS-y += tcp.c
VPATH += $(SRCDIR)/udp
SRCS-y += udp.c
VPATH += $(SRCDIR)/arp
SRCS-y += arp.c

SRCS-y += protostack.c

# include path
CFLAGS += -I$(SRCDIR)
CFLAGS += -I$(SRCDIR)/tcp/
CFLAGS += -I$(SRCDIR)/udp/
CFLAGS += -I$(SRCDIR)/arp/
CFLAGS += -I$(SRCDIR)/std/
CFLAGS += -I$(SRCDIR)/epoll/
CFLAGS += -I$(SRCDIR)/socket/

# build flags
CFLAGS += -O0 -g

## LD LIB
LDLIBS += -L/usr/local/lib
LDLIBS += -lnuma 

include $(RTE_SDK)/mk/rte.extapp.mk
