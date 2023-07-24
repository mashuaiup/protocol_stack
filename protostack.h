#ifndef __protostack__
#define __protostack__
#include <rte_ethdev.h>
#include <arpa/inet.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_arp.h>
#include <rte_icmp.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include "tcp.h"
#include "udp.h"
#include "arp.h"
#include "std.h"
#include "epoll.h"
#include "define.h"


extern uint32_t    gSrcIp;
extern uint32_t    gDstIp;
extern uint8_t     gSrcMac[RTE_ETHER_ADDR_LEN];
extern uint8_t     gDstMac[RTE_ETHER_ADDR_LEN];
extern uint16_t    gSrcPort;
extern uint16_t    gDstPort;
extern int         gDpdkPortId;
extern uint32_t    gLocalIp;
 

int stack_info_init(stack_arg_t *stack_arg);
#endif