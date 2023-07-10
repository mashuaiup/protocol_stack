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


extern uint32_t    gSrcIp;
extern uint32_t    gDstIp;
extern uint8_t     gSrcMac[RTE_ETHER_ADDR_LEN];
extern uint8_t     gDstMac[RTE_ETHER_ADDR_LEN];
extern uint16_t    gSrcPort;
extern uint16_t    gDstPort;
extern int         gDpdkPortId;
extern uint32_t    gLocalIp;
extern struct      localhost *lhost;

#define NUM_MBUFS                      (4096-1)
#define BURST_SIZE	                   32
#define RING_SIZE	                   1024
#define MAKE_IPV4_ADDR(a, b, c, d)     (a + (b<<8) + (c<<16) + (d<<24))//转换成网络字节序
#define TIMER_RESOLUTION_CYCLES        120000000000ULL // 10ms * 1000 = 10s * 6 

struct inout_ring {
	struct rte_ring *in;
	struct rte_ring *out;
};

struct localhost { // 

	int fd;

	//unsigned int status; //
	uint32_t localip; // ip --> mac
	uint8_t localmac[RTE_ETHER_ADDR_LEN];
	uint16_t localport;

	uint8_t protocol;

	struct rte_ring *sndbuf;
	struct rte_ring *rcvbuf;

	struct localhost *prev; //
	struct localhost *next;

	pthread_cond_t cond;
	pthread_mutex_t mutex;

};
struct offload { //

	uint32_t sip;
	uint32_t dip;

	uint16_t sport;
	uint16_t dport; //

	int protocol;

	unsigned char *data;
	uint16_t length;
	
}; 
struct inout_ring *ringInstance(void);
struct localhost * get_hostinfo_fromip_port(uint32_t dip, uint16_t port, uint8_t proto);
#endif