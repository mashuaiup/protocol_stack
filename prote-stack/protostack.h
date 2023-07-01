#ifndef __protostack__
#define __protostack__
#include <rte_ethdev.h>
#include <arpa/inet.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_arp.h>

extern uint32_t gSrcIp;
extern uint32_t gDstIp;
extern uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];
extern uint8_t gDstMac[RTE_ETHER_ADDR_LEN];
extern uint16_t gSrcPort;
extern uint16_t gDstPort;
extern int gDpdkPortId;
extern uint32_t gLocalIp;

#define LADD(item, list) do { \
    item->next = list; \
    item->pre = NULL; \
    if(list != NULL) list->pre = item; \
    list = item; \
}while(0);

typedef enum TCP_STATUS_{
	NG_TCP_TCP_STATUS_CLOSED=0,
	NG_TCP_TCP_STATUS_LISTEN=1,
	NG_TCP_TCP_STATUS_SYN_RECEIVED,
	NG_TCP_TCP_STATUS_SYN_SEND,
	NG_TCP_TCP_STATUS_ESTABLISHED,
	NG_TCP_TCP_STATUS_FIN_WAIT_1,
	NG_TCP_TCP_STATUS_FIN_WAIT_2,
	NG_TCP_TCP_STATUS_CLOSING,
	NG_TCP_TCP_STATUS_TIME_WAIT,
	NG_TCP_TCP_STATUS_CLOSE_WAIT,
	NG_TCP_TCP_STATUS_LASK_ACK
}TCP_STATUS;
typedef struct tcp_stream_{
	uint32_t sip;
	uint32_t dip;
	uint16_t sport;
	uint16_t dport;
	uint8_t proto;
	uint8_t status;
	uint32_t send_sqe;
	uint32_t recv_sqe;
	struct tcp_stream_ *pre;
	struct tcp_stream_ *next;

}tcp_stream;

typedef struct tcp_stream_table_{
	uint64_t table_size;
	tcp_stream *stream_item;
}tcp_stream_table;

static  tcp_stream_table *stream_table = NULL;

#endif