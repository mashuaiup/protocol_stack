#ifndef __TCP__
#define __TCP__
#include "std.h"
#include "socket.h"
#include "epoll.h"
#include <rte_mbuf.h>
#include <rte_tcp.h>
#include <rte_ip.h>
#include <rte_malloc.h>

#define TCP_MAX_SQE         4294967296

#define BUFFER_SIZE	        1024



struct conn_tuple {
	uint32_t sip;
	uint32_t dip; 
	uint16_t sport; 
	uint16_t dport;
};



// void ng_encode_tcp_pkt(uint8_t * pkt, tcp_stream *tcp_stream_item, struct rte_ether_hdr *ethdr_received);

int ng_tcp_process(struct rte_mbuf *tcpmbuf, struct ng_tcp_table *stream_table, struct ng_epoll_table *epoll_tb_lhead);
int ng_tcp_out(struct rte_mempool *mbuf_pool, struct inout_ring* ioa_ring, struct ng_tcp_table *table);
struct rte_mbuf *ng_tcp_pkt(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip, struct ng_tcp_fragment *fragment);
int tcp_server_entry(__attribute__((unused))  void *arg);

int ng_encode_tcp_apppkt(uint8_t *msg, uint32_t sip, uint32_t dip,struct ng_tcp_fragment *fragment);
int ng_tcp_handle_last_ack(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr);
int ng_tcp_handle_close_wait(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr);
int ng_tcp_handle_established(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr, int tcplen, struct eventpoll *ep);
int ng_tcp_send_ackpkt(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr);
int ng_tcp_enqueue_recvbuffer(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr, int tcplen);
int ng_tcp_handle_syn_rcvd(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr, struct ng_tcp_table *table, struct eventpoll *ep);
int ng_tcp_handle_listen(struct ng_tcp_stream *stream, struct rte_ipv4_hdr *iphdr);
struct ng_tcp_stream * ng_tcp_stream_create(struct conn_tuple* tuple);
struct ng_tcp_stream * ng_tcp_stream_search(struct conn_tuple *tuple, struct ng_tcp_table* stream_table);

#endif