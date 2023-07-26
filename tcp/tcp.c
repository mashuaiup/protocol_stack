#include "tcp.h"
#include <rte_tcp.h>
#include <rte_ip.h>
#include <rte_ether.h>


int ng_tcp_process(struct rte_mbuf *tcpmbuf, struct ng_tcp_table *stream_table, struct ng_epoll_table *epoll_tb_lhead) {

	struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(tcpmbuf, struct rte_ipv4_hdr *, 
				sizeof(struct rte_ether_hdr));
	struct rte_tcp_hdr *tcphdr = (struct rte_tcp_hdr *)(iphdr + 1);	
	
	// tcphdr, rte_ipv4_udptcp_cksum
	uint16_t tcpcksum = tcphdr->cksum;
	tcphdr->cksum = 0;
	uint16_t cksum = rte_ipv4_udptcp_cksum(iphdr, tcphdr);
	
	if (cksum != tcpcksum) { //
		printf("cksum: %x, tcp cksum: %x\n", cksum, tcpcksum);
		rte_pktmbuf_free(tcpmbuf);
		return -1;
	}
	struct conn_tuple tuple = {iphdr->src_addr, iphdr->dst_addr, tcphdr->src_port, tcphdr->dst_port};
	
	struct ng_tcp_stream *stream = ng_tcp_stream_search(&tuple, stream_table);
	if (stream == NULL) { 
		rte_pktmbuf_free(tcpmbuf);
		return -2;
	}

	switch (stream->status) {

		case NG_TCP_STATUS_CLOSED: //client 
			break;
			
		case NG_TCP_STATUS_LISTEN: // server
			ng_tcp_handle_listen(stream, iphdr);
			break;

		case NG_TCP_STATUS_SYN_RCVD: // server
			ng_tcp_handle_syn_rcvd(stream, (struct rte_tcp_hdr *)tcphdr, stream_table, epoll_tb_lhead->ep);
			break;

		case NG_TCP_STATUS_SYN_SENT: // client
			break;

		case NG_TCP_STATUS_ESTABLISHED: { // server | client

			int tcplen = ntohs(iphdr->total_length) - sizeof(struct rte_ipv4_hdr);
			struct eventpoll *ep = epoll_tb_lhead->ep;
			ng_tcp_handle_established(stream, (struct rte_tcp_hdr *)tcphdr, tcplen, ep);
			break;
		}
		case NG_TCP_STATUS_FIN_WAIT_1: //  ~client
			break;
			
		case NG_TCP_STATUS_FIN_WAIT_2: // ~client
			break;
			
		case NG_TCP_STATUS_CLOSING: // ~client
			break;
			
		case NG_TCP_STATUS_TIME_WAIT: // ~client
			break;

		case NG_TCP_STATUS_CLOSE_WAIT: // ~server
			ng_tcp_handle_close_wait(stream, tcphdr);
			break;
			
		case NG_TCP_STATUS_LAST_ACK:  // ~server
			ng_tcp_handle_last_ack(stream, (struct rte_tcp_hdr *)tcphdr);
			break;

	}
	rte_pktmbuf_free(tcpmbuf);
	return 0;
}

int ng_tcp_out(struct rte_mempool *mbuf_pool, struct inout_ring* ioa_ring, struct ng_tcp_table *table) {

	// struct ng_tcp_table *ng_tcp_tb = tcpInstance();
	struct ng_tcp_stream *stream;
	for (stream = table->tcb_set;stream != NULL;stream = stream->next) {

		if (stream->sndbuf == NULL) continue; // listener

		struct ng_tcp_fragment *fragment = NULL;		
		int nb_snd = rte_ring_mc_dequeue(stream->sndbuf, (void**)&fragment);
		if (nb_snd < 0) continue;
		struct rte_mbuf *tcpbuf = ng_tcp_pkt(mbuf_pool, stream->dip, stream->sip, fragment);
		int num = rte_ring_mp_enqueue_burst(ioa_ring->arp_ring, (void **)&tcpbuf, 1, NULL);
		if(num < 0){
			printf("tcp packet add into arp_ring failed\n");
		}
		if (fragment->data != NULL)
			rte_free(fragment->data);
		rte_free(fragment);
	}

	return 0;
}

struct ng_tcp_stream * ng_tcp_stream_search(struct conn_tuple *tuple, struct ng_tcp_table *table) { // proto

	struct ng_tcp_stream *iter;
	for (iter = table->tcb_set;iter != NULL; iter = iter->next) { // established

		if (iter->sip == tuple->sip && iter->dip == tuple->dip && 
			iter->sport == tuple->sport && iter->dport == tuple->dport) {
			return iter;
		}
	}

	for (iter = table->tcb_set;iter != NULL; iter = iter->next) {

		if (iter->dport == tuple->dport && iter->status == NG_TCP_STATUS_LISTEN) { // listen
			return iter;
		}
	}

	return NULL;
}

struct ng_tcp_stream * ng_tcp_stream_create(struct conn_tuple* tuple) { // proto

	// tcp --> status
	struct ng_tcp_stream *stream = rte_malloc("ng_tcp_stream", sizeof(struct ng_tcp_stream), 0);
	if (stream == NULL) return NULL;

	stream->sip = tuple->sip;
	stream->dip = tuple->dip;
	stream->sport = tuple->sport;
	stream->dport = tuple->dport;
	stream->protocol = IPPROTO_TCP;
	stream->fd = -1; //unused

	stream->status = NG_TCP_STATUS_LISTEN;

	//
	char sbufname[32] = {0};
	sprintf(sbufname, "sndbuf%x%d", tuple->sip, tuple->sport);
	stream->sndbuf = rte_ring_create(sbufname, RING_SIZE, rte_socket_id(), 0);
	
	char rbufname[32] = {0};
	sprintf(rbufname, "bufname%x%d", tuple->sip, tuple->sport);
	stream->rcvbuf = rte_ring_create(rbufname, RING_SIZE, rte_socket_id(), 0);
	
	// seq num
	uint32_t next_seed = time(NULL);
	stream->snd_nxt = rand_r(&next_seed) % TCP_MAX_SQE;
	// rte_memcpy(stream->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);

	pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
	rte_memcpy(&stream->cond, &blank_cond, sizeof(pthread_cond_t));

	pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
	rte_memcpy(&stream->mutex, &blank_mutex, sizeof(pthread_mutex_t));

	return stream;
}

int ng_tcp_handle_listen(struct ng_tcp_stream *stream, struct rte_ipv4_hdr *iphdr) {
	struct rte_tcp_hdr *tcphdr = (struct rte_tcp_hdr *)(iphdr + 1);	
	if (tcphdr->tcp_flags & RTE_TCP_SYN_FLAG)  {
		//stream --> listenfd
		if (stream->status == NG_TCP_STATUS_LISTEN) {

			ng_tcp_tb = tcpInstance();
			struct conn_tuple tuple = {iphdr->src_addr, iphdr->dst_addr,tcphdr->src_port, tcphdr->dst_port};
			struct ng_tcp_stream *syn = ng_tcp_stream_create(&tuple);
			LL_ADD(syn, ng_tcp_tb->tcb_set);


			struct ng_tcp_fragment *fragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
			if (fragment == NULL) return -1;
			memset(fragment, 0, sizeof(struct ng_tcp_fragment));

			fragment->sport = tcphdr->dst_port;
			fragment->dport = tcphdr->src_port;

			struct in_addr addr;
			addr.s_addr = syn->sip;
			printf("tcp ---> src: %s:%d ", inet_ntoa(addr), ntohs(tcphdr->src_port));

			addr.s_addr = syn->dip;
			printf("  ---> dst: %s:%d \n", inet_ntoa(addr), ntohs(tcphdr->dst_port));

			fragment->seqnum = syn->snd_nxt;
			fragment->acknum = ntohl(tcphdr->sent_seq) + 1;
			syn->rcv_nxt = fragment->acknum;
			
			fragment->tcp_flags = (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG);
			fragment->windows = TCP_INITIAL_WINDOW;
			fragment->hdrlen_off = 0x50;
			
			fragment->data = NULL;
			fragment->length = 0;
			rte_ring_mp_enqueue(syn->sndbuf, fragment);
			
			syn->status = NG_TCP_STATUS_SYN_RCVD;
		}
	}

	return 0;
}

int ng_tcp_handle_syn_rcvd(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr, struct ng_tcp_table *table, struct eventpoll *ep) {

	if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {
		if (stream->status == NG_TCP_STATUS_SYN_RCVD) {
			uint32_t acknum = ntohl(tcphdr->recv_ack);
			if (acknum == stream->snd_nxt + 1) {
				// 
			}
			stream->status = NG_TCP_STATUS_ESTABLISHED;
			// accept
			struct conn_tuple tuple = {0, 0, 0, stream->dport};
			struct ng_tcp_stream *listener = ng_tcp_stream_search(&tuple, table);
			if (listener == NULL) {
				rte_exit(EXIT_FAILURE, "ng_tcp_stream_search failed\n");
			}
			pthread_mutex_lock(&listener->mutex);
			pthread_cond_signal(&listener->cond);
			pthread_mutex_unlock(&listener->mutex);
			epoll_event_callback(ep, listener->fd, EPOLLIN);
		}

	}
	return 0;
}

/* 将 数据 拷贝到recvbuf中*/
int ng_tcp_enqueue_recvbuffer(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr, int tcplen) {

	// recv buffer
	struct ng_tcp_fragment *rfragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
	if (rfragment == NULL) return -1;
	memset(rfragment, 0, sizeof(struct ng_tcp_fragment));

	rfragment->dport = ntohs(tcphdr->dst_port);
	rfragment->sport = ntohs(tcphdr->src_port);

	uint8_t hdrlen = tcphdr->data_off >> 4;
	int payloadlen = tcplen - hdrlen * 4; //
	if (payloadlen > 0) {
		
		uint8_t *payload = (uint8_t*)tcphdr + hdrlen * 4;

		rfragment->data = rte_malloc("unsigned char *", payloadlen+1, 0);
		if (rfragment->data == NULL) {
			rte_free(rfragment);
			return -1;
		}
		memset(rfragment->data, 0, payloadlen+1);

		rte_memcpy(rfragment->data, payload, payloadlen);
		rfragment->length = payloadlen;

	} else if (payloadlen == 0) {

		rfragment->length = 0;
		rfragment->data = NULL;

	}
	rte_ring_mp_enqueue(stream->rcvbuf, rfragment);

	pthread_mutex_lock(&stream->mutex);
	pthread_cond_signal(&stream->cond);
	pthread_mutex_unlock(&stream->mutex);

	return 0;
}

int ng_tcp_send_ackpkt(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr) {

	struct ng_tcp_fragment *ackfrag = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
	if (ackfrag == NULL) return -1;
	memset(ackfrag, 0, sizeof(struct ng_tcp_fragment));

	ackfrag->dport = tcphdr->src_port;
	ackfrag->sport = tcphdr->dst_port;

	// remote
	
	printf("ng_tcp_send_ackpkt: %d, %d\n", stream->rcv_nxt, ntohs(tcphdr->sent_seq));
	

	ackfrag->acknum = stream->rcv_nxt;
	ackfrag->seqnum = stream->snd_nxt;

	ackfrag->tcp_flags = RTE_TCP_ACK_FLAG;
	ackfrag->windows = TCP_INITIAL_WINDOW;
	ackfrag->hdrlen_off = 0x50;
	ackfrag->data = NULL;
	ackfrag->length = 0;
	
	rte_ring_mp_enqueue(stream->sndbuf, ackfrag);

	return 0;
}

int ng_tcp_handle_established(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr, int tcplen, struct eventpoll *ep) {

	if (tcphdr->tcp_flags & RTE_TCP_SYN_FLAG) {
		//
	} 
	if (tcphdr->tcp_flags & RTE_TCP_PSH_FLAG) { //

		ng_tcp_enqueue_recvbuffer(stream, tcphdr, tcplen); //ms:将数据接收到recvbuf中
		
		epoll_event_callback(ep, stream->fd, EPOLLIN);     //ms:这边的文件描述符是客户端的文件描述符

		uint8_t hdrlen = tcphdr->data_off >> 4;
		int payloadlen = tcplen - hdrlen * 4;
		
		stream->rcv_nxt = stream->rcv_nxt + payloadlen;
		stream->snd_nxt = ntohl(tcphdr->recv_ack);
		
		ng_tcp_send_ackpkt(stream, tcphdr); //相应ack给客户端

	}
	if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {

	}
	if (tcphdr->tcp_flags & RTE_TCP_FIN_FLAG) {  //接收到客户端断开连接的请求时

		stream->status = NG_TCP_STATUS_CLOSE_WAIT;
		ng_tcp_enqueue_recvbuffer(stream, tcphdr, tcphdr->data_off >> 4);
		epoll_event_callback(ep, stream->fd, EPOLLIN);

		// send ack ptk
		stream->rcv_nxt = stream->rcv_nxt + 1;
		stream->snd_nxt = ntohl(tcphdr->recv_ack);
		
		ng_tcp_send_ackpkt(stream, tcphdr);
	}
	return 0;
}

int ng_tcp_handle_close_wait(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr) {

	if (tcphdr->tcp_flags & RTE_TCP_FIN_FLAG) { //

		if (stream->status == NG_TCP_STATUS_CLOSE_WAIT) {

		}
	}	
	return 0;
}

int ng_tcp_handle_last_ack(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr) {

	if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {

		if (stream->status == NG_TCP_STATUS_LAST_ACK) {

			stream->status = NG_TCP_STATUS_CLOSED;

			ng_tcp_tb = tcpInstance();
			LL_REMOVE(stream, ng_tcp_tb->tcb_set);

			rte_ring_free(stream->sndbuf);
			rte_ring_free(stream->rcvbuf);

			rte_free(stream);

		}

	}

	return 0;
}

// <tcb> --> tcp
int ng_encode_tcp_apppkt(uint8_t *msg, uint32_t sip, uint32_t dip,
	 struct ng_tcp_fragment *fragment) {

	// encode 
	const unsigned total_len = fragment->length + sizeof(struct rte_ether_hdr) +
							sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr) + 
							fragment->optlen * sizeof(uint32_t);

	// 1 ethhdr
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	uint8_t gDefaultArpMac[RTE_ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	rte_memcpy(eth->s_addr.addr_bytes, gDefaultArpMac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->d_addr.addr_bytes, gDefaultArpMac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);
	

	// 2 iphdr 
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
	ip->version_ihl = 0x45;
	ip->type_of_service = 0;
	ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
	ip->packet_id = 0;
	ip->fragment_offset = 0;
	ip->time_to_live = 64; // ttl = 64
	ip->next_proto_id = IPPROTO_TCP;
	ip->src_addr = sip;
	ip->dst_addr = dip;
	
	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);

	// 3 udphdr 

	struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	tcp->src_port = fragment->sport;
	tcp->dst_port = fragment->dport;
	tcp->sent_seq = htonl(fragment->seqnum);
	tcp->recv_ack = htonl(fragment->acknum);

	tcp->data_off = fragment->hdrlen_off;
	tcp->rx_win = fragment->windows;
	tcp->tcp_urp = fragment->tcp_urp;
	tcp->tcp_flags = fragment->tcp_flags;

	if (fragment->data != NULL) {
		uint8_t *payload = (uint8_t*)(tcp+1) + fragment->optlen * sizeof(uint32_t);
		rte_memcpy(payload, fragment->data, fragment->length);
	}

	tcp->cksum = 0;
	tcp->cksum = rte_ipv4_udptcp_cksum(ip, tcp);

	return 0;
}


struct rte_mbuf *ng_tcp_pkt(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip,
	struct ng_tcp_fragment *fragment) {

	// mempool --> mbuf

	const unsigned total_len = fragment->length + sizeof(struct rte_ether_hdr) +
							sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr) + 
							fragment->optlen * sizeof(uint32_t);

	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "ng_tcp_pkt rte_pktmbuf_alloc\n");
	}
	mbuf->pkt_len = total_len;
	mbuf->data_len = total_len;

	uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);

	ng_encode_tcp_apppkt(pktdata, sip, dip, fragment);

	return mbuf;

}

int tcp_server_entry(__attribute__((unused))  void *arg)  {
	int listenfd = nsocket(AF_INET, SOCK_STREAM, 0);
	if (listenfd == -1) {
		return -1;
	}
	struct sockaddr_in servaddr;
	memset(&servaddr, 0, sizeof(struct sockaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(9999);
	nbind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr));
	nlisten(listenfd, 10);

	int epfd = nepoll_create(1); // event poll

	struct epoll_event ev, events[128];
	ev.events = EPOLLIN;
	ev.data.fd = listenfd;
	nepoll_ctl(epfd, EPOLL_CTL_ADD, listenfd, &ev);
	
	char buff[BUFFER_SIZE] = {0};
	while(1) {

		int nready = nepoll_wait(epfd, events, 128, 5);
		if (nready < 0) continue;
		
		int i = 0;
		for (i = 0; i < nready; i++) {
			if (listenfd == events[i].data.fd) {
				struct sockaddr_in client;
				socklen_t len = sizeof(client);
				int connfd = naccept(listenfd, (struct sockaddr*)&client, &len);
				struct epoll_event ev;
				ev.events = EPOLLIN;
				ev.data.fd = connfd;
				nepoll_ctl(epfd, EPOLL_CTL_ADD, connfd, &ev);
			} else { // clientfd
				int connfd = events[i].data.fd;
				int n = nrecv(connfd, buff, BUFFER_SIZE, 0); //block
				if (n > 0) {
					printf("recv: %s\n", buff);
					nsend(connfd, buff, n, 0);
				} else {
					nepoll_ctl(epfd, EPOLL_CTL_DEL, connfd, NULL);
					nclose(connfd);
				} 
			}
		}
	}
}