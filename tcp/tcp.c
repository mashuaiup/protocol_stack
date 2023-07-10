#include "tcp.h"
struct ng_tcp_table *tInst = NULL;
struct ng_tcp_table *tcpInstance(void) {

	if (tInst == NULL) {

		tInst = rte_malloc("ng_tcp_table", sizeof(struct ng_tcp_table), 0);
		memset(tInst, 0, sizeof(struct ng_tcp_table));
		
	}
	return tInst;
}

struct ng_tcp_stream *get_accept_tcb(uint16_t dport) {

	struct ng_tcp_stream *apt;
	struct ng_tcp_table *table = tcpInstance();
	for (apt = table->tcb_set;apt != NULL;apt = apt->next) {
		if (dport == apt->dport && apt->fd == -1) {
			return apt;
		}
	}

	return NULL;
}

void* get_hostinfo_fromfd(int sockfd) {
	struct localhost *host;
	for (host = lhost; host != NULL;host = host->next) {

		if (sockfd == host->fd) {
			return host;
		}

	}
	struct ng_tcp_stream *stream = NULL;
	struct ng_tcp_table *table = tcpInstance();
	for (stream = table->tcb_set;stream != NULL;stream = stream->next) {
		if (sockfd == stream->fd) {
			return stream;
		}
	}
	struct eventpoll *ep = table->ep;
	if (ep != NULL) {
		if (ep->fd == sockfd) {
			return ep;
		}
	}
	return NULL;	
}

/* void ng_encode_tcp_pkt(uint8_t * pkt, tcp_stream *tcp_stream_item, struct rte_ether_hdr *ethdr_received){
	//ethdr
	struct rte_ether_hdr * ethdr = (struct rte_ether_hdr *)pkt;
	rte_memcpy(ethdr->s_addr.addr_bytes, ethdr_received->d_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
	rte_memcpy(ethdr->d_addr.addr_bytes, ethdr_received->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
    ethdr->ether_type = htons(RTE_ETHER_TYPE_IPV4);
	//iphdr
	struct rte_ipv4_hdr *iphdr = (struct rte_ipv4_hdr *)(ethdr + 1);
	struct rte_ipv4_hdr *iphdr_received = (struct rte_ipv4_hdr *)(ethdr_received + 1);
	iphdr->version_ihl = 0x45;
	iphdr->type_of_service = 0;
	iphdr->total_length = htons(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr));
	printf("iphdr->total_length:%04x\n", iphdr->total_length);
	iphdr->packet_id =  0;
	iphdr->fragment_offset = 0;
	iphdr->time_to_live =64;
	iphdr->next_proto_id = IPPROTO_TCP;
	iphdr->src_addr = iphdr_received->dst_addr;
	iphdr->dst_addr = iphdr_received->src_addr;
	iphdr->hdr_checksum = 0;
	iphdr->hdr_checksum = rte_ipv4_cksum(iphdr);
	//tcphdr
	struct rte_tcp_hdr * tcphdr =  (struct rte_tcp_hdr *)(iphdr+ 1);
	struct rte_tcp_hdr * tcphdr_received =  (struct rte_tcp_hdr *)(iphdr_received + 1);
	tcphdr->src_port = tcphdr_received->dst_port;
	tcphdr->dst_port = tcphdr_received->src_port;
	tcphdr->sent_seq = tcp_stream_item->send_sqe;
	tcphdr->recv_ack = htonl(ntohl(tcphdr_received->sent_seq) + 1); //暂时没能理解
	tcp_stream_item->recv_sqe = tcphdr->recv_ack;
	tcphdr->data_off = 0x50;
	tcphdr->tcp_flags = (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG);
	tcphdr->rx_win = TCP_INITIAL_WINDOW;
	tcphdr->cksum = 0;
	tcphdr->cksum = rte_ipv4_udptcp_cksum(iphdr, (const void *)tcphdr);
}
 */
/* static tcp_stream_table* get_stream_table_instance(void){
	if(!stream_table){
		stream_table = rte_malloc("stream_table", sizeof(tcp_stream_table), 0);
		if(stream_table==NULL){
			rte_exit(EXIT_FAILURE, "rte_malloc error!");
		}
		memset(stream_table, 0 ,sizeof(tcp_stream_table));
	}
	return stream_table;
} */

/* static tcp_stream * query_stream(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport){
	tcp_stream_table *list = get_stream_table_instance();
	while(list->stream_item){
		if(list->stream_item->sip == sip && list->stream_item->dip == dip && list->stream_item->sport == sport && list->stream_item->dport == dport){
			return list->stream_item;
		}
	}
	return NULL;
}

static tcp_stream * create_connect_stream(struct rte_ipv4_hdr *iphdr, struct rte_tcp_hdr* tcphdr){	
	tcp_stream * stream = rte_malloc("stream", sizeof(tcp_stream), 0);
	stream->sip = iphdr->src_addr;
	stream->dip = iphdr->dst_addr;

	stream->sport = tcphdr->src_port;
	stream->dport = tcphdr->dst_port;
	stream->proto = iphdr->next_proto_id;
	srand((unsigned)time(NULL));
	stream->send_sqe = rand() % TCP_MAX_SQE;
	printf("其中stream->send_sqe:%d",stream->send_sqe);
	stream->status = NG_TCP_STATUS_LISTEN;
	stream->pre = NULL;
	stream->next = NULL;
	return stream;
}

static int handle_listen(tcp_stream *tcp_stream_item, struct rte_mempool * mbuf_pool,struct rte_ether_hdr *ehdr, struct rte_ipv4_hdr *iphdr, struct rte_tcp_hdr *tcphdr){
	if(tcphdr->tcp_flags == RTE_TCP_SYN_FLAG){
		uint32_t sip = iphdr->src_addr;
		printf("客户端%d发来连接请求\n", sip);
		//申请mbuf
		struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
		if(mbuf == NULL){
			rte_exit(EXIT_FAILURE,"alloc error!\n");
		} 
		//1、构造报文 
		uint32_t total_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr);
		mbuf->data_len = total_len;
		mbuf->pkt_len = total_len;
		uint8_t *pktbuf = rte_pktmbuf_mtod(mbuf, uint8_t*);
		ng_encode_tcp_pkt(pktbuf, tcp_stream_item, ehdr);
		//2、通过tx_brust传送出去 
		rte_eth_tx_burst(gDpdkPortId, 0, &mbuf, 1);
		rte_pktmbuf_free(mbuf);
		//3、将状态转换成syn_received
		tcp_stream_item->status = NG_TCP_STATUS_SYN_RCVD;		
	}
	return 0;
}

static void handle_syn_received(tcp_stream *tcp_stream_item,struct rte_tcp_hdr *tcphdr){
	if(tcphdr->tcp_flags == RTE_TCP_SYN_FLAG){
		printf("再次收到请求报文,连接失败\n");
	}else{
		printf("连接成功\n");
	}
	tcp_stream_item->status = NG_TCP_STATUS_ESTABLISHED;
}

void handle_tcp(struct rte_mbuf *mbuf, struct rte_mempool* mbuf_pool){

	struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr*);
	struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, 
				sizeof(struct rte_ether_hdr));
	struct rte_tcp_hdr *tcphdr =  (struct rte_tcp_hdr *)(iphdr + 1);

	tcp_stream *tcp_stream_item = query_stream(iphdr->src_addr,iphdr->dst_addr, tcphdr->src_port, tcphdr->dst_port);  
	if(tcp_stream_item == NULL){
		//创建一个连接，且连接的状态为listen状态
		tcp_stream_item  = create_connect_stream(iphdr, tcphdr);
		tcp_stream_table *table = get_stream_table_instance();
		printf("新的连接,需要创建新的连接\n");
		LADD(tcp_stream_item, table->stream_item);
	}
	switch (tcp_stream_item->status)
	{
	case NG_TCP_STATUS_CLOSED:
		break;
	case NG_TCP_STATUS_LISTEN:
		handle_listen(tcp_stream_item, mbuf_pool, ehdr, iphdr, tcphdr);//解包，发包
		break;
	case NG_TCP_STATUS_SYN_RCVD:
		handle_syn_received(tcp_stream_item,tcphdr);//解包，发包
		break;
	default:
		break;
	}
	rte_pktmbuf_free(mbuf);	
} */

int ng_tcp_process(struct rte_mbuf *tcpmbuf) {

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

	struct ng_tcp_stream *stream = ng_tcp_stream_search(iphdr->src_addr, iphdr->dst_addr, 
		tcphdr->src_port, tcphdr->dst_port);
	if (stream == NULL) { 
		rte_pktmbuf_free(tcpmbuf);
		return -2;
	}

	switch (stream->status) {

		case NG_TCP_STATUS_CLOSED: //client 
			break;
			
		case NG_TCP_STATUS_LISTEN: // server
			ng_tcp_handle_listen(stream, tcphdr, iphdr);
			break;

		case NG_TCP_STATUS_SYN_RCVD: // server
			ng_tcp_handle_syn_rcvd(stream, tcphdr);
			break;

		case NG_TCP_STATUS_SYN_SENT: // client
			break;

		case NG_TCP_STATUS_ESTABLISHED: { // server | client

			int tcplen = ntohs(iphdr->total_length) - sizeof(struct rte_ipv4_hdr);
			
			ng_tcp_handle_established(stream, tcphdr, tcplen);
			
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
			ng_tcp_handle_last_ack(stream, tcphdr);
			break;

	}

	rte_pktmbuf_free(tcpmbuf);

	return 0;
}

int ng_tcp_out(struct rte_mempool *mbuf_pool) {

	struct ng_tcp_table *table = tcpInstance();
	
	struct ng_tcp_stream *stream;
	for (stream = table->tcb_set;stream != NULL;stream = stream->next) {

		if (stream->sndbuf == NULL) continue; // listener

		struct ng_tcp_fragment *fragment = NULL;		
		int nb_snd = rte_ring_mc_dequeue(stream->sndbuf, (void**)&fragment);
		if (nb_snd < 0) continue;

		uint8_t *dstmac = ng_get_dst_macaddr(stream->sip); // 
		if (dstmac == NULL) {

			//printf("ng_send_arp\n");
			struct rte_mbuf *arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, gDefaultArpMac, 
				stream->dip, stream->sip);

			struct inout_ring *ring = ringInstance();
			rte_ring_mp_enqueue_burst(ring->out, (void **)&arpbuf, 1, NULL);

			rte_ring_mp_enqueue(stream->sndbuf, fragment);

		} else {

			struct rte_mbuf *tcpbuf = ng_tcp_pkt(mbuf_pool, stream->dip, stream->sip, stream->localmac, dstmac, fragment);

			struct inout_ring *ring = ringInstance();
			rte_ring_mp_enqueue_burst(ring->out, (void **)&tcpbuf, 1, NULL);

			if (fragment->data != NULL)
				rte_free(fragment->data);
			
			rte_free(fragment);
		}

	}

	return 0;
}


































struct ng_tcp_stream * ng_tcp_stream_search(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) { // proto

	struct ng_tcp_table *table = tcpInstance();

	struct ng_tcp_stream *iter;
	for (iter = table->tcb_set;iter != NULL; iter = iter->next) { // established

		if (iter->sip == sip && iter->dip == dip && 
			iter->sport == sport && iter->dport == dport) {
			return iter;
		}

	}

	for (iter = table->tcb_set;iter != NULL; iter = iter->next) {

		if (iter->dport == dport && iter->status == NG_TCP_STATUS_LISTEN) { // listen
			return iter;
		}

	}

	return NULL;
}

struct ng_tcp_stream * ng_tcp_stream_create(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) { // proto

	// tcp --> status
	struct ng_tcp_stream *stream = rte_malloc("ng_tcp_stream", sizeof(struct ng_tcp_stream), 0);
	if (stream == NULL) return NULL;

	stream->sip = sip;
	stream->dip = dip;
	stream->sport = sport;
	stream->dport = dport;
	stream->protocol = IPPROTO_TCP;
	stream->fd = -1; //unused

	// 
	stream->status = NG_TCP_STATUS_LISTEN;

	printf("ng_tcp_stream_create\n");
	//
	char sbufname[32] = {0};
	sprintf(sbufname, "sndbuf%x%d", sip, sport);
	stream->sndbuf = rte_ring_create(sbufname, RING_SIZE, rte_socket_id(), 0);
	
	char rbufname[32] = {0};
	sprintf(rbufname, "bufname%x%d", sip, sport);
	stream->rcvbuf = rte_ring_create(rbufname, RING_SIZE, rte_socket_id(), 0);
	
	// seq num
	uint32_t next_seed = time(NULL);
	stream->snd_nxt = rand_r(&next_seed) % TCP_MAX_SQE;
	rte_memcpy(stream->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);

	pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
	rte_memcpy(&stream->cond, &blank_cond, sizeof(pthread_cond_t));

	pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
	rte_memcpy(&stream->mutex, &blank_mutex, sizeof(pthread_mutex_t));

	//struct ng_tcp_table *table = tcpInstance();
	//LL_ADD(stream, table->tcb_set);

	return stream;
}

int ng_tcp_handle_listen(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr, struct rte_ipv4_hdr *iphdr) {

	if (tcphdr->tcp_flags & RTE_TCP_SYN_FLAG)  {
		//stream --> listenfd
		if (stream->status == NG_TCP_STATUS_LISTEN) {

			struct ng_tcp_table *table = tcpInstance();
			struct ng_tcp_stream *syn = ng_tcp_stream_create(iphdr->src_addr, iphdr->dst_addr, tcphdr->src_port, tcphdr->dst_port);
			LL_ADD(syn, table->tcb_set);


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


int ng_tcp_handle_syn_rcvd(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr) {

	if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {

		if (stream->status == NG_TCP_STATUS_SYN_RCVD) {

			uint32_t acknum = ntohl(tcphdr->recv_ack);
			if (acknum == stream->snd_nxt + 1) {
				// 
			}

			stream->status = NG_TCP_STATUS_ESTABLISHED;

			// accept
			struct ng_tcp_stream *listener = ng_tcp_stream_search(0, 0, 0, stream->dport);
			if (listener == NULL) {
				rte_exit(EXIT_FAILURE, "ng_tcp_stream_search failed\n");
			}

			pthread_mutex_lock(&listener->mutex);
			pthread_cond_signal(&listener->cond);
			pthread_mutex_unlock(&listener->mutex);
			


			struct ng_tcp_table *table = tcpInstance();
			epoll_event_callback(table->ep, listener->fd, EPOLLIN);



		}

	}
	return 0;
}

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

int ng_tcp_handle_established(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr, int tcplen) {

	if (tcphdr->tcp_flags & RTE_TCP_SYN_FLAG) {
		//
	} 
	if (tcphdr->tcp_flags & RTE_TCP_PSH_FLAG) { //

		ng_tcp_enqueue_recvbuffer(stream, tcphdr, tcplen);
		

		struct ng_tcp_table *table = tcpInstance();
		epoll_event_callback(table->ep, stream->fd, EPOLLIN);

		uint8_t hdrlen = tcphdr->data_off >> 4;
		int payloadlen = tcplen - hdrlen * 4;
		
		stream->rcv_nxt = stream->rcv_nxt + payloadlen;
		stream->snd_nxt = ntohl(tcphdr->recv_ack);
		
		ng_tcp_send_ackpkt(stream, tcphdr);

	}
	if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {

	}
	if (tcphdr->tcp_flags & RTE_TCP_FIN_FLAG) {

		stream->status = NG_TCP_STATUS_CLOSE_WAIT;
		ng_tcp_enqueue_recvbuffer(stream, tcphdr, tcphdr->data_off >> 4);
		struct ng_tcp_table *table = tcpInstance();
		epoll_event_callback(table->ep, stream->fd, EPOLLIN);

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

			printf("ng_tcp_handle_last_ack\n");
			struct ng_tcp_table *table = tcpInstance();
			LL_REMOVE(stream, table->tcb_set);

			rte_ring_free(stream->sndbuf);
			rte_ring_free(stream->rcvbuf);

			rte_free(stream);

		}

	}

	return 0;
}

// <tcb> --> tcp



int ng_encode_tcp_apppkt(uint8_t *msg, uint32_t sip, uint32_t dip,
	uint8_t *srcmac, uint8_t *dstmac, struct ng_tcp_fragment *fragment) {

	// encode 
	const unsigned total_len = fragment->length + sizeof(struct rte_ether_hdr) +
							sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr) + 
							fragment->optlen * sizeof(uint32_t);

	// 1 ethhdr
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->d_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
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


struct rte_mbuf * ng_tcp_pkt(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip,
	uint8_t *srcmac, uint8_t *dstmac, struct ng_tcp_fragment *fragment) {

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

	ng_encode_tcp_apppkt(pktdata, sip, dip, srcmac, dstmac, fragment);

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
		for (i = 0;i < nready;i ++) {
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

//非epoll的实现
/* static int tcp_server_entry(__attribute__((unused))  void *arg)  {

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

	while (1) {
		
		struct sockaddr_in client;
		socklen_t len = sizeof(client);
		int connfd = naccept(listenfd, (struct sockaddr*)&client, &len);

		char buff[BUFFER_SIZE] = {0};
		while (1) {

			int n = nrecv(connfd, buff, BUFFER_SIZE, 0); //block
			if (n > 0) {
				printf("recv: %s\n", buff);
				nsend(connfd, buff, n, 0);

			} else if (n == 0) {

				nclose(connfd);
				break;
			} else { //nonblock

			}
		}

	}
	nclose(listenfd);
} */