#include<tcp.h>

void ng_encode_tcp_pkt(uint8_t * pkt, tcp_stream *tcp_stream_item, struct rte_ether_hdr *ethdr_received){
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

static  tcp_stream_table* get_stream_table_instance(void){
	if(!stream_table){
		stream_table = rte_malloc("stream_table", sizeof(tcp_stream_table), 0);
		if(stream_table==NULL){
			rte_exit(EXIT_FAILURE, "rte_malloc error!");
		}
		memset(stream_table, 0 ,sizeof(tcp_stream_table));
	}
	return stream_table;
}

static tcp_stream * query_stream(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport){
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
	stream->status = NG_TCP_TCP_STATUS_LISTEN;
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
		tcp_stream_item->status = NG_TCP_TCP_STATUS_SYN_RECEIVED;		
	}
	return 0;
}

static void handle_syn_received(tcp_stream *tcp_stream_item,struct rte_tcp_hdr *tcphdr){
	if(tcphdr->tcp_flags == RTE_TCP_SYN_FLAG){
		printf("再次收到请求报文,连接失败\n");
	}else{
		printf("连接成功\n");
	}
	tcp_stream_item->status = NG_TCP_TCP_STATUS_ESTABLISHED;
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
	case NG_TCP_TCP_STATUS_CLOSED:
		break;
	case NG_TCP_TCP_STATUS_LISTEN:
		handle_listen(tcp_stream_item, mbuf_pool, ehdr, iphdr, tcphdr);//解包，发包
		break;
	case NG_TCP_TCP_STATUS_SYN_RECEIVED:
		handle_syn_received(tcp_stream_item,tcphdr);//解包，发包
		break;
	default:
		break;
	}
	rte_pktmbuf_free(mbuf);	
}