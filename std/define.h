#ifndef __DEFINE__
#define __DEFINE__
#ifndef NULL
#define NULL ((void *)0)
#endif
#define NUM_MBUFS                      (4096-1)
#define BURST_SIZE	                   32
#define RING_SIZE	                   1024
#define MAKE_IPV4_ADDR(a, b, c, d)     (a + (b<<8) + (c<<16) + (d<<24))//转换成网络字节序
#define TIMER_RESOLUTION_CYCLES        120000000000ULL // 10ms * 1000 = 10s * 6 
#define DEFAULT_FD_NUM	               3
#define MAX_FD_COUNT	               1024
#define UDP_APP_RECV_BUFFER_SIZE	   128
#define TCP_OPTION_LENGTH	10
#define TCP_INITIAL_WINDOW  14600
#define EPOLL_CTL_ADD	1
#define EPOLL_CTL_DEL	2
#define EPOLL_CTL_MOD	3
#endif