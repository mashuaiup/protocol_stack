#ifndef __EPOLL__
#define __EPOLL__
#include <sys/queue.h>
#include <time.h>
#include "std.h"
#include <errno.h>
#include <rte_errno.h>
#define CLOCK_REALTIME			0
extern unsigned char fd_table[MAX_FD_COUNT];




int sockfd_cmp(struct epitem *ep1, struct epitem *ep2);
int epoll_event_callback(struct eventpoll *ep, int sockid, uint32_t event);
/* int nepoll_create(int size);
int nepoll_ctl(int epfd, int op, int sockid, struct epoll_event *event);
int nepoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout); */
#endif
