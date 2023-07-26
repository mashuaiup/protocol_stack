#ifndef __SOCKET__
#define __SOCKET__
#include <arpa/inet.h>
#include "std.h"
extern unsigned char fd_table[MAX_FD_COUNT];
extern struct localhost  *lhost;
int nsocket(__attribute__((unused)) int domain, int type, __attribute__((unused))  int protocol);
int nbind(int sockfd, const struct sockaddr *addr,
                __attribute__((unused))  socklen_t addrlen);
int nlisten(int sockfd, __attribute__((unused)) int backlog);
int naccept(int sockfd, struct sockaddr *addr, __attribute__((unused)) socklen_t *addrlen);
ssize_t nsend(int sockfd, const void *buf, size_t len,__attribute__((unused)) int flags);
ssize_t nrecv(int sockfd, void *buf, size_t len, __attribute__((unused)) int flags);
ssize_t nrecvfrom(int sockfd, void *buf, size_t len, __attribute__((unused))  int flags,
                        struct sockaddr *src_addr, __attribute__((unused))  socklen_t *addrlen);
ssize_t nsendto(int sockfd, const void *buf, size_t len, __attribute__((unused))  int flags,
                      const struct sockaddr *dest_addr, __attribute__((unused))  socklen_t addrlen);
int nclose(int fd);

#endif

