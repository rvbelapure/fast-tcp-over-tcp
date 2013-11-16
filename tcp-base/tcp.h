#ifndef __GTTCP_H
#define __GTTCP_H

#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>


#define SYN_FLAG 1
#define ACK_FLAG 2
#define FIN_FLAG 4

int gt_listen(int sockfd, int backlog);
int gt_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int gt_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int gt_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
ssize_t gt_send(int sockfd, const void *buf, size_t len, int flags);
size_t gt_recv(int sockfd, void *buf, size_t len, int flags);
int gt_close(int sockfd);

typedef struct _tcp_packet 
{
	void *ubuf;
	size_t ulen;
	int uflags;
	uint32_t gt_flags;
}tcp_packet_t;

#endif
