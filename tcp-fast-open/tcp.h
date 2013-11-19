#ifndef __GTTCP_H
#define __GTTCP_H

#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>

#define SYN_FLAG 1
#define ACK_FLAG 2
#define FIN_FLAG 4

typedef struct _tcp_packet 
{
	char *ubuf;
	size_t ulen;
	int uflags;
	uint32_t gt_flags;
}tcp_packet_t;

typedef struct _sock_descriptor
{
	int sockfd;
	char *data;
	ssize_t offset;
	ssize_t length;
}sock_descriptor_t;

sock_descriptor_t * gt_socket(int domain, int type, int protocol);
int gt_listen(sock_descriptor_t * sockfd, int backlog);
int gt_bind(sock_descriptor_t * sockfd, const struct sockaddr *addr, socklen_t addrlen);
int gt_connect(sock_descriptor_t * sockfd, const struct sockaddr *addr, socklen_t addrlen);
sock_descriptor_t *gt_accept(sock_descriptor_t * sockfd, struct sockaddr *addr, socklen_t *addrlen);
ssize_t gt_send(sock_descriptor_t * sockfd, const void *buf, size_t len, int flags);
ssize_t gt_recv(sock_descriptor_t * sockfd, void *buf, size_t len, int flags);
int gt_close(sock_descriptor_t * sockfd);

#endif
