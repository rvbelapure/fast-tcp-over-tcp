#ifndef __GTTCP_H
#define __GTTCP_H

#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <unistd.h>

#define SYN_FLAG 		1	/* SYN packet */
#define ACK_FLAG 		2	/* ACK packet */
#define FIN_FLAG 		4	/* FIN packet */
#define COOKIE_REQUEST_FLAG 	8	/* Client requesting new cookie */
#define COOKIE_GENERATED_FLAG 	16	/* Server generated and returned cookie */
#define COOKIE_REJECT_FLAG 	32	/* Server rejected cookie / server rejected cookie generation */
#define COOKIE_APPROVED_FLAG 	64	/* Server accepted client cookie */
#define FAST_OPEN_FLAG		128	/* Client is sending cookie to request fast open */

#define COOKIE_EXPIRY_TIMEOUT	300	/* Timeout in seconds */
#define ACTIVE_TFO_THRESHOLD	50	/* Number of concurrent connections that can be in TFO phase at same time */

typedef struct _tcp_packet 
{
	char *ubuf;
	size_t ulen;
	int uflags;
	uint32_t gt_flags;
	unsigned long cookie;
}tcp_packet_t;

typedef struct _sock_descriptor
{
	int sockfd;
	char *data;
	ssize_t offset;
	ssize_t length;
}sock_descriptor_t;

typedef struct _server_app_args
{
	char *data;
	ssize_t datalen;
	int  tfo_aware_flag;
	void *app_func_params;
}server_app_args_t;

typedef struct _thread_args
{
	pid_t app_tid;
	sock_descriptor_t *app_sockfd;
	sock_descriptor_t *hs_sockfd;
	unsigned long *cookie;
	char *udata;
	ssize_t ulen;	
	void *app_func;
	server_app_args_t *server_app_args;
}thread_args_t;

void gt_init();
sock_descriptor_t * gt_socket(int domain, int type, int protocol);
int gt_listen(sock_descriptor_t * sockfd, int backlog);
int gt_bind(sock_descriptor_t * sockfd, const struct sockaddr *addr, socklen_t addrlen);
int gt_connect(sock_descriptor_t *sockfd, const struct sockaddr *addr, socklen_t addrlen, unsigned long *cookie, char * udata, ssize_t ulen);
int gt_accept(sock_descriptor_t *sockfd, struct sockaddr *addr, socklen_t *addrlen, void *app_func, server_app_args_t *server_app_args);
ssize_t gt_send(sock_descriptor_t * sockfd, const void *buf, size_t len, int flags);
ssize_t gt_recv(sock_descriptor_t * sockfd, void *buf, size_t len, int flags);
int gt_close(sock_descriptor_t * sockfd);

void * gt_connect_handshake_thread(void * arguments);
void * gt_accept_handshake_thread(void * arguments);

int cookie_verify(tcp_packet_t *syn_pkt);
unsigned long cookie_gen(tcp_packet_t *syn_pkt);
void * key_updater(void *t);

#endif
