#ifndef __GTTCP_H
#define __GTTCP_H

#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>

#define SYN_FLAG 1
#define ACK_FLAG 2
#define FIN_FLAG 4
#define COOKIE_REQ_FLAG 8
#define FAST_OPEN_FLAG 16

#define MAX_PEERS 100

typedef enum
{
	CC,
	CC_NEW,
	CC_ECHO,
	NO_CC
} cc_flag_t;

typedef struct  _cc_cache
{
	uint32_t *CC;
	uint32_t *CCsent;
}cc_cache_t;

typedef struct _cc_options
{
	cc_flag_t cc;
	uint32_t seg_cc;
}cc_options_t;

typedef struct _tcp_packet 
{
	char *ubuf;
	size_t ulen;
	int uflags;
	uint32_t gt_flags;
	unsigned long cookie; //unused for T/TCP
	cc_options_t cc_options; //Added for T/TCP
	cc_options_t cc_echo_options; //Added for T/TCP

}tcp_packet_t;

typedef struct _sock_descriptor
{
	int sockfd;
	char *data;
	ssize_t offset;
	ssize_t length;
	uint32_t CCnumber; //Used for T/TCP
	int half_synchronized_flag; //Used for T/TCP
}sock_descriptor_t;

typedef struct _server_app_args
{
	char *data;
	ssize_t datalen;
	int  tfo_aware_flag; //Unused for T/TCP
	sock_descriptor_t *app_sockfd;
	void *app_func_params;
}server_app_args_t;

typedef struct _thread_args
{
	pid_t app_tid;
	sock_descriptor_t *app_sockfd;
	sock_descriptor_t *hs_sockfd;
	unsigned long client_addr; //Used for T/TCP to index into cache	
	unsigned long *cookie; //Unused for T/TCP
	uint32_t CCnumber; //Used for T/TCP
	char *udata;
	ssize_t ulen;
	void *app_func;
	server_app_args_t *server_app_args;	
}thread_args_t;

void gt_init();
sock_descriptor_t * gt_socket(int domain, int type, int protocol);
int gt_listen(sock_descriptor_t * sockfd, int backlog);
int gt_bind(sock_descriptor_t * sockfd, const struct sockaddr *addr, socklen_t addrlen);
int gt_connect(sock_descriptor_t *sockfd, const struct sockaddr *addr, socklen_t addrlen, 
	unsigned long *cookie, char * udata, ssize_t ulen);
sock_descriptor_t *gt_accept(sock_descriptor_t * sockfd, struct sockaddr *addr, socklen_t *addrlen, 
	void *app_func, server_app_args_t *server_app_args);
ssize_t gt_send(sock_descriptor_t * sockfd, const void *buf, size_t len, int flags);
ssize_t gt_recv(sock_descriptor_t * sockfd, void *buf, size_t len, int flags);
int gt_close(sock_descriptor_t * sockfd);

void * gt_connect_handshake_thread(void * arguments);
void * gt_accept_handshake_thread(void * arguments);

uint32_t cc_gen();
uint32_t get_client_id(unsigned long sockfd);
#endif
