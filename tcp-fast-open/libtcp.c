#include <sys/types.h>
#include <sys/socket.h>
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <netdb.h>
#include <netinet/in.h>
#include <limits.h>

#include "tcp.h"
#include "tcputils.h"

pthread_rwlock_t connect_cookie_rwlock = PTHREAD_RWLOCK_INITIALIZER;
pthread_rwlock_t server_key_rwlock = PTHREAD_RWLOCK_INITIALIZER;
pthread_mutex_t server_tfo_threshold_mutex = PTHREAD_MUTEX_INITIALIZER;

unsigned long key;
unsigned long active_tfo_connections;

void gt_init()
{
	pthread_t t;
	active_tfo_connections = 0;
	key = 0;
	while(key != 0)
		key = (unsigned long) random();
	pthread_create(&t, NULL, key_updater, NULL);
}

sock_descriptor_t * gt_socket(int domain, int type, int protocol)
{
	/* Allocate new socket descriptor. create a socket and return the descriptor */
	sock_descriptor_t * sockfd = (sock_descriptor_t *) malloc(sizeof(sock_descriptor_t));
	sockfd->sockfd = socket(domain, type, protocol);
	sockfd->data = NULL;
	sockfd->offset = 0;
	sockfd->length = 0;
	return sockfd;
}

int gt_listen(sock_descriptor_t *sockfd, int backlog) {
	return listen(sockfd->sockfd, backlog);
}
int gt_bind(sock_descriptor_t *sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	return bind(sockfd->sockfd, addr, addrlen);
}
int gt_connect(sock_descriptor_t *sockfd, const struct sockaddr *addr, socklen_t addrlen, 
						unsigned long *cookie, char * udata, ssize_t ulen) {
	/* Create connection to socket owned by application thread of server.
	 * This socket will be returned to client application.*/
	int sockfd_conn = sockfd->sockfd;
	int err = connect(sockfd_conn, addr, addrlen);
	if(err)
		return err;
	
	/* Create another connection with the socket owned by handshake thread of server.
	 * This is for internal use only and will not be exposed to client app. */
	sock_descriptor_t *hs = gt_socket(AF_INET, SOCK_STREAM, 0);
	while(connect(hs->sockfd, addr, addrlen) != 0);

	/* Fork the handshake thread on connect side. Pass on the cookie, data and socket to the
	 * handshake thread along with pid of main thread to communicate back (via signaling)  */
	pthread_t hs_thread;
	thread_args_t *args = (thread_args_t *) calloc(1, sizeof(thread_args_t));
	args->app_tid = pthread_self();
	args->app_sockfd = sockfd;
	args->hs_sockfd = hs;
	pthread_rwlock_rdlock(&connect_cookie_rwlock);
	args->cookie = cookie;
	pthread_rwlock_unlock(&connect_cookie_rwlock);
	args->ulen = ulen;
	args->udata = (char *) malloc(ulen * sizeof(char));
	memcpy(args->udata, udata, ulen);
	pthread_create(&hs_thread, NULL, gt_connect_handshake_thread, args);
	return 0;
}

int gt_accept(sock_descriptor_t *sockfd, struct sockaddr *addr, socklen_t *addrlen, void *app_func, server_app_args_t *server_app_args) 
{
	sock_descriptor_t * app_sockfd = (sock_descriptor_t *) malloc(sizeof(sock_descriptor_t));
	app_sockfd->sockfd = accept(sockfd->sockfd, addr, addrlen);
	app_sockfd->data = NULL;
	app_sockfd->offset = 0;
	app_sockfd->length = 0;

	if(app_sockfd->sockfd < 0)
		return 1;

	sock_descriptor_t * hs_sockfd = (sock_descriptor_t *) malloc(sizeof(sock_descriptor_t));
	hs_sockfd->sockfd = accept(sockfd->sockfd, addr, addrlen);
	hs_sockfd->data = NULL;
	hs_sockfd->offset = 0;
	hs_sockfd->length = 0;

	if(hs_sockfd->sockfd < 0)
		return 1;

	struct sockaddr_in *sa = (struct sockaddr_in *) &addr;

	server_app_args->tfo_aware_flag = 1;
	server_app_args->app_sockfd = app_sockfd;
	//Thread data set
	thread_args_t *hs_params = (thread_args_t *) malloc(sizeof(thread_args_t));
	hs_params->hs_sockfd = hs_sockfd;
	hs_params->app_sockfd = app_sockfd;
	hs_params->client_addr = (sa->sin_addr).s_addr;
	hs_params->app_func = app_func;
	hs_params->server_app_args = server_app_args;

	pthread_t handshake_thread;

	pthread_create(&handshake_thread, NULL, gt_accept_handshake_thread, hs_params);
	return 0;
}

ssize_t gt_send(sock_descriptor_t *sockfd, const void *buf, size_t len, int flags) {
	if(sockfd == NULL)
		return -1;
	tcp_packet_t *send_pkt = (tcp_packet_t *) calloc(1, sizeof(tcp_packet_t));
	send_pkt->ubuf = (char *) malloc(len * sizeof(char));
	memcpy(send_pkt->ubuf, buf, len);
	send_pkt->ulen = len;
	send_pkt->uflags = flags;
	send_pkt->gt_flags = 0;
	ssize_t ret = gt_send_size(sockfd->sockfd,send_pkt);
	free(send_pkt);
	return ret;
}

ssize_t gt_recv(sock_descriptor_t *sockfd, void *buf, size_t len, int flags) {
	if(sockfd == NULL)
		return -1;
	/* check if we have anything to return from buffer */
	ssize_t available = sockfd->length - sockfd->offset;
	ssize_t retval;
	if(available <= 0)
	{
		/* we don't have any data in the buffer. 
		 * So we get the data, put it in buffer and return the required amount */
		tcp_packet_t *pkt = NULL;
		retval = gt_recv_size(sockfd->sockfd, &pkt);
		sockfd->data = (char *) malloc(pkt->ulen * sizeof(char));
		sockfd->length = pkt->ulen;
		sockfd->offset = 0;
		memcpy(sockfd->data, pkt->ubuf, pkt->ulen);
		if(retval <= 0)
		{
			free(sockfd->data);
			sockfd->data = NULL;
			sockfd->offset = 0;
			sockfd->length = 0;
			return retval;
		}
	}

	/* we can return something from the buffer now.*/
	available = sockfd->length - sockfd->offset;
	ssize_t response_size = (available <= len) ? available : len;      // min(available, request);
	char *data = NULL;
	if(response_size > 0)
	{
		memcpy(buf, sockfd->data + sockfd->offset, response_size);
		sockfd->offset += response_size;
		if(sockfd->offset >= sockfd->length)
		{
			free(sockfd->data);
			sockfd->data = NULL;
			sockfd->offset = 0;
			sockfd->length = 0;
		}
	}

	return response_size;
}

int gt_close(sock_descriptor_t *sockfd) 
{
	/* Dummy close implementation for now to get things working.
	 * TODO : Implement connection teardown FSM here */
	if((sockfd->length - sockfd->offset > 0) && (sockfd->data))
	{
		free(sockfd->data);
		sockfd->length = 0;
		sockfd->offset = 0;
	}
	return close(sockfd->sockfd);
}


void * gt_connect_handshake_thread(void * arguments)
{
	thread_args_t * args = (thread_args_t *) arguments;

	tcp_packet_t *syn_pkt = (tcp_packet_t *)calloc(1, sizeof(tcp_packet_t));
	syn_pkt->ulen = args->ulen;
	syn_pkt->ubuf = (char *) malloc(args->ulen * sizeof(char));
	memcpy(syn_pkt->ubuf, args->udata, args->ulen);	
	syn_pkt->uflags = 0;
	syn_pkt->gt_flags |= SYN_FLAG;
	pthread_rwlock_rdlock(&connect_cookie_rwlock);
	syn_pkt->cookie = *args->cookie;
	unsigned long c = syn_pkt->cookie;
	pthread_rwlock_unlock(&connect_cookie_rwlock);
	if(c == 0)	syn_pkt->gt_flags |= COOKIE_REQUEST_FLAG;
	else		syn_pkt->gt_flags |= FAST_OPEN_FLAG;
	gt_send_size(args->hs_sockfd->sockfd, (void *)syn_pkt);
//SYN is sent at this point

	tcp_packet_t *syn_ack_pkt = NULL;
	gt_recv_size(args->hs_sockfd->sockfd, &syn_ack_pkt);
	if(! ((syn_ack_pkt->gt_flags & SYN_FLAG) && (syn_ack_pkt->gt_flags & ACK_FLAG)) )
	{
		/* Failed handshake - close the connection(s) and die */
		gt_close(args->app_sockfd);
		gt_close(args->hs_sockfd);
		free(args);
		free(syn_pkt);
		free(syn_ack_pkt);
		pthread_exit(NULL);
	}
	//SYN, ACK is received at this point

	/* gt_flags in syn_ack_pkt may or may not have FAST_OPEN_FLAG depending on whether
	 * this is a Fast open or not. Got cookie here if COOKIE_REQ_FLAG was set */
	if(syn_ack_pkt->gt_flags & COOKIE_GENERATED_FLAG)
	{
		pthread_rwlock_wrlock(&connect_cookie_rwlock);
		*(args->cookie) = syn_ack_pkt->cookie;
		pthread_rwlock_unlock(&connect_cookie_rwlock);
	}
	else if(syn_ack_pkt->gt_flags & COOKIE_INVALID_FLAG)
	{
		pthread_rwlock_wrlock(&connect_cookie_rwlock);
		*(args->cookie) = 0;
		pthread_rwlock_unlock(&connect_cookie_rwlock);
	}

	tcp_packet_t *ack_pkt = (tcp_packet_t *)calloc(1, sizeof(tcp_packet_t));
	ack_pkt->ubuf = NULL;
	ack_pkt->ulen = 0;
	ack_pkt->uflags = 0;
	ack_pkt->gt_flags |= ACK_FLAG;
	gt_send_size(args->hs_sockfd->sockfd, (void *)ack_pkt);
	gt_close(args->hs_sockfd);

	/* handshake successful - die silently */
	free(args);
	free(syn_pkt);
	free(syn_ack_pkt);
	free(ack_pkt);
	pthread_exit(NULL);
}


void * gt_accept_handshake_thread(void *arguments){
	thread_args_t *hs_param = (thread_args_t *) arguments;

	//recv syn + data packet
	tcp_packet_t *syn_pkt = NULL;
	gt_recv_size(hs_param->hs_sockfd->sockfd, &syn_pkt);
	if( ! (syn_pkt->gt_flags & SYN_FLAG) )
	{
		/* Failed handshake - close the connection(s) and die */
		gt_close(hs_param->app_sockfd);
		gt_close(hs_param->hs_sockfd);
		free(hs_param);
		free(syn_pkt);
		pthread_exit(NULL);
	}

	/* Fill data to application arguments */
	hs_param->server_app_args->data = (char *) malloc(syn_pkt->ulen * sizeof(char));
	memcpy(hs_param->server_app_args->data, syn_pkt->ubuf, syn_pkt->ulen);
	hs_param->server_app_args->datalen = syn_pkt->ulen;
	
	/* SYN + Data + Cookie packet received */
	pthread_t app_thread;
	uint32_t cookie_flags = 0; 
	unsigned long generated_cookie = 0;
	if( syn_pkt->gt_flags & FAST_OPEN_FLAG)
	{
		/* Case : When client sends cookie + data and requests fast open */
		int status = cookie_verify(syn_pkt->cookie, hs_param->client_addr);
		if(status > 0)
		{
			/* Server accepted the cookie */
			pthread_create(&app_thread, NULL, hs_param->app_func, hs_param->server_app_args);
			cookie_flags |= COOKIE_APPROVED_FLAG;
		}
		else if(status == 0)
		{
			/* Cookie valid but rejected due to too many open connections */
			cookie_flags |= COOKIE_REJECT_FLAG;
		}
		else
		{
			/* cookie invalid */
			cookie_flags |= COOKIE_INVALID_FLAG;
		}

	}
	else if( syn_pkt->gt_flags & COOKIE_REQUEST_FLAG )
	{
		/* Cookie generation request */
		generated_cookie = cookie_gen(hs_param->client_addr);
		if(generated_cookie == 0)
		{
			/* Fast open threshold reached. Cookie rejected */
			cookie_flags |= COOKIE_REJECT_FLAG;
		}
		else
		{
			/* Server generated a new cookie */
			cookie_flags |= COOKIE_GENERATED_FLAG;
		}
	}


	//start sending data in parallel swapn a send receive thread

	//send syn-ack 
	tcp_packet_t *syn_ack_pkt = (tcp_packet_t *)calloc(1, sizeof(tcp_packet_t));
	syn_ack_pkt->ubuf = NULL;
	syn_ack_pkt->ulen = 0;
	syn_ack_pkt->uflags = 0;
	syn_ack_pkt->gt_flags |= SYN_FLAG;
	syn_ack_pkt->gt_flags |= ACK_FLAG;
	syn_ack_pkt->gt_flags |= cookie_flags;
	if(cookie_flags & COOKIE_GENERATED_FLAG) syn_ack_pkt->cookie = generated_cookie;
	gt_send_size(hs_param->hs_sockfd->sockfd, (void *)syn_ack_pkt);

	//recv ack packet
	tcp_packet_t *ack_pkt = NULL;
	gt_recv_size(hs_param->hs_sockfd->sockfd, &ack_pkt);
	if( ! (ack_pkt->gt_flags & ACK_FLAG) )
	{
		/* Handshake failure */
		if(cookie_flags & COOKIE_APPROVED_FLAG)
			pthread_kill(app_thread, SIGUSR1);
		gt_close(hs_param->hs_sockfd);
		free(hs_param);
		free(syn_pkt);
		free(syn_ack_pkt);
		free(ack_pkt);
		pthread_exit(NULL);
	}

	if( ! ((syn_pkt->gt_flags & COOKIE_REQUEST_FLAG) && (syn_pkt->gt_flags & FAST_OPEN_FLAG)) )
		hs_param->server_app_args->tfo_aware_flag = 0;

	if( ! (cookie_flags & COOKIE_APPROVED_FLAG))
		pthread_create(&app_thread, NULL, hs_param->app_func, hs_param->server_app_args);

	gt_close(hs_param->hs_sockfd);

	if(cookie_flags & COOKIE_APPROVED_FLAG)
	{
		pthread_mutex_lock(&server_tfo_threshold_mutex);
		active_tfo_connections--;
		pthread_mutex_unlock(&server_tfo_threshold_mutex);
	}

	//malloc cleanup
	free(hs_param);
	free(syn_pkt);
	free(syn_ack_pkt);
	free(ack_pkt);
	pthread_exit(NULL);

}

void * key_updater(void *t)
{
	while(1)
	{
		sleep(COOKIE_EXPIRY_TIMEOUT);
		pthread_rwlock_wrlock(&server_key_rwlock);
		key = (unsigned long) random();
		while((key == 0) || (key == LONG_MAX)) key = (unsigned long) random();
		pthread_rwlock_unlock(&server_key_rwlock);
	}
}

int cookie_verify(unsigned long cookie, unsigned long addr)
{
	/* returns -1 when cookie is invalid, 0 when too many active TFO connections
	   and 1 when cookie is accepted */

	/* first determine if the cookie is valid */
	pthread_rwlock_rdlock(&server_key_rwlock);
	if(cookie != (key ^ addr))
	{
		pthread_rwlock_unlock(&server_key_rwlock);
		return -1;
	}

	/* now check if we are under ACTIVE_TFO_THRESHOLD */
	pthread_mutex_lock(&server_tfo_threshold_mutex);
	if(active_tfo_connections > ACTIVE_TFO_THRESHOLD)
	{
		pthread_mutex_unlock(&server_tfo_threshold_mutex);
		pthread_rwlock_unlock(&server_key_rwlock);
		return 0;
	}

	active_tfo_connections++;	/* safety check : we have lock on server_tfo_threshold_mutex */
	/* it is implicit that we have recognized validity of TFO connection here */
	pthread_mutex_unlock(&server_tfo_threshold_mutex);
	pthread_rwlock_unlock(&server_key_rwlock);

	return 1;
}

unsigned long cookie_gen(unsigned long addr)
{
	/* We give out cookies without much heed to ACTIVE_TFO_THRESHOLD. 
	 * If there is sudden surge of connections due to high number of cookies
	 * after this, they will be filtered by cookie verification function.
	 * Thus, we generate the cookie safely */
	unsigned long cookie = 0;
	pthread_rwlock_rdlock(&server_key_rwlock);
	cookie = key ^ addr;
	pthread_rwlock_unlock(&server_key_rwlock);
	assert(cookie != 0);	/* XXX if this happens frequently, then change the encryption function */
	return cookie;		/* except for rare case where key == addr, cookie will be always non-zero */
}

