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

uint32_t CCgen = 1;
cc_cache_t cache;

//#ifdef __SERVER
int *addr_list;
//#endif

pthread_mutex_t ccgen_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t addr_list_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_rwlock_t half_synchronized_rwlock = PTHREAD_RWLOCK_INITIALIZER;

void gt_init(){

	printf("gt_init starting\n");
//#ifdef __SERVER	
	cache.CC = (uint32_t *)calloc(MAX_PEERS, sizeof(uint32_t));
	cache.CCsent = (uint32_t *)calloc(MAX_PEERS, sizeof(uint32_t));
	addr_list = (int *)calloc(MAX_PEERS, sizeof(int));
//#endif
	printf("gt_init done\n");

//#ifdef __CLIENT	
//	cache.CC = (uint32_t *)calloc(1, sizeof(uint32_t));
//	cache.CCsent = (uint32_t *)calloc(1, sizeof(uint32_t));
//#endif

}

sock_descriptor_t * gt_socket(int domain, int type, int protocol)
{
	sock_descriptor_t * sockfd = (sock_descriptor_t *) malloc(sizeof(sock_descriptor_t));
	sockfd->sockfd = socket(domain, type, protocol);
	sockfd->data = NULL;
	sockfd->offset = 0;
	sockfd->length = 0;

//Added for T/TCP
	//sockfd->CCrecv = 0;
	//sockfd->CCsend = 0;

	return sockfd;
}

int gt_listen(sock_descriptor_t *sockfd, int backlog) {
	return listen(sockfd->sockfd, backlog);
}
int gt_bind(sock_descriptor_t *sockfd, const struct sockaddr *addr, socklen_t addrlen) 
{
	return bind(sockfd->sockfd, addr, addrlen);
}

int gt_connect(sock_descriptor_t *sockfd, const struct sockaddr *addr, socklen_t addrlen, 
			/*const void *buf, ssize_t ulen, int flags*/
			unsigned long *cookie, char * udata, ssize_t ulen) { /*cookie is unused for T/TCP*/
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
	struct sockaddr_in *sa = (struct sockaddr_in *) &addr;

	/* T/TCP stuff */
	uint32_t CCnumber;
	CCnumber = cc_gen();

	pthread_t hs_thread;
	thread_args_t *args = (thread_args_t *) calloc(1, sizeof(thread_args_t));
	args->app_tid = pthread_self();
	args->app_sockfd = sockfd;
	args->client_addr = (sa->sin_addr).s_addr;
	args->hs_sockfd = hs;
	args->cookie = cookie; /*cookie is unused for T/TCP*/
	args->CCnumber = CCnumber;
	args->ulen = ulen;
	args->udata = (char *) malloc(ulen * sizeof(char));
	memcpy(args->udata, udata, ulen);
	pthread_create(&hs_thread, NULL, gt_connect_handshake_thread, args);

	sockfd->CCnumber = CCnumber; //Added for T/TCP
	//New connections are always half-synchronized (assuming only T/TCP applications would be run)
	sockfd->half_synchronized_flag = 1; //Added for T/TCP

	return 0;

}


sock_descriptor_t * gt_accept(sock_descriptor_t *sockfd, struct sockaddr *addr, socklen_t *addrlen, void *app_func, server_app_args_t *server_app_args) 
{
	sock_descriptor_t * app_sockfd = (sock_descriptor_t *) malloc(sizeof(sock_descriptor_t));
	app_sockfd->sockfd = accept(sockfd->sockfd, addr, addrlen);
	app_sockfd->data = NULL;
	app_sockfd->offset = 0;
	app_sockfd->length = 0;
	//New connections are always half-synchronized (assuming only T/TCP applications would be run)
	app_sockfd->half_synchronized_flag = 1;

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

	server_app_args->tfo_aware_flag = 0; //Should be 0 for TTCP?
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
#ifdef __CLIENT
	pthread_rwlock_rdlock(&half_synchronized_rwlock);
	if(sockfd->half_synchronized_flag){
		cc_options_t cc_options;
		cc_options.cc = CC;
		cc_options.seg_cc = sockfd->CCnumber;
		send_pkt->cc_options = cc_options;
	}
	pthread_rwlock_unlock(&half_synchronized_rwlock);
#endif	
	return gt_send_size(sockfd->sockfd,send_pkt);
}

ssize_t gt_recv(sock_descriptor_t *sockfd, void *buf, size_t len, int flags) {
	if(sockfd == NULL)
		return -1;	
	/* check if we have anything to return from buffer */
	ssize_t available = sockfd->length - sockfd->offset;
	if(available <= 0)
	{
		/* we don't have any data in the buffer. 
		 * So we get the data, put it in buffer and return the required amount */
		tcp_packet_t *pkt = NULL;
		gt_recv_size(sockfd->sockfd, &pkt);
#ifdef __SERVER
		pthread_rwlock_rdlock(&half_synchronized_rwlock);
		if(sockfd->half_synchronized_flag){
			if((pkt->cc_options.cc != CC) || 
				((pkt->cc_options.cc == CC) && (pkt->cc_options.seg_cc != sockfd->CCnumber))){
				return 0;
			}	
		}
		pthread_rwlock_unlock(&half_synchronized_rwlock);
#endif			
		sockfd->data = (char *) malloc(pkt->ulen * sizeof(char));
		sockfd->length = pkt->ulen;
		sockfd->offset = 0;
		memcpy(sockfd->data, pkt->ubuf, pkt->ulen);
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
	syn_pkt->cookie = args->cookie; /*cookie is unused for T/TCP*/
	syn_pkt->uflags = 0;
	syn_pkt->gt_flags |= SYN_FLAG;
	//if(syn_pkt->cookie)	syn_pkt->gt_flags |= COOKIE_REQ_FLAG;
	//else			syn_pkt->gt_flags |= FAST_OPEN_FLAG;

	/* T/TCP stuff */
	uint32_t CCrecv = 0, CCsend;
	CCsend = args->CCnumber;/*cc_gen();*/

	uint32_t client_id = get_client_id(args->client_addr);
	cc_options_t cc_opt;
	if((cache.CCsent[client_id] == 0)/*Haven't talked to this server before*/ 
		|| (CCsend < cache.CCsent[client_id]) /*CCgen wrapped around due to too many transactions*/){
		cc_opt.cc = CC_NEW;
	} else {
		cc_opt.cc = CC;
	}
	cc_opt.seg_cc = CCsend;
	cache.CCsent[client_id] = CCsend;
	syn_pkt->cc_options = cc_opt;

	gt_send_size(args->hs_sockfd->sockfd, (void *)syn_pkt);
//SYN is sent at this point

	tcp_packet_t *syn_ack_pkt = NULL;
	gt_recv_size(args->hs_sockfd->sockfd, &syn_ack_pkt);
	if(! ((syn_ack_pkt->gt_flags & SYN_FLAG) && (syn_ack_pkt->gt_flags & ACK_FLAG)) && 
		(syn_ack_pkt->cc_echo_options.cc != CC_ECHO) && 
		((syn_ack_pkt->cc_echo_options.cc == CC_ECHO) && (syn_ack_pkt->cc_echo_options.seg_cc != CCsend)))
	{
		/* Failed handshake - close the connection(s) and die */
		gt_close(&args->app_sockfd);
		gt_close(&args->hs_sockfd);
		free(args);
		pthread_exit(NULL);
	}
	CCrecv = syn_ack_pkt->cc_options.seg_cc;

	//SYN, ACK is received at this point

	/* gt_flags in syn_ack_pkt may or may not have FAST_OPEN_FLAG depending on whether
	 * this is a Fast open or not */

	tcp_packet_t *ack_pkt = (tcp_packet_t *)calloc(1, sizeof(tcp_packet_t));
	ack_pkt->ubuf = NULL;
	ack_pkt->ulen = 0;
	ack_pkt->uflags = 0;
	ack_pkt->gt_flags |= ACK_FLAG;
	gt_send_size(args->hs_sockfd->sockfd, (void *)ack_pkt);

	pthread_rwlock_rdlock(&half_synchronized_rwlock);
	args->app_sockfd->half_synchronized_flag = 0;
	pthread_rwlock_unlock(&half_synchronized_rwlock);
		
	gt_close(args->hs_sockfd);

	/* handshake successful - die silently */
	free(args);
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
		pthread_exit(NULL);
	}

	/* Fill data to application arguments */
	hs_param->server_app_args->data = (char *) malloc(syn_pkt->ulen * sizeof(char));
	memcpy(hs_param->server_app_args->data, syn_pkt->ubuf, syn_pkt->ulen);
	hs_param->server_app_args->datalen = syn_pkt->ulen;	

	/* T/TCP stuff */
	uint32_t CCrecv = 0, CCsend;
	CCsend = cc_gen();
	hs_param->app_sockfd->CCnumber = CCsend;

	if((syn_pkt->cc_options.cc & CC) || (syn_pkt->cc_options.cc & CC_NEW)){
		CCrecv = syn_pkt->cc_options.seg_cc;
	}

	if(CCrecv != 0){ /*which would always be the case*/
		cc_options_t cc_opt, cc_echo_opt;

		cc_opt.cc = CC;
		cc_opt.seg_cc = CCsend;
		cc_echo_opt.cc = CC_ECHO;
		cc_echo_opt.seg_cc = CCrecv;
		syn_pkt->cc_options = cc_opt;
		syn_pkt->cc_echo_options = cc_echo_opt;
	}	

	pthread_t app_thread;
	int tao_test_ok = 0;
	uint32_t client_id = get_client_id(hs_param->client_addr);
	if((syn_pkt->cc_options.cc & CC) && (cache.CC[client_id] != 0) 
		&& (syn_pkt->cc_options.seg_cc > cache.CC[client_id])){

		//Server may talk to multiple clients
		//So server side CC cache will grow (pre-allocated in gt_init with MAX_PEERS which is very large)
		uint32_t client_id = get_client_id(hs_param->client_addr);

		/*TAO test OK*/
		tao_test_ok = 1;
		cache.CC[client_id] = CCrecv;
	
		//int err = token_verify(syn_pkt);
		//if return has error due to limit notify ???
		//if token failed would return work

		//how to keep data from syn_pkt in app_func_params ? TODO

		//start sending data in parallel swapn a send receive thread
		pthread_create(&app_thread, NULL, hs_param->app_func, hs_param->server_app_args);
	}

	//send syn-ack
	tcp_packet_t *syn_ack_pkt = (tcp_packet_t *)calloc(1, sizeof(tcp_packet_t));
	syn_ack_pkt->ubuf = NULL;
	syn_ack_pkt->ulen = 0;
	syn_ack_pkt->uflags = 0;
	syn_ack_pkt->gt_flags |= SYN_FLAG;
	syn_ack_pkt->gt_flags |= ACK_FLAG;
	gt_send_size(hs_param->hs_sockfd->sockfd, (void *)syn_ack_pkt);

	//recv ack packet
	tcp_packet_t *ack_pkt = NULL;
	gt_recv_size(hs_param->hs_sockfd->sockfd, &ack_pkt);
	if( ! (ack_pkt->gt_flags & ACK_FLAG) )
	{
		/* Handshake failure */
		if(tao_test_ok == 1)
			pthread_kill(app_thread, SIGUSR1);
		gt_close(hs_param->hs_sockfd);
		free(hs_param);
		pthread_exit(NULL);
	}

	/*Normal TCP processing if TAO test had failed*/
	if(tao_test_ok == 0){
		pthread_t app_thread;

		//start sending data in parallel swapn a send receive thread
		pthread_create(&app_thread, NULL, hs_param->app_func, hs_param->server_app_args);
	}
	
	//would assert fail means handshake failed ???
	//have to send signal to the app_thread in failed case and then continue

	pthread_rwlock_rdlock(&half_synchronized_rwlock);
	hs_param->app_sockfd->half_synchronized_flag = 0;
	pthread_rwlock_unlock(&half_synchronized_rwlock);	

	gt_close(hs_param->hs_sockfd);

	//malloc cleanup
	free(hs_param);
	pthread_exit(NULL); // all good handshake is sucessful
}

uint32_t cc_gen(){
	pthread_mutex_lock(&ccgen_mutex);
	if(CCgen == MAX_UINT_32)
		CCgen = 1;
	else 
		CCgen++;
	pthread_mutex_unlock(&ccgen_mutex);
	return CCgen;
}

uint32_t get_client_id(unsigned long addr){
	int addr_found = 0;
	int i;
	pthread_mutex_lock(&addr_list_mutex);
	for(i=0; i<MAX_PEERS; i++){
		//break on finding the addr in addr_list
		if(addr_list[i] == addr){
			addr_found = 1;
			break;
		}
		//Or, break on finding the end of the addr_list
		if(addr_list[i] == 0){
			break;
		}
	}
	if((i == MAX_PEERS) && (addr_found == 0))
		return -1; //This should never happen; MAX_PEERS should be large enough to never run out of available space
	if(addr_found == 0)
		addr_list[i] = addr;
	pthread_mutex_unlock(&addr_list_mutex);
	return i;
}

