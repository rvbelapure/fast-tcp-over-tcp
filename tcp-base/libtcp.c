#include <sys/types.h>
#include <sys/socket.h>
#include <assert.h>
#include <stdint.h>
#include "tcp.h"
#include "tcputils.h"

int gt_listen(int sockfd, int backlog) {
	int ret;
	ret = listen(sockfd, backlog);
	return ret;
}
int gt_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) 
{
	int ret;
	ret = bind(sockfd, addr, addrlen);
	return ret;
}
int gt_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {

	int sockfd_conn = connect(sockfd, addr, addrlen);

	tcp_packet_t *syn_pkt = (tcp_packet_t *)malloc(sizeof(tcp_packet_t));
	syn_pkt->ubuf = NULL;
	syn_pkt->ulen = 0;
	syn_pkt->uflags = 0;
	syn_pkt->gt_flags = SYN_FLAG;
	gt_send_size(sockfd_conn, (const void *)syn_pkt);
//SYN is sent at this point

	tcp_packet_t syn_ack_pkt = NULL;
	gt_recv_size(sockfd_conn, syn_ack_pkt);
	assert(syn_ack_pkt->gt_flags & (SYN_FLAG & ACK_FLAG) == 1);
//SYN, ACK is received at this point

	tcp_packet_t *ack_pkt = (tcp_packet_t *)malloc(sizeof(tcp_packet_t));
	ack_pkt->ubuf = NULL;
	ack_pkt->ulen = 0;
	ack_pkt->uflags = 0;
	ack_pkt->gt_flags = ACK_FLAG;
	gt_send_size(sockfd_conn, (const void *)ack_pkt);
}

int gt_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) 
{
	int new_sockid = accept(sockfd, addr, addrlen);
}

ssize_t gt_send(int sockfd, const void *buf, size_t len, int flags) {
	ssize_t ret;
	ret = send(sockfd, buf, len, flags);
	return ret;
}

ssize_t gt_recv(int sockfd, void *buf, size_t len, int flags) {
	ssize_t ret;
	ret = recv(sockfd, buf, len, flags);
	return ret;
}

int gt_close(int sockfd) {}
