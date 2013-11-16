#include <sys/types.h>
#include <sys/socket.h>
#include "tcp.h"
#include "tcputils.h"

size_t gt_send_size(int sockfd, tcp_packet_t *packet) 
{
	size_t tosend, totalsent, sent;
	send(sockfd, (void *) &(packet->ulen), sizeof(size_t), 0);

	tosend =  sizeof(tcp_packet_t) + (packet->ulen);
	totalsent = 0;
	sent = 0;
	while(totalsent < tosend)
	{
		sent = send(sockfd, (void *) (((char *)packet) + totalsent), (tosend - totalsent), 0);
		totalsent += sent;
	}
	return totalsent;

}
size_t gt_recv_size(int sockfd, tcp_packet_t *packet) 
{
	size_t torecv, totalrcvd, rcvd;
	recv(sockfd, &torecv, sizeof(size_t), 0);

	packet = (tcp_packet_t *) malloc(sizeof(tcp_packet_t));
	packet->ubuf = (char *) malloc(torecv * sizeof(char));

	totalrcvd = 0;
	rcvd = 0;
	while(totalrcvd < torecv)
	{
		rcvd = recv(sockfd, (void *) (((char *)packet) + totalrcvd), (torecv - totalrcvd), 0);
		totalrcvd += rcvd;
	}
	return totalrcvd;
}
