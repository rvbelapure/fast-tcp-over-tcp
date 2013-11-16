#ifndef __TCPUTILS_H
#define __TCPUTILS_H

#include "tcp.h"

int gt_send_size(int sockfd, tcp_packet_t *packet);
int gt_recv_size(int sockfd, tcp_packet_t *packet);

#endif
