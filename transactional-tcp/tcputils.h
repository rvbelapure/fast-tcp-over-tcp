#ifndef __TCPUTILS_H
#define __TCPUTILS_H

#include "tcp.h"

#define MAX_UINT_32 (1 << 31)
size_t gt_send_size(int sockfd, tcp_packet_t *packet);
size_t gt_recv_size(int sockfd, tcp_packet_t **packet);

#endif
