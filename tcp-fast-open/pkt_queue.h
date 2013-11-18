#ifndef __PKT_QUEUE_H
#define __PKT_QUEUE_H

typedef struct _sock_buffer_nd
{
	int sockfd;
	char *data;
	ssize_t offset;
	ssize_t length;
	struct _sock_buffer_nd *next;
}sock_buffer_node;

typedef sock_buffer_node * sock_buffer_t;

void sock_buffer_init(sock_buffer_t *head);
void sock_buffer_put_data(sock_buffer_t *head, int socket_id, int write_size, char *data);
char * sock_buffer_get_data(sock_buffer_t *head, int socket_id, ssize_t request_size, ssize_t *response_size);
ssize_t sock_buffer_can_read(sock_buffer_t *head, int socket_id); 	// returns how much can be read
void sock_buffer_remove(sock_buffer_t *head, int socket_id);
void sock_buffer_destroy(sock_buffer_t *head);

#endif
