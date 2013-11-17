#include <stdlib.h>
#include <string.h>
#include "pkt_queue.h"

void sock_buffer_init(sock_buffer_t *head)
{
	*head = NULL;
	return;
}

void sock_buffer_put_data(sock_buffer_t *head, int socket_id, int write_size, char *data) 
{
	/* Get a pointer to the node corresponding to socket_id*/
	sock_buffer_t ptr = *head;
	while((ptr) && (ptr->sockfd != socket_id))
		ptr = ptr->next;
	
	/* Add the node if it does not exist */
	if(ptr == NULL)
	{
		/* Either *head == NULL or socket_id does ot exist.
		 * Add the new node at the head of the queue */
		ptr = (sock_buffer_node *) malloc(sizeof(sock_buffer_node));
		ptr->sockfd = socket_id;
		ptr->next = *head;
		*head = ptr;
	}

	/* We have pointer to the required buffer. Now update the buffer */
	ptr->data = (char *) malloc(write_size * sizeof(char));
	memcpy(ptr->data, data, write_size);
	ptr->offset = 0;
	ptr->length = write_size;
	return;
}

char * sock_buffer_get_data(sock_buffer_t *head, int socket_id, ssize_t request_size, ssize_t *response_size)
{
	/* Get the required node */
	sock_buffer_t ptr = *head;
	while((ptr) && (ptr->sockfd != socket_id))
		ptr = ptr->next;

	/* socket_id not found */
	if(ptr == NULL)
	{
		*response_size = 0;
		return NULL;
	}	

	ssize_t available_size = ptr->length - ptr->offset;
	*response_size = (available_size <= request_size) ? available_size : request_size;	// min(available, request)
	char *output = (char *) malloc((*response_size) * sizeof(char));
	memcpy(output, (ptr->data + ptr->offset), *response_size);
	ptr->offset += (*response_size);

	/* Check if eligible for deletion */
	if(ptr->offset >= ptr->length)
	{
		free(ptr->data);
		ptr->data = NULL;
		ptr->offset = 0;
		ptr->length = 0;
	}

	return output;
}

ssize_t sock_buffer_can_read(sock_buffer_t *head, int socket_id) 
{
	/* Find the required node */
	sock_buffer_t ptr = *head;
	while((ptr) && (ptr->sockfd != socket_id))
		ptr = ptr->next;

	/* Can't read if this socket does not contain any buffer */
	if(ptr == NULL)
		return 0;
	
	/* return the number of readable bytes */
	return (ptr->length - ptr->offset);
}

void sock_buffer_remove(sock_buffer_t *head, int socket_id) 
{
	if(*head == NULL)
		return;

	/* Get ptr to the required node. 
	 * Maintaine a previous pointer to simplify deletion */
	sock_buffer_t prev = NULL, curr = *head;
	while((curr) && (curr->sockfd != socket_id))
	{
		prev = curr;
		curr = curr->next;
	}

	if(curr == NULL)
		return;
	
	/* Delete curr node and re-arrange the pointers */
	if(prev == NULL)
		*head = curr->next;
	else
		prev->next = curr->next;

	if(curr->data)
		free(curr->data);
	free(curr);
	return;
}

void sock_buffer_destroy(sock_buffer_t *head) 
{
	while(*head)
		sock_buffer_remove(head, (*head)->sockfd);
	*head = NULL;
}
