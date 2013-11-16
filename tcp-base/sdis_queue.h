#ifndef __SDIS_H

#define __SDIS_H
typedef struct socket_list_t{
	int socket_id;
	struct socket_list_t *next;
	char *data;
	ssize_t offset;
	ssize_t length;
}socket_list;

socket_list * create_socket_list();

void socket_list_add(socket_list *head, int socket_id);

void socket_list_remove(socket_list *head, int socket_id);

char * socket_list_get_data(socket_list *head, int socket_id, int read_size);

void socket_list_add_data(socket_list *head, int socket_id, int write_size, char *data);

//how much can be read
ssize_t socket_list_can_read(socket_list *head, int socket_id);

void socket_list_destroy(socket_list *head);

#endif
