/*
 * netcon.h
*
 */

#ifndef NETCON_H_
#define NETCON_H_
#include <ev.h>

#define NETCON_CMD_MATCHED 1
#define NETCON_CMD_UNKNOWN  0

int netcon_init( struct ev_loop *loop, char *host, int port );
/* cmd receives a string, return 1 if matched, 0 otherwise */
void netcon_register(int(*cmd)(char *msg ));
int netcon_resync(int fd );
void netcon_sync_clenaup();

#endif /* NETCON_H_ */
