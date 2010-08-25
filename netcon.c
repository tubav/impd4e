/**
 * Network console
 *
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <netdb.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ev.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include "logger.h"
#include "netcon.h"

#define SERVICE_NAME_LENGTH 64 /* service  = port no */
#define MAX_CLIENTS 5  /* max number of simultaneous clients */
#define BUFFER_SIZE 1024

/* === MODEL === */
/* used to store command callbacks */
struct registry {
	int(*cmd)(char *msg );
	struct registry *next;
};
/* read and write positions used for buffer manipulation*/
typedef struct {
	uint16_t rd;
	uint16_t wr;
}pos_t;
 /* Connection handling */
struct connection {
	u_char sync;
	int fd;
	ev_io ev_write;
	ev_io ev_read;
	char remote_host[64];     /* must be big enough to hold an IPv6 numeric string representation */
	char remote_port[64];
	pos_t in_pos;
	char  in_buf[BUFFER_SIZE];
	pos_t out_pos;
	char  out_buf[BUFFER_SIZE];
	struct connection  *next;
};
struct netcon {
	int listen_fd;
	struct sockaddr_in listen_addr;
	ev_io accept_watcher;
	struct registry *reg;   /* command callbacks */
	struct ev_loop *loop;
	struct connection *conn; /* store active connections */
} netcon;


/* === PROTOTYPES === */
static void connection_close( EV_P_ struct connection * conn);
static void connection_write( EV_P_ struct connection * conn, char * data );

static int setnonblock(int fd) {
	int flags;
	flags = fcntl(fd, F_GETFL);
	if (flags < 0)
		return flags;
	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) < 0)
		return -1;
	return 0;
}

static void write_cb(struct ev_loop *loop, struct ev_io *w, int revents) {
	struct connection *conn= (struct connection*) w->data ;
	static char motd[]="imp4e\n";
	LOGGER_debug("write CB");
	if (revents & EV_WRITE){
		write(conn->fd,motd,strlen(motd));
		ev_io_stop(EV_A_ w);
	}
	close(conn->fd);
	free(conn);
}
static void connection_write( EV_P_ struct connection * conn, char *data ){
	ev_io_start(loop,&conn->ev_write);


}
static void connection_close( EV_P_ struct connection * conn){
	LOGGER_debug("connection close: %s:%s sync:%d",conn->remote_host, conn->remote_port, conn->sync );
	if(conn->sync){
//		LOGGER_debug("CLOSING SYNC CONNECTION");
		ev_io_stop(EV_A_ &conn->ev_read );
		conn->fd=-1;
		return;
	}
	ev_io_stop(EV_A_ &conn->ev_read );
	ev_io_stop(EV_A_ &conn->ev_write);
	if( close(conn->fd) <0 ){
		LOGGER_error("close: %s",strerror(errno));
	}
	free(conn);
}
static void connection_read( struct connection * conn ){
	char msg[conn->in_pos.wr  - conn->in_pos.rd+1];
	int len = conn->in_pos.wr  - conn->in_pos.rd;
	struct registry **reg;
	int res = NETCON_CMD_UNKNOWN;
	strncpy(msg,conn->in_buf, len );
	msg[len]='\0';
	LOGGER_debug("cmd: %s",msg);
	conn->in_pos.rd=conn->in_pos.wr=0;
	/* execute cmd callbacks until msg consumed */
	for(reg=&netcon.reg;*reg!=NULL && res!=NETCON_CMD_MATCHED; reg=&(*reg)->next ){
		res = (*(*reg)->cmd)( msg);
	}
	if(!res){
		LOGGER_warn("Unknown command: %s",msg);
	}

}
static void read_cb(EV_P_ struct ev_io *w, int revents) {
	struct connection *conn= (struct connection*) w->data;
	int r=0;
	short maxlen = BUFFER_SIZE - conn->in_pos.wr;
//	if(conn->sync){
//		LOGGER_debug("SYNC DATA!");
//	}
	if( revents & EV_ERROR) {
		LOGGER_error("event loop error");
		return;
	}
	if( maxlen==0){
		LOGGER_warn("ïnput buffer is full");
		connection_read(conn);
		return;
	}
	if (revents & EV_READ){
		r=read(conn->fd,conn->in_buf+conn->in_pos.wr,maxlen);
		if(r<=0){
		    connection_close(EV_A_ conn);
			return;
		}
		conn->in_pos.wr+=r;
		connection_read(conn);
	}
	//	ev_io_stop(EV_A_ w);
	//	ev_io_init(&cli->ev_write,write_cb,cli->fd,EV_WRITE);
	//	ev_io_start(loop,&cli->ev_write);

}
/**
 *  Handle new clients
 *  */
static void accept_cb(EV_P_ struct ev_io *w, int revents) {
	int client_fd, res;
	struct connection *conn;
	struct sockaddr_in client_addr;
	socklen_t client_len = sizeof(client_addr);
	LOGGER_debug("accept cb!");

	client_fd = accept(w->fd, (struct sockaddr *)&client_addr, &client_len);
	if (client_fd == -1) {
		return;
	}
	/* Setting up connection  */
 	if ( (conn = calloc(1,sizeof(*conn)))==NULL ){
 		LOGGER_error("could not setup connection");
 		close(client_fd);
 		return;
 	}
 	/* saving remote host, port for reporting */
	res = getnameinfo((struct sockaddr *)&client_addr, client_len, conn->remote_host, NI_MAXHOST, conn->remote_port, 64, NI_NUMERICHOST);
	if (res != 0) {
		LOGGER_error("getnameinfo() failed: %s\n", gai_strerror(res));
		return;
	}
	LOGGER_debug("client connected: %s:%s",conn->remote_host, conn->remote_port);
	conn->fd=client_fd;
	if (setnonblock(conn->fd) < 0){
		LOGGER_error("failed to set client socket to non-blocking");
	}
	/* saving a reference of connection to handle it within call back */
	conn->ev_read.data = conn;
	conn->ev_write.data = conn;

	ev_io_init(&conn->ev_read,read_cb,conn->fd,EV_READ);
	ev_io_init(&conn->ev_write,write_cb, conn->fd, EV_WRITE);

	ev_io_start(loop,&conn->ev_read);
	//ev_io_start(loop,&client->ev_write);

}
void netcon_register(int(*cmd)(char *msg )){
	struct registry **reg;
	if(cmd==NULL){
		LOGGER_warn("command must not be null, ignored.");
		return;
	}
	for( reg=&netcon.reg;(*reg)!=NULL;reg=&(*reg)->next);
	if(((*reg)=calloc(1,sizeof(**reg)))==NULL){
		LOGGER_error("calloc: %s",strerror(errno));
		return;
	}
	(*reg)->cmd=cmd;
}

/**
 * Initalize network console
 *
 * @param loop ev loop
 * @param host host address to bind, use NULL to bind to 0.0.0.0
 * @param port
 * returns:
 *  0   sucessfull
 *  -1  failed
 */
int netcon_init( struct ev_loop *loop, char *host, int port ){
	struct addrinfo hints;
	struct addrinfo *rp,*serverAddrList;    /* list of server addresses */
	int res; /* result */
	char  service[SERVICE_NAME_LENGTH];
	int reuseaddr_on = 1;
	LOGGER_debug("netcon init: %s:%d",host, port);
	netcon.reg=NULL;
	netcon.loop = loop;
	netcon.conn = NULL;

	LOGGER_info("netcom sync only");
	return 0;
	/* -- checking if we can use host port for binding address  */
	/*getaddrinfo needs port as string  (or service name)*/
	snprintf(service,SERVICE_NAME_LENGTH,"%d",port);
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;       /* IPv4 only */
	hints.ai_socktype = SOCK_STREAM;   /* stream sockets */
	hints.ai_flags = AI_PASSIVE;       /* for wildcard IP address (accept on any address/port) */
	hints.ai_protocol = IPPROTO_TCP;   /* only protocol */
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	res = getaddrinfo(host, service , &hints, &serverAddrList);
	if (res != 0) {
		LOGGER_error("getaddrinfo: %s\n", gai_strerror(res));
		return -1;
	}
	/*  iterating through available addresses */
	for (rp = serverAddrList; rp != NULL; rp = rp->ai_next) {
		/* display the socket interface address, AF_INET6 not used, but support here */
		if (rp->ai_family == AF_INET || rp->ai_family == AF_INET6) {
			char hoststr[64]; /* must be big enough to hold an ipv6 numeric string representation */
			char service[64];
			res = getnameinfo(rp->ai_addr,
					(rp->ai_family == AF_INET) ? sizeof(struct sockaddr_in) :
							sizeof(struct sockaddr_in6),
							hoststr, NI_MAXHOST, service, 64, NI_NUMERICHOST);
			if (res != 0) {
				LOGGER_error("getnameinfo() failed: %s\n", gai_strerror(res));
				return -1;
			}
			LOGGER_info("binding to: <%s>:%s", hoststr,service);
		}
		netcon.listen_fd = socket(rp->ai_family, rp->ai_socktype , rp->ai_protocol );
		if (netcon.listen_fd  == -1){
			continue;
		}
		if (setsockopt(netcon.listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr_on,
				sizeof(reuseaddr_on)) == -1){
			LOGGER_error("setsockopt: %s",strerror(errno));
			close(netcon.listen_fd);
			return -1;
		}
		if (bind(netcon.listen_fd, rp->ai_addr, rp->ai_addrlen) == 0){
			break;                  /* Success */
		} else {
			LOGGER_error("bind: %s",strerror(errno));
			return -1;
		}
		close(netcon.listen_fd);
	}
	freeaddrinfo(serverAddrList);

	/* bind address ok, setting up call backs */

	if (listen(netcon.listen_fd,MAX_CLIENTS) < 0){
		close(netcon.listen_fd);
		LOGGER_error("listen: %s",strerror(errno));
		return -1;
	}
	if (setnonblock(netcon.listen_fd) < 0){
		LOGGER_error("failed to set server socket to non-blocking");
		return -1;
	}
	ev_io_init(&netcon.accept_watcher,accept_cb,netcon.listen_fd,EV_READ);
	ev_io_start(loop,&netcon.accept_watcher);
	return 0;

}
void netcon_sync_cleanup(){
	LOGGER_debug("cleaning up sync connection");
//	ev_io_stop(netcon.loop, )

}
int netcon_resync( int fd ){
	struct connection *conn,**ptr;
//	setnonblock(fd);
//	flags = fcntl(fd, F_GETFL);
//	LOGGER_debug("NONBLOCK?: %d",flags & O_NONBLOCK );
//	LOGGER_debug("netcon add sync: %d",fd);
	if( fd< 0 ){
		for(ptr=&netcon.conn;*ptr!=NULL;ptr=&(*ptr)->next ){
			if((*ptr)->fd >0 ){
				LOGGER_debug("cleaning: %d",(*ptr)->fd);
				close((*ptr)->fd);
				(*ptr)->fd = -1;
			}
		}
		return 0;
	}
	/* looking for closed connections */
 	for(ptr=&netcon.conn;*ptr!=NULL;ptr=&(*ptr)->next ){
//		LOGGER_debug("found: %d",(*ptr)->fd);
		if ((*ptr)->fd==fd){
// 			LOGGER_debug("already registered");
 			return 0;
 		}
 	}
 	/* looking for free slots */
	for(ptr=&netcon.conn;*ptr!=NULL && (*ptr)->fd!=-1 ;ptr=&(*ptr)->next );

 	/* Setting up sync connection  */
	if(  *ptr==NULL ){
		if ( (conn = calloc(1,sizeof(*conn)))==NULL ){
			LOGGER_error("could not setup sync connection");
			return -1;
		}
		*ptr=conn;
	} else {
//		LOGGER_debug("REUSING CONN ");
		conn = *ptr;
	}
 	conn->fd=fd;
 	conn->sync=1; /* this is a sync connection */

	/* saving a reference of connection to handle it within call back */
	conn->ev_read.data = conn;
	conn->ev_write.data = conn; /* won't be used in sync */

	ev_io_init(&conn->ev_read,read_cb,conn->fd,EV_READ);

	ev_io_start(netcon.loop,&conn->ev_read);

	return 0;
}








