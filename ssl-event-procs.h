/* $Id: ssl-event-procs.h,v 1.2 2013/09/13 14:56:38 akadams Exp $ */

// SSL event-loop processing routines.

// Copyright © 2009, Pittsburgh Supercomputing Center (PSC).  
// See the file 'COPYRIGHT.txt' for any restrictions.

#ifndef SSL_EVENT_PROCS_H_
#define SSL_EVENT_PROCS_H_

#include <poll.h>

#include <list>
using namespace std;

#include "SSLSession.h"
#include "ConfInfo.h"

// Networking definitions.

// System definitions.
#define SSL_EVENT_MAX_FDS 256

int ssl_event_poll_init(const list<SSLSession>& to_peers, 
                        const list<SSLSession>& from_peers,
                        const int max_fds, const int nfds, 
                        struct pollfd pollfds[]);
int ssl_event_poll_status(struct pollfd pollfds[], int nfds, int start_index);
list<SSLSession>::iterator 
ssl_event_poll_get_peer(const ConfInfo& info, const int fd, 
                        list<SSLSession>* peers);
int ssl_event_accept(const ConfInfo& info, const SSLConn& server, 
                     const int max_open_connections, const int framing,
                     SSLContext* ssl_context, list<SSLSession>* from_peers);
void ssl_event_read(const ConfInfo& info, list<SSLSession>::iterator peer);
void ssl_event_write(const ConfInfo& info, list<SSLSession>::iterator peer);

list<SSLSession>::iterator 
ssl_event_synchronize_connection(const bool receiver_initiated_flag, 
                                 ConfInfo* info, list<SSLSession>* to_peers, 
                                 list<SSLSession>* from_peers,
                                 list<SSLSession>::iterator peer);

#endif  /* #ifndef SSL_EVENT_PROCS_H_ */
