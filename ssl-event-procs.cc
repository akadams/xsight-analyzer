/* $Id: ssl-event-procs.cc,v 1.6 2014/04/11 17:42:15 akadams Exp $ */

// Copyright © 2009, Pittsburgh Supercomputing Center (PSC).  
// See the file 'COPYRIGHT.txt' for any restrictions.

#include <assert.h>
#include <err.h>
#include <stdlib.h>

#include "ErrorHandler.h"
#include "Logger.h"
#include "ssl-event-procs.h"

#define DEBUG_INCOMING 0
#define DEBUG_OUTGOING 0

// Flags to mark direction of the SSL socket's flow.
const int kSenderInitiated = 0;
const int kReceiverInitiated = 1;


// TODO(aka) Standarize on what event-loop-procs shold be returning,
// i.e., ints or booleans?  It should be returning bools.

// TOOD(aka) Moreover, decide *who*, i.e., the main event loop or
// these routines, should be handling the ErrorHandler events!  Well,
// this really isn't that hard to answer; if the error does *not*
// effect the SSL session, then it should be dealt with in here,
// otherwise we should punt to the main event-loop to clean up the
// session gracefully (i.e., either blowing it away (if we're the
// server), or trying again, if we're the client.

// Main event-loop functions.

// This poll(3)-based routine loads any SSLSession *active* file
// descriptors into the *read* ready mask.  If the active fd *also*
// has data pending it its write buffer, then we add that fd to the
// "write" ready mask as well.  We return the number of fds loaded.
int ssl_event_poll_init(const list<SSLSession>& to_peers, 
                        const list<SSLSession>& from_peers,
                        const int max_fds, const int nfds, 
                        struct pollfd pollfds[]) {
  if (! to_peers.size() && ! from_peers.size())
    return nfds;  // nfsd could already have the server's listen socket

  // Walk first list checking SSLSession objects for an *open* file
  // descriptor ...

  int i = nfds;
  list<SSLSession>::const_iterator peer = to_peers.begin();
  while (peer != to_peers.end() && i < max_fds) {
    //logger.Log(LOG_DEBUGGING, "event_load_poll(): Checking peer %s, connected: %d.", peer->print().c_str(), peer->IsConnected());

    // If we have a file descriptor add it to our POLLIN list.
    if (peer->IsConnected()) {
      pollfds[i].fd = peer->fd();
      pollfds[i].events = (short)0;  // since pollfds[] gets reused, clear it
      pollfds[i].events = POLLIN;

      //logger.Log(LOG_DEBUGGING, "event_load_poll(): Added peer %d (%s) at %d.", peer->handle(), peer->print().c_str(), peer->fd());

      // If we have any *pending* outgoing message(s), then add POLLOUT
      // to the events as well.

      if (peer->IsOutgoingDataPending()) {
        pollfds[i].events |= POLLOUT;
        //logger.Log(LOG_DEBUG, "ssl_event_poll_init(): Added to_peer %d for POLLOUT.", peer->handle());
      }

      i++;  // mark that we processed a peer
    }

    peer++;  // increment our loop counter ;-)
  }

  // Walk our second list checking SSLSession objects for an *open*
  // file descriptor ...

  peer = from_peers.begin();
  while (peer != from_peers.end() && i < max_fds) {
    //logger.Log(LOG_DEBUG, "ssl_event_poll_init(): Checking from peer %s, data pending: %d.", peer->print().c_str(), peer->IsOutgoingDataPending());

    // If we have a file descriptor add it to our POLLIN list.
    if (peer->IsConnected()) {
      pollfds[i].fd = peer->fd();
      pollfds[i].events = (short)0;  // since pollfds[] gets reused, clear it first
      pollfds[i].events = POLLIN;

      //logger.Log(LOG_DEBUGGING, "event_load_poll(): Added accepted peer %s at %d.", peer->print().c_str(), peer->fd());

      // If we have any *pending* outgoing message(s), then add POLLOUT
      // to the events as well.

      if (peer->IsOutgoingDataPending()) {
        pollfds[i].events |= POLLOUT;
        //logger.Log(LOG_DEBUG, "ssl_event_poll_init(): Added from_peer %d POLLOUT.", peer->handle());
      }

      i++;  // mark that we processed a peer
    }

    peer++;  // increment our loop counter ;-)
  }

  //logger.Log(LOG_DEBUGGING, "event_load_poll(): Added %d fds to pollfds[].", i);

  return i;
}	

// This poll(3)-based routine looks at a struct pollfd[], and returns
// the pollfds index to the first encountered *revents* that is set.
int ssl_event_poll_status(struct pollfd pollfds[], int nfds, int start_index) {
  // Loop through pollfds[] looking for the first *set* revents.
  for (int i = start_index; i < nfds; i++) {
    if (pollfds[i].revents)
      return i;
  }

  logger.Log(LOG_WARN, "ssl_event_poll_status(): Failed to find revents, "
             "nfds = %d, start_index = %d.", nfds, start_index);

  return -1;  // hmm, didn't find one
}

// This poll(3)-based routine returns the SSLSession peer that is
// associated with a file descriptor.
list<SSLSession>::iterator
ssl_event_poll_get_peer(const ConfInfo& info, const int fd, 
                        list<SSLSession>* peers) {
  // Look for the SSLSession that matches the ready fd in peers ...
  list<SSLSession>::iterator peer = peers->begin();
  while (peer != peers->end()) {
    if (peer->fd() == fd)
      return peer;

    peer++;
  }

  // If we made it here, we couldn't find a SSLSession.  Note, this
  // does not mean a problem, as it could be in the other
  // list<SSLSession>, i.e., to_peers or from_peers!

  //logger.Log(LOG_DEBUG, "ssl_event_poll_get_peer(): Unable to find peer for fd: %d.", fd);

  return peer;  // peer == peers->end()
}

// Routine to "accept()" a connection, and load it into our SSLSession list.
int ssl_event_accept(const ConfInfo& info, const SSLConn& server, 
                     const int max_open_connections, const int framing,
                     SSLContext* ssl_context, list<SSLSession>* from_peers) {
  //logger.Log(LOG_DEBUGGING, "ssl_event_accept(): checking server's listen socket: %d.", server.fd());

  // Setup a temporary list<SSLSession> element.
  SSLSession tmp_peer(framing);
  tmp_peer.Init();  // set aside buffer space
  server.Accept(&tmp_peer, ssl_context);  // call accept(2) to populate tmp_peer
  if (error.Event()) {
    logger.Log(LOG_NETWORK, "Unable to accept connection: %s.", 
               error.print().c_str());
    error.clear();
    return 1;  // TODO(aka) Figure out better error code here
  }

  from_peers->push_back(tmp_peer);  // add the session to our list

  /*
  // TODO(aka) Playing with a way to prevent DoS here ...

  // Make sure we aren't over our "connection limit".
  if (event_cnt_open_connections(from_peers) > max_open_connections) {
    // For now, simply close the connection and let the remote
    // end deal.

    if (tmp_peer.Is_Connected())
      logger.Log(LOG_VERBOSE, "Reached maximum number "
                 "of accept() connections: %d, "
                 "closing connection with %s, "
                 "and returning ...", 
                 max_open_connections, 
                 tmp_peer.hostname().c_str());
    else
      logger.Log(LOG_VERBOSE, "Reached maximum number "
                 "of accept() connections: %d, "
                 "closing connection, and returning ...", 
                 max_open_connections);

    from_peers.Remove(tmp_peer.ssl);	// clean up network queue

    return NULL;
  }
  */

  // TODO(aka) Because there are kernels out in the wild that do not
  // adhere to IANA's defined port ranges, e.g., dynamic =
  // 49152:65535, for ephemeral port assignment, can our comparisons
  // against our SSLSession queue ignore the port? That is, if we
  // already had a SSLConn element in our queue for the peer that just
  // connected via the accept(), then we will have more than one entry
  // for that host with (probably) different ports, yet our various
  // 'tests' could inadvertantly pick the wrong queue element.

  return 0;
}

// Routine to read any data on a socket (file descriptor) and load it
// into our SSLSession buffer for later processing within the main's
// event-loop.
//
// We call SSLSession::Read() to get the work done.  If we requested
// *streaming* file I/O, then we additionally call
// SSLSession::StreamRbuf() to send the chunk(s) of data read to a
// file (rfile_).  TODO(aka) Unfortunately, in streaming mode this
// means that our internal read buffer is now acting as a copy
// buffer!) to File object rfile_.
void ssl_event_read(const ConfInfo& info, list<SSLSession>::iterator peer) {
  /*
  // TODO(aka) Uh, do we need this in pollin()?

  // When using NON_BLOCKING I/O, select(2)'s firing may be to report
  // an ERROR on the socket, not that the socket is ready for
  // reading/writing.  Thus, before attempting anything on the fd, we
  // need to check the socket's SO_ERROR status first.

  int sock_status = 0;
  socklen_t status_len = sizeof(sock_status);
  int status = peer->Getsockopt(SOL_SOCKET, SO_ERROR);  // get socket status
  if (status == EALREADY) {
    logger.Log(LOG_VERBOSE, "ssl_event_read(): EALREADY on connection with %s:%hu.", 
               peer->hostname().c_str(), peer->port());
    return;  // EALREADY
  } else if (status == ECONNREFUSED || status == ECONNRESET || status == ETIMEDOUT) {
    // Handle the error ....
    logger.Log(LOG_ERROR, "ssl_event_read(): TODO(aka) "
               "TIMEOUT, RESET or Connection REFUSED with %s: %d.",
               peer->print().c_str(), status);
    // TODO(aka) Need to handle the error *remotely* somehow ...
    return;
  } else if (status) {

    // Hmm, genuine socket ERROR, even-though it's probably futile to
    // continue, handle the error ...

    logger.Log(LOG_ERROR, "ssl_event_read(): TODO(aka) connection failed with %s: %d.",
               peer->print().c_str(), status);
    return;
  }

  // Okay, our SSL connection should (still) be *healthy*.
  */

  // Read all the available data that we have free buffer space for on the
  // SSL socket ...

  bool eof = false;
  ssize_t bytes_read = 0;
  bytes_read = peer->Read(&eof);
  if (error.Event()) {
    // peer->Read() cleared peer on error, return to main event-loop.
    error.AppendMsg("ssl_event_read(): peer->Read() failed");  
    return;
  }

  if (bytes_read == 0 && !eof)
    logger.Log(LOG_DEBUG, "ssl_event_read():  Read() returned no data.");

  // If we should *stream* what we just read to file*, call StreamRbuf().
  if (bytes_read > 0 && peer->IsIncomingDataStreaming()) {
    // TODO(aka) Unfortunately, I can't figure out how to avoid the
    // one buffer copy (peer->Read()) prior to this call ...

#if 0  // For Debugging:
    const File rfile = peer->rfile();
    const MsgInfo rpending = peer->rpending();
    logger.Log(LOG_DEBUG, "ssl_event_read(): Streaming %ld byte(s) from %s to %s, eof: %d, rpending.storage: %d, rpending.file_offset: %lu, rpending.body_len: %lu.", bytes_read, peer->hostname().c_str(), rfile.path(NULL).c_str(), eof, rpending.storage, rpending.file_offset, rpending.body_len);
#endif

    (void)peer->StreamIncomingMsg();
  } else {
    logger.Log(LOG_DEBUG, "ssl_event_read(): Read %ld byte(s) from %s, rbuf_len: %ld, eof: %d.", bytes_read, peer->hostname().c_str(), peer->rbuf_len(), eof);
  }

  // See if the remote end closed the connection.
  if (eof) {
    peer->set_connected(0);  // mark that the connection is terminated
    logger.Log(LOG_NORMAL, "Peer %s, session ID: %d, closed connection.", 
               peer->SSLConn::print_3tuple().c_str(), peer->handle());
    return;  // calling-routine must check SSLConn::IsConnected()
  }

  // Head back to the main event-loop to process the read buffer on
  // our next timeout.

}

// Routine to write any data within the SSLSession to the verified
// *ready* socket.
void ssl_event_write(const ConfInfo& info, list<SSLSession>::iterator peer) {
  // When using NON_BLOCKING I/O, select(2)'s firing may be to report
  // an ERROR on the socket, not that the socket is ready for writing.
  // Thus, before attempting anything on the fd, we need to check the
  // socket's SO_ERROR status first ...
  
  int option_value = 0;
  socklen_t option_len = sizeof(option_value);
  peer->Getsockopt(SOL_SOCKET, SO_ERROR, &option_value, &option_len);
  if (option_value == EALREADY) {
    logger.Log(LOG_INFO, "ssl_event_write(): "
               "EALREADY on connection with %s.", peer->hostname().c_str());
    return;  // EALREADY, go back and wait to try again
  } else if (option_value == ECONNREFUSED || option_value == ECONNRESET ||
             option_value == ETIMEDOUT) {
    // Handle ERROR.
    error.Init(EX_OSERR, "ssl_event_write(): "
                   "TIMEOUT, RESET or Connection REFUSED with %s: %d.",
                   peer->hostname().c_str(), option_value);
    peer->PopOutgoingMsgQueue();  // can't send, so remove message pending
    return;
  } else if (option_value) {
    // Hmm, an ERROR on the socket ...
    error.Init(EX_OSERR, "ssl_event_write(): "
                   " socket status with %s failed: %d.",
                   peer->hostname().c_str(), option_value);
    peer->PopOutgoingMsgQueue();  // can't send, so remove message pending
    return;
  }

  // Okay, our SSL connection should (still) be *healthy*.

  //logger.Log(LOG_INFO, "ssl_event_write(): writing to peer: %s.", peer->print().c_str());

  peer->Write();
  if (error.Event()) {
    // Bleh.  Write() should have cleaned up peer, so just report.
    error.AppendMsg("ssl_event_write(): Unable to write message to %s: %s",
                   peer->print().c_str(), error.print().c_str());
    return;
  }

  // See if entire message has been written.
  if (!peer->IsOutgoingDataPending())
    logger.Log(LOG_INFO, "ssl_event_write(): sent entire message to %s.", 
               peer->hostname().c_str());

  //peer->stale_timer = SSL_QUEUE_DEFAULT_STALE_TIME;	// reset it
}

// Routine to establish the framing protocol over a *synchronized* SSL
// session.
//
// This message should be one of two types; an ACK to our REQ_INIT
// (kSenderInitiated via to_peers), or a REQ_INIT (kReceiverInitiated
// via from_peers).  If this is a REQ_INIT and we have *not* yet sent
// our REQ_INIT, we delete our to_peer for this peer (id), add the
// from_peer to to_peers, and build an ACK_INIT message.  If this
// is an ACK_INIT message and we have not yet received the
// REQ_INIT from the peer, we delete our from_peer.  Finally, if this
// is a REQ_INIT, but we've already sent out our REQ_INIT, then we use
// the tie-breaker (lowest peer id) to decide who sends the ACK.
//
// Note, usually, there is no need to synchronize connections, but it
// can be advantagous with making sure all your *well-known*
// connections stay in to_peers, as opposed to from_peers.
//
// TODO(aka) Honestly, this routine makes no sense with HTTP, and in
// fact, doesn't do anything when using HTTP, so why do we have it?
list<SSLSession>::iterator 
ssl_event_synchronize_connection(const bool receiver_initiated_flag, 
                                 ConfInfo* info,
                                 list<SSLSession>* to_peers, 
                                 list<SSLSession>* from_peers,
                                 list<SSLSession>::iterator peer) {
  switch (peer->rhdr().type()) {
    case MsgHdr::TYPE_BASIC :
#if USING_P2P
      //logger.Log(LOG_DEBUGGING, "ssl_event_synchronize_connection(): working with message-header %s for peer %s.", peer->rhdr().print().c_str(), peer->print().c_str());

      if (receiver_initiated_flag) {
        // Check for INIT via from_peers ...
        if (peer->rhdr().basic_hdr().type == MSG_REQ_INIT) {

          // Check which node (in to_peers) this session is from, and
          // decide if we should replace this node with the one in
          // to_peers or not.

          list<SSLSession>::iterator to_peer = to_peers->begin();
          while (to_peer != to_peers->end()) {
            if (to_peer->handle() == peer->rhdr().basic_hdr().id)
              break;
            to_peer++;
          }
          if (to_peer == to_peers->end()) {
            logger.Log(LOG_ERROR, "ssl_event_synchronize_connection(): TODO(aka) Unable to find peer for id %d!", peer->rhdr().basic_hdr().id);
            exit(1);
          }

          //logger.Log(LOG_DEBUGGING, "ssl_event_synchronize_connection(): Found %s in to_peers, deciding on whether to replace it with %s from from_peers.", to_peer->print().c_str(), peer->print().c_str());

          // If we have not yet sent an a INIT msg (wpending > 0), replace
          // the to_peer with the from_peer.  If we have sent an INIT msg,
          // replace the to_peer with the from_peer only if from_peer's id
          // is lower (to act as a tie-breaker).

          if ((!to_peer->IsConnected() || to_peer->wpending().size() > 0) || 
              peer->rhdr().basic_hdr().id < to_peer->handle()) {
            // Set from_peer's handle to be to_peer's, just in-case.
            peer->set_handle(to_peer->handle());
            peer->set_synchronize_status(1);

            // Blow away our to_peer for this peer id.
            if (to_peer->IsConnected())
              to_peer->Close();
            to_peers->remove(*to_peer);

            // Build the message RESPONSE.
            peer->ShiftRpending();  // remove processed message from SSLSession
            struct BasicFramingHdr basic_hdr;
            basic_hdr.id = info->id_;  // our id
            basic_hdr.msg_id = ++msg_id_hash;  // unique msg id
            basic_hdr.type = MSG_ACK_INIT;
            basic_hdr.lamport = info->lamport_;
            basic_hdr.len = 0;
#if 0
            // TODO(aka) Call changed.
            peer->AddMsgHdr((char*)&basic_hdr, kBasicHdrSize, 0, 
                            basic_hdr.msg_id, SSLSESSION_STORAGE_WBUF);
#endif
      
            //logger.Log(LOG_DEBUGGING, "ssl_event_synchronize_connection(): ACK_INIT is waiting transmission to %s.", peer->print().c_str());

            logger.Log(LOG_NORMAL, "Node %d established connection (%s).", 
                       peer->rhdr().basic_hdr().id, peer->print_3tuple().c_str());
            info->established_connections_++;

            // Add peer (from from_peers) to to_peers, then delete from from_peers.
            to_peers->push_back(*peer);
            peer = from_peers->erase(peer);

            /*
            // For Debugging:
            for (list<SSLSession>::const_iterator foo = to_peers->begin(); foo != to_peers->end(); foo++)
            logger.Log(LOG_DEBUGGING, "ssl_event_synchronize_connection(): Peer %d: %s.", foo->id(), foo->print().c_str());
            */
          } else {  // if ((!to_peer->IsConnected() || to_peer->wpending().size() > 0) ||

            // We've sent out our INIT *and* we have a lower ID, so ignore
            // this INIT while we await their ACK ...

            // Clean up.
            //logger.Log(LOG_DEBUGGING, "Cleaning %ld byte msg-body for request (%s) from peer %s.", peer->rhdr().msg_len(), peer->rhdr().print().c_str(), peer->print().c_str());

            peer->Close();
            peer->ShiftRpending();  // remove processed message from SSLSession
            peer = from_peers->erase(peer);
          }  // else if ((!to_peer->IsConnected() || to_peer->wpending().size() > 0) ||
        } else {  // if (peer->rhdr().basic_hdr().type == MSG_REQ_INIT) {
          logger.Log(LOG_ERROR, "ssl_event_synchronize_connection(): TODO(aka) Header %s from %s was not a MSG_REQ_INIT!", peer->rhdr().print().c_str(), peer->print().c_str());
          exit(1);
        }  //  else if (peer->rhdr().basic_hdr().type == MSG_REQ_INIT) {
      } else {  // if (receiver_initiated_flag) {
        // Process the ACK.
        if (peer->rhdr().basic_hdr().type != MSG_ACK_INIT) {
          logger.Log(LOG_ERROR, "ssl_event_synchronize_connection(): TODO(aka) Header %s from %s was not a MSG_ACK_INIT!", peer->rhdr().print().c_str(), peer->print().c_str());
          exit(1);
        }

        logger.Log(LOG_NORMAL, "Established connection with node %d (%s).", 
                   peer->handle(), peer->print_3tuple().c_str());
        peer->set_synchronize_status(1);
        info->established_connections_++;

        // If the peer is in from_peers (TOOD(aka) can this happen?), close & remove it.
        list<SSLSession>::iterator from_peer = from_peers->begin();
        while (from_peer != from_peers->end()) {
          if (from_peer->handle() == peer->handle())
            break;
          from_peer++;
        }
        if (from_peer != from_peers->end()) {
          logger.Log(LOG_ERROR, "ssl_event_synchronize_connection(): TODO(aka) "
                     "Found peer id %d in from_peers (%s)!", 
                     peer->handle(), from_peer->print().c_str());
          if (from_peer->IsConnected())
            from_peer->Close();
          from_peers->remove(*from_peer);
        }

        // Clean up.

        // Find and remove INIT REQUEST message-header; it should be the
        // only in whdrs ...

        if (peer->whdrs().size() != 1)
          logger.Log(LOG_ERR, "ssl_event_synchronize_connection(): "
                     "whdrs_ != 1.");

        peer->whdrs().erase(peer->whdrs().begin());
        peer->ShiftRpending();  // remove processed message from SSLSession

        // Finally, send out our current file directory.
        struct BasicFramingHdr basic_hdr;
        basic_hdr.id = info->id_;  // our id
        basic_hdr.msg_id = ++msg_id_hash;  // unique msg id
        basic_hdr.type = MSG_REQ_STATUS;
        basic_hdr.type_id = from_peers->size();  // work load
        basic_hdr.lamport = info->lamport_;
        basic_hdr.len = info->local_files_.size();  // TOOD(aka) breaks at 10 files!
#if 0
        // TODO(aka) Call changed.
        peer->AddMsgHdr((char*)&basic_hdr, kBasicHdrSize, basic_hdr.len,
                        basic_hdr.msg_id, SSLSESSION_STORAGE_WBUF);
#endif

        string tmp_str(128, '\0');  // '\0' so strlen works
        list<string>::const_iterator file = info->local_files_.begin();
        while (file != info->local_files_.end()) {
          snprintf((char*)tmp_str.c_str() + strlen(tmp_str.c_str()), 
                   128 - strlen(tmp_str.c_str()),
                   "%s", file->substr(1).c_str());
          logger.Log(LOG_DEBUGGING, "ssl_event_synchronize_connection(): Adding %s to %s.", file->substr(1).c_str(), tmp_str.c_str());
          file++;
        }
#if 0
        // TODO(aka) Call changed.
        peer->AppendMsgBody(tmp_str.c_str(), basic_hdr.len);
#endif

        // Build our REQUEST MsgHdr and add it to our list for later
        // processing during the RESPONSE.

        MsgHdr tmp_msg_hdr;
        tmp_msg_hdr.set_hdr(basic_hdr);
        tmp_msg_hdr.set_msg_id(basic_hdr.msg_id);
        peer->whdrs().push_back(tmp_msg_hdr);

        peer++;
      }  // if else (receiver_initiated_flag) {

      if ((info->num_nodes_ - 1) == info->established_connections_)
        logger.Log(LOG_QUIET, "Connections established with all %d peers.", 
                   info->num_nodes_ - 1);
#endif
      break;

    case MsgHdr::TYPE_HTTP :
      break;

    default :
      // TODO(aka) Why is this not an error?  Why do we have this rountine?
      warnx("ssl_event_synchronize_connection(): unknown type: %d.", 
            peer->rhdr().type());
  }

  return peer;
}
