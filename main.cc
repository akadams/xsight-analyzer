/* $Id: main.cc,v 1.7 2014/04/11 17:42:15 akadams Exp $ */

// Copyright © 2009, Pittsburgh Supercomputing Center (PSC).  
// See the file 'COPYRIGHT.txt' for any restrictions.

#include <sys/types.h>
#include <sys/stat.h>

#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>          // for exit on client
#include <string.h>          // for memset
#include <sysexits.h>
#include <unistd.h>

#include <string>
#include <list>
#include <map>
using namespace std;

#include "ErrorHandler.h"
#include "Base64.h"          // for HTTP basic authentication
#include "Logger.h"
#include "ConfInfo.h"
#include "SSLContext.h"
#include "SSLConn.h"
#include "SSLSession.h"
#include "AnalyzedInfo.h"
#include "FlowInfo.h"
#include "ssl-event-procs.h"
#include "analyzer-procs.h"


#define DEBUG_MUTEX_LOCK 0

// Global variables.
#define SERVER_VERSION "0.9.5"
#define CONF_FILE_DELIMITER '='

// Static defaults.
static const char* conf_file_default = "analyzer.conf";

// Networking defaults.
static const in_port_t kServerPort = 13500;  // not used
static const int kFramingType = MsgHdr::TYPE_HTTP;
static const int kMaxPeers = 128;
static const ssize_t kDefaultBufSize = TCPSESSION_DEFAULT_BUFSIZE;

// Event-loop timeout controls
static const int state_poll_interval = 86400;  // 24 hours
static const int kPollIntervalUnanalyzed = 60;   // 1 minute
static const int kPollIntervalInprogress = 600;  // 10 minute

// InFlux stuff.
static const char* kInfluxDBDefaultHost = "hotel.psc.edu";
static const in_port_t kInfluxDBDefaultPort = 8086;
static const char* kInfluxDBDefaultDB = "xsight";

static const char* kInfluxQueryDBPrefix = "db=";
static const char* kInfluxQueryAnalyzed = "&epoch=ns&q=select%20time%2C%20domain%2C%20dtn%2C%20netname%2C%20type%2C%20flow%2C%20value%20from%20analyzed%20where%20value%3D0%20order%20by%20desc%20limit%20";
static const char* kInfluxQueryMetrics = "&epoch=ns&q=select%20time%2C%20flow%2C%20value%20from%20src_ip%2C%20Timeouts%2C%20DataOctetsIn%2C%20DupAcksIn%20where%20flow%3D%27";
static const char* kInfluxQueryMetricsSuffix = "%27%20order%20by%20desc%20limit%201";

static const int kAnalyzedStatusRequested = 1;  // note, same as
                                                // kSeriesAnalyzedCompleted

static const int kSeriesAnalyzedCompleted = 1;
static const int kSeriesAnalyzedInprogress = 2;
static const int kSeriesAnalyzedNotified = 3;

// Local function declarations.
int parse_command_line(int argc, char* argv[], ConfInfo* info);
void parse_conf_file(ConfInfo* info);
void initiate_unanalyzed_poll(const ConfInfo& info, SSLContext* ssl_context, 
                              list<SSLSession>* to_peers,
                              pthread_mutex_t* to_peers_mtx);
void initiate_flow_data_request(const ConfInfo& info, const string& flow,
                                SSLContext* ssl_context,
                                list<SSLSession>* to_peers,
                                pthread_mutex_t* to_peers_mtx);
void initiate_analyzed_update(const ConfInfo& info,
                              const int update_value, AnalyzedInfo* analyzed,
                              SSLContext* ssl_context,
                              list<SSLSession>* to_peers,
                              pthread_mutex_t* to_peers_mtx);

// Main event-loop routine: The ANALYZER server loads & processes
// some configuration variables and then enters its main event-loop
// waiting on (poll(2)) either for an external initiated connection or
// an internal event signaling that work needs to be done.

int main(int argc, char* argv[]) {
  ConfInfo conf_info;           // daemon configuration information
  list<AnalyzedInfo> analyzed;  // flows identified by DB as not analyzed
  pthread_mutex_t analyzed_mtx;
  list<FlowInfo> flows;         // flows currently active (indexed by flow)
  pthread_mutex_t flow_list_mtx;
  list<SSLSession> to_peers;    // initated connections (to other nodes)
  pthread_mutex_t to_peers_mtx;
  list<SSLSession> from_peers;  // received connections (from accept(2))
  pthread_mutex_t from_peers_mtx;
  vector<pthread_t> thread_list;  // list to keep track of all threads
  pthread_mutex_t thread_list_mtx;
  vector<SSLConn> servers;      // listen sockets, vector used to
                                // handle multple listening ports (we
                                // accept(2) or connect(2) to peers,
                                // though), e.g., IPv4, IPv6, aliases
  SSLContext ssl_context;  // TODO(aka) this should have a mutex too,
                           // as its internal reference will be
                           // incremented in both Accept & Socket, but
                           // SSL_Conn::Socket can occur in a thread,
                           // no?

  // Set default values (can be overridden by user).
  conf_info.log_to_stderr_ = 0;
  conf_info.port_ = kServerPort;
  conf_info.uid_ = getuid();
  conf_info.gid_ = getgid();

  conf_info.database_ = kInfluxDBDefaultHost;
  conf_info.database_port_ = kInfluxDBDefaultPort;
  conf_info.database_db_ = kInfluxDBDefaultDB;
  /*
  conf_info.database_user_ = "dbuser";
  */

  logger.set_proc_name("analyzer");

  pthread_mutex_init(&flow_list_mtx, NULL);
  pthread_mutex_init(&to_peers_mtx, NULL);
  pthread_mutex_init(&from_peers_mtx, NULL);
  pthread_mutex_init(&thread_list_mtx, NULL);

  // Load "user" set-able global variables (ConfInfo) via command line.
  parse_command_line(argc, argv, &conf_info);

#if 0
  // TODO(aka) Setup file logging at some point.
  if (logger.mechanism_level(LOG_TO_FILE)) {
    try {  // t&c for util-local.a
      string* tmp_process_name = 
          new string(process_name(conf_info.Proc_ID()));
      logger.init_file(conf_info.Base_Path(), CONF_DIR, 
                       tmp_process_name->Tolower().Print());
      delete tmp_process_name;
    }
    if (error.Event()) {
      errx(EXIT_FAILURE, "%s", error.print().c_str());
    }
  }

  if (logger.mechanism_level(LOG_TO_SCRIPT))
    logger.init_script(conf_info.Base_Path());

  // It *should* now be safe for file/script logging (if enabled.)
#endif

  // Load configuration file (for additional user set-able globals).
  parse_conf_file(&conf_info);

  //logger.Log(LOG_DEBUGGING, "main(): .", );

  // Make sure we've got all the *key* information that we need.

  // If STDERR logging has *not* been *explicitly* set by the user, 
  // turn off STDERR logging.  Note, however, that if we chose to run
  // in the 'foreground', and no logging was set by the user, then
  // STDERR will be turned back on when we daemonize();

  if (! conf_info.log_to_stderr_)
    logger.clear_mechanism(LOG_TO_STDERR);

  // Setup/initialize SSL.
  // HACK: const char* session_id = process_name(conf_info.Proc_ID());
  const char* session_id = "analyzer-tls";

  // Add check for getuid here; may need to move certs/CAs /etc & config file!
  ssl_context.Init(TLSv1_method(), session_id,
                   NULL, NULL, SSL_FILETYPE_PEM, NULL, // private key
                   NULL, NULL, SSL_FILETYPE_PEM, // host cert
                   NULL, //"/home/pscnoc/analyzer/certsacc06fda.0.pem"
                   "/home/pscnoc/analyzer/certs/",
                   SSL_VERIFY_NONE, 2, SSL_SESS_CACHE_OFF,
                   SSL_OP_CIPHER_SERVER_PREFERENCE);
  if (error.Event())
    errx(EXIT_FAILURE, "%s", error.print().c_str());

  if (!conf_info.v4_enabled_ && !conf_info.v6_enabled_)
    conf_info.v4_enabled_ = true;  // give us something

  // Setup the server's listen socket(s).
#if 0  // TODO(aka) Not sure if we'll need a listening server ...
  if (conf_info.v4_enabled_) {
    SSLConn tmp_server;
    tmp_server.InitServer(AF_INET);  // listen on all IPv4 interfaces
    tmp_server.set_blocking();
    tmp_server.set_close_on_exec();
    tmp_server.Socket(PF_INET, SOCK_STREAM, 0, &ssl_context);
    tmp_server.Bind(conf_info.port_);
    tmp_server.Listen(TCPCONN_DEFAULT_BACKLOG);
    if (error.Event()) {
      logger.Log(LOG_ERROR, "%s, exiting ...", error.print().c_str());
      error.clear();
      exit(EXIT_FAILURE);
    }
    servers.push_back(tmp_server);  // no need to grab MUTEX, as not MT yet
  } 
  if (conf_info.v6_enabled_) {
    SSLConn tmp_server;
    tmp_server.InitServer(AF_INET6);  // listen on all interfaces ...
    tmp_server.set_blocking();
    tmp_server.set_close_on_exec();
    tmp_server.Socket(PF_INET6, SOCK_STREAM, 0, &ssl_context);
    int v6_only = 1;
    tmp_server.Setsockopt(IPPROTO_IPV6, IPV6_V6ONLY, &v6_only, 
                          sizeof(v6_only));  // ... *only* IPv6 interfaces
    tmp_server.Bind(conf_info.port_);
    tmp_server.Listen(TCPCONN_DEFAULT_BACKLOG);
    if (error.Event()) {
      logger.Log(LOG_ERROR, "%s, exiting ...", error.print().c_str());
      error.clear();
      exit(EXIT_FAILURE);
    }
    servers.push_back(tmp_server);  // no need to grab MUTEX, as not MT yet
  }

  logger.Log(LOG_NOTICE, "analyzer (%s) starting on port %hu.", SERVER_VERSION, conf_info.port_);

  // Daemonize program.
  if (getuid() == 0) {
    // Process is running as root, drop privileges.
    if (setgid(conf_info.gid_) != 0)
      err(EX_OSERR, "setgid() failed: %s", strerror(errno));
    if (setuid(conf_info.uid_) != 0)
      err(EX_OSERR, "setuid() failed: %s", strerror(errno));

    // Sanity check ...
    if (setuid(0) != -1)
      err(EX_OSERR, "ERROR: Analyzer managed to re-acquire root privileges!");
  }
#endif

  // Initialze more globals & externals: PRNG, signals
  srandom(time(NULL));  // TODO(aka) We really need to use srandomdev() here!

#if 0
  sig_handler.Init();  // TODO(aka) need to add signal handling
                       // routines (for execv()!)
#endif

  // Any work prior to the main event loop?

  // Setup poll timeout intervals.
  time_t unanalyzed_poll = time(NULL);
  time_t inprogress_poll = time(NULL) + kPollIntervalInprogress;

  unsigned int debug_print_cnt = 0;  // For Debugging:

  // Main event-loop.
  struct pollfd pollfds[SSL_EVENT_MAX_FDS];
  int nfds;             // num file descriptors to poll on
  int timeout = 1000;	// in milliseconds
  int n;                // poll return value
  while (1) {
    // Note, errors that can be returned to our peers (as NACKs) will
    // be processed in analyzer-procs.cc or possibly ssl-event-proces.cc.
    // All other errors will be processed in ssl-event-proces.cc or
    // in here.

    // Load all active sockets into poll(2)'s array.
    nfds = 0;

    // Load *all* our listening sockets (v4 & v6, e.g.) ...
    for (int i = 0; i < (int)servers.size(); i++) {
      pollfds[nfds].fd = servers[i].fd();
      pollfds[nfds].events = POLLIN;  // always listening, always listening ...
      nfds++;
    }

    // Load any fds from any *active* peers.
    nfds = ssl_event_poll_init(to_peers, from_peers, SSL_EVENT_MAX_FDS, 
                               nfds, pollfds);
		
    // Check the fds with poll(2) (or select()).
    n = poll(pollfds, nfds, timeout);

    if (n < 0) {  // check for error
      logger.Log(LOG_DEBUG, "poll() interrupted, errno: %d: %s", 
                 errno, strerror(errno));

      if (errno != EINTR) {  // it's not a signal
        logger.Log(LOG_WARN, "poll() error: %s, returning.", strerror(errno));
      } else {	// it's a signal

        // TODO(aka) Not sure if we should simply check for an
        // un-trapped signal here, or whether we should *actually*
        // process the signal here.
        //
        // TODO(aka) At some point, I thought that NON_BLOCKING calls
        // worked better if we processed the signals at the end of the
        // event loop ...  However, since I can't remember why that
        // was, let's *start* with processing them here!

#if 0
        // TODO(aka) Process signal, *if* we have a handler (see above!).
        if (sig_handler.CheckAll())
          event_signal_check(ssl_context);
#endif
      }

      continue;	 // in any event, head back to start of event-loop
    }	// if (n < 0)

    if (n == 0) {  // check for timeout
      try {  // t&c for debugging
        //logger.Log(LOG_INFO, "poll() timeout, continuing ...");

        time_t now = time(NULL);

        // For Debugging:
        if (debug_print_cnt++ == 0)
          logger.Log(LOG_NOTICE, "main(): TIMEOUT: "
                     "now: %d, unanalyzed poll: %d, inprogress poll: %d,  "
                     "to_peers(%d), analyzed(%d), flows(%d).",
                     (int)now, unanalyzed_poll, inprogress_poll,
                     (int)to_peers.size(), (int)analyzed.size(),
                     (int)flows.size());
        else
          if (debug_print_cnt == 10)
            debug_print_cnt = 0;

        // TIMEOUT-1: See if any of our *read* data in from_peers is complete.
#if DEBUG_MUTEX_LOCK
        warnx("main(timeout): requesting from_peers lock.");
#endif
        pthread_mutex_lock(&from_peers_mtx);  // TODO(aka) what if not threaded?

        list<SSLSession>::iterator from_peer = from_peers.begin();
        while (from_peer != from_peers.end()) {
          // If it's an entire message (according to the headers), process it.
          if (from_peer->IsIncomingMsgComplete()) {
            if (conf_info.multi_threaded_ &&
                !from_peer->IsIncomingMsgBeingProcessed()) {
              // Build struct for function arguments.
              struct analyzer_incoming_msg_args args = {
                &conf_info, &ssl_context, &analyzed, &analyzed_mtx,
                &flows, &flow_list_mtx,
                &to_peers, &to_peers_mtx, from_peer, from_peers.end(), 
                &thread_list, &thread_list_mtx,
              };

              // Create thread, store ID, and process message concurrently.
              pthread_t tid;
              pthread_create(&tid, NULL, 
                             &analyzer_concurrent_process_incoming_msg,
                             (void*)&args);
              pthread_mutex_lock(&thread_list_mtx);
              thread_list.push_back(tid);
              pthread_mutex_unlock(&thread_list_mtx);

              logger.Log(LOG_DEBUG, "main(timeout): "
                         "thread %d assigned to peer: %s.",
                         tid, from_peer->print().c_str());
            } else if (!conf_info.multi_threaded_) {
              // Process message single threaded.
              analyzer_process_incoming_msg(&conf_info, &ssl_context,
                                            &analyzed, &analyzed_mtx,
                                            &flows, &flow_list_mtx,
                                            &to_peers, &to_peers_mtx, from_peer);
              if (error.Event()) {
                // Note, if we reached here, then we could not NACK the
                // error we encountered processing the message in
                // analyzer-procs.cc.

                logger.Log(LOG_ERR, "main(): from_peer processing error: %s", 
                           error.print().c_str());
                from_peer = from_peers.erase(from_peer);
                error.clear();
#if DEBUG_MUTEX_LOCK
                warnx("main(timeout): releasing from_peers lock.");
#endif
                pthread_mutex_unlock(&from_peers_mtx);
                continue;  // start processing next peer
              }
            }  // } else if (!conf_info.multi_threaded_) {

            // Head back while(from_peer) to give
            // analyzer_process_incoming_msg() time to update peer's
            // meta-data.

#if DEBUG_MUTEX_LOCK
            warnx("main(timeout): releasing from_peers lock.");
#endif
            pthread_mutex_unlock(&from_peers_mtx);
            from_peer++;
            continue;  // start processing next peer
          }  // if (from_peer->IsIncomingMsgComplete()) {

          // Note, we don't check for non-initiated connections, as we
          // assume senders would be using to_peers.

          //logger.Log(LOG_INFO, "main(timeout): checking peer: %s, thread list: %d.", from_peer->print().c_str(), thread_list.size());
          
          // Finally, see if this peer should be removed.  Note, if
          // the connection to from_peers is closed, the game is
          // already over ...

          if (!from_peer->IsConnected() ||  
              (!from_peer->IsOutgoingDataPending() &&
               !from_peer->rbuf_len() && 
               !from_peer->IsIncomingMsgInitialized())) {
            // Make sure, if we're multi-threaded, that the thread
            // isn't still running.

            if (conf_info.multi_threaded_) {
              bool found = false;
              for (vector<pthread_t>::iterator tid = thread_list.begin();
                   tid != thread_list.end(); tid++) {
                if (*tid == from_peer->rtid()) {
                  found = true;
                  break;
                }
              }
              if (found) {
                logger.Log(LOG_DEBUG, "main(timeout): can't remove peer: %s, "
                           "thread still active.", 
                           from_peer->print().c_str());
                from_peer++;
              } else {
                if (from_peer->IsOutgoingDataPending())
                  logger.Log(LOG_WARN, "Removing peer %s, "
                             "even though a response is pending.", 
                             from_peer->print().c_str());
                else
                  logger.Log(LOG_DEBUG, "main(timeout): Removing peer %s.", 
                             from_peer->print().c_str());
                from_peer = from_peers.erase(from_peer);
              }
            } else {
              logger.Log(LOG_DEBUG, "main(timeout): Removing peer %s.", 
                         from_peer->print().c_str());
              from_peer = from_peers.erase(from_peer);
            }

#if DEBUG_MUTEX_LOCK
            warnx("main(timeout): releasing from_peers lock.");
#endif
            pthread_mutex_unlock(&from_peers_mtx);
            continue;  // head back to while()
          }  // if (!from_peer->IsConnected() ||  

          /*
          // TODO(aka) Spot for final check to see if something whet wrong ...
          if (!from_peer->IsIncomingMsgInitialized() && 
              from_peer->rbuf_len() > 0) {
            // Something went wrong, report the error and remove the peer.
            logger.Log(LOG_ERR, "main(): "
                       "peer (%s) has data in timeout, but not initialized!",
                       from_peer->print().c_str());
            from_peer = from_peers.erase(from_peer);
#if DEBUG_MUTEX_LOCK
            warnx("main(): releasing from_peers lock.");
#endif
            pthread_mutex_unlock(&from_peers_mtx);
            continue;  // head back to while()
          } 
          */

          from_peer++;
        }  // while (from_peer != from_peers.end()) {

#if DEBUG_MUTEX_LOCK
        warnx("main(timeout): releasing from_peers lock.");
#endif
        pthread_mutex_unlock(&from_peers_mtx);


        // TIMEOUT-2: See if any of our *read* data in to_peers is complete.
#if DEBUG_MUTEX_LOCK
        warnx("main(timeout): requesting to_peers lock.");
#endif
        pthread_mutex_lock(&to_peers_mtx);
        list<SSLSession>::iterator to_peer = to_peers.begin();
        while (to_peer != to_peers.end()) {
          // If it's an entire message (according to the headers), process it.
          if (to_peer->IsIncomingMsgComplete()) {

            // TODO(aka) Note, we currently process all *initiated*
            // connections within analyzer-procs as sequential, blocking
            // processes.  When we decide to move away from that,
            // we'll need to setup our multi-threading processing here
            // (as we did with from_peers).

            // Process message single threaded.
            analyzer_process_incoming_msg(&conf_info, &ssl_context,
                                          &analyzed, &analyzed_mtx,
                                          &flows, &flow_list_mtx,
                                          &to_peers, &to_peers_mtx, to_peer);
            if (error.Event()) {
              // Note, if we reached here, then we could not NACK the
              // error we encountered processing the message in
              // analyzer-procs.cc.

              logger.Log(LOG_ERR, "main(): to_peer processing error: %s",
                         error.print().c_str());
              to_peer = to_peers.erase(to_peer);
              error.clear();

#if DEBUG_MUTEX_LOCK
              warnx("main(timeout): releasing to_peers lock.");
#endif
              pthread_mutex_unlock(&to_peers_mtx);
              continue;  // head back to while()
            }

            // Head back to while(to_peer) to give
            // analyzer_proccess_incoming_msg() time to update peer's
            // meta-data.

#if DEBUG_MUTEX_LOCK
            warnx("main(timeout): releasing to_peers lock.");
#endif
            pthread_mutex_unlock(&to_peers_mtx);
            to_peer++;
            continue;
          }  // if (to_peer->IsIncomingMsgComplet()) {

          // See if we need to initiate a connection.
          if (to_peer->wbuf_len() && 
              to_peer->IsOutgoingDataPending() && 
              !to_peer->IsConnected()) {
            to_peer->Connect();
            if (error.Event()) {
              // Bleh.  Can't connect.
              logger.Log(LOG_ERR, "main(timeout): "
                         "Unable to connect to %s: %s", 
                         to_peer->print().c_str(), error.print().c_str());
              // peer->PopOutgoingMsgQueue();  // can't send, so pop message
              to_peer = to_peers.erase(to_peer);  // to_peers is not MT
              error.clear();
     
#if DEBUG_MUTEX_LOCK
              warnx("main(timeout): releasing to_peers lock.");
#endif
              pthread_mutex_unlock(&to_peers_mtx);
              continue;  // head back to while()
            } 
          }

        if (debug_print_cnt == 0)
          logger.Log(LOG_DEBUG, "main(timeout): checking if to_peer: %s, can be removed (IsConnected, IsOutgoingDataPending, rbuf_len, IsIncomingMsgInitialized): %d, %d, %d, %d.", to_peer->print().c_str(), to_peer->IsConnected(), to_peer->IsOutgoingDataPending(), (int)to_peer->rbuf_len(), to_peer->IsIncomingMsgInitialized());

          // Finally, see if this peer should be removed.
          if (!to_peer->IsConnected() && 
              !to_peer->IsOutgoingDataPending() &&
              !to_peer->rbuf_len() && 
              !to_peer->IsIncomingMsgInitialized()) {
            if (conf_info.multi_threaded_) {
              bool found = false;
              for (vector<pthread_t>::iterator tid = thread_list.begin();
                   tid != thread_list.end(); tid++) {
                if (*tid == to_peer->rtid()) {
                  found = true;
                  break;
                }
              }
              if (found) {
                logger.Log(LOG_DEBUG, "main(timeout): can't remove peer: %s, "
                           "thread still active.", 
                           to_peer->print().c_str());
                to_peer++;
              } else {
                logger.Log(LOG_DEBUG, "main(timeout): Removing peer %s.",
                           to_peer->print().c_str());
                to_peer = to_peers.erase(to_peer);
              }
            } else {
              logger.Log(LOG_DEBUG, "main(timeout): Removing peer %s.",
                         to_peer->print().c_str());
              to_peer = to_peers.erase(to_peer);
            }

            // Skip to next peer.
#if DEBUG_MUTEX_LOCK
            warnx("main(timeout): releasing to_peers lock.");
#endif
            pthread_mutex_unlock(&to_peers_mtx);
            continue;
          }

          /*
          // TODO(aka) Spot for final check to see if something whet wrong ...
          if (!to_peer->IsIncomingMsgInitialized() && 
              to_peer->rbuf_len() > 0) {
            // Something went wrong, report the error and remove the peer.
            logger.Log(LOG_ERR, "main(): "
                       "peer (%s) has data in timeout, but not initialized!",
                       to_peer->print().c_str());
            to_peer = to_peers.erase(to_peer);
#if DEBUG_MUTEX_LOCK
            warnx("main(): releasing to_peers lock.");
#endif
            pthread_mutex_unlock(&to_peers_mtx);
            continue;  // head back to while()
          } 
          */

          to_peer++;
        }  // while (to_peer != to_peers.end()) {

#if DEBUG_MUTEX_LOCK
        warnx("main(timeout): releasing to_peers lock.");
#endif
        pthread_mutex_unlock(&to_peers_mtx);


        // TIMEOUT-3: See if we should request some unanalyzed flows.
        if (unanalyzed_poll <= now) {
          initiate_unanalyzed_poll(conf_info, &ssl_context,
                                   &to_peers, &to_peers_mtx);
          if (error.Event()) {
            logger.Log(LOG_ERR, "Failed to initialize peer: %s", 
                       error.print().c_str());
            error.clear();
          }

          unanalyzed_poll += kPollIntervalUnanalyzed;
        }  // if (unanalyzed_poll <= now) {


        // TIMEOUT-4: Initiate request(s) for unanalyzed flow meta-data.
#if DEBUG_MUTEX_LOCK
        warnx("main(timeout): requesting analyzed lock.");
#endif
        pthread_mutex_lock(&analyzed_mtx);

        list<AnalyzedInfo>::iterator analyzed_itr = analyzed.begin();
        while (analyzed_itr != analyzed.end()) {
          if (analyzed_itr->status_ == 0) {
            // Request flow meta-data for unanalyzed flow.
            initiate_flow_data_request(conf_info, analyzed_itr->flow_, 
                                       &ssl_context, &to_peers, &to_peers_mtx);
            if (error.Event()) {
              logger.Log(LOG_ERR, "Failed to initialize peer: %s", 
                         error.print().c_str());
              error.clear();
            } else {
              analyzed_itr->status_ = kAnalyzedStatusRequested;  // mark true
            }
          }
          analyzed_itr++;
        }

#if DEBUG_MUTEX_LOCK
        warnx("main(timeout): releasing analyzed lock.");
#endif
        pthread_mutex_unlock(&analyzed_mtx);


        // TIMEOUT-5: Analyze (unanalyzed) flow data.
#if DEBUG_MUTEX_LOCK
        warnx("main(timeout): requesting flow list lock.");
#endif
        pthread_mutex_lock(&flow_list_mtx);

        list<FlowInfo>::iterator flow_itr = flows.begin();
        while (flow_itr != flows.end()) {
          // Get the AnalyzedInfo for this flow (since we'll need it
          // to update InFlux regardless).

#if DEBUG_MUTEX_LOCK
          warnx("main(timeout): requesting analyzed lock.");
#endif
          pthread_mutex_lock(&analyzed_mtx);

          list<AnalyzedInfo>::iterator analyzed_itr = analyzed.begin();
          while (analyzed_itr != analyzed.end()) {
            if (!analyzed_itr->flow_.compare(flow_itr->flow_))
              break;

            analyzed_itr++;
          }
          if (analyzed_itr == analyzed.end())
            logger.Log(LOG_ERR, "main(): TODO(aka) "
                       "Unable to find %s in analyzed (%d).",
                       flow_itr->flow_.c_str(), (int)analyzed.size());

          logger.Log(LOG_INFO, "main(): "
                     "Checking flow %s (SrcIP, DupAcksIn, Timeouts): "
                     "%s, %d, %d.", 
                     flow_itr->flow_.c_str(), flow_itr->src_ip_.c_str(), 
                     flow_itr->DupAcksIn_, flow_itr->Timeouts_);

          // ANALYZER: Just performing very simple tests here!
          // TODO(aka) Eventually, we want to look at the number of
          // timeouts/dupacks as a percentage of segments (perhaps use
          // Matt's value showing the effect of loss based on MTU &
          // segements).

          if (flow_itr->DupAcksIn_ > 0 || flow_itr->Timeouts_ > 0) {
            // Send e-mail NOC.
            static const char* mail = "/usr/bin/mail";
            static const char* arg1 = "-s Analyzer Positive";
            static const char* arg2 = "akadams@psc.edu";

            pid_t fork_pid;
            if ((fork_pid = fork()) < 0) {
              logger.Log(LOG_ERR, "main(): fork() failed: %s", strerror(errno));
            } else if (fork_pid == 0) {
              // We are the child!
              printf("DEBUG: XXX Executing: %s %s %s\n", mail, arg1, arg2);

              // Call mail.
              if ((execl(mail, arg1, arg2, (char*)NULL)) == -1)
                err(EXIT_FAILURE, "main(): execl() failed: ");
            }

            // Update analyzed series for flow to NOTIFIED.
            initiate_analyzed_update(conf_info, kSeriesAnalyzedNotified,
                                     &(*analyzed_itr), &ssl_context,
                                     &to_peers, &to_peers_mtx);
            if (error.Event()) {
              logger.Log(LOG_ERR, "Failed to initialize peer: %s", 
                         error.print().c_str());
              error.clear();
            }

            // Remove from analyzed & flows.  TODO(aka) We may want to
            // simply mark each for deletion, and then clean them up
            // in TIMEOUT-7?

            printf("XXX deleting analyzed & flow for %s.  TODO(aka) mark & wait?\n", analyzed_itr->flow_.c_str());
            // analyzed_itr->status_ = kSeriesAnalyzedNotified;
            analyzed.erase(analyzed_itr);
            flow_itr = flows.erase(flow_itr);
          } else {
            if (flow_itr->end_time_ <= 0) {
              // Update analyzed series for flow to INPROGRESS.
              initiate_analyzed_update(conf_info, kSeriesAnalyzedInprogress,
                                       &(*analyzed_itr), &ssl_context,
                                       &to_peers, &to_peers_mtx);
              if (error.Event()) {
                logger.Log(LOG_ERR, "Failed to initialize peer: %s", 
                           error.print().c_str());
                error.clear();
              } else {
                analyzed_itr->status_ = kSeriesAnalyzedInprogress;
              }
            } else {
              // Update analyzed series for flow to COMPLETED.
              initiate_analyzed_update(conf_info, kSeriesAnalyzedCompleted,
                                       &(*analyzed_itr), &ssl_context,
                                       &to_peers, &to_peers_mtx);
              if (error.Event()) {
                logger.Log(LOG_ERR, "Failed to initialize peer: %s", 
                           error.print().c_str());
                error.clear();
              }

              // Remove from analyzed & flows.  TODO(aka) We may want to
              // simply mark each for deletion, and then clean them up
              // in TIMEOUT-7?

              printf("XXX deleting analyzed & flow for %s.  TODO(aka) mark & wait?\n", analyzed_itr->flow_.c_str());
              // analyzed_itr->status_ = kSeriesAnalyzedCompleted;
              analyzed.erase(analyzed_itr);
              flow_itr = flows.erase(flow_itr);
            }
          }

#if DEBUG_MUTEX_LOCK
          warnx("main(timeout): releasing analyzed lock.");
#endif
          pthread_mutex_unlock(&analyzed_mtx);

          flow_itr++;
        }

#if DEBUG_MUTEX_LOCK
        warnx("main(timeout): releasing flow list lock.");
#endif
        pthread_mutex_unlock(&flow_list_mtx);


        // TIMEOUT-6: Initiate request(s) for INPROGRESS updated meta-data.
        if (inprogress_poll <= now) {
#if DEBUG_MUTEX_LOCK
          warnx("main(timeout): requesting analyzed lock.");
#endif
          pthread_mutex_lock(&analyzed_mtx);

          // Look for any INPROGRESS flows.
          list<AnalyzedInfo>::iterator analyzed_itr = analyzed.begin();
          while (analyzed_itr != analyzed.end()) {
            if (analyzed_itr->status_ == kSeriesAnalyzedInprogress) {
              // Request flow meta-data for inprogress flow.
              initiate_flow_data_request(conf_info, analyzed_itr->flow_, 
                                         &ssl_context, &to_peers, &to_peers_mtx);
              if (error.Event()) {
                logger.Log(LOG_ERR, "Failed to initialize peer: %s", 
                           error.print().c_str());
                error.clear();
              }
            }
            
            analyzed_itr++;
          }

#if DEBUG_MUTEX_LOCK
          warnx("main(timeout): releasing analyzed lock.");
#endif
          pthread_mutex_unlock(&analyzed_mtx);

          inprogress_poll += kPollIntervalInprogress;
        }  // if (inprogress_poll <= now) {


        // TIMEOUT-7: Clean-up flow & analyzed lists.
        if (analyzed.size() || flows.size())
          logger.Log(LOG_NOTICE, "main(): Need to add clean-up work, analyzed(%d), flows(%d).", analyzed.size(), flows.size());

#if DEBUG_MUTEX_LOCK
        warnx("main(timeout): requesting analyzed lock.");
#endif
        pthread_mutex_lock(&analyzed_mtx);

#if 0
        list<AnalyzedInfo>::iterator analyzed_itr = analyzed.begin();
        while (analyzed_itr != analyzed.end()) {
          if (analyzed_itr->status_ == 0) {
            // Add some work here!  (And repeat for flows!)
          }
          analyzed_itr++;
        }
#endif

#if DEBUG_MUTEX_LOCK
        warnx("main(timeout): releasing analyzed lock.");
#endif
        pthread_mutex_unlock(&analyzed_mtx);

#if DEBUG_MUTEX_LOCK
        warnx("main(timeout): requesting flow list lock.");
#endif
        pthread_mutex_lock(&flow_list_mtx);

#if DEBUG_MUTEX_LOCK
        warnx("main(timeout): releasing flow list lock.");
#endif
        pthread_mutex_unlock(&flow_list_mtx);

      } catch (...) {
        logger.Log(LOG_ERR, "main(): "
                   "Unexpected exception thrown during TIMEOUT proccessing.");
      }

      continue;  // head back to poll()
    }  // if (n == 0) {

    // Must have (at least) one ready fd.

    //logger.Log(LOG_DEBUGGING, "poll() fired, num ready: %d", n);

    int i = 0;  // index into pollfds[] array

    // First, check our listen socket(s), i.e.,
    // pollfds[0..(servers.size()-1)] ...

    for (int j = 0; j < (int)servers.size(); j++) {
      if (pollfds[j].revents && pollfds[j].revents & POLLIN) {
        try {  // t&c for debugging
#if DEBUG_MUTEX_LOCK
          warnx("main(listen): requesting from_peers lock.");
#endif
          pthread_mutex_lock(&from_peers_mtx);

          // As we haven't added anything to from_peers yet, we handle
          // all errors internally in ssl_event_accept().

          ssl_event_accept(conf_info, servers[j], kMaxPeers, kFramingType,
                           &ssl_context, &from_peers);
#if DEBUG_MUTEX_LOCK
          warnx("main(listen): releasing from_peers lock.");
#endif
          pthread_mutex_unlock(&from_peers_mtx);

        } catch (...) {
          logger.Log(LOG_ERR, "main(): "
                     "Unexpected exception thrown in listen socket POLLIN "
                     "proccessing.");
        }

        n--;
      } else if (pollfds[j].revents) {
        logger.Log(LOG_WARN, "Server[%d]: %d, revents: %d, continuing ...",
                   j, pollfds[j].fd, pollfds[j].revents);
        n--;
      }
    }

    i = servers.size();  // remember that "i = 0" is the first listen socket

    // Now, check the rest of the fds ...
    while (n > 0) {

      // Note, under OSX, poll() returns the *number of events*, not
      // the number of ready file descriptors like the man page says.
      // Big difference if and when a single fd has both read and
      // write ready data on it!

      // TODO(aka) If any other O/S do this, as well, then we'll
      // change the code to decrement n after every event.

      //logger.Log(LOG_INFO, "main(event): Processing event %d, total left: %d.", i, n);

      int tmp_i = i;  // For Debugging ...
      if ((i = ssl_event_poll_status(pollfds, nfds, i)) < 0) {
        logger.Log(LOG_ERROR, "ssl_event_poll_status() failed, "
                   "nfds = %d, i = %d, prev i = %d, n = %d.", 
                   nfds, i, tmp_i, n);
        break;
      }

      // Check POLLIN first ...
      if (pollfds[i].revents & POLLIN) {
        try {  // t&c for debugging
          // Check to_peers for our fd (first grab lock!) ...
#if DEBUG_MUTEX_LOCK
          warnx("main(POLLIN): requesting to_peers lock.");
#endif
          pthread_mutex_lock(&to_peers_mtx);
          list<SSLSession>::iterator peer =
              ssl_event_poll_get_peer(conf_info, pollfds[i].fd, &to_peers);
          if (peer != to_peers.end()) {
            // Slurp up the waiting data, and initialize (if not yet).
            ssl_event_read(conf_info, peer);
            // ssl_event_read(conf_info, &(*peer));  // note, iterator hack

            if (!peer->IsIncomingMsgInitialized()) {
              peer->InitIncomingMsg();
              //logger.Log(LOG_INFO, "main(POLLIN): post-init to_peer: %s.", peer->print().c_str());
            }
            if (error.Event()) {
              logger.Log(LOG_ERR, "main(POLLIN): "
                         "Unable to read incoming data from %s: %s.",
                         peer->print().c_str(), error.print().c_str());
              to_peers.erase(peer);  // to_peers is not multi-threaded
              error.clear();

              // Fall-through to release locks.
            } else {
#if CLIENT_CONNECTION
#endif
            }

            // Since we have to release our to_peers lock prior to
            // grabbing our from_peers lock, we also need to release it
            // here, in this equivalent nested branch.

#if DEBUG_MUTEX_LOCK
            warnx("main(POLLIN): releasing to_peers lock.");
#endif
            pthread_mutex_unlock(&to_peers_mtx);
          } else {  // if (peer != to_peers.end()) {
            // Grab from_peers lock (first, relase to_peers lock).
#if DEBUG_MUTEX_LOCK
            warnx("main(POLLIN): releasing to_peers lock.");
#endif
            pthread_mutex_unlock(&to_peers_mtx);

#if DEBUG_MUTEX_LOCK
            warnx("main(POLLIN): requesting from_peers lock.");
#endif
            pthread_mutex_lock(&from_peers_mtx);
            peer = 
                ssl_event_poll_get_peer(conf_info, pollfds[i].fd, &from_peers);
            if (peer == from_peers.end()) {
              logger.Log(LOG_ERR, "main(POLLIN): "
                         "Unable to find peer for file descriptor: %d",
                         pollfds[i].fd);
              // Fall-through to continue processing pollfds[] vector.
            } else {  // if (peer == from_peers.end()) {
              // Slurp up the waiting data, and initialize (if not yet).
              ssl_event_read(conf_info, peer);
              // ssl_event_read(conf_info, &(*peer));  // note, iterator hack

              if (!peer->IsIncomingMsgInitialized())
                peer->InitIncomingMsg();
              if (error.Event()) {
                logger.Log(LOG_ERR, "main(POLLIN): "
                           "unable to read incoming data from %s: %s.",
                           peer->print().c_str(), error.print().c_str());
                from_peers.erase(peer);  // threading should not have occured
                error.clear();
              }
            }  // else (peer == from_peers.end()) {
#if DEBUG_MUTEX_LOCK
            warnx("main(POLLIN): releasing from_peers lock.");
#endif
            pthread_mutex_unlock(&from_peers_mtx);
          }  // else (peer != to_peers.end()) {

          // Interestingly, from this point on we can report all ERRORS
          // *remotely* via NACKs, as we *know* we can read correctly read the
          // framing protocol over the socket.  Moreover, we'll be able to
          // read an EOF, *if* the remote end decides to shutdown the
          // connection after receiving our NACK + error message.

        } catch (...) {
          logger.Log(LOG_ERR, "main(): "
                     "Unexpected exception thrown during POLLIN proccessing.");
        }
      }  // if (pollfds[i].revents & POLLIN) {

      // ... then check POLLOUT.
      if (pollfds[i].revents & POLLOUT) {
        try {  // t&c for debugging
          // Check to_peers for our fd (first grab lock!) ...
#if DEBUG_MUTEX_LOCK
          warnx("main(POLLOUT): requesting to_peers lock.");
#endif
          pthread_mutex_lock(&to_peers_mtx);
          list<SSLSession>::iterator peer =
              ssl_event_poll_get_peer(conf_info, pollfds[i].fd, &to_peers);
          if (peer != to_peers.end()) {
            // Write a chunk of data out the waiting socket.
            ssl_event_write(conf_info, peer);
            if (error.Event()) {
              logger.Log(LOG_ERR, "main(POLLOUT): "
                         "Unable to write data to %s: %s.",
                         peer->print().c_str(), error.print().c_str());
              to_peers.erase(peer);  // no threading on to_peers
              error.clear();
            } else if (peer->IsOutgoingMsgSent()) {
              peer->PopOutgoingMsgQueue();  // clean up first pending message
              if (error.Event()) {
                logger.Log(LOG_ERR, "main(POLLOUT): "
                           "Failed to clear outgoing msg queue to %s: %s", 
                           peer->print().c_str(), error.print().c_str());
                to_peers.erase(peer);  // no threading on to_peers
                error.clear();
              }
            }

            // Since we have to release our to_peers lock prior to
            // grabbing our from_peers lock, we also need to release it
            // here, in this equivalent nested branch.

#if DEBUG_MUTEX_LOCK
            warnx("main(POLLOUT): releasing to_peers lock.");
#endif
            pthread_mutex_unlock(&to_peers_mtx);
          } else {  // if (peer != to_peers.end()) {
            // Grab from_peers lock (first, relase to_peers lock).
#if DEBUG_MUTEX_LOCK
            warnx("main(POLLOUT): releasing to_peers lock.");
#endif
            pthread_mutex_unlock(&to_peers_mtx);

#if DEBUG_MUTEX_LOCK
            warnx("main(POLLOUT): requesting from_peers lock.");
#endif
            pthread_mutex_lock(&from_peers_mtx);
            peer = 
                ssl_event_poll_get_peer(conf_info, pollfds[i].fd, &from_peers);
            if (peer == from_peers.end()) {
              logger.Log(LOG_ERR, "main(POLLOUT): "
                         "Unable to find peer for file descriptor: %d",
                         pollfds[i].fd);
              // Fall-through to continue processing pollfds[] vector.
            } else {  // if (peer == from_peers.end()) {
              // Write a chunk of data out the waiting socket.
              ssl_event_write(conf_info, peer);
              if (error.Event()) {
                logger.Log(LOG_ERR, "main(POLLOUT): "
                           "Unable to write data to %s: %s.",
                           peer->print().c_str(), error.print().c_str());
                if (peer->rtid() == TCPSESSION_THREAD_NULL)
                  from_peers.erase(peer);
                error.clear();
              } else if (peer->IsOutgoingMsgSent()) {
                peer->PopOutgoingMsgQueue();  // clean up first pending message
                if (error.Event()) {
                  logger.Log(LOG_ERR, "main(POLLOUT): "
                             "Failed to clear outgoing msg queue to %s: %s", 
                             peer->print().c_str(), error.print().c_str());
                  if (peer->rtid() == TCPSESSION_THREAD_NULL)
                    from_peers.erase(peer);
                  error.clear();
                }
              }
            }  // else (peer == from_peers.end()) {
#if DEBUG_MUTEX_LOCK
            warnx("main(POLLOUT): releasing from_peers lock.");
#endif
            pthread_mutex_unlock(&from_peers_mtx);
          }  // else (peer != to_peers.end()) {
        } catch (...) {
          logger.Log(LOG_ERR, "main(): "
                     "Unexpected exception thrown during POLLOUT proccessing.");
        }
      }  // if (pollfds[i].revents & POLLOUT) {

      // ERROR conditions ...
      if (pollfds[i].revents & POLLERR) {
        try {  // t&c for debugging
          // Check to_peers for our fd (first grab lock!) ...
#if DEBUG_MUTEX_LOCK
          warnx("main(): requesting to_peers lock.");
#endif
          pthread_mutex_lock(&to_peers_mtx);
          list<SSLSession>::iterator peer =
              ssl_event_poll_get_peer(conf_info, pollfds[i].fd, &to_peers);
          if (peer != to_peers.end()) {
            // Report the error and remove the peer.
            logger.Log(LOG_ERR, "main(): "
                       "Peer (%s) returned POLLERR on socket %d.",
                       peer->print().c_str(), pollfds[i].fd);
            to_peers.erase(peer);  // to_peers is not multi-threaded

            // Since we have to release our to_peers lock prior to
            // grabbing our from_peers lock, we also need to release it
            // here, in this equivalent nested branch.

#if DEBUG_MUTEX_LOCK
            warnx("main(): releasing to_peers lock.");
#endif
            pthread_mutex_unlock(&to_peers_mtx);
          } else {  // if (peer != to_peers.end()) {
            // Grab from_peers lock (first, relase to_peers lock).
#if DEBUG_MUTEX_LOCK
            warnx("main(): releasing to_peers lock.");
#endif
            pthread_mutex_unlock(&to_peers_mtx);

#if DEBUG_MUTEX_LOCK
            warnx("main(): requesting from_peers lock.");
#endif
            pthread_mutex_lock(&from_peers_mtx);
            peer = 
                ssl_event_poll_get_peer(conf_info, pollfds[i].fd, &from_peers);
            if (peer == from_peers.end()) {
              logger.Log(LOG_ERR, "main(): "
                         "Unable to find peer for file descriptor: %d",
                         pollfds[i].fd);
              // Fall-through to continue processing pollfds[] vector.
            } else {  // if (peer == from_peers.end()) {
              // Report the error and remove the peer.
              logger.Log(LOG_ERR, "main(): "
                         "Peer (%s) returned POLLERR on socket %d.",
                         peer->print().c_str(), pollfds[i].fd);
              if (peer->rtid() == TCPSESSION_THREAD_NULL)
                from_peers.erase(peer);
            }  // else (peer == from_peers.end()) {
#if DEBUG_MUTEX_LOCK
            warnx("main(): releasing from_peers lock.");
#endif
            pthread_mutex_unlock(&from_peers_mtx);
          }  // else (peer != to_peers.end()) {
        } catch (...) {
          logger.Log(LOG_ERR, "main(): "
                     "Unexpected exception thrown during POLLERR proccessing.");
        }
      }  // if (pollfds[i].revents & POLLERR) {
				
      if (pollfds[i].revents & POLLHUP) {
        try {  // t&c for debugging
          // Check to_peers for our fd (first grab lock!) ...
#if DEBUG_MUTEX_LOCK
          warnx("main(): requesting to_peers lock.");
#endif
          pthread_mutex_lock(&to_peers_mtx);
          list<SSLSession>::iterator peer =
              ssl_event_poll_get_peer(conf_info, pollfds[i].fd, &to_peers);
          if (peer != to_peers.end()) {
            // If peer is still connected, report the genuine error.
            if (peer->IsConnected()) {
              logger.Log(LOG_ERR, "main(): "
                         "Peer (%s) returned POLLHUP on socket %d.",
                         peer->print().c_str(), pollfds[i].fd);
              to_peers.erase(peer);  // to_peers is not multi-threaded
            }

            // Since we have to release our to_peers lock prior to
            // grabbing our from_peers lock, we also need to release it
            // here, in this equivalent nested branch.

#if DEBUG_MUTEX_LOCK
            warnx("main(): releasing to_peers lock.");
#endif
            pthread_mutex_unlock(&to_peers_mtx);
          } else {  // if (peer != to_peers.end()) {
            // Grab from_peers lock (first, relase to_peers lock).
#if DEBUG_MUTEX_LOCK
            warnx("main(): releasing to_peers lock.");
#endif
            pthread_mutex_unlock(&to_peers_mtx);

#if DEBUG_MUTEX_LOCK
            warnx("main(): requesting from_peers lock.");
#endif
            pthread_mutex_lock(&from_peers_mtx);
            peer = 
                ssl_event_poll_get_peer(conf_info, pollfds[i].fd, &from_peers);
            if (peer == from_peers.end()) {
              logger.Log(LOG_ERR, "main(): "
                         "Unable to find peer for file descriptor: %d",
                         pollfds[i].fd);
              // Fall-through to continue processing pollfds[] vector.
            } else {  // if (peer == from_peers.end()) {
              // If peer is still connected, report the genuine error.
              if (peer->IsConnected()) {
                logger.Log(LOG_ERR, "main(): "
                           "Peer (%s) returned POLLHUP on socket %d.",
                           peer->print().c_str(), pollfds[i].fd);
                if (peer->rtid() == TCPSESSION_THREAD_NULL)
                  from_peers.erase(peer);
              }
            }  // else (peer == from_peers.end()) {
#if DEBUG_MUTEX_LOCK
            warnx("main(): releasing from_peers lock.");
#endif
            pthread_mutex_unlock(&from_peers_mtx);
          }  // else (peer != to_peers.end()) {

        } catch (...) {
          logger.Log(LOG_ERR, "main(): "
                     "Unexpected exception thrown during POLLHUP proccessing.");
        }
      }  // if (pollfds[i].revents & POLLHUP) {
				
      if (pollfds[i].revents & POLLNVAL) {
        try {  // t&c for debugging
          // Check to_peers for our fd (first grab lock!) ...
#if DEBUG_MUTEX_LOCK
          warnx("main(): requesting to_peers lock.");
#endif
          pthread_mutex_lock(&to_peers_mtx);
          list<SSLSession>::iterator peer =
              ssl_event_poll_get_peer(conf_info, pollfds[i].fd, &to_peers);
          if (peer != to_peers.end()) {
            // Report the error and remove the peer.
            logger.Log(LOG_ERR, "main(): "
                       "Peer (%s) returned POLLNVAL on socket %d.",
                       peer->print().c_str(), pollfds[i].fd);
            to_peers.erase(peer);  // to_peers is not multi-threaded

            // Since we have to release our to_peers lock prior to
            // grabbing our from_peers lock, we also need to release it
            // here, in this equivalent nested branch.

#if DEBUG_MUTEX_LOCK
            warnx("main(): releasing to_peers lock.");
#endif
            pthread_mutex_unlock(&to_peers_mtx);
          } else {  // if (peer != to_peers.end()) {
            // Grab from_peers lock (first, relase to_peers lock).
#if DEBUG_MUTEX_LOCK
            warnx("main(): releasing to_peers lock.");
#endif
            pthread_mutex_unlock(&to_peers_mtx);

#if DEBUG_MUTEX_LOCK
            warnx("main(): requesting from_peers lock.");
#endif
            pthread_mutex_lock(&from_peers_mtx);
            peer = 
                ssl_event_poll_get_peer(conf_info, pollfds[i].fd, &from_peers);
            if (peer == from_peers.end()) {
              logger.Log(LOG_ERR, "main(): "
                         "Unable to find peer for file descriptor: %d",
                         pollfds[i].fd);
              // Fall-through to continue processing pollfds[] vector.
            } else {  // if (peer == from_peers.end()) {
              // Report the error and remove the peer.
              logger.Log(LOG_ERR, "main(): "
                         "Peer (%s) returned POLLNVAL on socket %d.",
                         peer->print().c_str(), pollfds[i].fd);
              if (peer->rtid() == TCPSESSION_THREAD_NULL)
                from_peers.erase(peer);
            }  // else (peer == from_peers.end()) {
#if DEBUG_MUTEX_LOCK
            warnx("main(): releasing from_peers lock.");
#endif
            pthread_mutex_unlock(&from_peers_mtx);
          }  // else (peer != to_peers.end()) {
        } catch (...) {
          logger.Log(LOG_ERR, "main(): "
                     "Unexpected exception thrown during POLLNVAL proccessing.");
        }
      }  // if (pollfds[i].revents & POLLNVAL) {

      // Check for *other* events ...
      if (pollfds[i].revents & POLLPRI ||
          pollfds[i].revents & POLLRDNORM ||
          pollfds[i].revents & POLLRDBAND ||
          pollfds[i].revents & POLLWRBAND) {
        logger.Log(LOG_WARN, "Received event: %d, on fd: %d, "
                   "unable to process, continuing ...",
                   pollfds[i].revents, pollfds[i].fd);
      }

      // We processed something, bump counters.
      i++;
      n--;
    }  // while (n > 0)

    // And finally, after processing *all* the ready fds, check 
    // for signals.

#if 0
    // TODO(aka) Add signal checking!
    event_signal_check();
#endif
  }  // while (1)

  // Clean up.

  return 0;
}

// Main utility functions.

// Routine to print out "usage" information.
void usage(void) {
  fprintf(stderr, "Usage: analyzer [-46htVvq] [-c config_file] "
          "\t[-d database host] [-D database name]"
          "\t[-l limit for number of unanalyzed flows to request]\n"
          "\t[-L log_device[[:log_level],...]\n"
          "\t[-P database password \"username:password\"] [-p network port]\n");
}

// Routine to parse command line options and load values into the
// global ConfInfo struct.
int parse_command_line(int argc, char* argv[], ConfInfo* info) {
  extern char* optarg;
  const char* getopt_flags = "46A:a:B:b:c:D:d:F:f:G:g:HhI:i:K:k:L:l:M:m:N:n:O:o:P:p:qS:s:TtU:u:Vv?";

  // Loop on argv options.
  int ch;
  while ((ch = getopt(argc, argv, getopt_flags)) != -1) {
    switch(ch) {
      case '4' :
        info->v4_enabled_ = true;
        break;

      case '6' :
        info->v6_enabled_ = true;
        break;

      case 'A' :
        // Fall-through.

      case 'a' :
        warn("parse_command_line(): option a not supported.");
        break;

      case 'B' :
        // Fall-through.

      case 'b' :
        warn("parse_command_line(): option b not supported.");
        break;

      case 'c' :  // Configuration file
        if (!optarg)
          errx(EX_CONFIG, "parse_command_line(): NULL config file.");  // die horribly

        info->conf_file_ = optarg;
        break;

      case 'D' :  // Database name
        if (!optarg)
          errx(EX_CONFIG, "parse_command_line(): NULL database name.");  // die horribly
        info->database_db_ = optarg;
        break;

      case 'd' :  // database host
        if (!optarg)
          errx(EX_CONFIG, "parse_command_line(): NULL database host.");  // die horribly
        info->database_ = optarg;
        break;

      case 'E' :  // Errors are fatal
        logger.set_errors_fatal();
        break;

      case 'F' :
        // Fall-through.

      case 'f' :
        warn("parse_command_line(): option f not supported.");
        break;

      case 'G' :
        // Fall-through.

      case 'g' :  // Group ID to run as
        if (!optarg)
          errx(EX_CONFIG, "parse_command_line(): NULL gid.");  // die horribly
        info->gid_ = atoi(optarg);
        break;

      case 'H' :
        // Fall-through.

      case 'h' :  // Help
        usage();
        exit(1);
        break;

      case 'I' :  
        // Fall-through

      case 'i' : 
        warn("parse_command_line(): option i not supported.");
        break;

      case 'K' :
        // Fall-through

      case 'k' :
        warn("parse_command_line(): option k not supported.");
        break;

      case 'L' :  // Log location or mechanism
#if 0
        // TODO(aka) Before going into the background, mark that logging was set.
        if (!info->logging_set_)
          info->logging_set_ = 1;  // user explicitly *set* a logging type/level
#endif

        if (!strncasecmp("stderr", optarg, strlen("stderr")))
          info->log_to_stderr_ = 1;  // stderr explicitly set by user

        logger.set_mechanism_priority(optarg);
        break;

      case 'l' :  // Limit to apply when polling database for unanalyzed flows
        if (!optarg)
          errx(EX_CONFIG, "parse_command_line(): NULL database limit.");  // die horribly
        info->database_poll_limit_ = atoi(optarg);  // override default
        break;

      case 'M' :  // Mode of operation
        // Fall through

      case 'm' :
        warn("parse_command_line(): option m not supported.");
        break;

      case 'N' :
        //fall through

      case 'n' :
        warn("parse_command_line(): option n not supported.");
        break;

      case 'O' :
        // Fall through.

      case 'o' :
        warn("parse_command_line(): option o not supported.");
        break;

      case 'P' :  // Password for database
        if (!optarg)
          errx(EX_CONFIG, "parse_command_line(): "
               "NULL database Passwd.");  // die horribly
        info->database_pw_ = optarg;
        break;
      
      case 'p' :  // Port number for my_url
        info->port_ = (in_port_t)atoi(optarg);
        break;

      case 'q' :  // Quite logging by one level
        logger.DecrementMechanismPriority();
        break;

      case 'S' :
        // Fall-through

      case 's' :
        warn("parse_command_line(): option s not supported.");
        break;
      
      case 'T' :
        // Fall-through

      case 't' :  // multi-Thread server
        info->multi_threaded_ = true;
        break;

      case 'U' :  // database User
        if (!optarg)
          errx(EX_CONFIG, "parse_command_line(): "
               "NULL database User.");  // die horribly
        info->database_user_ = optarg;
        break;
      
      case 'u' :  // Uid to run as
        if (!optarg)
          errx(EX_CONFIG, "parse_command_line(): NULL uid.");  // die horribly
        info->uid_ = atoi(optarg);
        break;
      

      case 'V' :  // Version
        fprintf(stdout, "%s\n", SERVER_VERSION);
        exit(0);
        break;

      case 'v' :  // set loggging to one level higher or Verbose
        logger.IncrementMechanismPriority();
        break;

      case '?' :
        // Fall-through!

      default :
        fprintf(stderr, "ERROR: unknown option: %c.\n", ch);
        usage();
        exit(1);
    }  // switch(ch)
  }  // while (ch = getopt() !- -1)

  // Modify argc & argv based on what we processed with getopt(3).
  argc -= optind;
  argv += optind;

  // TODO(aka) Test for additional command line arguments.

  if (argc)
    logger.Log(LOG_DEBUGGING, "parse_command_line(): "
               "post getopts(), argc is %d.", argc);

  return optind;
}

// Routine to parse our configuation file.
void parse_conf_file(ConfInfo* info) {
  // Load the default configuration filename *if* not set by user.
  if (strlen(info->conf_file_.c_str()) == 0)
    info->conf_file_ = conf_file_default;

  // See if the file exists.
  struct stat stat_info;
  if (stat(info->conf_file_.c_str(), &stat_info)) {
    logger.Log(LOG_VERBOSE, "parse_conf_file(): %s does not exist ...", 
               info->conf_file_.c_str());
    return;
  }

  if (stat_info.st_size == 0) {
    logger.Log(LOG_VERBOSE, "parse_conf_file(): %s is empty, not using ...", 
               info->conf_file_.c_str());
    return;
  }

  // Open file.
  FILE* fp = NULL;
  if ((fp = fopen(info->conf_file_.c_str(), "r")) == NULL) {
    logger.Log(LOG_VERBOSE, "Not using %s, fopen failed.", 
               info->conf_file_.c_str());
    return;
  }

  char buf[PATH_MAX];
  char* buf_ptr;
  char* key_ptr;
  char* val_ptr;
  char* delimit_ptr;

  // Parse each line as a "key = value" pair.
  while ((buf_ptr = fgets(buf, PATH_MAX, fp)) != NULL) {
    // Skip over preceeding whitespace.
    while (*buf_ptr == '\t' || *buf_ptr == ' ' || 
           *buf_ptr == '\n')
      buf_ptr++;

    if (*buf_ptr == '#' || *buf_ptr == '\0')
      continue;  // skip comments and empty lines

    key_ptr = buf_ptr;  // assign pointer to key

    if ((delimit_ptr = strchr(key_ptr, CONF_FILE_DELIMITER)) == NULL) {
      logger.Log(LOG_WARN, "Unable to parse %s at line: %s.", 
                 info->conf_file_.c_str(), key_ptr);
      fclose(fp);
      return;
    }

    char* key_end_ptr = delimit_ptr;
    *key_end_ptr = '\0';  // separate key from value
    delimit_ptr++;  // increment over delimiter (which is now '\0')

    // Remove trailing whitespace from key.
    key_end_ptr--;  // backup off of NULL terminator
    while (*key_end_ptr == '\t' || *key_end_ptr == ' ' || 
           *key_end_ptr == '\n' || *key_end_ptr == CONF_FILE_DELIMITER) 
      *key_end_ptr-- = '\0';

    // Remove preceeding white space *and* initial quotes from value.
    while (*delimit_ptr == '\t' || *delimit_ptr == ' ' || 
           *delimit_ptr == '\n' || *delimit_ptr == CONF_FILE_DELIMITER ||
           *delimit_ptr == '\'' || *delimit_ptr == '"')
      delimit_ptr++;

    val_ptr = delimit_ptr;  // assign pointer to value

    char* val_end_ptr = strchr(val_ptr, '\0');  // find end of value
    if (val_end_ptr == NULL) {
      logger.Log(LOG_ERR, "parse_conf_file(): val_end_ptr is NULL!");
      exit(1);  // die horribly before we start up
    }
    
    // Remove trailing whitespace *and* quotes from value.
    val_end_ptr--;
    while (*val_end_ptr == '\t' || *val_end_ptr == ' ' || 
           *val_end_ptr == '\n' || *val_end_ptr == '\'' || *val_end_ptr == '"') 
      *val_end_ptr-- = '\0';

    // Before (over-)writing any variables, first set them to defaults.
    //info->tar_path_ = TAR_CMD;

    // Switch (well, if-than-else) based on key.
#if 0
    if (!strncasecmp(KEY_FONT_PATH, key_ptr, 
                     strlen(KEY_FONT_PATH))) {
      info->font_path_ = val_ptr;
    } else if (!strncasecmp(KEY_FFMPEG_PATH, key_ptr,
                            strlen(KEY_FFMPEG_PATH))) {
      info->ffmpeg_path_ = val_ptr;
    } else if (!strncasecmp(KEY_TAR_PATH, key_ptr,
                            strlen(KEY_TAR_PATH))) {
      info->tar_path_ = val_ptr;
    } else {
      logger.Log(LOG_WARN, "parse_conf_file(): Unknown key: %s", key_ptr);
    }
#else
    logger.Log(LOG_WARN, "parse_conf_file(): Unknown key: %s", key_ptr);
#endif
  }
}

// Routine to *initiate* the sending a GET request to the InFlux DB
// for unanalyzed flow data.
//
//  Note, main()'s event-loop will take care of opening the connetion
//  and sending the data out.
void initiate_unanalyzed_poll(const ConfInfo& info, SSLContext* ssl_context,
                         list<SSLSession>* to_peers,
                         pthread_mutex_t* to_peers_mtx) {
  // Setup a client connection to the InfluxDB.
  SSLSession tmp_session(MsgHdr::TYPE_HTTP);
  tmp_session.Init();  // set aside buffer space
  tmp_session.SSLConn::Init(info.database_.c_str(), AF_INET, 
                            IPCOMM_DNS_RETRY_CNT);  // init IPComm base class
  tmp_session.set_port(info.database_port_);
  tmp_session.set_blocking();
  tmp_session.Socket(PF_INET, SOCK_STREAM, 0, ssl_context);
  //tmp_session.set_handle(tmp_session.fd());  // for now, set it to the socket
  if (error.Event()) {
    error.AppendMsg("initiate_unanalyzed_poll():");
    return;
  }

  // Build a (HTTP) framing header and load the framing header into
  // our SSLSession's MsgHdr list.
  //
  // example: GET /query?db=xsight&q=select%20time%2C%20domain%2C%20dtn%2C%20netname%2C%20type%2C%20flow%2C%20value%20from%20analyzed%20where%20value%3D%270%27%20limit%202

  char query_buf[kURLMaxSize];
  snprintf(query_buf, kURLMaxSize - 1, "%s%s%s%d", kInfluxQueryDBPrefix,
           info.database_db_.c_str(), kInfluxQueryAnalyzed,
           info.database_poll_limit_);
  URL query_url;
  query_url.Init("https", info.database_.c_str(), info.database_port_,
                 "query", strlen("query"), query_buf, strlen(query_buf), NULL);
  HTTPFraming query_http_hdr;
  query_http_hdr.InitRequest(HTTPFraming::GET, query_url);

  // Add HTTP message-headers (for basic auth & host).
  if (info.database_pw_.size() <= 0) {
    usage();
    errx(EXIT_FAILURE, "Database password not set");
  }

  struct rfc822_msg_hdr mime_msg_hdr;
  mime_msg_hdr.field_name = MIME_AUTHORIZATION;
  mime_msg_hdr.field_value = "Basic ";
  unsigned char* tmp_data = new unsigned char[info.database_pw_.size() + 1];
  strncpy((char*)tmp_data, info.database_pw_.c_str(), 
          info.database_pw_.size());
  string b64_pw = Base64Encode(tmp_data, info.database_pw_.size());
  mime_msg_hdr.field_value += b64_pw;
  query_http_hdr.AppendMsgHdr(mime_msg_hdr);
  mime_msg_hdr.field_name = MIME_HOST;
  mime_msg_hdr.field_value = info.database_.c_str();
  query_http_hdr.AppendMsgHdr(mime_msg_hdr);

  logger.Log(LOG_DEBUG, "initiate_unanalyzed_poll(): Generated HTTP headers:\n%s", query_http_hdr.print_hdr(0).c_str());

  MsgHdr tmp_msg_hdr(MsgHdr::TYPE_HTTP);
  tmp_msg_hdr.Init(++msg_id_hash, query_http_hdr);
  tmp_session.AddMsgBuf(query_http_hdr.print_hdr(0).c_str(),
                        query_http_hdr.hdr_len(), "", 0, tmp_msg_hdr);
  if (error.Event()) {
    logger.Log(LOG_ERR, "initiate_unanalyzed_poll(): failed to build msg: %s",
               error.print().c_str());
    return;
  }

#if DEBUG_MUTEX_LOCK
  warnx("initiate_unanalyzed_poll(): requesting to_peers lock.");
#endif
  pthread_mutex_lock(to_peers_mtx);
  to_peers->push_back(tmp_session);
#if DEBUG_MUTEX_LOCK
  warnx("initiate_unanalyzed_poll(): releasing to_peers lock.");
#endif
  pthread_mutex_unlock(to_peers_mtx);

  logger.Log(LOG_NOTICE, "Initiated poll to %s for next %d unanalyzed flows.",
             tmp_session.print_2tuple().c_str(), info.database_poll_limit_);
}

// Routine to *initiate* the sending of a GET request to the InFlux DB
// for a specific flow's meta-data.
//
//  Note, main()'s event-loop will take care of opening the connetion
//  and sending the data out.
void initiate_flow_data_request(const ConfInfo& info, const string& flow,
                                SSLContext* ssl_context,
                                list<SSLSession>* to_peers,
                                pthread_mutex_t* to_peers_mtx) {
  // Setup a client connection to the InfluxDB.
  SSLSession tmp_session(MsgHdr::TYPE_HTTP);
  tmp_session.Init();  // set aside buffer space
  tmp_session.SSLConn::Init(info.database_.c_str(), AF_INET, 
                            IPCOMM_DNS_RETRY_CNT);  // init IPComm base class
  tmp_session.set_port(info.database_port_);
  tmp_session.set_blocking();
  tmp_session.Socket(PF_INET, SOCK_STREAM, 0, ssl_context);
  //tmp_session.set_handle(tmp_session.fd());  // for now, set it to the socket
  if (error.Event()) {
    error.AppendMsg("initiate_flow_data_request():");
    return;
  }

  // Build a (HTTP) framing header and load the framing header into
  // our SSLSession's MsgHdr list.
  //
  // TODO(aka) Each InFlux series should be controlled via the
  // command-line, e.g., Timeouts should be a flag, as should
  // DupAcksIn.
  //
  // example: GET /query?db=xsight&q=select%20flow%2C%20value%20from%20src_ip%2C%20Timeouts%2C%20DataOctetsIn%2C%20DupAcksIn%2C%20EndTime%20where%20flow%3D%2783e37d27-85fa-4cba-9ffc-fdd9329547e3%27

  char query_buf[kURLMaxSize];

  // Note, kInfluxQueryMetrics ends in "where flow='", so we must add
  // the flow along with the suffix (i.e., ' limit 1).

  snprintf(query_buf, kURLMaxSize - 1, "%s%s%s%s%s",
           kInfluxQueryDBPrefix, info.database_db_.c_str(),
           kInfluxQueryMetrics, flow.c_str(), kInfluxQueryMetricsSuffix);
  URL query_url;
  query_url.Init("https", info.database_.c_str(), info.database_port_,
                 "query", strlen("query"), query_buf, strlen(query_buf), NULL);
  HTTPFraming query_http_hdr;
  query_http_hdr.InitRequest(HTTPFraming::GET, query_url);

  // Add HTTP message-headers (for basic auth & host).
  if (info.database_pw_.size() <= 0) {
    usage();
    errx(EXIT_FAILURE, "Database password not set");
  }

  struct rfc822_msg_hdr mime_msg_hdr;
  mime_msg_hdr.field_name = MIME_AUTHORIZATION;
  mime_msg_hdr.field_value = "Basic ";
  unsigned char* tmp_data = new unsigned char[info.database_pw_.size() + 1];
  strncpy((char*)tmp_data, info.database_pw_.c_str(), 
          info.database_pw_.size());
  string b64_pw = Base64Encode(tmp_data, info.database_pw_.size());
  mime_msg_hdr.field_value += b64_pw;
  query_http_hdr.AppendMsgHdr(mime_msg_hdr);
  mime_msg_hdr.field_name = MIME_HOST;
  mime_msg_hdr.field_value = info.database_.c_str();
  query_http_hdr.AppendMsgHdr(mime_msg_hdr);

  logger.Log(LOG_DEBUG, "initiate_flow_data_request(): Generated HTTP headers:\n%s", query_http_hdr.print_hdr(0).c_str());

  MsgHdr tmp_msg_hdr(MsgHdr::TYPE_HTTP);
  tmp_msg_hdr.Init(++msg_id_hash, query_http_hdr);
  tmp_session.AddMsgBuf(query_http_hdr.print_hdr(0).c_str(),
                        query_http_hdr.hdr_len(), "", 0, tmp_msg_hdr);
  if (error.Event()) {
    logger.Log(LOG_ERR, "initiate_flow_data_request(): failed to build msg: %s",
               error.print().c_str());
    return;
  }

#if DEBUG_MUTEX_LOCK
  warnx("initiate_flow_data_request(): requesting to_peers lock.");
#endif
  pthread_mutex_lock(to_peers_mtx);
  to_peers->push_back(tmp_session);
#if DEBUG_MUTEX_LOCK
  warnx("initiate_flow_data_request(): releasing to_peers lock.");
#endif
  pthread_mutex_unlock(to_peers_mtx);

  logger.Log(LOG_NOTICE, "Initiated request to %s for flow: %s.",
             tmp_session.print_2tuple().c_str(), flow.c_str());
}

// Routine to *initiate* the sending of a POST request to the InFlux DB
// to update a specific flow's analyzed value.
//
// Note, main()'s event-loop will take care of opening the connetion
// and sending the data out.
void initiate_analyzed_update(const ConfInfo& info,
                              const int update_value, AnalyzedInfo* analyzed,
                              SSLContext* ssl_context,
                              list<SSLSession>* to_peers,
                              pthread_mutex_t* to_peers_mtx) {
  // Setup a client connection to the InfluxDB.
  SSLSession tmp_session(MsgHdr::TYPE_HTTP);
  tmp_session.Init();  // set aside buffer space
  tmp_session.SSLConn::Init(info.database_.c_str(), AF_INET, 
                            IPCOMM_DNS_RETRY_CNT);  // init IPComm base class
  tmp_session.set_port(info.database_port_);
  tmp_session.set_blocking();
  tmp_session.Socket(PF_INET, SOCK_STREAM, 0, ssl_context);
  //tmp_session.set_handle(tmp_session.fd());  // for now, set it to the socket
  if (error.Event()) {
    error.AppendMsg("initiate_analyzed_update():");
    return;
  }

  // Build a (HTTP) framing header and load the framing header into
  // our SSLSession's MsgHdr list.  Our actual update data (series,
  // tags & value) will be sent as our message-body (so we'll need a
  // Content-Length!).
  //
  // example: 

  char write_buf[kURLMaxSize];
  snprintf(write_buf, kURLMaxSize - 1, "%s%s",
           kInfluxQueryDBPrefix, info.database_db_.c_str());
  URL write_url;
  write_url.Init("https", info.database_.c_str(), info.database_port_,
                 "write", strlen("write"), write_buf, strlen(write_buf), NULL);
  HTTPFraming write_http_hdr;
  write_http_hdr.InitRequest(HTTPFraming::POST, write_url);

  // Add HTTP message-headers (for basic auth, host, 
  // Content-Type (x-www-form-urlencoded) & Content-Length).

  if (info.database_pw_.size() <= 0) {
    usage();
    errx(EXIT_FAILURE, "Database password not set");
  }

  struct rfc822_msg_hdr mime_msg_hdr;
  mime_msg_hdr.field_name = MIME_AUTHORIZATION;
  mime_msg_hdr.field_value = "Basic ";
  unsigned char* tmp_data = new unsigned char[info.database_pw_.size() + 1];
  strncpy((char*)tmp_data, info.database_pw_.c_str(), 
          info.database_pw_.size());
  string b64_pw = Base64Encode(tmp_data, info.database_pw_.size());
  mime_msg_hdr.field_value += b64_pw;
  write_http_hdr.AppendMsgHdr(mime_msg_hdr);

  mime_msg_hdr.field_name = MIME_HOST;
  mime_msg_hdr.field_value = info.database_.c_str();
  write_http_hdr.AppendMsgHdr(mime_msg_hdr);

  mime_msg_hdr.field_name = MIME_CONTENT_TYPE;
  mime_msg_hdr.field_value = MIME_APP_X_WWW_FORM_URLENCODED;
  write_http_hdr.AppendMsgHdr(mime_msg_hdr);

  char msg_body[1024];
  snprintf(msg_body, 1024 - 1,
           "analyzed,domain=%s,dtn=%s,netname=%s,type=%s,flow=%s "
           "value=%di %lld", 
           analyzed->domain_.c_str(), analyzed->dtn_.c_str(),
           analyzed->netname_.c_str(), analyzed->type_.c_str(),
           analyzed->flow_.c_str(), update_value, analyzed->time_);

  mime_msg_hdr.field_name = MIME_CONTENT_LENGTH;
  char tmp_long_buf[64];  // field_value is a string, so must convert long
  snprintf(tmp_long_buf, 64, "%ld", (long)strlen(msg_body)); 
  mime_msg_hdr.field_value = tmp_long_buf;
  write_http_hdr.AppendMsgHdr(mime_msg_hdr);

  logger.Log(LOG_WARNING, "initiate_analyzed_update(): Generated HTTP headers:\n%s", write_http_hdr.print_hdr(0).c_str());

  MsgHdr tmp_msg_hdr(MsgHdr::TYPE_HTTP);
  tmp_msg_hdr.Init(++msg_id_hash, write_http_hdr);
  if (error.Event()) {
    logger.Log(LOG_ERR, "initiate_analyzed_update(): failed to build msg: %s",
               error.print().c_str());
    return;
  }

  // Add our MsgHdr & message to our SSL list.
  tmp_session.AddMsgBuf(write_http_hdr.print_hdr(0).c_str(),
                        write_http_hdr.hdr_len(), msg_body, strlen(msg_body),
                        tmp_msg_hdr);
  if (error.Event()) {
    logger.Log(LOG_ERR, "initiate_analyzed_update(): failed to build SSL: %s",
               error.print().c_str());
    return;
  }

#if DEBUG_MUTEX_LOCK
  warnx("initiate_analyzed_update(): requesting to_peers lock.");
#endif
  pthread_mutex_lock(to_peers_mtx);
  to_peers->push_back(tmp_session);
#if DEBUG_MUTEX_LOCK
  warnx("initiate_analyzed_update(): releasing to_peers lock.");
#endif
  pthread_mutex_unlock(to_peers_mtx);

  logger.Log(LOG_NOTICE, "Initiated update to %s (flow, ts, value): "
             "%s, %lld, %d.",
             tmp_session.print_2tuple().c_str(), analyzed->flow_.c_str(), 
             analyzed->time_, update_value);
}

