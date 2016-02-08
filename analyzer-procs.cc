/* $Id: analyzer-procs.cc,v 1.35 2014/05/21 15:19:42 akadams Exp $ */

// Copyright © 2009, Pittsburgh Supercomputing Center (PSC).  
// See the file 'COPYRIGHT.txt' for any restrictions.

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <ctime>
#include <err.h>
#include <fcntl.h>
#include <math.h>
#include <omp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>      // for lower-casing std::string via transform & find
using namespace std;

#include "ErrorHandler.h"
#include "Logger.h"
#include "File.h"
#include "URL.h"

#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"

#include "defines.h"       // TODO(aka) not sure if we need it anymore ...

#include "analyzer-procs.h"


#define DEBUG_NETWORKING 0
#define DEBUG_XML 0
#define DEBUG_MUTEX_LOCK 0

static const char* kNameResults = "results";
static const char* kNameSeries = "series";
static const char* kNameName = "name";
//static const char* kNameColumns = "columns";
static const char* kNameValues = "values";

//static const char* kColumnTime = "time";
//static const char* kColumnValue = "value";
//static const char* kColumnFlow = "flow";

static const char* kSeriesAnalyzed = "analyzed";
static const char* kSeriesDataOctetsIn = "DataOctetsIn";
static const char* kSeriesDupAcksIn = "DupAcksIn";
static const char* kSeriesEndTime = "EndTime";
static const char* kSeriesSrcIP = "src_ip";
//static const char* kSeriesSrcPort = "src_port";
//static const char* kSeriesDstIP = "dst_ip";
//static const char* kSeriesDstPort = "dst_port";
static const char* kSeriesTimeouts = "Timeouts";

// Routine to process a ready (incoming) message in our SSLSession
// object.  This routine must deal with both the message framing *and*
// the application (to know what routines to call for message
// processing).
//
// TODO(aka) Note, we pass in the to_peers list in case we need to
// inititate a new connection out, but *if* we do this, we need to be
// certain that we don't mess with our current list iterator (peer),
// if indeed peer came from to_peers!  For this reason, we may want to
// create two of these routines, or at least check if from_(peer) and
// to_(peer) are NULL (i.e., pass both in, and only operate on one).
//
// This routine can set an ErrorHandler event.
bool analyzer_process_incoming_msg(ConfInfo* info, SSLContext* ssl_context, 
                                   list<AnalyzedInfo>* analyzed,
                                   pthread_mutex_t* analyzed_mtx,
                                   list<FlowInfo>* flows,
                                   pthread_mutex_t* flow_list_mtx,
                                   list<SSLSession>* to_peers,
                                   pthread_mutex_t* to_peers_mtx, 
                                   list<SSLSession>::iterator peer) {
  if (&(*peer) == NULL) {  // note iterator hack
    error.Init(EX_SOFTWARE, "analyzer_process_incoming_msg(): peer is NULL");
    return false;
  }

  try {  // for debugging

    //logger.Log(LOG_DEBUG, "analyzer_process_incoming_msg(): Working with header: %s.", peer->rhdr().print().c_str());

    // First, make a copy of the incoming msg and remove the *original*
    // data from the SSLSession (i.e., either rbuf_ or rfile_ (along
    // with rhdr_)).  We *trade-off* the cost of the buffer copy in-order
    // for us to multi-thread different messages within the same SSLSession,
    // i.e., we need to clear out the incoming message ASAP!

    const MsgHdr msg_hdr = peer->rhdr();
    string msg_body;
    File msg_data;
    if (peer->IsIncomingDataStreaming())
      msg_data = peer->rfile();  // TODO(aka) I doubt this will ever happen ...
    else
      msg_body.assign(peer->rbuf(), peer->rhdr().body_len());

    //logger.Log(LOG_DEBUG, "analyzer_process_incoming_msg(): Cleaning %ld byte msg-body for request (%s)/response (%s) from peer %s.", peer->rhdr().msg_len(), req_hdr->print_hdr(0).c_str(), peer->rhdr().print_hdr(0).c_str(), peer->print().c_str());

    peer->ClearIncomingMsg();  // remove *now copied* message from peer

    // See what type of message this is; if this is a REQUEST, call the
    // appropriate process_request_msg() for our application.  If,
    // however, this is a RESPONSE, then we additionally need to find
    // its associated REQUEST message-header (in peer->whdrs) to
    // correctly process the message.

    int response_flag = 0;
    switch (msg_hdr.type()) {
      case MsgHdr::TYPE_BASIC :
        if (msg_hdr.basic_hdr().type > MSG_REQ_FILE)
          response_flag++;  // all msgs > REQ_FILE must be ACKs
        break;

      case MsgHdr::TYPE_HTTP :
        if (msg_hdr.http_hdr().msg_type() == HTTPFraming::RESPONSE)
          response_flag++;
        break;

      default :
        error.Init(EX_DATAERR, "analyzer_process_incoming_msg(): "
                   "unknown type: %d", msg_hdr.type());
        return false;  // msg in peer was already cleared up above
    }

    if (response_flag) {
      // Presumably, we are a client, and not the server ...

      // Find REQUEST message-header in whdrs.
      list<MsgHdr> request_hdrs = peer->whdrs();  // need to work on a
                                                  // copy of the list,
                                                  // as that's what
                                                  // SSLSession::whdrs()
                                                  // returns
      list<MsgHdr>::iterator req_hdr = request_hdrs.begin(); 
      while (req_hdr != request_hdrs.end()) {
        bool found = false;
        switch (req_hdr->type()) {
          case MsgHdr::TYPE_BASIC :
            if (req_hdr->msg_id() == msg_hdr.msg_id())
              found = true;
            break;

          case MsgHdr::TYPE_HTTP :
            // TOOD(aka) Until we find a way to embed our message ids into
            // the HTTP headers, we can't compare message ids here, we just
            // assume (since HTTP is a sequential protocol) that the first
            // header whdrs_() is our request header.

            found = true;  // first time in, leave
            break;

          default :
            ;  // NOT-REACHABLE (test was already done up above)
        }

        if (found)
          break;

        req_hdr++;
      }  // while (req_hdr != request_hdrs.end()) {

      if (req_hdr != request_hdrs.end()) {
        logger.Log(LOG_DEBUG, "analyzer_process_incoming_msg(): "
                   "Using REQUEST message-header %s "
                   "for current message-header %s.", 
                   req_hdr->print().c_str(), msg_hdr.print().c_str());

        // Process message based on our application.
        analyzer_process_response(*info, msg_hdr, msg_body, msg_data,
                                  analyzed, analyzed_mtx, 
                                  flows, flow_list_mtx, peer, req_hdr);

        peer->delete_whdr(req_hdr->msg_id());  // clean-up whdrs,
                                               // since we found the
                                               // hdr
      } else {
        logger.Log(LOG_ERROR, "analyzer_process_incoming_msg(): TODO(aka) "
                   "Unable to find our REQUEST header associated with the "
                   "received RESPONSE message-header: %s, from %s.", 
                   msg_hdr.print().c_str(), peer->print().c_str());
        // Fall-through to clean-up peer.
      }

      // Since this was a RESPONSE, if we don't have any more business
      // with this peer we can shutdown the connection.  (The SSLSession
      // will be removed in tcp_event_chk_stale_connections()).

      if (peer->rbuf_len() || peer->IsOutgoingDataPending() ||
          peer->whdrs().size()) {
        logger.Log(LOG_INFO, "analyzer_process_incoming_msg(): TODO(aka) "
                   "peer (%s) still has %ld bytes in rbuf, or "
                   "%d messages in wpending, or %d REQUEST headers left, "
                   "so not removing from queue.", 
                   peer->print().c_str(), peer->rbuf_len(), 
                   peer->IsOutgoingDataPending(), peer->whdrs().size());
      } else {
        peer->Close();  // close the connection
      }
    } else {  // if (response_flag) {
      // Process message based on our framing and application.
      switch (msg_hdr.type()) {
        case MsgHdr::TYPE_BASIC :  // not used
          break;

        case MsgHdr::TYPE_HTTP :
          {  // block protect case statement inside of case statement

            // Note, if we encounter any errors from this point forward,
            // we need to issue an HTTP ERROR RESPONSE (see
            // analyzer_gen_http_error_response()).

            // TODO(aka) Also, don't we need a multipart and/or
            // chunking data test here!?!

            HTTPFraming http_hdr = msg_hdr.http_hdr();
            URL url = http_hdr.uri();

            logger.Log(LOG_INFO, "Received REQUEST (%s) from %s, "
                       "content-type: %s.",
                       http_hdr.print_start_line().c_str(),
                       peer->hostname().c_str(), 
                       http_hdr.content_type().c_str());

            string service = url.path();
            std::transform(service.begin(), service.end(), service.begin(),
                           ::tolower);

            // TODO(aka) Deprecated.
            // First, see if this is a WSDL service REQUEST, if so, mark it.
            //request_info.wsdl_request_ = http_hdr.IsWSDLRequest();

            string ret_msg;
            
            // Process message-body based on HTTP method & content-type.
            switch (http_hdr.method()) {
              case HTTPFraming::POST :
                {
                  // Report the error.  NACK sent outside of switch() {} block.
                  error.Init(EX_SOFTWARE, "analyzer_process_incoming_msg(): "
                             "No support for POST service \'%s\'",
                             service.c_str());
                }
                break;

              case HTTPFraming::DELETE :
                {
                  // Report the error.  NACK sent outside of switch() {} block.
                  error.Init(EX_SOFTWARE, "analyzer_process_incoming_msg(): "
                             "No support for DELETE service \'%s\'",
                             service.c_str());
                }
                break;

              case HTTPFraming::GET :
                {
                  // Report the error.  NACK sent outside of switch() {} block.
                  error.Init(EX_SOFTWARE, "analyzer_process_incoming_msg(): "
                             "No support for GET service \'%s\'",
                             service.c_str());
                }
                break;

              case HTTPFraming::PUT :
                {
                  // Report the error.  NACK sent outside of switch() {} block.
                  error.Init(EX_SOFTWARE, "analyzer_process_incoming_msg(): "
                             "No support for PUT service \'%s\'",
                             service.c_str());
                }
                break;

              default :
                // Report the error.  NACK sent outside of switch() {} block.
                error.Init(EX_SOFTWARE, "analyzer_process_incoming_msg(): "
                           "unknown method: %d in REQUEST %s", 
                           http_hdr.method(), http_hdr.print_hdr(0).c_str());
                break;
            }  // switch (msg_hdr.basic_hdr().method()) {

            // Catch any locally generated error events (i.e., connection is healthy).
            if (error.Event()) {
              // We failed to process the REQUEST, so send our NACK
              // back.  Note, if the communication channel has since
              // somehow got corrupted, all we can do is cleanup peer
              // and wait for its removal back in the main event-loop.

              error.AppendMsg("analyzer_process_incoming_msg()");
              analyzer_gen_http_error_response(*info, http_hdr, peer);
              if (error.Event()) {
                // Report the non-NACKable error.
                error.Init(EX_SOFTWARE, "analyzer_process_incoming_msg(): "
                           "unable to send NACK to %s: %s",
                           peer->print().c_str(), error.print().c_str());
              }
#if 0  // Deprecated
            } else if (request_info.wsdl_request_) {
              // Build the message RESPONSE for WSDL services.
              analyzer_gen_wsdl_response(*info, request_info, http_hdr, peer);
#endif
            } else {
              // Build the message RESPONSE as an HTTP message.
              analyzer_gen_http_response(*info, http_hdr, ret_msg, peer);

              // ... and log what we processed.
              logger.Log(LOG_NOTICE, "Processed HTTP REQUEST (%s) from %s; "
                         "is awaiting delivery.",
                         http_hdr.print_start_line().c_str(), 
                         peer->print().c_str());
            }

            // Note, although it might seem like a good idea to delete
            // any tmp files created in making the response, reality
            // is that we are probably sending it back to requester,
            // so we need it around until *they* close the connection!

          }  // block protect for case MsgHdr::TYPE_HTTP :
          break;

        default :
          ; // NOT-REACHABLE (test was already done up above)
      }  // switch (msg_hdr.type()) {
    }  //  else (if (response_flag)) {
  } catch (...) {
    error.Init(EX_SOFTWARE, "analyzer_process_incoming_msg(): "
               "Unexpected exception thrown");
  }

  return true;
}

// Routine to act as a wrapper for pthread_create(), as we want to
// pass more than one argument into analyzer_process_incoming_msg().
void* analyzer_concurrent_process_incoming_msg(void* ptr) {
  pthread_detach(pthread_self());

  // Grab our function's parameters from the thread's stack and make a
  // copy of them incase they change back in the main event loop!

  // TODO(aka) Change this so that all we pass in is the index to the
  // global that holds our arguments.  Main can then *clean-up* the
  // global storage once this thread exits (by marking the boolean
  // flag in the global!

  struct analyzer_incoming_msg_args* args =
      (struct analyzer_incoming_msg_args*)ptr;

  // Mark that *this* thead is dealing with the next available
  // incoming message.
  
  args->peer->set_rtid(pthread_self());

  logger.Log(LOG_INFO, "Thread %lu processing REQUEST from %s.", 
             pthread_self(), args->peer->hostname().c_str());

  // Process the *complete* message.
  analyzer_process_incoming_msg(args->info, args->ssl_context, 
                                args->analyzed, args->analyzed_mtx,
                                args->flows, args->flow_list_mtx,
                                args->to_peers, args->to_peers_mtx, args->peer);
  if (error.Event()) {
    logger.Log(LOG_ERR, "analyzer_concurrent_process_incoming_msg(): "
               "Thread %d failed to process REQUEST from %s: %s.", 
               pthread_self(), args->peer->hostname().c_str(), 
               error.print().c_str());
    // peer should have been cleaned in analyzer_process_incoming_msg()
  }

  logger.Log(LOG_INFO, "Thread %lu finished processing REQUEST from %s.", 
             pthread_self(), args->peer->hostname().c_str());

  // Clean up global thread list (to signal to main event-loop that
  // we're finished).

  args->peer->set_rtid(TCPSESSION_THREAD_NULL);

  pthread_mutex_lock(args->thread_list_mtx);
  bool found = false;
  for (vector<pthread_t>::iterator tid = args->thread_list->begin();
       tid != args->thread_list->end(); tid++) {
    if (*tid == pthread_self()) {
      found = true;
      args->thread_list->erase(tid);
      break;
    }
  }
  pthread_mutex_unlock(args->thread_list_mtx);

  if (!found)
    logger.Log(LOG_WARN, "analyzer_concurrent_process_incoming_msg(): "
               "TODO(aka) Unable to find thead id (%d).", pthread_self());

  //pthread_exit();  // implicitly called when we return
  return (NULL);
}

// Routine to process a RESPONSE "message-body".  Note, this routine
// should only be called by a client.
//
// TOOD(aka) We only need the HTTPFraming header in here, not MsgHdr ...
void analyzer_process_response(const ConfInfo& info, const MsgHdr& msg_hdr,
                               const string& msg_body, const File& msg_data,
                               list<AnalyzedInfo>* analyzed,
                               pthread_mutex_t* analyzed_mtx,
                               list<FlowInfo>* flows, 
                               pthread_mutex_t* flow_list_mtx,
                               list<SSLSession>::iterator peer, 
                               list<MsgHdr>::iterator req_hdr) {
  if (msg_hdr.http_hdr().status_code() == 200) {
    // InFlux should never send us a file (at least I'm not programming for one).
    if (msg_data.Exists(NULL) && msg_data.size(NULL) > 0) {
      error.Init(EX_DATAERR, "analyzer_process_response(): "
                 "Recevied a file in message-body from %s, "
                 "but unable to process", peer->hostname().c_str());
      return;
    }


    logger.Log(LOG_NOTICE, 
               "Received RESPONSE \'%d %s\' from %s for REQUEST: %s.", 
               msg_hdr.http_hdr().status_code(), 
               status_code_phrase(msg_hdr.http_hdr().status_code()),
               peer->TCPConn::print().c_str(), 
               req_hdr->http_hdr().print_start_line().c_str());

    // Parse JSON message-body.
    rapidjson::Document response;
    if (response.Parse(msg_body.c_str()).HasParseError()) {
      error.Init(EX_DATAERR, "analyzer_process_response(): "
                 "Failed to parse JSON from %s: %s",
                 peer->hostname().c_str(), msg_body.c_str());
      return;
    }

    if (!response.IsObject() || !response.HasMember(kNameResults) ||
        !response[kNameResults].IsArray()) {
      error.Init(EX_DATAERR, "analyzer_process_response(): %s is invalid: %s", 
                 kNameResults, msg_body.c_str());
      return;
    }

    // RAPIDJSON: Uses SizeType instead of size_t.

#if 0
    // For Debugging: To see what a value's type is in RapidJSON.
    static const char* kTypeNames[] = { "Null", "False", "True", "Object", "Array", "String", "Number" };
    for (rapidjson::Value::ConstMemberIterator doc_itr = response.MemberBegin(); doc_itr != response.MemberEnd(); ++doc_itr)
      printf("DEBUG: Working on %s (%s) ...\n", doc_itr->name.GetString(), kTypeNames[doc_itr->value.GetType()]);
#endif

    // Loop over results array ...
    const rapidjson::Value& results = response[kNameResults];
    for (rapidjson::SizeType i = 0; i < results.Size(); ++i) {
      if (!results[i].HasMember(kNameSeries) ||
          !results[i][kNameSeries].IsArray()) {
        error.Init(EX_DATAERR, "analyzer_process_response(): "
                   "Failed to parse %s within JSON from %s: %s",
                   kNameSeries, peer->hostname().c_str(), msg_body.c_str());
        return;
      }
      const rapidjson::Value& series = results[i][kNameSeries];

      // Loop over series array ...
      for (rapidjson::SizeType j = 0; j < series.Size(); ++j) {
        if (!series[j].HasMember(kNameName)) {
          error.Init(EX_DATAERR, "analyzer_process_response(): "
                     "Failed to parse %s within JSON from %s: %s",
                     kNameName, peer->hostname().c_str(), msg_body.c_str());
          return;
        }
        const rapidjson::Value& name = series[j][kNameName];

        // Depending on what series this is, process it.
        if (strlen(name.GetString()) == strlen(kSeriesAnalyzed) &&
            !strncasecmp(name.GetString(), kSeriesAnalyzed, 
                         strlen(kSeriesAnalyzed))) {
          // Working on our array of Analyzed.

          // TODO(aka) Need to grab kNameColumns array here?  We kinda
          // of know it's going to be time/value/flow ... But what if
          // there is no value, would the output change?

          // Grab the values array.
          if (!series[j].HasMember(kNameValues) ||
              !series[j][kNameValues].IsArray()) {
            error.Init(EX_DATAERR, "analyzer_process_response(): "
                       "Failed to parse %s within JSON from %s: %s",
                       kNameValues, peer->hostname().c_str(), msg_body.c_str());
            return;
          }
          const rapidjson::Value& values = series[j][kNameValues];

          // Loop over values array ...
          AnalyzedInfo tmp_flow;
          for (rapidjson::SizeType k = 0; k < values.Size(); ++k) {
            if (!values[k].IsArray()) {
              error.Init(EX_DATAERR, "analyzer_process_response(): "
                         "Failed to parse %s as array within JSON from %s: %s",
                         kNameValues, peer->hostname().c_str(),
                         msg_body.c_str());
              return;
            }
            const rapidjson::Value& anon_array = values[k];

            // Okay, based on our query (kInfluxQueryAnalzyed) we know
            // anon_array will be:
            //
            //   anon_array[0] = time
            //   anon_array[1] = domain
            //   anon_array[2] = dtn
            //   anon_array[3] = netname
            //   anon_array[4] = type
            //   anon_array[5] = flow
            //   anon_array[6] = value
            //
            // So process them depending on our index. (See comment
            // about *columns* above!)

            // Sanity check values ...
            if (!anon_array[0].IsNumber() || !anon_array[1].IsString() ||
                !anon_array[2].IsString() || !anon_array[3].IsString() ||
                !anon_array[4].IsString() || !anon_array[5].IsString() ||
                !anon_array[6].IsNumber()) {
              error.Init(EX_DATAERR, "analyzer_process_response(): "
                         "A tag in analyzed is incorrect type "
                         "within values[%d] from %s: %s",
                         k, peer->hostname().c_str(), msg_body.c_str());
              return;
            }
            uint64_t time_ns = anon_array[0].GetInt64();
            string domain = anon_array[1].GetString();
            string dtn = anon_array[2].GetString();
            string netname = anon_array[3].GetString();
            string type = anon_array[4].GetString();
            string flow = anon_array[5].GetString();
            // int analyzed = anon_array[6].GetInt();  // note, we know this is '0'

            // Process, depending on whether this is a *new* flow or not.
#if DEBUG_MUTEX_LOCK
            warnx("analyzer_process_response(): requesting analyzed lock.");
#endif
            pthread_mutex_lock(analyzed_mtx);

            list<AnalyzedInfo>::iterator analyzed_itr = analyzed->begin();
            while (analyzed_itr != analyzed->end()) {
              if (!flow.compare(analyzed_itr->flow_))
                break;
              analyzed_itr++;
            }
            if (analyzed_itr == analyzed->end()) {
              // Add new entry to our analyzed list.
              tmp_flow.clear();  // start anew
              tmp_flow.time_ = time_ns;
              tmp_flow.flow_ = flow;
              tmp_flow.domain_ = domain;
              tmp_flow.dtn_ = dtn;
              tmp_flow.netname_ = netname;
              tmp_flow.type_ = type;
              analyzed->push_back(tmp_flow);
            }  // else if (analyzed_itr != analyzed->end()) {
#if DEBUG_MUTEX_LOCK
            warnx("analyzer_process_response(): releasing analyzed lock.");
#endif
              pthread_mutex_unlock(analyzed_mtx);
          }  // for (rapidjson::SizeType k = 0; k < values.Size(); ++k) {
        } else if (strlen(name.GetString()) == strlen(kSeriesDataOctetsIn) &&
            !strncasecmp(name.GetString(), kSeriesDataOctetsIn, 
                         strlen(kSeriesDataOctetsIn))) {
          // Working on our array of DataOctetsIn.

          // TODO(aka) Need to grab kNameColumns array here?  We kinda
          // of know it's going to be time/value/flow ... But what if
          // there is no value, would the output change?

          // Grab the values array.
          if (!series[j].HasMember(kNameValues) ||
              !series[j][kNameValues].IsArray()) {
            error.Init(EX_DATAERR, "analyzer_process_response(): "
                       "Failed to parse %s within JSON from %s: %s",
                       kNameValues, peer->hostname().c_str(), msg_body.c_str());
            return;
          }
          const rapidjson::Value& values = series[j][kNameValues];

          // Loop over values array ...
          FlowInfo tmp_flow;
          for (rapidjson::SizeType k = 0; k < values.Size(); ++k) {
            if (!values[k].IsArray()) {
              error.Init(EX_DATAERR, "analyzer_process_response(): "
                         "Failed to parse %s as array within JSON from %s: %s",
                         kNameValues, peer->hostname().c_str(),
                         msg_body.c_str());
              return;
            }
            const rapidjson::Value& anon_array = values[k];

            // Okay, we know that time is anon_array[0], flow is
            // anon_array[1] and value is anon_array[2], so process
            // them depending on our index. (See comment about
            // *columns* above!)

            // Sanity check values ...
            if (!anon_array[0].IsNumber() || !anon_array[1].IsString() ||
                !anon_array[2].IsNumber()) {
              error.Init(EX_DATAERR, "analyzer_process_response(): "
                         "Either time, flow or value is incorrect type "
                         "within values[%d] (DataOctetsIn) from %s: %s",
                         k, peer->hostname().c_str(), msg_body.c_str());
              return;
            }
            uint64_t time_ns = anon_array[0].GetInt64();
            string flow = anon_array[1].GetString();
            double DataOctetsIn = 0;
            if (anon_array[2].IsDouble())
              DataOctetsIn = anon_array[2].GetDouble();
            else if (anon_array[2].IsInt64())
              DataOctetsIn = (double)anon_array[2].GetInt64();
            else {
              error.Init(EX_DATAERR, "analyzer_process_response(): "
                         "DataOctetsIn value is incorrect type "
                         "within values[%d] from %s: %s",
                         k, peer->hostname().c_str(), msg_body.c_str());
            }

            // Process, depending on whether this is a *new* flow or not.
#if DEBUG_MUTEX_LOCK
            warnx("analyzer_process_response(): requesting flows lock.");
#endif
            pthread_mutex_lock(flow_list_mtx);

            list<FlowInfo>::iterator flow_itr = flows->begin();
            while (flow_itr != flows->end()) {
              if (!flow.compare(flow_itr->flow_))
                break;
              flow_itr++;
            }
            if (flow_itr != flows->end()) {
              // Update our Time & DataOctetsIn in our existing flow.
              flow_itr->time_ = time_ns;
              flow_itr->DataOctetsIn_ = DataOctetsIn;
            } else {
              tmp_flow.clear();  // start anew
              tmp_flow.time_ = time_ns;
              tmp_flow.flow_ = flow;
              tmp_flow.DataOctetsIn_ = DataOctetsIn;
              flows->push_back(tmp_flow);
            }  // else if (flow_itr != flows->end()) {
#if DEBUG_MUTEX_LOCK
            warnx("analyzer_process_response(): releasing flows lock.");
#endif
              pthread_mutex_unlock(flow_list_mtx);
          }  // for (rapidjson::SizeType k = 0; k < values.Size(); ++k) {
        } else if (strlen(name.GetString()) == strlen(kSeriesDupAcksIn) &&
                   !strncasecmp(name.GetString(), kSeriesDupAcksIn, 
                                strlen(kSeriesDupAcksIn))) {
          // Working on our array of DupAcksIn.

          // TODO(aka) Need to grab kNameColumns array here?  We kinda
          // of know it's going to be time/value/flow ... But what if
          // there is no value, would the output change?

          // Grab the values array.
          if (!series[j].HasMember(kNameValues) ||
              !series[j][kNameValues].IsArray()) {
            error.Init(EX_DATAERR, "analyzer_process_response(): "
                       "Failed to parse %s within JSON from %s: %s",
                       kNameValues, peer->hostname().c_str(), msg_body.c_str());
            return;
          }
          const rapidjson::Value& values = series[j][kNameValues];

          // Loop over values array ...
          FlowInfo tmp_flow;
          for (rapidjson::SizeType k = 0; k < values.Size(); ++k) {
            if (!values[k].IsArray()) {
              error.Init(EX_DATAERR, "analyzer_process_response(): "
                         "Failed to parse %s as array within JSON from %s: %s",
                         kNameValues, peer->hostname().c_str(),
                         msg_body.c_str());
              return;
            }
            const rapidjson::Value& anon_array = values[k];

            // Okay, we know that time is anon_array[0], flow is
            // anon_array[1] and value is anon_array[2], so process
            // them depending on our index. (See comment about
            // *columns* above!)

            // Sanity check values ...
            if (!anon_array[0].IsNumber() || !anon_array[1].IsString() ||
                !anon_array[2].IsInt()) {
              error.Init(EX_DATAERR, "analyzer_process_response(): "
                         "Either time, flow or value is incorrect type "
                         "within values[%d] (DupAcksIn) from %s: %s",
                         k, peer->hostname().c_str(), msg_body.c_str());
              return;
            }
            uint64_t time_ns = anon_array[0].GetInt64();
            string flow = anon_array[1].GetString();
            int DupAcksIn = anon_array[2].GetInt();

            // Process, depending on whether this is a *new* flow or not.
#if DEBUG_MUTEX_LOCK
            warnx("analyzer_process_response(): requesting flows lock.");
#endif
            pthread_mutex_lock(flow_list_mtx);

            list<FlowInfo>::iterator flow_itr = flows->begin();
            while (flow_itr != flows->end()) {
              if (!flow.compare(flow_itr->flow_))
                break;
              flow_itr++;
            }
            if (flow_itr != flows->end()) {
              // Update our Time & DupAcksIn in our existing flow.
              flow_itr->time_ = time_ns;
              flow_itr->DupAcksIn_ = DupAcksIn;
            } else {
              tmp_flow.clear();  // start anew
              tmp_flow.time_ = time_ns;
              tmp_flow.flow_ = flow;
              tmp_flow.DupAcksIn_ = DupAcksIn;
              flows->push_back(tmp_flow);
            }  // else if (flow_itr != flows->end()) {
#if DEBUG_MUTEX_LOCK
            warnx("analyzer_process_response(): releasing flows lock.");
#endif
              pthread_mutex_unlock(flow_list_mtx);
          }  // for (rapidjson::SizeType k = 0; k < values.Size(); ++k) {
        } else if (strlen(name.GetString()) == strlen(kSeriesEndTime) &&
                   !strncasecmp(name.GetString(), kSeriesEndTime, 
                                strlen(kSeriesEndTime))) {
          // Working on our array of EndTime.

          // TODO(aka) Need to grab kNameColumns array here?  We kinda
          // of know it's going to be time/value/flow ... But what if
          // there is no value, would the output change?

          // Grab the values array.
          if (!series[j].HasMember(kNameValues) ||
              !series[j][kNameValues].IsArray()) {
            error.Init(EX_DATAERR, "analyzer_process_response(): "
                       "Failed to parse %s within JSON from %s: %s",
                       kNameValues, peer->hostname().c_str(), msg_body.c_str());
            return;
          }
          const rapidjson::Value& values = series[j][kNameValues];

          // Loop over values array ...
          FlowInfo tmp_flow;
          for (rapidjson::SizeType k = 0; k < values.Size(); ++k) {
            if (!values[k].IsArray()) {
              error.Init(EX_DATAERR, "analyzer_process_response(): "
                         "Failed to parse %s as array within JSON from %s: %s",
                         kNameValues, peer->hostname().c_str(),
                         msg_body.c_str());
              return;
            }
            const rapidjson::Value& anon_array = values[k];

            // Okay, we know that time is anon_array[0], flow is
            // anon_array[1] and value is anon_array[2], so process
            // them depending on our index. (See comment about
            // *columns* above!)

            // Sanity check values ...
            if (!anon_array[0].IsNumber() || !anon_array[1].IsString() ||
                !anon_array[2].IsDouble()) {
              error.Init(EX_DATAERR, "analyzer_process_response(): "
                         "Either time, flow or value is incorrect type "
                         "within values[%d] (EndTime) from %s: %s",
                         k, peer->hostname().c_str(), msg_body.c_str());
              return;
            }
            uint64_t time_ns = anon_array[0].GetInt64();
            string flow = anon_array[1].GetString();
            double end_time = anon_array[2].GetDouble();

            // Process, depending on whether this is a *new* flow or not.
#if DEBUG_MUTEX_LOCK
            warnx("analyzer_process_response(): requesting flows lock.");
#endif
            pthread_mutex_lock(flow_list_mtx);

            list<FlowInfo>::iterator flow_itr = flows->begin();
            while (flow_itr != flows->end()) {
              if (!flow.compare(flow_itr->flow_))
                break;
              flow_itr++;
            }
            if (flow_itr != flows->end()) {
              // Update our Time & EndTime in our existing flow.
              flow_itr->time_ = time_ns;
              flow_itr->end_time_ = end_time;
            } else {
              tmp_flow.clear();  // start anew
              tmp_flow.time_ = time_ns;
              tmp_flow.flow_ = flow;
              tmp_flow.end_time_ = end_time;
              flows->push_back(tmp_flow);
            }  // else if (flow_itr != flows->end()) {
#if DEBUG_MUTEX_LOCK
            warnx("analyzer_process_response(): releasing flows lock.");
#endif
              pthread_mutex_unlock(flow_list_mtx);
          }  // for (rapidjson::SizeType k = 0; k < values.Size(); ++k) {
        } else if (strlen(name.GetString()) == strlen(kSeriesSrcIP) &&
                   !strncasecmp(name.GetString(), kSeriesSrcIP, 
                                strlen(kSeriesSrcIP))) {
          // Working on our array of SrcIP.

          // TODO(aka) Need to grab kNameColumns array here?  We kinda
          // of know it's going to be time/value/flow ... But what if
          // there is no value, would the output change?

          // Grab the values array.
          if (!series[j].HasMember(kNameValues) ||
              !series[j][kNameValues].IsArray()) {
            error.Init(EX_DATAERR, "analyzer_process_response(): "
                       "Failed to parse %s within JSON from %s: %s",
                       kNameValues, peer->hostname().c_str(), msg_body.c_str());
            return;
          }
          const rapidjson::Value& values = series[j][kNameValues];

          // Loop over values array ...
          FlowInfo tmp_flow;
          for (rapidjson::SizeType k = 0; k < values.Size(); ++k) {
            if (!values[k].IsArray()) {
              error.Init(EX_DATAERR, "analyzer_process_response(): "
                         "Failed to parse %s as array within JSON from %s: %s",
                         kNameValues, peer->hostname().c_str(),
                         msg_body.c_str());
              return;
            }
            const rapidjson::Value& anon_array = values[k];

            // Okay, we know that time is anon_array[0], flow is
            // anon_array[1] and value is anon_array[2], so process
            // them depending on our index. (See comment about
            // *columns* above!)

            // Sanity check values ...
            if (!anon_array[0].IsNumber() || !anon_array[1].IsString() ||
                !anon_array[2].IsString()) {
              error.Init(EX_DATAERR, "analyzer_process_response(): "
                         "Either time, flow or value is incorrect type "
                         "within values[%d] (SrcIP) from %s: %s",
                         k, peer->hostname().c_str(), msg_body.c_str());
              return;
            }
            uint64_t time_ns = anon_array[0].GetInt64();
            string flow = anon_array[1].GetString();
            string src_ip = anon_array[2].GetString();

            // Process, depending on whether this is a *new* flow or not.
#if DEBUG_MUTEX_LOCK
            warnx("analyzer_process_response(): requesting flows lock.");
#endif
            pthread_mutex_lock(flow_list_mtx);

            list<FlowInfo>::iterator flow_itr = flows->begin();
            while (flow_itr != flows->end()) {
              if (!flow.compare(flow_itr->flow_))
                break;
              flow_itr++;
            }
            if (flow_itr != flows->end()) {
              // Update our Time & SrcIP in our existing flow.
              flow_itr->time_ = time_ns;
              flow_itr->src_ip_ = src_ip;
            } else {
              tmp_flow.clear();  // start anew
              tmp_flow.time_ = time_ns;
              tmp_flow.flow_ = flow;
              tmp_flow.src_ip_ = src_ip;
              flows->push_back(tmp_flow);
            }  // else if (flow_itr != flows->end()) {
#if DEBUG_MUTEX_LOCK
            warnx("analyzer_process_response(): releasing flows lock.");
#endif
              pthread_mutex_unlock(flow_list_mtx);
          }  // for (rapidjson::SizeType k = 0; k < values.Size(); ++k) {
        } else if (strlen(name.GetString()) == strlen(kSeriesTimeouts) &&
                   !strncasecmp(name.GetString(), kSeriesTimeouts, 
                                strlen(kSeriesTimeouts))) {
          // Working on our array of Timeouts.

          // TODO(aka) Need to grab kNameColumns array here?  We kinda
          // of know it's going to be time/value/flow ... But what if
          // there is no value, would the output change?

          // Grab the values array.
          if (!series[j].HasMember(kNameValues) ||
              !series[j][kNameValues].IsArray()) {
            error.Init(EX_DATAERR, "analyzer_process_response(): "
                       "Failed to parse %s within JSON from %s: %s",
                       kNameValues, peer->hostname().c_str(), msg_body.c_str());
            return;
          }
          const rapidjson::Value& values = series[j][kNameValues];

          // Loop over values array ...
          FlowInfo tmp_flow;
          for (rapidjson::SizeType k = 0; k < values.Size(); ++k) {
            if (!values[k].IsArray()) {
              error.Init(EX_DATAERR, "analyzer_process_response(): "
                         "Failed to parse %s as array within JSON from %s: %s",
                         kNameValues, peer->hostname().c_str(),
                         msg_body.c_str());
              return;
            }
            const rapidjson::Value& anon_array = values[k];

            // Okay, we know that time is anon_array[0], flow is
            // anon_array[1] and value is anon_array[2], so process
            // them depending on our index. (See comment about
            // *columns* above!)

            // Sanity check values ...
            if (!anon_array[0].IsNumber() || !anon_array[1].IsString() ||
                !anon_array[2].IsInt()) {
              error.Init(EX_DATAERR, "analyzer_process_response(): "
                         "Either time, flow or value is incorrect type "
                         "within values[%d] (Timeouts) from %s: %s",
                         k, peer->hostname().c_str(), msg_body.c_str());
              return;
            }
            uint64_t time_ns = anon_array[0].GetInt64();
            string flow = anon_array[1].GetString();
            int Timeouts = anon_array[2].GetInt();

            // Process, depending on whether this is a *new* flow or not.
#if DEBUG_MUTEX_LOCK
            warnx("analyzer_process_response(): requesting flows lock.");
#endif
            pthread_mutex_lock(flow_list_mtx);

            list<FlowInfo>::iterator flow_itr = flows->begin();
            while (flow_itr != flows->end()) {
              if (!flow.compare(flow_itr->flow_))
                break;
              flow_itr++;
            }
            if (flow_itr != flows->end()) {
              // Update our Time & Timeouts in our existing flow.
              flow_itr->time_ = time_ns;
              flow_itr->Timeouts_ = Timeouts;
            } else {
              tmp_flow.clear();  // start anew
              tmp_flow.time_ = time_ns;
              tmp_flow.flow_ = flow;
              tmp_flow.Timeouts_ = Timeouts;
              flows->push_back(tmp_flow);
            }  // else if (flow_itr != flows->end()) {
#if DEBUG_MUTEX_LOCK
            warnx("analyzer_process_response(): releasing flows lock.");
#endif
              pthread_mutex_unlock(flow_list_mtx);
          }  // for (rapidjson::SizeType k = 0; k < values.Size(); ++k) {
        } else {
          error.Init(EX_DATAERR, "analyzer_process_response(): "
                     "Unknown series name: %s, within JSON from %s: %s",
                     name.GetString(), 
                     peer->hostname().c_str(), msg_body.c_str());
          return;
        }
      }  // for (rapidjson::SizeType j = 0; j < series.Size(); ++j) {
    }  // for (rapidjson::SizeType i = 0; i < results.Size(); ++i) {
  } else {  // if (msg_hdr.http_hdr().status_code() == 200) {
    if (msg_body.size() > 0)
      logger.Log(LOG_NOTICE, 
                 "Received ERROR response \'%d %s\' from %s "
                 "for REQUEST: %s: %s.",
                 msg_hdr.http_hdr().status_code(), 
                 status_code_phrase(msg_hdr.http_hdr().status_code()),
                 peer->TCPConn::print().c_str(),
                 req_hdr->http_hdr().print_hdr(0).c_str(),
                 msg_body.c_str());
    else
      logger.Log(LOG_NOTICE, 
                 "Received ERROR response \'%d %s\' from %s for REQUEST: %s.",
                 msg_hdr.http_hdr().status_code(), 
                 status_code_phrase(msg_hdr.http_hdr().status_code()),
                 peer->TCPConn::print().c_str(),
                 req_hdr->http_hdr().print_hdr(0).c_str());
  }
}


// Routine to encapsulate (frame) the REPONSE ERROR as a standard HTTP
// message.
//
// This routine can set an ErrorHandler event.
void analyzer_gen_http_error_response(const ConfInfo& info, 
                                   const HTTPFraming& http_hdr, 
                                   list<SSLSession>::iterator peer) {
  // Build ERROR message.
  string msg(1024, '\0');  // '\0' so strlen() works
  snprintf((char*)msg.c_str() + strlen(msg.c_str()),
           1024 - strlen(msg.c_str()), 
           "Unable to satisfy REQUEST \"%s\": %s",
           http_hdr.print_start_line().c_str(), 
           error.print().c_str());
  error.clear();

  // Setup HTTP RESPONSE message header.
  HTTPFraming ack_hdr;
  ack_hdr.InitResponse(500, HTTPFraming::CLOSE);

  // Add HTTP content-type and content-length message-headers.
  struct rfc822_msg_hdr mime_msg_hdr;
  mime_msg_hdr.field_name = MIME_CONTENT_TYPE;
  mime_msg_hdr.field_value = MIME_TEXT_PLAIN;    // XXX need to set this correctly
  struct rfc822_parameter param;
  param.key = MIME_CHARSET;
  param.value = MIME_ISO_8859_1;
  mime_msg_hdr.parameters.push_back(param);
  ack_hdr.AppendMsgHdr(mime_msg_hdr);
  if (error.Event()) {
    error.AppendMsg("analyzer_gen_http_error_response()");
    return;
  }

  param.key.clear();  // so we don't hose next msg-hdr
  param.value.clear();

  mime_msg_hdr.field_name = MIME_CONTENT_LENGTH;
  char tmp_buf[64];
  snprintf(tmp_buf, 64, "%ld", (long)strlen(msg.c_str())); 
  mime_msg_hdr.field_value = tmp_buf;
  ack_hdr.AppendMsgHdr(mime_msg_hdr);
  if (error.Event()) {
    error.AppendMsg("analyzer_gen_http_error_response()");
    return;
  }

  //logger.Log(LOG_INFO, "analyzer_gen_http_error_response(): Generated HTTP headers:\n%s", http_hdr.print_hdr(0).c_str());

  // Setup opaque MsgHdr for SSLSession, and add HTTP header to it.
  MsgHdr ack_msg_hdr(MsgHdr::TYPE_HTTP);
  ack_msg_hdr.Init(++msg_id_hash, ack_hdr);  // HTTP has no id
  if (error.Event()) {
    error.AppendMsg("analyzer_gen_http_error_response()");
    return;
  }

  // And add the message to our SSLSession queue for transmission.
  peer->AddMsgBuf(ack_hdr.print_hdr(0).c_str(), ack_hdr.hdr_len(), 
                  msg.c_str(), strlen(msg.c_str()), ack_msg_hdr);
  if (error.Event()) {
    error.AppendMsg("analyzer_gen_http_error_response()");
    return;  // AddMsgFile() throws events before updating peer
  }

  //logger.Log(LOG_INFO, "analyzer_gen_http_error_response(): %s is waiting transmission to %s, contents: %s", ack_hdr.print().c_str(), peer->print().c_str(), msg.c_str());

  logger.Log(LOG_ERROR, "Returning ERROR \"%s\" to %s.", 
             msg.c_str(), peer->print().c_str());
}

// Routine to encapsulate (frame) the REPONSE as a standard HTTP message.
void analyzer_gen_http_response(const ConfInfo& info,
                                const HTTPFraming& http_hdr,
                                const string msg,
                                list<SSLSession>::iterator peer) {
  // Setup HTTP RESPONSE message header.
  HTTPFraming ack_hdr;
  ack_hdr.InitResponse(200, HTTPFraming::CLOSE);

  // Add HTTP content-type and content-length message-headers.
  struct rfc822_msg_hdr mime_msg_hdr;
  mime_msg_hdr.field_name = MIME_CONTENT_TYPE;
  mime_msg_hdr.field_value = MIME_TEXT_PLAIN;
  ack_hdr.AppendMsgHdr(mime_msg_hdr);
  if (error.Event()) {
    error.AppendMsg("analyzer_gen_http_response()");
    return;
  }

  mime_msg_hdr.field_name = MIME_CONTENT_LENGTH;
  char tmp_buf[64];
  snprintf(tmp_buf, 64, "%ld", (long)msg.size());
  mime_msg_hdr.field_value = tmp_buf;
  ack_hdr.AppendMsgHdr(mime_msg_hdr);
  if (error.Event()) {
    error.AppendMsg("analyzer_gen_http_response()");
    return;
  }

  // Setup opaque MsgHdr for SSLSession, and add HTTP header to it.
  MsgHdr ack_msg_hdr(MsgHdr::TYPE_HTTP);
  ack_msg_hdr.Init(++msg_id_hash, ack_hdr);  // HTTP has no id
  if (error.Event()) {
    error.AppendMsg("analyzer_gen_http_response()");
    return;
  }

  // And add the message to our SSLSession queue for transmission.
  peer->AddMsgBuf(ack_hdr.print_hdr(0).c_str(), ack_hdr.hdr_len(), 
                  msg.c_str(), ack_hdr.msg_len(), ack_msg_hdr);
  if (error.Event()) {
    error.AppendMsg("analyzer_gen_http_response()");
    return;  // AddMsgFile() throws events before updating peer
  }

  logger.Log(LOG_DEBUG, "analyzer_gen_http_response(): processed request %s; "
             "%s is waiting transmission to %s, contents: %s", 
             http_hdr.print_start_line().c_str(), 
             ack_hdr.print().c_str(), peer->print().c_str(), 
             msg.c_str());
}

// Routine to return the rediculous date string returned by InFlux
// back to Unix EPOC.
//
// TODO(aka) This routine has been deprecated now that Bryan figured
// out that we can request the timestamp tag in nanoseconds via the
// HTTP query option "epoch=ns"!
int64_t convert_influx_date(const string& influx_date) {

  // Example InFlux date: 2015-12-16T15:52:30.723944113Z

  size_t pos = influx_date.find('.', 0);
  if (pos <= 0) {
    error.Init(EX_DATAERR, "convert_influx_date(): find(%s, .) failed",
                influx_date.c_str());
    return 0;
  }

  string nanoseconds_str = influx_date.substr(pos + 1);
  int64_t nanoseconds = strtol(nanoseconds_str.c_str(), (char**)NULL, 10);

  printf("XXX DEBUG: Working with date: %s, and nanoseconds remainder: %lld.\n", influx_date.substr(0, pos).c_str(), nanoseconds);

  struct tm tmp_tm;
  memset((void*)&tmp_tm, 0, sizeof(struct tm));

  /*
  tmp_tm.tm_sec;   // seconds of minutes from 0 to 61
  tmp_tm.tm_min;   // minutes of hour from 0 to 59
  tmp_tm.tm_hour;  // hours of day from 0 to 24
  tmp_tm.tm_mday;  // day of month from 1 to 31
  tmp_tm.tm_mon;   // month of year from 0 to 11
  tmp_tm.tm_year;  // year since 1900
  tmp_tm.tm_wday;  // days since sunday
  tmp_tm.tm_yday;  // days since January 1st
  tmp_tm.tm_isdst; // hours of daylight savings time
  */

  if ((strptime(influx_date.substr(0, pos).c_str(), "%FT%T", &tmp_tm)) == NULL) {
    error.Init(EX_DATAERR, "convert_influx_date(): strptime(%s) failed",
                influx_date.substr(0, pos).c_str());
    return 0;
  }

  printf("XXX DEBUG: Got: %d/%d/%d:%d/%d/%d, as well as: isdst %d, yday & wday: %d, %d\n", tmp_tm.tm_year + 1900, tmp_tm.tm_mon, tmp_tm.tm_mday, tmp_tm.tm_hour, tmp_tm.tm_min, tmp_tm.tm_sec, tmp_tm.tm_isdst, tmp_tm.tm_yday, tmp_tm.tm_wday);

  // Now, convert struct tm to epoch.
  time_t utc_mktime = mktime(&tmp_tm);
  time_t utc_timegm = timegm(&tmp_tm);

  printf("XXX DEBUG: mktime = %ld, timegm = %ld.\n", utc_mktime, utc_timegm);


  int64_t utc_ns = ((int64_t)utc_timegm * 1000000000) + nanoseconds;

  printf("XXX DEBUG: convert_influx_date(): Outputing %lld for %s.\n", utc_ns, influx_date.c_str());

  return utc_ns;
}
