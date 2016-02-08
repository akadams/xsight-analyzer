/* $Id: analyzer-procs.h,v 1.9 2014/05/21 15:19:42 akadams Exp $ */

// analyzer-procs: routines for processing messages in our ANALYZER.

// Copyright © 2010, Pittsburgh Supercomputing Center (PSC).  
// See the file 'COPYRIGHT.txt' for any restrictions.

#ifndef ANALYZER_PROCS_H_
#define ANALYZER_PROCS_H_

#include <sysexits.h>

#include <vector>
#include <string>
#include <list>
using namespace std;

#include "SSLSession.h"
#include "ConfInfo.h"
#include "AnalyzedInfo.h"
#include "FlowInfo.h"

#define ANALYZER_SERVER_PORT 443  // https

struct analyzer_incoming_msg_args {
  ConfInfo* info;
  SSLContext* ssl_context;
  list<AnalyzedInfo>* analyzed;
  pthread_mutex_t* analyzed_mtx;
  list<FlowInfo>* flows;
  pthread_mutex_t* flow_list_mtx;
  list<SSLSession>* to_peers;
  pthread_mutex_t* to_peers_mtx;
  list<SSLSession>::iterator peer;
  list<SSLSession>::iterator peer_end;
  vector<pthread_t>* thread_list;
  pthread_mutex_t* thread_list_mtx;
};

const char kANALYZERMsgDelimiter = ':';

bool analyzer_process_incoming_msg(ConfInfo* info, SSLContext* ssl_context, 
                                   list<AnalyzedInfo>* analyzed,
                                   pthread_mutex_t* analyzed_mtx,
                                   list<FlowInfo>* flows, 
                                   pthread_mutex_t* flow_list_mtx,
                                   list<SSLSession>* to_peers,
                                   pthread_mutex_t* to_peers_mtx, 
                                   list<SSLSession>::iterator peer);
void* analyzer_concurrent_process_incoming_msg(void* args);
void analyzer_process_response(const ConfInfo& info, const MsgHdr& msg_hdr,
                               const string& msg_body, const File& msg_data,
                               list<AnalyzedInfo>* analyzed,
                               pthread_mutex_t* analyzed_mtx,
                               list<FlowInfo>* flows, 
                               pthread_mutex_t* flow_list_mtx,
                               list<SSLSession>::iterator peer, 
                               list<MsgHdr>::iterator req_hdr);

void analyzer_gen_http_error_response(const ConfInfo& info,
                                      const HTTPFraming& http_hdr, 
                                      list<SSLSession>::iterator peer);
void analyzer_gen_http_response(const ConfInfo& info,
                                const HTTPFraming& http_hdr, const string msg,
                                list<SSLSession>::iterator peer);

int64_t convert_influx_date(const string& influx_date);

#endif  /* #ifndef ANALYZER_PROCS_H_ */
