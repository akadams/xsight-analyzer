/* $Id: FlowInfo.h,v 1.9 2014/02/24 18:06:00 akadams Exp $ */

// FlowInfo Class: meta-data for describing & examining flows

// Copyright © 2009, Pittsburgh Supercomputing Center (PSC).  
// See the file 'COPYRIGHT.txt' for any restrictions.

#ifndef FLOWINFO_H_
#define FLOWINFO_H_

#include <arpa/inet.h>

#include <stdint.h>

#include <vector>
#include <list>
#include <map>
#include <string>
using namespace std;


// Non-class specific defines & data structures.

// FlowInfo Class: A class to hold all necessary meta-data to examine
// flows.
class FlowInfo {
 public:

  // TODO(aka) For now, they're all public ... we'll abstract them
  // later when we figure out what we need and don't need.

  // Flow details.
  string flow_;              // unique token handed out by InFlux DB.
  uint64_t time_;            // timestamp tag in series in nanoseconds
  short status_;             // 0 == okay, 
                             // 1 == contacting NOC,
                             // 2 == contacted NOC

  string src_ip_;
  in_port_t src_port_;
  string dst_ip_;
  in_port_t dst_port_;
  double start_time_;
  double end_time_;
  double DataOctetsIn_;
  int DupAcksIn_;
  int Timeouts_;

  // TODO(aka) Not sure if we need the two below elements ...
  string peer_;              // who requested this flow
  uint16_t msg_hdr_id_;      // link to message (socket) in either to_peers or from_peers

  // Constructor & destructor.
  FlowInfo(void) {
    time_ = 0;
    status_ = 0;
    start_time_ = -1;
    end_time_ = -1;
    DataOctetsIn_ = -1;
    DupAcksIn_ = -1;
    Timeouts_ = -1;
  }

  virtual ~FlowInfo(void) { };

  // Copy constructor.  TODO(aka) Using system-defined one ...

  // Accessors & mutators.
  void clear(void);

 protected:

 private:
  // Dummy declarations for assignment & equality operator.
  void operator =(const FlowInfo& src);
  int operator ==(const FlowInfo& other) const;
};


#endif  /* #ifndef FLOWINFO_H_ */
