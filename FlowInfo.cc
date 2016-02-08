/* $Id: FlowInfo.cc,v 1.3 2014/02/24 18:06:00 akadams Exp $ */

// Copyright © 2009, Pittsburgh Supercomputing Center (PSC).  
// See the file 'COPYRIGHT.txt' for any restrictions.

#include <stdlib.h>
#include <string.h>

#include "ErrorHandler.h"
#include "Logger.h"
#include "FlowInfo.h"

#define SCRATCH_BUF_SIZE (1024 * 4)


// Accessors & mutators.
void FlowInfo::clear(void) {
  flow_.clear();
  time_ = 0;
  status_ = 0;

  src_ip_.clear();
  src_port_ = 0;
  dst_ip_.clear();
  dst_port_ = 0;
  start_time_ = -1;
  end_time_ = -1;
  DataOctetsIn_ = (double)-1;
  DupAcksIn_ = -1;
  Timeouts_ = -1;

  peer_.clear();
}
