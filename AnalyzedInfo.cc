/* $Id: AnalyzedInfo.cc,v 1.1 2012/02/03 13:17:10 akadams Exp $ */

// Copyright © 2010, Pittsburgh Supercomputing Center (PSC).  
// See the file 'COPYRIGHT.txt' for any restrictions.

#include "AnalyzedInfo.h"

// Non-class specific defines & data structures.

// Non-class specific utility functions.

// AnalyzedInfo Class.

// Mutators.
void AnalyzedInfo::clear(void) {
  flow_.clear();
  time_ = 0;
  domain_.clear();
  dtn_.clear();
  netname_.clear();
  type_.clear();
  status_ = 0;
}
