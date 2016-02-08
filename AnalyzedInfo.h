// Copyright © 2010, Pittsburgh Supercomputing Center (PSC).  
// See the file 'COPYRIGHT.txt' for any restrictions.

#ifndef ANALYZED_INFO_H_
#define ANALYZED_INFO_H_

#include <stdint.h>

#include <string>
using namespace std;

// Forward declarations (used if only needed for member function parameters).

// Non-class specific defines & data structures.

// Non-class specific utilities.

/** Class for managing the analyzed series.
 *
 *  RCSID: $Id: AnalyzedInfo.h,v 1.2 2012/05/22 16:33:27 akadams Exp $.
 *
 *  @author Andrew K. Adams <akadams@psc.edu>
 */
class AnalyzedInfo {
 public:
  // TODO(aka) For now, they're all public ... we'll abstract them
  // later when we figure out what we need and don't need.

  // Flow details.
  string flow_;              // unique token handed out by InFlux DB.
  uint64_t time_;            // timestamp tag in series in nanoseconds
  string domain_;            // tag in series
  string dtn_;               // tag in series
  string netname_;           // tag in series
  string type_;              // tag in series
  //int value_;             // we know this is 0
  short status_;             // 0 == unanalyzed
                             // 1 == analyzed, but no end_time
                             // 2 == ???  TODO(aka) Do we need this?

  // Constructor & Destructor.
  AnalyzedInfo(void) {
    status_ = 0;
  }
  
  virtual ~AnalyzedInfo(void) { };

  // Copy constructor.  TODO(aka) Using system-defined one ...

  // Accessors & Mutators.
  void clear(void);

 protected:
  // Data members.

 private:
  // Dummy declarations for copy constructor and assignment & equality operator.
  // AnalyzedInfo(const AnalyzedInfo& src);

  AnalyzedInfo& operator =(const AnalyzedInfo& src);
  int operator ==(const AnalyzedInfo& other) const;
};

#endif  /* #ifndef ANALYZED_INFO_H_ */

