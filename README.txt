$Id$

The analyzer is a C++ daemon that monitors the RFC 4898 extended metrics database, and report on abnormal behavior.  After a periodic interval (kPollIntervalUnanalyzed), it contacts the InFluxDB for n flows that have yet to analyzed.  As it receives unanalyzed flows from the database (note, each flow is a separate HTTP request), it turns around and issues a request for *specific* metrics for that flow (currently, that's SrcIP, DataOctetsIn, DupAcksIn, Timeouts and EndTime).  In its nascent version, the analyzer only looks for postive values in DupAcksIn or Timeouts, but one can easily modify the code to view these as a percentage of DataOctetsIn (which seems like a much better test).  If a positive value is seen, the analyzer attempts to fork off an exec to mail its NOC list (currently akadams@psc.edu, rapier@psc.edu, blearn@psc.edu).  Finally, depending on if (i) the flow is normal and a FIN has been seen (via an EndTime value), (ii) the flow is normal but the FIN has not yet been seen, or (iii) the flow was flagged for notification, the analyzer updates the analyzed series value for that flow with 1, 2, or 3 respectively.  Note, if the flow was marked with a 2 (i.e., normal, but still open), then the analyzer will periodicially (kPollIntervalInprogress) re-fetch that flows (stored in its internal state table) metrics and re-analyze it.

INSTALL

1) Fetch RapidJSON from github (in analyzer's build directory): git clone https://github.com/miloyip/rapidjson.git

2) Fetch ip-utils from github (in analyzer's build directory): git clone https://github.com/akadams/ip-utils.git

3) Run make: ./make

The daemon (analyzer) can be left in the current directory or moved elsewhere.

OPERATION:

Run "./analyzer -h" to see its usage.  At a minimum, you'll need to specify the InFluxDB host (-d), the database (-D) and the user:password (-P).  Logging information can be saved to a file via the -L option, e.g., "-L file=analyzer.log:info"
