# $Id: Makefile,v 1.9 2014/03/11 14:35:21 akadams Exp $

PREFIX = /usr/local
BIN_DIR = /bin
PKG_CONFIG_PATH=/usr/local/lib/pkgconfig

CXX = g++

# JSON parsing (only headers)
RAPIDJSON_INCLUDES = -I./rapidjson/include

# MySQL Library (need headers and library).
#MYSQL_CONFIG = mysql_config
#MYSQL_INCLUDES = `${MYSQL_CONFIG} --include`
#MYSQL_LDFLAGS = `${MYSQL_CONFIG} --libs`

# Xerces XML library (need headers and library).
#XERCES_INCLUDES =
#XERCES_LDFLAGS = -L/usr/local/lib
#XERCES_LIBS = -lxerces-c

CXXFLAGS = -g -O3 -Wall -D_THREAD_SAFE -DUSE_LOGGER
#CXXFLAGS = -g -O3 -fopenmp -Wall -D_THREAD_SAFE -DUSE_LOGGER
INCLUDES = -I./ip-utils ${RAPIDJSON_INCLUDES}
#INCLUDES = -I./ip-utils ${XERCES_INCLUDES} ${MYSQL_INCLUDES}
LDFLAGS = -Wl,-rpath /usr/local/lib
#LDFLAGS = ${XERCES_LDFLAGS} -Wl,-rpath /usr/local/lib
LIBS =  -lssl -lcrypto -lpthread
#LIBS =  ${MYSQL_LDFLAGS} ${XERCES_LIBS} -lpthread -lgomp
CXXOPTIM =
CXXPATH =

OBJS = AnalyzedInfo.o FlowInfo.o ssl-event-procs.o analyzer-procs.o

all: analyzer

analyzer: libip-utils.a ${OBJS} main.cc
	${CXX} ${CXXFLAGS} -D SERVER_FLAG ${INCLUDES} ${LDFLAGS} main.cc ${OBJS} -o analyzer ./ip-utils/libip-utils.a ${LIBS}

libip-utils.a:
	cd ip-utils; ${MAKE} libip-utils.a

%.o: %.cc
	${CXX} -c ${CXXFLAGS} ${INCLUDES} ${CXXOPTIM} ${CXXPATH} $?

# Build c files as if they were c++ files.
%.o: %.c
	${CXX} -c ${CXXFLAGS} ${INCLUDES} ${CXXOPTIM} ${CXXPATH} $?

# Argh, who uses a "C" extension for c++?
%.o: %.C
	${CXX} -c ${CXXFLAGS} ${INCLUDES} ${CXXOPTIM} ${CXXPATH} $?

# And apparently, some people still use cpp extensions ...
%.o: %.cpp
	${CXX} -c ${CXXFLAGS} ${INCLUDES} ${CXXOPTIM} ${CXXPATH} $?

clean:	
	cd ip-utils; ${MAKE} clean
	rm -rf analyzer *.o
