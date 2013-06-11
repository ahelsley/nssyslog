#include "ns.h"							/* -*-tab-width: 4-*- ex:ts=4:sw=4: */

#include <stdlib.h>		/* for bsearch */
#include <syslog.h>

#define MOD_NAME "nsrepl"

#define TRACE()
#if !defined(TRACE)
#	if defined(__FUNCTION__)
#		define TRACE() do{Ns_Log(Notice, MOD_NAME ": " __FILE__ ":" __FUNCTION__ ":%d", __LINE__);}while(0)
#	elsif define(__FUNC__)
#		define TRACE() do{Ns_Log(Notice, MOD_NAME ": " __FILE__ ":" __FUNC__ ":%d", __LINE__);}while(0)
#	else
#		define TRACE() do{Ns_Log(Notice, MOD_NAME ": " __FILE__ ":%d", __LINE__);}while(0)
#	endif
#endif

/* The NS module settings. */
typedef struct {
	char		*server, *module;
	int			accessLogFacility, errorLogFacility,
				priority, logMask;
	int			suppressQueryP;
} SysLog;

static Ns_Callback SysLogCloseCallback;
static Ns_TraceProc SysLogTrace;

typedef struct CodeMap { int code, nscode; char *id, *nsid, *info; } CodeMap;

/* Compare 2 text ids from CodeMap entries */
static int Code_compare(const void *key, const void *elmt) {
	return strcoll((const char *)key,
				   ((const CodeMap *)elmt)->id);
}

#define SIZEOF_ARRAY(x) ((sizeof(x))/(sizeof(*x)))

static int LookupCode(CodeMap *map, int n, const char *id, int dfalt) {
	CodeMap *found = NULL;
	if (!map || n == 0 || !id
		|| !(found = bsearch(id, map, n, sizeof(CodeMap), Code_compare)))
		return dfalt;
	return found->code;
}

#define ConfigMap(ARRAY, NAME, DEFAULT)				\
	(LookupCode((ARRAY),							\
				SIZEOF_ARRAY((ARRAY)),				\
				Ns_ConfigGetValue(path, (NAME)),	\
				(DEFAULT)))

/* or from syslog.h: facilitynames */
CodeMap facilities[] = {
	{LOG_AUTH,		0,		"authentication",	"", "Security (authorization)"},
	{LOG_AUTHPRIV,	0,		"authorization",	"", "Private security (authorization)"},
	{LOG_CRON,		0,		"cron",				"", "Cron and At"},
	{LOG_DAEMON,	0,		"daemon",			"", "A miscellaneous system daemon"},
	{LOG_FTP,		0,		"ftp",				"", "Ftp server"},

	{LOG_LOCAL0,	0,		"local0",			"", "Locally defined, 0"},
	{LOG_LOCAL1,	0,		"local1",			"", "Locally defined, 1"},
	{LOG_LOCAL2,	0,		"local2",			"", "Locally defined, 2"},
	{LOG_LOCAL3,	0,		"local3",			"", "Locally defined, 3"},
	{LOG_LOCAL4,	0,		"local4",			"", "Locally defined, 4"},
	{LOG_LOCAL5,	0,		"local5",			"", "Locally defined, 5"},
	{LOG_LOCAL6,	0,		"local6",			"", "Locally defined, 6"},
	{LOG_LOCAL7,	0,		"local7",			"", "Locally defined, 7"},

	{LOG_LPR,		0,		"print",			"", "Central printer"},
	{LOG_MAIL,		0,		"mail",				"", "Mail"},
	{LOG_NEWS,		0,		"news",				"", "Network news (e.g. Usenet)"},
	{LOG_SYSLOG,	0,		"syslog",			"", "Syslog"},
	{LOG_USER,		0,		"user",				"", "A miscellaneous user process"},
	{LOG_UUCP,		0,		"uucp",				"", "UUCP"},
};

/* or from syslog.h: prioritynames */
CodeMap priorities[] = {
	/* SysLog Code	NS Code	SysLog ID		NS ID		SysLog "Severity" Level, Description */
	{LOG_ALERT,		Bug,	"alert",		"",			/* 1 */ "Action on the message must be taken immediately."},
	{LOG_CRIT,		Bug,	"critical",		"Bug",		/* 2 */ "The message states a critical condition."},
	{LOG_DEBUG,		Debug,	"debug",		"Debug",	/* 7 */ "The message is only for debugging purposes."},
	{LOG_EMERG,		Fatal,	"emergency",	"Fatal",	/* 0 */ "The message says the system is unusable."},
	{LOG_ERR,		Error,	"error",		"Error",	/* 3 */ "The message describes an error."},
	{LOG_INFO,		Dev,	"info",			"Dev",		/* 6 */ "The message is purely informational."},
	{LOG_NOTICE,	Notice,	"notice",		"Notice",	/* 5 */ "The message describes a normal but important event."},
	{LOG_WARNING,	Warning,"warning",		"Warning",	/* 4 */ "The message is a warning."},
};

int NsSysLog_ModuleInit(char *server, char *module) {
    static int	 first = 1;
	if(!first) {
		return NS_OK;
	}
	first = 0;

    SysLog	*nssyslog	= ns_calloc(1, sizeof(SysLog));
	char	*path		= Ns_ConfigGetPath(server, module, NULL);

	nssyslog->server	= server;
	nssyslog->module	= module;

	if (!Ns_ConfigGetBool(path, "suppressQuery", &nssyslog->suppressQueryP)) {
		nssyslog->suppressQueryP = 0;
	}

	nssyslog->accessLogFacility	= ConfigMap(facilities, "accessLogFacility",LOG_DAEMON);
	nssyslog->errorLogFacility	= ConfigMap(facilities, "errorLogFacility",	LOG_LOCAL3);
	nssyslog->priority			= ConfigMap(priorities, "priority",			LOG_INFO);
	//TODO// read logMask from the config and translate it into a coded value to use in setlogmask(...)

	//TODO// incorporate more info into server (path to web root?, binary(nsd)?)
	openlog(nssyslog->server, LOG_PID|LOG_NOWAIT, LOG_DAEMON);
	Ns_RegisterServerTrace(server, SysLogTrace, nssyslog);
	Ns_RegisterAtShutdown(SysLogCloseCallback, nssyslog);
	return NS_OK;
}


/*
 *------------------------------------------------------------------------------
 *
 * SysLogTrace --
 *
 *	Trace routine for appending the current connection results to syslog.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	Entry is appended to the syslog.
 *
 *------------------------------------------------------------------------------
 */
static void SysLogTrace(void *arg, Ns_Conn *conn) {
	/* NOTE: Syslog will prepend the timestamp, server name (configured via
	 *	openlog(...)), and PID.
	 */

	/* Format1:
	 *	server[PID]
	 *	server-{hostname/ip:port}
	 *	peer-or-proxy[(actual-peer)]
	 *	#bytes-recvd,#bytes-sent/elapsed
	 *	HTTP-status
	 *	content-type
	 *	Host|hostname
	 *	conn->request->line (method, uri, protocol, version)
	 *	HTTP referrer/agent
	 */

	//TODO// gather pointers to data then build string with fewer calls to *_DString*
	//TODO// convert most of this into Ns_DStringPrintf(&ds, fmt, ...) calls
	SysLog			*nssyslog = (SysLog *)arg;
	char			fmtbuf[150], *header = NULL;
	Ns_DString		ds;
    Ns_DStringInit(&ds);

	snprintf(fmtbuf, sizeof(fmtbuf), "%d", Ns_ConnPort(conn));
	Ns_DStringVarAppend(&ds,
						Ns_ConnHost(conn), ":",	/* server hostname/ip */
						fmtbuf,					/* server port */
						"\t", NULL);

	/*------------------------------------------------------------------------*/
	/* Peer IP (and proxy if there is one)									  */
	/* SECURITY NOTE: the actualPeer could be a lie sent by a malicious user! */
	char *actualPeer;
	if (conn->headers && (actualPeer = Ns_SetIGet(conn->headers, "X-Forwarded-For"))) {
		Ns_DStringAppend(&ds, Ns_ConnPeer(conn));
		Ns_DStringVarAppend(&ds, "({", actualPeer, "}?)\t", NULL);
	} else {
		Ns_DStringVarAppend(&ds, Ns_ConnPeer(conn), "\t", NULL);
	}

	/*------------------------------------------------------------------------*/
	/* # Content Bytes Sent/Received; Elapsed time							  */
	Ns_Time now, elapsed;
	Ns_GetTime(&now);
	Ns_DiffTime(&now, Ns_ConnStartTime(conn), &elapsed);
	snprintf(fmtbuf, sizeof(fmtbuf), "%lu,%lu/%d.%06ld\t",
			 (unsigned long)Ns_ConnContentLength(conn), 	// Client sent this much as request body content
			 (unsigned long)Ns_ConnContentSent(conn),		// Server sent this much as response body content
			 (int)elapsed.sec, elapsed.usec);
	Ns_DStringAppend(&ds, fmtbuf);

	/*------------------------------------------------------------------------*/
	/* HTTP Status															  */
	int status = Ns_ConnResponseStatus(conn);
	snprintf(fmtbuf, sizeof(fmtbuf), "%d\t",
			 status ? status : 200);
	Ns_DStringAppend(&ds, fmtbuf);

	/*------------------------------------------------------------------------*/
	/* Response Content-Type												  */
	Ns_DStringVarAppend(&ds, "{", Ns_ConnGetType(conn), "}\t", NULL);

	/*------------------------------------------------------------------------*/
	/* Host|hostname														  */
	if ((header = Ns_SetIGet(conn->headers, "Host"))) {
		Ns_DStringVarAppend(&ds, header, "\t", NULL);
	} else if (conn->request && conn->request->host) {
		Ns_DStringVarAppend(&ds, conn->request->host, "\t", NULL);
	} else {
		Ns_DStringVarAppend(&ds, Ns_ConnHost(conn), "\t", NULL);
	}

	/*------------------------------------------------------------------------*/
	/* Requested Entity														  */
	/* conn->request->line is typically: METHOD /URI PROTOCOL/version		  */
	if (conn->request && conn->request->line) {
		Ns_DStringVarAppend(&ds, "{", conn->request->line, "}\t", NULL);
	} else {
		Ns_DStringAppend(&ds, "{}\t");
	}

	/*------------------------------------------------------------------------*/
	/* HTTP Referer and User-Agent											  */
	Ns_DStringAppend(&ds, "{");
	if ((header = Ns_SetIGet(conn->headers, "Referer"))) {
		Ns_DStringAppend(&ds, header);
	}
	Ns_DStringAppend(&ds, "}\t{");
	if ((header = Ns_SetIGet(conn->headers, "User-Agent"))) {
		Ns_DStringAppend(&ds, header);
	}
	Ns_DStringAppend(&ds, "}");

	/*------------------------------------------------------------------------*/
	syslog(nssyslog->accessLogFacility|LOG_INFO, "%s", ds.string);

	/*------------------------------------------------------------------------*/
	Ns_DStringFree(&ds);
}

// NsTclLogObjCmd/Ns_Log replacement (Ns_Log -> Log).  Load with
//	Tcl_CreateObjCommand?  Tcl_CreateObjCommand will only do part of the work.
//	C-level error log messages directly call the non-ObjCommand function.
/*-
static void SysLogPassThrough(Ns_LogSeverity severity, char *fmt, ...) {
	//TODO// see NsTclLogObjCmd
    va_list ap;
    va_start(ap, fmt);
    Ns_Log(severity, fmt, ap);
    va_end(ap);
}
-*/

static void SysLogCloseCallback(void *arg) {
	closelog();
}
