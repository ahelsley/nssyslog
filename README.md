nssyslog
========

#### Summary ####
A syslog(3) interface for logging requests served from an AOLserver webserver.  Future work will attempt to log error messages to syslog(3) as well.

#### Introduction ####
Standardized and centralized logging are often required by information security compliance frameworks (i.e. FISMA, SOX, ...).  This module helps provide that for AOLserver mostly without patching the original code and using the simple syslog(3) BSD 4.2/POSIX.1-2001 API that is available on most *NIX platforms.

#### Configuration ####
All module configuration parameters are optional.  A complete module configuration looks like:

    ns_section  "ns/server/$server/module/nssyslog"
    ns_param    accessLogFacility   daemon
    ns_param    errorLogFacility    local3
    ns_param    priority            info
    ns_param    logMask             0
    ns_param    suppressQueryP      false
    
    ns_section  "ns/server/$server/modules"
    ns_param    nssyslog        ${aolserver_bindir}/nssyslog.so

#### Testing ####
To test the module, configure it as above then start your AOLserver instance.  While the server is starting, tail(1) your system log (Linux: /var/log/messages, MacOSX: /var/log/system).  Once the server is listening for HTTP requests, retrieve a web page.  You should see information about the request and its related resources in the system log.
