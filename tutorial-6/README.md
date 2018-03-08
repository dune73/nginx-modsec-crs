##Embedding ModSecurity 

###What are we doing?
We are compiling the ModSecurity module, embedding it in the Apache web server, creating a base configuration and dealing with _false positives_ for the first time.

###Why are we doing this?

ModSecurity is a security module for the web server. The tool enables the inspection of both the request and the response according to predefined rules. This is also called a _Web Application Firewall_. It gives the administrator direct control over the requests and the responses passing through the system. The module also provides new options for monitoring, because the entire traffic between client and server can be written 1:1 to the hard disk. This helps with debugging.


###Requirements

* An NGINX web server, ideally one created using the file structure shown in [Tutorial 1 (Compiling a NGINX web server)](https://www.netnea.com/cms/nginx-tutorial-1_compiling-nginx/).
* Understanding of the minimal configuration [Tutorial 2 (Configuring a Minimal NGINX Web Server)](https://www.netnea.com/cms/nginx-tutorial-2_minimal-nginx-configuration/).

###Step 1: Downloading the source code and verifying the checksum

We previously downloaded the source code for the web server to <i>/usr/src/nginx</i>. We will now be doing the same with ModSecurity. To do so, we create the directory <i>/usr/src/modsecurity/</i> as root, we transfer it to ourselves and then download the code into the folder. 

```bash
$> sudo mkdir /usr/src/modsecurity
$> sudo chown `whoami` /usr/src/modsecurity
$> cd /usr/src/modsecurity
$> wget https://github.com/SpiderLabs/ModSecurity/releases/download/v3.0.0/modsecurity-v3.0.0.tar.gz
```

Compressed, the source code is just below 3 megabytes in size. We now need to verify the checksum. It is provided in SHA256 format.

```bash
$> wget https://github.com/SpiderLabs/ModSecurity/releases/download/v3.0.0/modsecurity-v3.0.0.tar.gz.sha256
$> sha256sum --check modsecurity-v3.0.0.tar.gz.sha256 
```

We expect the following response:

```bash
modsecurity-v3.0.0.tar.gz: OK
```

###Step 2: Unpacking and configuring the compiler

We now unpack the source code and initiate the configuration. But before this it is essential to install several packages that constitute the prerequisite for compiling _ModSecurity_. If you did the first tutorial in this series, you should be covered, but it's still worth checking the following list of packages is really ready: A library for parsing XML structures, the base header files of the system’s own Regular Expression Library and everything to work with JSON files. Like in the previous tutorials, we are working on a system from the Debian family. The packages are thus named as follows:

* libxml2 
* libxml2-dev
* libexpat1-dev
* libpcre3-dev
* libpcre++-dev 
* libyajl-dev
* libgeoip-dev 
* libcurl4-gnutls-dev 
* dh-autoreconf 


The stage is thus set and we are ready for ModSecurity.

```bash
$> tar -xvzf modsecurity-v3.0.0.tar.gz 
$> cd modsecurity-v3.0.0/
$> ./configure --prefix=/opt/modsecurity-3.0.0 --enable-mutex-on-pm
```

We created the <i>/apache</i> symlink in the tutorial on compiling Apache. This again comes to our assistance, because independent from the Apache version being used, we can now have the ModSecurity configuration always work with the same parameters and always get access to the current Apache web server. The first two options establish the link to the Apache binary, since we have to make sure that ModSecurity is working with the right API version. The _with-pcre_ option defines that we are using the system’s own _PCRE-Library_, or Regular Expression Library, and not the one provided by Apache. This gives us a certain level of flexibility for updates, because we are becoming independent from Apache in this area, which has proven to work in practice. It requires the first installed _libpcre3-dev_ package.

###Step 3: Compiling and installing standalone ModSecurity

Following this preparation compiling should no longer pose a problem.

```bash
$> make
```

Installation is also easily accomplished. Since we continue to be working on a test system, we transfer ownership of the installed module from the root user to ourselves, because for all of the NGINX binaries we made sure to be the owner ourselves. This in turn produces a clean setup with uniform ownerships.

```bash
$> sudo make install
$> sudo chown -R `whoami` /opt/modsecurity-3.0.0
```

###Step 4: Compiling the connector module

ModSecurity 3.0 runs standalone. It is integrated via a NGINX module that organises the exchange between the webserver and ModSecurity. This allows ModSecurity remain webserver agnostic while the whole integration happens in the connector module.

```bash
$> cd /usr/src/modsecurity
$> wget https://github.com/SpiderLabs/ModSecurity-nginx/releases/download/v1.0.0/modsecurity-nginx-v1.0.0.tar.gz
$> wget https://github.com/SpiderLabs/ModSecurity-nginx/releases/download/v1.0.0/modsecurity-nginx-v1.0.0.tar.gz.sha256
$> sha256sum --check modsecurity-nginx-v1.0.0.tar.gz.sha256
modsecurity-nginx-v1.0.0.tar.gz: OK
```

This seems to be alright, let's unpack this archive and return to the NGINX source code:

```bash
$> tar -xvzf modsecurity-nginx-v1.0.0.tar.gz
$> cd /usr/src/nginx/nginx-1.13.9
$> ./configure --prefix=/opt/nginx-1.13.9 --with-http_ssl_module --with-threads --with-file-aio --with-debug --with-compat --add-dynamic-module=/usr/src/modsecurity/modsecurity-nginx-v1.0.0
```

This should be smooth. When it's done, then you can proceed and build the module

```bash
$> make modules
```

We want to copy this module to the nginx destination. Let's create a folder to allow for this:

```bash
$> [ ! -d /nginx/modules ] && mkdir /nginx/modules
$> cp objs/ngx_http_modsecurity_module.so /nginx/modules
```
That's it. Let's see if we can launch the webserver together with ModSecurity.

###Step 5: Creating the base configuration

We start with the setup up a base ModSecurity configuration. ModSecurity is now a standalone WAF directed by NGINX with the help of a dynamic connector module. So our configuration needs to load said module and then configure ModSecurity. It is best to use our existing configuration and to extend it for ModSecurity:

```bash

daemon            off;
worker_processes  2;
user              www-data;

load_module modules/ngx_http_modsecurity_module.so;

events {
    use           epoll;
    worker_connections  128;
}

error_log         logs/error.log debug;


http {
    server_tokens off;
    
    include       mime.types;
    charset       utf-8;

    access_log    logs/access.log  combined;

    modsecurity on;

    modsecurity_rules '
    
                SecRuleEngine On
                SecRequestBodyAccess On
                SecRequestBodyLimit 13107200

                SecRequestBodyNoFilesLimit 64000

                SecResponseBodyAccess On
                SecResponseBodyLimit 10000000

                SecTmpDir /tmp/
                SecDataDir /tmp/
                SecUploadDir /tmp/

                SecAuditEngine RelevantOnly
                SecAuditLogRelevantStatus "^(?:5|4(?!04))"
                SecAuditLogParts ABEFHIJZ

                SecAuditLogType Serial
                SecAuditLog logs/modsec_audit.log

                SecPcreMatchLimit 500000
                SecPcreMatchLimitRecursion 500000

                SecDebugLog logs/modsec_debug.log
                SecDebugLogLevel 0

    ';

    server {
        server_name   localhost;
        listen        127.0.0.1:40080;

        error_page    500 502 503 504  /50x.html;

        location      / {
            root      html;
        }

    }

}
```

FIXME

The ModSecurity base configuration begins on the next line: We define the base settings of the module in this part. Then in a separate part come individual security rules, most of which are a bit complicated. Let’s go through this configuration step-by-step: _SecRuleEngine_ is what enables ModSecurity in the first place. We then enable access to the request body and set two limits: By default only the header lines of the request are examined. This is like looking only at the envelope of a letter. Inspecting the body and thus the content of the request of course involves more work and takes more time, but a large number of attacks are not detectable from outside, which is why we are enabling this. We then limit the size of the request body to 10 MB. This includes file uploads. For requests with body, but without file upload, such as an online form, we then specify 64 KB as the limit. In detail, *SecRequestBodyNoFilesLimit* is responsible for *Content-Type application/x-www-form-urlencoded*, while *SecRequestBodyLimit* takes care of *Content-Type: multipart/form-data*.

On the response side we enable body access and in turn define a limit of 10 MB. No differentiation is made here in the transfer of forms or files; all of them are files.

Now comes the memory reserved for the _PCRE library_. ModSecurity documentation suggests a value of 1000 matches. But this quickly leads to problems in practice. Our base configuration with a limit of 100000 is much more robust. If problems still occur, values above 100000 are also manageable; memory requirements grow only marginally.

ModSecurity requires three directories for data storage. We put all of them in the _tmp directory_. For productive operation this is of course the wrong place, but for the first baby steps it’s fine and it is not easy to give general recommendations for the right choice of this directory, because the local environment plays a big role.  For the aforementioned directories this concerns temporary data, a storage for file uploads that raised suspicion and finally about session data that should be retained after a server restart, 

ModSecurity has a very detailed _debug log_. The configurable log level ranges from 0 to 9. We leave it at 0 and are prepared to be able to increase it when problems occur in order to see exactly how the module is working. In addition to the actual _rule engine_, an _audit engine_ also runs within ModSecurity. It organizes the logging of requests. Because in case of attack we would like to get as much information as possible. With _SecAuditEngine RelevantOnly_ we define that only _relevant_ requests should be logged. What’s relevant to us is what we define on the next line via a regular expression: All requests whose HTTP status begins with 4 or 5, but not 404. At a later point in time we will see that other things can be defined as relevant, but this rough classification is good enough for the start. It then continues with a definition of the parts of this request that should be logged. We are already familiar with the request header (part B), the request body (part I), the response header (part F) and the response body (part E). Then comes additional information from ModSecurity (parts A, H, K, Z) and details about uploaded files, which we do not map completely (part J). A detailed explanation of these audit log parts are available in the ModSecurity reference manual.

Depending on request, a large volume of data is written to the audit log. There are often several hundred lines for each request. On a server under a heavy load with many simultaneous requests this can cause problems writing the file. This is why the _Concurrent Log Format_ was introduced. It keeps a central audit log including the most important information. The detailed information in the parts just described are stored in in individual files. These files are placed in the directory tree defined using the _SecAuditLogStorageDir_ directive. Every day, ModSecurity creates a directory in this tree and another directory for each minute of the day (however, only if a request was actually logged within this minute). In them are the individual requests with file names labeled by date, time and the unique ID of the request.

Here is an example from the central audit log:

```bash
localhost 127.0.0.1 - - [17/Oct/2015:15:54:54 +0200] "POST /index.html HTTP/1.1" 200 45 "-" "-" \
UYkHrn8AAQEAAHb-AM0AAAAB "-" /20130507/20130507-1554/20130507-155454-UYkHrn8AAQEAAHb-AM0AAAAB \
0 20343 md5:a395b35a53c836f14514b3fff7e45308
```

We see some information about the request, the HTTP status code and shortly afterward the _unique ID_ of the request, which we also find in our access log. An absolute path follows a bit later. But it only appears to be absolute. Specifically, we have to add this part of the path to the value in _SecAuditLogStorageDir_. For us this means _/apache/logs/audit/20130507/20130507-1554/20130507-155454-UYkHrn8AAQEAAHb-AM0AAAAB_. We can then find the details about the request in this file.

```bash
--5a70c866-A--
[17/Oct/2013:15:54:54 +0200] UYkHrn8AAQEAAHb-AM0AAAAB 127.0.0.1 42406 127.0.0.1 80
--5a70c866-B--
POST /index.html HTTP/1.1
User-Agent: curl/7.35.0 (x86_64-pc-linux-gnu) libcurl/7.35.0 OpenSSL/1.0.1 zlib/1.2.3.4 libidn/1.23 …  
Accept: */*
Host: 127.0.0.1
Content-Length: 3
Content-Type: application/x-www-form-urlencoded

...

```

The parts described divide the file into sections. What follows is part _--5a70c866-A--_ as part A, then _--5a70c866-B--_ as part B, etc. We will be having a look at this log in detail in a subsequent tutorial. This introduction should suffice for the moment. But what is not sufficient is our file system. Because, in order to write the _audit log_ at all, the directory must first be created and the appropriate permissions assigned:

```bash
$> sudo mkdir /apache/logs/audit
$> sudo chown www-data:www-data /apache/logs/audit
```

This brings us to the _SecDefaultAction_ directive. It denotes the basic setting of a security rule. Although we can define this value for each rule, it is normal to work with one default value which is then inherited by all of the rules. ModSecurity is aware of five phases. Phase 1 listed here starts once the request headers have arrived on the server. The other phases are the _request body phase (phase 2)_, _response header phase (phase 3)_, _response body phase (phase 4)_ and the _logging phase (phase 5)_. We then say that when a rule takes effect we would normally like the request to pass. We will be defining blocking measures separately. We would like to log; meaning that we would like to see a message about the triggered rule in the Apache server's _error log_ and ultimately assign each of these log entries a *tag*. The tag set, _Local Lab Service_, is only one example of the strings, even several of them, that can be set. In a larger company it can for example be useful for adding additional information about a service (contract number, customer contact details, references to documentation, etc.). This information is then included along with every log entry. This may first sound like a waste of resources, but one employee on an operational security team may be responsible for several hundred services and the URL alone is not enough at this time for unknown services. These service metadata, added by using tags, enable a quick and appropriate reaction to attacks.

This brings us to the ModSecurity rules. Although the module works with the limits defined above, the actual functionality lies mainly in the individual rules that can be expressed in their own rule language. But before we have a look at the individual rules, a comment section with definitions of the namespace of the rule ID numbers follows in the Apache configuration. Each ModSecurity rule has a number for identification. In order to keep the rules manageable, it is useful to cleanly divide up the namespace.

The OWASP ModSecurity Core Rule Set project provides a basic set of over 200 ModSecurity rules. We will be embedding these rules in the next tutorial. They have IDs beginning with the number 900,000 and range up to 999,999. For this reason, we shouldn't set up any rules in this range. The ModSecurity sample configuration provides a few rules in the range starting at 200,000. Our own rules are best organized in the big spaces in between. I suggest keeping in the range below 100,000.

If ModSecurity is being used for multiple services, eventually some shared rules will be used. These are self-written rules configured for each of their own instances. We put these in the 80,000 to 99,999 range. For the other service-specific rules it often plays a role as to whether they are defined before or after the core rules. For logical reasons, we therefore divide the remaining space into two sections: 10,000 to 49,999 for service-specific rules before the core rules and 50,000 to 79,999 after the core rules. Although we won’t yet be embedding the core rules in this tutorial, we will be preparing for them. It bears mentioning that the rule ID has nothing to do with the order of the execution of the rules.

This brings us to the first rules. We start off with a block of performance data. There are not yet any security-related rules, but the definition of information for the path of the request within ModSecurity. We use the _SecAction_ directive. A _SecAction_ is always performed without condition. A comma separated list with instructions follows as parameters. We initially define the rule ID, then the phase in which the rule is to run (1 to 5). We do no wish to have an entry in the server’s error log (_nolog_). Furthermore, we let the request _pass_ and set multiple internal variables: We define a timestamp for each ModSecurity phase. As it were, an intermediate time within the request when starting each individual phase. This is done by using the clock running in the form of the _Duration_ variables which begin ticking in microseconds at the start of the request.

The rule with ID 90005 is commented out. We can enable it in order to set the Apache *write_perflog* environment variable. Once we do that the performance log defined in the Apache section will be written. This rule is no longer defined as _SecAction_, but as _SecRule_. A preceding condition is added to the rule instruction here. In our case we inspect *REQUEST_FILENAME* with respect to the beginning of the string. If the string begins with _/_, then the subsequent instructions including setting the environment variables should be performed. Of course, every valid request URI begins with the _/_ character. But if we only want to enable the log for specific paths (e.g. _/login_), we are then prepared for this and only need to modify the path.

So much for this performance part. Now come the rules proposed by the *ModSecurity* project in the sample configuration file. They have rule IDs starting at 200,000 and are not very numerous. The first rule inspects the _request headers Content-Type_. The rule applies when these headers match the text _text/xml_. It is evaluated in phase 1. After the phase comes the _t:none_ instruction. This means _transformation: none_. We do not want to transform the parameters of the request prior to processing this rule. Following _t:none_ a transformation with the self-explanatory name _t:lowercase_ is applied to the text. Using _t:none_ we delete all predefined default transformations if need be and then execute _t:lowercase_. This means that we will be touching _text/xml_, _Text/Xml_, _TEXT/XML_ and all other combinations in the _Content-Type_ header. If this rule applies, then we perform a _control action_ at the very end of the line: We choose _XML_ as the processor of the _request body_. There is one detail still to be explained: The preceding commented out rule introduced the operator _@beginsWith_. By contrast, no operator is designated here. _Default-Operator @rx_ is applied. This is an operator for regular expressions (_regex_). As expected, _beginsWith_ is a very fast operator while working with regular expressions is cumbersome and slow.

The next rule is an almost exact copy of this rule. It uses the same mechanism to apply the JSON request body processor to the request body. This allows us access to the individual parameters inside the post payload.

By contrast, the next rule is a bit more complicated. We are inspecting the internal *REQBODY_ERROR* variable. In the condition part we use the numerical comparison operator _@eq_. The exclamation mark in front negates its value. The syntax thus means if the *REQBODY_ERROR* is not equal to zero. Of course, we could also work with a regular expression here, but the _@eq_ operator is more efficient when being processed by the module. In the action part of the rule _deny_ is applied for the first time. The request should thus be blocked if processing the request body resulted in an error. Specifically, we return HTTP status code _400 Bad Request_ (_status:400_). We would like to log first and specify the message. As additional information we also write to a separate log field called _logdata_ the exact description of the error. This information will appear in both the server’s error log as well as in the audit log. Finally, the _severity_ is assigned to the rule. This is the degree of importance for the rule, which can be used in evaluating very many rule violations.

The rule with the ID 200003 also deals with errors in the request body. This concerns _multipart HTTP bodies_. It applies if files are to be transferred to the server via HTTP requests. This is very useful on the one hand, but poses a big security problem on the other. This is why ModSecurity very precisely inspects _multipart HTTP bodies_. It has an internal variable called *MULTIPART_STRICT_ERROR*, which combines the numerous checks. If there is a value other than 0 here, then we block the request using status code 403 (_forbidden_). In the log message we then report the results of the individual checks. In practice you have to know that in very rare cases this rule may also be applied to legitimate requests. If this is the case, it may have to be modified or disabled as a _false positive_. We will be returning to the elimination of false positives further below and will become familiar with the topic in detail in a subsequent tutorial.

The ModSecurity distribution sample configuration has another rule with ID 200004. However, I have not included it in the tutorial, because in practice it blocks too many legitimate requests (_false positives_). The *MULTIPART_UNMATCHED_BOUNDARY* variable is checked. This value, which signifies an error in the boundary of multipart bodies, is prone to error and frequently reports text snippets which do not indicate boundaries. In my opinion, it has not shown itself to be useful in practice.

With 200005 comes another rule which intercepts internal processing errors. Unlike the preceding internal variables, here we are looking for a group of variables dynamically provided along with the current request. A data sheet called _TX_ (transaction) is opened for each request. In ModSecurity jargon we refer to a _collection_ of variables and values. While processing a request ModSecurity now in some circumstances sets additional values in the _TX collection_, in addition to the variables already inspected. The names of these variables begin with the prefix *MSC_*. We now access in parallel all variables of this pattern in the collection. This is done via the *TX:/^MSC_/* construct. Thus, the transaction collection and then variable names matching the regular expression *^MSC_*: A word beginning with *MSC_*. If one of these found variables is not equal to zero, we then block the request using HTTP status 500 (_internal server error_) and write the variable names in the log file.

We have now looked at a few rules and have become familiar with the principle functioning of the ModSecurity _WAF_. The rule language is demanding, but very systematic. The structure is unavoidably oriented to the structure of Apache directives. Because before ModSecurity is able to process the directives, they are read by Apache's configuration parser. This is also accompanied by complexity in the way they are expressed. *ModSecurity* is currently being developed in a direction making the module independent from Apache. We will hopefully be benefitting from a configuration that is easier to read.

Now comes a comment in the configuration file which marks the spot for additional rules to be entered. Following this block, which in some circumstances can become very large, come yet more rules that provide performance data for the performance log defined above. The block containing rule IDs 90010 to 90014 stores the time of the end of the individual ModSecurity phases. This corresponds to the 90000 - 90004 block of IDs we became familiar with above. Calculations with the performance data collected are then performed in the last ModSecurity block. For us this means that we totaling up the time that phase 1 and phase 2 need in the *perf_modsecinbound* variable. In the rule with ID 90100 this variable is first set to the performance of phase 1. Then, the performance of phase 2 is added to it. We have to calculate the variable *perf_application* from the timestamps. To do this, we subtract the end of phase 2 from the start of phase 3 in the subsequent `setvar` actions of the same rule. This is of course not an exact calculation of the time that the application itself needs on the server, because other Apache modules play a role (such as authentication), but the value is an indication that sheds light on whether ModSecurity is actually limiting performance or whether the problem more likely lies with the application. The final variable calculations in the rule work on phases 3 and 4, similar to phases 1 and 2. This gives us three relevant values which simply summarize performance: *perf_modsecinbound*, *perf_application* and *perf_modsecoutbound*. They appear in a separate performance log. We have, however, provided enough space for these three values in the normal access log. There we have _ModSecTimeIn_, _ApplicationTime_ and _ModSecTimeOut_. The following `setenv` actions, still in the same rule, are used to export our _perf_ values to the corresponding environment variables in order for them to appear in the _access log_. And finally, we export the _OWASP ModSecurity Core Rule Set_ anomaly values. These values are not yet written, but because we will be making these rules available in the next tutorial, we can already prepare for variable export here.

We are now at the point that we can understand the performance log. The definition above is accompanied by the following parts:

```bash
LogFormat "[%{%Y-%m-%d %H:%M:%S}t.%{usec_frac}t] %{UNIQUE_ID}e %D \
PerfModSecInbound: %{TX.perf_modsecinbound}M \
PerfAppl: %{TX.perf_application}M \
PerfModSecOutbound: %{TX.perf_modsecoutbound}M \
TS-Phase1: %{TX.ModSecTimestamp1start}M-%{TX.ModSecTimestamp1end}M \
TS-Phase2: %{TX.ModSecTimestamp2start}M-%{TX.ModSecTimestamp2end}M \
TS-Phase3: %{TX.ModSecTimestamp3start}M-%{TX.ModSecTimestamp3end}M \
TS-Phase4: %{TX.ModSecTimestamp4start}M-%{TX.ModSecTimestamp4end}M \
TS-Phase5: %{TX.ModSecTimestamp5start}M-%{TX.ModSecTimestamp5end}M \
Perf-Phase1: %{PERF_PHASE1}M \
Perf-Phase2: %{PERF_PHASE2}M \
Perf-Phase3: %{PERF_PHASE3}M \
Perf-Phase4: %{PERF_PHASE4}M \
Perf-Phase5: %{PERF_PHASE5}M \
Perf-ReadingStorage: %{PERF_SREAD}M \
Perf-ReadingStorage: %{PERF_SWRITE}M \
Perf-GarbageCollection: %{PERF_GC}M \
Perf-ModSecLogging: %{PERF_LOGGING}M \
Perf-ModSecCombined: %{PERF_COMBINED}M" perflog
```

   * %{%Y-%m-%d %H:%M:%S}t.%{usec_frac}t means, as in our normal log, the timestamp the request was received with a precision of microseconds.
   * %{UNIQUE_ID}e : The unique ID of the request
   * %D : The total duration of the request from receiving the request line to the end of the complete request in microseconds.
   * PerfModSecInbound: %{TX.perf_modsecinbound}M : Summary of the time needed by ModSecurity for an inbound request.
   * PerfAppl: %{TX.perf_application}M : Summary of the time used by the application
   * PerfModSecOutbound: %{TX.perf_modsecoutbound}M :  Summary of the time needed in ModSecurity to process the response
   * TS-Phase1: %{TX.ModSecTimestamp1start}M-%{TX.ModSecTimestamp1end}M : The timestamps for the start and end of phase 1 (after receiving the request headers)
   * TS-Phase2: %{TX.ModSecTimestamp2start}M-%{TX.ModSecTimestamp2end}M : The timestamps for the start and end of phase 2 (after receiving the request body)
   * TS-Phase3: %{TX.ModSecTimestamp3start}M-%{TX.ModSecTimestamp3end}M : The timestamps for the start and end of phase 3 (after receiving the response headers) 
   * TS-Phase4: %{TX.ModSecTimestamp4start}M-%{TX.ModSecTimestamp4end}M : The timestamps for the start and end of phase 4 (after receiving the response body)
   * TS-Phase5: %{TX.ModSecTimestamp5start}M-%{TX.ModSecTimestamp5end}M : The timestamps for the start and end of phase 5 (logging phase) 
   * Perf-Phase1: %{PERF_PHASE1}M : Calculation of the performance of the rules in phase 1 performed by ModSecurity
   * Perf-Phase2: %{PERF_PHASE2}M : Calculation of the performance of the rules in phase 2 performed by ModSecurity
   * Perf-Phase3: %{PERF_PHASE3}M : Calculation of the performance of the rules in phase 3 performed by ModSecurity
   * Perf-Phase4: %{PERF_PHASE4}M : Calculation of the performance of the rules in phase 4 performed by ModSecurity
   * Perf-Phase5: %{PERF_PHASE5}M : Calculation of the performance of the rules in phase 5 performed by ModSecurity
   * Perf-ReadingStorage: %{PERF_SREAD}M : The time required to read the ModSecurity session storage
   * Perf-WritingStorage: %{PERF_SWRITE}M : The time required to write the ModSecurity session storage
   * Perf-GarbageCollection: s%{PERF_GC}M \ The time required for garbage collection
   * Perf-ModSecLogging: %{PERF_LOGGING}M : The time used by ModSecurity for logging, specifically the error log and the audit log
   * Perf-ModSecCombined: %{PERF_COMBINED}M : The time ModSecurity requires in total for all work

This long list of numbers can be used to very well narrow down ModSecurity performance problems and rectify them if necessary. When you need to look even deeper, the _debug log_ can help, or make use of the *PERF_RULES* variable collection, which is well explained in the reference manual.

###Step 6: Writing simple blacklist rules

ModSecurity is set up and configured using the configuration above. It can diligently log performance data, but only the rudimentary basis is present on the security side. In a subsequent tutorial we will be embedding the _OWASP ModSecurity Core Rules_, a comprehensive collection of rules. But it’s important for us to first learn how to write rules ourselves. Some rules have already been explained in the base configuration. It's just another small step from here.

Let’s take a simple case: We want to be sure that access to a specific URI on the server is blocked. We want to respond to such a request with _HTTP status 403_. We write the rule for this in the _ModSecurity rule_ section in the configuration and assign it ID 10000 (_service-specific before core-rules_).

```bash
SecRule  REQUEST_FILENAME "/phpmyadmin" "id:10000,phase:1,deny,log,t:lowercase,t:normalisePath,\
  msg:'Blocking access to %{MATCHED_VAR}.',tag:'Blacklist Rules'"
```

We start off the rule using _SecRule_. Then we say that we want to inspect the path of the request using the *REQUEST_FILENAME* variable. If _/phpmyadmin_ appears anywhere in this path we want to block it right away in the first processing phase. The keyword _deny_ does this for us. Our path criterion is maintained in lowercase letters. Because we are using the _t:lowercase_ transformation, we catch all possible lower and uppercase combinations in the path. The path could now of course also point to a subdirectory or be obfuscated in other ways. We remedy this by enabling the _t:normalisePath_ transformation. The path is thus transformed before our rule is applied. We enter a message in the _msg part_, which will then show up in the server’s _error log_ if the rule is triggered. Finally, we assign a tag. We already did this using _SecDefaultAction_ in the base configuration. There is now another tag here that can be used to group different rules.

We call this type of rules _blacklist rules_, because it describes what we want to block. In principle, we let everything pass, except for requests that violate the configured rules. The opposite approach of describing the requests we want and by doing so block all unknown requests is what we call _whitelist rules_. _Blacklist rules_ are easier to write, but often remain incomplete. _Whitelist rules_ are more comprehensive and when written correctly can be used to completely seal off a server. But they are difficult to write and in practice often lead to problems if they are not fully formulated. A _whitelist example_ follows below.

###Step 7: Trying out the blockade

Let’s try out the blockade:

```bash
$> curl http://localhost/phpmyadmin
```

We expect the following response:

```bash
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access /phpmyadmin
on this server.</p>
</body></html>
```

Let’s also have a look at what we can find about this in the _error log_:

```bash
[2017-02-25 06:46:29.793701] [-:error] 127.0.0.1:50430 WLEaNX8AAQEAAFZKT5cAAAAA …
[client 127.0.0.1] ModSecurity: Access denied with code 403 (phase 1). …
Pattern match "/phpmyadmin" at REQUEST_FILENAME. [file "/apache/conf/httpd.conf_pod_2017-02-25_06:45"] …
[line "140"] [id "10000"] [msg "Blocking access to /phpmyadmin."] [tag "Blacklist Rules"]  …
[hostname "localhost"] [uri "/phpmyadmin"] [unique_id "WLEaNX8AAQEAAFZKT5cAAAAA"]
```

Here, _ModSecurity_ describes the rule that was applied and the action taken: First the timestamp. Then the severity of the log entry assigned by Apache. The _error_ stage is assigned to all _ModSecurity_ messages. Then comes the client IP address. Between that there are some empty fields, indicated only by "-". In Apache 2.4 they remain empty, because the log format has changed and *ModSecurity* is not yet able to understand it. Afterwards comes the actual message which opens with action: _Access denied with code 403_, specifically already in phase 1 while receiving the request headers. We then see a message about the rule violation: The string _"/phpMyAdmin"_ was found in the *REQUEST_FILENAME*. This is exactly what we defined. The subsequent bits of information are embedded in blocks of square brackets. In each block first comes the name and then the information separated by a space. Our rule puts us on line 140 in the file */apache/conf/httpd.conf_modsec_minimal*. As we know, the rule has ID 10000. In _msg_ we see the summary of the rule defined in the rule, where the variable *MATCHED_VAR* has been replaced by the path part of the request. Afterwards comes the tag that we set in _SetDefaultAction_; finally, the tag set in addition for this rule. At the end come the hostname, URI and the unique ID of the request.

We will also find more details about this information in the _audit log_ discussed above. However, for normal use the _error log_ is often enough.

###Step 8: Writing simple whitelist rules

Using the rules described in Step 7, we were able to prevent access to a specific URL. We will now be using the opposite approach: We want to make sure that only one specific URL can be accessed. In addition, we will we only be accepting previously known _POST parameters_ in a specified format. This is a very tight security technique which is also called positive security: It is no longer us trying to find known attacks in user submitted content, it is now the user who has to proof that his request meets all our criteria.

Our example is a whitelist for a login with display of the form, submission of the credentials and the logout. We do not have the said login in place, but this does not stop us from defining the ruleset to protect this hypothetical service in our lab. And if you have a login or any other simple application you want to protect, you can take the code as a template and adopt as suitable.

So here are the rules (I will explain them in detail afterwards):

```bash

SecMarker BEGIN_WHITELIST_login

# Make sure there are no URI evasion attempts
SecRule REQUEST_URI "!@streq %{REQUEST_URI_RAW}" \
    "id:10000,phase:1,deny,t:normalizePathWin,log,\
    msg:'URI evasion attempt'"

# START whitelisting block for URI /login
SecRule REQUEST_URI "!@beginsWith /login" \
    "id:10001,phase:1,pass,t:lowercase,nolog,skipAfter:END_WHITELIST_login"
SecRule REQUEST_URI "!@beginsWith /login" \
    "id:10002,phase:2,pass,t:lowercase,nolog,skipAfter:END_WHITELIST_login"

# Validate HTTP method
SecRule REQUEST_METHOD "!@pm GET HEAD POST OPTIONS" \
    "id:10100,phase:1,deny,log,tag:'Login Whitelist',\
    msg:'Method %{MATCHED_VAR} not allowed'"

# Validate URIs
SecRule REQUEST_FILENAME "@beginsWith /login/static/css" \
    "id:10200,phase:1,pass,nolog,tag:'Login Whitelist',\
    skipAfter:END_WHITELIST_URIBLOCK_login"
SecRule REQUEST_FILENAME "@beginsWith /login/static/img" \
    "id:10201,phase:1,pass,nolog,tag:'Login Whitelist',\
    skipAfter:END_WHITELIST_URIBLOCK_login"
SecRule REQUEST_FILENAME "@beginsWith /login/static/js" \
    "id:10202,phase:1,pass,nolog,tag:'Login Whitelist',\
    skipAfter:END_WHITELIST_URIBLOCK_login"
SecRule REQUEST_FILENAME \
    "@rx ^/login/(displayLogin|login|logout).do$" \
    "id:10250,phase:1,pass,nolog,tag:'Login Whitelist',\
    skipAfter:END_WHITELIST_URIBLOCK_login"

# If we land here, we are facing an unknown URI,
# which is why we will respond using the 404 status code
SecAction "id:10299,phase:1,deny,status:404,log,tag:'Login Whitelist',\
    msg:'Unknown URI %{REQUEST_URI}'"

SecMarker END_WHITELIST_URIBLOCK_login

# Validate parameter names
SecRule ARGS_NAMES "!@rx ^(username|password|sectoken)$" \
    "id:10300,phase:2,deny,log,tag:'Login Whitelist',\
    msg:'Unknown parameter: %{MATCHED_VAR_NAME}'"

# Validate each parameter's cardinality
SecRule &ARGS:username  "@gt 1" \
    "id:10400,phase:2,deny,log,tag:'Login Whitelist',\
    msg:'%{MATCHED_VAR_NAME} occurring more than once'"
SecRule &ARGS:password  "@gt 1" \
    "id:10401,phase:2,deny,log,tag:'Login Whitelist',\
    msg:'%{MATCHED_VAR_NAME} occurring more than once'"
SecRule &ARGS:sectoken  "@gt 1" \
    "id:10402,phase:2,deny,log,tag:'Login Whitelist',\
    msg:'%{MATCHED_VAR_NAME} occurring more than once'"

# Check individual parameters
SecRule ARGS:username "!@rx ^[a-zA-Z0-9.@-]{1,32}$" \
    "id:10500,phase:2,deny,log,tag:'Login Whitelist',\
    msg:'Invalid parameter format: %{MATCHED_VAR_NAME} (%{MATCHED_VAR})'"
SecRule ARGS:sectoken "!@rx ^[a-zA-Z0-9]{32}$" \
    "id:10501,phase:2,deny,log,tag:'Login Whitelist',\
    msg:'Invalid parameter format: %{MATCHED_VAR_NAME} (%{MATCHED_VAR})'"
SecRule ARGS:password "@gt 64" \
    "id:10502,phase:2,deny,log,t:length,tag:'Login Whitelist',\
    msg:'Invalid parameter format: %{MATCHED_VAR_NAME} too long (%{MATCHED_VAR} bytes)'"
SecRule ARGS:password "@validateByteRange 33-244" \
    "id:10503,phase:2,deny,log,tag:'Login Whitelist',\
    msg:'Invalid parameter format: %{MATCHED_VAR_NAME} (%{MATCHED_VAR})'"

SecMarker END_WHITELIST_login

```

Since this is a multi-line set of rules, we delimit the group of rules using two markers: *BEGIN_WHITELIST_login* and *END_WHITELIST_login*. We only need the first marker for readability, but the second one is a jump label. The first rule (ID 10000) enforces our policy to deny requests containing two dots in succession in the URI. Two dots in succession might serve as a way to evade our subsequent path criteria. E.g., constructing an URI which looks like accessing some other folder, but then uses `..` to escape from that folder and access `/login` nevertheless. This rule makes sure none of these games can be played with our server.

In the two following rules (ID 10001 and 10002) we check whether our set of rules is affected at all. If the path written in lowercase and normalized does not begin with _/login_, we skip to the end marker - with no entry in the log file. It would be possible to place the entire block of rules within an Apache *Location* block, however, I prefer the rule style presented here. The whitelist we are constructing is a partial whitelist as it does not cover the whole server. Instead, it focuses on the login with the idea, that the login page will be accessed by anonymous users. Once they have performed the login, they have at least proved their credentials and a certain trust has been established. The login is thus a likely target for anonymous attackers and we want to secure it really well. It is also likely that any application on the server is more complex than the login and writing a positive ruleset for an advanced application would be too complicated for this tutorial. But the limited scope of the login makes it perfectly achievable and it adds a lot of security. The example serves as a template to use for other partial whitelists.

Having established the fact that we are dealing with a login request, we can now write down our rules checking these request. An HTTP request has several characteristics that are of concern to us: The method, the path, the query string parameter as well as any post parameters (this concerns the submission of a login form). We will leave out the request headers including cookies in this example, but they could also become a vulnerability depending on the application and should also be queried then.

First, we look at the HTTP method in rule ID 10100. Displaying the login form is going to be a _GET_ request; submitting the credentials will be a _POST_ request. Some clients like to issue _HEAD_ and _OPTIONS_ requests as well and not much harm is done by permitting these requests. Everything else, _PUT_ and _DELETE_ and all the webdav methods, are being blocked by this rule. We check the four whitelisted methods with a parallel matching operator (`@pm`). This is faster then a regular expression and it is also more readable.

In the rule block starting at rule ID 10200, we examine the URL in detail. We establish three folders, where we allow access to static files: `/login/static/css/`, `/login/static/img/` and `/login/static/js/`. We do not want to micromanage the individual files retrieved from these folders, so we simply allow access to these folders. The rule ID 10250 is different. It defines the targets of the dynamic requests of the users. We construct a regular expression which allows exactly three URIs: `/login/displayLogin.do`, `/login/login.do` and `/login/logout.do`. Anything outside this list is going to be forbidden.

But how is all this checked? After all, it's a complicated set of paths spread over several rules! The rules 10200, 10201, 10202 and 10250 check for the URI. If we have a match, we do not block, but we jump to the label `END_WHITELIST_URIBLOCK_login`. When we arrive at this label, we know that the URI is one of the predefined set: the request adheres to our rules. But if we pass 10250 and still no hit with the URI, then we know that the client looks like an offender and we can block it accordingly. This is performed in the fallback rule with ID 10299. Notice, how this is not a conditional _SecRule_, but a _SecAction_ which is the same thing, but without an operator and without a parameter. The actions are executed immediately with the goal to block the request. Here is a twist: if we block in this rule, we do not tell the client his request was forbidden (HTTP status 403, which would be the default for a _deny_). We return a HTTP status 404 instead and leave the client in the dark about the existence of our ruleset.

Now it is time to look at parameters. There are query string parameters and POST parameters. We could look at them separately, but it is more convenient to treat them as one group. The POST parameters will only be available in the 2nd phase, so all the rules from here to the end of our whitelist will work in phase 2.

There are three things to check for any parameter: the name (do we know the parameter?), the cardinality (is it submitted more than once? I will explain this shortly) and the format (does the parameter follow out predefined pattern?).
We perform the checks one after the other starting with the name in rule ID 10300. Here we check for a predefined list of parameter names. We expect three individual parameters: _username_, _password_ and a _sectoken_. Anything outside this list is forbidden. Unlike the check for the HTTP method, we use a regular expression here even if we could make this rule more readable by using the parallel matching operator `@pm`. The reason being, parallel matching treats uppercase and lowercase characters the same. So you could submit a parameter named _userName_, it would pass the name check and the subsequent rules might overlook it based on the odd capital _N_. So let's stick to the regular expression here.

So what's the matter with this cardinality check. Let me explain it as follows: Suppose an attacker submits a parameter twice in the same request. What will happen in the application? Will the application use the first occurrence? The second occurrence? Both? Or will it concatenate? Honestly, we do not know. That's why we need to stop this: We count all the parameter and if any one of them is appearing more than once, we stop the request. There is one rule for each parameter starting with rule 10400. If you examine the rules carefully, you see the _&_ character in front of the _ARGS_. This means that we do not look at the parameter itself, but we want to count its occurrence. The operator `@gt` will then simply match any sum bigger than 1.

We are slowly coming to an end now. But before we do, we need to look at the individual parameters: Do they match a predefined pattern? In the case of the username (rule ID 10500) and the sectoken (rule ID 10501), the case is quite clear: We know how a username is supposed to look like on our site and for the machine generated sectoken it is even easier. So we use regular expressions to check this format.

The case with the password is less obvious. Apparently, we want users to use a lot of special characters. Ideally special characters outside the standard ascii set. But how do we check their format? We are hitting a limit here. Allowing the full character range, we also allow exploits and there is not much we can do about it with the whitelisting approach. But let's not give up so fast and enforce at least some limit. First we look at the length of the password parameter. Longer parameter means more room to construct an attack. We can limit this by leveraging the _length_ transformation. The operator in the rule will thus not look at the parameter itself, but at its length. The `@ge` operator is a good fit. If the password is longer than 64 bytes, then we deny access. In the next and final rule (ID 10503), we use another operator to validate the byterange. As we are expecting special characters, we need to make sure the visible UTF-8 range is allowed. This enforces some miminal standard, but it also means that the application will need to remain vigilant on the password parameter as it can not be locked down the same way as the username and the sectoken.

This concludes our partial whitelisting example.

###Step 9: Trying out the blockade

But does it really work? Here are some attempts:

```bash
$> curl http://localhost/login/displayLogin.do
-> OK (ModSecurity permits access. But this page itself does not exist. So we get 404, Page not Found)
$> curl http://localhost/login/displayLogin.do?debug=on
-> FAIL
$> curl http://localhost/login/admin.html
-> FAIL (Again a 404, but the error log should show a deny with status 404)
$> curl -d "username=john&password=test" http://localhost/login/login.do
-> OK (ModSecurity permits access. But this page itself does not exist. So we get 404, Page not Found)
$> curl -d "username=john&password=test&backdoor=1" http://localhost/login/login.do
-> FAIL
$> curl -d "username=john56789012345678901234567890123&password=test" http://localhost/login/login.do
-> FAIL
$> curl -d "username=john'&password=test" http://localhost/login/login.do
-> FAIL
$> curl -d "username=john&username=jack&password=test" http://localhost/login/login.do
-> FAIL
```

A glance at the server’s error log proves that the are applied exactly as we defined them (excerpt filtered)

```bash
[2017-12-17 16:04:06.363090] [-:error] 127.0.0.1:53482 WjaHZrq3BsfzODHx0EBwoQAAAAM [client 127.0.0.1] …
ModSecurity: Access denied with code 403 (phase 2). Match of "rx ^(username|password|sectoken)$" …
against "ARGS_NAMES:debug" required. [file "/apache/conf/httpd.conf_pod_2017-12-17_12:10"] [line "227"] …
[id "10300"] [msg "Unknown parameter: ARGS_NAMES:debug"] [tag "Login Whitelist"] [hostname "localhost"] …
[uri "/login/displayLogin.do"] [unique_id "WjaHZrq3BsfzODHx0EBwoQAAAAM"]
[2017-12-17 16:04:13.818721] [-:error] 127.0.0.1:53694 WjaHbbq3BsfzODHx0EBwogAAAAU [client 127.0.0.1] …
ModSecurity: Access denied with code 404 (phase 1). Unconditional match in SecAction. [file …
"/apache/conf/httpd.conf_pod_2017-12-17_12:10"] [line "220"] [id "10299"] …
[msg "Unknown URI /login/admin.html"] [tag "Login Whitelist"] [hostname "localhost"] …
[uri "/login/admin.html"] [unique_id "WjaHbbq3BsfzODHx0EBwogAAAAU"]
[2017-12-17 16:04:27.427211] [-:error] 127.0.0.1:54314 WjaHe7q3BsfzODHx0EBwpAAAAAk [client 127.0.0.1] …
ModSecurity: Access denied with code 403 (phase 2). Match of "rx ^(username|password|sectoken)$" …
against "ARGS_NAMES:backdoor" required. [file "/apache/conf/httpd.conf_pod_2017-12-17_12:10"] …
[line "227"] [id "10300"] [msg "Unknown parameter: ARGS_NAMES:backdoor"] [tag "Login Whitelist"] …
[hostname "localhost"] [uri "/login/login.do"] [unique_id "WjaHe7q3BsfzODHx0EBwpAAAAAk"]
[2017-12-17 16:04:34.347509] [-:error] 127.0.0.1:54616 WjaHgrq3BsfzODHx0EBwpQAAAAo [client 127.0.0.1] …
ModSecurity: Access denied with code 403 (phase 2). Match of "rx ^[a-zA-Z0-9.@-]{1,32}$" against …
"ARGS:username" required. [file "/apache/conf/httpd.conf_pod_2017-12-17_12:10"] [line "243"] [id …
"10500"] [msg "Invalid parameter format: ARGS:username (john56789012345678901234567890123)"] [tag …
"Login Whitelist"] [hostname "localhost"] [uri "/login/login.do"] …
[unique_id "WjaHgrq3BsfzODHx0EBwpQAAAAo"]
[2017-12-17 16:04:42.069838] [-:error] 127.0.0.1:54850 WjaHirq3BsfzODHx0EBwpgAAAAw [client 127.0.0.1] …
ModSecurity: Access denied with code 403 (phase 2). Match of "rx ^[a-zA-Z0-9.@-]{1,32}$" against …
"ARGS:username" required. [file "/apache/conf/httpd.conf_pod_2017-12-17_12:10"] [line "243"] …
[id "10500"] [msg "Invalid parameter format: ARGS:username (john')"] [tag "Login Whitelist"] …
[hostname "localhost"] [uri "/login/login.do"] [unique_id "WjaHirq3BsfzODHx0EBwpgAAAAw"]
[2017-12-17 16:04:55.542582] [-:error] 127.0.0.1:55288 WjaHl7q3BsfzODHx0EBwpwAAAAs [client 127.0.0.1] …
ModSecurity: Access denied with code 403 (phase 2). Operator GT matched 1 at ARGS. [file …
"/apache/conf/httpd.conf_pod_2017-12-17_12:10"] [line "232"] [id "10400"] [msg "ARGS occurring …
more than once"] [tag "Login Whitelist"] [hostname "localhost"] [uri "/login/login.do"] …
[unique_id "WjaHl7q3BsfzODHx0EBwpwAAAAs"]
```

It works from top to bottom and it seems the behaviour is just what we expected.

###Step 10 (Goodie): Writing all client traffic to disk

Before coming to the end of this tutorial here’s one more tip that often proves useful in practice: _ModSecurity_ is not just a _Web Application Firewall_. It is also a very precise debugging tool. The entire traffic between client and server can be logged. This is done as follows:

```bash
SecRule REMOTE_ADDR  "@streq 127.0.0.1"   "id:11000,phase:1,pass,log,auditlog,\
	msg:'Initializing full traffic log'"
```
We then find the traffic for the client 127.0.0.1 specified in the rule in the audit log.

```bash
$> curl localhost
...
$> sudo tail -1 /apache/logs/modsec_audit.log
localhost 127.0.0.1 - - [17/Oct/2015:06:17:08 +0200] "GET /index.html HTTP/1.1" 404 214 "-" "-" …
UcAmDH8AAQEAAGUjAMoAAAAA "-" /20151017/20151017-0617/20151017-061708-UcAmDH8AAQEAAGUjAMoAAAAA …
0 15146 md5:e2537a9239cbbe185116f744bba0ad97 
$> sudo cat /apache/logs/audit/20151017/20151017-0617/20151017-061708-UcAmDH8AAQEAAGUjAMoAAAAA
--c54d6c5e-A--
[17/Oct/2015:06:17:08 +0200] UcAmDH8AAQEAAGUjAMoAAAAA 127.0.0.1 52386 127.0.0.1 80
--c54d6c5e-B--
GET /index.html HTTP/1.1
User-Agent: curl/7.35.0 (x86_64-pc-linux-gnu) libcurl/7.35.0 OpenSSL/1.0.1 zlib/1.2.3.4 libidn/1.23 …
Host: localhost
Accept: */*

--c54d6c5e-F--
HTTP/1.1 200 OK
Date: Tue, 27 Oct 2015 21:39:03 GMT
Server: Apache
Last-Modified: Tue, 06 Oct 2015 11:55:08 GMT
ETag: "2d-5216e4d2e6c03"
Accept-Ranges: bytes
Content-Length: 45

--c54d6c5e-E--
<html><body><h1>It works!</h1></body></html>
...

```

The rule that logs traffic can of course be customized, enabling us to precisely see what goes into the server and what it returns (only a specific client IP, a specific user, only a application part with a specific path, etc.). It often allows you to quickly find out about the misbehavior of an application.

We have reached the end of this tutorial. *ModSecurity* is an important component for the operation of a secure web server. This tutorial has hopefully provided a successful introduction to the topic.

###References

* Apache [https://httpd.apache.org](http://httpd.apache.org)
* ModSecurity [https://www.modsecurity.org](http://www.modsecurity.org)
* ModSecurity Reference Manual [https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual)

### License / Copying / Further use

<a rel="license" href="http://creativecommons.org/licenses/by-nc-sa/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by-nc-sa/4.0/80x15.png" /></a><br />This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by-nc-sa/4.0/">Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License</a>.
