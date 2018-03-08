##Configuring a minimal NGINX server

###What are we doing?

We are configuring a minimal NGINX web server and will occasionally be talking to it with curl and siege.

###Why are we doing this?

A secure server is one that permits only as much as what is really needed. Ideally, you would build a server based on a minimal system by enabling additional features individually. This is also preferable in terms of understanding what’s going on, because this is the only way of knowing what is really configured.
Starting with a minimal system is also helpful in debugging. If the error is not present in the minimal system, features are added individually and the search for the error goes on. When the error occurs, it is identified to be related to the last configuration directive added.

###Requirements

* An NGINX web server, ideally one created using the file structure shown in [Tutorial 1 (Compiling a NGINX web server)](https://www.netnea.com/cms/nginx-tutorial-1_compiling-nginx).

###Step 1: Creating a minimal configuration

Our web server is stored in `/nginx` on the file system. It’s default configuration is located in `/nginx/conf/httpd.conf`. That configuration is okay, even if it is a bit untidy. We can do better and replace it with a very brief configuration that is right to the point. NGINX plays into our arms by coming with sane default values. 
This allows us to be very terse.

```bash
daemon            off;
worker_processes  2;
user              www-data;

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

    server {
        server_name   localhost;
        listen        80;

        error_page    500 502 503 504  /50x.html;

        location      / {
            root      html;
        }

    }

}

```

###Step 2: Understanding the configuration

Let’s go through this configuration step-by-step.

We start off the configuration with the directive `daemon`. A webserver process is generally a process that runs int he background, it's a unix daemon. Here we tell NGINX to stay in the foreground. This is helpful in a lab setup as we can stop the server with `CTRL-c` that way and we are always sure if it is running or not. The directive `worker_processes` tells the master process to spawn two processes that will handle the HTTP calls. And then the `user` directive that assigns the user `nobody` with the `nogroup` as its group. What's this? A webserver facing the internet generally listens on privileged ports 80 for starters and then 443 for encrypted traffic. A privileged port can only be bound by the root user, that's why you need to start the server with `sudo`. However, we do not want to perform the serving with the root user. So that NGINX does, it is forking server processes and has them run under a different user. And here we define this user to be `www-data`; a user that comes installed on the system. The user `www-data` is a non-privileged user with minimal rights. Perfect for our use case from a security perspective.

The next block introduced by `events` defines a context that specifies the handling of connection events; new requests coming in. We assign the `epoll` event model that is the most performing model on new Linux system. This defines how the server process and the kernel communicate with one another when a new connection is being initiated. And finally, we use `worker_connections` to define 128 workers per server process. So we have a master process that spawn two worker processes and each of these will accept up to 128 connections.

The directive `error_log` defines the verbosity of the error log. In the first We compiled the server with the compile option `--with-debug`. This is a precondition to be able to enable the log level `debug` here. The other levels ordered by severity are `info`, `notice`, `warn`, `error`, `crit`, `alert`, and `emerg`.

Then we launch a big block with the `http` directive. This tells the server that we want to handle http requests and we initiate a configuration context specifying the details. First, we tell the server to restrict server tokens. This is meant to keep the HTTP `server` header to a minimum. A server needs to identify its software in the response. By default, NGINX responds with it's server version. This could be an information leakage, so we disable this and the response header will now be reduced to `nginx`.

The inclusion of the `mime.types` in the configuration folder helps the server map filename extensions to mime types in the response. Setting The correct mime on the other hand helps a browser display a response correctly. On the next line, we tell the server that we generally work with UTF-8. So in addition to the mime type, the HTTP response header will also indicate this charset to the client.

We proceed to the server context that specifies how the HTTP requests are being handled. We call our server `localhost` for the time being and we instruct it to listen on the TCP port 80. Then we instruct the server to be ready to serve a custom error page for all the HTTP error status codes. That is 500 and above. 500, 502, 503 und 504 should all be handled by an error page 50x.html that came with our NGINX installation.

The `location` block that follows maps the document root folder `/` to the relative folder `html`. In our setup this resolves to `/nginx/html` on the file system.

And with this, we're already done with this basic configuration.

###Step 3: Starting the server

Our minimal server has thus been described. It would be possible to define a server that is even more bare bones. It would however not be as comfortable to work with as ours and it would not be any more secure. A certain amount of basic security is however advisable. This is because in the lab we are building a service which should then with specific adjustments be able to be put into a production environment. Wanting to secure a service from top to bottom right before entering a production environment is illusory.

Let’s now start the server in the foreground and not as a daemon:

```bash

$> cd /nginx
$> sudo sbin/nginx
```

###Step 4: Talking to the server using curl

Now we can again communicate with the server from a web browser. But working in the shell at first can be more effective, making it easier to understand what is going on.

```bash
$> curl http://localhost/index.html
```

Returns the following:

```bash
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
```

We have thus sent an HTTP request and have received a response from our minimally configured server, meeting our expectations.

###Step 5: Examining requests and responses

This is what happens during an HTTP request. But what exactly is the server saying to us? To find out, let’s start _curl_. This time with the _verbose_ option.

```bash
$> curl --verbose http://localhost/index.html
*   Trying 127.0.0.1...
* Connected to localhost (127.0.0.1) port 80 (#0)
> GET /index.html HTTP/1.1
> Host: localhost
> User-Agent: curl/7.47.0
> Accept: */*
> 
< HTTP/1.1 200 OK
< Server: nginx
< Date: Thu, 01 Mar 2018 20:53:15 GMT
< Content-Type: text/html; charset=utf-8
< Content-Length: 612
< Last-Modified: Thu, 01 Mar 2018 09:55:09 GMT
< Connection: keep-alive
< ETag: "5a97cdfd-264"
< Accept-Ranges: bytes
< 
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>
```

The lines marked with a asterisk (*) describe messages concerning opening and closing the connection. They do not reflect network traffic. The request follows > and the response <.

Specifically, an HTTP request comprises 4 parts:

* Request line and request header
* Request body (optional and missing here for a GET request)
* Response header
* Response body

We don’t have to worry about the first parts just yet. It’s the _response headers_ that are interesting. This is the part used by the web server to describe the response. The actual response, the _response body_, follows after an empty line.

In order, what do the headers mean?

At first comes the _status_ line including the _protocol_, the version, followed by the _status code_. _200 OK_ is the normal response from a web server. Then comes the _server_ line immediately. Here, our NGINX web server identifies itself. This is the shortest possible identification. We have defined it using _server_tokens_ above.
On the next line we see the date and time as defined on the server.

The next line brings the Content-Type of the response, extended to include the charset UTF-8 as well. And then follows the Content-Length. This is interesting. It specifies how many bytes to expect in the _response body_. 612 bytes in our case.
The server will then tell us when the file the response is based on was last changed, i.e. the _Unix modified timestamp_. _Connection_, _ETag_ and _Accept-Ranges_ don’t require our attention for the moment. 

Incidentally, the order of these headers is characteristic for web servers. _Apache_ uses a different order and, for instance, puts the date before the _server header_ and that is hard-wired into the binary without a config option to change it. So even if we would change the identification to mislead a potential attacker, we would still be able to identify NGINX. So it's not worth bothering.

###Step 6: Examining the response a bit more closely

During communication it is possible to get a somewhat more detailed view in _curl_. We use the _--trace-ascii_ command line parameter to do this:

```bash
$> curl   http://localhost/index.html --trace-ascii -
Warning: --trace-ascii overrides an earlier trace/verbose option
== Info:   Trying 127.0.0.1...
== Info: Connected to localhost (127.0.0.1) port 80 (#0)
=> Send header, 83 bytes (0x53)
0000: GET /index.html HTTP/1.1
001a: Host: localhost
002b: User-Agent: curl/7.47.0
0044: Accept: */*
0051: 
<= Recv header, 17 bytes (0x11)
0000: HTTP/1.1 200 OK
<= Recv header, 15 bytes (0xf)
0000: Server: nginx
<= Recv header, 37 bytes (0x25)
0000: Date: Thu, 01 Mar 2018 21:01:37 GMT
<= Recv header, 40 bytes (0x28)
0000: Content-Type: text/html; charset=utf-8
<= Recv header, 21 bytes (0x15)
0000: Content-Length: 612
<= Recv header, 46 bytes (0x2e)
0000: Last-Modified: Thu, 01 Mar 2018 09:55:09 GMT
<= Recv header, 24 bytes (0x18)
0000: Connection: keep-alive
<= Recv header, 22 bytes (0x16)
0000: ETag: "5a97cdfd-264"
<= Recv header, 22 bytes (0x16)
0000: Accept-Ranges: bytes
<= Recv header, 2 bytes (0x2)
0000: 
<= Recv data, 612 bytes (0x264)
0000: <!DOCTYPE html>.<html>.<head>.<title>Welcome to nginx!</title>.<
0040: style>.    body {.        width: 35em;.        margin: 0 auto;. 
0080:        font-family: Tahoma, Verdana, Arial, sans-serif;.    }.</
00c0: style>.</head>.<body>.<h1>Welcome to nginx!</h1>.<p>If you see t
0100: his page, the nginx web server is successfully installed and.wor
0140: king. Further configuration is required.</p>..<p>For online docu
0180: mentation and support please refer to.<a href="http://nginx.org/
01c0: ">nginx.org</a>.<br/>.Commercial support is available at.<a href
0200: ="http://nginx.com/">nginx.com</a>.</p>..<p><em>Thank you for us
0240: ing nginx.</em></p>.</body>.</html>.
...
```

_--trace-ascii_ requires a file as a parameter in order to make an _ASCII dump_ of communication in it. "-" works as a shortcut for _STDOUT_, enabling us to easily see what is being logged.

Compared to _verbose_, _trace-ascii_ provides more details about the length of transferred bytes in the _request_ and _response_ phase. The request headers in the example above are thus 83 bytes. The bytes are then listed for each header in the response and overall for the body in the response: 612 bytes. This may seem like we are splitting hairs. But in fact, it can be crucial when something is missing and it is not quite certain what or where in the sequence it was delivered. Thus, it’s worth noting that 2 bytes are added to each header line. These are the CR (carriage returns) and NL (new lines) in the header lines included in the HTTP protocol. This is different in the response body, which returns only what is actually in the file. This is obviously only one NL without CR here. On the last line qupted (_0240: ing nginx._) a point comes after the greater than character. This is code for the NL character in the response, which like other escape sequences is output in the form of a point.


###Step 7: Using "siege" to test the server

So much for the simple server. But just for fun we can put it to the test. We’ll perform a small performance test using _siege_. This is a fairly simple benchmarking program able to quickly give you initial performance results. I like to run a little performance test before and after a configuration change to get an idea about whether anything in terms of performance has changed. _siege_ is very powerful and calling it locally does not give you clean results. But you can get an initial impression using this tool.

```bash
$> siege --concurrent 100 --reps 10 http://localhost/index.html
```

We are starting _siege_ using _concurrency 100_. The means that we are executing 100 requests at a time. In total, we will be executing 100 x 10 requests from the known _URL_. This is the output from _siege_:

```bash
** SIEGE 3.0.8
** Preparing 100 concurrent users for battle.
The server is now under siege..      done.

Transactions:                   1000 hits
Availability:                 100.00 %
Elapsed time:                   9.02 secs
Data transferred:               0.58 MB
Response time:                  0.00 secs
Transaction rate:             110.86 trans/sec
Throughput:                     0.06 MB/sec
Concurrency:                    0.36
Successful transactions:        1000
Failed transactions:               0
Longest transaction:            0.02
Shortest transaction:           0.00
 
FILE: /var/log/siege.log
You can disable this annoying message by editing
the .siegerc file in your home directory; change
the directive 'show-logfile' to false.
[error] unable to create log file: /var/log/siege.log: Permission denied

```

What’s of primary interest to us is the number of errors (_Failed requests_) and the number of requests per second (_Requests per second_). We are not getting very high with our configuration since we defined the error log level _debug_ which is a horrible performance hog.

That's it for this lesson. I hope you learnt something even if much of it was repetition.


###References

* NGINX: [https://nginx.org](http://nginx.org)
* NGINX directives: [https://nginx.org/en/docs/dirindex.html](https://nginx.org/en/docs/dirindex.html)
* HTTP headers: [https://en.wikipedia.org/wiki/List_of_HTTP_header_fields](http://en.wikipedia.org/wiki/List_of_HTTP_header_fields)
* RFC 2616 (HTTP protocol): (http://www.ietf.org/rfc/rfc2616.txt](http://www.ietf.org/rfc/rfc2616.txt)


### License / Copying / Further use

<a rel="license" href="http://creativecommons.org/licenses/by-nc-sa/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by-nc-sa/4.0/80x15.png" /></a><br />This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by-nc-sa/4.0/">Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License</a>.


