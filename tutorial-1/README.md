## Compiling an NGINX web server

### What are we doing?

We're compiling an NGINX web server for a test system.

### Why are we doing this?

In professional use of the web server it’s at times the case that special requirements (security, additional debugging messages, special features from a new patch, etc.) force you to leave behind the distribution packages and quickly create some binaries on your own. In this case it’s important for the infrastructure to be prepared and to already have experience compiling and running your own binaries on production systems. It’s also easier to work with self-compiled NGINX in a laboratory-like setup, which is also beneficial in terms of debugging. Finally, compiling the server yourself is a useful exercise that helps you to understand the full stack.

### Step 1: Preparing the directory tree for the source code

It’s not all that important where the source code is located. The following is a recommendation based on the [File Hierarchy Standard](http://www.pathname.com/fhs/). The FHS defines the path structure of a Unix system; the structure for all stored files.

```bash
$> sudo mkdir /usr/src/nginx
$> sudo chown `whoami` /usr/src/nginx
$> cd /usr/src/nginx
```

### Step 2: Meeting the requirements for NGINX

NGINX distributes pre-built binaries as part of the NGINX Plus offering. Authentication happens via SSL/TLS keys which makes the installation process a bit tedious. We are compiling the source code ourselves, so we do not have to bother. However, self-compilation means we need to make sure all dependencies are met ourselves.

When compiling, you run a _configure_ command first. This configures the compiler and it gathers a variety of information and settings about our system. The configure command frequently complains about missing components. One thing is certain: Without a working compiler we will be unable to compile and it’s configure’s task to check whether everything is assembled correctly.

Things typically missing:

* build-essential
* binutils
* gcc
* libpcre3-dev
* libssl-dev
* zlib1g-dev

These are the package names on Debian-based distributions. The packages may have different names elsewhere. 
The absence of these files can be easily rectified by re-installing them using the utilities from your own distribution. 

### Step 3: Downloading the source code and verifying the integrity of the code

We’ll now download the program code from [NGINX](https://nginx.org/) in a browser or by using wget on the command line, which is the preferred approach. But we also want to make sure we have an unmanipulated copy of the code. We can do that by checking the signature on the code based on a publicly available key of one of the lead developers. NGINX has Maxim Dounin sign its code. Let's grab his key:

```bash
$> wget http://nginx.org/keys/mdounin.key
...
$> gpg --import mdounin.key
gpg: key A1C052F8: public key "Maxim Dounin <mdounin@mdounin.ru>" imported
gpg: Total number processed: 1
gpg:               imported: 1  (RSA: 1)
gpg: 3 marginal(s) needed, 1 complete(s) needed, classic trust model
gpg: depth: 0  valid:   9  signed:   4  trust: 0-, 0q, 0n, 0m, 0f, 9u
gpg: depth: 1  valid:   4  signed:   5  trust: 2-, 0q, 0n, 1m, 1f, 0u
gpg: depth: 2  valid:   4  signed:   0  trust: 1-, 0q, 0n, 0m, 3f, 0u
gpg: next trustdb check due at 2018-08-19
```

Good. The key is identified by the short ID `A1C052F8`, but actually we need the long ID to check the signature.
Let's get that ID:

```bash
$> gpg --list-keys --keyid-format long A1C052F8
pub   2048R/520A9993A1C052F8 2011-11-27
uid                          Maxim Dounin <mdounin@mdounin.ru>
sub   2048R/57A82F1DD345AB09 2011-11-27
```
With this in our hands, let's download the source code and the signature next to it:

```bash
$> wget https://nginx.org/download/nginx-1.13.9.tar.gz
$> wget https://nginx.org/download/nginx-1.13.9.tar.gz.asc
```

The compressed source code is a bit less than a megabyte in size. Let's now verify everything is correct:

```bash
$> gpg --trusted-key 520A9993A1C052F8 --verify nginx-1.13.9.tar.gz.asc nginx-1.13.9.tar.gz
gpg: Signature made Tue Feb 20 15:10:07 2018 CET using RSA key ID A1C052F8
gpg: Good signature from "Maxim Dounin <mdounin@mdounin.ru>"
```

Perfect. We're finally ready for the configuration of the compiler and the compilation itself.

### Step 4: Unpacking and configuring the compiler

We will start by unpacking the tar archive

```bash
$> tar -xvzf nginx-1.13.9.tar.gz
```

This results in approximately 7 MB.

We now enter the directory and configure the compiler with our options:

```bash
$> cd nginx-1.13.9
$> ./configure --prefix=/opt/nginx-1.13.9 --with-http_ssl_module --with-threads --with-file-aio
...
Configuration summary
  + using threads
  + using system PCRE library
  + using system OpenSSL library
  + using system zlib library

  nginx path prefix: "/opt/nginx-1.13.9"
  nginx binary file: "/opt/nginx-1.13.9/sbin/nginx"
  nginx modules path: "/opt/nginx-1.13.9/modules"
  nginx configuration prefix: "/opt/nginx-1.13.9/conf"
  nginx configuration file: "/opt/nginx-1.13.9/conf/nginx.conf"
  nginx pid file: "/opt/nginx-1.13.9/logs/nginx.pid"
  nginx error log file: "/opt/nginx-1.13.9/logs/error.log"
  nginx http access log file: "/opt/nginx-1.13.9/logs/access.log"
  nginx http client request body temporary files: "client_body_temp"
  nginx http proxy temporary files: "proxy_temp"
  nginx http fastcgi temporary files: "fastcgi_temp"
  nginx http uwsgi temporary files: "uwsgi_temp"
  nginx http scgi temporary files: "scgi_temp"

```

This is where we define the target directory for the future NGINX web server. We are compiling in compliance with the _File Hierarchy Standard_ and will install NGINX under `/opt/nginx-1.13.9`. The `/opt/` file tree allows us to keep our complete installation together under a branch of the tree. If we would look at the alternative `/usr/local` instead, we would need to split binaries, configuration files and logs over multiple branches.

NGINX comes with several dynamic modules we can enable or disable at will. But the encryption module `http_ssl` is not part of the default set. So we need to enable this with a config time option named `--with-http_ssl_module`. After this option, there are two options that affect the performance of the server: `--with-thread` and `with-file-aio`. The threads option does not only enable threads (NGINX is threads-based by default), but it lets you instruct the server to work with pools of threads that are much more dynamic when processing requests. Say you need to wait for a file to be read from the disk. With a thread pool, the server thread hands of this specialised task and jumps to the next request. As soon as the file has been read, a different thread takes over immediately. This technique allows for better use of your resources, as the server threads are never idle.

The file AIO option enables use of high performance asynchronous input and output options in the Linux kernel. Enabling this option frees your server threads by handing over I/O operations to the kernel and concentrate on handling requests. Again, this is a separate module that needs to be called at compile time in order to be available when we configure the server.

At last, we enable the debug logging. NGINX does a fair bit of logging, but with this compile time option, it brings even more log entries which is helpful for debugging situations.

Now you may wonder why we enable performance-relevant options and additional logging in the same binary. But this makes perfect sense for our lab setup actually. We want to try out the performance options in the lab and at the same time we want to be able to dig deep into the logs when hunting for bugs or misconfigurations. For a production server, we would simply leave away the `--with-debug` option.

Once the configure script has finished, please make sure to check the final lines of the output. If they resemble the example output above, then you are on the safe side. If an error is reported, then you will have to solve that problem. Usually it's a missing piece of software that the compilation process and NGINX depends upon.

### Step 5: Compiling

Once _configure_ is completed, we are ready for the compiler. Nothing should go wrong any longer at this point.

```bash
$> make
```

This takes some time and 38 MB becomes just under 100 MB.

### Step 6: Installing

When compiling is successful, we then install the NGINX web server we built ourselves. Installation must be performed by the super user. But right afterwards we’ll see how we can again take ownership of the web server. This is much more practical for a test system.

```bash
$> sudo make install
```

Installation may also take some time.

```bash
$> sudo chown -R `whoami` /opt/nginx-1.13.9
```

And now for a trick: If you work professionally with NGINX then you may have several different versions on the test server. Different versions, different patches, different set of modules, etc. all result in tedious and long pathnames with version numbers and other descriptions. To ease things, I usually create a soft link from `/nginx` to the current NGINX web server when I switch to a new version or compilation. Care must be given that we and not the root user are is the owner of the soft link (this is important in configuring the server).

```bash
$> sudo ln -s /opt/nginx-1.13.9 /nginx
$> sudo chown `whoami` --no-dereference /nginx
$> cd /nginx
```

Our web server now has a pathname clearly describing it by version number. We will however simply use `/nginx` for access. This makes work easier.

### Step 7: Starting

Now let’s see if our server will start up. For the moment, this again has to be done by the super user:

```bash
$> sudo ./sbin/nginx
```

This launches the webserver and immediately sends it to the background. This is so fast, you're almost tempted to believe it died and as there is not even a footprint to be found in the error log, this might actually be the case. But in fact it's not. Let's query for the process via the `ps` command:

```bash
$> ps -awuq $(cat logs/nginx.pid)
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root     13423  0.0  0.0  32184  3288 ?        Ss   11:19   0:00 nginx: master process ./sbin/nginx
```
That's our daemon!


### Step 8: Trying it out

The server is running. But is it also working? Time for the function test: We access NGINX by entering the following URL in our browser:

[http://127.0.0.1/index.html](http://127.0.0.1/index.html)

We then expect the following:

![Screenshot: It works!](https://www.netnea.com/files/nginx-tutorial-1-screenshot-it-works.png)

NGINX shows the first signs of life in the browser.

Fantastic! Goal achieved: The self-compiled NGINX is running.

Return to the shell and stop the server via the following command:

```bash
$> sudo ./sbin/nginx -s stop
```

Again, no feedback on the command line. But we can check if the PID file is still there. If it is gone, then the server did indeed stop.

### Step 9 (Goodie): Inspecting the binary a bit

Before completing the tutorial, we’d like to take a closer look at the server. Let’s open the engine compartment and take a peek inside. We can get some basic information about our binary as follows:

```bash
$> sudo ./sbin/nginx -V
nginx version: nginx/1.13.9
built by gcc 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.9) 
built with OpenSSL 1.0.2g  1 Mar 2016
TLS SNI support enabled
configure arguments: --prefix=/opt/nginx-1.13.9 --with-http_ssl_module --with-threads --with-file-aio --with-debug
```

That's not much, but the basics are covered and we see which compile time options we included. Looking at the size of the binary file, we can see that it is approximately 6 MB in size.

Before we finish this compilation tutorial, let's look at the libraries linked into the server:

```bash
$> ldd sbin/nginx 
        linux-vdso.so.1 =>  (0x00007fffbd4d1000)
        libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f9e1e5dd000)
        libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f9e1e3c0000)
        libcrypt.so.1 => /lib/x86_64-linux-gnu/libcrypt.so.1 (0x00007f9e1e188000)
        libpcre.so.3 => /lib/x86_64-linux-gnu/libpcre.so.3 (0x00007f9e1df18000)
        libssl.so.1.0.0 => /lib/x86_64-linux-gnu/libssl.so.1.0.0 (0x00007f9e1dcaf000)
        libcrypto.so.1.0.0 => /lib/x86_64-linux-gnu/libcrypto.so.1.0.0 (0x00007f9e1d86b000)
        libz.so.1 => /lib/x86_64-linux-gnu/libz.so.1 (0x00007f9e1d651000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f9e1d287000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f9e1e7e1000)
```

We see a couple of system libraries including the threading library, the PCRE (perl compatible regular expressions), the encryption libraries including openssl and then also `libz` which is used for the deflation of HTTP responses.

Let's leave it at that for the moment. I hope you enjoyed this tutorial.


### References
- NGINX: [https://www.nginx.org](https://www.nginx.org)
- NGINX Compile time options: [https://www.nginx.com/resources/wiki/start/topics/tutorials/installoptions/](https://www.nginx.com/resources/wiki/start/topics/tutorials/installoptions/)
- File Hierarchy Standard: [http://www.pathname.com/fhs/](http://www.pathname.com/fhs/)


### License / Copying / Further use

<a rel="license" href="http://creativecommons.org/licenses/by-nc-sa/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by-nc-sa/4.0/80x15.png" /></a><br />This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by-nc-sa/4.0/">Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License</a>.


