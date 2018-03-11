##Handling False Positives with the OWASP ModSecurity Core Rule Set

###What are we doing?

To successfully ward off attackers, we are reducing the number of *false positives* for a fresh installation of *OWASP ModSecurity Core Rules* and set the anomaly limits to a stricter level step by step.

###Why are we doing this?

A fresh installation of *core rules* will typically have some false alarms. In some special cases, namely at higher paranoia levels, there can be thousands of them. In the last tutorial, we saw a number of approaches for suppressing individual false alarms. It's always hard at the beginning. What we're missing is a strategy for coping with different kinds of false alarms. Reducing the number of false alarms is the prerequisite for lowering the *Core Rule Set* (CRS) anomaly threshold and this, in turn, is required in order to use *ModSecurity* to actually ward off attackers. And only after the false alarms really are disabled, or at least curtailed to a large extent, do we get a picture of the real attackers.

###Requirements

* An NGINX web server, ideally one created using the file structure shown in [Tutorial 1 (Compiling a NGINX web server)](https://www.netnea.com/cms/nginx-tutorial-1_compiling-nginx/).
* Understanding of the minimal configuration [Tutorial 2 (Configuring a Minimal NGINX Web Server)](https://www.netnea.com/cms/nginx-tutorial-2_minimal-nginx-configuration/).
* An NGINX web server with ModSecurity as shown in [Tutorial 6 (Embedding ModSecurity)](https://www.netnea.com/cms/nginx-tutorial-6_embedding-modsecurity/).
* An NGINX web server with the OWASP ModSecurity Core Rule Set installed as shown in [Tutorial 7 (Including the OWASP ModSecurity Core Rule Set)](https://www.netnea.com/cms/nginx-tutorial-7_including-owasp-modsecurity-core-rule-set/).

There is no point in learning to fight false positives on a lab server without traffic. What you need is a real set of false alarms. This will let you practice writing rules exclusions so the false alarms disappear from the installation. I have prepared two such files for you:

* [tutorial-8-nginx-example-error.log](https://www.netnea.com/files/tutorial-8-nginx-example-error.log)

It is difficult to provide real production logs for an exercise due to all the sensitive data in the logs. So, I went and created false positives from scratch. With the Core Rule Set 2.2.x, this would have been simple, but with the 3.0 release (CRS3), most of the false positives in the default install are now gone. What I did was set the CRS to Paranoia Level 4 and then install a local Drupal site. I then published a couple of articles and then read the articles in the browser. Rinse and repeat up to 10,000 requests.

Drupal and the core rules are not really in a loving relationship. Whenever the two software packages meet, they tend to have a falling out with each other, since the CRS is so pedantic and Drupal's habit of having square brackets in parameter names drives the CRS crazy. However, the default CRS3 installation at Paranoia Level 1, and especially the new optional exclusion rules for Drupal (see the `crs-setup.conf` file and [this blog post](https://www.netnea.com/cms/2016/11/22/securing-drupal-with-modsecurity-and-the-core-rule-set-crs3/) for details), wards off almost all of the remaining false positives with a core Drupal installation.

But things look completely different when you do not use these exclusion rules and if you raise the Paranoia Level to 4, you will get plenty of false positives. For the 10,000 requests in my test run, I received over 27,000 false alarms. That should do for a training session.

###Step 1: Defining a Policy to Fight False Positives

The problem with false positives is that if you are unlucky, they flood you like an avalanche and you do not know where to start the clean up. What you need is a plan and there is no official documentation proposing one. So here we go: This is my recommended approach to fighting false alarms:

* Always work in blocking mode
* Highest scoring requests go first
* Work in several iterations

What does that mean? The default installation come in blocking mode and with an anomaly threshold of 5 for the requests. In fact, this is a very good goal for our work, but it's an overambitious start on an existing production server. The risk is that a false positive raises an alarm, the wrong customer's browser is blocked, a phone call to the manager ensues and you are forced to switch off the Web Application Firewall. In many installations I have seen, this was the end of the story.

Don't let a badly tuned system catch you like this. Instead, start with a high threshold for the anomaly score. Let's say 1,000 for the requests and also 1,000 for the responses for symmetry's sake (in practice, the responses do not score very high). That way you know that no customer is ever going to be blocked, you get reports of false alarms and you gain time to weed them out.

If you have a proper security program, this is all performed during an extensive testing phase, so the service never hits production without a strict configuration. But if you start with ModSecurity on an existing production service, starting out with a high threshold in production is the preferred method with minimal interruption to existing customers (zero impact, if you work diligently). 

The problem with integrating ModSecurity in production is the fact that false positives and real alarms are intermixed. In order to tune your installation, you need to separate the two groups to really work on the false positives alone. This is not always easy. Manual review helps, restricting to known IP addresses, pre-authentication, testing/tuning on a test system separated from the internet, filtering the access log by country of origin for the IP address, etc... It's a large topic and making general recommendations is difficult. But please do take this seriously. Years ago, I demonstrated the exclusion of a false positive in a workshop - and the example alarm I used turned out to be a real attack. Needless to say, I learned my lesson.

There is another question that we need to get out of the way: Doesn't disabling rules actually lower the security of the site? Yes it does, but we need to keep things in perspective. In an ideal setup, all rules would be intact, the paranoia level would be very high (thus a total of 200 rules in place) and the anomaly limit very low; but the application would run without any problems or false alarms. But in practice, this won't work outside of the rarest of cases. If we raise the anomaly threshold, then the alerts are still there, but the attackers are no longer affected. If we reduce the paranoia level, we disable dozens of rules with one setting. If we talk to the developers about changing their software so that the false positives go away, we spend a lot of time arguing without much chance of success (at least in my experience). So disabling a single rule from a set of 200 rules is the best of all the bad solutions. The worst of all the bad solutions would be to disable ModSecurity altogether. And as this is very real in many organizations, I would rather disable individual rules based on a false positive than run the risk of being forced to kill the WAF.


###Step 2: Getting an Overview

The character of the application, the paranoia level and the amount of traffic all influence the amount of false positives you get in your logs. In the first run, a couple of thousand or one hundred thousand requests max will do. Once you have that in your access log, it's time to take a look. Let's get an overview of the situation: Let's look at the example logs!

One would think that the error log with the alerts is the place to go. But, we are looking at the access log first. We defined the log format in a way that gives us the anomaly scores for every request. This helps us with this step.

In the previous tutorial, we used the script [modsec-positive-stats.rb](https://www.netnea.com/files/modsec-positive-stats.rb). We return to this script with the example access log as the target:

```bash
$> cat tutorial-8-example-access.log | alscores | modsec-positive-stats.rb
INCOMING                     Num of req. | % of req. |  Sum of % | Missing %
Number of incoming req. (total) |  10000 | 100.0000% | 100.0000% |   0.0000%

Empty or miss. incoming score   |      0 |   0.0000% |   0.0000% | 100.0000%
Reqs with incoming score of   0 |   5583 |  55.8300% |  55.8300% |  44.1700%
Reqs with incoming score of   1 |      0 |   0.0000% |  55.8300% |  44.1700%
Reqs with incoming score of   2 |      0 |   0.0000% |  55.8300% |  44.1700%
Reqs with incoming score of   3 |      0 |   0.0000% |  55.8300% |  44.1700%
Reqs with incoming score of   4 |      0 |   0.0000% |  55.8300% |  44.1700%
Reqs with incoming score of   5 |     30 |   0.3000% |  56.1300% |  43.8700%
Reqs with incoming score of   6 |      0 |   0.0000% |  56.1300% |  43.8700%
Reqs with incoming score of   7 |      0 |   0.0000% |  56.1300% |  43.8700%
Reqs with incoming score of   8 |      1 |   0.0100% |  56.1399% |  43.8601%
Reqs with incoming score of   9 |      0 |   0.0000% |  56.1399% |  43.8601%
Reqs with incoming score of  10 |   3194 |  31.9400% |  88.0800% |  11.9200%
Reqs with incoming score of  11 |      0 |   0.0000% |  88.0800% |  11.9200%
Reqs with incoming score of  12 |      0 |   0.0000% |  88.0800% |  11.9200%
Reqs with incoming score of  13 |      0 |   0.0000% |  88.0800% |  11.9200%
Reqs with incoming score of  14 |      0 |   0.0000% |  88.0800% |  11.9200%
Reqs with incoming score of  15 |      0 |   0.0000% |  88.0800% |  11.9200%
Reqs with incoming score of  16 |      0 |   0.0000% |  88.0800% |  11.9200%
Reqs with incoming score of  17 |      0 |   0.0000% |  88.0800% |  11.9200%
Reqs with incoming score of  18 |      0 |   0.0000% |  88.0800% |  11.9200%
Reqs with incoming score of  19 |      0 |   0.0000% |  88.0800% |  11.9200%
Reqs with incoming score of  20 |     56 |   0.5599% |  88.6400% |  11.3600%
Reqs with incoming score of  21 |      0 |   0.0000% |  88.6400% |  11.3600%
Reqs with incoming score of  22 |      0 |   0.0000% |  88.6400% |  11.3600%
Reqs with incoming score of  23 |      0 |   0.0000% |  88.6400% |  11.3600%
Reqs with incoming score of  24 |      0 |   0.0000% |  88.6400% |  11.3600%
Reqs with incoming score of  25 |      0 |   0.0000% |  88.6400% |  11.3600%
Reqs with incoming score of  26 |      0 |   0.0000% |  88.6400% |  11.3600%
Reqs with incoming score of  27 |      0 |   0.0000% |  88.6400% |  11.3600%
Reqs with incoming score of  28 |      0 |   0.0000% |  88.6400% |  11.3600%
Reqs with incoming score of  29 |      0 |   0.0000% |  88.6400% |  11.3600%
Reqs with incoming score of  30 |     77 |   0.7700% |  89.4100% |  10.5900%
Reqs with incoming score of  31 |      0 |   0.0000% |  89.4100% |  10.5900%
Reqs with incoming score of  32 |      0 |   0.0000% |  89.4100% |  10.5900%
Reqs with incoming score of  33 |      0 |   0.0000% |  89.4100% |  10.5900%
Reqs with incoming score of  34 |      0 |   0.0000% |  89.4100% |  10.5900%
Reqs with incoming score of  35 |     77 |   0.7700% |  90.1799% |   9.8201%
Reqs with incoming score of  36 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  37 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  38 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  39 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  40 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  41 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  42 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  43 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  44 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  45 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  46 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  47 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  48 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  49 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  50 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  51 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  52 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  53 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  54 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  55 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  56 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  57 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  58 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  59 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  60 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  61 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  62 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  63 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  64 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  65 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  66 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  67 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  68 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  69 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  70 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  71 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  72 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  73 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  74 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  75 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  76 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  77 |      0 |   0.0000% |  90.1799% |   9.8201%
Reqs with incoming score of  78 |     77 |   0.7700% |  90.9499% |   9.0501%
Reqs with incoming score of  79 |    449 |   4.4900% |  95.4399% |   4.5601%
Reqs with incoming score of  80 |      0 |   0.0000% |  95.4399% |   4.5601%
Reqs with incoming score of  81 |      0 |   0.0000% |  95.4399% |   4.5601%
Reqs with incoming score of  82 |      0 |   0.0000% |  95.4399% |   4.5601%
Reqs with incoming score of  83 |      0 |   0.0000% |  95.4399% |   4.5601%
Reqs with incoming score of  84 |      0 |   0.0000% |  95.4399% |   4.5601%
Reqs with incoming score of  85 |      0 |   0.0000% |  95.4399% |   4.5601%
Reqs with incoming score of  86 |      0 |   0.0000% |  95.4399% |   4.5601%
Reqs with incoming score of  87 |      0 |   0.0000% |  95.4399% |   4.5601%
Reqs with incoming score of  88 |      0 |   0.0000% |  95.4399% |   4.5601%
Reqs with incoming score of  89 |      0 |   0.0000% |  95.4399% |   4.5601%
Reqs with incoming score of  90 |      0 |   0.0000% |  95.4399% |   4.5601%
Reqs with incoming score of  91 |      0 |   0.0000% |  95.4399% |   4.5601%
Reqs with incoming score of  92 |      0 |   0.0000% |  95.4399% |   4.5601%
Reqs with incoming score of  93 |      1 |   0.0100% |  95.4499% |   4.5501%
Reqs with incoming score of  94 |      0 |   0.0000% |  95.4499% |   4.5501%
Reqs with incoming score of  95 |      0 |   0.0000% |  95.4499% |   4.5501%
Reqs with incoming score of  96 |      0 |   0.0000% |  95.4499% |   4.5501%
Reqs with incoming score of  97 |      0 |   0.0000% |  95.4499% |   4.5501%
Reqs with incoming score of  98 |    448 |   4.4799% |  99.9299% |   0.0701%
Reqs with incoming score of  99 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 100 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 101 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 102 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 103 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 104 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 105 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 106 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 107 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 108 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 109 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 110 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 111 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 112 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 113 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 114 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 115 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 116 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 117 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 118 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 119 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 120 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 121 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 122 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 123 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 124 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 125 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 126 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 127 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 128 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 129 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 130 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 131 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 132 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 133 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 134 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 135 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 136 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 137 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 138 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 139 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 140 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 141 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 142 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 143 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 144 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 145 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 146 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 147 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 148 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 149 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 150 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 151 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 152 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 153 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 154 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 155 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 156 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 157 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 158 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 159 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 160 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 161 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 162 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 163 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 164 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 165 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 166 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 167 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 168 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 169 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 170 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 171 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 172 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 173 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 174 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 175 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 176 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 177 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 178 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 179 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 180 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 181 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 182 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 183 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 184 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 185 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 186 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 187 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 188 |      0 |   0.0000% |  99.9299% |   0.0701%
Reqs with incoming score of 189 |      1 |   0.0100% |  99.9400% |   0.0600%
Reqs with incoming score of 190 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 191 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 192 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 193 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 194 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 195 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 196 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 197 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 198 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 199 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 200 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 201 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 202 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 203 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 204 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 205 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 206 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 207 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 208 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 209 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 210 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 211 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 212 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 213 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 214 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 215 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 216 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 217 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 218 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 219 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 220 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 221 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 222 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 223 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 224 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 225 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 226 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 227 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 228 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 229 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 230 |      0 |   0.0000% |  99.9400% |   0.0600%
Reqs with incoming score of 231 |      6 |   0.0600% | 100.0000% |   0.0000%

Incoming average:  12.5272    Median   0.0000    Standard deviation  26.2197


OUTGOING                     Num of req. | % of req. |  Sum of % | Missing %
Number of outgoing req. (total) |  10000 | 100.0000% | 100.0000% |   0.0000%

Empty or miss. outgoing score   |      0 |   0.0000% |   0.0000% | 100.0000%
Reqs with outgoing score of   0 |  10000 | 100.0000% | 100.0000% |   0.0000%

Outgoing average:   0.0000    Median   0.0000    Standard deviation   0.0000
```

So we have 10,000 requests and about half of them pass without raising any alarm. Over 3,000 requests come in with an anomaly score of 10 and of the remaining requests form two distinct anomaly score clusters around 79 and 98. Then there is a very long tail with the highest group of requests scoring 231. That's more than 40 critical alerts on a single request (a critical alert gives 5 points, 40 critical alerts will thus score 200). Wow.

Let's visualize this:

<img src="/files/tutorial-8-distribution-untuned.png" alt="Untuned Distribution" width="950" height="550" />

_A quick overview over the stats generated above_



This is only a graph cobbled together on the quick. But it shows the problem that most requests are located near the left. They did not score at all, or they scored exactly 10 points. But there requests with higher scores and there is even a handful of outliers very far on the right outside the frame. So where do we start? 

We start with the request returning the highest anomaly score, we start on the right side of the graph! This makes sense because we are in blocking mode and we would like to reduce the threshold. The group of requests standing in our way are the six requests with a score of 231 and the single request with a score of 189. Let's write rule exclusions to suppress the alarms leading to these scores.



###Step 3: The first batch of rule exclusions

In order to find out what rules stand behind the anomaly scores 231 and 189, we need to link the access log to the error log. The unique request ID is this link:

```bash
$> egrep " (231|189) [0-9-]+$" tutorial-8-example-access.log | alreqid | tee ids
WBuxz38AAQEAAEdWQ5UAAACH
WBux0H8AAQEAAEdWQ7QAAACT
WBux0H8AAQEAAEdS9vYAAAAW
WBux0H8AAQEAAEdWQ7kAAACE
WBux0H8AAQEAAEdTojoAAABW
WBux0H8AAQEAAEdS9v4AAAAA
WBux0H8AAQEAAEdTokEAAABL
```

With this one-liner, we *grep* for the requests with score 231 or 189. We know it is the second item from the end of the log line. The final value is the outgoing anomaly score. In our case, all responses scored 0, but theoretically, this value could be any number or undefined (-> `-`) so it is generally a good practice to write the pattern this way. The alias *alreqid* extracts the unique ID and *tee* will show us the IDs and write them to the file *ids* at the same time.

We can then take the IDs in this file and use them to extract the alerts belonging to the requests we're focused on. We use `grep -f` to perform this step. The `-F` flag tells *grep* that our pattern file is actually a list of fixed strings separated by newlines. Thus equipped, *grep* is a lot more efficient than without the flag.  The *melidmsg* alias extracts the ID and the message explaining the alert. Combining both is very helpful. The already familiar *sucs* alias is then used to sum it all up:

```bash
$> grep -F -f ids tutorial-8-example-error.log  | melidmsg | sucs
      7 921180 HTTP Parameter Pollution (ARGS_NAMES:ids[])
     12 942450 SQL Hex Encoding Identified
     35 942431 Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (6)
     75 942130 SQL Injection Attack: SQL Tautology Detected.
    110 920273 Invalid character in request (outside of very strict set)
    150 942432 Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (2)
```

So these are the culprits. Let's go through them one by one. 921180 is a rule that identifies when a parameter (*ids[]* here) is submitted more than once within the same request. It's an advanced rule which appeared in the CRS3 for the first time (based on a mechanic I developed). Drupal seems to do this and we can hardly instruct it to stop this behaviour. 942450 looks for strings of the pattern `0x` with two additional hexadecimal digits. This is a hexadecimal encoding which can point to an exploit being used. The problem with this encoding is that session cookies can sometimes contain this pattern. Session cookies are randomly generated strings and at times you get this pattern in such an identifier. When you do, there is a paranoia level 2 rule that looks for attack patterns in hexadecimal encoding that try to sneak past our ruleset. So, we are facing a false positive in a very classical way.

942431 and 942432 are closely related. We call these siblings. They form a group with 942430, the base rule looking for 12 special characters like square brackets, colons, semicolons, asterisks, etc. (paranoia level 2). 942431 is a strict sibling doing the same things, but with a limit of 6 characters at paranoia level 3 and finally the paranoid zealot in the family, 942432, is going crazy after the 2nd special character (paranoia level 4).

942130 is one from the big group of SQL injection rules (this is a field the CRS are very strong in) and finally, 920273, another paranoid rule from paranoia level 4 defining the set of allowed ASCII characters (i.e. `38,44-46,48-58,61,65-90,95,97-122`).

For every alert, we need to write a rule exclusion and as we have seen in the previous tutorial, there are multiple options. It takes a bit of experience to make the right choice and very often, multiple approaches can be suitable. Let's look at the cheat sheet again:

<a href="https://www.netnea.com/cms/rule-exclusion-cheatsheet-download/"><img src="https://www.netnea.com/files/tutorial-7-rule-exclusion-cheatsheet_small.png" alt="Rule Exclusion CheatSheet" width="476" height="673" /></a>

_Click to get to the download of the large version_

Let's start with a simple case: 920273. We could look at this in great detail and check out all the different parameters triggering this rule. Depending on the security level we want to provide for our application, this would be the right approach. But then this is an exercise, so we will keep it simple: Let's kick this rule out completely. We'll opt for a startup rule (to be placed after the CRS include).

```bash
# === ModSec Core Rules: Startup Time Rules Exclusions

# ModSec Rule Exclusion: 920273 : Invalid character in request (outside of very strict set)
SecRuleRemoveById 920273
```

Next are the alerts for 942432:

```bash
$> grep -F -f ids tutorial-8-example-error.log  | grep 942432 | melmatch | sucs
     75 ARGS:ids[]
     75 ARGS_NAMES:ids[]
``` 

Drupal obviously uses square brackets within the parameter name. This is not limited to IDs, but a general pattern. Two square brackets are enough to trigger the rule, so this sets off a lot of false alarms. Running after all occurrences would be very tedious, so we will kick this rule out as well (remember, it's a paranoia level 4 rule and a more relaxed version of this rule exists at PL3). 

```bash
# ModSec Rule Exclusion: 942432 : Restricted SQL Character Anomaly Detection (args): 
# number of special characters exceeded (2)
SecRuleRemoveById 942432
```

The next one is 942450. This is the rule looking for traces of hex encoding. This is a peculiar case as we can easily see:


```bash
$> grep -F -f ids tutorial-8-example-error.log  | grep 942450 | melmatch | sucs
      6 REQUEST_COOKIES:98febd3dhf84de73ab2e32889dc5f0x032a9
      6 REQUEST_COOKIES_NAMES:SESS29af1facda0a866a687d5055f0x034ca
```

As expected, it's a session cookie, but unexpectedly, the session cookie has a dynamic name on top! This means we can not simply ignore the session cookie by name, we need to ignore cookies whose name matches a certain pattern and this is very, very complicated. And it's probably not worth the hassle. The easier approach is to have this rule ignore all cookies. This way, the rule is still intact for post and query string parameter, but it does not trigger on cookies anymore.

```bash
# ModSec Rule Exclusion: 942450 : SQL Hex Encoding Identified (severity: 5 CRITICAL)
SecRuleUpdateTargetById 942450 "!REQUEST_COOKIES"
SecRuleUpdateTargetById 942450 "!REQUEST_COOKIES_NAMES"
```

Three more to go: 921180, 942431 and 942130. We start with the latter:

```bash
$> grep -F -f ids tutorial-8-example-error.log | grep 942130 | melmatch | sucs
     75 ARGS:ids[]
```

So this is always the same parameter *ids[]*, which is already familiar to us. Maybe it's worth looking at the URI to understand how this is happening:

```bash
$> grep -F -f ids tutorial-8-example-error.log  | grep 942130 | meluri | sucs
     75 /drupal/index.php/contextual/render
```

So this is always the same URI. Let's exclude the parameter `ids[]` from being examined when it occurs in requests to this location. This boils down to a run-time exclusion rule. In the previous tutorial, we have seen that writing these kind of rules is cumbersome. It would be nice to have a script do the work for us. So, I created such a script: introducing [modsec-rulereport.rb](https://www.netnea.com/files/modsec-rulereport.rb). It takes an alert message (or the error log in a more general sense) on STDIN and proposes one of many rules exclusions of different types (see modsec-rulereport.rb -h` for an overview). 


```bash
$> grep -F -f ids tutorial-8-example-error.log  | grep 942130 | modsec-rulereport.rb --mode combined

75 x 942130 SQL Injection Attack: SQL Tautology Detected.
--------------------------------------------------------------------------------
      # ModSec Rule Exclusion: 942130 : SQL Injection Attack: SQL Tautology Detected.
      SecRule REQUEST_URI "@beginsWith /drupal/index.php/contextual/render" \
              "phase:2,nolog,pass,id:10000,ctl:ruleRemoveTargetById=942130;ARGS:ids[]"
```

The mode _combined_ instructs the script to write a rule that combines a path condition with a rule ID and a certain parameter. First, it reports the number of occurrences, then it proposes an exclusion rule which we can copy together with the comment into our Apache configuration file 1:1. The proposed rule has an ID of 10,000. If we continue to use the script, we will have to edit this ID ourselves to avoid ID collisions, but that's a simple task.

Here is how the configuration looks when we enter this construct (line break introduced for display reasons):

```bash
# === ModSec Core Rules: Runtime Exclusion Rules (ids: 10000-49999)

# ModSec Rule Exclusion: 942130 : SQL Injection Attack: SQL Tautology Detected.
SecRule REQUEST_URI "@beginsWith /drupal/index.php/contextual/render" \
    "phase:2,nolog,pass,id:10000,ctl:ruleRemoveTargetById=942130;ARGS:ids[]"

```

This is script is very handy. Let's throw in 942431 and see what happens:


```bash
$> grep -F -f ids tutorial-8-example-error.log  | grep 942431 | modsec-rulereport.rb --mode combined
35 x 942431 Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (6)
---------------------------------------------------------------------------------------------------
      # ModSec Rule Exclusion: 942431 : Restricted SQL Character Anomaly Detection (args): …
      SecRule REQUEST_URI "@beginsWith /drupal/index.php/contextual/render" \
              "phase:2,nolog,pass,id:10000,ctl:ruleRemoveTargetById=942431;ARGS:ids[]"
```

So that's almost the same thing. We can thus take out the control action (the bit starting with `ctl`) and append it to the previous statement:


```bash
# === ModSec Core Rules: Runtime Exclusion Rules (ids: 10000-49999)

# ModSec Rule Exclusion: 942130 : SQL Injection Attack: SQL Tautology Detected.
# ModSec Rule Exclusion: 942431 : Restricted SQL Character Anomaly Detection (args): # of ...
SecRule REQUEST_URI "@beginsWith /drupal/index.php/contextual/render" \
    "phase:2,nolog,pass,id:10000,ctl:ruleRemoveTargetById=942130;ARGS:ids[],\
                                 ctl:ruleRemoveTargetById=942431;ARGS:ids[]"

```

And now 921180:

```bash
$> grep -F -f ids tutorial-8-example-error.log  | grep 921180 | modsec-rulereport.rb --mode combined

7 x 921180 HTTP Parameter Pollution (ARGS_NAMES:ids[])
------------------------------------------------------
      # ModSec Rule Exclusion: 921180 : HTTP Parameter Pollution (ARGS_NAMES:ids[])
      SecRule REQUEST_URI "@beginsWith /drupal/index.php/contextual/render" \
               "phase:2,nolog,pass,id:10000,ctl:ruleRemoveTargetById=921180;TX:paramcounter_ARGS_NAMES:ids[]"
```

This is a special case. It's caused by submitting a single parameter multiple times. The rule works with a separate counter introduced for every parameter which will then check the counter in rule 921180. If we want to suppress the alarm, we'd best suppress the examination of this counter as the script proposes. We are facing the same URI again, but I have that feeling that this rule will be triggered by other parameters as well. We will see.

In fact, this brings us to an organizational problem. How do we best organize the rule exclusions? Especially the complicated run-time exclusions. We can order by rule ID, by URI or by parameter. There is no easy answer. For large sites with multiple services or many different application paths, I use the URI to group the exclusion rules by branches of the service. But with small services, sorting by rule ID seems like a reasonable approach.

We now take the proposed rule, prepare the comment for future variables, raise the rule ID by 1 to avoid ID collisions and add it to the configuration:

```bash
# ModSec Rule Exclusion: 921180 : HTTP Parameter Pollution (multiple variables)
SecRule REQUEST_URI "@beginsWith /drupal/index.php/contextual/render" \
    "phase:2,nolog,pass,id:10001,ctl:ruleRemoveTargetById=921180;TX:paramcounter_ARGS_NAMES:ids[]"
```

With this, we have covered these seven highly scoring requests (189 and 231). Writing these six rule exclusions was a bit cumbersome, but the script seems to be a real improvement to the process. The rest will be faster. Promise.


###Step 4: Reducing the anomaly score threshold

We have tuned away the alerts leading to the highest anomaly scores. Actually, anything above 100 is now gone. In a production setup, I would deploy the updated configuration and observe the behaviour a bit. If the high scores are really gone, then it is time to reduce the anomaly limit. A typical first step is from 1,000 to 100. Then we do more rules exclusions, reduce to 50 or so, then to 20, 10 and 5. In fact, a limit of 5 is really strong (first critical alert blocks a request), but for sites with less security needs, a limit of 10 might just be good enough. Anything above does not really block attackers.

But before we get there, we need to add few more rule exclusions.



###Step 5: The second batch of rule exclusions

After the first batch of rule exclusions, we would observe the service and end up with the following new logs:

* [tutorial-8-example-access-round-2.log](https://www.netnea.com/files/tutorial-8-example-access-round-2.log)
* [tutorial-8-example-error-round-2.log](https://www.netnea.com/files/tutorial-8-example-error-round-2.log)

We start again with a look at the score distribution:

```bash
$> cat tutorial-8-example-access-round-2.log | alscores | modsec-positive-stats.rb

INCOMING                     Num of req. | % of req. |  Sum of % | Missing %
Number of incoming req. (total) |  10000 | 100.0000% | 100.0000% |   0.0000%

Empty or miss. incoming score   |      0 |   0.0000% |   0.0000% | 100.0000%
Reqs with incoming score of   0 |   8944 |  89.4400% |  89.4400% |  10.5600%
Reqs with incoming score of   1 |      0 |   0.0000% |  89.4400% |  10.5600%
Reqs with incoming score of   2 |      0 |   0.0000% |  89.4400% |  10.5600%
Reqs with incoming score of   3 |      0 |   0.0000% |  89.4400% |  10.5600%
Reqs with incoming score of   4 |     20 |   0.2000% |  89.6400% |  10.3600%
Reqs with incoming score of   5 |    439 |   4.3900% |  94.0300% |   5.9700%
Reqs with incoming score of   6 |      0 |   0.0000% |  94.0300% |   5.9700%
Reqs with incoming score of   7 |      0 |   0.0000% |  94.0300% |   5.9700%
Reqs with incoming score of   8 |    368 |   3.6800% |  97.7100% |   2.2900%
Reqs with incoming score of   9 |      0 |   0.0000% |  97.7100% |   2.2900%
Reqs with incoming score of  10 |      1 |   0.0100% |  97.7200% |   2.2800%
Reqs with incoming score of  11 |      0 |   0.0000% |  97.7200% |   2.2800%
Reqs with incoming score of  12 |      0 |   0.0000% |  97.7200% |   2.2800%
Reqs with incoming score of  13 |      0 |   0.0000% |  97.7200% |   2.2800%
Reqs with incoming score of  14 |      0 |   0.0000% |  97.7200% |   2.2800%
Reqs with incoming score of  15 |      0 |   0.0000% |  97.7200% |   2.2800%
Reqs with incoming score of  16 |      0 |   0.0000% |  97.7200% |   2.2800%
Reqs with incoming score of  17 |      0 |   0.0000% |  97.7200% |   2.2800%
Reqs with incoming score of  18 |      0 |   0.0000% |  97.7200% |   2.2800%
Reqs with incoming score of  19 |      0 |   0.0000% |  97.7200% |   2.2800%
Reqs with incoming score of  20 |      0 |   0.0000% |  97.7200% |   2.2800%
Reqs with incoming score of  21 |      0 |   0.0000% |  97.7200% |   2.2800%
Reqs with incoming score of  22 |      0 |   0.0000% |  97.7200% |   2.2800%
Reqs with incoming score of  23 |      0 |   0.0000% |  97.7200% |   2.2800%
Reqs with incoming score of  24 |      0 |   0.0000% |  97.7200% |   2.2800%
Reqs with incoming score of  25 |     76 |   0.7600% |  98.4800% |   1.5200%
Reqs with incoming score of  26 |      0 |   0.0000% |  98.4800% |   1.5200%
Reqs with incoming score of  27 |      0 |   0.0000% |  98.4800% |   1.5200%
Reqs with incoming score of  28 |      0 |   0.0000% |  98.4800% |   1.5200%
Reqs with incoming score of  29 |      0 |   0.0000% |  98.4800% |   1.5200%
Reqs with incoming score of  30 |     76 |   0.7600% |  99.2400% |   0.7600%
Reqs with incoming score of  31 |      0 |   0.0000% |  99.2400% |   0.7600%
Reqs with incoming score of  32 |      0 |   0.0000% |  99.2400% |   0.7600%
Reqs with incoming score of  33 |      0 |   0.0000% |  99.2400% |   0.7600%
Reqs with incoming score of  34 |      0 |   0.0000% |  99.2400% |   0.7600%
Reqs with incoming score of  35 |      0 |   0.0000% |  99.2400% |   0.7600%
Reqs with incoming score of  36 |      0 |   0.0000% |  99.2400% |   0.7600%
Reqs with incoming score of  37 |      0 |   0.0000% |  99.2400% |   0.7600%
Reqs with incoming score of  38 |      0 |   0.0000% |  99.2400% |   0.7600%
Reqs with incoming score of  39 |      0 |   0.0000% |  99.2400% |   0.7600%
Reqs with incoming score of  40 |      0 |   0.0000% |  99.2400% |   0.7600%
Reqs with incoming score of  41 |      0 |   0.0000% |  99.2400% |   0.7600%
Reqs with incoming score of  42 |      0 |   0.0000% |  99.2400% |   0.7600%
Reqs with incoming score of  43 |      0 |   0.0000% |  99.2400% |   0.7600%
Reqs with incoming score of  44 |      0 |   0.0000% |  99.2400% |   0.7600%
Reqs with incoming score of  45 |      0 |   0.0000% |  99.2400% |   0.7600%
Reqs with incoming score of  46 |      0 |   0.0000% |  99.2400% |   0.7600%
Reqs with incoming score of  47 |      0 |   0.0000% |  99.2400% |   0.7600%
Reqs with incoming score of  48 |      0 |   0.0000% |  99.2400% |   0.7600%
Reqs with incoming score of  49 |      0 |   0.0000% |  99.2400% |   0.7600%
Reqs with incoming score of  50 |      0 |   0.0000% |  99.2400% |   0.7600%
Reqs with incoming score of  51 |      0 |   0.0000% |  99.2400% |   0.7600%
Reqs with incoming score of  52 |      0 |   0.0000% |  99.2400% |   0.7600%
Reqs with incoming score of  53 |      0 |   0.0000% |  99.2400% |   0.7600%
Reqs with incoming score of  54 |      0 |   0.0000% |  99.2400% |   0.7600%
Reqs with incoming score of  55 |      0 |   0.0000% |  99.2400% |   0.7600%
Reqs with incoming score of  56 |      0 |   0.0000% |  99.2400% |   0.7600%
Reqs with incoming score of  57 |      0 |   0.0000% |  99.2400% |   0.7600%
Reqs with incoming score of  58 |      0 |   0.0000% |  99.2400% |   0.7600%
Reqs with incoming score of  59 |      0 |   0.0000% |  99.2400% |   0.7600%
Reqs with incoming score of  60 |     76 |   0.7600% | 100.0000% |   0.0000%

Incoming average:   1.3969    Median   0.0000    Standard deviation   6.3634


OUTGOING                     Num of req. | % of req. |  Sum of % | Missing %
Number of outgoing req. (total) |  10000 | 100.0000% | 100.0000% |   0.0000%

Empty or miss. outgoing score   |      0 |   0.0000% |   0.0000% | 100.0000%
Reqs with outgoing score of   0 |   9980 |  99.8000% |  99.8000% |   0.2000%
Reqs with outgoing score of   1 |      0 |   0.0000% |  99.8000% |   0.2000%
Reqs with outgoing score of   2 |      0 |   0.0000% |  99.8000% |   0.2000%
Reqs with outgoing score of   3 |      0 |   0.0000% |  99.8000% |   0.2000%
Reqs with outgoing score of   4 |     20 |   0.2000% | 100.0000% |   0.0000%

Outgoing average:   0.0080    Median   0.0000    Standard deviation   0.1787
```

If we compare this to the first run of the statistic script, we reduced the average score from 12.5 to 1.4. This is very impressive. So by focusing on a handful of high scoring requests, we improved the whole service by a lot.

We could expect the high scoring requests of 231 and 189 to be gone, but funnily enough, the cluster at 98 and the one at 10 have also disappeared. We only covered 7 requests in the initial tuning, but two clusters with alerts from over 400 repectively over 3,000 requests are gone, too. And this is not an exceptional effect. It is the standard behaviour if we work with this tuning method: a few rule exclusions that we derieved from the highest scoring requests does away with most of the false alarms.

Our next goal is the group of requests with a score of 60. Let's extract the rule IDs and then examine the alerts a bit.

```bash
$> egrep " 60 [0-9-]+$" tutorial-8-example-access-round-2.log | alreqid > ids
$> grep -F -f ids tutorial-8-example-error-round-2.log | melidmsg | sucs
     76 921180 HTTP Parameter Pollution (ARGS_NAMES:keys)
     76 942100 SQL Injection Attack Detected via libinjection
    152 942190 Detects MSSQL code execution and information gathering attempts
    152 942200 Detects MySQL comment-/space-obfuscated injections and backtick …
    152 942260 Detects basic SQL authentication bypass attempts 2/3
    152 942270 Looking for basic sql injection. Common attack string for mysql, …
    152 942410 SQL Injection Attack
$> grep -F -f ids tutorial-8-example-error-round-2.log | meluri | sucs
    912 /drupal/index.php/search/node
```

So this points to a search form and payloads resembling SQL injections (outside of the first rule 921180, which we have seen before). It's obvious that a search form will attract SQL injection attacks. But then I know this was legitimate traffic (I filled in the forms personally when I searched for SQL statements in the Drupal articles I had posted as an exercise) and we are now facing a dilemma: If we suppress the rules, we open a door for SQL injections. If we leave the rules intact and reduce the limit, we will block legitimate traffic. I think it is OK to say that nobody should be using the search form to look for sql statements in our articles. But I could also say that Drupal is smart enough to fight off SQL attacks via the search form. As this is an exercise, this is our position for the moment: Let's exclude these rules. Let's feed it all into our helper script:

```bash
$> grep -F -f ids tutorial-8-example-error-round-2.log | modsec-rulereport.rb -m combined

76 x 921180 HTTP Parameter Pollution (ARGS_NAMES:keys)
------------------------------------------------------
      # ModSec Rule Exclusion: 921180 : HTTP Parameter Pollution (ARGS_NAMES:keys)
      SecRule REQUEST_URI "@beginsWith /drupal/index.php/search/node" \
              "phase:2,nolog,pass,id:10000,ctl:ruleRemoveTargetById=921180;TX:paramcounter_ARGS_NAMES:keys"

76 x 942100 SQL Injection Attack Detected via libinjection
----------------------------------------------------------
      # ModSec Rule Exclusion: 942100 : SQL Injection Attack Detected via libinjection
      SecRule REQUEST_URI "@beginsWith /drupal/index.php/search/node" \
              "phase:2,nolog,pass,id:10000,ctl:ruleRemoveTargetById=942100;ARGS:keys"

152 x 942190 Detects MSSQL code execution and information gathering attempts
----------------------------------------------------------------------------
      # ModSec Rule Exclusion: 942190 : Detects MSSQL code execution and information gathering attempts
      SecRule REQUEST_URI "@beginsWith /drupal/index.php/search/node" \
              "phase:2,nolog,pass,id:10001,ctl:ruleRemoveTargetById=942190;ARGS:keys"

152 x 942200 Detects MySQL comment-/space-obfuscated injections and backtick termination
----------------------------------------------------------------------------------------
      # ModSec Rule Exclusion: 942200 : Detects MySQL comment-/space-obfuscated injections and backtick …
      SecRule REQUEST_URI "@beginsWith /drupal/index.php/search/node" \
              "phase:2,nolog,pass,id:10002,ctl:ruleRemoveTargetById=942200;ARGS:keys"

152 x 942260 Detects basic SQL authentication bypass attempts 2/3
-----------------------------------------------------------------
      # ModSec Rule Exclusion: 942260 : Detects basic SQL authentication bypass attempts 2/3
      SecRule REQUEST_URI "@beginsWith /drupal/index.php/search/node" \
              "phase:2,nolog,pass,id:10003,ctl:ruleRemoveTargetById=942260;ARGS:keys"

152 x 942270 Looking for basic sql injection. Common attack string for mysql, oracle and others.
------------------------------------------------------------------------------------------------
      # ModSec Rule Exclusion: 942270 : Looking for basic sql injection. Common attack string for mysql, …
      SecRule REQUEST_URI "@beginsWith /drupal/index.php/search/node" \
              "phase:2,nolog,pass,id:10004,ctl:ruleRemoveTargetById=942270;ARGS:keys"

152 x 942410 SQL Injection Attack
---------------------------------
      # ModSec Rule Exclusion: 942410 : SQL Injection Attack
      SecRule REQUEST_URI "@beginsWith /drupal/index.php/search/node" \
              "phase:2,nolog,pass,id:10005,ctl:ruleRemoveTargetById=942410;ARGS:keys"
```

We had separated a spot for 921180 exclusions before. We put the first rule into that position and end up with the following:

```bash
# ModSec Rule Exclusion: 921180 : HTTP Parameter Pollution (multiple variables)
SecRule REQUEST_URI "@beginsWith /drupal/index.php/contextual/render" \
    "phase:2,nolog,pass,id:10001,ctl:ruleRemoveTargetById=921180;TX:paramcounter_ARGS_NAMES:ids[]"
SecRule REQUEST_URI "@beginsWith /drupal/index.php/search/node" \
    "phase:2,nolog,pass,id:10002,ctl:ruleRemoveTargetById=921180;TX:paramcounter_ARGS_NAMES:keys"
```

With 942100, the case it quite clear. But let's look at the alert message itself. There we see that ModSecurity used a special library to identify what it thought an SQL injection attempt. So instead of a regular expression, a dedicated injection parser was used.

```bash
$> grep -F -f ids tutorial-8-example-error-round-2.log | grep 942100 | head -1
[2016-11-05 09:47:18.423889] [-:error] - - [client 127.0.0.1] ModSecurity: Warning. detected SQLi …
using libinjection with fingerprint 'UEkn' [file …
"/apache/conf/owasp-modsecurity-crs-3.0.0-rc1/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] …
[line "67"] [id "942100"] [rev "1"] [msg "SQL Injection Attack Detected via libinjection"] [data …
"Matched Data: UEkn found within ARGS:keys: union select from users"] [ver "OWASP_CRS/3.0.0"] …
[maturity "1"] [accuracy "8"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] …
[tag "attack-sqli"] [tag "OWASP_CRS/WEB_ATTACK/SQL_INJECTION"] [tag "WASCTC/WASC-19"] [tag …
"OWASP_TOP_10/A1"] [tag "OWASP_AppSensor/CIE1"] [tag "PCI/6.5.2"] [hostname "localhost"] …
[uri "/drupal/index.php/search/node"] [unique_id "WB2cln8AAQEAAAehPc8AAADK"]
```

For the treatment of the false positive, this does not matter though, and we take the proposal by the script:

```bash
# ModSec Rule Exclusion: 942100 : SQL Injection Attack Detected via libinjection
SecRule REQUEST_URI "@beginsWith /drupal/index.php/search/node" \
    "phase:2,nolog,pass,id:10003,ctl:ruleRemoveTargetById=942100;ARGS:keys"
```

With the remaining ones, we use a shortcut:

```bash
$> grep -F -f ids tutorial-8-example-error-round-2.log | grep -v "942100\|921180" | \
modsec-rulereport.rb -m combined | sort
...
      # ModSec Rule Exclusion: 942190 : Detects MSSQL code execution and information gathering attempts
      # ModSec Rule Exclusion: 942200 : Detects MySQL comment-/space-obfuscated injections and backtick …
      # ModSec Rule Exclusion: 942260 : Detects basic SQL authentication bypass attempts 2/3
      # ModSec Rule Exclusion: 942270 : Looking for basic sql injection. Common attack string for mysql, …
      # ModSec Rule Exclusion: 942410 : SQL Injection Attack
      SecRule REQUEST_URI "@beginsWith /drupal/index.php/search/node" \
              "phase:2,nolog,pass,id:10000,ctl:ruleRemoveTargetById=942190;ARGS:keys"
      SecRule REQUEST_URI "@beginsWith /drupal/index.php/search/node" \
              "phase:2,nolog,pass,id:10001,ctl:ruleRemoveTargetById=942200;ARGS:keys"
      SecRule REQUEST_URI "@beginsWith /drupal/index.php/search/node" \
              "phase:2,nolog,pass,id:10002,ctl:ruleRemoveTargetById=942260;ARGS:keys"
      SecRule REQUEST_URI "@beginsWith /drupal/index.php/search/node" \
              "phase:2,nolog,pass,id:10003,ctl:ruleRemoveTargetById=942270;ARGS:keys"
      SecRule REQUEST_URI "@beginsWith /drupal/index.php/search/node" \
              "phase:2,nolog,pass,id:10004,ctl:ruleRemoveTargetById=942410;ARGS:keys"

```

We can simplify this into the following rule, which is then appended to the previous run-time exclusion rule for 942100:


```bash
# ModSec Rule Exclusion: 942100 : SQL Injection Attack Detected via libinjection
# ModSec Rule Exclusion: 942190 : Detects MSSQL code execution and information gathering attempts
# ModSec Rule Exclusion: 942200 : Detects MySQL comment-/space-obfuscated injections and backtick …
# ModSec Rule Exclusion: 942260 : Detects basic SQL authentication bypass attempts 2/3
# ModSec Rule Exclusion: 942270 : Looking for basic sql injection. Common attack string for mysql, …
# ModSec Rule Exclusion: 942410 : SQL Injection Attack
SecRule REQUEST_URI "@beginsWith /drupal/index.php/search/node" "phase:2,nolog,pass,id:10004,\
    ctl:ruleRemoveTargetById=942100;ARGS:keys,\
    ctl:ruleRemoveTargetById=942190;ARGS:keys,\
    ctl:ruleRemoveTargetById=942200;ARGS:keys,\
    ctl:ruleRemoveTargetById=942260;ARGS:keys,\
    ctl:ruleRemoveTargetById=942270;ARGS:keys,\
    ctl:ruleRemoveTargetById=942410;ARGS:keys"
```

And done. This time, we cleaned out all the scores above 50. Time to reduce the anomaly threshold to 50, let it rest a bit and then examine the logs for the third batch.


###Step 6: The third batch of rule exclusions

Here are the new exercise files. It's still the same traffic, but with fewer alerts again thanks to the rule exclusions.

* [tutorial-8-example-access-round-3.log](https://www.netnea.com/files/tutorial-8-example-access-round-3.log)
* [tutorial-8-example-error-round-3.log](https://www.netnea.com/files/tutorial-8-example-error-round-3.log)


This brings us to the following statistics (this time only printing numbers for the incoming requests):

```bash
$> cat tutorial-8-example-access-round-3.log | alscores | modsec-positive-stats.rb --incoming
INCOMING                     Num of req. | % of req. |  Sum of % | Missing %
Number of incoming req. (total) |  10000 | 100.0000% | 100.0000% |   0.0000%

Empty or miss. incoming score   |      0 |   0.0000% |   0.0000% | 100.0000%
Reqs with incoming score of   0 |   9192 |  91.9200% |  91.9200% |   8.0800%
Reqs with incoming score of   1 |      0 |   0.0000% |  91.9200% |   8.0800%
Reqs with incoming score of   2 |      0 |   0.0000% |  91.9200% |   8.0800%
Reqs with incoming score of   3 |      0 |   0.0000% |  91.9200% |   8.0800%
Reqs with incoming score of   4 |      0 |   0.0000% |  91.9200% |   8.0800%
Reqs with incoming score of   5 |    439 |   4.3900% |  96.3100% |   3.6900%
Reqs with incoming score of   6 |      0 |   0.0000% |  96.3100% |   3.6900%
Reqs with incoming score of   7 |      0 |   0.0000% |  96.3100% |   3.6900%
Reqs with incoming score of   8 |    368 |   3.6800% |  99.9900% |   0.0100%
Reqs with incoming score of   9 |      0 |   0.0000% |  99.9900% |   0.0100%
Reqs with incoming score of  10 |      1 |   0.0100% | 100.0000% |   0.0000%

Incoming average:   0.5149    Median   0.0000    Standard deviation   1.7882
```

So again, a great deal of the false positives disappeared because of a bunch of exclusions for a score of 60. For this tuning round, we'll tackle the lone request at 10 and the cluster at 8, allowing us to reduce the anomaly threshold to 10 afterwards, which is already quite low.


```bash
$> egrep " (10|8) [0-9-]+$" tutorial-8-example-access-round-3.log | alreqid > ids
$> grep -F -f ids tutorial-8-example-error-round-3.log | melidmsg | sucs
      2 932160 Remote Command Execution: Unix Shell Code Found
    368 921180 HTTP Parameter Pollution (ARGS_NAMES:editors[])
    368 942431 Restricted SQL Character Anomaly Detection (args): # of special characters …
```

The first alert is funny: "Remote command execution." What's this?


```bash
$> grep -F -f ids tutorial-8-example-error-round-3.log | grep 932160 | melmatch
ARGS:account[pass][pass1]
ARGS:account[pass][pass2]
$> grep -F -f ids tutorial-8-example-error-round-3.log | grep 932160 | meldata
Matched Data: /bin/bash found within ARGS:account[pass
Matched Data: /bin/bash found within ARGS:account[pass
```

OK, so there seems to be a password `/bin/bash`. That is probably not the smartest choice, but nothing that should harm us. We can easily suppress this rule for this parameter. Or looking forward a bit, we can expect other funny passwords to trigger all sorts of rules on the password field. And, in fact, the password field is not a typical target of an attack. So this might be a situation where it makes sense to disable a whole class of rules. We have multiple options. We can disable by tag, or we can disable by rule ID range. Let's look over the various rules files:

```bash
REQUEST-901-INITIALIZATION.conf
REQUEST-903.9001-DRUPAL-EXCLUSION-RULES.conf
REQUEST-903.9002-WORDPRESS-EXCLUSION-RULES.conf
REQUEST-905-COMMON-EXCEPTIONS.conf
REQUEST-910-IP-REPUTATION.conf
REQUEST-911-METHOD-ENFORCEMENT.conf
REQUEST-912-DOS-PROTECTION.conf
REQUEST-913-SCANNER-DETECTION.conf
REQUEST-920-PROTOCOL-ENFORCEMENT.conf
REQUEST-921-PROTOCOL-ATTACK.conf
REQUEST-930-APPLICATION-ATTACK-LFI.conf
REQUEST-931-APPLICATION-ATTACK-RFI.conf
REQUEST-932-APPLICATION-ATTACK-RCE.conf
REQUEST-933-APPLICATION-ATTACK-PHP.conf
REQUEST-941-APPLICATION-ATTACK-XSS.conf
REQUEST-942-APPLICATION-ATTACK-SQLI.conf
REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf
REQUEST-949-BLOCKING-EVALUATION.conf
RESPONSE-950-DATA-LEAKAGES.conf
RESPONSE-951-DATA-LEAKAGES-SQL.conf
RESPONSE-952-DATA-LEAKAGES-JAVA.conf
RESPONSE-953-DATA-LEAKAGES-PHP.conf
RESPONSE-954-DATA-LEAKAGES-IIS.conf
RESPONSE-959-BLOCKING-EVALUATION.conf
RESPONSE-980-CORRELATION.conf
```

We do not want to ignore the protocol attacks, but all the application stuff should be off limits. So let's kick the rules from `REQUEST-930-APPLICATION-ATTACK-LFI.conf` to `REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf`. This is effectively the rule range from 930,000 to 943,999. We can exclude the two parameters for all these rules with the following startup time directives:

```bash
# ModSec Rule Exclusion: 930000 - 943999 : All application rules for password parameters
SecRuleUpdateTargetById 930000-943999 "!ARGS:account[pass][pass1]"
SecRuleUpdateTargetById 930000-943999 "!ARGS:account[pass][pass2]"
```

We are left with another instance of 921180, plus the 942431 which we have seen before too. Here is what the script proposes:

```bash
$> grep -F -f ids tutorial-8-example-error-round-3.log | grep "921180\|942431" | \
modsec-rulereport.rb -m combined 

448 x 921180 HTTP Parameter Pollution (ARGS_NAMES:editors[])
------------------------------------------------------------
      # ModSec Rule Exclusion: 921180 : HTTP Parameter Pollution (ARGS_NAMES:editors[])
      SecRule REQUEST_URI "@beginsWith /drupal/index.php/quickedit/attachments" \
              "phase:2,nolog,pass,id:10000,\
              ctl:ruleRemoveTargetById=921180;TX:paramcounter_ARGS_NAMES:editors[]"

448 x 942431 Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (6)
----------------------------------------------------------------------------------------------------
      # ModSec Rule Exclusion: 942431 : Restricted SQL Character Anomaly Detection (args): …
      SecRule REQUEST_URI "@beginsWith /drupal/index.php/quickedit/attachments" \
              "phase:2,nolog,pass,id:10001,ctl:ruleRemoveTargetById=942431;ARGS:ajax_page_state[libraries]"
```

You know the drill by now: The first one goes with the other 921180 exclusions (don't forget to pick a new rule ID) and the second is added as a new entry:


```bash
# ModSec Rule Exclusion: 942431 : Restricted SQL Character Anomaly Detection (args): …
SecRule REQUEST_URI "@beginsWith /drupal/index.php/quickedit/attachments" \
    "phase:2,nolog,pass,id:10005,ctl:ruleRemoveTargetById=942431;ARGS:ajax_page_state[libraries]"
```

Time to reduce the limit once more (down to 10 this time) and see what happens.

###Step 7: The fourth batch of rule exclusions

We have a new pair of logs: 

* [tutorial-8-example-access-round-4.log](https://www.netnea.com/files/tutorial-8-example-access-round-4.log)
* [tutorial-8-example-error-round-4.log](https://www.netnea.com/files/tutorial-8-example-error-round-4.log)

These are the statistics:

```bash
$> cat tutorial-8-example-access-round-4.log | alscores | modsec-positive-stats.rb --incoming
INCOMING                     Num of req. | % of req. |  Sum of % | Missing %
Number of incoming req. (total) |  10000 | 100.0000% | 100.0000% |   0.0000%

Empty or miss. incoming score   |      0 |   0.0000% |   0.0000% | 100.0000%
Reqs with incoming score of   0 |   9561 |  95.6100% |  95.6100% |   4.3900%
Reqs with incoming score of   1 |      0 |   0.0000% |  95.6100% |   4.3900%
Reqs with incoming score of   2 |      0 |   0.0000% |  95.6100% |   4.3900%
Reqs with incoming score of   3 |      0 |   0.0000% |  95.6100% |   4.3900%
Reqs with incoming score of   4 |      0 |   0.0000% |  95.6100% |   4.3900%
Reqs with incoming score of   5 |    439 |   4.3900% | 100.0000% |   0.0000%

Incoming average:   0.2195    Median   0.0000    Standard deviation   1.0244
```

It seems that we are almost done. What rules are behind these remaining alerts?


```bash
$> cat tutorial-8-example-access-round-4.log | egrep " 5 [0-9-]+$"  | alreqid > ids
$> grep -F -f ids tutorial-8-example-error-round-4.log  | melidmsg | sucs
     30 921180 HTTP Parameter Pollution (ARGS_NAMES:op)
     41 932160 Remote Command Execution: Unix Shell Code Found
    368 921180 HTTP Parameter Pollution (ARGS_NAMES:fields[])
```

So our friend 921180 is back again for two parameters and another shell execution. Probably another occurrence of the password parameter. Let's check this:

```bash
$> grep -F -f ids tutorial-8-example-error-round-4.log  | grep 921180 | modsec-rulereport.rb -m combined

398 x 921180 HTTP Parameter Pollution (ARGS_NAMES:op)
-----------------------------------------------------
      # ModSec Rule Exclusion: 921180 : HTTP Parameter Pollution (ARGS_NAMES:op)
      SecRule REQUEST_URI "@beginsWith /drupal/index.php/quickedit/metadata" \
              "phase:2,nolog,pass,id:10000,\
              ctl:ruleRemoveTargetById=921180;TX:paramcounter_ARGS_NAMES:fields[]"
      SecRule REQUEST_URI "@beginsWith /drupal/core/install.php" \
              "phase:2,nolog,pass,id:10001,ctl:ruleRemoveTargetById=921180;TX:paramcounter_ARGS_NAMES:op"
```

It's simple enough to add this in the usual place with new rule IDs. And then the final alert:


```bash
$> grep -F -f ids tutorial-8-example-error-round-4.log  | grep 932160 | modsec-rulereport.rb -m combined

41 x 932160 Remote Command Execution: Unix Shell Code Found
-----------------------------------------------------------
      # ModSec Rule Exclusion: 932160 : Remote Command Execution: Unix Shell Code Found
      SecRule REQUEST_URI "@beginsWith /drupal/index.php/user/login" \
              "phase:2,nolog,pass,id:10000,ctl:ruleRemoveTargetById=932160;ARGS:pass"
```

So yes, it is the password field again. I think it is best to execute the same process we performed with the other occurrences of the password. That was probably the registration, while this time it is the login form.

```bash
SecRuleUpdateTargetById 930000-943999 "!ARGS:pass"
```

And with this, we are done. We have successfully fought all the false positives of a content management system with peculiar parameter formats and a ModSecurity rule set pushed to insanely paranoid levels. 

###Step 8: Summarizing all rule exclusions

Time to look back and rearrange the configuration file with all the rule exclusions. I have regrouped them a bit, I added some comments and reassigned rule IDs. As outlined before, it is not obvious how to arrange the rules. Here, I ordered them by ID, but also included a block where I cover the search form separately.

```bash
# === ModSec Core Rules: Runtime Exclusion Rules (ids: 10000-49999)

# ModSec Rule Exclusion: 921180 : HTTP Parameter Pollution (multiple variables)
SecRule REQUEST_URI "@beginsWith /drupal/index.php/contextual/render" \
    "phase:2,nolog,pass,id:10001,ctl:ruleRemoveTargetById=921180;TX:paramcounter_ARGS_NAMES:ids[]"
SecRule REQUEST_URI "@beginsWith /drupal/index.php/search/node" \
    "phase:2,nolog,pass,id:10002,ctl:ruleRemoveTargetById=921180;TX:paramcounter_ARGS_NAMES:keys"
SecRule REQUEST_URI "@beginsWith /drupal/index.php/quickedit/attachments" \
    "phase:2,nolog,pass,id:10003,ctl:ruleRemoveTargetById=921180;TX:paramcounter_ARGS_NAMES:editors[]"
SecRule REQUEST_URI "@beginsWith /drupal/index.php/quickedit/metadata" \
    "phase:2,nolog,pass,id:10004,ctl:ruleRemoveTargetById=921180;TX:paramcounter_ARGS_NAMES:fields[]"
SecRule REQUEST_URI "@beginsWith /drupal/core/install.php" \
    "phase:2,nolog,pass,id:10005,ctl:ruleRemoveTargetById=921180;TX:paramcounter_ARGS_NAMES:op"

# ModSec Rule Exclusion: 942130 : SQL Injection Attack: SQL Tautology Detected.
# ModSec Rule Exclusion: 942431 : Restricted SQL Character Anomaly Detection (args): …
SecRule REQUEST_URI "@beginsWith /drupal/index.php/contextual/render" \
    "phase:2,nolog,pass,id:10006,ctl:ruleRemoveTargetById=942130;ARGS:ids[],\
                                 ctl:ruleRemoveTargetById=942431;ARGS:ids[]"

# ModSec Rule Exclusion: 942431 : Restricted SQL Character Anomaly Detection (args): …
SecRule REQUEST_URI "@beginsWith /drupal/index.php/quickedit/attachments" \
    "phase:2,nolog,pass,id:10007,ctl:ruleRemoveTargetById=942431;ARGS:ajax_page_state[libraries]"


# Handling alerts for the search form:
# ModSec Rule Exclusion: 942100 : SQL Injection Attack Detected via libinjection
# ModSec Rule Exclusion: 942190 : Detects MSSQL code execution and information gathering attempts
# ModSec Rule Exclusion: 942200 : Detects MySQL comment-/space-obfuscated injections and backtick …
# ModSec Rule Exclusion: 942260 : Detects basic SQL authentication bypass attempts 2/3
# ModSec Rule Exclusion: 942270 : Looking for basic sql injection. Common attack string for mysql, …
# ModSec Rule Exclusion: 942410 : SQL Injection Attack
SecRule REQUEST_URI "@beginsWith /drupal/index.php/search/node" "phase:2,nolog,pass,id:10100,\
   ctl:ruleRemoveTargetById=942100;ARGS:keys,\
   ctl:ruleRemoveTargetById=942190;ARGS:keys,\
   ctl:ruleRemoveTargetById=942200;ARGS:keys,\
   ctl:ruleRemoveTargetById=942260;ARGS:keys,\
   ctl:ruleRemoveTargetById=942270;ARGS:keys,\
   ctl:ruleRemoveTargetById=942410;ARGS:keys"


# === ModSecurity Core Rules Inclusion

Include    /apache/conf/crs/rules/*.conf


# === ModSec Core Rules: Startup Time Rules Exclusions

# ModSec Rule Exclusion: 942450 : SQL Hex Encoding Identified
SecRuleUpdateTargetById 942450 "!REQUEST_COOKIES"
SecRuleUpdateTargetById 942450 "!REQUEST_COOKIES_NAMES"

# ModSec Rule Exclusion: 920273 : Invalid character in request (outside of very strict set)
# ModSec Rule Exclusion: 942432 : Restricted SQL Character Anomaly Detection (args): 
# number of special characters exceeded (2) (severity:  NONE/UNKOWN)
SecRuleRemoveById 920273
SecRuleRemoveById 942432

# ModSec Rule Exclusion: 930000 - 943999 : All application rules for password parameters
SecRuleUpdateTargetById 930000-943999 "!ARGS:account[pass][pass1]"
SecRuleUpdateTargetById 930000-943999 "!ARGS:account[pass][pass2]"
SecRuleUpdateTargetById 930000-943999 "!ARGS:pass"

```


###Step 9 (Goodie): Getting a quicker overview

If you do this the first time, it all looks a bit overwhelming. But then it's only been an hour of work or so, which seems reasonable - even more so if you stretch it out over multiple iterations. One thing to help you get up to speed is getting an overview of all the alerts standing behind the scores. It’s a good idea to have a look at the distribution of the scores as described above. A good next step is to get a report of how exactly the *anomaly scores* occurred, such as an overview of the rule violations for each anomaly score. The following construct generates a report like this. On the first line, we extract a list of anomaly scores from the incoming requests which actually appear in the log file. We then build a loop around these *scores*, read the *request ID* for each *score*, save it in the file `ids` and perform a short analysis for these *IDs* in the *error log*.

```bash
$> cat tutorial-8-example-access.log | alscorein | sort -n | uniq | egrep -v -E "^0" > scores
$> cat scores | while read S; do echo "INCOMING SCORE $S";\
grep -E " $S [0-9-]+$" tutorial-8-example-access.log \
| alreqid > ids; grep -F -f ids tutorial-8-example-error.log | melidmsg | sucs; echo ; done 
INCOMING SCORE 5
     30 921180 HTTP Parameter Pollution (ARGS_NAMES:op)

INCOMING SCORE 8
      1 920273 Invalid character in request (outside of very strict set)
      1 942432 Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (2)

INCOMING SCORE 10
      4 920273 Invalid character in request (outside of very strict set)
   6384 942450 SQL Hex Encoding Identified

INCOMING SCORE 20
     56 932160 Remote Command Execution: Unix Shell Code Found
    168 920273 Invalid character in request (outside of very strict set)

INCOMING SCORE 30
     77 920273 Invalid character in request (outside of very strict set)
     77 942190 Detects MSSQL code execution and information gathering attempts
     77 942200 Detects MySQL comment-/space-obfuscated injections and backtick termination
     77 942260 Detects basic SQL authentication bypass attempts 2/3
     77 942270 Looking for basic sql injection. Common attack string for mysql, oracle and others.
     77 942410 SQL Injection Attack

INCOMING SCORE 35
     77 920273 Invalid character in request (outside of very strict set)
     77 942100 SQL Injection Attack Detected via libinjection
     77 942190 Detects MSSQL code execution and information gathering attempts
     77 942200 Detects MySQL comment-/space-obfuscated injections and backtick termination
     77 942260 Detects basic SQL authentication bypass attempts 2/3
     77 942270 Looking for basic sql injection. Common attack string for mysql, oracle and others.
     77 942410 SQL Injection Attack

INCOMING SCORE 78
     77 921180 HTTP Parameter Pollution (ARGS_NAMES:keys)
     77 942100 SQL Injection Attack Detected via libinjection
     77 942432 Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (2)
    154 942190 Detects MSSQL code execution and information gathering attempts
    154 942200 Detects MySQL comment-/space-obfuscated injections and backtick termination
    154 942260 Detects basic SQL authentication bypass attempts 2/3
    154 942270 Looking for basic sql injection. Common attack string for mysql, oracle and others.
    154 942410 SQL Injection Attack
    231 920273 Invalid character in request (outside of very strict set)

INCOMING SCORE 79
    448 921180 HTTP Parameter Pollution (ARGS_NAMES:editors[])
    448 942431 Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (6)
    896 942450 SQL Hex Encoding Identified
   3144 942432 Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (2)
   3595 920273 Invalid character in request (outside of very strict set)

INCOMING SCORE 93
      2 932160 Remote Command Execution: Unix Shell Code Found
      6 942432 Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (2)
     13 920273 Invalid character in request (outside of very strict set)

INCOMING SCORE 98
    448 921180 HTTP Parameter Pollution (ARGS_NAMES:fields[])
    896 942450 SQL Hex Encoding Identified
   2688 942432 Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (2)
   5824 920273 Invalid character in request (outside of very strict set)

INCOMING SCORE 189
      1 921180 HTTP Parameter Pollution (ARGS_NAMES:ids[])
      5 942431 Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (6)
      9 942130 SQL Injection Attack: SQL Tautology Detected.
     14 920273 Invalid character in request (outside of very strict set)
     18 942432 Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (2)

INCOMING SCORE 231
      6 921180 HTTP Parameter Pollution (ARGS_NAMES:ids[])
     12 942450 SQL Hex Encoding Identified
     30 942431 Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (6)
     66 942130 SQL Injection Attack: SQL Tautology Detected.
     96 920273 Invalid character in request (outside of very strict set)
    132 942432 Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (2)
```

A similar script that has been slightly extended is part of my private toolbox.

Before we finish with this tutorial, let me present my tuning policy again:

* Always work in blocking mode
* Highest scoring requests go first
* Work in several iterations

When you grow more proficient, you can reduce the number of iterations and tackle more false alarms in a single batch. Or you can concentrate on the rules that are triggered most often. That may work as well and in the end, when all rule exclusions are in place, you should end up with the same configuration. But in my experience, this policy with three simple guiding rules is the one with the highest chance of success and the lowest drop out rate. This is how you end up with a tight ModSecurity CRS setup in blocking mode with a low anomaly scoring limit.

We have now reached the end of the block consisting of three *ModSecurity tutorials*. The next one will look into setting up a *reverse proxy*.

###References
- [Spider Labs Blog Post: Exception Handling](http://blog.spiderlabs.com/2011/08/modsecurity-advanced-topic-of-the-week-exception-handling.html)
- [ModSecurity Reference Manual](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual)

### License / Copying / Further use

<a rel="license" href="http://creativecommons.org/licenses/by-nc-sa/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by-nc-sa/4.0/80x15.png" /></a><br />This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by-nc-sa/4.0/">Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License</a>.
