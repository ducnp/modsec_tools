# modsec_tools

Simple scripts to help with mod_security2 for Apache.

## analyse_audit

```
analyse_audit --help
usage: analyse_audit [-h] [--rule-summary] [--file-summary] [--client-summary]
                     [--uri-summary] [--filter FILTER] [--filter-id FILTER_ID]
                     [--filter-host FILTER_HOST] [--filter-no-rule]
                     [--filter-rules] [--filter-response FILTER_RESPONSE]
                     [--filter-uid FILTER_UID] [--filter-client FILTER_CLIENT]
                     [--filter-uri FILTER_URI] [--show-requests] [--show-full]
                     [--include-headers]
                     [files [files ...]]

Analyse audit information from mod_security2

positional arguments:
  files                 Audit file(s) to parse

optional arguments:
  -h, --help            show this help message and exit
  --rule-summary        Print a summary of rules triggered
  --file-summary        Print a summary of rule files used
  --client-summary      Print a summary of clients
  --uri-summary         Print a summary of host/uri requests
  --filter FILTER       String to match for rule message
  --filter-id FILTER_ID
                        Filter by ID of rule
  --filter-host FILTER_HOST
                        Hostname to filter requests for
  --filter-no-rule      Only include requests with no rules matched
  --filter-rules        Only include requests that match at least one rule
  --filter-response FILTER_RESPONSE
                        Filter for given response code
  --filter-uid FILTER_UID
                        Filter for unique id's
  --filter-client FILTER_CLIENT
                        Filter for client IP
  --filter-uri FILTER_URI
                        Filter for URI containing supplied text
  --show-requests       Output request and response details
  --show-full           Show full log entry information
  --include-headers     Show request/response headers in output
```

### What
After installing mod_security2, the amount of data generated in the logfiles made figuring out what was going on hard, so these scripts aim to provide some simple information with which to make decisions about rulesets to use.

### Input Files
If input files have been gzipped they will be opened and read by the scipt, so the files to analyse can be specified as /var/log/apache2/modsec_audit.log* and all files present will be analysed.

### Filtering
There are many ways that the audit files may need to be filtered, and the analyse_audit script tries to provide a few of the more useful ones. Unless noted the matches are done in a case insensitive way.

- --filter TXT requires that TXT is present for one of the rules that matched a request
- --filter-id NNNNNN requires that one of the rules that matched a request had the ID provided.
- --filter-host HOST requires the hostname the request was made to contains HOST (from the Host header)
- --filter-response NNN requires the request provoked the response given
- --filter-uid UUUU requires the request unique id contain the supplied characters (case sensitive)
- --filter-client AAA requires that the remote address (IP) contains the supplied characters
- --filter-uri UUU requires that the request uri contains the supplied characters (case sensitive)
- --filter-rules When specified only requests that triggered mod_security2 rules will be included
- --filter-no-rule When specified only requests that did not trigger a mod_security2 rule will be included.

The last 2 filters are included for when the SecAuditEngine has a setting that includes relevant entries. This will normally capture a lot of requests that are triggered for reasons other than mod_security2 rules (simple 404's for instance). Sometimes it's useful to review these or to exclude these, hence these 2 filters. They cannot be used together!

### Output
There are various summaries that are available, but the requests can be output in more verbose for additional study. All summaries and output is applied after any filtering.

- --rule-summary Will display a summary of the rules that have matched requests
- --client-summary Displays a list of the number of times a remote IP address was used (long list)
- --file-summary Lists the files and line numbers that rules used are found in
- --uri-summary Actually produces a list of host/uri combinations with the rules that matched.

To view additional details of requests made,

- --show-requests Will show a summary of each log entry
- --show-full Will show the full log entry

When requests are being output using the --show-requests flag, headers are NOT included by default. To include the headers use the --include-headers flag.

### Examples

The rule summary gives a good indication of which rules are working and proving effective.
```
$ analyse_audit modsec_audit.log* --rule-summary
  Processing modsec_audit.log
  Processing modsec_audit.log.1
  Processing modsec_audit.log.2.gz
Total of 12673 entries were found.

Rule Summary

       1: Empty User Agent Header [960006 NOTICE]
     603: Failed to parse request body. [200001 CRITICAL]
     603: Failed to parse request body. [960912 CRITICAL]
       1: HTTP header is restricted by policy [960038 WARNING]
       3: IE XSS Filters - Attack Detected. [973335 ]
       1: Invalid character in request [960901 ERROR]
      16: Meta-Character Anomaly Detection Alert - Repetative Non-Word Characters [960024 ]
     328: No rules matched
      93: Possible Remote File Inclusion (RFI) Attack: Off-Domain Reference/Link [950120 CRITICAL]
       4: Possible XSS Attack Detected - HTML Tag Handler [973300 ]
       2: Pragma Header requires Cache-Control Header for HTTP/1.1 requests. [960020 NOTICE]
     125: Request Containing Content, but Missing Content-Type header [960904 NOTICE]
      51: Request Indicates a Security Scanner Scanned the Site [990002 CRITICAL]
   11325: Request Missing a User Agent Header [960009 NOTICE]
   11842: Request Missing an Accept Header [960015 NOTICE]
       2: Rogue web site crawler [990012 WARNING]
       1: Rule 7f37af10b060  - Execution error - PCRE limits exceeded (-8): (null). [973302 ]
       1: Rule 7f37af260028  - Execution error - PCRE limits exceeded (-8): (null). [973334 ]
       1: Rule 7f37af278850  - Execution error - PCRE limits exceeded (-8): (null). [973347 ]
       1: Rule 7fd7aaad5738  - Execution error - PCRE limits exceeded (-8): (null). [973332 ]
       4: XSS Attack Detected [973304 ]

Finished.
```

Where are those rules?

```
$ analyse_audit modsec_audit.log* --file-summary
  Processing modsec_audit.log
  Processing modsec_audit.log.1
  Processing modsec_audit.log.2.gz
Total of 12673 entries were found.

File Summary

  /etc/modsecurity/modsecurity.conf
      Line    54: 603
  /usr/share/modsecurity-crs/activated_rules/modsecurity_crs_20_protocol_violations.conf
      Line   151: 603
      Line   399: 2
      Line   533: 1
  /usr/share/modsecurity-crs/activated_rules/modsecurity_crs_21_protocol_anomalies.conf
      Line    47: 11842
      Line    66: 11325
      Line    68: 1
      Line    84: 125
  /usr/share/modsecurity-crs/activated_rules/modsecurity_crs_30_http_policy.conf
      Line   100: 1
  /usr/share/modsecurity-crs/activated_rules/modsecurity_crs_35_bad_robots.conf
      Line    20: 51
      Line    27: 2
  /usr/share/modsecurity-crs/activated_rules/modsecurity_crs_40_generic_attacks.conf
      Line   163: 93
      Line    37: 16
  /usr/share/modsecurity-crs/activated_rules/modsecurity_crs_41_xss_attacks.conf
      Line   301: 4
      Line   309: 1
      Line   333: 4
      Line   504: 1
      Line   506: 3
      Line   508: 1
      Line   514: 1

Finished.
```
When considering how rules interact with uri's the uri-summary flag can be used.

```
$ analyse_audit modsec_audit.log* --filter-client 89 --uri-summary
  Processing modsec_audit.log
  Processing modsec_audit.log.1
  Processing modsec_audit.log.2.gz
Total of 12673 entries were found.

Applying requested filters...
    - remote IP address must contain '89'

After filtering, 8 entries were left.

Host/URI Summary
  example.com
    /quicklinks/archives/2005/05/
      No mod_security2 rules were matched.
  example2.com
    /robots.txt
      No mod_security2 rules were matched.
    /xmlrpc.php
      Request Containing Content, but Missing Content-Type header [960904 NOTICE]: 6
      Request Missing a User Agent Header [960009 NOTICE]         : 6

Finished.
```

When the --show-requests flags are used, each request is printed as below. Headers are omitted by default.

```
    Unique ID           : UUUUUUUUUUUUUUUUUUUUUUUU
    Audit File          : modsec_audit.log.1
    URI                 : /xmlrpc.php
    Host                : XXXXXXXXXXXXXXXXXXXXXXX
    Date/Time           : 2015-07-13 01:09:08
    Remote Address      : AAA.109.CCC.211
    Response Code       : 401
    # of Rules Matched  : 2
      -  Request Containing Content, but Missing Content-Type header
         ID: 960904, Severity: NOTICE
         File: /usr/share/modsecurity-crs/activated_rules/modsecurity_crs_21_protocol_anomalies.conf
      -  Request Missing a User Agent Header
         ID: 960009, Severity: NOTICE
         File: /usr/share/modsecurity-crs/activated_rules/modsecurity_crs_21_protocol_anomalies.conf
```

To view information on a particular entry (NB no mod_security2 rules were matched for this entry).

```
$ analyse_audit modsec_audit.log* --show-full --include-headers --filter-uid UUUUUUUUUUUUUUUUUUUUUUUU
  Processing modsec_audit.log
  Processing modsec_audit.log.1
  Processing modsec_audit.log.2.gz
Total of 12673 entries were found.

Applying requested filters...
After filtering, 1 entries were left.

FULL REQUEST LOG:
    Unique ID           : UUUUUUUUUUUUUUUUUUUUUUUU
    Audit File          : modsec_audit.log.1
    URI                 : /wp-login.php
    Host                : XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    Date/Time           : 2015-07-13 05:28:17
    Remote Address      : AAA.246.CCC.109
    Response Code       : 401
  Request Header Section
    POST /wp-login.php HTTP/1.1
    Host: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    Keep-Alive: 300
    Connection: keep-alive
    Cookie: wordpress_test_cookie=WP+Cookie+check
    User-Agent: Mozilla/5.0 (Windows NT 5.1; rv:29.0) Gecko/20100101 Firefox/29.0
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 42
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
  Request Body Section
    log=xxxxxxxxxxxxxxxxxxxxxxxxxx&pwd=1&testcookie=1
  Audit Log Section
    Apache-Handler: application/x-httpd-php
    Stopwatch: 1436765297575522 17820 (- - -)
    Stopwatch2: 1436765297575522 17820; combined=2064, p1=490, p2=1564, p3=1, p4=0, p5=8, sr=132, sw=1, l=0, gc=0
    Response-Body-Transformed: Dechunked
    Producer: ModSecurity for Apache/VVVVV (http://www.modsecurity.org/); OWASP_CRS/VVVVV.
    Server: Apache
    Engine-Mode: "DETECTION_ONLY"
  Response Headers Section
    HTTP/1.1 401 Unauthorized
    Expires: Wed, EEEEEEEEEEEEEEEEEEEEEEEEEEE
    Cache-Control: no-cache, must-revalidate, max-age=0
    Pragma: no-cache
    Set-Cookie: wordpress_test_cookie=WP+Cookie+check; path=/
    X-Frame-Options: SAMEORIGIN
    Content-Length: 3593
    Keep-Alive: timeout=5, max=99
    Connection: Keep-Alive
    Content-Type: text/html; charset=UTF-8
  Response Body Section
    <!DOCTYPE html>
    ...

Finished.
```

To view summary information for all requests that returned a particular response code.

```
$ analyse_audit modsec_audit.log* --show-requests --filter-response 401
...
    Unique ID           : UUUUUUUUUUUUUUUUUUUUUUUU
    Audit File          : modsec_audit.log.1
    URI                 : /xmlrpc.php
    Host                : XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    Date/Time           : 2015-07-13 03:18:57
    Remote Address      : AAA.135.CCC.181
    Response Code       : 401
    Request Headers:
      POST /xmlrpc.php HTTP/1.1
      Connection: Close
      Content-Length: 216
      Host: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    # of Rules Matched  : 2
      -  Request Containing Content, but Missing Content-Type header
         ID: 960904, Severity: NOTICE
         File: /usr/share/modsecurity-crs/activated_rules/modsecurity_crs_21_protocol_anomalies.conf
      -  Request Missing a User Agent Header
         ID: 960009, Severity: NOTICE
         File: /usr/share/modsecurity-crs/activated_rules/modsecurity_crs_21_protocol_anomalies.conf
    Response Headers:
      HTTP/1.1 401 Unauthorized
      Connection: close
      Content-Length: 307
      Cache-Control: max-age=0
      Expires: Mon, 13 Jul 2015 03:18:55 GMT
      Content-Type: text/xml; charset=UTF-8
```

## extract_rules

```
$ extract_rules --help
usage: extract_rules [-h] [--filter FILTER] [--filter-id FILTER_ID]
                     [--filter-host FILTER_HOST] [--filter-no-rule]
                     [--filter-rules] [--filter-response FILTER_RESPONSE]
                     [--filter-uid FILTER_UID] [--filter-client FILTER_CLIENT]
                     [--filter-uri FILTER_URI] [--show-requests] [--show-full]
                     [--include-headers] [--output OUTPUT] [--ignore IGNORE]
                     [--block] [--log] [--nolog] [--deny] [--allow]
                     [--skip-conf SKIP_CONF] [--copy-files]
                     [files [files ...]]

Analyse audit logs and extract rules

positional arguments:
  files                 Audit file(s) to parse

optional arguments:
  -h, --help            show this help message and exit
  --filter FILTER       String to match for rule message
  --filter-id FILTER_ID
                        Filter by ID of rule
  --filter-host FILTER_HOST
                        Hostname to filter requests for
  --filter-no-rule      Only include requests with no rules matched
  --filter-rules        Only include requests that match at least one rule
  --filter-response FILTER_RESPONSE
                        Filter for given response code
  --filter-uid FILTER_UID
                        Filter for unique id's
  --filter-client FILTER_CLIENT
                        Filter for client IP
  --filter-uri FILTER_URI
                        Filter for URI containing supplied text
  --show-requests       Output request and response details
  --show-full           Show full log entry information
  --include-headers     Show request/response headers in output
  --output OUTPUT       File to save output into
  --ignore IGNORE       Level below which to ignore rules (default=20)
  --block               Set all rules to block
  --log                 Set all rules to log
  --nolog               Set all rules to NOT log
  --deny                Set all rules to deny
  --allow               Set all rules to allow
  --skip-conf SKIP_CONF
                        Ignore rules from the file specified
  --copy-files          Attempt to copy required files
```

### What?
After analysing the rules that have generated matches, it is possible to extract them into a single file using the extract_rules command. The intent is to simplify the maintenance and provide clarity over which rules are being used.

### Commercial?
If you have purchased a commercial ruleset, it's probably best if you not use this utility!

