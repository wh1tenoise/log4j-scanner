# Log4Shell Scanner

Scanner for the log4j < 2.17.0 RCE vulnerability.
* CVE-2021-44228
* CVE-2021-45056

The scanner can interact with servers over various protocols to test for the vulnerability.

## How to Run
The tool runs with python 3.9<
```Help menu
usage: A scanner to check for the log4j vulnerability [-h] (-t TARGET | --target-list TARGET_LIST)
                                                      [-p {http,ssh,imap,smtp,socket,ftp,postgres}] [-o]
                                                      [--certificate-path CERTIFICATE_PATH] [--no-payload-domain]
                                                      [--request-path REQUEST_PATH] [-l {debug,info,error}]
                                                      [--use-localhost-bypass] [--proxy PROXY] [--generate-clientcert]
                                                      [--all-in-one] [--local-hostname LOCAL_HOSTNAME]
                                                      [--dns-callback {interact.sh,dnslog.cn} | --custom-callback CUSTOM_CALLBACK]

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        The target to check
  --target-list TARGET_LIST
                        The target to check
  -p {http,ssh,imap,smtp,socket,ftp,postgres}, --protocol {http,ssh,imap,smtp,socket,ftp,postgres}
                        which protocol to test
  -o, --obfuscate       Whether payloads should be obfuscated or not
  --certificate-path CERTIFICATE_PATH
                        Path to a client certificate for mTLS or SSH.
  --no-payload-domain   Whether the original domain should be removed from the payload
  --request-path REQUEST_PATH
                        A custom path to add to the requests
  -l {debug,info,error}, --log-level {debug,info,error}
                        How detailed logging should be.
  --use-localhost-bypass
                        Will use the bypass of CVE-2021-45046 in the payloads.
  --dns-callback {interact.sh,dnslog.cn}
                        Which built-in DNS callback to use
  --custom-callback CUSTOM_CALLBACK
                        A different callback to use. Won't be checked by the application.

HTTP Options:
  --proxy PROXY         A proxy URL
  --generate-clientcert
                        Generates a client certificate.
  --all-in-one          Test all headers in one iteration

SMTP Options:
  --local-hostname LOCAL_HOSTNAME
                        The localhost name to use, defaults to the hostname of the computer
```
Checking a HTTP endpoint
```Default HTTP scanner
python -m log4j_scanner -t example.com
```
SMTP example with a check for CVE-2021-45046
```SMTP example
python -m log4j_scanner -t example.com -p smtp --use-localhost-bypass
```


## References
The following references were integrated or served as inspiration for the scanner  
[1] https://github.com/fullhunt/log4j-scan  
[2] https://github.com/woodpecker-appstore/log4j-payload-generator
